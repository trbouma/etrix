from __future__ import annotations

import hashlib
import json
from urllib import error, parse, request

import bech32
import click
import secp256k1
from monstr.encrypt import Keys

from openetr.helpers import resolve_keys

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BECH32M_CONST = 0x2BC830A3


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b58encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(data, "big")
    encoded: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(alphabet[remainder])
    prefix = "1" * (len(data) - len(data.lstrip(b"\x00")))
    return prefix + "".join(reversed(encoded or ["1"]))


def b58check(version: bytes, payload: bytes) -> str:
    body = version + payload
    checksum = sha256(sha256(body))[:4]
    return b58encode(body + checksum)


def private_key_bytes_to_mnemonic(privkey_bytes: bytes) -> str | None:
    try:
        from mnemonic import Mnemonic
    except ModuleNotFoundError:
        return None

    return Mnemonic("english").to_mnemonic(privkey_bytes)


def derive_compressed_pubkey(privkey_bytes: bytes) -> bytes:
    key = secp256k1.PrivateKey(privkey_bytes, raw=True)
    return key.pubkey.serialize(compressed=True)


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = sha256(tag.encode("utf-8"))
    return sha256(tag_hash + tag_hash + payload)


def normalize_bip340_private_key(privkey_hex: str) -> tuple[bytes, bytes, bool]:
    scalar = int(privkey_hex, 16)
    if scalar <= 0 or scalar >= SECP256K1_ORDER:
        raise click.ClickException("private key is outside the valid secp256k1 scalar range")

    privkey_bytes = bytes.fromhex(privkey_hex)
    compressed_pubkey = derive_compressed_pubkey(privkey_bytes)
    if compressed_pubkey[0] == 0x02:
        return privkey_bytes, compressed_pubkey, False

    normalized_scalar = SECP256K1_ORDER - scalar
    normalized_bytes = normalized_scalar.to_bytes(32, "big")
    normalized_pubkey = derive_compressed_pubkey(normalized_bytes)
    if normalized_pubkey[0] != 0x02:
        raise click.ClickException("failed to normalize private key to the BIP-340 even-y representative")
    return normalized_bytes, normalized_pubkey, True


def bech32m_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = bech32.bech32_hrp_expand(hrp) + list(data)
    polymod = bech32.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32m_encode(hrp: str, data: list[int]) -> str:
    combined = list(data) + bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join(bech32.CHARSET[d] for d in combined)


def taproot_address(output_key_xonly: bytes, hrp: str = "bc") -> str:
    data = [1] + bech32.convertbits(output_key_xonly, 8, 5, True)
    return bech32m_encode(hrp, data)


def taproot_material_from_internal_key(internal_key_xonly: bytes) -> dict[str, str]:
    if len(internal_key_xonly) != 32:
        raise click.ClickException("taproot internal key must be 32 bytes")

    tweak_bytes = tagged_hash("TapTweak", internal_key_xonly)
    tweak_int = int.from_bytes(tweak_bytes, "big")
    if tweak_int >= SECP256K1_ORDER:
        raise click.ClickException("taproot tweak exceeds the secp256k1 scalar order")

    internal_pubkey = secp256k1.PublicKey(b"\x02" + internal_key_xonly, raw=True)
    output_pubkey = internal_pubkey.tweak_add(tweak_bytes)
    output_compressed = output_pubkey.serialize(compressed=True)
    output_key_xonly = output_compressed[1:]
    return {
        "internal_public_key_hex": internal_key_xonly.hex(),
        "taproot_output_key_hex": output_key_xonly.hex(),
        "taproot_tweak_hex": tweak_bytes.hex(),
        "p2tr": taproot_address(output_key_xonly),
    }


def derive_bitcoin_material_from_nostr_key(nostr_key: str) -> dict[str, str]:
    keys = resolve_keys(nostr_key) if nostr_key.startswith("nsec") else Keys(pub_k=nostr_key)
    privkey_hex = keys.private_key_hex()
    warning = ""
    normalized = False
    internal_privkey_hex = ""
    taproot_private_key_hex = ""

    if privkey_hex is not None:
        normalized_privkey_bytes, compressed_pubkey, normalized = normalize_bip340_private_key(privkey_hex)
        internal_privkey_hex = normalized_privkey_bytes.hex()
        internal_key_xonly = compressed_pubkey[1:]
        taproot_material = taproot_material_from_internal_key(internal_key_xonly)
        tweak_bytes = bytes.fromhex(taproot_material["taproot_tweak_hex"])
        tweaked_private_key = secp256k1.PrivateKey(normalized_privkey_bytes, raw=True).tweak_add(tweak_bytes)
        taproot_private_key_hex = tweaked_private_key.hex()
        if normalized:
            warning = (
                "nsec input was normalized to the BIP-340 even-y representative before deriving the Taproot "
                "internal key. The recovery material below is tied to that canonical internal key."
            )
    else:
        pubkey_hex = keys.public_key_hex()
        if pubkey_hex is None:
            raise click.ClickException("input must be a valid nsec or npub key")
        taproot_material = taproot_material_from_internal_key(bytes.fromhex(pubkey_hex))
        warning = (
            "npub input uses the BIP-340 x-only public key as the Taproot internal key. OpenETR derives the "
            "canonical single-key P2TR address using the BIP-341 TapTweak construction."
        )

    mnemonic = private_key_bytes_to_mnemonic(bytes.fromhex(internal_privkey_hex)) if internal_privkey_hex else None
    npub = keys.public_key_bech32()
    return {
        "npub": npub,
        "private_key_hex": internal_privkey_hex,
        "taproot_private_key_hex": taproot_private_key_hex,
        "internal_wif_compressed": b58check(b"\x80", bytes.fromhex(internal_privkey_hex) + b"\x01") if internal_privkey_hex else "",
        "taproot_wif": b58check(b"\x80", bytes.fromhex(taproot_private_key_hex) + b"\x01") if taproot_private_key_hex else "",
        "mnemonic": mnemonic or "",
        "warning": warning,
        "bip340_normalized": "yes" if normalized else "no",
        **taproot_material,
    }


def derive_bitcoin_wallet_material(nsec: str) -> dict[str, str]:
    wallet = derive_bitcoin_material_from_nostr_key(nsec)
    if wallet["private_key_hex"] is None:
        raise click.ClickException("session signer is missing a private key")
    if not wallet["mnemonic"]:
        wallet["mnemonic"] = "Unavailable: optional mnemonic dependency is not installed."
    return wallet


def fetch_blockstream_address_balance_sats(
    address: str,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> dict[str, int | str]:
    url = f"{api_base.rstrip('/')}/address/{parse.quote(address)}"
    req = request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "openetr/0.1",
        },
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        raise click.ClickException(
            f"Blockstream balance lookup failed for {address}: HTTP {exc.code}"
        ) from exc
    except error.URLError as exc:
        raise click.ClickException(
            f"Blockstream balance lookup failed for {address}: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise click.ClickException(
            f"Blockstream balance lookup timed out for {address}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"Blockstream balance lookup returned invalid JSON for {address}"
        ) from exc

    chain_stats = payload.get("chain_stats") or {}
    mempool_stats = payload.get("mempool_stats") or {}
    confirmed_sats = int(chain_stats.get("funded_txo_sum", 0)) - int(chain_stats.get("spent_txo_sum", 0))
    mempool_sats = int(mempool_stats.get("funded_txo_sum", 0)) - int(mempool_stats.get("spent_txo_sum", 0))
    return {
        "address": address,
        "confirmed_sats": confirmed_sats,
        "mempool_sats": mempool_sats,
        "total_sats": confirmed_sats + mempool_sats,
        "api_base": api_base.rstrip('/'),
    }


def fetch_blockstream_wallet_balance_sats(
    wallet_material: dict[str, str],
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> dict[str, object]:
    taproot = fetch_blockstream_address_balance_sats(wallet_material["p2tr"], api_base=api_base, timeout=timeout)
    return {
        "api_base": api_base.rstrip('/'),
        "taproot": taproot,
        "confirmed_sats": int(taproot["confirmed_sats"]),
        "mempool_sats": int(taproot["mempool_sats"]),
        "total_sats": int(taproot["total_sats"]),
    }


def derive_bitcoin_material_with_balance(
    nostr_key: str,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> dict[str, object]:
    wallet = derive_bitcoin_material_from_nostr_key(nostr_key)
    try:
        wallet["balance"] = fetch_blockstream_wallet_balance_sats(wallet, api_base=api_base, timeout=timeout)
        wallet["balance_error"] = ""
    except click.ClickException as exc:
        wallet["balance"] = None
        wallet["balance_error"] = str(exc)
    return wallet
