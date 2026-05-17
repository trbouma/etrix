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


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


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


def bech32_segwit_address(pubkey_hash: bytes, hrp: str = "bc", witness_version: int = 0) -> str:
    data = [witness_version] + bech32.convertbits(pubkey_hash, 8, 5)
    return bech32.bech32_encode(hrp, data)


def address_set_from_compressed_pubkey(compressed_pubkey: bytes) -> dict[str, str]:
    pubkey_hash = hash160(compressed_pubkey)
    return {
        "public_key_hex": compressed_pubkey.hex(),
        "p2pkh": b58check(b"\x00", pubkey_hash),
        "p2wpkh": bech32_segwit_address(pubkey_hash),
    }


def derive_bitcoin_material_from_nostr_key(nostr_key: str) -> dict[str, str]:
    keys = resolve_keys(nostr_key) if nostr_key.startswith("nsec") else Keys(pub_k=nostr_key)
    privkey_hex = keys.private_key_hex()
    warning = ""
    normalized = False
    if privkey_hex is not None:
        normalized_privkey_bytes, compressed_pubkey, normalized = normalize_bip340_private_key(privkey_hex)
        privkey_hex = normalized_privkey_bytes.hex()
        addresses = address_set_from_compressed_pubkey(compressed_pubkey)
        if normalized:
            warning = (
                "nsec input was normalized to the BIP-340 even-y representative. The canonical Bitcoin "
                "private key and addresses below match the x-only Nostr public key, but may differ from the "
                "raw secp256k1 compression parity of the original secret scalar."
            )
    else:
        pubkey_hex = keys.public_key_hex()
        if pubkey_hex is None:
            raise click.ClickException("input must be a valid nsec or npub key")
        canonical_pubkey = bytes.fromhex("02" + pubkey_hex)
        warning = (
            "npub input uses the BIP-340 x-only public key. OpenETR derives the canonical Bitcoin address "
            "from the even-y representative, equivalent to compressed 02||x."
        )
        addresses = address_set_from_compressed_pubkey(canonical_pubkey)

    mnemonic = private_key_bytes_to_mnemonic(bytes.fromhex(privkey_hex)) if privkey_hex is not None else None
    npub = keys.public_key_bech32()
    return {
        "npub": npub,
        "private_key_hex": privkey_hex,
        "wif_compressed": b58check(b"\x80", bytes.fromhex(privkey_hex) + b"\x01") if privkey_hex is not None else "",
        "mnemonic": mnemonic or "",
        "warning": warning,
        "bip340_normalized": "yes" if normalized else "no",
        **addresses,
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
    segwit = fetch_blockstream_address_balance_sats(wallet_material["p2wpkh"], api_base=api_base, timeout=timeout)
    legacy = fetch_blockstream_address_balance_sats(wallet_material["p2pkh"], api_base=api_base, timeout=timeout)
    return {
        "api_base": api_base.rstrip('/'),
        "native_segwit": segwit,
        "legacy_p2pkh": legacy,
        "confirmed_sats": int(segwit["confirmed_sats"]) + int(legacy["confirmed_sats"]),
        "mempool_sats": int(segwit["mempool_sats"]) + int(legacy["mempool_sats"]),
        "total_sats": int(segwit["total_sats"]) + int(legacy["total_sats"]),
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
