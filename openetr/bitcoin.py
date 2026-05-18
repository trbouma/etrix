from __future__ import annotations

import hashlib
import json
import math
from urllib import error, parse, request

import bech32
from btclib.ecc import ssa
from btclib.script import sig_hash
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
import click
import secp256k1
from monstr.encrypt import Keys

from openetr.helpers import format_pubkey, normalize_nip05_identifier, resolve_author, resolve_keys

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


def normalize_nostr_key_input(nostr_key: str) -> tuple[str, str]:
    candidate = nostr_key.strip()
    if not candidate:
        raise click.ClickException("nostr key input cannot be empty")

    if candidate.startswith("nsec"):
        return candidate, "nsec"

    if candidate.startswith("npub"):
        return candidate, "npub"

    nip05_candidate = normalize_nip05_identifier(candidate)
    if "@" in nip05_candidate:
        return format_pubkey(resolve_author(nip05_candidate)), "nip05"

    raise click.ClickException("input must be a valid nsec, npub, or NIP-05 identifier")


def derive_bitcoin_material_from_nostr_key(nostr_key: str) -> dict[str, str]:
    normalized_input, input_kind = normalize_nostr_key_input(nostr_key)
    keys = resolve_keys(normalized_input) if input_kind == "nsec" else Keys(pub_k=normalized_input)
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
        "input_value": nostr_key,
        "input_kind": input_kind,
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


def derive_p2tr_balance_for_nostr_input(
    nostr_key: str,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> dict[str, object]:
    wallet = derive_bitcoin_material_from_nostr_key(nostr_key)
    balance = fetch_blockstream_wallet_balance_sats(wallet, api_base=api_base, timeout=timeout)
    return {
        "input_value": nostr_key,
        "input_kind": wallet["input_kind"],
        "npub": wallet["npub"],
        "p2tr": wallet["p2tr"],
        "internal_public_key_hex": wallet["internal_public_key_hex"],
        "taproot_output_key_hex": wallet["taproot_output_key_hex"],
        "taproot_tweak_hex": wallet["taproot_tweak_hex"],
        "balance": balance,
    }


DEFAULT_DUST_THRESHOLD_SATS = 546
DUST_THRESHOLD_BY_TYPE = {
    "p2tr": 330,
    "p2wpkh": 294,
    "p2pkh": 546,
    "p2sh": 540,
}




def dust_threshold_for_script_pub_key(script_pub_key: ScriptPubKey) -> int:
    return DUST_THRESHOLD_BY_TYPE.get(script_pub_key.type, DEFAULT_DUST_THRESHOLD_SATS)

def fetch_blockstream_address_utxos(
    address: str,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> list[dict[str, object]]:
    url = f"{api_base.rstrip('/')}/address/{parse.quote(address)}/utxo"
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
            f"Blockstream UTXO lookup failed for {address}: HTTP {exc.code}"
        ) from exc
    except error.URLError as exc:
        raise click.ClickException(
            f"Blockstream UTXO lookup failed for {address}: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise click.ClickException(
            f"Blockstream UTXO lookup timed out for {address}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"Blockstream UTXO lookup returned invalid JSON for {address}"
        ) from exc

    if not isinstance(payload, list):
        raise click.ClickException(f"Blockstream UTXO lookup returned an unexpected payload for {address}")

    utxos: list[dict[str, object]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        status = item.get("status") or {}
        utxos.append({
            "txid": str(item["txid"]),
            "vout": int(item["vout"]),
            "value": int(item["value"]),
            "confirmed": bool(status.get("confirmed")),
            "block_height": int(status.get("block_height", 0) or 0),
        })
    return utxos


def _estimate_signed_p2tr_vsize(input_count: int, output_script_pub_keys: list[ScriptPubKey]) -> int:
    vin = [
        TxIn(
            prev_out=OutPoint(bytes.fromhex("11" * 32), index, check_validity=False),
            sequence=0xFFFFFFFD,
            script_witness=Witness([b"\x00" * 64]),
            check_validity=False,
        )
        for index in range(input_count)
    ]
    vout = [TxOut(1000, script_pub_key, check_validity=False) for script_pub_key in output_script_pub_keys]
    tx = Tx(vin=vin, vout=vout, check_validity=False)
    return tx.vsize




def validate_non_dust_tx_outputs(outputs: list[tuple[str, TxOut]]) -> None:
    for label, tx_out in outputs:
        threshold = dust_threshold_for_script_pub_key(tx_out.script_pub_key)
        if tx_out.value < threshold:
            raise click.ClickException(
                f"{label} output is dust for {tx_out.script_pub_key.type}: {tx_out.value} sats < {threshold} sats"
            )

def _select_utxos_for_amount(
    utxos: list[dict[str, object]],
    amount_sats: int,
    fee_rate: float,
    change_script_pub_key: ScriptPubKey,
    destination_script_pub_key: ScriptPubKey,
) -> tuple[list[dict[str, object]], int, int, str]:
    if amount_sats <= 0:
        raise click.ClickException("amount_sats must be greater than zero")
    if fee_rate <= 0:
        raise click.ClickException("fee_rate must be greater than zero")

    ordered_utxos = sorted(utxos, key=lambda u: (not bool(u["confirmed"]), int(u["value"])))
    selected: list[dict[str, object]] = []
    total_in = 0
    for utxo in ordered_utxos:
        selected.append(utxo)
        total_in += int(utxo["value"])

        fee_with_change = math.ceil(
            _estimate_signed_p2tr_vsize(len(selected), [destination_script_pub_key, change_script_pub_key]) * fee_rate
        )
        change_amount = total_in - amount_sats - fee_with_change
        change_dust_threshold = dust_threshold_for_script_pub_key(change_script_pub_key)
        if change_amount >= change_dust_threshold:
            return selected, change_amount, fee_with_change, "change_output"

        fee_no_change = math.ceil(_estimate_signed_p2tr_vsize(len(selected), [destination_script_pub_key]) * fee_rate)
        if total_in >= amount_sats + fee_no_change:
            return selected, 0, fee_no_change, "folded_dust_into_fee"

    raise click.ClickException("insufficient funds for the requested amount and fee rate")


def build_signed_p2tr_transaction(
    taproot_private_key_hex: str,
    source_address: str,
    utxos: list[dict[str, object]],
    destination_address: str,
    amount_sats: int,
    fee_rate: float,
    change_address: str | None = None,
) -> dict[str, object]:
    if not utxos:
        raise click.ClickException(f"no UTXOs are available to spend from {source_address}")

    source_spk = ScriptPubKey.from_address(source_address)
    destination_spk = ScriptPubKey.from_address(destination_address)
    change_spk = ScriptPubKey.from_address(change_address or source_address)

    destination_dust_threshold = dust_threshold_for_script_pub_key(destination_spk)
    if amount_sats < destination_dust_threshold:
        raise click.ClickException(
            f"destination amount {amount_sats} sats is dust for {destination_spk.type}; minimum supported amount is {destination_dust_threshold} sats"
        )

    selected_utxos, change_amount, fee_sats, change_policy = _select_utxos_for_amount(
        utxos, amount_sats, fee_rate, change_spk, destination_spk
    )

    vin = [
        TxIn(
            prev_out=OutPoint(bytes.fromhex(str(utxo["txid"])), int(utxo["vout"]), check_validity=False),
            sequence=0xFFFFFFFD,
            check_validity=False,
        )
        for utxo in selected_utxos
    ]
    vout = [TxOut(amount_sats, destination_spk, check_validity=False)]
    if change_amount:
        vout.append(TxOut(change_amount, change_spk, check_validity=False))

    tx = Tx(vin=vin, vout=vout, check_validity=False)
    prevouts = [TxOut(int(utxo["value"]), source_spk, check_validity=False) for utxo in selected_utxos]

    labeled_outputs = [("destination", tx.vout[0])]
    if change_amount:
        labeled_outputs.append(("change", tx.vout[1]))
    validate_non_dust_tx_outputs(labeled_outputs)

    for index, _ in enumerate(selected_utxos):
        sighash = sig_hash.taproot(tx, index, prevouts, 0, 0, b"", b"")
        sig = ssa.sign_(sighash, int(taproot_private_key_hex, 16)).serialize()
        tx.vin[index].script_witness = Witness([sig])

    tx_hex = tx.serialize(include_witness=True, check_validity=False).hex()
    total_in = sum(int(utxo["value"]) for utxo in selected_utxos)
    return {
        "tx_hex": tx_hex,
        "txid": tx.id.hex(),
        "vsize": tx.vsize,
        "weight": tx.weight,
        "fee_sats": fee_sats,
        "fee_rate": fee_rate,
        "amount_sats": amount_sats,
        "change_sats": change_amount,
        "source_address": source_address,
        "destination_address": destination_address,
        "change_address": (change_address or source_address) if change_amount else "",
        "change_policy": change_policy,
        "destination_dust_threshold": destination_dust_threshold,
        "change_dust_threshold": dust_threshold_for_script_pub_key(change_spk),
        "selected_utxos": selected_utxos,
        "input_count": len(selected_utxos),
        "output_count": len(vout),
        "total_in_sats": total_in,
    }


def broadcast_blockstream_transaction(
    tx_hex: str,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 10.0,
) -> str:
    url = f"{api_base.rstrip('/')}/tx"
    req = request.Request(
        url,
        data=tx_hex.encode("utf-8"),
        headers={
            "Content-Type": "text/plain",
            "Accept": "text/plain",
            "User-Agent": "openetr/0.1",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            return response.read().decode("utf-8").strip()
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise click.ClickException(
            f"Blockstream broadcast failed: HTTP {exc.code}{': ' + detail if detail else ''}"
        ) from exc
    except error.URLError as exc:
        raise click.ClickException(f"Blockstream broadcast failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise click.ClickException("Blockstream broadcast timed out") from exc


def create_p2tr_send_result(
    nostr_key: str,
    destination_address: str,
    amount_sats: int,
    fee_rate: float,
    api_base: str = "https://blockstream.info/api",
    change_address: str | None = None,
    timeout: float = 5.0,
) -> dict[str, object]:
    wallet = derive_bitcoin_material_from_nostr_key(nostr_key)
    if not wallet["taproot_private_key_hex"]:
        raise click.ClickException("nsec input is required to sign and spend a Taproot wallet")
    utxos = fetch_blockstream_address_utxos(wallet["p2tr"], api_base=api_base, timeout=timeout)
    tx_result = build_signed_p2tr_transaction(
        wallet["taproot_private_key_hex"],
        wallet["p2tr"],
        utxos,
        destination_address,
        amount_sats,
        fee_rate,
        change_address=change_address,
    )
    tx_result["wallet"] = wallet
    tx_result["api_base"] = api_base.rstrip('/')
    return tx_result
