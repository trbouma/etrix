from __future__ import annotations

import hashlib
import json
import math
from urllib import error, parse, request

import bech32
import click
import secp256k1
from monstr.encrypt import Keys
from btclib.script.script_pub_key import ScriptPubKey

from openetr.bitcoin import _estimate_signed_p2tr_vsize, build_signed_p2tr_transaction, confirmed_utxos_only, dust_threshold_for_script_pub_key, fetch_blockstream_address_utxos
from openetr.helpers import format_pubkey, normalize_nip05_identifier, resolve_author, resolve_keys

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BECH32M_CONST = 0x2BC830A3
SCAN_OUTPUT_SEARCH_LIMIT = 4096


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = sha256(tag.encode("utf-8"))
    return sha256(tag_hash + tag_hash + payload)


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


def bech32m_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = bech32.bech32_hrp_expand(hrp) + list(data)
    polymod = bech32.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32m_encode(hrp: str, data: list[int]) -> str:
    combined = list(data) + bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join(bech32.CHARSET[d] for d in combined)


def encode_silent_payment_address(scan_pubkey: bytes, spend_pubkey: bytes, hrp: str = "sp", version: int = 0) -> str:
    if len(scan_pubkey) != 33 or len(spend_pubkey) != 33:
        raise click.ClickException("silent payment scan and spend public keys must be 33-byte compressed pubkeys")
    data = bech32.convertbits(scan_pubkey + spend_pubkey, 8, 5, True)
    return bech32m_encode(hrp, [version] + data)


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


def _derive_tweak_scalar(base_pubkey: bytes, tag: str) -> int:
    tweak_int = int.from_bytes(tagged_hash(tag, base_pubkey), "big") % SECP256K1_ORDER
    if tweak_int == 0:
        raise click.ClickException(f"{tag} derivation produced an invalid zero tweak")
    return tweak_int


def _tweak_pubkey(base_pubkey: bytes, tweak_scalar: int) -> bytes:
    pubkey = secp256k1.PublicKey(base_pubkey, raw=True)
    return pubkey.tweak_add(tweak_scalar.to_bytes(32, "big")).serialize(compressed=True)


def derive_silent_payment_material(nostr_key: str, hrp: str = "sp") -> dict[str, str]:
    normalized_input, input_kind = normalize_nostr_key_input(nostr_key)
    keys = resolve_keys(normalized_input) if input_kind == "nsec" else Keys(pub_k=normalized_input)
    npub = keys.public_key_bech32()
    privkey_hex = keys.private_key_hex()
    warning = ""
    bip340_normalized = "no"

    if privkey_hex is not None:
        base_privkey_bytes, base_pubkey, normalized = normalize_bip340_private_key(privkey_hex)
        bip340_normalized = "yes" if normalized else "no"
        base_scalar = int.from_bytes(base_privkey_bytes, "big")
        if normalized:
            warning = (
                "nsec input was normalized to the BIP-340 even-y representative before deriving Silent Payments "
                "scan and spend keys."
            )
    else:
        pubkey_hex = keys.public_key_hex()
        if pubkey_hex is None:
            raise click.ClickException("input must be a valid nsec or npub key")
        base_pubkey = b"\x02" + bytes.fromhex(pubkey_hex)
        base_scalar = None
        warning = (
            "npub input derives Silent Payments public keys only. Private scan and spend keys are unavailable "
            "without the matching nsec."
        )

    scan_tweak = _derive_tweak_scalar(base_pubkey, "OpenETR/SilentPayments/v1/scan")
    spend_tweak = _derive_tweak_scalar(base_pubkey, "OpenETR/SilentPayments/v1/spend")
    scan_pubkey = _tweak_pubkey(base_pubkey, scan_tweak)
    spend_pubkey = _tweak_pubkey(base_pubkey, spend_tweak)

    scan_priv_hex = ""
    spend_priv_hex = ""
    if base_scalar is not None:
        scan_scalar = (base_scalar + scan_tweak) % SECP256K1_ORDER
        spend_scalar = (base_scalar + spend_tweak) % SECP256K1_ORDER
        if scan_scalar == 0 or spend_scalar == 0:
            raise click.ClickException("silent payment derivation produced an invalid zero private key")
        scan_priv_hex = scan_scalar.to_bytes(32, "big").hex()
        spend_priv_hex = spend_scalar.to_bytes(32, "big").hex()

    return {
        "input_value": nostr_key,
        "input_kind": input_kind,
        "npub": npub,
        "bip340_normalized": bip340_normalized,
        "base_public_key_hex": base_pubkey.hex(),
        "scan_private_key_hex": scan_priv_hex,
        "spend_private_key_hex": spend_priv_hex,
        "scan_public_key_hex": scan_pubkey.hex(),
        "spend_public_key_hex": spend_pubkey.hex(),
        "silent_payment_address": encode_silent_payment_address(scan_pubkey, spend_pubkey, hrp=hrp),
        "warning": warning,
    }


def _script_type(script_hex: str) -> str:
    if script_hex.startswith("76a914") and script_hex.endswith("88ac") and len(script_hex) == 50:
        return "p2pkh"
    if script_hex.startswith("a914") and script_hex.endswith("87") and len(script_hex) == 46:
        return "p2sh"
    if script_hex.startswith("0014") and len(script_hex) == 44:
        return "p2wpkh"
    if script_hex.startswith("5120") and len(script_hex) == 68:
        return "p2tr"
    return "unknown"


def _normalize_script_type_name(script_type: str) -> str:
    normalized = script_type.strip().lower()
    aliases = {
        "v0_p2wpkh": "p2wpkh",
        "v1_p2tr": "p2tr",
        "v0_p2wsh": "p2wsh",
        "p2sh-p2wpkh": "p2sh",
    }
    return aliases.get(normalized, normalized)


def _outpoint_bytes(txid: str, vout: int) -> bytes:
    return bytes.fromhex(txid)[::-1] + int(vout).to_bytes(4, "little")


def _ser32(value: int) -> bytes:
    return int(value).to_bytes(4, "big")


def _compressed_pub_from_xonly(xonly_hex: str) -> bytes:
    xonly = bytes.fromhex(xonly_hex)
    if len(xonly) != 32:
        raise click.ClickException("x-only public key must be 32 bytes")
    return b"\x02" + xonly


def _xonly_pubkey_bytes(xonly_hex: str) -> bytes:
    xonly = bytes.fromhex(xonly_hex)
    if len(xonly) != 32:
        raise click.ClickException("x-only public key must be 32 bytes")
    return xonly


def _extract_input_pubkey(vin: dict[str, object]) -> bytes | None:
    prevout = vin.get("prevout")
    if not isinstance(prevout, dict):
        return None
    script_hex = str(prevout.get("scriptpubkey") or "")
    script_type = _normalize_script_type_name(str(prevout.get("scriptpubkey_type") or _script_type(script_hex)))
    witness = vin.get("witness") or []
    scriptsig_hex = str(vin.get("scriptsig") or "")

    if script_type == "p2wpkh":
        if isinstance(witness, list) and witness:
            pubkey_hex = str(witness[-1])
            pubkey = bytes.fromhex(pubkey_hex)
            if len(pubkey) == 33:
                return pubkey
        return None

    if script_type == "p2sh":
        redeem_hex = scriptsig_hex[2:] if scriptsig_hex.startswith("16") else scriptsig_hex
        if redeem_hex.startswith("0014") and isinstance(witness, list) and witness:
            pubkey_hex = str(witness[-1])
            pubkey = bytes.fromhex(pubkey_hex)
            if len(pubkey) == 33:
                return pubkey
        return None

    if script_type == "p2tr":
        if script_hex.startswith("5120"):
            return _compressed_pub_from_xonly(script_hex[4:])
        return None

    if script_type == "p2pkh":
        script_bytes = bytes.fromhex(scriptsig_hex)
        for idx in range(len(script_bytes), 32, -1):
            candidate = script_bytes[idx - 33:idx]
            if len(candidate) == 33 and candidate[0] in (0x02, 0x03):
                return candidate
        return None

    return None


def inspect_silent_payment_transaction(
    txid: str,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> dict[str, object]:
    tx = fetch_blockstream_transaction(txid, api_base=api_base, timeout=timeout)
    vin = tx.get("vin")
    vout = tx.get("vout")
    if not isinstance(vin, list) or not isinstance(vout, list):
        raise click.ClickException("transaction payload is missing vin/vout arrays")

    inputs: list[dict[str, object]] = []
    extracted_pubkeys = 0
    for index, txin in enumerate(vin):
        if not isinstance(txin, dict):
            continue
        prevout = txin.get("prevout")
        prevout_dict = prevout if isinstance(prevout, dict) else {}
        script_hex = str(prevout_dict.get("scriptpubkey") or "")
        script_type = _normalize_script_type_name(str(prevout_dict.get("scriptpubkey_type") or _script_type(script_hex)))
        witness = txin.get("witness") or []
        pubkey = _extract_input_pubkey(txin)
        notes: list[str] = []
        if not isinstance(prevout, dict):
            notes.append("missing prevout")
        if not witness:
            notes.append("no witness stack")
        if script_type == "p2sh" and not str(txin.get("scriptsig") or ""):
            notes.append("no scriptsig redeem data")
        if pubkey is None:
            notes.append("no eligible pubkey extracted")
        else:
            extracted_pubkeys += 1

        inputs.append(
            {
                "index": index,
                "txid": str(txin.get("txid") or ""),
                "vout": int(txin.get("vout", 0) or 0),
                "sequence": int(txin.get("sequence", 0) or 0),
                "prevout_script_type": script_type,
                "prevout_scriptpubkey": script_hex,
                "witness_items": len(witness) if isinstance(witness, list) else 0,
                "scriptsig_length": len(str(txin.get("scriptsig") or "")) // 2,
                "pubkey_extracted": pubkey is not None,
                "pubkey_hex": pubkey.hex() if pubkey is not None else "",
                "notes": notes,
            }
        )

    outputs: list[dict[str, object]] = []
    taproot_outputs = 0
    for index, output in enumerate(vout):
        if not isinstance(output, dict):
            continue
        script_hex = str(output.get("scriptpubkey") or "")
        script_type = _normalize_script_type_name(str(output.get("scriptpubkey_type") or _script_type(script_hex)))
        if script_type == "p2tr":
            taproot_outputs += 1
        outputs.append(
            {
                "index": index,
                "value": int(output.get("value", 0) or 0),
                "script_type": script_type,
                "scriptpubkey_address": str(output.get("scriptpubkey_address") or ""),
                "scriptpubkey": script_hex,
            }
        )

    return {
        "txid": str(tx.get("txid") or txid),
        "api_base": api_base.rstrip("/"),
        "status": tx.get("status") if isinstance(tx.get("status"), dict) else {},
        "input_count": len(inputs),
        "eligible_input_pubkeys": extracted_pubkeys,
        "taproot_output_count": taproot_outputs,
        "inputs": inputs,
        "outputs": outputs,
    }


def _combine_pubkeys(pubkeys: list[bytes]) -> bytes | None:
    if not pubkeys:
        return None
    try:
        pubkey_objects = [secp256k1.PublicKey(pubkey, raw=True) for pubkey in pubkeys]
        combined = secp256k1.PublicKey()
        combined.combine([pubkey.public_key for pubkey in pubkey_objects])
    except Exception:
        return None
    return combined.serialize(compressed=True)


def _get_input_hash(outpoint_bytes: list[bytes], summed_input_pubkey: bytes) -> bytes:
    lowest_outpoint = sorted(outpoint_bytes)[0]
    return tagged_hash("BIP0352/Inputs", lowest_outpoint + summed_input_pubkey)


def fetch_blockstream_transaction(
    txid: str,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> dict[str, object]:
    url = f"{api_base.rstrip('/')}/tx/{parse.quote(txid)}"
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
            f"Blockstream transaction lookup failed for {txid}: HTTP {exc.code}"
        ) from exc
    except error.URLError as exc:
        raise click.ClickException(
            f"Blockstream transaction lookup failed for {txid}: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise click.ClickException(
            f"Blockstream transaction lookup timed out for {txid}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"Blockstream transaction lookup returned invalid JSON for {txid}"
        ) from exc
    if not isinstance(payload, dict):
        raise click.ClickException(f"Blockstream transaction lookup returned an unexpected payload for {txid}")
    return payload


def fetch_blockstream_tip_height(
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> int:
    url = f"{api_base.rstrip('/')}/blocks/tip/height"
    req = request.Request(
        url,
        headers={
            "Accept": "text/plain",
            "User-Agent": "openetr/0.1",
        },
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            payload = response.read().decode("utf-8").strip()
    except error.HTTPError as exc:
        raise click.ClickException(
            f"Blockstream tip-height lookup failed: HTTP {exc.code}"
        ) from exc
    except error.URLError as exc:
        raise click.ClickException(
            f"Blockstream tip-height lookup failed: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise click.ClickException("Blockstream tip-height lookup timed out") from exc
    try:
        return int(payload)
    except ValueError as exc:
        raise click.ClickException("Blockstream tip-height lookup returned an invalid height") from exc


def fetch_blockstream_block_hash_for_height(
    height: int,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> str:
    url = f"{api_base.rstrip('/')}/block-height/{height}"
    req = request.Request(
        url,
        headers={
            "Accept": "text/plain",
            "User-Agent": "openetr/0.1",
        },
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            payload = response.read().decode("utf-8").strip()
    except error.HTTPError as exc:
        raise click.ClickException(
            f"Blockstream block-hash lookup failed for height {height}: HTTP {exc.code}"
        ) from exc
    except error.URLError as exc:
        raise click.ClickException(
            f"Blockstream block-hash lookup failed for height {height}: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise click.ClickException(
            f"Blockstream block-hash lookup timed out for height {height}"
        ) from exc
    if not payload:
        raise click.ClickException(f"Blockstream block-hash lookup returned an empty hash for height {height}")
    return payload


def fetch_blockstream_block_txids(
    block_hash: str,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
) -> list[str]:
    url = f"{api_base.rstrip('/')}/block/{parse.quote(block_hash)}/txids"
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
            f"Blockstream block txid lookup failed for {block_hash}: HTTP {exc.code}"
        ) from exc
    except error.URLError as exc:
        raise click.ClickException(
            f"Blockstream block txid lookup failed for {block_hash}: {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise click.ClickException(
            f"Blockstream block txid lookup timed out for {block_hash}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"Blockstream block txid lookup returned invalid JSON for {block_hash}"
        ) from exc
    if not isinstance(payload, list):
        raise click.ClickException(f"Blockstream block txid lookup returned an unexpected payload for {block_hash}")
    return [str(txid) for txid in payload if txid]


def collect_block_txids(
    api_base: str = "https://blockstream.info/api",
    start_blockheight: int | None = None,
    block_count: int = 1,
    timeout: float = 5.0,
) -> tuple[list[str], list[dict[str, object]]]:
    if block_count <= 0:
        raise click.ClickException("block_count must be a positive integer")

    tip_height = fetch_blockstream_tip_height(api_base=api_base, timeout=timeout)
    effective_start = tip_height if start_blockheight is None else start_blockheight
    if effective_start < 0:
        raise click.ClickException("start_blockheight must be zero or greater")
    if effective_start > tip_height:
        raise click.ClickException(
            f"start_blockheight {effective_start} is above the current tip height {tip_height}"
        )

    block_summaries: list[dict[str, object]] = []
    txids: list[str] = []
    for offset in range(block_count):
        height = effective_start - offset
        if height < 0:
            break
        block_hash = fetch_blockstream_block_hash_for_height(height, api_base=api_base, timeout=timeout)
        block_txids = fetch_blockstream_block_txids(block_hash, api_base=api_base, timeout=timeout)
        block_summaries.append(
            {
                "height": height,
                "block_hash": block_hash,
                "tx_count": len(block_txids),
            }
        )
        txids.extend(block_txids)
    return txids, block_summaries


def scan_silent_payment_transaction(
    nostr_key: str,
    tx: dict[str, object],
) -> dict[str, object]:
    material = derive_silent_payment_material(nostr_key)
    if not material["scan_private_key_hex"] or not material["spend_private_key_hex"]:
        raise click.ClickException("nsec input is required to scan Silent Payments receipts")

    vin = tx.get("vin")
    vout = tx.get("vout")
    if not isinstance(vin, list) or not isinstance(vout, list):
        raise click.ClickException("transaction payload is missing vin/vout arrays")

    input_pubkeys: list[bytes] = []
    outpoints: list[bytes] = []
    for txin in vin:
        if not isinstance(txin, dict):
            continue
        pubkey = _extract_input_pubkey(txin)
        if pubkey is None:
            continue
        txid = str(txin.get("txid") or "")
        vout_index = int(txin.get("vout", 0) or 0)
        if not txid:
            continue
        input_pubkeys.append(pubkey)
        outpoints.append(_outpoint_bytes(txid, vout_index))

    if not input_pubkeys or not outpoints:
        return {
            "txid": str(tx.get("txid", "")),
            "matched_outputs": [],
            "input_pubkey_count": 0,
            "warning": "No eligible input public keys were found for Silent Payments scanning.",
        }

    summed_input_pubkey = _combine_pubkeys(input_pubkeys)
    if summed_input_pubkey is None:
        return {
            "txid": str(tx.get("txid", "")),
            "matched_outputs": [],
            "input_pubkey_count": len(input_pubkeys),
            "warning": "Input public keys summed to an invalid point for Silent Payments scanning.",
        }

    scan_priv_bytes = bytes.fromhex(material["scan_private_key_hex"])
    spend_pubkey = bytes.fromhex(material["spend_public_key_hex"])
    input_hash = _get_input_hash(outpoints, summed_input_pubkey)
    input_hash_scalar = int.from_bytes(input_hash, "big") % SECP256K1_ORDER
    if input_hash_scalar == 0:
        return {
            "txid": str(tx.get("txid", "")),
            "matched_outputs": [],
            "input_pubkey_count": len(input_pubkeys),
            "warning": "Silent Payments input hash resolved to an invalid zero scalar.",
        }

    scan_priv_scalar = int.from_bytes(scan_priv_bytes, "big")
    shared_scalar = (input_hash_scalar * scan_priv_scalar) % SECP256K1_ORDER
    if shared_scalar == 0:
        return {
            "txid": str(tx.get("txid", "")),
            "matched_outputs": [],
            "input_pubkey_count": len(input_pubkeys),
            "warning": "Silent Payments shared secret resolved to an invalid zero scalar.",
        }

    summed_input_point = secp256k1.PublicKey(summed_input_pubkey, raw=True)
    ecdh_point = summed_input_point.tweak_mul(shared_scalar.to_bytes(32, "big"))
    ecdh_compressed = ecdh_point.serialize(compressed=True)

    remaining_outputs: dict[bytes, dict[str, object]] = {}
    for output in vout:
        if not isinstance(output, dict):
            continue
        script_hex = str(output.get("scriptpubkey") or "")
        script_type = _normalize_script_type_name(str(output.get("scriptpubkey_type") or _script_type(script_hex)))
        if script_type != "p2tr":
            continue
        remaining_outputs[_xonly_pubkey_bytes(script_hex[4:])] = output

    matched_outputs: list[dict[str, object]] = []
    warning = ""
    for k in range(SCAN_OUTPUT_SEARCH_LIMIT):
        if not remaining_outputs:
            break
        t_k = tagged_hash("BIP0352/SharedSecret", ecdh_compressed + _ser32(k))
        tweak_scalar = int.from_bytes(t_k, "big") % SECP256K1_ORDER
        if tweak_scalar == 0:
            continue
        derived_pubkey = (
            secp256k1.PublicKey(spend_pubkey, raw=True)
            .tweak_add(tweak_scalar.to_bytes(32, "big"))
            .serialize(compressed=True)
        )
        output = remaining_outputs.pop(derived_pubkey[1:], None)
        if output is not None:
            matched_outputs.append(
                {
                    "vout": int(output.get("vout", 0) or 0),
                    "value": int(output.get("value", 0) or 0),
                    "scriptpubkey_address": str(output.get("scriptpubkey_address") or ""),
                    "output_pubkey_hex": derived_pubkey.hex(),
                    "priv_key_tweak_hex": t_k.hex(),
                    "shared_secret_index": k,
                }
            )
    if remaining_outputs and not matched_outputs:
        warning = (
            "No matching Silent Payments outputs were found within the current scan window. "
            "A larger search window or fuller BIP-352 labeling support may be required."
        )

    return {
        "txid": str(tx.get("txid", "")),
        "matched_outputs": matched_outputs,
        "input_pubkey_count": len(input_pubkeys),
        "warning": warning,
    }


def scan_silent_payment_receipts(
    nostr_key: str,
    txids: list[str] | None = None,
    api_base: str = "https://blockstream.info/api",
    start_blockheight: int | None = None,
    block_count: int = 1,
    timeout: float = 5.0,
) -> dict[str, object]:
    material = derive_silent_payment_material(nostr_key)
    if not material["scan_private_key_hex"] or not material["spend_private_key_hex"]:
        raise click.ClickException("nsec input is required to scan Silent Payments receipts")

    effective_txids = [txid for txid in (txids or []) if txid]
    block_summaries: list[dict[str, object]] = []
    scan_mode = "txids"
    if not effective_txids:
        scan_mode = "blocks"
        effective_txids, block_summaries = collect_block_txids(
            api_base=api_base,
            start_blockheight=start_blockheight,
            block_count=block_count,
            timeout=timeout,
        )

    scanned_transactions: list[dict[str, object]] = []
    for txid in effective_txids:
        tx = fetch_blockstream_transaction(txid, api_base=api_base, timeout=timeout)
        result = scan_silent_payment_transaction(nostr_key, tx)
        scanned_transactions.append(result)

    return {
        "input_value": nostr_key,
        "npub": material["npub"],
        "silent_payment_address": material["silent_payment_address"],
        "api_base": api_base.rstrip("/"),
        "scan_mode": scan_mode,
        "block_summaries": block_summaries,
        "transactions": scanned_transactions,
    }


def _silent_payment_output_private_key_hex(
    spend_private_key_hex: str,
    tweak_hex: str,
    output_pubkey_hex: str,
) -> str:
    spend_scalar = int(spend_private_key_hex, 16)
    tweak_scalar = int(tweak_hex, 16) % SECP256K1_ORDER
    if tweak_scalar == 0:
        raise click.ClickException("receipt tweak resolved to an invalid zero scalar")
    output_scalar = (spend_scalar + tweak_scalar) % SECP256K1_ORDER
    if output_scalar == 0:
        raise click.ClickException("receipt spend key resolved to an invalid zero scalar")
    if output_pubkey_hex.startswith("03"):
        output_scalar = (SECP256K1_ORDER - output_scalar) % SECP256K1_ORDER
        if output_scalar == 0:
            raise click.ClickException("receipt spend key normalization resolved to an invalid zero scalar")
    return output_scalar.to_bytes(32, "big").hex()


def create_silent_payment_sweep_result(
    nsec: str,
    txid: str,
    destination_address: str,
    fee_rate: float,
    api_base: str = "https://blockstream.info/api",
    timeout: float = 5.0,
    vout: int | None = None,
) -> dict[str, object]:
    material = derive_silent_payment_material(nsec)
    if not material["scan_private_key_hex"] or not material["spend_private_key_hex"]:
        raise click.ClickException("nsec input is required to sweep a Silent Payments receipt")

    scan_result = scan_silent_payment_receipts(
        nsec,
        [txid],
        api_base=api_base,
        timeout=timeout,
    )
    tx_result = scan_result["transactions"][0]
    matches = tx_result["matched_outputs"]
    if not matches:
        raise click.ClickException(f"no Silent Payments receipt was detected in transaction {txid}")

    selected_match: dict[str, object] | None = None
    if vout is not None:
        for match in matches:
            if int(match["vout"]) == vout:
                selected_match = match
                break
        if selected_match is None:
            raise click.ClickException(f"transaction {txid} does not contain a matched Silent Payments receipt at vout {vout}")
    elif len(matches) == 1:
        selected_match = matches[0]
    else:
        matched_vouts = ", ".join(str(match["vout"]) for match in matches)
        raise click.ClickException(
            f"transaction {txid} contains multiple matched Silent Payments receipts ({matched_vouts}); specify --vout"
        )

    source_address = str(selected_match["scriptpubkey_address"])
    source_vout = int(selected_match["vout"])
    confirmed_utxos = confirmed_utxos_only(
        fetch_blockstream_address_utxos(source_address, api_base=api_base, timeout=timeout)
    )
    selected_utxos = [
        utxo
        for utxo in confirmed_utxos
        if str(utxo["txid"]) == txid and int(utxo["vout"]) == source_vout
    ]
    if not selected_utxos:
        raise click.ClickException(
            f"matched Silent Payments output {txid}:{source_vout} is not available as a confirmed unspent output"
        )

    if fee_rate <= 0:
        raise click.ClickException("fee_rate must be greater than zero")

    destination_spk = ScriptPubKey.from_address(destination_address)
    destination_dust_threshold = dust_threshold_for_script_pub_key(destination_spk)
    total_in = sum(int(utxo["value"]) for utxo in selected_utxos)
    fee_sats = math.ceil(
        _estimate_signed_p2tr_vsize(len(selected_utxos), [destination_spk]) * fee_rate
    )
    amount_sats = total_in - fee_sats
    if amount_sats <= 0:
        raise click.ClickException("insufficient funds to sweep the Silent Payments receipt at the requested fee rate")
    if amount_sats < destination_dust_threshold:
        raise click.ClickException(
            f"sweep amount {amount_sats} sats is dust for {destination_spk.type}; minimum supported amount is {destination_dust_threshold} sats"
        )

    receipt_private_key_hex = _silent_payment_output_private_key_hex(
        material["spend_private_key_hex"],
        str(selected_match["priv_key_tweak_hex"]),
        str(selected_match["output_pubkey_hex"]),
    )
    tx_build_result = build_signed_p2tr_transaction(
        receipt_private_key_hex,
        source_address,
        selected_utxos,
        destination_address,
        amount_sats,
        fee_rate,
        change_address=source_address,
    )
    tx_build_result["api_base"] = api_base.rstrip("/")
    tx_build_result["npub"] = material["npub"]
    tx_build_result["silent_payment_address"] = material["silent_payment_address"]
    tx_build_result["matched_txid"] = txid
    tx_build_result["matched_vout"] = source_vout
    tx_build_result["matched_value"] = int(selected_match["value"])
    tx_build_result["matched_tweak_hex"] = str(selected_match["priv_key_tweak_hex"])
    tx_build_result["matched_output_pubkey_hex"] = str(selected_match["output_pubkey_hex"])
    tx_build_result["matched_shared_secret_index"] = int(selected_match["shared_secret_index"])
    tx_build_result["sweep"] = True
    return tx_build_result
