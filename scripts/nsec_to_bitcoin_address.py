#!/usr/bin/env python3
"""Derive Bitcoin addresses from a Nostr nsec using the same private key."""

from __future__ import annotations

import hashlib

import bech32
import click
from mnemonic import Mnemonic
import secp256k1
from monstr.encrypt import Keys


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def b58encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(data, "big")
    encoded = []
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(alphabet[remainder])
    prefix = "1" * (len(data) - len(data.lstrip(b"\x00")))
    return prefix + "".join(reversed(encoded or ["1"]))


def b58check(version: bytes, payload: bytes) -> str:
    body = version + payload
    checksum = sha256(sha256(body))[:4]
    return b58encode(body + checksum)


def derive_compressed_pubkey(privkey_hex: str) -> bytes:
    pk = secp256k1.PrivateKey(bytes.fromhex(privkey_hex), raw=True)
    return pk.pubkey.serialize(compressed=True)


def bech32_segwit_address(pubkey_hash: bytes, hrp: str = "bc", witness_version: int = 0) -> str:
    data = [witness_version] + bech32.convertbits(pubkey_hash, 8, 5)
    return bech32.bech32_encode(hrp, data)


@click.command()
@click.argument("nsec")
@click.option(
    "--show-mnemonic",
    is_flag=True,
    help="Also print a BIP39-style mnemonic encoding of the same 32-byte private key.",
)
def main(nsec: str, show_mnemonic: bool) -> None:
    """Print Bitcoin addresses derived from the same private key as NSEC."""
    key = Keys.get_key(nsec)
    if key is None or key.private_key_hex() is None:
        raise click.ClickException("input must be a valid nsec private key")

    privkey_hex = key.private_key_hex()
    compressed_pubkey = derive_compressed_pubkey(privkey_hex)
    pubkey_hash = hash160(compressed_pubkey)

    legacy_p2pkh = b58check(b"\x00", pubkey_hash)
    native_segwit = bech32_segwit_address(pubkey_hash)
    wif_compressed = b58check(b"\x80", bytes.fromhex(privkey_hex) + b"\x01")

    click.echo(f"nsec:            {nsec}")
    click.echo(f"private_key_hex: {privkey_hex}")
    click.echo(f"wif_compressed:  {wif_compressed}")
    click.echo(f"public_key_hex:  {compressed_pubkey.hex()}")
    click.echo(f"p2pkh:           {legacy_p2pkh}")
    click.echo(f"p2wpkh:          {native_segwit}")
    if show_mnemonic:
        mnemonic = Mnemonic("english").to_mnemonic(bytes.fromhex(privkey_hex))
        click.echo(f"mnemonic:        {mnemonic}")
        click.echo(
            "warning:         this mnemonic encodes the same raw 32-byte private key, "
            "but many wallet apps will treat it as an HD-wallet seed and may not recreate "
            "the same single-key Bitcoin address."
        )


if __name__ == "__main__":
    main()
