#!/usr/bin/env python3
"""Derive Bitcoin addresses from a Nostr nsec using the same private key."""

from __future__ import annotations

import click
from openetr.bitcoin import derive_bitcoin_material_with_balance


@click.command()
@click.argument("nostr_key")
@click.option(
    "--show-mnemonic",
    is_flag=True,
    help="Also print a BIP39-style mnemonic encoding when a private nsec is supplied.",
)
def main(nostr_key: str, show_mnemonic: bool) -> None:
    """Print Bitcoin addresses derived from an nsec or npub."""
    wallet = derive_bitcoin_material_with_balance(nostr_key)

    click.echo(f"nostr_key:       {nostr_key}")
    click.echo(f"npub:            {wallet['npub']}")
    if wallet["private_key_hex"]:
        click.echo(f"private_key_hex: {wallet['private_key_hex']}")
        click.echo(f"bip340_normalized: {wallet['bip340_normalized']}")
        click.echo(f"wif_compressed:  {wallet['wif_compressed']}")
    click.echo(f"public_key_hex:  {wallet['public_key_hex']}")
    click.echo(f"p2pkh:           {wallet['p2pkh']}")
    click.echo(f"p2wpkh:          {wallet['p2wpkh']}")
    if wallet["balance"]:
        click.echo(f"balance_sats:    {wallet['balance']['total_sats']}")
        click.echo(f"confirmed_sats:  {wallet['balance']['confirmed_sats']}")
        click.echo(f"mempool_sats:    {wallet['balance']['mempool_sats']}")
        click.echo(f"balance_source:  {wallet['balance']['api_base']}")
    elif wallet["balance_error"]:
        click.echo(f"balance_error:   {wallet['balance_error']}")
    if wallet["warning"]:
        click.echo(f"warning:         {wallet['warning']}")
    if show_mnemonic and wallet["mnemonic"]:
        click.echo(f"mnemonic:        {wallet['mnemonic']}")
        click.echo(
            "warning:         this mnemonic encodes the canonical BIP-340-normalized 32-byte private key, "
            "but many wallet apps will treat it as an HD-wallet seed and may not recreate "
            "the same single-key Bitcoin address."
        )
    elif show_mnemonic:
        click.echo("mnemonic:        unavailable for public-only npub input")


if __name__ == "__main__":
    main()
