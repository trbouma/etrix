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
    help="Also print the raw-key mnemonic encoding for reference; this is not the recommended Taproot wallet import format.",
)
def main(nostr_key: str, show_mnemonic: bool) -> None:
    """Print Bitcoin addresses derived from an nsec or npub."""
    wallet = derive_bitcoin_material_with_balance(nostr_key)

    click.echo(f"nostr_key:       {nostr_key}")
    click.echo(f"npub:            {wallet['npub']}")
    if wallet["private_key_hex"]:
        click.echo(f"internal_private_key_hex: {wallet['private_key_hex']}")
        click.echo(f"bip340_normalized:   {wallet['bip340_normalized']}")
        click.echo(f"taproot_private_key_hex: {wallet['taproot_private_key_hex']}")
        click.echo(f"internal_wif_compressed: {wallet['internal_wif_compressed']}")
        click.echo(f"taproot_wif:           {wallet['taproot_wif']}")
    click.echo(f"internal_public_key_hex: {wallet['internal_public_key_hex']}")
    click.echo(f"taproot_output_key_hex: {wallet['taproot_output_key_hex']}")
    click.echo(f"taproot_tweak_hex:   {wallet['taproot_tweak_hex']}")
    click.echo(f"p2tr:               {wallet['p2tr']}")
    if wallet["balance"]:
        click.echo(f"balance_sats:       {wallet['balance']['total_sats']}")
        click.echo(f"confirmed_sats:     {wallet['balance']['confirmed_sats']}")
        click.echo(f"mempool_sats:       {wallet['balance']['mempool_sats']}")
        click.echo(f"balance_source:     {wallet['balance']['api_base']}")
    elif wallet["balance_error"]:
        click.echo(f"balance_error:   {wallet['balance_error']}")
    if wallet["warning"]:
        click.echo(f"warning:         {wallet['warning']}")
    if show_mnemonic and wallet["mnemonic"]:
        click.echo(f"mnemonic:        {wallet['mnemonic']}")
        click.echo(
            "warning:         this mnemonic is only a raw-key encoding of the Taproot internal key. "
            "Many wallet apps will treat it as an HD-wallet seed and may derive a different wallet. "
            "Use taproot_wif as the recommended import format for the p2tr address above."
        )
    elif show_mnemonic:
        click.echo("mnemonic:        unavailable for public-only npub input")


if __name__ == "__main__":
    main()
