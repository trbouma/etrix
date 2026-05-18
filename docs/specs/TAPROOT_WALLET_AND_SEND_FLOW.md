# Taproot Wallet and Send Flow

## Purpose

OpenETR derives a Bitcoin Taproot single-address wallet from a Nostr key and supports:

- deterministic `p2tr` address derivation
- balance lookup through an Esplora-compatible API
- exact Taproot wallet import via `taproot_wif`
- CLI-based Taproot transaction creation, signing, and broadcast

## Wallet Model

OpenETR uses a single-key Taproot model.

- The Nostr key is interpreted as the Taproot internal key.
- The internal key is normalized to the BIP-340 even-y representative when required.
- The Taproot output key is derived using the BIP-341 TapTweak construction.
- The resulting wallet is a single-address `p2tr` wallet, not an HD derivation wallet.

This means the OpenETR Bitcoin wallet is exact-key oriented, not seed-path oriented.

## Recovery Material

OpenETR exposes multiple recovery or import artifacts, but they have different semantics.

### Exact Taproot Recovery

The recommended import artifact for exact OpenETR wallet recovery is:

- `taproot_wif`

This value corresponds to the tweaked Taproot private key used for the final `p2tr` output key.
Importing this value into a wallet that supports Taproot single-address WIF import should recover the same `p2tr` address.

### Internal-Key Material

OpenETR may also expose:

- `nsec`
- internal private key hex
- internal compressed WIF
- mnemonic encoding of the normalized internal key

These values are useful for debugging, derivation transparency, or advanced workflows, but they are not the recommended general wallet recovery format for the OpenETR Taproot wallet.

### Mnemonic Caveat

The mnemonic provided by OpenETR is a raw-key encoding of the normalized internal key.
Many wallet apps interpret a mnemonic as an HD wallet seed and may derive a different wallet, often a standard HD SegWit wallet, rather than the exact OpenETR `p2tr` address.

For that reason:

- mnemonic import may create a usable wallet
- mnemonic import does not guarantee exact OpenETR Taproot recovery
- `taproot_wif` is the preferred exact recovery/import artifact

## Balance Lookup

OpenETR queries an Esplora-compatible API for the `p2tr` address.

Current implementation uses the Blockstream Esplora API shape:

- address summary via `/address/:address`
- UTXO discovery via `/address/:address/utxo`
- broadcast via `POST /tx`

Balance in sats is computed as:

- `funded_txo_sum - spent_txo_sum`

with confirmed and mempool values tracked separately.

## CLI Inspection Command

The Taproot wallet details can be inspected with:

```bash
openetr get-bitcoin-info <nsec-or-npub>
```

This command returns Taproot-oriented fields, including:

- `npub`
- internal public key
- Taproot output key
- Taproot tweak
- `p2tr`
- `taproot_wif` for private-key input
- balance information when API lookup succeeds

## CLI Send Command

OpenETR supports an experimental Taproot send flow via:

```bash
openetr send-bitcoin <nsec> <destination_address> <amount_sats> [--fee-rate 2.0] [--broadcast]
```

### Behavior

The command:

1. derives the Taproot wallet from the provided `nsec`
2. fetches UTXOs for the source `p2tr` address
3. selects inputs sufficient for amount plus fee
4. estimates fee from signed Taproot transaction vsize and `sats/vbyte`
5. signs each input as a Taproot key-path spend
6. prints the signed transaction as a dry run by default
7. broadcasts only when `--broadcast` is provided

### Fee Rate

The current default is:

- `--fee-rate 2.0`

Users may override it explicitly.

### Dust Handling

The send flow validates dust policy per output type.

For Taproot outputs, the current dust threshold is:

- `330 sats`

If change would be dust-sized, OpenETR folds that remainder into the fee instead of creating a dust output.
The CLI reports this through:

- `change_policy: change_output`
- or `change_policy: folded_dust_into_fee`

The CLI also reports:

- `destination_dust_threshold`
- `change_dust_threshold`

## Scope and Caution

This Taproot wallet functionality is intended to provide deterministic key control and practical spendability for OpenETR-derived wallets.
It should currently be treated as an advanced or experimental feature.

In particular:

- wallet import behavior varies across apps
- mnemonic import often behaves like HD wallet recovery, not exact Taproot recovery
- exact OpenETR recovery should prefer `taproot_wif`
- users should verify that any imported wallet shows the same `p2tr` address before relying on it
