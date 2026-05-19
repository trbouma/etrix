# Silent Payments Design Note

## Purpose

OpenETR will keep its existing exact-key Taproot `p2tr` wallet flow and add a separate Bitcoin Silent Payments capability based on BIP-352.

The two modes serve different goals:

- existing `p2tr` wallet:
  exact single-address Taproot spending and deterministic wallet control
- Silent Payments:
  privacy-preserving static receive addresses with receiver-side scanning

Silent Payments should be treated as an additional receive protocol, not as a replacement for the current OpenETR Taproot wallet.

## Design Goals

OpenETR Silent Payments should provide:

- a stable `sp1q...` receive address per profile or root context
- compatibility with the existing relay-backed and multi-modality architecture
- deterministic recovery from OpenETR key material
- a clear separation between:
  - spendable exact `p2tr` wallet control
  - privacy-preserving Silent Payments receiving
- shared implementation in `openetr` with thin CLI, web, and API adapters

## Non-Goals

This design does not initially attempt to:

- replace the existing `p2tr` wallet flow
- merge Silent Payments balances into the exact single-address Taproot wallet balance
- make Silent Payments the default Bitcoin receive mode everywhere
- solve full light-client Silent Payments scanning in the first iteration

## Coexistence Model

OpenETR will expose two parallel Bitcoin capabilities.

### Exact Taproot Wallet

This remains the current OpenETR behavior:

- derive a canonical single-address `p2tr` wallet from a Nostr key
- inspect balance
- export `taproot_wif`
- create and sign spend transactions directly

### Silent Payments Receive Mode

This adds a second Bitcoin receive identity:

- derive a Silent Payments scan/spend key pair
- publish or display a static `sp1q...` Silent Payment address
- scan blockchain activity to detect payments
- derive per-output spend keys when needed

The operational rule is:

- `p2tr` mode is exact-key and immediately spendable by OpenETR
- Silent Payments mode is private static receiving with scan-based discovery

## Key Derivation Model

OpenETR should derive Silent Payments keys deterministically from the existing profile or root `nsec`, using explicit domain separation.

Recommended approach:

1. Start from the normalized OpenETR profile private key material.
2. Derive a Silent Payments master seed with a domain-separated tagged hash.
3. From that master seed, derive:
   - `scan_priv_key`
   - `spend_priv_key`
4. Publish or display:
   - `scan_pub_key`
   - `spend_pub_key`
   - encoded Silent Payment address `sp1q...`

Recommended domain tags:

- `OpenETR/SilentPayments/v1/master`
- `OpenETR/SilentPayments/v1/scan`
- `OpenETR/SilentPayments/v1/spend`

This keeps Silent Payments key material:

- deterministic
- profile-specific
- recoverable from OpenETR-controlled keys
- distinct from the existing exact `p2tr` wallet flow

## Recovery Model

Recovery should be deterministic from the profile `nsec` and not require separate local wallet state.

The user should be able to recover:

- the Silent Payments address
- the scan key
- the spend key
- any detected outputs after rescanning

This matches the broader OpenETR philosophy:

- minimal local state
- deterministic regeneration where possible
- relay-backed or query-backed discovery where appropriate

## Shared Core Implementation

All Silent Payments behavior should live in `openetr`, not in individual adapters.

Recommended shared module areas:

- `openetr/bitcoin_silent.py`
  or
- `openetr/bitcoin.py`
  if the code remains compact enough

Core shared functions should include:

- `derive_silent_payment_keys(nostr_key)`
- `derive_silent_payment_address(nostr_key)`
- `scan_silent_payment_outputs(...)`
- `summarize_silent_payment_receipts(...)`
- `derive_silent_payment_spend_key(...)`

## CLI Surface

Recommended initial CLI commands:

- `openetr get-silent-payment-address <nsec|npub|nip05>`
- `openetr check-silent-payment-receipts <nsec|npub|nip05> [--limit 20]`

Possible later command:

- `openetr spend-silent-payment <nsec> <destination_address> <outpoint-or-detected-output> ...`

The first iteration should prioritize:

- address derivation
- receipt scanning
- transaction summary

Direct spending from detected Silent Payments outputs can be added later.

## Web App Surface

Recommended initial web experience:

- show a `Silent Payments` pane separate from the existing `Bitcoin Wallet` pane
- allow the user to:
  - derive the `sp1q...` address
  - show it as text and QR
  - scan and summarize recent detected Silent Payments receipts

The web app should not initially mix:

- exact `p2tr` wallet balance
- Silent Payments receipts

Those should be presented as separate views to avoid confusing users about which funds belong to which receive model.

## API Surface

Recommended future agent/API endpoints:

- `GET /api/bitcoin/silent/address`
- `POST /api/bitcoin/silent/scan`
- `GET /api/bitcoin/silent/receipts`

These endpoints should return structured JSON derived from the shared `openetr` service layer.

## Scanning Model

Silent Payments require receiver-side scanning.

The first OpenETR implementation should assume:

- scanning against an Esplora-compatible source or full-node-derived transaction feed
- server-side or CLI-side scanning in bounded windows
- explicit recent-history or pagination parameters

Recommended first-pass scan controls:

- `limit`
- optional `last_seen_txid`
- optional block-height range later

This keeps the first implementation practical without claiming full-wallet historical scan coverage from day one.

### Txid Hint Model via NIP-17

OpenETR should explicitly support a more efficient discovery pattern in which the sender provides the Bitcoin transaction id as an out-of-band hint over Nostr.

Recommended near-term pattern:

1. The receiver shares a Silent Payments `sp1q...` address.
2. The sender pays that address from a Bitcoin wallet.
3. The sender sends a NIP-17 DM to the receiver containing the resulting Bitcoin `txid`.
4. The receiver uses that `txid` as a targeted scan hint:
   - fetch the transaction
   - run Silent Payments receipt detection on that transaction
   - confirm whether one of the outputs belongs to them

This model has several advantages:

- avoids broad block-range scanning for routine payments
- reduces public Esplora/API load and rate-limit risk
- fits naturally with OpenETR's Nostr-centric identity model
- gives the receiver a fast confirmation path before full wallet-style scanning exists

This should be treated as the preferred first operational discovery pattern, even after bounded block scanning exists.

Recommended DM payload shape:

```json
{
  "type": "silent_payment_hint",
  "txid": "<bitcoin-txid>",
  "network": "mainnet",
  "note": "optional human context"
}
```

OpenETR should eventually support:

- extracting Silent Payments txid hints from NIP-17 DMs
- offering one-click receipt verification from the DM
- optionally sweeping or managing the detected output after verification

This design does not replace autonomous receiver-side scanning. It provides a practical and efficient interoperability layer for the first production-capable OpenETR Silent Payments workflows.

## Storage Model

OpenETR should avoid storing derived Silent Payments secrets redundantly.

Preferred model:

- derive scan/spend keys from deterministic OpenETR key material when needed
- cache only transient scan results where useful
- avoid persistent local storage of duplicate Silent Payments secret state

If scan cursors or optimization indexes are introduced later, they should be treated as:

- optional acceleration data
- reconstructible state

## Security Model

Silent Payments improve receive privacy, but they introduce scanning complexity.

Important security and operational rules:

- keep the existing exact `p2tr` wallet model for straightforward sending and recovery
- derive Silent Payments keys with strict domain separation
- never silently merge the two wallet models
- clearly label Silent Payments as a separate Bitcoin receive protocol
- expose scan and spend semantics explicitly in UI and CLI messaging

If scan/spend key separation is implemented per BIP-352, OpenETR should prefer:

- online scanning with scan key responsibilities
- minimized exposure of spend key material

## Implementation Notes and Interoperability Glitches

The first OpenETR Silent Payments implementation exposed several practical glitches that are worth documenting because they are easy to reintroduce accidentally.

### 1. Esplora Script Type Naming Differences

During early receipt detection testing, Cake Wallet produced transactions whose Esplora `scriptpubkey_type` values were returned as:

- `v0_p2wpkh`
- `v1_p2tr`

The initial OpenETR scanner only recognized:

- `p2wpkh`
- `p2tr`

Result:

- eligible input pubkeys were not extracted
- Taproot outputs were not recognized as candidate Silent Payments outputs

Fix:

- normalize Esplora script type aliases before input/output classification

### 2. Taproot Output Matching Must Use X-Only Keys

Taproot outputs on-chain are represented as x-only pubkeys.

The initial OpenETR scanner compared:

- full compressed derived pubkeys

against:

- Taproot output keys reconstructed with an assumed `02` prefix

That can fail whenever the actual derived output point has odd y.

Fix:

- compare Taproot outputs using x-only pubkey bytes
- treat the on-chain output key as x-only for receipt matching

### 3. Input Hash Serialization Bug

The initial implementation computed the BIP-352 `Inputs` tagged hash using:

- lowest outpoint
- x-only bytes of the summed input pubkey

But the receiver derivation needs the full compressed summed input pubkey.

Result:

- sender and receiver derived different shared-secret contexts

Fix:

- include the full compressed summed input pubkey in `hash BIP0352/Inputs(...)`

### 4. Shared Secret Tweak Serialization Bug

The first scanner version derived `t_k` using:

- x-only bytes of the shared point
- little-endian serialization for the index `k`

That does not match the intended BIP-352 serialization flow.

Fix:

- hash the full compressed shared point for `BIP0352/SharedSecret`
- serialize `k` using `ser_32(k)` in big-endian form

### 5. Public Key Aggregation API Misuse

The Python `secp256k1` binding used by OpenETR expects raw `secp256k1_pubkey *` handles when combining public keys.

The first implementation attempted to combine higher-level wrapper objects directly.

Result:

- summed input pubkey derivation failed
- receipt detection reported that input pubkeys summed to an invalid point

Fix:

- pass the underlying raw secp256k1 pubkey handles into the combine call

### 6. Transaction Inspection Was Essential

The addition of a dedicated transaction inspection command was important for debugging interoperability:

- `openetr inspect-silent-payment-tx <txid>`

This made it possible to see:

- actual input types
- witness structure
- extracted pubkeys
- candidate Taproot outputs

Without this tool, it would have been much harder to separate:

- transaction parsing issues
- BIP-352 derivation issues

from one another.

### Resulting Guidance

Based on the implementation work so far:

- Silent Payments address derivation alone is not enough to claim interoperability
- receipt detection must be tested against real wallet-produced transactions
- Esplora response normalization should be treated as part of the compatibility layer
- transaction-inspection tooling should remain part of the OpenETR developer and operator workflow

## Rollout Plan

Recommended rollout phases:

1. Silent Payments derivation only
   - derive scan/spend keys
   - derive and display `sp1q...`
   - CLI and web display support

2. Receipt scanning
   - summarize recent detected Silent Payments receipts
   - CLI and web summaries
   - targeted txid-hint scanning via NIP-17 DM

3. Recovery and rescan ergonomics
   - scanning checkpoints
   - better historical recovery workflow

4. Spending support
   - spend detected Silent Payments outputs
   - only after the receipt and recovery model is stable

## Recommended Product Framing

OpenETR should describe the feature like this:

- `Bitcoin Wallet`
  exact Taproot single-address wallet derived from OpenETR key material

- `Silent Payments`
  private static receive address capability derived from the same OpenETR identity, requiring scan-based payment detection

This makes the distinction clear and avoids confusing users into thinking Silent Payments is just another name for the current `p2tr` wallet flow.
