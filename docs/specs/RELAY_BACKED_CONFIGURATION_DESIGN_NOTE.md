# Relay-Backed Configuration Design Note

This note describes a proposed OpenETR configuration model in which operational CLI state is stored on relays as signed events rather than treated as machine-local configuration.

The purpose is to make OpenETR configuration portable, signed, recoverable, and independent of any one local installation.

This note is architectural, but it also records the current preferred implementation direction.

## Status

Draft, with partial implementation already in the OpenETR CLI.

The current CLI now uses relay-backed records for a substantial part of its operational state.

## Purpose

The current OpenETR CLI uses a local `config.yaml` file to store:

- named profiles
- the active profile
- aliases
- default relay information
- operational defaults

That model is simple, but it binds the user's working configuration to one machine unless the file is copied manually.

OpenETR's broader philosophy points in a different direction.

If signed control-relevant events can live independently of any one system, then the CLI configuration used to work with those events should also be capable of existing independently of any one machine.

The design goal is therefore:

> OpenETR configuration should be portable, signed, and recoverable from relays, with only minimal local bootstrap state required.

## Core Idea

OpenETR should support a relay-backed configuration model with two layers:

1. A minimal local bootstrap layer
2. A relay-backed authoritative configuration layer

The local bootstrap layer exists only to let the CLI find and unlock the relay-backed state.

The relay-backed layer becomes the real source of truth.

## Current Implementation State

OpenETR is no longer treating the local `config.yaml` file as the sole authoritative source of CLI state.

The current implementation direction is:

- relay-backed records are the primary source for profile discovery and operational recovery
- the local bootstrap file is being reduced toward the minimum needed to locate and unlock relay-backed state
- local YAML is still retained as a compatibility mirror in some paths, but it is no longer the intended long-term source of truth

As currently implemented, OpenETR uses relay-backed records for:

- the profile index
- the active profile
- aliases
- per-profile signer secrets
- per-profile operational settings

This means that a fresh machine can increasingly recover the CLI environment from relay-backed records once the bootstrap values are known.

## Underlying Philosophy

This design follows the same underlying philosophy already visible in the OpenETR event model:

- publication can be global
- recovery should not depend on one local installation
- state should be attributable to keys, not to platforms
- portability should come from signed protocol objects, not from copying opaque local files

In practical terms, this means that a user should be able to move to another machine and reconstruct CLI state using only:

- a root CLI key
- one or more home relays

That is a better fit for OpenETR than treating `config.yaml` as the authoritative store.

## Root CLI Key

This model introduces a distinct root CLI key.

The purpose of the root CLI key is administrative, not transactional.

It is used to:

- publish configuration records
- retrieve configuration records
- decrypt encrypted configuration content
- authenticate updates to CLI state

It should not be treated as the same thing as the operational keys used by named OpenETR profiles.

That separation matters.

The root CLI key is the control key for the CLI environment.

The profile keys are the operational identities that:

- issue ETR origin events
- initiate transfers
- accept transfers
- terminate ETRs
- publish kind `0` social metadata

This keeps configuration administration separate from operational authorship.

## Minimal Local Bootstrap

OpenETR should still keep a very small local bootstrap record.

That bootstrap record is not the authoritative configuration.

Its role is only to let the CLI locate and unlock the authoritative configuration on relays.

The bootstrap record should be limited to things such as:

- root `nsec`, or a reference to where the root key is held
- home relay or home relay list
- optional local cache metadata
- optional last-sync metadata

The bootstrap layer should remain intentionally small.

It is a locator and unlock mechanism, not the primary config store.

### Current Bootstrap Minimum

The intended local bootstrap minimum is now:

- `root_nsec`
- `home_relay`

In practical terms, that means the intended final local file can be as small as:

```yaml
root_nsec: nsec1...
home_relay: wss://relay.example
```

Once the relay-backed records have been populated, this is sufficient to recover:

- the profile index
- the active profile
- aliases
- per-profile settings
- per-profile signer secrets

## Relay-Backed Authoritative Configuration

The authoritative OpenETR CLI configuration should live on relays as signed events under the root CLI key.

This state should be:

- signed by the root key
- encrypted to the root key where content is sensitive
- recoverable from one or more relays
- structured so that logical configuration components can be read and updated independently

This means the relay-backed state can be reconstructed on a new machine without requiring manual migration of a large local config file.

## Preferred Event Shape

The current preferred direction is to use addressable records for relay-backed configuration.

For this purpose, OpenETR should use:

- kind `31500`
- one logical record per label
- a deterministic `d` tag derived from the label using the root secret as a salt

This follows the same general approach already used in the Acorn component.

The key idea is that configuration records should be:

- independently addressable
- replaceable by later updates to the same logical record
- hard to enumerate meaningfully without knowledge of the label derivation rule

The exact label-to-`d` derivation should be deterministic for the root key holder and stable across machines.

### Current Working Convention

The current OpenETR CLI implementation uses:

- kind `31500`
- NIP-44 encrypted event content
- Pydantic models for structured record payloads
- a deterministic `d` tag derived from the record label using the root secret as a salt

This is now the active working convention for relay-backed CLI configuration.

## Record Label Index

The relay-backed configuration model also needs a record label index.

This is necessary because the CLI must know which logical labels exist before it can derive the corresponding salted `d` tags and retrieve the associated records.

Without a record label index, the CLI would know how to derive a `d` tag only for labels it already knew in advance.

That is not enough for full recovery of relay-backed state on a new machine.

The record label index should therefore serve as the discovery entrypoint for the rest of the configuration.

Its function is to tell the CLI:

- which configuration labels currently exist
- which record categories are expected
- which profile labels are present
- which additional records should be fetched and decrypted

In effect, the record label index is the table of contents for the relay-backed configuration space.

## Preferred Index Shape

The preferred design is for the record label index itself to be a kind `31500` addressable record.

It should be:

- signed by the root CLI key
- encrypted with NIP-44 to the root public key
- serialized from a Pydantic model
- located through a stable well-known label known to the CLI implementation

That stable label can itself be converted into a salted `d` tag using the same deterministic derivation rule.

This allows the CLI to recover the label index first, and then use the index contents to derive and fetch the remaining configuration records.

## What the Index Should Contain

The record label index should contain enough information to let the CLI rebuild the relay-backed configuration map.

At a minimum, it should include:

- the known configuration labels
- the record category for each label
- the set of named profile labels
- the set of reserved or well-known labels
- optional schema or version metadata

For example, the index may point to logical records such as:

- `config:root`
- `config:active_profile`
- `config:aliases`
- `config:defaults`
- `config:profile:shipper`
- `config:profile:buyer`

The exact schema can be finalized later, but the design requirement is clear:

the CLI must be able to recover the list of label names before it can derive all of the `d` tags needed for record retrieval.

### Current Reserved Records

The current implementation uses or is converging on the following reserved relay-backed records:

- `profiles`
  stores the known profile names and the active profile
- `aliases`
  stores nickname-to-`npub` mappings
- `config:profile:<name>`
  stores the non-secret operational settings for a named profile
- `config:profile:<name>:as_user`
  stores the encrypted signer secret for a named profile

## Why Labeled Records Are Better Than One Big Blob

OpenETR should prefer labeled relay-backed configuration records over one monolithic encrypted config object.

A single blob is possible, but labeled records are the stronger design.

They allow OpenETR to:

- update one profile without rewriting all configuration
- update aliases without touching profile data
- rotate the active profile independently
- inspect and debug configuration components more clearly
- replicate or cache specific records more easily

A labeled-record model also matches the way OpenETR already thinks about state:

- distinct objects
- distinct actions
- signed units of meaning

That is a more natural protocol shape than one large opaque document.

## Proposed Record Categories

The following relay-backed configuration categories would be a reasonable first model:

- `config:root`
  CLI-level metadata and versioning
- `config:active_profile`
  the currently selected profile name
- `config:profile:<name>`
  one record per named operational profile
- `config:aliases`
  nickname-to-`npub` mappings
- `config:defaults`
  CLI defaults such as relay preferences or timeouts

The exact names are illustrative.

The important point is the separation of logical concerns into independent relay-backed records.

Each such category would be represented as its own kind `31500` addressable record.

The record label index would describe which of these records currently exist.

The implementation has now effectively specialized these categories into a small set of concrete reserved records used by the CLI.

## Structured Payloads

Relay-backed configuration content should be represented as structured application data rather than ad hoc string blobs.

The preferred approach is to define the content payloads with Pydantic models.

That gives OpenETR:

- explicit schemas
- validation on read and write
- easier migration between versions
- a clearer API path later when the CLI logic is extracted into reusable Python services

Examples may include models for:

- root configuration
- active profile selection
- profile configuration
- alias mappings
- default operational settings

The relay event content should therefore be treated as serialized structured data, not as arbitrary free-form text.

The current implementation uses Pydantic-backed structured payloads for:

- the profile index
- the alias index
- per-profile operational settings
- per-profile signer secrets

## Proposed Profile Record Contents

A relay-backed profile record may contain fields such as:

- profile name
- encrypted `nsec` for the operational signer
- derived `npub`
- default relay list
- query timeout
- publish wait
- local display metadata

Sensitive material such as `nsec` values should not be stored as plain content.

They should be encrypted to the root key.

## Encryption Boundary

Not all configuration data has the same sensitivity.

OpenETR should distinguish between:

- public or low-sensitivity metadata
- private signer material

At a minimum:

- operational `nsec` values must be encrypted
- any sensitive default settings should be encrypted
- public alias maps may be left unencrypted only if that is a conscious design choice

The safer default is to encrypt the relay-backed configuration records and let the root key recover them.

This preserves portability without making signer material public.

The preferred mechanism is NIP-44 encryption.

That means:

- configuration payloads are serialized from Pydantic models
- the serialized payload is encrypted to the root public key using NIP-44
- the encrypted payload is stored as the event content
- the root key can later decrypt and reconstruct the structured record on any machine

This is a strong fit for OpenETR because it preserves:

- portability
- key-bound recoverability
- structured data integrity at the application layer

## Deterministic Record Addressing

Relay-backed configuration records should be stored in a way that lets the CLI find them deterministically.

That should be done with addressable records keyed by a stable label-derived `d` tag.

A practical pattern is:

- one label per logical record
- a deterministic digest of the label using the root secret as a salt

In practical terms, the `d` tag can be derived by hashing:

- the label
- together with root-key-derived secret material

This gives the CLI a stable way to retrieve the same record on any machine while also avoiding plain, human-readable labels on the relay.

This gives OpenETR:

- stable lookup
- addressable replacement semantics
- predictable retrieval on a new machine

The exact derivation rule should be specified explicitly in a later implementation note or event-format draft.

The design requirement is that the CLI can locate a specific config record without scanning arbitrary history.

That requirement depends on two things together:

- deterministic salted `d` tag derivation
- recovery of the label set through the record label index

## Home Relay and Replication

The relay-backed model does not require a single relay forever.

But it should define a home relay concept for bootstrap and recovery.

The home relay is simply the place the CLI looks first.

It is not the sole authoritative database in a platform sense.

OpenETR should support:

- one home relay for primary recovery
- optional replication to additional relays

That way the configuration remains:

- portable
- backed by multiple independent stores
- still recoverable if one relay disappears

This fits the larger OpenETR claim that important protocol state can exist across multiple independent relays rather than inside one application boundary.

## Relationship to Kind `0` Social Profiles

Relay-backed CLI configuration is different from kind `0` social profile metadata.

Kind `0` is for public-facing identity metadata such as:

- name
- display name
- address
- LEI
- website

Relay-backed CLI configuration is for operational state such as:

- which named profiles exist locally for the operator
- which profile is active
- which alias points to which actor
- which operational key is used for which named profile

These should remain conceptually separate even if both are stored on relays.

The current OpenETR implementation therefore distinguishes clearly between:

- relay-backed CLI administration records under the root CLI key
- public kind `0` social profile records under the operational profile keys

## Advantages

This model provides several important benefits.

### 1. Machine Portability

A user can move to a new machine with only:

- the root key
- the home relay(s)

and recover CLI state.

### 2. Signed Administrative State

Configuration becomes attributable to a key and protected by signature, rather than being merely an editable local file.

### 3. Better Fit With OpenETR Philosophy

OpenETR already treats signed relay-distributed events as the basis of operational truth.

Relay-backed configuration extends that same ethos to CLI administration.

### 4. Reduced Dependence on One Local Installation

The user's environment no longer depends on one disk image or copied YAML file as the authoritative state.

### 5. Easier Recovery and Replication

The same relay-distributed model used for records can support resilient recovery of operator state.

## Tradeoffs and Risks

This model also introduces new considerations.

### 1. Relay Availability

Configuration recovery depends on the availability of at least one reachable relay holding the records.

This argues for replication and optional local caching.

### 2. Key Management

The root CLI key becomes important administrative infrastructure.

If it is lost, recovery of encrypted relay-backed config may be difficult or impossible.

### 3. Privacy

Even if content is encrypted, metadata such as event timing or record existence may still be observable.

### 4. Migration Complexity

Moving from a purely local config file to relay-backed state requires careful migration logic and compatibility behavior.

## Recommended Transition Path

OpenETR should not replace the current `config.yaml` model all at once.

A staged approach is better.

### Stage 1

Keep `config.yaml` as the source of truth, but add the ability to export or mirror configuration to relays.

### Stage 2

Treat relay-backed configuration as the source of truth and local YAML as bootstrap plus cache.

### Stage 3

Allow a fresh installation to bootstrap directly from:

- root key
- home relay

with no prior full local configuration file required.

In that final model, the CLI bootstrap sequence would be:

1. use the local bootstrap to learn the root key and home relay
2. derive and fetch the record label index
3. decrypt the label index
4. derive the salted `d` tags for the indexed labels
5. fetch and decrypt the remaining configuration records
6. reconstruct the usable CLI state

### Current Position

OpenETR is now effectively between Stage 2 and Stage 3.

The CLI can already:

- bootstrap from a root `nsec` and home relay
- recover relay-backed profile and alias information
- recover relay-backed per-profile settings
- recover relay-backed signer secrets

The local file is therefore being reduced to bootstrap information rather than continuing as the authoritative operational store.

This staged path reduces migration risk while moving toward the more portable architecture.

## Open Questions

The final design still needs decisions on:

- which event kinds should be used for relay-backed config
- whether each record category gets its own kind or shares a family
- whether labels should be public or obfuscated
- how local cache invalidation should work
- how conflict resolution should work if multiple relay copies disagree
- how root-key rotation should be handled

## Working Conclusion

OpenETR should move toward a relay-backed configuration model.

The likely best shape is:

- a small local bootstrap file
- a root CLI key used for configuration administration
- encrypted labeled configuration records on relays
- separate operational profile keys for actual OpenETR actions

That model is more portable, more attributable, and more aligned with the broader OpenETR design philosophy than relying on a machine-local `config.yaml` as the sole authoritative configuration store.
