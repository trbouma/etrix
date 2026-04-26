# Title Transfer Authority Replaceable Event Specification

This note describes a proposed implementation of title and transfer attestations on Nostr using replaceable events.

It is intended as a companion to [TITLE_TRANSFER_AUTHORITY_TRUST_ASSUMPTIONS.md](TITLE_TRANSFER_AUTHORITY_TRUST_ASSUMPTIONS.md).

## Purpose

The goal is to represent current title for a digest-identified object using a simple Nostr-native event model that is:

- searchable by object digest
- attributable to a designated authority pubkey
- easy to republish across relays
- simple to validate from relay data

The design assumes that title is determined by a designated `Title Transfer Authority` (`TTA`) rather than by self-assertion from end users.

## Design Choice

The proposed implementation uses parameterized replaceable events.

Rationale:

- the object identifier can be placed in the `d` tag
- the most recent valid event for a given `pubkey + kind + d` tuple becomes the authoritative current state for that authority and object
- events remain queryable by digest using `#d`
- the authority can update or transfer title by publishing a new event with the same `d` value

## Proposed Event Kind

Use a dedicated custom kind for title records.

Recommended starting point:

- `kind = 31415`

This is only a working value for experimentation. A production deployment should choose and document a stable application kind.

## Object Identifier

Each titled object is identified by a stable digest.

Recommended format:

- lowercase hex SHA-256 digest

The digest is stored in:

- `d` tag: the canonical object identifier for replaceable addressing
- optional `o` tag: a secondary generic object tag for cross-kind or cross-schema indexing

Minimum required identifier:

- `d`

Recommended optional duplication:

- `o`

Using `o` is optional. If the system only needs replaceable addressing, `d` is sufficient.

## Authority Model

The event `pubkey` should be the pubkey of the `Title Transfer Authority`.

This means:

- end users do not create authoritative title events
- the TTA signs the event that states current title
- the TTA is the source of truth for title changes

## Event Semantics

Each event represents the TTA's current authoritative statement about title for a single object digest.

Because the event is replaceable for the tuple `pubkey + kind + d`, only one current state exists per:

- Title Transfer Authority
- object digest

Different TTAs may issue different records for the same digest. That is acceptable, but any implementation must define which TTA or set of TTAs it recognizes as authoritative.

## Required Tags

The following tags are required:

- `["d", "<digest>"]`
- `["p", "<current_title_holder_pubkey>"]`

Recommended required meaning:

- `d` identifies the object
- the first `p` tag identifies the current title holder

## Optional Tags

The following tags are recommended where applicable:

- `["o", "<digest>"]`
- `["from", "<previous_title_holder_pubkey>"]`
- `["e", "<previous_tta_event_id>"]`
- `["version", "1"]`
- `["action", "issue"]` or `["action", "transfer"]`
- `["timestamp", "<iso8601 or unix time>"]`
- `["jurisdiction", "<text>"]`
- `["asset_class", "<text>"]`

Suggested meanings:

- `o`: optional duplicate digest tag for generic indexing
- `from`: previous title holder if the event records a transfer
- `e`: previous authoritative TTA event being superseded
- `version`: schema version
- `action`: whether the event is an initial issuance, transfer, correction, or revocation
- `timestamp`: business-level event timestamp if needed in addition to `created_at`
- `jurisdiction`: legal or operational context
- `asset_class`: category of object or rights being titled

## Content

The `content` field should contain a human-readable summary of the attestation.

Suggested content:

- object name or file name
- digest generation timestamp if relevant
- file size or descriptive metadata
- issuance or transfer notes
- case or reference number

The `content` field is informational. Validation should depend on signed tags and event metadata rather than parsing free text content.

## Canonical Validation Rules

An event is considered a valid title record if all of the following are true:

- the event signature is valid
- the event kind matches the configured title-record kind
- the event pubkey is a recognized TTA pubkey
- the event has exactly one valid `d` tag
- the event has at least one valid `p` tag
- the `d` tag contains a supported digest format

If `o` is present, it should match the `d` value.

If `e` is present, it should reference the prior TTA event being replaced.

## Current Title Resolution

For a given digest, current title is determined as follows:

1. Query for events with `kind = <title kind>` and `#d = <digest>`.
2. Discard events not signed by a recognized TTA.
3. Discard malformed or invalidly signed events.
4. Group remaining events by TTA pubkey.
5. For each TTA pubkey, select the latest valid replaceable state for `kind + d`.
6. Read the first `p` tag on that event as the current title holder designated by that TTA.

If the system recognizes a single TTA, then the result is a single current title holder for that digest.

If the system recognizes multiple TTAs, then the application must define conflict resolution rules, for example:

- one configured primary TTA
- a ranked list of trusted TTAs
- jurisdiction-specific TTA selection
- explicit rejection of conflicting records

## Transfer Model

A transfer is represented by a new replaceable event with the same:

- `kind`
- `d`
- TTA `pubkey`

and an updated current-title-holder `p` tag.

Recommended transfer event shape:

- `["d", "<digest>"]`
- `["p", "<new_title_holder_pubkey>"]`
- `["from", "<previous_title_holder_pubkey>"]`
- `["e", "<prior_tta_event_id>"]`
- `["action", "transfer"]`

The old state is not deleted from relays in a global sense, but the new event becomes the current authoritative state for that TTA and digest.

## Issuance Model

An initial title issuance is represented by a replaceable event with:

- `["d", "<digest>"]`
- `["p", "<title_holder_pubkey>"]`
- `["action", "issue"]`

It may omit `from` and `e` because there is no prior title state in the registry.

## Correction and Revocation

The same replaceable mechanism can support corrections and revocations.

Suggested patterns:

- correction: publish a new event with the same `d`, corrected tags, and `["action", "correct"]`
- revocation: publish a new event with the same `d` and `["action", "revoke"]`

If revocation is supported, the implementation should define whether:

- title becomes undefined until a new issuance occurs
- title reverts to a prior valid state
- title is marked disputed or suspended

This behavior must be defined by policy, not inferred only from Nostr mechanics.

## Search Model

The minimum required query is:

```python
{
    "kinds": [31415],
    "#d": ["<digest>"]
}
```

If `o` is also used, additional queries may be supported:

```python
{
    "kinds": [31415],
    "#o": ["<digest>"]
}
```

For authoritative resolution, `#d` should be treated as canonical.

## Why Replaceable Events

This approach uses replaceable events because they naturally model current state.

Benefits:

- simple query model
- simple update model
- one current record per TTA and digest
- relay-native behavior without external indexing requirements beyond tag search

Limitations:

- history may still need to be collected across relays
- relay retention is not guaranteed
- governance and trust remain external to the protocol
- current state is only meaningful relative to recognized TTA pubkeys

## Path Toward an Open MLETR-Style System

This model may provide a foundation for an open system inspired by the goals of MLETR, especially where the objective is to treat a digital artifact as a uniquely controlled transferable record rather than as a mere copyable file.

The core idea is that an ordinary electronic artifact such as:

- a PDF
- a JPG
- a bill of lading image
- a warehouse receipt PDF
- a promissory note document
- any other digitally represented record

can be assigned a stable digest and then bound to an authoritative title record published by a recognized Title Transfer Authority.

In that design, the artifact itself remains an ordinary file, but the authoritative title state for that artifact is externalized into a signed replaceable event keyed by digest. The transferable quality does not come from the file format itself. It comes from the combination of:

- a unique object identifier
- an authoritative control record
- a transfer process governed by the Title Transfer Authority
- a way to determine the current holder of title from the latest valid attestation

### Why This Maps to MLETR-Like Objectives

At a high level, systems inspired by MLETR need to support functional equivalents for concepts such as:

- singularity
- exclusivity
- control
- transferability

This model can support those objectives in the following way:

- singularity: the digest acts as the canonical object identifier
- exclusivity: the current authoritative title state is the latest valid TTA event for that digest
- control: authority over the title state is exercised through the TTA-issued attestation chain
- transferability: title is transferred when the TTA publishes a new authoritative event naming a new current holder

The result is that a common digital artifact can be treated as the subject of a transferable title regime without requiring the artifact itself to live on a blockchain or within a proprietary platform database.

### Open System Characteristics

This approach can become an open system if the following properties are preserved:

- the artifact identifier is based on an open digest standard
- the event format is publicly documented
- the title and transfer records are published over an open relay protocol
- validation rules are transparent and implementable by any participant
- multiple clients can independently query and verify current title state

In this sense, the registry is portable and inspectable. Any participant with relay access and the TTA trust anchor can reconstruct current title status for a digest-identified artifact.

### Turning an Artifact into a Transferable Electronic Document

Under this model, an electronic artifact becomes a transferable electronic document in a practical registry sense when:

1. the artifact is reduced to a canonical digest
2. the digest is bound to a TTA-issued title event
3. the TTA recognizes a current title holder through the first `p` tag or equivalent title-holder tag
4. subsequent transfers are represented by later TTA-issued replaceable events for the same digest

At that point, the operative document is not only the PDF, image, or file. It is the combination of:

- the artifact
- its digest
- the current authoritative title attestation

This is what allows a plain electronic artifact to function as a transferable record within the registry.

### Important Legal Qualification

This specification does not claim that publication of these events alone automatically satisfies MLETR or any specific legal regime.

Whether a given implementation is legally effective will depend on:

- applicable law
- recognition of the Title Transfer Authority
- adequacy of the control and transfer procedures
- evidentiary and governance requirements
- whether the implementation satisfies the relevant functional-equivalence standards in the target jurisdiction

The more modest and accurate claim is that this design can provide a technical architecture that is compatible with the kinds of singularity, exclusivity, control, and transferability properties that an open MLETR-style system would need.

### Practical Implication

If implemented carefully, this model could allow open-network title and transfer records for ordinary electronic artifacts without requiring:

- a proprietary registry operator
- a closed platform authentication model
- a smart contract as the source of legal authority

Instead, the system would rely on:

- open digest-based identification
- public relay-based publication
- transparent validation rules
- a recognized Title Transfer Authority as the trust anchor

## Open Questions

The following items remain to be finalized:

- final event kind selection
- exact tag vocabulary
- whether `o` should always duplicate `d`
- title-holder key rotation semantics
- dispute handling
- revocation behavior
- multi-TTA conflict resolution
- whether `content` should be free text or structured JSON

## Minimal Example

Example title event:

```json
{
  "kind": 31415,
  "pubkey": "<tta_pubkey>",
  "tags": [
    ["d", "<sha256_digest>"],
    ["o", "<sha256_digest>"],
    ["p", "<current_title_holder_pubkey>"],
    ["action", "issue"],
    ["version", "1"]
  ],
  "content": "name=artifact1.pdf; digest_generated_at=2026-04-13T12:00:00Z; size_bytes=123456"
}
```

Example transfer event:

```json
{
  "kind": 31415,
  "pubkey": "<tta_pubkey>",
  "tags": [
    ["d", "<sha256_digest>"],
    ["o", "<sha256_digest>"],
    ["p", "<new_title_holder_pubkey>"],
    ["from", "<previous_title_holder_pubkey>"],
    ["e", "<prior_tta_event_id>"],
    ["action", "transfer"],
    ["version", "1"]
  ],
  "content": "Transfer of title for digest-identified object"
}
```
