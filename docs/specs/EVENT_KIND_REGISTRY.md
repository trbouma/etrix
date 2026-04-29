# Event Kind Registry

This document is the working registry for OpenETR event kinds.

Its purpose is to provide one canonical place to track:

- event kind numbers
- event kind names
- current status
- intended purpose
- related specifications
- implementation notes

This registry is a draft and may change as the OpenETR model evolves.

## Status Values

Suggested status values:

- `working` for active experimental assignments
- `draft` for proposed but not yet adopted assignments
- `reserved` for intentionally held future assignments
- `deprecated` for assignments that should no longer be used

## Registry

| Kind | Name | Status | Purpose | Notes |
|------|------|--------|---------|-------|
| `31415` | origin event | working | Initial OpenETR record bringing an object into the scheme | Currently used for initial issuance/origin flows |
| `31416` | control transfer event | working | Transfer of control after origin | Intended for later control-history traversal |

## Current Interpretation

### `31415` Origin Event

The origin event is the initial event by which an object enters the OpenETR scheme.

Current intended role:

- establish the initial OpenETR record
- bind the object identifier into the scheme
- serve as the starting point for later control analysis

### `31416` Control Transfer Event

The control transfer event is the event family intended to express later movement of control.

Current intended role:

- represent transfer after origin
- support later exclusive-controller determination
- separate control movement from initial origin

## Related Specifications

- [CANONICAL_ETR_TRANSACTION_SPEC.md](./CANONICAL_ETR_TRANSACTION_SPEC.md)
- [TITLE_TRANSFER_AUTHORITY_REPLACEABLE_EVENT_SPEC.md](./TITLE_TRANSFER_AUTHORITY_REPLACEABLE_EVENT_SPEC.md)

## Notes

- This registry does not yet define all future OpenETR event kinds.
- Endorsement, termination, substitution, cancellation, revocation, and attestation kinds are still open design areas.
- Event kind assignment alone does not determine legal or operational effect; effect depends on the wider OpenETR attestation and recognition model.
