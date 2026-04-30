# Transfer Validation Guards Design Note

This note explains the role of CLI-side validation guards in the OpenETR transfer flow.

It is not a claim that OpenETR can prevent all invalid or conflicting events from being published.

Instead, it defines why local validation rules still matter and how they can serve as an early expression of the policy that future attestors may apply before recognizing or attesting control-relevant events.

An underlying philosophy of the OpenETR protocol is:

> Transact globally, validate locally.

This is a deliberate play on "think globally, act locally."

OpenETR allows parties to publish and exchange control-relevant events in a shared global environment, while leaving validation, attestation, and recognition to the local policy of the party who must decide whether to rely on the resulting chain.

## Status

Draft.

## Purpose

OpenETR is an open event scheme.

That means a participant can still publish events that:

- violate local workflow assumptions
- conflict with earlier events
- reference the wrong object or wrong prior event
- omit information that a stricter implementation would require

The existence of that possibility does not weaken the value of validation rules.

It clarifies their proper role.

Validation guards in the CLI are useful because they:

- make the expected transaction grammar explicit
- reduce accidental misuse by ordinary operators
- provide a practical reference implementation of OpenETR policy
- create an early executable model of the checks that attestors may later apply before attesting events

## Historical Context

OpenETR can also be understood against the background of global shipping and the historical ethos of the high seas.

Maritime trade developed across jurisdictions long before any single sovereign could govern global trade end to end.

Commerce at sea therefore depended on records, customs, and recognition practices that could travel across ports, carriers, merchants, financiers, and legal systems.

The high seas were not the domain of any one platform or any one legal authority.

What mattered was whether a record, claim, or act would be recognized by the party who needed to rely on it.

In that sense, OpenETR is an attempt to replicate digitally some of the same operating ethos:

- publication in a shared global environment
- movement across institutional and jurisdictional boundaries
- reliance on signed and reviewable evidence
- recognition by the relevant relying party rather than by a single controlling system

Just as maritime trade evolved to function across open waters and multiple jurisdictions, OpenETR is designed to function across an open digital environment where publication is global but recognition remains local.

## Core Distinction

OpenETR does not depend on the network preventing publication.

Instead, OpenETR depends on accountable recognition of valid actions.

The distinction is:

- publication is open
- recognition is conditional
- attestation is accountable

This means the question is not:

> Can an invalid event be published?

It is:

> Under what rules would an identifiable attestor refuse to attest or recognize that event?

CLI guards are therefore not final enforcement.

They are an executable expression of those rules.

## Why Guards Matter Even If They Can Be Bypassed

A bypassable rule can still be valuable if it clearly states the expected policy.

In OpenETR, that value appears in four places.

### 1. User Safety

Operators using the CLI should be protected from accidental mistakes such as:

- referencing the wrong prior event
- initiating a transfer from the wrong object history
- publishing a conflicting replaceable transfer event
- accepting a transfer that does not correspond to the expected object or intended counterparty

### 2. Policy Clarity

If a rule is implemented in the CLI, it is no longer merely implied.

It becomes a concrete statement of expected behavior.

That helps make future attestation logic easier to define and review.

### 3. Auditability

A validation rule that is explicit in code and in specifications can be:

- reviewed
- tested
- challenged
- revised

That is stronger than relying on vague operator intuition.

### 4. Attestor Alignment

Attestors do not need to trust that every event on the network is valid.

They need to know what checks they are expected to perform before attesting a control-relevant action.

CLI guards provide an early, concrete form of that checklist.

## Validation as Attestor Policy

OpenETR should treat transfer validation rules as part of the emerging attestor policy layer.

That does not mean:

- MLETR requires a specific checklist
- every CLI rule is automatically legally decisive
- a relay or client can define legal effect on its own

It does mean:

- OpenETR can define the conditions under which a transfer event is considered valid for recognition
- attestors can later rely on those conditions when deciding whether to attest an event
- the CLI can serve as a reference implementation of those conditions

This supports the broader OpenETR position that reliability is attributable to accountable actors applying policy, not to platform behavior alone.

## Recommended Rule Classes

Not every validation concern needs the same outcome.

OpenETR should classify validation rules into three categories.

### Error

The command should block publication or completion.

Examples:

- a referenced prior event cannot be found
- a transfer chain cannot be resolved back to a valid origin event
- the object identifier in a referenced event is missing or inconsistent
- an accept event references an event that is not a valid transfer initiate event

### Warning

The command should allow the action but require operator confirmation.

Examples:

- a replaceable transfer slot already contains an event for the same object and action
- multiple origin events exist for the same object
- a later event may supersede an earlier event but the operator is still choosing to proceed

### Attestor Note

The CLI may not yet block or warn, but the condition should be documented as a future recognition or attestation check.

Examples:

- whether the initiating party is the latest recognized controller
- whether a transfer is in conflict with another pending transfer for the same object
- whether the relevant attestor policy recognizes a particular signer or counterparty

## Initial Transfer Rules to Formalize

The next practical step is to formalize the first transfer checks directly in the CLI and specs.

### Transfer Initiate

Candidate validation rules:

- the supplied prior event must exist
- the supplied prior event must be either:
  - a valid origin event, or
  - a valid control transfer event that can be traversed back to an origin event
- the resulting origin event must belong to the same object being transferred
- the transferee must be a valid counterparty identifier
- a conflicting replaceable initiate event for the same object and signer should trigger a warning
- if the supplied prior event is a `kind 31415` origin event, the signer of the new `kind 31416` event should match the issuer of that origin event
- if the supplied prior event is a `kind 31416` control transfer event, the signer of the new `kind 31416` event should match the transferee identified in the prior transfer event's `p` tag
- if a subsequent transfer initiate is being published before a corresponding accept event has been observed for the prior transfer event, the CLI may warn but still allow publication

### Transfer Accept

Candidate validation rules:

- the referenced initiate event must exist
- the referenced event must actually be a transfer initiate event
- the object identifier must be present and valid
- the accept event must point to the intended initiate event
- the signer of the accept event should match the intended transferee identified in the initiate event's `p` tag
- a conflicting replaceable accept event for the same object and signer should trigger a warning or block, depending on policy

## Working Publication Model for Initiate and Accept

OpenETR should distinguish between structural invalidity, incomplete acknowledgment, and full attestation validity.

This suggests the following working model for transfer events:

- a `transfer initiate` event may reference a prior `kind 31416` transfer event even if no corresponding accept event has yet been observed
- the absence of a corresponding accept event should be surfaced as a warning rather than a hard block
- a `transfer accept` event should reference a `kind 31416` initiate event and should be signed by the transferee identified in that initiate event
- attestors may later require the full initiate-and-accept sequence before recognizing a subsequent transfer as fully valid

Under this model:

- publication remains open
- structural invalidity is still blocked
- incomplete acknowledgment is visible to operators
- attestors retain the ability to require stricter completion rules for recognition

OpenETR therefore permits unilateral transfer initiation.

Whether that initiation is sufficient for recognized transfer of control is a matter for attestation or assessment policy, which may require a corresponding accept event.

This may be useful where an ETR needs to operate in real time, where participants cannot wait for attestors to catch up, or where the parties do not require the added formality of attestation for a particular transfer step.

OpenETR therefore provides evidence of control-relevant actions.

It does not by itself determine their final legal or operational effect.

Recognition remains a matter for the party applying the relevant assessment or attestation policy.

This also means that more than one candidate control chain may appear for the same object.

OpenETR does not necessarily prevent conflicting or competing control histories from being published.

Instead, it makes those histories visible as signed evidence so that the relevant assessor, attestor, or relying party can decide which chain, if any, should be recognized under the applicable policy.

This preserves a useful distinction between:

- publication rules, which determine whether an event is well-formed enough to be issued
- warning rules, which surface incompleteness or ambiguity without preventing publication
- attestation rules, which determine whether the resulting transfer chain is sufficient for recognition

## Design Principle

OpenETR should not confuse publication with validity.

The more accurate principle is:

> Events may be published openly, but recognition and attestation depend on explicit validation rules.

CLI guards are one of the first places those rules become visible and testable.

## Operational Consequence

As the CLI evolves, transfer validation should be treated as more than user-interface polish.

It is part of the specification effort.

Each new guard should ideally answer three questions:

1. What condition is being checked?
2. Why does that condition matter for valid recognition of the action?
3. Should failure produce an error, a warning, or only an attestor note?

That keeps implementation and policy aligned.

## Summary

OpenETR validation guards are valuable even if they do not make invalid publication impossible.

Their real purpose is to:

- reduce operator error
- formalize transaction expectations
- make attestor policy concrete
- support accountable recognition of control-relevant events

OpenETR is designed to operate in an open, permissionless environment.

It does not prevent every action at the protocol layer.

Instead, it provides a sound cryptographic basis for recognition by making control-relevant actions signed, attributable, and reviewable.

In this sense, CLI validation is not merely defensive tooling.

It is an early executable form of OpenETR's attestation policy.
