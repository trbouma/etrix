# Canonical ETR Transaction Specification

This draft defines a canonical interaction model for OpenETR transactions.

It focuses on control-relevant actions and the minimum attestable structure required for an OpenETR scheme to express:

- issuance
- transfer
- endorsement
- termination
- revocation of incomplete actions

The purpose of this note is not to prescribe one legal implementation for all use cases. It is to define a canonical transaction grammar that can be:

- independently attested
- independently recognized
- evaluated under explicit policy
- aligned with MLETR-style reliability requirements without relying on platform trust

## Status

Draft.

## Purpose

OpenETR treats legal effect as the result of attested actions rather than as the product of a platform or registry asserting state.

That means the canonical question is not:

> What does the system say happened?

It is:

> Which actions were declared, accepted where required, attested by accountable parties, and recognized under policy?

This specification defines the minimal matrix for answering that question.

## Core Principle

All control-relevant actions must be independently attested.

Legal effect arises only when all required actions are:

- performed
- attested
- recognized

In this model, attestation applies to each action, not merely to the final outcome.

## Canonical Interaction Matrix

| Lifecycle | Declare (Initiator) | Accept (Counterparty) |
|-----------|----------------------|------------------------|
| Issue | Declare Issue -> Attest(Declare) | — |
| Transfer | Declare Transfer -> Attest(Declare) | Accept Transfer -> Attest(Accept) |
| Endorse | Declare Endorsement -> Attest(Declare) | Accept Endorsement -> Attest(Accept) |
| Terminate | Declare Termination (Release / Cancel / Substitute) -> Attest(Declare) | — |

## Foundational Rule

Effect exists only when all required actions are attested and recognized.

Therefore:

- Issue requires `Declare + Attest`
- Transfer requires `Declare + Accept + Attest(Declare) + Attest(Accept)`
- Endorse requires `Declare + Accept + Attest(Declare) + Attest(Accept)`
- Terminate requires `Declare + Attest`

Recognition is external to raw event publication. An event may exist on relays and still lack effect if the required action set has not been completed or if the attestors are not recognized under policy.

## Terms

### Object

The electronic transferable record or the canonical object identifier to which a transaction applies.

### Controller

The party capable of exercising control over the object at a given moment.

### Initiator

The party that declares a control-relevant action.

### Counterparty

The party whose acceptance is required for the action to become effective.

### Attestor

An identifiable signing party whose attestation anchors accountability for the application of policy to a specific action.

### Recognition

The policy act of treating an attested action set as effective for the relevant legal or operational context.

## Canonical Action Types

### 1. Issue

Issue is the initial declaration that an object is being brought into effective circulation under the scheme.

Required actions:

- declare issue
- attest the declaration

No counterparty acceptance is required for issue in the canonical model.

Issue becomes effective only when the declaration is both:

- attested
- recognized

### 2. Transfer

Transfer is the movement of control from one controller to another.

Required actions:

- declare transfer by the initiating side
- accept transfer by the receiving side
- attest the declaration
- attest the acceptance

Transfer becomes effective only when all four action components are recognized.

### 3. Endorse

Endorsement is the application of additional meaning, authority, approval, or delegated effect to the object or to a pending transaction concerning the object.

Required actions:

- declare endorsement
- accept endorsement
- attest the declaration
- attest the acceptance

This keeps endorsement aligned with the same bilateral accountability rule as transfer when the endorsement affects control-relevant status.

### 4. Terminate

Termination ends or supersedes the current effective state of an object within the scheme.

Canonical termination forms include:

- release
- cancel
- substitute

Required actions:

- declare termination
- attest the declaration

No counterparty acceptance is required in the canonical model, although an application profile may impose one.

## Working Event Kind Allocation

For the current OpenETR reference direction, canonical transaction families are split across distinct event kinds.

The working registry for these assignments is maintained in [EVENT_KIND_REGISTRY.md](./EVENT_KIND_REGISTRY.md).

Working allocation:

- `31415` = origin event
- `31416` = control transfer event

### Origin Event

The origin event is the event by which an object first enters the OpenETR scheme.

It is intended to represent:

- initial issuance
- initial declaration of the object within the scheme
- the first effective control-relevant state for that object

In the current working model, origin events are published as:

- `kind = 31415`

### Control Transfer Event

The control transfer event is the event by which control moves after origin.

It is intended to represent:

- transfer of control from one controller to another
- later control transitions in the object lifecycle

In the current working model, control transfer events are published as:

- `kind = 31416`

### Why Split Kinds

This split is useful because it distinguishes:

- the event that brings an object into the scheme
- the events that subsequently move control over that object

That separation improves:

- query clarity
- lifecycle reasoning
- validation logic
- traversal of control history

It also allows an implementation to identify the initial OpenETR record without inferring it only from timestamps or event ordering within a single mixed event family.

### Current Scope

This specification currently treats the following as the working minimum:

- issue/origin mapped to `31415`
- control transfer mapped to `31416`

Endorsement, termination, substitution, cancellation, and revocation may later receive their own event kinds or remain subtyped within broader event families depending on implementation experience.

This allocation should therefore be treated as:

- current working convention
- not yet a final permanent registry decision

## Query Implications

Under this split-kind model:

- initial-record discovery should query origin events
- control-history traversal should query control transfer events
- full object-state evaluation will typically need both event families

In practice that means an implementation may need to:

1. query the object's origin event using `kind = 31415`
2. query subsequent control transfer events using `kind = 31416`
3. evaluate the attested action chain across both families

This is consistent with the broader OpenETR design goal of making lifecycle semantics explicit rather than collapsing all control-relevant actions into one undifferentiated event stream.

## Replaceable Events and Attested Binding Effect

OpenETR does not require raw transaction events to be permanently preserved at the relay layer in order for them to matter.

The current design direction assumes that canonical transaction events may be published as Nostr replaceable events.

That means there may be nothing at the relay layer alone to prevent an author from:

- replacing the event
- deleting the event from a particular relay's retained view
- making the event difficult to recover later from ordinary relay queries

This is not treated as a fatal flaw in the scheme.

### Core Distinction

OpenETR distinguishes between:

- the transaction event
- the attestation event

The transaction event expresses the underlying control-relevant act.

The attestation event expresses the accountable statement that the act was witnessed, evaluated under policy, and recognized for effect.

In this model, binding effect does not arise from the relay persistence of the underlying transaction event alone.

Binding effect arises when an identifiable attestor issues an attestation referencing that transaction event and thereby assumes accountability for having witnessed and evaluated it.

### Consequence

An event may later be replaced, removed, or become unavailable from common relay views, while an attestation concerning it still remains the binding evidence that the event existed and satisfied policy at the relevant time.

The attestation therefore functions as:

- witnessed evidence
- policy-bearing evidence
- accountability-bearing evidence

### Trust Anchor

The trust anchor in OpenETR is not platform behavior.

It is the accountable use of protocol by recognized attestors.

This means the scheme does not ultimately rely on the proposition:

> the platform preserved the event, therefore the effect is trustworthy

Instead, it relies on the proposition:

> the attestor is accountable for having witnessed and evaluated the event under policy

### Why This Matters

This distinction allows OpenETR to avoid making legal or operational effect depend entirely on:

- relay retention
- platform immutability claims
- centralized registry persistence

It places the decisive weight on identifiable actors who can be reviewed, challenged, and held accountable.

### Persistence as Evidence

Persistence is still valuable.

An event that remains queryable across relays is useful evidence.

However, persistence is not treated as the ultimate source of effect.

The decisive source of effect is attested witness combined with recognition under policy.

### Specification Implication

Future OpenETR specifications should therefore distinguish clearly between:

- transaction-event semantics
- attestation-event semantics
- recognition rules

Transaction events may remain replaceable.

Attestation events are the layer at which witnessed reliability and accountable effect are anchored.

## Revocation

Revocation is not a lifecycle transition in the same sense as issue, transfer, endorse, or terminate.

Revocation applies only to actions that are:

- declared
- optionally accepted
- not yet fully attested

That means revocation is a control on incomplete action sets.

Revocation itself must be:

- declared
- attested

Revocation must not be used to unwind a transaction that has already become effective under the canonical rule unless a separate correction, dispute, rescission, or termination policy expressly permits it.

## Action Completion Model

A transaction is not evaluated as a monolithic event. It is evaluated as an action set.

The minimum evaluation steps are:

1. Identify the intended lifecycle action.
2. Determine the required action components for that lifecycle.
3. Determine whether each required component exists.
4. Determine whether each required component is attested.
5. Determine whether the attestors are recognized under policy.
6. Determine whether the action set is internally consistent and refers to the same object and transaction context.
7. Conclude effect only if the complete required set is present, attested, and recognized.

## Reliable Method Under MLETR

MLETR requires a reliable method to:

- identify the record
- preserve integrity
- establish exclusive control
- identify the person in control

MLETR deliberately does not prescribe one implementation.

OpenETR therefore does not claim that attestation is required by MLETR as such.

Instead, OpenETR uses attestation as the mechanism by which reliability is achieved and evidenced.

### OpenETR formulation

OpenETR satisfies the reliable-method requirement by making reliability attributable to identifiable attestors (`npubs`) who apply defined policies, rather than to a platform or system as a whole.

### Consequences

This means:

- identifiability is anchored in public keys
- accountability is anchored in signatures attributable to specific attestors
- integrity is anchored in the event and attestation chain
- exclusive control is expressed by recognizing only properly attested control transitions as effective

## Actor-Based Reliability

This specification rejects platform-based reliability as the canonical trust model.

It does not assume:

- the platform is reliable because it is certified
- the registry is reliable because it is centralized
- the application is reliable because it controls the database

Instead, it adopts actor-based reliability:

- each control-relevant action is attributable
- each attestor is identifiable
- each attestor is accountable for the application of policy
- each attestation can be independently reviewed

### Canonical rule

Every control-relevant action must be attested by an identifiable party whose public key anchors accountability for the application of policy.

## Why This Is Stronger Than Platform Trust

### 1. Granular accountability

The relevant question becomes:

> Who attested this specific action?

instead of:

> Which system was supposed to manage it?

### 2. Composability

Different policies and attestors may coexist.

The scheme can support:

- multiple attestors
- different recognition rules
- layered validation
- selective acceptance by different relying parties

### 3. Auditability

Each attestation is:

- signed
- attributable
- reviewable
- separable from platform claims

### 4. Legal alignment

Legal systems ultimately hold actors and entities accountable, not software abstractions.

This model aligns the technical structure with that practical legal reality.

## Transaction Recognition

Recognition is out of scope for the raw event layer and in scope for policy.

An implementation profile must specify:

- which attestors are recognized
- which policies they are expected to apply
- whether one or multiple attestations are required for a given action
- how conflicts are resolved
- how disputes, rescissions, and substitutions are handled

This specification only defines the canonical minimum:

- no effect without a fully attested required action set

## Minimum Data Expectations

This specification does not yet define a final wire format, but each canonical transaction should be able to express at least:

- the object identifier
- the lifecycle type
- the action type
- the initiating party
- the counterparty where applicable
- the attestor identity
- the policy context or policy reference
- the relationship to prior actions where applicable
- the signature covering the action

## Canonical Validation Rules

An OpenETR transaction action should be considered canonically valid only if:

- the object is clearly identified
- the action type is clearly identified
- the signer is identifiable
- the attestation is cryptographically valid
- the action is internally consistent with its referenced object and counterpart actions
- the action satisfies the lifecycle’s required interaction pattern

An OpenETR transaction becomes canonically effective only if:

- all required actions are present
- all required actions are attested
- the relevant attestors are recognized

## Transaction Families

This specification is intended to support transaction families such as:

- canonical issue transactions
- canonical transfer transactions
- canonical endorsement transactions
- canonical termination transactions
- canonical revocation transactions for incomplete action sets

Future companion specifications may define:

- a canonical event schema
- a canonical attestor schema
- policy reference formats
- dispute and rescission handling
- transaction grouping and correlation identifiers

## Non-Goals

This draft does not yet define:

- a complete JSON schema
- a final Nostr event-kind assignment
- jurisdiction-specific legal effect rules
- substantive commercial law rules for title, endorsement, or negotiability
- a universal recognition policy

## Summary

The central move in this specification is simple:

Reliability is not treated as a property of systems.
It is treated as a property of accountable actors applying policy.

OpenETR makes that accountability explicit through attestation.

That allows the scheme to express control-relevant transactions in a way that is:

- independently verifiable
- policy-aware
- portable across infrastructures
- aligned with the technology-neutral logic of MLETR
