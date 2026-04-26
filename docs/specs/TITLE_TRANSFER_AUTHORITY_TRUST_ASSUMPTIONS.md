# Title Transfer Authority Trust Assumptions

This note summarizes the trust assumptions for a digest-addressed title registry built on Nostr.

## Overview

In this model, a file or object is identified by a stable cryptographic digest. That digest is used as the canonical object identifier and is published in searchable event tags such as `d` or `o`.

Title is not established by self-assertion from end users. Instead, the authoritative statement of current title is made by a designated `Title Transfer Authority` (`TTA`) pubkey. The TTA may also issue subsequent attestations transferring title from one pubkey to another.

Relays provide storage, distribution, and searchability. They do not determine title. Title is determined by the signed attestations of the TTA.

## Core Trust Assumptions

The system assumes trust in the following properties of the TTA:

### 1. Identity

Participants must be able to determine which pubkey is the legitimate TTA for a given registry, asset class, or operating context.

Trust assumption:
The published TTA pubkey is authentically bound to the real-world authority that is supposed to administer title.

### 2. Procedural Legitimacy

The TTA is expected to follow a defined process before issuing or transferring title.

Examples include:
- verifying the identity or authority of the requesting party
- confirming the existence or provenance of the underlying object
- confirming that the claimed transfer is valid
- checking that the prior chain of title is consistent
- applying any required dispute, revocation, or correction procedures

Trust assumption:
The TTA applies correct and consistent procedures before signing an attestation.

### 3. Attestation Integrity

The TTA must issue truthful, non-conflicting, and policy-compliant statements.

Trust assumption:
The TTA will not knowingly sign false title assertions, duplicate current-title assertions that conflict with each other, or unauthorized transfers.

### 4. Key Control

The authority of the TTA is exercised through its signing key.

Trust assumption:
The TTA private key is securely controlled, protected against compromise, and subject to a documented recovery, rotation, and revocation process.

### 5. Continuity and Availability

The title system is only useful if the TTA remains available to issue new attestations, transfers, corrections, and key-rotation notices.

Trust assumption:
The TTA will remain operational enough to support ongoing registry maintenance, or there is a documented succession and continuity plan.

## What the System Does Not Need to Trust

This model reduces reliance on other trust layers:

- it does not rely on a platform account system to determine title
- it does not rely on a relay to decide which title claim is authoritative
- it does not require a blockchain smart contract to express title logic
- it does not depend on wallet possession alone as proof of title

These components may still matter operationally, but they are not the source of title authority.

## Practical Interpretation

The key trust statement in this design is:

> We trust the designated Title Transfer Authority pubkey to maintain and sign the authoritative title record for objects identified by digest.

This means the system minimizes technical trust in platforms and contracts, but it still requires institutional trust in:

- the identity of the TTA
- the TTA's procedures
- the TTA's integrity
- the TTA's key management

## Design Implication

This is not a trustless title system. It is a trust-minimized registry system that makes the trust anchor explicit.

Instead of distributing trust across:

- platform authentication
- database permissions
- application business logic
- smart contracts
- wallet custody

the model concentrates trust in a clearly identified and auditable authority key.

That simplification can make the system easier to reason about, easier to govern, and easier to explain, especially where title depends on legal or institutional judgment rather than pure technical possession.
