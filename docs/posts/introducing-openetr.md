---
title: Introducing OpenETR
eyebrow: Introduction
description: Why OpenETR begins with durable control, portable records, and an open scheme built on Nostr.
---

OpenETR starts from a simple observation: many important records still behave as though they belong to the systems that host them.

A platform may store the record, a registry may display the record, and an application may let users act on the record, but none of that answers the deeper question of whether the record can stand on its own when it needs to move. For transferable records, that question matters.

If control only works inside one institution or one software environment, the record is not really portable. It is only visible through a particular window.

## The problem

Digital records are often:

- locked inside a vendor or platform
- difficult to verify independently
- hard to move without re-issuance or reconciliation
- dependent on the continuity of the originating system

That is workable for internal workflow. It is much weaker for records that need to be transferred, endorsed, recognized, or enforced across organizational boundaries.

## The OpenETR starting point

OpenETR is an open scheme for electronic transferable records. It is built around three simple primitives:

- objects
- controllers
- events

An object is the record surface. A controller is the key or actor able to exercise exclusive control. An event is the signed action that changes state, meaning, or authority.

From those primitives, a record can move without being trapped inside the original system that first created it.

## Why Nostr is the first reference implementation

OpenETR is not trying to invent a new transport protocol from scratch. Nostr already gives us a useful foundation:

- signed events
- relay-based distribution
- independent verification

That makes it a practical first environment for expressing durable control and portable records on open infrastructure.

## Why this matters for MLETR

The UNCITRAL Model Law on Electronic Transferable Records points toward a legal world where certain electronic records can function like their paper equivalents. But legal recognition still needs technical patterns that can support control, transfer, and independent verification.

OpenETR is aimed at that gap.

## Where this goes next

The project is still early. The immediate goal is to make the model legible through:

- draft specifications
- a working CLI
- reference record flows on Nostr
- practical writing that explains the design choices

If the scheme works, records become more durable than the systems that temporarily host them, and control becomes something that can be exercised, proven, and transferred without being confined to one application boundary.
