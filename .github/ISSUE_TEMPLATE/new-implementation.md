---
name: New Language Implementation
about: Register a new CPS implementation in another language
title: "[Implementation] "
labels: implementation
assignees: ''
---

## Language

What language is this implementation in?

## Repository

Link to the repository (or note if it will be a PR to this repo).

## Conformance Status

- [ ] Capsule data model with all 6 sections
- [ ] `to_dict()` — convert Capsule to plain dictionary/map
- [ ] `canonicalize()` — CPS Section 2 canonical JSON
- [ ] `compute_hash()` — SHA3-256 of canonical JSON
- [ ] `seal()` — hash + Ed25519 signature
- [ ] `verify()` — recompute hash and verify signature
- [ ] `from_dict()` — deserialize from dictionary/map
- [ ] Pass all 16 golden test vectors from `conformance/fixtures.json`
- [ ] Chain verification (sequence + hash linkage)

## Crypto Libraries Used

| Capability | Library |
|---|---|
| SHA3-256 | |
| Ed25519 | |

## Additional Context

Any notes on implementation approach, trade-offs, or help needed.
