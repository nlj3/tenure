# ADR-0002: plan objects with fingerprints, applied by a generic engine

**Date:** 2026-10-08  ·  **Status:** accepted

## Context
Offboarding is a sequence of 10 to 30 state changes across Graph, Exchange and Intune.
Run as a script, a failure in step 12 leaves the account half-done with no record, and
a re-run repeats steps 1 to 11 blindly.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Imperative script with `-WhatIf` | Simple | No diff, no drift check, no resume, no audit of what was already true |
| DSC-style resources with a plan/apply engine (Get/Test/Set per provider; plan = ordered steps with before/after) | Idempotent, diffable, resumable, mockable | More structure up front |
| PowerShell DSC proper | Standard | Windows-centric, heavy, wrong tool for one-shot lifecycle events |

## Decision
Providers expose `Get`, `Test`, `Set`, `Describe`. A plan builder snapshots `before`
via `Get`, records `after`, and hashes `before` into a fingerprint. The apply engine
re-reads state, refuses on fingerprint mismatch (drift), skips satisfied steps, calls
`Set` inside `ShouldProcess`, re-reads, and verifies `Test` is true before recording
`Applied`. Three step kinds: `State` (Get/Test/Set), `Invoke` (fire-once actions like
session revoke and wipe), `Check` (preconditions that warn or refuse).

## Consequences
- Easy: `-WhatIf`, dry run, resume, audit, custom operations composed from steps.
- Hard: every provider needs a `Test` that is honest; `Invoke` steps need explicit
  idempotency handling (status, not state).
- Committed to: plan JSON schema v1 (bump with migration if it changes).

## Revisit when
Plans exceed ~100 steps (then batching matters) or a second consumer needs
transactions across steps.
