# ADR-0002: plan objects with fingerprints, applied by a generic engine

Date: 2026-10-08
Status: accepted

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
- Committed to: plan JSON schema v1 (bump with migration if it changes). Now v2; see the second amendment.

## Amendment 2026-10-11
- The fingerprint hashes the step's target identity (Kind and Id) together with `before`
  (`Get-TenureStepFingerprint`). The engine and `Test-TenurePlan` compute it from the target they are
  about to read, so a plan file edited to point a step at a different object drifts even when that
  object's state equals the snapshot. The target's display Name and other target keys stay outside it.

## Amendment 2026-10-11 (second): plan schema 2
The first amendment changed the fingerprint formula without the schema bump this ADR promised, and a plan file
could be edited in ways the fingerprints did not catch, which is why the bump matters. Plan schema version 2:
- Every step carries a fingerprint. A `$null` Before is hashed as null instead of giving an empty fingerprint: for
  a Create it means "the target does not exist", and the engine refuses a Create whose target exists unless the
  audit log shows this plan attempted it (adoption on resume); `-Force` does not override that. A step on the
  `{{subjectId}}` placeholder binds the placeholder target. A snapshot taken before the subject existed names it
  by the placeholder (an onboarding's group step records "not a member"), and the engine compares it with the
  live state after filling the placeholder in. An empty fingerprint used to switch the drift check off.
- The plan carries `Integrity`, a SHA-256 over everything it says and does except what the engine writes
  (statuses, results, and a subject id filled in after the create step); see ADR-0007. Fingerprints bind a step
  to its target's state; the integrity value binds the plan to what was reviewed (providers, actions, desired
  states, order, dependencies, risk). Neither is a signature.
- The plan records the policy facts the engine needs without `-Policy` (`PolicySnapshot`: protected users and the
  managed set), and the self-protection check's snapshot holds only its verdict, not the signed-in account or the
  protected list, so another administrator can apply a plan without drift.
- The engine no longer writes resolved `{{subjectId}}` values back into a step's Target and After; it fills them
  in a copy on every run, so the sealed content does not change while a plan is applied.
- Invoke providers declare `Repeatable`. A step in doubt after an interrupted run runs again under `-Resume` only
  when it is Repeatable; otherwise the run stops until the operator names it in `-AssumeFired`, and such a plan
  never ends `Applied`. Treating every step in doubt as fired let a resumed run report a session revoke that
  never ran.
- Migration: none. A version 1 file is refused with `Tenure.Plan.UnsupportedSchema` and a message to plan again.
  Plans are meant to live hours (24 h `-MaxAge`), and a version 1 file has nothing a migration could check its
  content against.

## Amendment 2026-10-11 (third): what a step acts on, and what a run trusts
The engine trusted labels in the plan and statuses left in it by earlier runs. The contract between the engine and
its providers grows by three declarations, and the engine trusts the live state and the audit log over the plan file:
- Every provider declares `TargetKind` (the one kind of object it acts on) and `Actions` (the step actions it
  allows); a Check provider also declares `AffectedBy` (the providers whose steps change what it reads). A step whose
  `Target.Kind` or `Action` disagrees with its provider is refused, and the protection preflight and the subject
  binding read the account a step changes from the provider's kind. A `Mailbox.Forwarding` step on a protected
  user's mailbox, labelled `group`, used to forward that mail outside, because those checks read the label.
- A `State` step whose desired state already holds is Skipped before the drift check, because there is nothing to
  do; snapshots leave out what the plan's own earlier steps move (inherited licenses, the session timestamp). On a
  later run, a check whose input the plan's own step changed (audit log) is evaluated against the live state.
- A dependency is met by this run's outcome or by the live state, never by a status an earlier run left in the plan;
  a declined confirmation is recorded `Declined`.
- The audit log decides what a plan already did: a plan it shows finished `Applied` is refused without `-Force`, a
  step skipped under `-AssumeFired` stays assumed, and a Create adopts an account only when it was created during an
  attempt of that step that did not end in a refused request.
- A membership step is read, before and after `Set`, for the user it changes (`After.userId`).

## Revisit when
Plans exceed ~100 steps (then batching matters) or a second consumer needs
transactions across steps.
