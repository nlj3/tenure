# Changelog

All notable changes to Tenure are recorded here. The format follows Keep a Changelog;
versions follow SemVer.

## [Unreleased]

### Added
- Module spine: manifest, loader, Graph and Exchange seams with retry and paging,
  provider registry, canonical JSON hashing, build script, three-OS CI matrix, a
  Gallery release workflow with a rehearsal job.
- Policy file (JSON, schema, strict loader with JSON-path errors) with role templates,
  offboarding defaults, protected users and a managed set for role changes.
- Plan model: steps with before/after state, a fingerprint that binds the snapshot to
  its target, dependencies, risk and reversibility; export and import with type
  normalization.
- Apply engine: `-WhatIf`, `-DryRun`, `-Force` (drift only), `-AllowStale`, `-Resume`,
  `-ContinueOnError`, `-AllowDestructive`, per-step `ShouldContinue` for destructive
  work, write-ahead `Attempting` audit entries, plan file rewritten after every step,
  audit-log history consulted on resume, interrupt-safe `finally` with
  `Get-TenureApplyResult`.
- Audit log: append-only JSONL with a SHA-256 hash chain, exclusive-lock writer with
  rollback on torn writes, `Get-TenureAudit`, `Test-TenureAudit`, `AuditHead` anchor.
- Providers: sign-in, password reset, session revoke, directory role removal, groups (Graph and
  distribution lists), licenses, user create/attributes/manager/leave date, Temporary
  Access Pass, mailbox type/forwarding/auto-reply/delegate/hidden, shared-mailbox
  eligibility check, meeting cancellation, Intune wipe and retire (company-owned only,
  subject-bound), OneDrive access grant (subject-bound), subject-allowed and
  not-global-admin checks, user-absent check.
- Plan builders: `New-TenureOnboardPlan`, `New-TenureRoleChangePlan`,
  `New-TenureOffboardPlan`.
- `Show-TenurePlan` with a Terraform-style diff view and format views for every object.
- `Connect-Tenure` / `Disconnect-Tenure` / `Get-TenureConnection` for interactive, device
  code, certificate and client-secret sign-in across the four Microsoft clouds.
- Test suite: in-memory Graph and Exchange fakes, fault injection, property and fuzz
  tests, golden files, adversarial suites for seam isolation and secret leakage, and
  regressions for every attack on plan files, the apply engine and resume that once worked.
- `Invoke-TenurePlan -AssumeFired`, `Test-TenurePlan -Policy`, and the `Repeatable` key on
  Invoke providers.
- Provider declarations `TargetKind` (the one kind of object a provider acts on), `Actions` (the step actions it
  allows) and, for checks, `AffectedBy` (the providers whose steps change what the check reads), shown by
  `Get-TenureProvider`.
- `New-TenureRoleChangePlan -AllowMailboxLoss`, the step status `Declined`, `Summary.Declined` on the apply result,
  and `Unverified` on the result of `Test-TenurePlan`.

### Changed
- Plan schema version 2. Every plan carries an `Integrity` value and a `PolicySnapshot` (the policy's protected
  users and managed set). Version 1 plan files are refused with `Tenure.Plan.UnsupportedSchema` and must be planned
  again; there is no migration (ADR-0002 second amendment, ADR-0007).
- Every step has a fingerprint. A step without a snapshot is a Create (its fingerprint means "the target does not
  exist") or a step on the `{{subjectId}}` placeholder. `New-TenureStep -SkipSnapshot` is refused for anything else.
- Onboarding group steps take a snapshot when the plan is built, with the new user named by `{{subjectId}}`
  ("not a member"), so a built onboarding plan with groups and a Temporary Access Pass now applies.
- The apply engine no longer writes resolved `{{subjectId}}` values into a step's Target and After; it fills them
  in a copy on every run. The audit log records the resolved values.
- Snapshots no longer hold values that change on their own: devices drop `lastSyncDateTime` and
  `managementState`; the shared-mailbox eligibility check stores whether the size is over the limit, whether an
  archive exists and which kinds of hold exist, not the size; the subject check stores who the subject is and its
  verdict, not the signed-in account or the protected list.
- Write-ahead `Attempting` audit entries are now also written for Create steps.
- A license grants a mailbox when a service plan is `EXCHANGE_S_*`, is not `EXCHANGE_S_FOUNDATION`, and is not
  `Disabled`. Unknown shapes still count.
- `Test-TenureAudit` returns `Problem`, which names the line that breaks the chain; for a torn last line it gives
  the command that keeps the lines before it.
- On macOS, an audit log under `~/Desktop` or `~/Documents` gets a warning (iCloud Drive can sync those folders
  without any sign in the path). It is not refused.
- The example policy's second role is `warehouse` (department Operations, group Warehouse Users).
- A State step whose desired state already holds is Skipped before the drift check, so a plan no longer stops on a
  change its own earlier step made (a sign-in disable that empties a dynamic group, a group removal that takes an
  inherited license). The `User.Licenses` snapshot holds only the directly assigned SKUs, the ones it changes, and the
  `User.Sessions` snapshot no longer holds the session timestamp its own revoke moves.
- A check whose input a step of the same plan changed (a role removal for the Global Administrator check) is
  evaluated against the live state on a later run instead of reporting drift: passing, it is Skipped; failing, it
  stops the run.
- A role-removal step's Action is `Remove`; `DirectoryRole.Member` allows only `Remove` and `NoOp`, and no longer
  adds a user to a role (see Security).
- A membership step reads the user it changes (`After.userId`) for its snapshot and before and after `Set`, so a
  Custom plan's change for someone other than the subject is audited as Applied.
- Group lookups and the `Group.Member` snapshot carry `isAssignableToRole`; group license reads keep each
  assignment's disabled service plans.
- A declined confirmation is recorded `Declined` in the plan and its file (not in the audit log); a plan with a
  declined step does not end Applied.
- A plan built with `-Policy` while connected warns about each `protectedUsers` entry that matches no user.
  `New-TenurePlan -Inputs $null` records an empty table, so the plan imports again.
- A plan built without `-Policy` can no longer be applied or tested (see Security).

### Security
- The Graph seam forces `-Debug:$false` on every SDK call: the SDK logs full request and response bodies to the
  Debug stream, which would have printed generated passwords and Temporary Access Passes.
- Plans are sealed with `Integrity`, a SHA-256 over everything a plan says and does except the statuses and
  results the apply engine writes. `Import-TenurePlan`, `Export-TenurePlan`, `Test-TenurePlan` and
  `Invoke-TenurePlan` refuse a plan whose content no longer matches with `Tenure.Plan.Tampered`. It is a plain
  hash, not a signature: it catches a plan edited by hand or by a tool that does not recompute it, and someone who
  recomputes it is not stopped by it.
- Each step's fingerprint binds its target as well as its state. A Create step whose target exists, and that this
  plan did not attempt to create according to the audit log, is Drifted even with `-Force`.
- `Invoke-TenurePlan` and `Test-TenurePlan` refuse, before step 1, a plan whose subject or any account a step
  changes is the signed-in account or a protected user, whether or not the plan has a `Check.SubjectAllowed`
  step. The account a step changes is read from its provider's `TargetKind`, and a step whose `Target.Kind` or
  `Action` is not its provider's own is refused (`Tenure.Plan.Invalid`; `New-TenureStep` refuses it too), so a
  mislabelled step can no longer change a protected account or grant a role through an `Update`.
- Without `-Policy` they use the protected users the plan recorded when it was built, and refuse a plan that
  records none (`Tenure.Plan.PolicyMissing`). With `-Policy`, the policy must carry the plan's recorded hash: a
  policy object without a hash, a different policy, or a plan that records none is `Tenure.Plan.PolicyMismatch`.
- A plan built in one tenant is refused in another, and a plan that names no tenant is refused everywhere
  (`Tenure.Plan.WrongTenant`).
- A plan the audit log shows finished `Applied` is refused (`Tenure.Plan.AlreadyApplied`) unless `-Force`, whatever
  its file says, so a plan applied as an object cannot be applied again from its file.
- A dependency counts as met only when this run applied or skipped it, or when the live state shows its desired
  state holds, so a mailbox conversion undone since an earlier run and declined now no longer lets the license
  removal run.
- A plan built without a subject id (an onboarding) is refused when the id it carries was not produced by its own
  create step according to the audit log. A Create adopts an existing account on resume only when the account was
  created during an attempt of that step recorded in the audit log (from its `Attempting` entry to the next entry
  for the step or the run's end, with 5 minutes either side for clock difference) that did not end in a refused
  request; the plan file's `Result.Attempted` alone is not enough. An attempt whose run died without a later entry
  ends at the longest a Graph call can take (23 minutes), so an account created after that is never adopted.
  `Retry-After` waits in the Graph seam are capped at 60 seconds.
- No plan, resealed or not, grants a directory role, directly or through a role-assignable group:
  `DirectoryRole.Member` refuses an add (`member = $true`) with `Tenure.Provider.Unsupported` before any request,
  even through a step labelled `Remove`, and `Group.Member` refuses an add to a group whose `isAssignableToRole` is
  true before any write. The builders leave such an add out with a warning.
- Identifiers in a step are strings: a `Target.Id` or `After.userId` of another type is refused when the step is
  built and before step 1, so a value the protection check skipped can no longer reach a provider that turns it
  into an id. A mailbox or drive step names its target by the owner's object id, so an alias, address or display
  name that Exchange would resolve to a protected account is refused.
- A role change that would remove a user's last license with Exchange Online, direct or through a group, is refused
  (`Tenure.Plan.MailboxUnlicensed`) with the license and the group named, unless `-AllowMailboxLoss`, which makes
  the steps that remove it Destructive. It counts service plans, not SKU ids: a group assignment that switches the
  Exchange plan off keeps nothing, and a license a new group brings counts only when its SKU has a free seat (the
  refusal names the shortage).
- A step named in `-AssumeFired` stays assumed in every later run, including one started from a plan file that never
  saw the assumed run, so such a plan never ends `Applied`. `Test-TenurePlan` reports an Invoke step that only the
  plan file calls done as `Unverified`.
- Removing a user from a group that carries a license is ordered after the mailbox conversion, like the license
  step, and is left out when license removal is off. When a plan does not convert a mailbox that a license
  grants, the license step and those group removals are Destructive and need their own confirmation or
  `-AllowDestructive`.
- License steps list exactly the SKU ids they add and remove; applying a license step, even with `-Force`, never
  removes a license the step does not list.
- On resume, an Invoke step that may have fired runs again only when its provider is Repeatable (session revoke,
  device retire and wipe, meeting cancellation). Any other stops the run until the operator names it in
  `-AssumeFired`, which is recorded in the audit log, and a plan with such a step never ends `Applied`. An Invoke
  step is skipped as already done only when the audit log records it; one the plan file alone calls done is
  treated as in doubt, so editing a status cannot silence a revoke or a wipe.
- The confirmation for a Destructive step names the provider and shows the provider's own description of the
  change, worked out from the live state, not the plan's `Reason` text.
- Exchange cmdlets are given user principal names and SMTP addresses, never Entra object ids, and only a
  "couldn't be found" that names the requested object counts as not found.
- An offboarding plan leaves the mailbox steps out only when Exchange finds no mailbox and none of the user's
  licenses grants one; otherwise it refuses with `Tenure.Plan.MailboxUnknown` instead of removing licenses from a
  mailbox that may exist.
- A Graph group or directory role membership read that says "not a member" while the user's memberOf lists the
  group or role is refused with `Tenure.Provider.InconsistentState` when the plan is built, instead of being taken
  as "nothing to remove". Distribution lists and mail-enabled security groups are read from Exchange and are not
  cross-checked this way.
- `protectedUsers` entries match a user's object id and mail address as well as the user principal name, and
  role-change plans refuse a protected user too.
- The release workflow passes the tag name and the other event values to its scripts through environment
  variables, never pasted into the script text.
