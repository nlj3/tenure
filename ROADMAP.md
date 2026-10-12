# Roadmap

What exists, what is missing, and what is known to need hardening. Dates are when
the item was last reviewed.

## Done

- Module spine: manifest, loader, the Graph and Exchange seams, the provider registry,
  canonical JSON, the build gate and CI.
- Plan model and policy: plan and step objects, the JSON policy with role templates,
  policy validation, plan export and import with round-trip tests.
- Apply engine and audit: ordered apply with per-step drift fingerprints, `-WhatIf`,
  `-DryRun`, `-Force`, `-AllowDestructive`, confirmation for destructive steps, and the
  JSONL audit log with a SHA-256 hash chain checked by `Test-TenureAudit`.
- `Show-TenurePlan` with text and JSON formats, checked against golden output.
- Providers: user attributes, licenses, groups, directory roles, manager, sessions,
  password, leave date, mailbox conversion and forwarding, distribution group
  membership, devices, OneDrive.
- Plan builders: `New-TenureOnboardPlan`, `New-TenureRoleChangePlan`,
  `New-TenureOffboardPlan`.
- `Connect-Tenure`, `Disconnect-Tenure`, `Get-TenureConnection` and preflight checks.

## Not done

- Comment-based help pass over every public function, with examples that run.
- Integration harness: one onboard, role change and offboard cycle against a tenant the
  maintainer owns, creating and deleting its own test user, with devices switched off.
  Until this has run, the module has only been exercised against the fake seams.
- A published release.

## Hardening

- The audit directory is created with default permissions. Restrict it to the user where
  the runtime allows.
- 403 messages from the seam are generic. The engine should append the failing step's
  provider scopes to the error.
- National clouds: the Graph seam and the `@odata.id` references hard-code
  `graph.microsoft.com`.
- `ConvertTo-TenureUtcDateString` lives in a provider file and is used by four
  providers. Move it to the core.
- `Connect-Tenure` has no `-ClientId` in the interactive parameter set.
- `Disconnect-Tenure` drops every Exchange connection in the process, not only its own.
- `Assert-TenureConnection` trusts stored flags. Re-check `Get-MgContext` cheaply so a
  later connection to another tenant cannot pass.
- The integration run must confirm the behaviors the fakes assume: replication lag
  after create, the undocumented single-member Graph routes, Exchange parameters that
  take a UPN, the English error strings the Exchange helpers match on, that a not-found
  from a mailbox read by object id names that id in its message, that an onboard's
  distribution list add waits for the new mailbox to exist, and that the memberOf cross-check
  agrees with the single-member routes.
- Signed plan files. The integrity value is a hash, so an editor who recomputes it is not
  detected; a key the operator holds would close that. The two gaps that leaves today: a
  resealed step using an action its provider allows, and the recorded protected list when
  `-Policy` is not given.
- The tenant check trusts the tenant id stored on the connection.

## Deferred

- `New-TenureRetirePlan`: delete after N days, with OneDrive retention.
- MFA method removal, OAuth consent revocation, Entra device disable.
- Scope-minimal connect that requests only the scopes an operation needs.
