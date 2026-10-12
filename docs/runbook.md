# Runbook

Operating notes for people running Tenure against a real tenant. The README explains what
the module does; this is what to do when something is in front of you.

## 1. First connection

```powershell
Install-Module Tenure -Scope CurrentUser        # or Import-Module ./src/Tenure/Tenure.psd1 from a checkout
Connect-Tenure -TenantId <tenant>.onmicrosoft.com
Get-TenureConnection
```

Interactive sign-in asks for the union of every provider's Graph scopes plus `User.Read`.
The first time, an administrator has to consent. `Get-TenureProvider | Select-Object Name,
Scopes` shows what each provider needs; `Connect-Tenure -Scopes ...` narrows the request if
you only plan to run some operations. Exchange Online is connected in the same call unless
you pass `-SkipExchange`.

Roles the signed-in account needs, in addition to the scopes: User Administrator for the
identity steps, Exchange Administrator for mailbox steps, Intune Administrator for device
steps, Privileged Role Administrator or Global Administrator to remove directory roles, and
Global Administrator to write `employeeLeaveDateTime`.

For automation use a certificate:

```powershell
Connect-Tenure -ClientId <app id> -TenantId <tenant id> -CertificateThumbprint <thumbprint> -Organization <tenant>.onmicrosoft.com
```

Client secrets work for Graph only; Exchange Online does not accept them, so pair a secret
with `-SkipExchange`.

## 2. Policy

```powershell
New-TenurePolicy -Path ./tenure.policy.json
Test-TenurePolicy -Path ./tenure.policy.json
```

Put break-glass accounts in `defaults.protectedUsers`, as object ids, user principal names
or mail addresses. Put groups that must survive
offboarding (for example an alumni list) in `defaults.offboard.keepGroups`. Keep the file in
version control; its hash is recorded on every plan. The plan also records the protected
list and the managed set, so another administrator can apply it without the policy file.
Pass `-Policy` when applying anyway; without it, the recorded list is the plan's own word.

## 3. Planning

Planning is read-only. Build the plan, read it, keep it.

```powershell
$plan = New-TenureOffboardPlan -User alice@example.com -Policy ./tenure.policy.json
Show-TenurePlan $plan
Export-TenurePlan $plan -Path ./plans/alice-offboard.json
```

A plan file is sealed when it is built. Edit it and `Invoke-TenurePlan`, `Test-TenurePlan`
and `Import-TenurePlan` refuse it as tampered; a file from an older schema is refused too.
Re-plan instead of editing.

Read the `Warnings:` block. The usual ones: the mailbox is over 50 GB or on hold (it will
still need a license after conversion; add `-SkipLicenseRemoval` or sort the hold out
first), the user is the only owner of a group (hand ownership over first), a device has
unknown ownership (it will be retired, not wiped), no manager is set (forwarding, delegate
and OneDrive steps were left out), a `protectedUsers` entry that matches no account (fix the
typo before you rely on it). A role change that would remove the last license granting a
mailbox is refused with `Tenure.Plan.MailboxUnlicensed`; `-AllowMailboxLoss` turns that
into a destructive step with a warning.

A plan is good for 24 hours. After that, re-plan; do not reach for `-AllowStale` unless you
have re-read the plan and know why it is still right.

## 4. Applying

```powershell
Invoke-TenurePlan ./plans/alice-offboard.json -WhatIf      # prints, writes nothing
Invoke-TenurePlan ./plans/alice-offboard.json -DryRun      # re-reads live state, writes DryRun audit entries
Invoke-TenurePlan ./plans/alice-offboard.json              # prompts per step
```

When `-Plan` is a path, the file is rewritten after every step, so it always shows where
the run got to.

Unattended:

```powershell
Invoke-TenurePlan ./plans/alice-offboard.json -Confirm:$false -AllowDestructive
```

Without `-AllowDestructive`, destructive steps (device wipe, canceling organized meetings)
are refused in an unattended run and the plan stops there.

## 5. When a step is Drifted

The state the step was planned against has changed. Look at the audit entry's `Note` and at
`Test-TenurePlan $plan` to see which steps still hold. Then re-plan. `-Force` overrides the
drift check for the whole run and should be the exception. It also overrides the refusal of
a plan the audit log already shows as applied. It never passes a create step whose target
already exists, and the wipe step re-checks device ownership on its own. A step whose
desired state already holds is skipped, not drifted.

## 6. When a step is Refused

The reason is in the step's `Result.Note` and in the audit entry. Common causes: a
dependency was not applied or skipped in this run and does not hold now (license removal
waits for the mailbox conversion), a `Check` failed closed (the mailbox could not be
inspected), a destructive step without `-AllowDestructive`, or the audit log shows an
earlier run of the same plan that never finished (see 7). A prompt you declined shows the
step as `Declined`. A protected subject, a plan from another tenant, or an edited plan file is
refused before step one, with `Tenure.Plan.Refused`, `Tenure.Plan.WrongTenant` or
`Tenure.Plan.Tampered`. So is a plan that recorded no policy or whose `-Policy` hash differs
(`Tenure.Plan.PolicyMissing`, `Tenure.Plan.PolicyMismatch`), a step whose target kind or
action does not match its provider (`Tenure.Plan.Invalid`), a plan the audit log already
shows as applied (`Tenure.Plan.AlreadyApplied`), and a plan with no tenant id.

## 7. When a run was interrupted

Ctrl+C, a lost connection or a crash leaves the plan part-applied. Three things to do, in
order:

1. `Get-TenureApplyResult` returns the last result of this session, including any secret
   that was generated before the interruption. Collect it before anything else.
2. `Get-TenureAudit -PlanId <id>` shows what was recorded. An `Attempting` entry without an
   `Applied` after it means the step may or may not have landed. Create and destructive
   steps write one too.
3. Resume with `Invoke-TenurePlan ./plans/<file>.json -Resume`. `-Resume` acknowledges the
   open run. A step in doubt is run again when its provider declares it safe to repeat
   (session revoke, device retire and wipe, meeting cancellation). Any other step in doubt
   stops the run; `-AssumeFired <StepId>` tells the engine you have confirmed it landed, the
   audit log records that, and the plan's final status says a step was assumed.

Every state step is re-tested against its desired state and skipped when it holds, and a
check whose inputs the run itself changed is re-evaluated live, so a resume does not report
the run's own changes as drift. `-AssumeFired` carries across runs.

## 8. When Graph returns 403

The error names the provider. `Get-TenureProvider -Name <provider>` lists the scopes it
needs; compare with `(Get-TenureConnection).Scopes`. Missing scopes mean a new consent;
present scopes with a 403 mean the signed-in account lacks the directory role (section 1).

## 9. The audit log

Default path: `~/.tenure/audit.jsonl`, overridable with `-AuditPath` or
`TENURE_AUDIT_PATH`. Keep it on a local disk; the writer's lock does not work on network
shares or cloud-synced folders.

```powershell
Test-TenureAudit                                   # walks the hash chain
Get-TenureAudit -Since (Get-Date).AddDays(-7) | Format-Table Seq, Ts, Outcome, PlanId, StepId, Provider
```

A broken chain reports the first bad sequence number, and `Test-TenureAudit` names the line
and prints the repair: copy the file up to the last good line with
`Get-Content -LiteralPath '<path>' -TotalCount <N> | Set-Content -LiteralPath '<path>.repaired'`,
check the copy with `Test-TenureAudit -Path`, then move it over the original. On macOS an
audit log under Desktop or Documents gets a warning, because iCloud may sync those folders. Deleting lines from the end is not
detectable from the file alone: each apply result carries `AuditHead` (the last sequence
number and hash); record it somewhere the file's writer cannot reach, for example a ticket.

To archive, move the file and start a new one; chains do not span files. Do not merge files.

## 10. Secrets

Generated passwords and Temporary Access Passes exist only on the apply result:

```powershell
$result = Invoke-TenurePlan $plan
$result.Secrets.Keys                                              # step ids
[System.Net.NetworkCredential]::new('', $result.Secrets['S02']).Password
```

Hand them over through whatever channel you already use for credentials. They are not in
the plan file, the audit log or the transcript. An offboarding password reset discards the
new password on purpose.

## 11. Before the first real run

The opt-in integration harness (`TENURE_INTEGRATION=1`, `./build.ps1 -Task Integration`)
is not written yet. Until it is, rehearse by hand in a tenant you own: create a throwaway
user, build an offboard plan for it, run `Invoke-TenurePlan -WhatIf`, then `-DryRun`, read
the audit log, and only then apply with device steps off. The things the unit fakes
cannot prove are listed in `ROADMAP.md` under Hardening; the
integration run is where they get confirmed.
