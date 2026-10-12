# Tenure

Tenure onboards, re-roles and offboards Microsoft 365 accounts the way Terraform changes
infrastructure. It reads the live state of the user, builds a plan you can review, and
then applies that plan one step at a time with drift detection, dry runs, confirmation
prompts and an append-only audit log.

It is a PowerShell 7 module. It runs on Windows, macOS and Linux, needs two dependencies
(`Microsoft.Graph.Authentication` and `ExchangeOnlineManagement`), and its unit suite runs
with no tenant, no network and no credentials.

## Status

Tenure is tested against in-memory fakes of Microsoft Graph and Exchange Online. It has
not yet been run against a live tenant. Until the integration run described in
`ROADMAP.md` has happened, treat it as a design you can read and a test suite you can run,
not as a tool to point at a tenant you care about. The plan, show and audit parts are the
most settled. The providers are what the live run will test.

## What a plan looks like

This is the output of `Show-TenurePlan` for an offboard. It was produced by the real
offboard builder against the in-memory fakes, with the example policy that ships in
`src/Tenure/Policies`:

```text
Plan 1a6d82b1: Offboard alice@example.com (Alice Example)
Created 2026-10-12 05:49 UTC by admin@example.com with Tenure 0.1.0, policy 1fd47c26
Status Planned. 17 steps: 12 changes, 3 no-ops, 2 destructive.

  = S01 Check.SubjectAllowed            alice@example.com       alice@example.com is allowed as a
                                                                subject: not the signed-in account
                                                                and not protected by policy
  = S02 Check.SubjectNotGlobalAdmin     alice@example.com       alice@example.com does not hold
                                                                Global Administrator
  ~ S03 User.SignIn                     alice@example.com       Update sign-in of alice@example.com
                                                                (enabled: true -> false)
  ! S04 User.Password                   alice@example.com       Invoke password of
                                                                alice@example.com: reset to a random
                                                                password (discarded)
  ! S05 User.Sessions                   alice@example.com       Invoke sessions of
                                                                alice@example.com: revoke all
                                                                sign-in sessions (refresh tokens;
                                                                access tokens expire within an hour)
  = S06 Check.MailboxSharedEligibility  alice@example.com       NoOp shared mailbox eligibility of
                                                                alice@example.com: under 50 GB, no
                                                                archive, no holds; can become a
                                                                shared mailbox without a license
  ~ S07 Mailbox.Type                    alice@example.com       Update mailbox type of
                                                                alice@example.com: Regular -> Shared
  ~ S08 Mailbox.Forwarding              alice@example.com       Update forwarding on
                                                                alice@example.com: forward to
                                                                bob@example.com and keep a copy in
                                                                the mailbox
  ~ S09 Mailbox.AutoReply               alice@example.com       Update auto-reply on
                                                                alice@example.com: turn on, external
                                                                audience All, message "Alice Example
                                                                has left {company}. Please contact
                                                                Bob Mana..."
  ~ S10 Mailbox.Delegate                alice@example.com       Update mailbox access on
                                                                alice@example.com: grant FullAccess
                                                                to bob@example.com (automapping off)
  ~ S11 Mailbox.Hidden                  alice@example.com       Update address list visibility of
                                                                alice@example.com: hide from address
                                                                lists
  x S12 Calendar.CancelMeetings         alice@example.com       Cancel all meetings organized by
                                                                alice@example.com for the next 120
                                                                days, irreversible
  ~ S13 OneDrive.Access                 alice@example.com       grant bob@example.com write access
                                                                to alice@example.com's OneDrive (no
                                                                invitation email)
  ~ S14 Group.Member                    All Staff               Update user
                                                                10000000-0000-4000-8000-000000000001
                                                                out of group All Staff
  ~ S15 Group.Member                    Sales                   Update user
                                                                10000000-0000-4000-8000-000000000001
                                                                out of group Sales
  ~ S16 User.Licenses                   alice@example.com       Remove the licenses assigned
                                                                directly to alice@example.com:
                                                                SPE_E3.
  x S17 Device.Wipe                     ALICE-LAPTOP (company)  wipe ALICE-LAPTOP (company,
                                                                Windows), irreversible

Depends: S16 -> S07
Warnings:
  - The auto-reply message has placeholders Tenure does not fill and leaves as written: {company}.
    Change the policy message or pass -AutoReplyMessage.
Destructive: S12 Calendar.CancelMeetings, S17 Device.Wipe. Needs an interactive -Confirm or
             -AllowDestructive.
Legend: + create  ~ update  - remove  ! invoke  x destructive  = no-op  ? check
```

Nothing in that plan has run. Each step records the state it found and the state it
wants, and the apply engine re-reads the state before each step and stops if it changed.
The warning at the bottom is real too: the example policy's auto-reply uses a placeholder
Tenure does not fill, and the builder says so before you apply.

## The problem it solves

In a small Microsoft 365 shop, leaver handling is a checklist someone runs by hand: block
sign-in, revoke sessions, convert the mailbox to shared, forward the mail, hand the OneDrive
to the manager, strip licenses and groups, wipe the laptop. Done by hand it takes an hour,
it gets done in the wrong order (license removed before the mailbox is converted, mailbox
gone), and afterwards nobody can say exactly what was changed, by whom, or whether a step
was skipped. Joiner and mover changes have the same shape with lower stakes.

Tenure turns each of those into a plan. The plan is built from what the tenant looks like
right now, so a step that is already true shows up as a no-op instead of being repeated.
The plan is applied only after you have looked at it.

## How it works

```
policy file  +  live tenant state  ->  plan  ->  show  ->  apply  ->  audit log
```

1. A policy file describes your tenant: which licenses and groups each role gets, where
   offboarded mail should go, whether devices get wiped or retired, which accounts may
   never be touched.
2. `New-TenureOffboardPlan` (or the onboard and role change equivalents) reads the user,
   their groups, licenses, roles, mailbox, OneDrive and devices, and produces an ordered
   list of steps. Each step records the state it found, the state it wants, and a
   fingerprint of the state it found.
3. `Show-TenurePlan` prints the plan the way `terraform plan` does: one line per step with
   a symbol for create, update, remove, invoke, destructive and no-op.
4. `Invoke-TenurePlan` applies it. Before each step it re-reads the state and compares the
   fingerprint; if something changed since the plan was built, it stops and tells you.
   `-WhatIf` and `-DryRun` rehearse. Destructive steps (device wipe, canceling every
   meeting the person organized) need an explicit confirmation of their own.
5. Every outcome is appended to a JSONL audit log. Each line carries a SHA-256 hash that
   chains to the previous line, and `Test-TenureAudit` walks the chain and reports the
   first break.

Under the hood every tenant resource is a provider with `Get`, `Test` and `Set`, in the
style of DSC resources. Plan builders compose steps from providers; the apply engine runs
them without knowing what they do. All Graph traffic goes through one wrapper and all
Exchange Online cmdlets through another, which is what makes the whole thing testable in
memory.

## Install

Until the first Gallery release, install from source:

```powershell
git clone https://github.com/nlj3/tenure.git
cd tenure
./build.ps1 -Task Bootstrap     # installs the two dependencies and the test tools
Import-Module ./src/Tenure/Tenure.psd1
```

Once published:

```powershell
Install-Module Tenure -Scope CurrentUser
```

## Quick start: offboard someone

```powershell
Connect-Tenure -TenantId <tenant>.onmicrosoft.com      # Graph plus Exchange Online, interactive

New-TenurePolicy -Path ./tenure.policy.json            # writes an example policy; edit it once

$plan = New-TenureOffboardPlan -User alice@example.com -Policy ./tenure.policy.json
Show-TenurePlan $plan

Invoke-TenurePlan $plan -WhatIf                        # prints what would happen, writes nothing
Invoke-TenurePlan $plan -DryRun                        # re-reads live state, records a rehearsal in the audit log
Invoke-TenurePlan $plan                                # prompts per step; destructive steps prompt again

Get-TenureAudit -PlanId $plan.PlanId | Format-Table Seq, Outcome, StepId, Provider
Test-TenureAudit
```

Plans can be saved and applied later, for example after a manager has reviewed them:

```powershell
Export-TenurePlan $plan -Path ./alice-offboard.json
Invoke-TenurePlan ./alice-offboard.json -Confirm:$false -AllowDestructive
```

A plan older than 24 hours is refused (`-AllowStale` overrides). A plan whose fingerprints no
longer match the tenant is refused (`-Force` overrides drift and the refusal of a plan the
audit log already shows as applied, and nothing else; it never passes a create step whose
target already exists). A plan file edited after it was built is
refused as tampered whatever flags are passed; re-plan instead.

## What an offboard plan contains

In order, with the reason for the order:

| Step | Why here |
|---|---|
| Refuse if the subject is you, or a protected account; warn if they hold Global Administrator | before anything else |
| Block sign-in | stops new sessions |
| Reset the password to a random value nobody is given | stops password reuse |
| Revoke sign-in sessions | after the two above, so no new token can be minted |
| Remove directory role assignments | admin rights go first |
| Check the mailbox is eligible to be shared (under 50 GB, no archive, no holds) | a warning, so you know before the license goes |
| Convert the mailbox to shared | must happen before the license is removed |
| Forward mail, set the auto-reply, grant the manager full access, hide from the address list | mailbox is now shared; its license goes later, after these steps |
| Cancel the meetings the person organized | destructive, needs its own confirmation |
| Grant the manager access to the OneDrive | before the account is deprovisioned |
| Remove group memberships (Microsoft 365, security, distribution lists) | dynamic groups are reported, not touched; a group that carries a license waits for the mailbox conversion, like a license does |
| Remove directly assigned licenses | depends on the mailbox conversion step; destructive when no conversion is planned and a license grants a mailbox |
| Wipe company-owned devices, retire personal ones | destructive, needs its own confirmation; never wipes a device the provider cannot attribute to the subject |
| Set the employee leave date | optional |

Onboarding creates the user with a generated password (returned to you as a `SecureString`
on the result and never written anywhere), sets the manager, assigns the role's licenses,
adds the role's groups and can issue a Temporary Access Pass. A role change diffs the old
role against the new one and only ever removes groups and licenses that some role in your
policy manages, so ad hoc memberships are left alone. A role change that would take away the last license granting a
mailbox is refused unless `-AllowMailboxLoss` is passed, and then that step is destructive.

```powershell
$plan = New-TenureOnboardPlan -UserPrincipalName bob@example.com -DisplayName 'Bob Example' `
    -Role sales -Manager alice@example.com -Policy ./tenure.policy.json -TemporaryAccessPass
$result = Invoke-TenurePlan $plan
$result.Secrets      # the generated password and the pass, as SecureStrings

$plan = New-TenureRoleChangePlan -User bob@example.com -Role warehouse -Policy ./tenure.policy.json
```

## The safety model

Planning is read-only. Nothing in `New-Tenure*Plan` writes to the tenant, so you can plan
against anyone and just look.

Every step carries a fingerprint of the state it was planned against. Apply refuses a step
whose live state no longer matches, and skips one whose desired state already holds, so a
plan built on Monday cannot silently act on
Wednesday's reality.

`-WhatIf` is PowerShell's own rehearsal: nothing is called, nothing is written, not even to
the audit log. `-DryRun` is a recorded rehearsal: live state is re-read, drift is checked,
and `DryRun` entries go into the audit log.

Confirmation is on by default (`ConfirmImpact` is High). Steps marked destructive (device
wipe, meeting cancellation) ask again on their own, and a "Yes to All" at an earlier prompt
does not cover them. In unattended runs you must pass `-AllowDestructive` as well as
`-Confirm:$false`.

The policy's `protectedUsers` list and the signed-in account can never be the subject of a
plan. An entry can be an object id, a user principal name or a mail address. The check runs
when the plan is built and again before step one of every apply, for every account a step
would change, in custom plans too. The plan records the protected list, so another
administrator can apply it without passing `-Policy`; pass it anyway when you can, because
without it the recorded list is the plan's own word, and a plan that recorded no policy is
refused.

A user whose mailbox cannot be found is refused rather than skipped, unless none of their
licenses carries a service plan that grants a mailbox (an Exchange Online plan other than the
foundation plan, and not disabled). Removing licenses from an account that still has a mailbox
deletes the mailbox after thirty days, so the plan stops and tells you; pass `-SkipMailbox`
once you have checked by hand.

Generated secrets (passwords, Temporary Access Passes) exist only on the apply result as
`SecureString`. They are not in the plan, the plan file, the audit log, verbose output or
error messages, and the test suite checks that. If a run is interrupted after a secret was
generated, `Get-TenureApplyResult` still has it.

The audit log is hash-chained. Editing a line, or deleting one in the middle, is detected by
`Test-TenureAudit`. Deleting the tail is not detectable from the file alone, so the apply
result reports the last sequence number and hash for you to keep elsewhere.

Resuming a run that was interrupted (Ctrl+C, crash, lost connection) is explicit, with
`-Resume`. The engine consults its own audit log. A step that was attempted but never
confirmed is run again only when its provider declares it safe to repeat (session revoke,
device retire and wipe, meeting cancellation). Any other such step stops the run until you
name it with `-AssumeFired`, which the audit log records, and a plan with an assumed step
never ends as Applied.

## Permissions

`Get-TenureProvider` lists every provider with the Graph scopes it needs; `Connect-Tenure`
requests the union of them by default, or pass `-Scopes` to narrow. Exchange Online uses
roles rather than scopes: the signed-in account needs Exchange Administrator (or the
specific recipient roles) for the mailbox steps, and Intune Administrator for device steps.
A 403 from Graph is reported with the provider's scopes so you know what to add.

App-only authentication works with a certificate (`-ClientId -TenantId
-CertificateThumbprint -Organization`). Client secrets work for Graph but Exchange Online
does not support them, so pair a client secret with `-SkipExchange`.

## The policy file

`New-TenurePolicy` writes an example. It is JSON with a schema for editor validation
(`src/Tenure/Policies/tenure.policy.schema.json`). Roles name licenses by SKU part number
and groups by display name, mail address or object id; names are resolved against the
tenant when a plan is built, and an ambiguous name is an error rather than a guess.

```json
{
  "version": 1,
  "tenant": { "domain": "example.com" },
  "defaults": {
    "usageLocation": "US",
    "protectedUsers": ["breakglass@example.com"],
    "offboard": { "forwardTo": "manager", "devices": "wipeCorporateRetirePersonal" }
  },
  "roles": {
    "sales": { "licenses": ["SPE_E3"], "groups": ["sales@example.com", "All Staff"], "department": "Sales" }
  }
}
```

## Custom operations

The three lifecycle commands are built from parts you can use yourself: providers, steps
and a plan. Anything that fits "read state, decide, apply, audit" can be built the same way,
for example a password reset that a help desk runs at the end of a contractor's engagement:

```powershell
$user = @{ Id = '00000000-0000-0000-0000-000000000001'; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice Example' }
$steps = @(
    New-TenureStep -Provider 'User.Password' -Target @{ Kind = 'user'; Id = $user.Id; Name = $user.UserPrincipalName } `
        -Desired @{ discard = $false } -Key 'reset'
)
$plan = New-TenurePlan -Operation Custom -Subject @{ Id = $user.Id; UserPrincipalName = $user.UserPrincipalName; DisplayName = $user.DisplayName } `
    -Step $steps -Policy ./tenure.policy.json
Invoke-TenurePlan $plan
```

## Testing

```powershell
./build.ps1 -Task Test          # unit and adversarial suites, no tenant needed
./build.ps1 -Task CI            # analyzer, tests, manifest check, build
```

The unit suite runs against an in-memory Graph and an in-memory Exchange that serve the
same routes and cmdlets the providers use. Fault injection (throttling, 403, 5xx, torn
audit writes, interrupted runs) and property tests (plan round trips, policy fuzzing,
eligibility predicates) are part of it. Adversarial suites fail the build if any file
calls an SDK cmdlet outside the two seams, or if a seeded secret shows up in any output.

An integration run against a real tenant is planned as an opt-in task (`TENURE_INTEGRATION=1`
and `./build.ps1 -Task Integration`) that creates a throwaway user in a tenant the maintainer
owns, runs the three operations with device steps off, verifies the audit chain and deletes
the user. The harness is not written yet; `ROADMAP.md` tracks it.

## Not in version 1

Deleting the user object, removing MFA methods, revoking OAuth consents, disabling Entra
device objects, PIM eligible assignments, administrative units, scheduling, and any form of
notification. Windows PowerShell 5.1 is not supported.

## Development

`docs/SPEC.md` is the contract, `ROADMAP.md` what is done and what is left,
`docs/adr/` the decisions, `docs/RISKS.md` the risk register. `CONTRIBUTING.md` holds the rules
the code is held to. CI runs the full gate on Ubuntu, Windows and macOS; a GitHub release
from a `vX.Y.Z` tag publishes to the PowerShell Gallery through a rehearsal job and a
gated publish job.

## License

MIT.
