# Spec: Tenure

**Status:** agreed (2026-10-08). Changes to §2, §3 or §4 need an ADR.

## 1. Scope
A PowerShell 7 module that turns a lifecycle request (onboard, role change, offboard)
plus a policy file plus live tenant state into a **plan**, and applies plans through a
generic engine with drift checks, `-WhatIf`/`-DryRun`, confirmation, dependency order,
resume, and a hash-chained audit log. Everything tenant-specific lives in the policy
file or in parameters. Nothing tenant-specific lives in code.

Not covered: user deletion, MFA method removal, OAuth consent revocation, Entra device
object disable, PIM, granting directory roles, directly or through role-assignable groups (Tenure only removes
them), administrative units, GUI, scheduling,
notifications.

## 2. Domain model

### 2.1 Policy (`Tenure.Policy`)
Loaded from JSON by `Get-TenurePolicy`. Shape (all keys camelCase):

```jsonc
{
  "version": 1,
  "tenant": { "domain": "example.com" },           // UPN suffix for new users
  "defaults": {
    "usageLocation": "US",
    "passwordLength": 20,
    "protectedUsers": ["breakglass@example.com"],   // plan refuses these as subjects (object id, UPN or mail)
    "offboard": {
      "resetPassword": true,
      "revokeSessions": true,
      "removeDirectoryRoles": true,
      "convertMailboxToShared": true,
      "hideFromAddressLists": true,
      "forwardTo": "manager",                        // "manager" | "none" | "<smtp address>"
      "deliverToMailboxAndForward": true,
      "autoReply": { "enabled": true, "message": "{displayName} is no longer with the company. Please contact {managerDisplayName} ({managerMail})." },
      "grantMailboxTo": "manager",                   // "manager" | "none" | "<upn>"
      "grantOneDriveTo": "manager",
      "cancelMeetings": true,
      "removeFromGroups": true,
      "keepGroups": [],                              // names, mails or ids never removed
      "removeLicenses": true,
      "devices": "wipeCorporateRetirePersonal",      // | "retireAll" | "none"
      "setEmployeeLeaveDate": false
    }
  },
  "roles": {
    "sales":   { "licenses": ["SPE_E3"], "groups": ["sales@example.com", "All Staff"], "department": "Sales" },
    "warehouse": { "licenses": ["EXCHANGEDESKLESS"], "groups": ["Warehouse Users"], "department": "Operations", "jobTitle": "Warehouse Associate" }
  }
}
```

Invariants:
- `version` is 1. Unknown top-level keys are an error; unknown keys inside `roles.*`
  are an error (typos must not pass silently).
- `roles` may be empty. A role's `licenses` are SKU part numbers (strings);
  `groups` are display names, mail addresses, or object ids.
- `forwardTo`, `grantMailboxTo`, `grantOneDriveTo` accept the literal `manager`,
  `none`, or an address.
- `Hash`: SHA-256 of the canonical JSON of the loaded policy (used in plans).
- **Managed set**: the union of every `licenses` and `groups` value across all roles.
  Role changes only ever remove items in the managed set.

### 2.2 Provider (`Tenure.Provider`)
Registered at module load by files in `Private/Providers/`.

```
Name        'Area.Resource'            e.g. User.SignIn, Mailbox.Type, Device.Wipe
Kind        'State' | 'Invoke' | 'Check'
Backend     'Graph' | 'Exchange'
Scopes      string[]                   Graph delegated/app scopes this provider needs
Risk        'Low' | 'Medium' | 'High' | 'Destructive'
Reversible  bool
Repeatable  bool (Invoke only, default false)   firing it twice does no harm, so a resumed run may fire it again
TargetKind  'user'|'group'|'device'|'mailbox'|'drive'|'role'   the one kind of object the provider acts on
Actions     string[]                   the step actions the provider allows: from Create, Update, Remove, NoOp for
                                       State; Invoke for Invoke; Check, NoOp for Check
AffectedBy  string[] (Check only, required, may be empty)   providers whose steps change what the check reads
Get         { param([hashtable]$Target, [hashtable]$Context) -> [pscustomobject] }   current state, no secrets
Test        { param($Current, $Desired) -> [bool] }                                   true when satisfied
Set         { param([hashtable]$Target, $Desired, $Current, [hashtable]$Context) -> [pscustomobject] }   State/Invoke only
Describe    { param([hashtable]$Target, $Current, $Desired, [string]$Action) -> [string] }   one line, no secrets
Severity    'Warn' | 'Refuse'          Check only: what a failing Test does to the plan
```

Invariants:
- `TargetKind` and `Actions` are declared by every provider and are authoritative. A step whose `Target.Kind` is not
  its provider's `TargetKind`, or whose `Action` is not in its provider's `Actions`, is refused by `New-TenureStep`
  (`Tenure.Step.InvalidTarget`, `Tenure.Step.Invalid`) and by the apply engine and `Test-TenurePlan`
  (`Tenure.Plan.Invalid`). The engine reads the account a step changes from the provider: `Target.Id` for a
  provider whose `TargetKind` is user, mailbox or drive; `After.userId` (or the subject) for a group or role
  membership. `DirectoryRole.Member` allows `Remove` and `NoOp` only, and its `Set` refuses an add (`member = $true`)
  with `Tenure.Provider.Unsupported` before any request: Tenure removes directory roles and never grants them.
  `Group.Member` reads `isAssignableToRole` and refuses an add to a role-assignable group the same way, from the live
  state before any request and again from its own group read before the write; removing a member is allowed.
- Identifiers are strings: `Target.Id`, and `After.userId` when a step has one, must be non-empty strings, in every
  plan, Custom ones included (`New-TenureStep`: `Tenure.Step.InvalidTarget` / `Tenure.Step.Invalid`; the engine and
  `Test-TenurePlan`: `Tenure.Plan.Invalid`). A step of a provider whose `TargetKind` is mailbox or drive names its
  target by the owner's Entra object id (or `{{subjectId}}`): Exchange resolves an alias, display name or proxy
  address, and the protection check knows only ids, user principal names and mail addresses.
  Declared values:
  `Check.SubjectNotGlobalAdmin` is affected by `DirectoryRole.Member`, `Check.UserAbsent` by `User.Create`,
  `Check.MailboxSharedEligibility` by `Mailbox.Type`, `Check.SubjectAllowed` by nothing.
- `Set` then `Get` then `Test` is true for `State` providers.
- `Get` on a missing target throws `Tenure.Provider.TargetNotFound`.
- `Get`/`Set` only reach the tenant through `Invoke-TenureGraph` / `Invoke-TenureExchange`.
- Exchange identities: Exchange is not trusted to resolve an Entra object id given as `-Identity`. The
  `Get-EXOMailbox` and `Get-EXOMailboxStatistics` reads name a mailbox by `-ExternalDirectoryObjectId` (the
  Entra id in `Target.Id`); every other cmdlet gets a user principal name or primary SMTP address for
  `-Identity`, `-User`, `-Member` and `-ForwardingAddress`. A distribution group is named by `Target.Mail`,
  and the group Exchange returns must carry `Target.Id`. A read maps a failure to
  `Tenure.Provider.TargetNotFound` only when it says "'<value>' couldn't be found" for a value it asked for.
- `Context` carries `Policy`, `Subject`, `Session`, `Mode` ('Plan'|'Apply'|'DryRun'), `StepId` (apply time),
  `ProtectedUsers` (apply and test time: the `-Policy` list, or the list the plan recorded) and a `Secrets` hashtable; a `Set` that creates a secret puts it in `Context.Secrets[<stepId>]` as
  `SecureString` and returns a state object that does not contain it. Provider scriptblocks are invoked
  plainly (`& $provider.Get $Target $Context`); they run in the scope they were created in. While a plan
  builder runs (`Mode` 'Plan'), `ExchangeAddresses` holds the address of each mailbox already read by
  Entra id, so the steps of one plan read it once, `GroupLicenses` caches each group's license assignments, and
  `MemberOf` holds the ids `users/{id}/memberOf` listed; the apply engine passes none of them.
- Snapshots hold only state that changes when someone changes the object. A field that moves on its own (a
  device's `lastSyncDateTime` and `managementState`, a mailbox's size) is left out or reduced to the fact a
  decision depends on, because it would make every plan drift between planning and applying.
- A membership read (`Group.Member`, `DirectoryRole.Member`) that answers "not a member" while `Context.MemberOf`
  lists the group or role refuses with `Tenure.Provider.InconsistentState` instead of taking the "no".
  `DistributionGroup.Member` has no such cross-check: Exchange's member list is not compared with `memberOf`.
- A membership provider's `Get` reads the membership of `Context.Subject.Id`. For a step of a provider whose
  `TargetKind` is group or role, `New-TenureStep` (the snapshot), the engine (before and after `Set`) and
  `Test-TenurePlan` pass a context whose `Subject.Id` is the step's `After.userId`, the user the step changes.
- Snapshots that the plan's own earlier steps move are reduced too: `User.Licenses` keeps only the directly
  assigned SKU ids (`skuIds`), the only ones it changes; inherited licenses and the usage location come from
  `Get-TenureUserLicenseState` for builders and `Set`. `User.Sessions` keeps the user's id and user principal name
  only, not `signInSessionsValidFromDateTime`, which its own revoke moves.
- While a plan is built for a user an earlier step creates, `Context.Subject.Id` may be the `{{subjectId}}`
  placeholder; the membership providers then read "not a member" without asking and name the user by the
  placeholder in the snapshot.
- `Invoke` providers: `Get` returns whatever is needed for `Describe`; `Test` returns
  `$false`; idempotency is by the audit log (an Invoke step the log records as Applied or Skipped is skipped on
  resume; one the plan file alone calls done is in doubt, see 5.4). `Repeatable` says whether firing it twice is
  harmless.

### 2.3 Step (`Tenure.Step`)
```
Id           'S01'..'S99' (assigned by New-TenurePlan in order)
Provider     provider name
Kind         copied from provider
Target       @{ Kind='user'|'group'|'device'|'mailbox'|'drive'|'role'; Id; Name }   Kind is the provider's TargetKind;
             Id a non-empty string (an Entra object id for a mailbox or drive)
Action       'Create' | 'Update' | 'Remove' | 'Invoke' | 'Check' | 'NoOp'          one of the provider's Actions
Before       object (Get snapshot at plan time; $null only for a Create, or for a step whose Target.Id is {{subjectId}})
After        object (desired state)                     -- never contains a secret; a userId in it is a non-empty string
Fingerprint  sha256 hex of canonical JSON of @{ Target = @{ Kind; Id }; Before }; never empty. A $null Before is
             hashed as null: for a Create it means "the target does not exist", for a {{subjectId}} step it binds
             the placeholder target.
Risk         copied from provider (plan builder may raise, never lower)
Reversible   copied from provider
Reason       string, human
DependsOn    string[] of step ids
Status       'Pending' | 'Applied' | 'Skipped' | 'Failed' | 'DryRun' | 'Drifted' | 'Refused' | 'Declined'
Result       $null or @{ At; DurationMs; Observed; Error; Note; Attempted; Uncertain; Assumed }
```
Invariants: `Action` is `NoOp` iff `Test(Before, After)` was true at plan time. The apply engine writes only
`Status` and `Result`; `Target` and `After` keep any `{{subjectId}}` placeholder, which every run fills in from
`Subject.Id` in a copy. `Result.Assumed` is set, and stays set, when the operator named the step in
`-AssumeFired`, or when the audit log shows an earlier run that skipped the step because it was named there.
`Declined` records that the operator answered No at the step's confirmation; nothing was changed and nothing is
audited, and the plan counts the step as not done.

### 2.4 Plan (`Tenure.Plan`)
```
SchemaVersion 2
PlanId        guid
CreatedAt     UTC ISO 8601
CreatedBy     @{ Account; TenantId; AuthType }
ModuleVersion
Operation     'Onboard' | 'RoleChange' | 'Offboard' | 'Custom'
Subject       @{ Id; UserPrincipalName; DisplayName }     (Id $null until an Onboard is applied)
PolicyHash    sha256 hex or $null   ($null: the plan cannot be applied or tested, see 5.4)
PolicySnapshot @{ ProtectedUsers = string[]; ManagedSet = @{ Licenses; Groups } } recorded from the policy, or $null
Inputs        hashtable of the request parameters, secrets excluded
Steps         Tenure.Step[] in execution order
Warnings      string[]
Status        'Planned' | 'DryRun' | 'Applied' | 'PartiallyApplied' | 'Failed'
Integrity     sha256 hex: Get-TenurePlanIntegrity, sealed by New-TenurePlan
```
Invariants: step ids unique; every `DependsOn` target exists and precedes the step;
no step's `Before`/`After`/`Reason` contains a value from `Context.Secrets`. `New-TenurePlan -Inputs $null` records
an empty table. Built with `-Policy` while connected to Graph, a plan carries a warning for each `protectedUsers`
entry that matches no user of the tenant (by object id, user principal name or mail address): it protects no one.

`Integrity` is the SHA-256 of the canonical JSON of `SchemaVersion`, `PlanId`, `CreatedAt` (UTC `o`),
`CreatedBy`, `ModuleVersion`, `Operation`, `Subject`, `PolicyHash`, `PolicySnapshot`, `Inputs`, `Warnings` and,
for every step in order, `Id`, `Key`, `Provider`, `Kind`, `Target`, `Action`, `Before`, `After`, `Fingerprint`,
`Risk`, `Reversible`, `Reason` and `DependsOn`. Left out are what the apply engine writes: `Plan.Status`, each
step's `Status` and `Result`, and `Subject.Id` when the plan was sealed without one (an onboarding; the value
is then computed with `Subject.Id` null). `Import-TenurePlan`, `Export-TenurePlan`, `Test-TenurePlan` and
`Invoke-TenurePlan` recompute it and refuse a mismatch with `Tenure.Plan.Tampered`. It is a plain hash, not a
signature (ADR-0007): it catches a file edited by hand or by a tool that does not recompute it, not a forger who
reimplements the formula. A resealed plan is a new plan; the checks it still meets are listed in ADR-0007.

### 2.5 Audit entry (`Tenure.AuditEntry`), one JSON object per line
```
Seq, Ts, PrevHash, Hash, PlanId, Operation, StepId, Provider, Target, Action, Actor (@{Account; TenantId}),
Outcome ('Attempting'|'Applied'|'Skipped'|'Failed'|'DryRun'|'Drifted'|'Refused'|'PlanStarted'|'PlanFinished'),
Before, After, Observed, Error, Note, DurationMs, ModuleVersion, Format (1), Host, Mode ('Apply'|'DryRun')
```
`Attempting` is a write-ahead entry recorded before `Set` runs for any Invoke step, any Create step, and any step
with effective risk Destructive, so a crash between `Set` and its result still leaves evidence that the step may
have fired. The engine trusts that evidence, not the plan file's `Result.Attempted`, when it adopts a created
account or passes a user-absent check on resume. An attempt lasts from its `Attempting` entry to the next entry for
the same step, or the plan's next `PlanFinished` or `PlanStarted`, whichever comes first. It ended in a refused
request when that next entry is `Failed` with an error showing the request was refused before or by the service
(`Tenure.Graph.Forbidden`, `NotFound`, `NotConnected`; `Tenure.Exchange.NotConnected`, `CommandUnavailable`;
`Tenure.Provider.InvalidDesired`, `Precondition`, `Unsupported`; `Tenure.Graph.Failed` with a 4xx status other than
408). Any other failure may have landed.
`Hash = sha256(PrevHash + canonicalJson(entry without Hash))`. First `PrevHash` is 64 zeros.
Line format: the canonical JSON of the entry without `Hash`, with `,"Hash":"<hex>"` appended as the
last member. The verifier strips that suffix and re-hashes the stored text, so re-serialization can
never report tampering that did not happen. `Note` explains Skipped, Drifted and Refused outcomes.
`PlanStarted` carries in `Observed` the plan's status, step count, `CreatedAt`, `CreatedBy`, `PolicyHash`,
`Integrity`, `Inputs` and `Warnings`, and the run's options (including `AssumeFired` and whether `-Policy` was
given); `PlanFinished` carries the final status and summary. A later run reads both back: a `PlanFinished` of an
Apply run whose status is `Applied` makes the plan already applied (5.4), and a step skipped in a run whose
`PlanStarted` named it in `AssumeFired` stays assumed. `Actor` on every entry is the account that ran it,
which may differ from the plan's `CreatedBy`.
The writer takes an exclusive lock (FileShare.None) with a short retry, so two writers interleave safely.

### 2.6 Apply result (`Tenure.ApplyResult`)
```
Plan      the plan with updated statuses
Summary   @{ Applied; Skipped; Failed; DryRun; Drifted; Refused; Pending; Declined }
Secrets   hashtable stepId -> SecureString (empty when none)
AuditPath
AuditHead @{ Seq; Hash } of the last entry written (the external anchor for Test-TenureAudit; tail deletion is
          undetectable without one)
```
The last result of the session is also kept in module state and returned by `Get-TenureApplyResult`, so a run
interrupted with Ctrl+C after a secret was generated can still hand the secret over.

## 3. Interfaces

### 3.1 Seams (private)
```powershell
Invoke-TenureGraph    -Method GET|POST|PATCH|PUT|DELETE -Uri <relative 'users/{id}' | '/beta/...' | absolute>
                      [-Body <object>] [-All] [-Headers <hashtable>] [-MaxRetry 3]
   -> PSCustomObject (with -All: the concatenated value[] across @odata.nextLink)
   throws Tenure.Graph.NotConnected, Tenure.Graph.NotFound (404), Tenure.Graph.Forbidden (403, message names the provider scopes),
          Tenure.Graph.Throttled (429 after retries), Tenure.Graph.Failed (other 4xx/5xx; Data: StatusCode, Code, Message, RequestId)
Invoke-TenureExchange -Command <string> [-Parameters <hashtable>]
   -> whatever the cmdlet returns
   throws Tenure.Exchange.NotConnected, Tenure.Exchange.CommandUnavailable, Tenure.Exchange.Failed (Data: Inner)
Assert-TenureConnection -Backend Graph|Exchange     throws the NotConnected ids above
Get-TenureCanonicalJson -InputObject <object> -> string (keys sorted recursively, compressed, dates as 'o')
Get-TenureHash -InputObject <object|string> -> lowercase sha256 hex
New-TenureError -Id <string> -Message <string> [-Category <ErrorCategory>] [-Data <hashtable>] [-Inner <ErrorRecord>] -> ErrorRecord
Register-TenureProvider -Definition <hashtable>    validates and stores in $script:Providers
Resolve-TenureUser -Identity <upn|id> -> @{ Id; UserPrincipalName; DisplayName; AccountEnabled; Mail; ManagerId }  (throws Tenure.User.NotFound)
Resolve-TenureGroup -Identity <name|mail|id> -> @{ Id; DisplayName; Mail; GroupTypes; MembershipRule; MailEnabled; SecurityEnabled;
                    IsDynamic; IsUnified; IsExchangeManaged; IsAssignableToRole }  (throws Tenure.Group.NotFound / Tenure.Group.Ambiguous)
Resolve-TenureSku -PartNumber <string> -> @{ SkuId; SkuPartNumber; Available }  (throws Tenure.Sku.NotFound)
Get-TenureUserIdentity -Identity <upn|id> -> @{ Id; UserPrincipalName; Mail } or $null on 404
Get-TenureGroupLicense -GroupId <id> [-Cache <hashtable>] [-Detailed] -> sku ids the group assigns (assignedLicenses); with
                    -Detailed, @{ SkuId; DisabledPlans } per assignment
Get-TenureUserExchangePlan -UserId <id> -> @{ SkuId; SkuPartNumber; ServicePlanName } per service plan that grants a mailbox (see 5.5)
Get-TenureMailboxSku -> @{ SkuId; SkuPartNumber; Enabled; Consumed; Available; MailboxPlanIds } per subscribed sku
                    (MailboxPlanIds: the service plans that grant a mailbox; unreported plans give none)
Get-TenureGraphLongestCall -> the longest one Invoke-TenureGraph call can take: 4 attempts of the SDK client
                    timeout (5 minutes by default) and 3 waits of at most 60 s, 23 minutes
Get-TenureUserLicenseState -UserId <id> -> @{ skuIds; inheritedSkuIds; inheritedFrom; usageLocation }
Test-TenureProtectedEntry -Entry <string> -> true when a protectedUsers entry names a user of the tenant
Get-TenurePlanIntegrity -Plan <Tenure.Plan> -> sha256 hex (2.4)
New-TenurePassword -Length 20 -> SecureString   (upper, lower, digit, symbol; crypto RNG)
Write-TenureAudit -Entry <hashtable> [-Path] -> Tenure.AuditEntry   (appends, chains)
```

### 3.2 Public
```powershell
Connect-Tenure      [-TenantId] [-Scopes <string[]>] [-ClientId] [-CertificateThumbprint] [-Certificate <X509Certificate2>]
                    [-ClientSecretCredential <PSCredential>] [-UseDeviceCode] [-SkipExchange] [-Environment Global|USGov|USGovDoD|China]
                    -> Tenure.Connection
Disconnect-Tenure
Get-TenureConnection -> Tenure.Connection  (@{ Account; TenantId; AuthType; Graph: bool; Exchange: bool; Scopes; ConnectedAt })
Get-TenureProvider  [-Name] -> Tenure.Provider[]
Get-TenurePolicy    -Path <string> -> Tenure.Policy        (throws Tenure.Policy.Invalid with the JSON path of the first problem)
Test-TenurePolicy   -Path <string> -> @{ Valid: bool; Errors: string[] }
New-TenurePolicy    -Path <string> [-Force]              writes the example policy
New-TenureStep      -Provider <name> -Target <hashtable> [-Desired <object>] [-Reason] [-DependsOn <string[]>] [-Context <hashtable>] -> Tenure.Step
New-TenurePlan      -Operation <string> -Subject <hashtable> -Step <Tenure.Step[]> [-Policy <Tenure.Policy>] [-Inputs <hashtable>] [-Warning <string[]>] -> Tenure.Plan
New-TenureOnboardPlan    -UserPrincipalName -DisplayName [-GivenName] [-Surname] -Role <string> -Policy <Tenure.Policy|path>
                         [-Manager <upn>] [-Department] [-JobTitle] [-UsageLocation] [-AdditionalGroup <string[]>] [-AdditionalLicense <string[]>]
                         [-TemporaryAccessPass] [-MailNickname] -> Tenure.Plan
New-TenureRoleChangePlan -User <upn|id> -Role <string> -Policy <...> [-FromRole <string>] [-Manager] [-Department] [-JobTitle] [-KeepGroup <string[]>]
                         [-AllowMailboxLoss] -> Tenure.Plan
New-TenureOffboardPlan   -User <upn|id> -Policy <...> [-ForwardTo <'manager'|'none'|smtp>] [-GrantMailboxTo] [-GrantOneDriveTo]
                         [-Devices wipeCorporateRetirePersonal|retireAll|none] [-AutoReplyMessage] [-KeepGroup <string[]>]
                         [-SkipLicenseRemoval] [-SkipMailbox] [-SkipDevices] -> Tenure.Plan
Show-TenurePlan     -Plan <Tenure.Plan> [-PassThru] -> string[] (and writes to host)
Export-TenurePlan   -Plan -Path [-Force]
Import-TenurePlan   -Path -> Tenure.Plan   (throws Tenure.Plan.UnsupportedSchema, Tenure.Plan.Invalid)
Test-TenurePlan     -Plan [-Policy] -> @{ Drifted; Satisfied; Pending; Unverified: Tenure.Step[] }   (read-only;
                    refuses as Invoke-TenurePlan's preflight does: Invalid, Tampered, WrongTenant, PolicyMissing,
                    PolicyMismatch, Refused). It does not read the audit log: an Invoke step the plan file alone calls
                    Applied or Skipped is Unverified.
Invoke-TenurePlan   -Plan <Tenure.Plan|path> [-Policy] [-DryRun] [-Force] [-AllowStale] [-Resume] [-ContinueOnError] [-AllowDestructive]
                    [-AssumeFired <step id[]>] [-MaxAge <timespan>=24h] [-AuditPath] [-OutFile]
                    SupportsShouldProcess, ConfirmImpact=High -> Tenure.ApplyResult
                    -Force overrides drift (not a Create whose target exists) and the audit log's record that the plan
                    already finished Applied (not a plan file that says Applied). -AllowStale overrides the plan-age
                    checks. -Resume acknowledges an open or interrupted earlier run of the same plan and runs a
                    Repeatable Invoke step in doubt again (see 5.4). -AssumeFired records named Invoke steps in doubt
                    as fired. When -Plan is a path, -OutFile defaults to that path and the file is rewritten after
                    every status change.
Get-TenureApplyResult -> Tenure.ApplyResult (the last result of this session, or $null)
Get-TenureAudit     [-Path] [-PlanId] [-Last <int>] [-Since <datetime>] -> Tenure.AuditEntry[]
Test-TenureAudit    [-Path] -> @{ Valid: bool; Entries: int; FirstBrokenSeq: int?; Problem: string? }   (Problem names the
                    breaking line; for a torn last line it gives the command that keeps the lines before it)
```

## 4. Data schema
- Plan file: JSON, `SchemaVersion: 2`, the plan object as in section 2.4 (PascalCase property names, dates as UTC `o` strings, hashtable keys sorted) with `ConvertTo-Json -Depth 20`.
  Written through a temporary file that is flushed to disk before it is renamed over the target.
  Import refuses any `SchemaVersion` other than 2 (`Tenure.Plan.UnsupportedSchema`: a newer one needs a newer module;
  version 1 files carry no integrity value and empty fingerprints, so they are not migrated and must be planned again),
  refuses an `Integrity` that does not match (`Tenure.Plan.Tampered`), and matches property names case-insensitively.
- Audit file: JSONL per §2.5. Default `~/.tenure/audit.jsonl` (`$HOME` on all OSes),
  env override `TENURE_AUDIT_PATH`, parameter override `-AuditPath`.
- Policy schema: `src/Tenure/Policies/tenure.policy.schema.json` (JSON Schema draft 7) mirrors §2.1.

## 5. Semantics and decision rules

### 5.1 Offboard step order (and why)
1. `Check.SubjectAllowed` (refuse if subject is the signed-in account or in `protectedUsers`) and
   `Check.SubjectNotGlobalAdmin` (warn).
2. `User.SignIn` → `accountEnabled=false`.
3. `User.Password` → reset to a generated value (Invoke; value never leaves `Secrets`, and for offboarding is discarded, not returned).
4. `User.Sessions` → `revokeSignInSessions` (Invoke). After 2 and 3 so no new tokens can be minted.
5. `DirectoryRole.Member` → one Remove step per active role assignment.
6. `Check.MailboxSharedEligibility` → warn when size ≥ 50 GB, archive enabled, or litigation/retention hold (a shared mailbox then still needs a license).
   The snapshot holds the facts only (over the limit or not, archive or not, which kinds of hold), never the size.
7. `Mailbox.Type` → `Shared`.
8. `Mailbox.Forwarding` → resolved address, `DeliverToMailboxAndForward` per policy.
9. `Mailbox.AutoReply` → enabled, internal and external message rendered from the template.
10. `Mailbox.Delegate` → FullAccess (no automapping) to the resolved grantee. The grantee rides on the target (`Target.Grantee`) because `Get` has no `Desired`.
11. `Mailbox.Hidden` → `HiddenFromAddressListsEnabled=true`.
12. `Calendar.CancelMeetings` → `Remove-CalendarEvents -CancelOrganizedMeetings` (Invoke, Destructive).
13. `OneDrive.Access` → `drive/root/invite` write role to the grantee, `sendInvitation=false`.
14. `Group.Member` (Graph) / `DistributionGroup.Member` (Exchange) → one Remove per membership not in `keepGroups`.
    Dynamic groups: step emitted as `NoOp` with reason "dynamic membership" (a warning when the group carries a license).
    Sole-owner groups: warning. A group that carries a license (its `assignedLicenses`, read once per plan, or the
    user's license states naming it) is handled like step 15: its removal `DependsOn` the `Mailbox.Type` step, its
    reason says the group carries a license, and it is left out with a warning when license removal is off
    (`-SkipLicenseRemoval` or `removeLicenses: false`).
15. `User.Licenses` → remove all directly assigned SKUs, listed by id in the step's `remove` delta. `DependsOn` = the `Mailbox.Type` step id when present.
    The reason says which group-inherited SKUs go with a group removal of this plan and which stay because the user
    stays in the group. When the plan has no `Mailbox.Type` step and a license of the user grants a mailbox (5.5),
    this step and every license-carrying group removal are Risk `Destructive`, with a plan warning: removing the
    license deletes the mailbox after about 30 days.
16. `Device.Wipe` / `Device.Retire` → one step per Intune managed device by ownership (`company` → wipe, `personal` → retire) or `retireAll`.
    `Device.Retire`, `Device.Wipe`, `User.Sessions` and `Calendar.CancelMeetings` are Repeatable; `User.Password` and
    `User.TemporaryAccessPass` are not.
17. `User.LeaveDate` → `employeeLeaveDateTime = now` when `setEmployeeLeaveDate` is true (its own provider and scope, `User-LifeCycleInfo.ReadWrite.All`; delegated use also needs Global Administrator).

### 5.2 Onboard step order
1. `Check.UserAbsent` → refuse if the UPN or mail nickname already exists (including soft-deleted users).
2. `User.Create` → UPN, displayName, mailNickname, givenName, surname, usageLocation, department, jobTitle, officeLocation,
   `passwordProfile` with a generated password and `forceChangePasswordNextSignIn=true`. Password goes to `Secrets['S02']`.
3. `User.Manager`.
4. `User.Licenses` → add role SKUs. Warn when `Available` is 0 for any SKU.
5. `Group.Member` → one Add per role group (plus `-AdditionalGroup`). A role-assignable group is left out with a
   warning: Tenure never grants roles, including through role-assignable groups (the same holds for role changes).
6. `User.TemporaryAccessPass` → when requested; value to `Secrets`.
Steps 3 to 6 `DependsOn` step 2. Steps 3, 4 and 6 target the literal placeholder `{{subjectId}}` (built with
`New-TenureStep -SkipSnapshot -Action ...`, `Before` null, the fingerprint binding the placeholder target). Step 5
targets the group; its snapshot is taken at plan time with the new user named by the placeholder ("not a member")
and its `After.userId` is the placeholder. The engine substitutes the id observed from the create step, into fresh
copies, every time it runs these steps; for step 5 it compares the live membership with the snapshot after the
same substitution. The create step's fingerprint binds its target as absent.

### 5.3 Role change
- Desired = new role's licenses and groups (plus `-AdditionalGroup` style extras later).
- Remove = (current licenses and groups ∩ managed set) − desired, minus `-KeepGroup`.
  With `-FromRole`, the removal set is limited to that role's items.
- Add = desired − current.
- Attribute updates (department, jobTitle, manager) only when supplied or defined on the role.
- The `User.Licenses` step's Desired is a delta, `@{ add = <sku ids>; remove = <sku ids> }` (both lists
  required). `remove` lists only the managed licenses the user holds now, so applying the step, even with
  `-Force`, never removes a license the plan did not show. The same shape is used by the other builders.
- A subject listed in `protectedUsers` is refused with `Tenure.Plan.Refused`.
- The mailbox: a user who holds a license with Exchange Online (5.5), directly or through a group, keeps a mailbox
  only while one such license stays. The builder works out which of those licenses survive the change (a direct
  one the license step does not remove; an inherited one whose group the plan does not remove; a dynamic group's
  removal is a NoOp) and which the change brings (the license step's `add`, and the licenses of groups it adds).
  It counts service plans, not SKU ids: an assignment keeps the mailbox only when one of the SKU's service plans
  that grant a mailbox (`Get-TenureMailboxSku`) is not in that assignment's `disabledPlans` (the direct
  assignment's, or the group's from `Get-TenureGroupLicense -Detailed`; a group that no longer reports the
  assignment does not count), and a license a new group brings counts only when its SKU has a free seat
  (`prepaidUnits.enabled` minus `consumedUnits`), because group-based licensing fails quietly. When none survives
  and none is added, the plan is refused with `Tenure.Plan.MailboxUnlicensed`, naming each license and the group it
  comes through and any group license that lacks a seat,
  unless `-AllowMailboxLoss` is given; then the license step (when it removes such a license) and the removals of
  groups that carry one are Risk `Destructive`, with a plan warning.

### 5.4 Apply engine
For each step in order:
1. A `DependsOn` step is met only when this run applied or skipped it (`DryRun` in a dry run; simulated under
   `-WhatIf`), or when a live `Get` plus `Test` of that step shows its desired state holds now (never for an Invoke
   or a Create step). A status an earlier run left in the plan does not count. Not met: `Refused` ("dependency
   S07 not applied"); stop unless `-ContinueOnError`.
2. `Invoke` step the audit log records as `Applied` or `Skipped` (resume) → `Skipped`. One in doubt (below) → runs
   again only under `-Resume` when Repeatable, `Skipped` with `Result.Assumed` when named in `-AssumeFired`, else
   `Refused` and the run stops.
3. `Get` current (a Create's `TargetNotFound` is current `$null`). If `Fingerprint` is not the fingerprint of the
   step's Target and current state (2.3) and not `-Force` → `Drifted`, audit, stop unless `-ContinueOnError`. A step
   retargeted in the plan file therefore drifts even when the new target looks the same. A Create whose target
   exists drifts (its fingerprint means "absent") and `-Force` does not override that. A step on the
   `{{subjectId}}` placeholder with no snapshot checks only its binding. A snapshot that names the subject by the
   placeholder is compared after the placeholder is filled in.
   A `State` step (not a Create) is tested before the drift check: `Test(current, After)` true gives `Skipped` ("already
   satisfied"), with no drift verdict, because there is nothing to do; an earlier step of the plan may have moved
   the state the snapshot describes. A `Check` whose provider's `AffectedBy` names the provider of a step of this
   plan that changed state (an `Applied` entry in the audit log, or an attempt that did not end in a refused
   request, or `Applied` in this run) is evaluated against the live state instead of drift-checked: passing gives
   `Skipped` with a note, failing gives `Refused`, and the run stops (whatever its `Severity`).
4. `State`/`Check`: if `Test(current, After)` → `Skipped` (already satisfied). `Check` failing with `Severity=Refuse` → `Refused`, stop.
5. `-DryRun` → `DryRun`, audit with `Mode=DryRun`, continue.
6. `Risk=Destructive` and `-Confirm:$false` without `-AllowDestructive` → `Refused`, stop.
7. `ShouldProcess(target, description)` false: under `-WhatIf` the status stays `Pending`; a declined prompt (or a
   declined Destructive question) makes the step `Declined`, recorded in the plan and the plan file. Neither is
   written to the audit log (`-WhatIf` has no side effects at all). Continue.
   The description is the provider's own `Describe` of the change, worked out from the live state; the Destructive
   question names the provider and that description. Neither rests on the plan's `Reason` text.
8. `Set`, then `Get`, then `Test(observed, After)`; false → `Failed` ("post-condition not met"). Audit. Stop on failure unless `-ContinueOnError`.
   The `Get` before and after `Set` reads the step's own target: for a membership step, the user in `After.userId`
   (2.2), so a change for someone other than the plan's subject is read back and audited as what it did.
Resume rules: an `Invoke` step the audit log records as `Applied` or `Skipped` never fires again (and stays marked
assumed when the run that skipped it named it in `-AssumeFired`); a `State` step is tested against `After` before
the drift check (step 3) so the run's own earlier change is not reported as drift. A `Check` with `Severity=Refuse` stops the plan even with `-ContinueOnError`. Confirmation counts as suppressed when `-Confirm:$false` is passed or the effective `$ConfirmPreference` is `None`. The plan file can never lower safety: the effective risk is the higher of the step's and the provider's, and `Kind`/`Severity` always come from the registered provider, whose `TargetKind` and `Actions` every step must
match. `-WhatIf` runs against a copy of the plan and writes nothing.
Before step 1 of the first step: preflight. Refuse the whole plan when its `Integrity` does not match
(`Tenure.Plan.Tampered`), when a step's `Target.Kind` is not its provider's `TargetKind` or its `Action` is not in
the provider's `Actions` (`Tenure.Plan.Invalid`), when `CreatedAt` is older than `-MaxAge` (or more than 5 minutes
in the future) unless `-AllowStale`, when any required backend (and Graph) is not connected, when the plan names
no tenant or a tenant (`CreatedBy.TenantId`) other than the connected one (`Tenure.Plan.WrongTenant`), when
`-Policy` is not given and the plan records no `PolicyHash` or no `PolicySnapshot` (`Tenure.Plan.PolicyMissing`),
when `-Policy` is given and has no `Hash`, or its hash is not the plan's `PolicyHash`, or the plan records none
(`Tenure.Plan.PolicyMismatch`), when `Plan.Status` is `Applied`, when a step has no fingerprint, when a step
without a snapshot is neither a Create nor on the placeholder, when `-AssumeFired` names anything but an Invoke
step of the plan, when the plan was sealed without a subject id and the id it carries now is not one the audit log
shows this plan's create step producing (`Tenure.Plan.Tampered`), when the audit log shows a `PlanStarted` for
this plan with no later `PlanFinished` (another run is in flight or died) unless `-Resume`, or when the audit log
shows a `PlanFinished` of an Apply run of this plan with status `Applied`, whatever the plan file says
(`Tenure.Plan.AlreadyApplied`), unless `-Force`. That is known only to the audit log this run reads: a plan applied
on one machine can be applied again from its file on another machine, whose audit log has no record of it, within
`-MaxAge`. Apply a plan from the machine that keeps its audit log.
Subject protection is part of preflight and does not depend on a `Check.SubjectAllowed` step: for every plan,
Custom plans included, the subject and every account a non-Check step changes (`Target.Id` of a step whose
provider's `TargetKind` is user, mailbox or drive, whatever the `Target.Kind` label says, and `After.userId` of a
membership) is read once (`Get-TenureUserIdentity`) and compared, by object id, user
principal name and mail address, with the signed-in account and with the protected users of `-Policy` or, when
none is given, the list the plan recorded (`PolicySnapshot`). A match refuses the plan with `Tenure.Plan.Refused`
before step 1 and before `PlanStarted`.
The audit log is also consulted for this plan's step outcomes: an Invoke step with an `Applied` or `Skipped`
entry is Skipped. Statuses are not sealed, so an Invoke step the plan file calls Applied or Skipped without the
audit log's record is in doubt too, and a status edited to hide a revoke or a wipe stops the run instead of
silencing the step. An Invoke step in doubt (an `Attempting` entry and no outcome, or a Failed result of
`Tenure.Apply.Interrupted`) runs again under `-Resume` when its provider is Repeatable (the drift check is skipped
for it, since its own earlier attempt may have moved the state); otherwise it is Refused and the run stops there,
even with `-ContinueOnError`, naming the way on: `-AssumeFired <StepId>`, which records it Skipped with
`Result.Assumed`, is written to `PlanStarted`, and keeps the plan from ever ending `Applied`. A step named in
`-AssumeFired` that is not in doubt is Refused.
A `Check` with `Severity=Refuse` fails closed: any outcome other than "Test true" (Get error, drift, Test false)
refuses and stops the plan regardless of `-ContinueOnError` or `-Force`.
A Destructive step without `-AllowDestructive` gets its own `ShouldContinue` prompt after `ShouldProcess`, so a
"Yes to All" answered at an earlier step never covers it; a host that cannot prompt makes the step Refused.
`Result.Attempted` is set the moment `Set` is called. On resume, a Create step whose target now exists is Skipped
and its id is adopted as `Subject.Id` only when the audit log holds an attempt of that step (2.5) that did not end
in a refused request and the target's `createdDateTime` lies within that attempt: from its `Attempting` entry to its
end, each widened by 5 minutes for clock difference. The end is the next entry for the step or the plan's next
`PlanFinished` or `PlanStarted`, and never later than the `Attempting` entry plus `Get-TenureGraphLongestCall`, so
an attempt whose run died without a later entry still ends. A target outside every such attempt, or one that does not
report `createdDateTime`, is someone else's account that took the name: Drifted, run stops. A Check step that
passed in an earlier run of the plan (audit log) is not checked again when a later Create step of the plan on the
same target has such an attempt: that is the user-absent check after the plan's own create. A Create that the audit log does not show as
attempted never adopts a pre-existing account; the plan file's `Result.Attempted` alone is not evidence.
Interrupts (Ctrl+C) run the engine's `finally`: best-effort `PlanFinished`, plan file persisted, result kept for
`Get-TenureApplyResult`.
Plan status after: `Applied` (no Failed/Drifted/Refused, no Pending, no step with `Result.Assumed`), `PartiallyApplied`, `Failed`, `DryRun`.

### 5.5 Edge rules
- Missing optional field in policy → the default in §2.1. Missing required field → `Tenure.Policy.Invalid`.
- Empty `roles` with `-Role` given → `Tenure.Policy.RoleNotFound`.
- Group name matching more than one group → `Tenure.Group.Ambiguous` at plan time (never guess).
- Subject not found → `Tenure.User.NotFound` at plan time.
- No mailbox → mailbox steps are omitted with a plan warning only when Exchange reports the mailbox not found
  and none of the user's licenses (direct or through a group) grants a mailbox. Not found while a license grants
  one is `Tenure.Plan.MailboxUnknown`: the mailbox may exist, and removing the licenses without converting it would
  delete it. Any other Exchange failure stops the plan as well.
- A license grants a mailbox when one of its service plans (`licenseDetails`) is named `EXCHANGE_S_*`, is not
  `EXCHANGE_S_FOUNDATION`, and has a `provisioningStatus` other than `Disabled`. A license whose service plans are
  not reported, or a service plan without a name, counts as granting one (fail closed).
- OneDrive never provisioned (404 on `drive`) → step omitted with a warning.
- No managed devices → no device steps, no warning.
- `forwardTo: "manager"` with no manager → forwarding and grants omitted, warning.
- Canonical JSON: hashtable and PSCustomObject keys sorted ordinal, case-sensitive; arrays keep order; `$null` as `null`; dates as `o` strings.

## 6. Failure modes
| Dependency | Fails how | Our behavior | User sees |
|---|---|---|---|
| Graph | 401 | `Tenure.Graph.NotConnected` before any step | "Run Connect-Tenure" |
| Graph | 403 | `Tenure.Graph.Forbidden` naming the provider's scopes | which scope to add |
| Graph | 404 at plan | `*.NotFound` with the identity | typo or wrong tenant |
| Graph | 404 at apply | step `Failed`, plan `PartiallyApplied` | resume after fixing |
| Graph | 429 / 503 | retry with `Retry-After` (at most 60 s) or 2^n s, max 3 | verbose line per retry |
| Graph | 200 with `error` body | treated as failure | error code and message |
| Exchange | not connected | preflight refusal before step 1 | "Connect-Tenure without -SkipExchange" |
| Exchange | cmdlet throws | step `Failed` with inner message | message |
| Exchange | mailbox not found at plan, user licensed for Exchange Online | `Tenure.Plan.MailboxUnknown`, no plan | check the mailbox, re-plan, or `-SkipMailbox` |
| Graph | member route says "not a member", memberOf lists the group or role | `Tenure.Provider.InconsistentState`, no plan | wait for replication, re-plan |
| Disk (audit) | unwritable | apply refuses before step 1 (write a `PlanStarted` entry first) | path and OS error |
| Plan file | newer schema | `Tenure.Plan.UnsupportedSchema` | upgrade the module |
| Plan file | schema 1 (earlier version) | `Tenure.Plan.UnsupportedSchema` | re-plan |
| Plan file | edited after it was built | `Tenure.Plan.Tampered`, nothing applied | re-plan |
| Plan | built in another tenant, or names none | `Tenure.Plan.WrongTenant` before step 1 | connect to that tenant or re-plan |
| Plan | records no policy, `-Policy` not given | `Tenure.Plan.PolicyMissing` before step 1 | pass the policy, or re-plan with `-Policy` |
| Plan | `-Policy` has no hash, another hash, or the plan records none | `Tenure.Plan.PolicyMismatch` before step 1 | pass the policy the plan was built from |
| Plan | a step's `Target.Kind` or `Action` is not its provider's | `Tenure.Plan.Invalid` before step 1 | re-plan |
| Plan | the audit log shows it finished `Applied` | `Tenure.Plan.AlreadyApplied` before step 1 | re-plan, or `-Force` to apply it again |
| Role change | would remove the last license with Exchange Online | `Tenure.Plan.MailboxUnlicensed`, no plan | keep a mailbox license, convert first, or `-AllowMailboxLoss` |
| Plan | subject or a changed account is protected or signed in | `Tenure.Plan.Refused` before step 1 | nothing to do; by design |
| Disk (audit) | last line torn (crash, full disk) | writer refuses with `Tenure.Audit.Corrupt` naming the line | `Test-TenureAudit` `Problem` gives the command that keeps the intact lines |
| Plan | older than MaxAge | refused | re-plan |

## 7. Non-functional
- Planning an offboard: about 25 Graph requests plus two per group the user is removed from (its owners and its
  license assignments, each read once per plan), one or two per `protectedUsers` entry (the lookup that warns about
  an entry that matches no user), and at most 8 Exchange calls; under 60 s on a normal tenant for a user with ≤ 30 groups.
  A role change also reads the user's license details, and the tenant's SKUs when it would remove the last license
  with Exchange Online.
- Applying a plan: one extra Graph read per account the plan changes (the subject-protection preflight).
- Unit suite: under 90 s on a laptop, no network.
- Module import: under 1.5 s.

## 8. Security
- Auth delegated to the two SDK connect cmdlets; interactive, device code, certificate, and client secret supported. Scopes requested = union of registered providers' scopes unless `-Scopes` is given.
- Least surprise: `ConfirmImpact=High`; destructive steps need `-AllowDestructive` when confirmation is suppressed.
- Self-protection: refuse to plan against the signed-in account or `protectedUsers`, and refuse to apply (or test)
  a plan whose subject, or any account a step changes, is either (5.4 preflight). Which account a step changes
  comes from its provider's `TargetKind`, never from the plan's `Target.Kind` label. An entry protects the user whose
  object id, user principal name or mail address it equals, ignoring case; only whole values match; an entry that
  matches no user is a plan warning. A plan records the protected users of its policy, so applying without
  `-Policy` still checks them, and a plan that records none is refused without `-Policy`. Without `-Policy` the
  recorded list is the plan's own word: pass `-Policy` to check against the policy file.
- Plan integrity: a plain SHA-256 over the plan (2.4, ADR-0007). It shows that a plan file was edited by hand or by
  a tool that did not recompute it; it is not a signature and does not stop someone who recomputes it. ADR-0007
  lists the checks a resealed plan still meets.
- Secrets: §2.2 and CONTRIBUTING.md rule 2. Audit `Before`/`After` are provider state objects that never include `passwordProfile`, TAP values or tokens.
- Audit integrity: §2.5 chain, `Test-TenureAudit`.
- Logs: no bearer tokens, no full request bodies for `User.Create` (the body contains the password).

## 9. Observability
- `-Verbose` on every public function prints one line per seam call (method, URI, status, ms) and per step.
- Apply writes `PlanStarted` and `PlanFinished` audit entries with the summary.
- `Get-TenureAudit -PlanId <id>` reconstructs a run; `Show-TenurePlan` on the returned plan shows statuses.

## 10. Open questions
| Question | Close by |
|---|---|
| Which tenant runs the integration harness: a trial tenant or a paid seat in a tenant the maintainer owns | before the first live run |
| Should a retire operation (delete after N days) ship in v1.1 | after the first live run |
| OneDrive handoff: is a Graph `invite` on the drive root enough, or does the grantee need site collection administrator | v1.1 |
