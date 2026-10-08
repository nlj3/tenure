# Spec: Tenure

**Status:** agreed (2026-10-08). Changes to §2, §3 or §4 need an ADR.

## 1. Scope
A PowerShell 7 module that turns a lifecycle request (onboard, role change, offboard)
plus a policy file plus live tenant state into a **plan**, and applies plans through a
generic engine with drift checks, `-WhatIf`/`-DryRun`, confirmation, dependency order,
resume, and a hash-chained audit log. Everything tenant-specific lives in the policy
file or in parameters. Nothing tenant-specific lives in code.

Not covered: user deletion, MFA method removal, OAuth consent revocation, Entra device
object disable, PIM, administrative units, GUI, scheduling, notifications.

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
    "protectedUsers": ["breakglass@example.com"],   // plan refuses these as subjects
    "offboard": {
      "resetPassword": true,
      "revokeSessions": true,
      "removeDirectoryRoles": true,
      "convertMailboxToShared": true,
      "hideFromAddressLists": true,
      "forwardTo": "manager",                        // "manager" | "none" | "<smtp address>"
      "deliverToMailboxAndForward": true,
      "autoReply": { "enabled": true, "message": "{displayName} has left {company}. Please contact {managerDisplayName} ({managerMail})." },
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
    "kiosk":   { "licenses": ["EXCHANGEDESKLESS"], "groups": ["Kiosk Users"], "department": "Front Desk", "jobTitle": "Kiosk" }
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
Get         { param([hashtable]$Target, [hashtable]$Context) -> [pscustomobject] }   current state, no secrets
Test        { param($Current, $Desired) -> [bool] }                                   true when satisfied
Set         { param([hashtable]$Target, $Desired, $Current, [hashtable]$Context) -> [pscustomobject] }   State/Invoke only
Describe    { param([hashtable]$Target, $Current, $Desired, [string]$Action) -> [string] }   one line, no secrets
Severity    'Warn' | 'Refuse'          Check only: what a failing Test does to the plan
```

Invariants:
- `Set` then `Get` then `Test` is true for `State` providers.
- `Get` on a missing target throws `Tenure.Provider.TargetNotFound`.
- `Get`/`Set` only reach the tenant through `Invoke-TenureGraph` / `Invoke-TenureExchange`.
- `Context` carries `Policy`, `Subject`, `Session`, `Mode` ('Plan'|'Apply'|'DryRun'), `StepId` (apply time)
  and a `Secrets` hashtable; a `Set` that creates a secret puts it in `Context.Secrets[<stepId>]` as
  `SecureString` and returns a state object that does not contain it. Provider scriptblocks are invoked
  plainly (`& $provider.Get $Target $Context`); they run in the scope they were created in.
- `Invoke` providers: `Get` returns whatever is needed for `Describe`; `Test` returns
  `$false`; idempotency is by step status (an `Applied` Invoke step is skipped on resume).

### 2.3 Step (`Tenure.Step`)
```
Id           'S01'..'S99' (assigned by New-TenurePlan in order)
Provider     provider name
Kind         copied from provider
Target       @{ Kind='user'|'group'|'device'|'mailbox'|'drive'|'role'; Id; Name }
Action       'Create' | 'Update' | 'Remove' | 'Invoke' | 'Check' | 'NoOp'
Before       object (Get snapshot at plan time; may be $null for Create)
After        object (desired state)                     -- never contains a secret
Fingerprint  sha256 hex of canonical JSON of Before ('' when Before is $null)
Risk         copied from provider (plan builder may raise, never lower)
Reversible   copied from provider
Reason       string, human
DependsOn    string[] of step ids
Status       'Pending' | 'Applied' | 'Skipped' | 'Failed' | 'DryRun' | 'Drifted' | 'Refused'
Result       $null or @{ At; DurationMs; Observed; Error; Note }
```
Invariant: `Action` is `NoOp` iff `Test(Before, After)` was true at plan time.

### 2.4 Plan (`Tenure.Plan`)
```
SchemaVersion 1
PlanId        guid
CreatedAt     UTC ISO 8601
CreatedBy     @{ Account; TenantId; AuthType }
ModuleVersion
Operation     'Onboard' | 'RoleChange' | 'Offboard' | 'Custom'
Subject       @{ Id; UserPrincipalName; DisplayName }     (Id $null until an Onboard is applied)
PolicyHash    sha256 hex or $null
Inputs        hashtable of the request parameters, secrets excluded
Steps         Tenure.Step[] in execution order
Warnings      string[]
Status        'Planned' | 'DryRun' | 'Applied' | 'PartiallyApplied' | 'Failed'
```
Invariants: step ids unique; every `DependsOn` target exists and precedes the step;
no step's `Before`/`After`/`Reason` contains a value from `Context.Secrets`.

### 2.5 Audit entry (`Tenure.AuditEntry`), one JSON object per line
```
Seq, Ts, PrevHash, Hash, PlanId, Operation, StepId, Provider, Target, Action, Actor (@{Account; TenantId}),
Outcome ('Applied'|'Skipped'|'Failed'|'DryRun'|'Drifted'|'Refused'|'PlanStarted'|'PlanFinished'),
Before, After, Observed, Error, DurationMs, ModuleVersion, Host, Mode ('Apply'|'DryRun')
```
`Hash = sha256(PrevHash + canonicalJson(entry without Hash))`. First `PrevHash` is 64 zeros.

### 2.6 Apply result (`Tenure.ApplyResult`)
```
Plan      the plan with updated statuses
Summary   @{ Applied; Skipped; Failed; DryRun; Drifted; Refused }
Secrets   hashtable stepId -> SecureString (empty when none)
AuditPath
```

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
Resolve-TenureGroup -Identity <name|mail|id> -> @{ Id; DisplayName; Mail; GroupTypes; MembershipRule; MailEnabled; SecurityEnabled }  (throws Tenure.Group.NotFound / Tenure.Group.Ambiguous)
Resolve-TenureSku -PartNumber <string> -> @{ SkuId; SkuPartNumber; Available }  (throws Tenure.Sku.NotFound)
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
New-TenureRoleChangePlan -User <upn|id> -Role <string> -Policy <...> [-FromRole <string>] [-Manager] [-Department] [-JobTitle] [-KeepGroup <string[]>] -> Tenure.Plan
New-TenureOffboardPlan   -User <upn|id> -Policy <...> [-ForwardTo <'manager'|'none'|smtp>] [-GrantMailboxTo] [-GrantOneDriveTo]
                         [-Devices wipeCorporateRetirePersonal|retireAll|none] [-AutoReplyMessage] [-KeepGroup <string[]>]
                         [-SkipLicenseRemoval] [-SkipMailbox] [-SkipDevices] -> Tenure.Plan
Show-TenurePlan     -Plan <Tenure.Plan> [-PassThru] -> string[] (and writes to host)
Export-TenurePlan   -Plan -Path [-Force]
Import-TenurePlan   -Path -> Tenure.Plan   (throws Tenure.Plan.UnsupportedSchema, Tenure.Plan.Invalid)
Test-TenurePlan     -Plan -> @{ Drifted: Tenure.Step[]; Satisfied: Tenure.Step[]; Pending: Tenure.Step[] }   (read-only)
Invoke-TenurePlan   -Plan <Tenure.Plan|path> [-DryRun] [-Force] [-ContinueOnError] [-AllowDestructive] [-MaxAge <timespan>=24h] [-AuditPath] [-OutFile]
                    SupportsShouldProcess, ConfirmImpact=High -> Tenure.ApplyResult
Get-TenureAudit     [-Path] [-PlanId] [-Last <int>] [-Since <datetime>] -> Tenure.AuditEntry[]
Test-TenureAudit    [-Path] -> @{ Valid: bool; Entries: int; FirstBrokenSeq: int? }
```

## 4. Data schema
- Plan file: JSON, `schemaVersion: 1`, the plan object as in §2.4 with `ConvertTo-Json -Depth 20`.
  Import refuses `schemaVersion` > 1.
- Audit file: JSONL per §2.5. Default `~/.tenure/audit.jsonl` (`$HOME` on all OSes),
  env override `TENURE_AUDIT_PATH`, parameter override `-AuditPath`.
- Policy schema: `policies/tenure.policy.schema.json` (JSON Schema draft 7) mirrors §2.1.

## 5. Semantics and decision rules

### 5.1 Offboard step order (and why)
1. `Check.Subject`: refuse if subject is the signed-in account or in `protectedUsers`;
   warn if the subject holds Global Administrator.
2. `User.SignIn` → `accountEnabled=false`.
3. `User.Password` → reset to a generated value (Invoke; value never leaves `Secrets`, and for offboarding is discarded, not returned).
4. `User.Sessions` → `revokeSignInSessions` (Invoke). After 2 and 3 so no new tokens can be minted.
5. `DirectoryRole.Member` → one Remove step per active role assignment.
6. `Check.MailboxSharedEligibility` → warn when size ≥ 50 GB, archive enabled, or litigation/retention hold (a shared mailbox then still needs a license).
7. `Mailbox.Type` → `Shared`.
8. `Mailbox.Forwarding` → resolved address, `DeliverToMailboxAndForward` per policy.
9. `Mailbox.AutoReply` → enabled, internal and external message rendered from the template.
10. `Mailbox.Delegate` → FullAccess (no automapping) to the resolved grantee.
11. `Mailbox.Hidden` → `HiddenFromAddressListsEnabled=true`.
12. `Calendar.CancelMeetings` → `Remove-CalendarEvents -CancelOrganizedMeetings` (Invoke, Destructive).
13. `OneDrive.Access` → `drive/root/invite` write role to the grantee, `sendInvitation=false`.
14. `Group.Member` (Graph) / `DistributionGroup.Member` (Exchange) → one Remove per membership not in `keepGroups`.
    Dynamic groups: step emitted as `NoOp` with reason "dynamic membership". Sole-owner groups: warning.
15. `User.Licenses` → remove all directly assigned SKUs. `DependsOn` = the `Mailbox.Type` step id when present.
    Group-inherited SKUs are listed in the reason and not removed.
16. `Device.Wipe` / `Device.Retire` → one step per Intune managed device by ownership (`company` → wipe, `personal` → retire) or `retireAll`.
17. `User.Attributes` → `employeeLeaveDateTime = now` when `setEmployeeLeaveDate` is true.

### 5.2 Onboard step order
1. `Check.UserAbsent` → refuse if the UPN or mail nickname already exists (including soft-deleted users).
2. `User.Create` → UPN, displayName, mailNickname, givenName, surname, usageLocation, department, jobTitle, officeLocation,
   `passwordProfile` with a generated password and `forceChangePasswordNextSignIn=true`. Password goes to `Secrets['S02']`.
3. `User.Manager`.
4. `User.Licenses` → add role SKUs. Warn when `Available` is 0 for any SKU.
5. `Group.Member` → one Add per role group (plus `-AdditionalGroup`).
6. `User.TemporaryAccessPass` → when requested; value to `Secrets`.
Steps 3 to 6 `DependsOn` step 2. Their `Target.Id` is `$null` at plan time and is filled from the create step's observed state at apply time (the engine substitutes `{{subjectId}}`).

### 5.3 Role change
- Desired = new role's licenses and groups (plus `-AdditionalGroup` style extras later).
- Remove = (current licenses and groups ∩ managed set) − desired, minus `-KeepGroup`.
  With `-FromRole`, the removal set is limited to that role's items.
- Add = desired − current.
- Attribute updates (department, jobTitle, manager) only when supplied or defined on the role.

### 5.4 Apply engine
For each step in order:
1. If any `DependsOn` step is not `Applied`/`Skipped` → `Refused` ("dependency S07 not applied"); stop unless `-ContinueOnError`.
2. `Invoke` step already `Applied` (resume) → `Skipped`.
3. `Get` current. If `Fingerprint` ≠ hash(current) and not `-Force` → `Drifted`, audit, stop unless `-ContinueOnError`.
4. `State`/`Check`: if `Test(current, After)` → `Skipped` (already satisfied). `Check` failing with `Severity=Refuse` → `Refused`, stop.
5. `-DryRun` → `DryRun`, audit with `Mode=DryRun`, continue.
6. `Risk=Destructive` and `-Confirm:$false` without `-AllowDestructive` → `Refused`, stop.
7. `ShouldProcess(target, description)` false (`-WhatIf` or declined) → status stays `Pending`, nothing is written to the audit log (`-WhatIf` has no side effects at all), continue.
8. `Set`, then `Get`, then `Test(observed, After)`; false → `Failed` ("post-condition not met"). Audit. Stop on failure unless `-ContinueOnError`.
Before step 1 of the first step: preflight. Refuse the whole plan when `CreatedAt` is older than `-MaxAge`,
when any required backend is not connected, or when `Plan.Status` is `Applied`.
Plan status after: `Applied` (no Failed/Drifted/Refused, no Pending), `PartiallyApplied`, `Failed`, `DryRun`.

### 5.5 Edge rules
- Missing optional field in policy → the default in §2.1. Missing required field → `Tenure.Policy.Invalid`.
- Empty `roles` with `-Role` given → `Tenure.Policy.RoleNotFound`.
- Group name matching more than one group → `Tenure.Group.Ambiguous` at plan time (never guess).
- Subject not found → `Tenure.User.NotFound` at plan time.
- No mailbox (never licensed) → mailbox steps are omitted with a plan warning, not an error.
- OneDrive never provisioned (404 on `drive`) → step omitted with a warning.
- No managed devices → no device steps, no warning.
- `forwardTo: "manager"` with no manager → forwarding and grants omitted, warning.
- Canonical JSON: hashtable and PSCustomObject keys sorted ordinal, case-sensitive; arrays keep order; `$null` as `null`; dates as `o` strings.

## 6. Failure modes
| Dependency | Fails how | Our behaviour | User sees |
|---|---|---|---|
| Graph | 401 | `Tenure.Graph.NotConnected` before any step | "Run Connect-Tenure" |
| Graph | 403 | `Tenure.Graph.Forbidden` naming the provider's scopes | which scope to add |
| Graph | 404 at plan | `*.NotFound` with the identity | typo or wrong tenant |
| Graph | 404 at apply | step `Failed`, plan `PartiallyApplied` | resume after fixing |
| Graph | 429 / 503 | retry with `Retry-After` or 2^n s, max 3 | verbose line per retry |
| Graph | 200 with `error` body | treated as failure | error code and message |
| Exchange | not connected | preflight refusal before step 1 | "Connect-Tenure without -SkipExchange" |
| Exchange | cmdlet throws | step `Failed` with inner message | message |
| Disk (audit) | unwritable | apply refuses before step 1 (write a `PlanStarted` entry first) | path and OS error |
| Plan file | newer schema | `Tenure.Plan.UnsupportedSchema` | upgrade the module |
| Plan | older than MaxAge | refused | re-plan |

## 7. Non-functional
- Planning an offboard: ≤ 25 Graph requests and ≤ 8 Exchange calls for a user with ≤ 30 groups; under 60 s on a normal tenant.
- Unit suite: under 90 s on a laptop, no network.
- Module import: under 1.5 s.

## 8. Security
- Auth delegated to the two SDK connect cmdlets; interactive, device code, certificate, and client secret supported. Scopes requested = union of registered providers' scopes unless `-Scopes` is given.
- Least surprise: `ConfirmImpact=High`; destructive steps need `-AllowDestructive` when confirmation is suppressed.
- Self-protection: refuse to plan against the signed-in account or `protectedUsers`.
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
