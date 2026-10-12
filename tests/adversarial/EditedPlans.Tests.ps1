# Attacks on the plan file, the apply engine and the builders that once did harm against the fakes, kept as
# regressions. Each case below names what used to happen; the test now shows the engine or a builder refusing
# it, or doing the safe thing instead. The labels (X1, R7a and so on) only name the cases.
#
#   X1   a removal from a group that carries a license ran before the mailbox conversion
#   X2   a plan file edited to forward mail elsewhere applied without drift
#   X3   a step turned into a Global Administrator grant by editing Provider, Target, After and Action
#   X4   a whole offboard re-pointed at a protected account by editing Subject and targets
#   X5   a device that synced between plan and apply made the wipe step drift
#   X6a  an onboard plan with groups was refused as Invalid
#   X6b  an onboard interrupted after the create landed could not be finished
#   X8   a resumed run marked a session revoke done that never ran
#   X9   one message arriving between plan and apply made the eligibility check drift
#   X10  a retire step turned into a wipe by editing Provider
#   R1   a resealed plan granted Global Administrator through a role step labelled Update or Remove
#   R2   a resealed plan with its recorded policy removed disabled a protected account
#   R3   a plan applied as an object left its file at Planned, and the file applied a second time
#   R4   a re-run of a role holder's offboarding stopped at its own Global Administrator check
#   R5   a dynamic group the plan's own sign-in step emptied made its no-op step drift
#   R6   a group removal that took an inherited license made the license step drift
#   R7   a role change removed the last license with Exchange Online without a word
#   R8   a create whose earlier attempt was refused adopted an account created hours later
#   R9   -AssumeFired from a run on a plan object was lost by a later run from the plan file
#   R10  New-TenurePlan -Inputs $null sealed a plan its own Import-TenurePlan refused
#   R11  Test-TenurePlan called an Invoke step done on the plan file's word
#   R13  a dependency Applied in an earlier run let a step run after the dependency was declined now
#   R14  a -Policy object without a Hash replaced the protected users the plan recorded
#   R15  a membership change for someone other than the subject landed and was recorded Failed
#   R16  a step whose Target.Kind label disagreed with its provider got past the protection check
#   TenantId  a plan that named no tenant was applied in any tenant
#
# Plus the decisions that came with them: subject protection without a check step (A3), the
# destructive prompt text (A4), plans applied by another administrator and without -Policy (C),
# license removals that delete a mailbox (E), the plan's tenant (H).
#
# Real providers and the real engine against FakeGraph and FakeExchange; every audit path is under TestDrive.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeExchange.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'PlanFixtures.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    $global:FakeExchangeWorld = New-FakeExchangeWorld
    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
    Mock -ModuleName Tenure Invoke-TenureExchange {
        & (Get-Module -Name Tenure) { Assert-TenureConnection -Backend Exchange }
        Invoke-FakeExchangeCommand -World $global:FakeExchangeWorld -Command $Command -Parameters $Parameters
    }
    # Retries and read-backs sleep in the real code; nothing here needs to wait.
    Mock -ModuleName Tenure Start-Sleep { }

    $script:SavedConfirmPreference = $global:ConfirmPreference
    $global:ConfirmPreference = 'None'
    $script:SavedAuditEnv = $env:TENURE_AUDIT_PATH
    $script:PolicyPath = Join-Path $script:TenureSourceRoot 'Policies' 'example.policy.json'

    function New-Pol([scriptblock]$Edit) {
        $raw = Get-Content -LiteralPath $script:PolicyPath -Raw | ConvertFrom-Json -AsHashtable
        $raw['defaults']['offboard']['autoReply']['message'] = '{displayName} has left.'
        if ($Edit) { & $Edit $raw }
        Get-TenurePolicy -InputObject $raw
    }
    function Get-User([string]$Key) { $global:FakeGraphWorld.Users | Where-Object { $_['id'] -eq $Key -or $_['userPrincipalName'] -eq $Key } | Select-Object -First 1 }
    function Get-FakeGroup([string]$Id) { $global:FakeGraphWorld.Groups | Where-Object { $_['id'] -eq $Id } | Select-Object -First 1 }
    function Get-Step($Plan, [string]$Key) { @($Plan.Steps | Where-Object { $_.Key -ceq $Key })[0] }
    function New-PlanFile { Join-Path $TestDrive ('plan-{0}.json' -f [guid]::NewGuid().ToString('N')) }
    # Reads a plan file as the plain tables an editor would change. The module's strict reader keeps date-like
    # strings as strings (ConvertFrom-Json would turn them into dates and change the text on the way back).
    function Read-PlanTable([string]$Path) { Invoke-InTenure { param($p) ConvertFrom-TenureJsonText -Text ([System.IO.File]::ReadAllText($p)) -ErrorId 'Tenure.Plan.Invalid' } @($Path) }
    function Write-PlanTable($Table, [string]$Path) { $Table | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path }
    # What a forger who reimplements the integrity formula would write: the honest value for the edited content.
    function Set-ForgedIntegrity([string]$Path) {
        $plan = Invoke-InTenure { param($p) ConvertFrom-TenurePlanModel -Model (ConvertFrom-TenureJsonText -Text ([System.IO.File]::ReadAllText($p)) -ErrorId 'Tenure.Plan.Invalid') } @($Path)
        $table = Read-PlanTable $Path
        $table['Integrity'] = Invoke-InTenure { param($p) Get-TenurePlanIntegrity -Plan $p } @($plan)
        Write-PlanTable $table $Path
    }
    $script:RoleGroupId = '20000000-0000-4000-8000-0000000000a1'
    $script:DeskGroupId = '20000000-0000-4000-8000-0000000000a2'
    function Get-Statuses($Plan) { (@($Plan.Steps) | ForEach-Object { "$($_.Key)=$($_.Status)" }) -join ' ' }
    # What a provider's Get reports for a target, read the way a builder reads it, and the fingerprint of it.
    function Get-Snapshot([string]$Provider, [hashtable]$Target, [string]$SubjectId) {
        Invoke-InTenure { param($n, $t, $s) & (Get-TenureProviderDefinition -Name $n).Get $t @{ Subject = @{ Id = $s }; Secrets = @{}; Mode = 'Plan' } } @($Provider, $Target, $SubjectId)
    }
    function Get-Fp([hashtable]$Target, $Before) { Invoke-InTenure { param($t, $b) Get-TenureStepFingerprint -Target $t -Before $b } @($Target, $Before) }
    function Add-FakeGraphMember([string]$GroupId, [string]$UserId) {
        $group = Get-FakeGroup $GroupId
        $group['members'] = [string[]]@(@($group['members']) + $UserId)
    }
    # Gives alice SPE_E3 (with Exchange Online) through All Staff only, and nothing directly.
    function Set-GroupLicensedAlice {
        $alice = Get-User $script:ids.AliceId
        $alice['licenseAssignmentStates'] = [System.Collections.Generic.List[hashtable]]::new()
        $alice['licenseAssignmentStates'].Add(@{ skuId = $script:ids.SkuE3Id; assignedByGroup = $script:ids.AllStaffGroupId; state = 'Active'; error = 'None' })
        (Get-FakeGroup $script:ids.AllStaffGroupId)['assignedLicenses'] = @(@{ skuId = $script:ids.SkuE3Id; disabledPlans = @() })
    }
}

AfterAll {
    $global:ConfirmPreference = $script:SavedConfirmPreference
    $env:TENURE_AUDIT_PATH = $script:SavedAuditEnv
    Remove-Variable -Name FakeGraphWorld, FakeExchangeWorld -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Attacks that used to work' {
    BeforeEach {
        Reset-FakeGraphWorld
        Reset-FakeExchangeWorld
        Set-TenureTestSession
        $script:ids = $global:FakeGraphWorld.Ids
        $script:audit = Join-Path $TestDrive ('audit-{0}.jsonl' -f [guid]::NewGuid().ToString('N'))
        $env:TENURE_AUDIT_PATH = Join-Path $TestDrive 'env-sentinel.jsonl'
    }

    Context 'A: a plan file cannot be edited after it is built' {
        It 'X2: a forwarding address and a OneDrive grantee edited in the file are refused as Tampered by Import, Test and Invoke' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $json = (Get-Content -LiteralPath $file -Raw).Replace('"forwardingSmtpAddress": "bob@example.com"', '"forwardingSmtpAddress": "drop@attacker.example"').Replace('"granteeEmail": "bob@example.com"', '"granteeEmail": "drop@attacker.example"')
            $json | Should -Match 'drop@attacker.example' -Because 'the edit must change the file'
            Set-Content -LiteralPath $file -Value $json -NoNewline

            { Import-TenurePlan -Path $file } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
            { Test-TenurePlan -Plan $file } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
            { Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
            $global:FakeExchangeWorld.Mailboxes[$ids.AliceId].ForwardingSmtpAddress | Should -BeNullOrEmpty
            @($global:FakeGraphWorld.Drives[$ids.AliceId].permissions).Count | Should -Be 0
            Test-Path $audit | Should -BeFalse
        }

        It 'X2: the same edit made to the plan object in memory is refused too' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none
            (Get-Step $plan 'forwarding').After['forwardingSmtpAddress'] = 'drop@attacker.example'
            { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
            { Export-TenurePlan -Plan $plan -Path (New-PlanFile) } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
            Test-Path $audit | Should -BeFalse
        }

        It 'X3: a step rewritten into a Global Administrator grant is Tampered; resealed, its Create is an action the role provider does not allow' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $victim = $model.Steps | Where-Object { $_.Provider -eq 'Group.Member' } | Select-Object -First 1
            $victim.Provider = 'DirectoryRole.Member'
            $victim.Target = @{ Kind = 'role'; Id = $ids.GlobalAdminRoleId; Name = 'Global Administrator' }
            $victim.After = @{ userId = $ids.AliceId; member = $true }
            $victim.Action = 'Create'
            $victim.Before = $null
            $victim.Fingerprint = Invoke-InTenure { param($t) Get-TenureStepFingerprint -Target $t -Before $null } @($victim.Target)
            $victim.Risk = 'High'
            Write-PlanTable $model $file
            { Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
            $global:FakeGraphWorld.DirectoryRoles[0].members | Should -Not -Contain $ids.AliceId

            # The integrity value is a plain hash, so a forger can recompute it. DirectoryRole.Member allows only
            # Remove (and NoOp), so the resealed Create is refused by the shape check, even with -Force.
            Set-ForgedIntegrity $file
            $failure = { Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false -Force -ContinueOnError } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -PassThru
            $failure.Exception.Message | Should -Match "Action 'Create'"
            $global:FakeGraphWorld.DirectoryRoles[0].members | Should -Not -Contain $ids.AliceId
        }

        It 'X4: an offboard re-pointed at a protected account is Tampered; a resealed copy is refused by the protection preflight before step 1' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $model.Subject.Id = $ids.BobId
            $model.Subject.UserPrincipalName = 'bob@example.com'
            $model.PlanId = [guid]::NewGuid().ToString()
            $keep = [System.Collections.Generic.List[object]]::new()
            foreach ($step in $model.Steps) {
                # The check steps go: protection must not depend on them. The user steps are retargeted at bob with
                # bob's own snapshots, so no fingerprint gives the forgery away.
                if ($step.Provider -notlike 'User.*') { continue }
                $step.Target.Id = $ids.BobId
                $step.Target.Name = 'bob@example.com'
                $step.Before = Get-Snapshot $step.Provider @{ Kind = 'user'; Id = $ids.BobId; Name = 'bob@example.com' } $ids.BobId
                $step.Fingerprint = Get-Fp @{ Kind = 'user'; Id = $ids.BobId } $step.Before
                $step.DependsOn = @()
                $keep.Add($step)
            }
            $index = 1
            foreach ($step in $keep) { $step.Id = 'S{0:D2}' -f $index; $index++ }
            $model.Steps = $keep.ToArray()
            Write-PlanTable $model $file
            { Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'

            Set-ForgedIntegrity $file
            $failure = { Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Refused' -PassThru
            $failure.Exception.Message | Should -Match "protectedUsers entry 'bob@example.com'"
            (Get-User $ids.BobId).accountEnabled | Should -BeTrue
            Test-Path $audit | Should -BeFalse -Because 'the refusal comes before PlanStarted'
        }

        It 'X10: a retire step turned into a wipe by editing Provider and After is Tampered' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices retireAll -SkipMailbox -SkipLicenseRemoval -GrantOneDriveTo none
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $laptop = $model.Steps | Where-Object { $_.Target.Id -eq $ids.CompanyDeviceId }
            $laptop.Provider | Should -Be 'Device.Retire'
            $laptop.Provider = 'Device.Wipe'
            $laptop.Risk = 'Destructive'
            $laptop.After = @{ keepEnrollmentData = $false; keepUserData = $false }
            Write-PlanTable $model $file
            { Test-TenurePlan -Plan $file } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
            { Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false -AllowDestructive } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
            ($global:FakeGraphWorld.ManagedDevices | Where-Object { $_.id -eq $ids.CompanyDeviceId }).wiped | Should -BeFalse
        }

        It 'refuses a Subject.Id filled in after an onboard plan was built unless the audit log shows this plan created it' {
            $policy = New-Pol
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role sales -Policy $policy
            $plan.Subject['Id'] = $ids.BobId
            $failure = { Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Tampered' -PassThru
            $failure.Exception.Message | Should -Match 'audit log does not show'
            @((Get-FakeGroup $ids.SalesGroupId).members) | Should -Not -Contain $ids.BobId
        }
    }

    Context 'B and E: removals that would delete a mailbox' {
        It 'X1: a declined mailbox conversion stops the removal from a group that carries the license' {
            Set-GroupLicensedAlice
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none
            $allStaff = Get-Step $plan "group:$($ids.AllStaffGroupId)"
            $mailboxType = Get-Step $plan 'mailboxType'
            @($allStaff.DependsOn) | Should -Contain $mailboxType.Id

            # The operator declines the conversion and accepts everything else.
            $cmdlet = New-TestCmdlet -ShouldProcess { param($t, $a) -not ($t -like '*Mailbox.Type*') }
            $null = Invoke-TestCore -Plan $plan -Cmdlet $cmdlet -AuditPath $audit -With @{ AllowDestructive = $true; Policy = $policy }
            $mailboxType.Status | Should -Be 'Declined'
            $allStaff.Status | Should -Be 'Refused'
            $allStaff.Result.Note | Should -Match "dependency $($mailboxType.Id) not applied"
            @((Get-FakeGroup $ids.AllStaffGroupId).members) | Should -Contain $ids.AliceId
            $global:FakeExchangeWorld.Mailboxes[$ids.AliceId].RecipientTypeDetails | Should -Be 'UserMailbox'
        }

        It 'E: without the conversion, a license removal is Destructive and needs its own confirmation or -AllowDestructive' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox
            (Get-Step $plan 'licenses').Risk | Should -Be 'Destructive'
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false | Out-Null
            (Get-Step $plan 'licenses').Status | Should -Be 'Refused'
            (Get-Step $plan 'licenses').Result.Note | Should -Match 'AllowDestructive'
            @((Get-User $ids.AliceId).assignedLicenses).Count | Should -Be 1 -Because 'the license, and with it the mailbox, stays'
        }

        It 'E: the PlanStarted entry records the inputs, the warnings and the policy hash' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive | Out-Null
            $started = @(Get-TenureAudit -Path $audit | Where-Object Outcome -eq 'PlanStarted')[0]
            $started.Observed.Inputs.SkipMailbox | Should -BeTrue
            $started.Observed.Inputs.User | Should -Be 'alice@example.com'
            @($started.Observed.Warnings | Where-Object { $_ -like '*does not convert the mailbox*' }).Count | Should -Be 1
            $started.Observed.PolicyHash | Should -Be $policy.Hash
            $started.Observed.Integrity | Should -Be $plan.Integrity
            $started.Observed.Options.PolicyGiven | Should -BeFalse
        }
    }

    Context 'C: snapshots that move on their own, another administrator, no -Policy' {
        It 'X5: a device that syncs between plan and apply does not drift, and the wipe runs without -Force' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -SkipMailbox
            foreach ($device in $global:FakeGraphWorld.ManagedDevices) { $device['lastSyncDateTime'] = '2026-10-11T16:30:00Z'; $device['complianceState'] = 'noncompliant' }
            @((Test-TenurePlan -Plan $plan).Drifted).Count | Should -Be 0
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive | Out-Null
            (Get-Step $plan "device:$($ids.CompanyDeviceId)").Status | Should -Be 'Applied'
            ($global:FakeGraphWorld.ManagedDevices | Where-Object { $_.id -eq $ids.CompanyDeviceId }).wiped | Should -BeTrue
        }

        It 'X9: one message arriving between plan and apply does not drift the eligibility check, and the conversion runs' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none
            Set-FakeExchangeMailboxSize -World $global:FakeExchangeWorld -Identity 'alice@example.com' -Bytes (12GB + 48213)
            @((Test-TenurePlan -Plan $plan).Drifted).Count | Should -Be 0
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive | Out-Null
            (Get-Step $plan 'eligibility').Status | Should -Be 'Skipped'
            (Get-Step $plan 'mailboxType').Status | Should -Be 'Applied'
            $global:FakeExchangeWorld.Mailboxes[$ids.AliceId].RecipientTypeDetails | Should -Be 'SharedMailbox'
        }

        It 'a plan built by one administrator applies for another, and the audit log records who applied it' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $plan.CreatedBy.Account | Should -Be 'admin@example.com'
            Set-TenureTestSession -Account 'second.admin@example.com'
            Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false | Out-Null
            $plan.Status | Should -Be 'Applied'
            (Get-Step $plan 'subject').Status | Should -Be 'Skipped' -Because 'the subject check snapshot holds no signed-in account, so it does not drift'
            @(Get-TenureAudit -Path $audit | ForEach-Object { $_.Actor.Account } | Sort-Object -Unique) | Should -Be @('second.admin@example.com')
        }

        It 'applies and tests without -Policy, using the protected users the plan recorded' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('breakglass@example.com', 'carol@example.com') }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            @($plan.PolicySnapshot.ProtectedUsers) | Should -Be @('breakglass@example.com', 'carol@example.com')
            $check = Test-TenurePlan -Plan $plan
            @($check.Drifted).Count | Should -Be 0
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false | Out-Null
            $plan.Status | Should -Be 'Applied'
            (Get-User $ids.AliceId).accountEnabled | Should -BeFalse
        }

        It 'Test-TenurePlan takes -Policy and refuses one the plan was not built from' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            @((Test-TenurePlan -Plan $plan -Policy $policy).Drifted).Count | Should -Be 0
            { Test-TenurePlan -Plan $plan -Policy (New-Pol { param($r) $r['defaults']['usageLocation'] = 'GB' }) } | Should -Throw -ErrorId 'Tenure.Plan.PolicyMismatch'
        }
    }

    Context 'A3: subject protection does not depend on a step' {
        It 'refuses, before step 1, a Custom plan with no check step that disables a protected user' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $target = @{ Kind = 'user'; Id = $ids.BobId; Name = 'bob@example.com' }
            $step = New-TenureStep -Provider 'User.SignIn' -Target $target -Desired @{ accountEnabled = $false } -Key 'off'
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.BobId; UserPrincipalName = 'bob@example.com'; DisplayName = 'Bob' } -Step $step -Policy $policy
            { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            { Test-TenurePlan -Plan $plan } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            (Get-User $ids.BobId).accountEnabled | Should -BeTrue
            Test-Path $audit | Should -BeFalse
        }

        It 'refuses a Custom plan whose subject is fine but whose step adds a protected user to a group' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $step = New-TenureStep -Provider 'Group.Member' -Target @{ Kind = 'group'; Id = $ids.SalesGroupId; Name = 'Sales' } -Desired @{ userId = $ids.BobId; member = $true } -Context @{ Subject = @{ Id = $ids.BobId } } -Key 'add'
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy $policy
            $failure = { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Refused' -PassThru
            $failure.Exception.Message | Should -Match 'step S01 \(Group.Member\)'
            @((Get-FakeGroup $ids.SalesGroupId).members) | Should -Not -Contain $ids.BobId
        }

        It 'refuses a plan whose subject is the signed-in account, matched by mail address' {
            (Get-User $ids.AliceId)['mail'] = 'alice.example@example.com'
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            Set-TenureTestSession -Account 'Alice.Example@example.com'
            $failure = { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Refused' -PassThru
            $failure.Exception.Message | Should -Match 'signed-in account'
            (Get-User $ids.AliceId).accountEnabled | Should -BeTrue
        }
    }

    Context 'A4: the destructive confirmation' {
        It 'shows the provider and its own description of the change, not only the Reason the plan carries' {
            $context = @{ Subject = @{ Id = $ids.AliceId } }
            $step = New-TenureStep -Provider 'Device.Wipe' -Target @{ Kind = 'device'; Id = $ids.CompanyDeviceId; Name = 'ALICE-LAPTOP (company)' } -Desired @{ keepEnrollmentData = $false; keepUserData = $false } -Context $context -Key 'wipe' -Reason 'harmless check-in, nothing changes'
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy (New-Pol)
            $cmdlet = New-TestCmdlet -ShouldContinue { param($query, $caption) $false }
            $null = Invoke-TestCore -Plan $plan -Cmdlet $cmdlet -AuditPath $audit
            $query = @($cmdlet.Calls | Where-Object { $_ -like 'ShouldContinue:*' })[0]
            $query | Should -Match 'Device\.Wipe will: wipe ALICE-LAPTOP \(company, Windows\), irreversible'
            $query | Should -Not -Match 'harmless'
            @($cmdlet.Calls | Where-Object { $_ -like 'ShouldProcess:*Device.Wipe*' }).Count | Should -Be 1
            ($global:FakeGraphWorld.ManagedDevices | Where-Object { $_.id -eq $ids.CompanyDeviceId }).wiped | Should -BeFalse
        }
    }

    Context 'D: onboarding' {
        It 'X6a: a built onboard plan with groups and a Temporary Access Pass passes the shape check and applies end to end' {
            $policy = New-Pol
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role sales -Policy $policy -Manager 'bob@example.com' -TemporaryAccessPass
            $null = Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath (Join-Path $TestDrive 'dry.jsonl') -Confirm:$false -DryRun
            $result = Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false
            $plan.Status | Should -Be 'Applied' -Because (Get-Statuses $plan)
            $erin = Get-User 'erin@example.com'
            $plan.Subject.Id | Should -Be $erin['id']
            @((Get-FakeGroup $ids.SalesGroupId).members) | Should -Contain $erin['id']
            @((Get-FakeGroup $ids.AllStaffGroupId).members) | Should -Contain $erin['id']
            @($erin['assignedLicenses'] | ForEach-Object { $_.skuId }) | Should -Contain $ids.SkuE3Id
            $result.Secrets.Keys | Should -Contain (Get-Step $plan 'tap').Id
            (Get-Step $plan "group:$($ids.SalesGroupId)").After.userId | Should -Be '{{subjectId}}' -Because 'the plan keeps the placeholder'
            $entry = @(Get-TenureAudit -Path $audit | Where-Object { $_.StepId -eq (Get-Step $plan "group:$($ids.SalesGroupId)").Id -and $_.Outcome -eq 'Applied' })[0]
            $entry.After.userId | Should -Be $erin['id'] -Because 'the audit log names the user the step acted on'
        }

        It 'X6a: a group step whose new user is already a member has nothing to do: it is Skipped, not applied twice' {
            # Something outside the plan puts every new user in Sales the moment it is created.
            Mock -ModuleName Tenure Invoke-TenureGraphRaw {
                $response = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
                if ($Method -eq 'POST' -and $Uri -like '*/v1.0/users' -and $response.Status -eq 201) {
                    $sales = $global:FakeGraphWorld.Groups | Where-Object { $_['id'] -eq $global:FakeGraphWorld.Ids.SalesGroupId }
                    $sales['members'] = [string[]](@($sales['members']) + [string]$response.Body.id)
                }
                $response
            }
            $policy = New-Pol
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role sales -Policy $policy
            $sales = Get-Step $plan "group:$($ids.SalesGroupId)"
            $sales.Before.member | Should -BeFalse
            Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false | Out-Null
            (Get-Step $plan 'create').Status | Should -Be 'Applied'
            $sales.Status | Should -Be 'Skipped' -Because 'the desired state holds, so there is nothing to do and no drift verdict'
            $sales.Result.Note | Should -Match 'already satisfied'
            @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method POST -UriLike "*groups/$($ids.SalesGroupId)/members*").Count | Should -Be 0
        }

        It 'X6b: an onboard interrupted after the create landed finishes on -Resume, adopting the user it created' {
            $policy = New-Pol { param($r) $r['roles']['solo'] = @{ licenses = @('SPE_E3') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role solo -Policy $policy
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            # What a run killed just after the create's POST landed leaves behind: the check passed, the create's
            # Attempting entry is in the audit log, no outcome and no PlanFinished, and the user exists.
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Provider = 'Check.UserAbsent'; Action = 'NoOp'; Outcome = 'Skipped'; Note = 'check passed' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S02'; Provider = 'User.Create'; Action = 'Create'; Outcome = 'Attempting'; Note = 'Set is about to run' } $audit | Out-Null
            $null = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body (@{ userPrincipalName = 'erin@example.com'; displayName = 'Erin New'; mailNickname = 'erin'; accountEnabled = $true; usageLocation = 'US'; passwordProfile = @{ password = 'Xx1!aaaaaaaaaaaaaaaa'; forceChangePasswordNextSignIn = $true } } | ConvertTo-Json -Compress)
            $erin = Get-User 'erin@example.com'

            { Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.RunInProgress'
            $result = Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false -Resume
            Get-Statuses $result.Plan | Should -Be 'absent=Skipped create=Skipped licenses=Applied'
            (Get-Step $result.Plan 'absent').Result.Note | Should -Match "this plan's create step S02 ran"
            (Get-Step $result.Plan 'create').Result.Note | Should -Match 'adopted'
            $result.Plan.Subject.Id | Should -Be $erin['id']
            $result.Plan.Status | Should -Be 'Applied'
            @($erin['assignedLicenses'] | ForEach-Object { $_.skuId }) | Should -Contain $ids.SkuE3Id
            @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method POST -UriLike '*/users').Count | Should -Be 1 -Because 'the user is never created twice'

            # The saved file carries the adopted id: still within its integrity value, because a plan sealed
            # before its subject existed may have Subject.Id filled in.
            $saved = Import-TenurePlan -Path $file
            $saved.Subject.Id | Should -Be $erin['id']
            $saved.Status | Should -Be 'Applied'
        }

        It 'X6b: an account that took the name before the create step ran is not adopted, even with the audit evidence' {
            $policy = New-Pol { param($r) $r['roles']['solo'] = @{ licenses = @('SPE_E3') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role solo -Policy $policy
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Provider = 'Check.UserAbsent'; Action = 'NoOp'; Outcome = 'Skipped' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S02'; Provider = 'User.Create'; Action = 'Create'; Outcome = 'Attempting' } $audit | Out-Null
            $null = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body (@{ userPrincipalName = 'erin@example.com'; displayName = 'Someone Else'; mailNickname = 'erin'; accountEnabled = $true; usageLocation = 'US'; passwordProfile = @{ password = 'Xx1!aaaaaaaaaaaaaaaa'; forceChangePasswordNextSignIn = $true } } | ConvertTo-Json -Compress)
            (Get-User 'erin@example.com')['createdDateTime'] = [datetime]::UtcNow.AddHours(-2).ToString('o')
            Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false -Resume | Out-Null
            (Get-Step $plan 'create').Status | Should -Be 'Drifted'
            (Get-Step $plan 'create').Result.Note | Should -Match 'not the account this plan created'
            $plan.Subject.Id | Should -BeNullOrEmpty
            @((Get-User 'erin@example.com')['assignedLicenses']).Count | Should -Be 0
        }

        It 'X6b: without the audit evidence the existing account is not adopted: the plan file alone proves nothing' {
            $policy = New-Pol { param($r) $r['roles']['solo'] = @{ licenses = @('SPE_E3') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role solo -Policy $policy
            (Get-Step $plan 'absent').Status = 'Skipped'
            (Get-Step $plan 'create').Result = @{ At = [datetime]::UtcNow.ToString('o'); Attempted = $true; Note = 'Set in progress'; Uncertain = $false; DurationMs = $null; Observed = $null; Error = $null }
            $null = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body (@{ userPrincipalName = 'erin@example.com'; displayName = 'Someone Else'; mailNickname = 'erin'; accountEnabled = $true; usageLocation = 'US'; passwordProfile = @{ password = 'Xx1!aaaaaaaaaaaaaaaa'; forceChangePasswordNextSignIn = $true } } | ConvertTo-Json -Compress)
            Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false -Resume | Out-Null
            (Get-Step $plan 'absent').Status | Should -Be 'Refused'
            $plan.Subject.Id | Should -BeNullOrEmpty
            @((Get-User 'erin@example.com')['assignedLicenses']).Count | Should -Be 0
        }
    }

    Context 'F: resume after an attempt with no recorded outcome' {
        BeforeEach {
            $script:policy = New-Pol { param($r) foreach ($k in 'removeDirectoryRoles', 'removeFromGroups', 'removeLicenses') { $r['defaults']['offboard'][$k] = $false } }
            $script:plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $script:policy -Devices none -SkipMailbox -GrantOneDriveTo none
            $script:file = New-PlanFile
            Export-TenurePlan -Plan $script:plan -Path $script:file
        }

        It 'X8: a session revoke that may not have run is run again under -Resume, because it is Repeatable' {
            $sessions = Get-Step $plan 'sessions'
            # What a killed run leaves: the revoke attempted, the process stopped before Graph saw it, no outcome.
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = $sessions.Id; Provider = 'User.Sessions'; Action = 'Invoke'; Outcome = 'Attempting' } $audit | Out-Null
            $result = Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false -Resume
            (Get-Step $result.Plan 'sessions').Status | Should -Be 'Applied'
            (Get-Step $result.Plan 'sessions').Result.Note | Should -Match 'Repeatable, so it runs again'
            @($global:FakeGraphWorld.SignInSessionsRevoked).Count | Should -Be 1
            $result.Plan.Status | Should -Be 'Applied'
        }

        It 'a session revoke whose status is edited to Skipped in the plan file is not silenced: without the audit log''s record it is in doubt' {
            $model = Read-PlanTable $file
            ($model.Steps | Where-Object { $_.Key -eq 'sessions' }).Status = 'Skipped'
            Write-PlanTable $model $file
            $result = Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false -ContinueOnError
            (Get-Step $result.Plan 'sessions').Status | Should -Be 'Refused'
            (Get-Step $result.Plan 'sessions').Result.Note | Should -Match 'has no record of it'
            $result.Plan.Status | Should -Not -Be 'Applied'
            $result = Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false -Resume
            (Get-Step $result.Plan 'sessions').Status | Should -Be 'Applied' -Because 'a revoke is Repeatable, so -Resume runs it'
            @($global:FakeGraphWorld.SignInSessionsRevoked).Count | Should -Be 1
        }

        It 'X8: a password reset that may not have run stops the run and names -AssumeFired; the plan then never ends Applied' {
            $password = Get-Step $plan 'password'
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = $password.Id; Provider = 'User.Password'; Action = 'Invoke'; Outcome = 'Attempting' } $audit | Out-Null
            $result = Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false -Resume -ContinueOnError
            (Get-Step $result.Plan 'password').Status | Should -Be 'Refused'
            (Get-Step $result.Plan 'password').Result.Note | Should -Match "-AssumeFired $($password.Id)"
            (Get-Step $result.Plan 'sessions').Status | Should -Be 'Pending' -Because 'the run stops at that step, even with -ContinueOnError'
            @($global:FakeGraphWorld.SignInSessionsRevoked).Count | Should -Be 0

            $again = Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false -AssumeFired $password.Id
            (Get-Step $again.Plan 'password').Status | Should -Be 'Skipped'
            (Get-Step $again.Plan 'password').Result.Assumed | Should -BeTrue
            (Get-Step $again.Plan 'sessions').Status | Should -Be 'Applied'
            $again.Plan.Status | Should -Be 'PartiallyApplied'
            # The staged PlanStarted above has no Observed; the runs' own entries carry the options.
            $started = @(Get-TenureAudit -Path $audit | Where-Object { $_.Outcome -eq 'PlanStarted' -and $null -ne $_.Observed -and $_.Observed.PSObject.Properties['Options'] })
            @($started | ForEach-Object { @($_.Observed.Options.AssumeFired) -join ',' }) | Should -Contain $password.Id
        }
    }

    Context 'H: the plan''s tenant and membership reads that contradict memberOf' {
        It 'refuses a plan built in another tenant, before any step' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            Set-TenureTestSession -TenantId '00000000-0000-0000-0000-0000000000aa'
            { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.WrongTenant'
            { Test-TenurePlan -Plan $plan } | Should -Throw -ErrorId 'Tenure.Plan.WrongTenant'
            (Get-User $ids.AliceId).accountEnabled | Should -BeTrue
            Test-Path $audit | Should -BeFalse
        }

        It 'refuses to plan a group removal when the member route says "not a member" but memberOf lists the group' {
            Mock -ModuleName Tenure Invoke-TenureGraphRaw -ParameterFilter { $Method -eq 'GET' -and $Uri -like "*groups/$($global:FakeGraphWorld.Ids.SalesGroupId)/members/*" } {
                @{ Status = 404; Headers = @{}; Body = [pscustomobject]@{ error = [pscustomobject]@{ code = 'Request_ResourceNotFound'; message = 'Replication lag.' } } }
            }
            $failure = { New-TenureOffboardPlan -User 'alice@example.com' -Policy (New-Pol) -Devices none } | Should -Throw -ErrorId 'Tenure.Provider.InconsistentState' -PassThru
            $failure.Exception.Message | Should -Match "memberOf lists the group"
        }

        It 'refuses to plan a role removal when the role''s members leave out a user memberOf lists' {
            $role = $global:FakeGraphWorld.DirectoryRoles[0]
            $role['members'] = [string[]]@($ids.CarolId, $ids.AliceId)
            Mock -ModuleName Tenure Invoke-TenureGraphRaw -ParameterFilter { $Method -eq 'GET' -and $Uri -like "*directoryRoles/$($global:FakeGraphWorld.Ids.GlobalAdminRoleId)/members?*" } {
                @{ Status = 200; Headers = @{}; Body = [pscustomobject]@{ value = @([pscustomobject]@{ id = $global:FakeGraphWorld.Ids.CarolId }) } }
            }
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy (New-Pol) -Devices none -SkipMailbox } | Should -Throw -ErrorId 'Tenure.Provider.InconsistentState'
        }

        It 'does not cross-check a distribution list read from Exchange against memberOf (a documented limit): the step follows Exchange' {
            Mock -ModuleName Tenure Invoke-TenureExchange -ParameterFilter { $Command -eq 'Get-DistributionGroupMember' } { @() }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy (New-Pol) -Devices none
            $list = Get-Step $plan "group:$($ids.LegalDlGroupId)"
            $list.Provider | Should -Be 'DistributionGroup.Member'
            $list.Action | Should -Be 'NoOp' -Because 'Exchange said "not a member", and memberOf is not compared for distribution lists'
        }
    }

    Context 'R16: what a step acts on comes from its provider, not from the Target.Kind label' {
        It 'R16a, R16b, R16d: New-TenureStep refuses a target labelled with a kind the provider does not act on' -ForEach @(
            @{ Provider = 'User.SignIn'; Kind = 'group'; Desired = @{ accountEnabled = $false } }
            @{ Provider = 'User.Password'; Kind = 'device'; Desired = @{ discard = $true } }
            @{ Provider = 'Mailbox.Forwarding'; Kind = 'group'; Desired = @{ forwardingSmtpAddress = 'drop@attacker.example'; deliverToMailboxAndForward = $true } }
        ) {
            { New-TenureStep -Provider $Provider -Target @{ Kind = $Kind; Id = $ids.BobId; Name = 'Helpdesk queue' } -Desired $Desired -Key 'x' } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
        }

        It 'R16a, R16b, R16d: a step relabelled after it was built is refused before step 1, so a protected account is untouched' -ForEach @(
            @{ Provider = 'User.SignIn'; Kind = 'group'; Desired = @{ accountEnabled = $false } }
            @{ Provider = 'User.Password'; Kind = 'device'; Desired = @{ discard = $true } }
            @{ Provider = 'Mailbox.Forwarding'; Kind = 'group'; Desired = @{ forwardingSmtpAddress = 'drop@attacker.example'; deliverToMailboxAndForward = $true } }
        ) {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $realKind = if ($Provider -like 'Mailbox.*') { 'mailbox' } else { 'user' }
            $step = New-TenureStep -Provider $Provider -Target @{ Kind = $realKind; Id = $ids.BobId; Name = 'bob@example.com' } -Desired $Desired -Key 'x'
            $step.Target['Kind'] = $Kind
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy $policy
            $failure = { Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -PassThru
            $failure.Exception.Message | Should -Match "acts on a $realKind"
            { Test-TenurePlan -Plan $plan } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
            (Get-User $ids.BobId).accountEnabled | Should -BeTrue
            (Get-User $ids.BobId).lastPasswordChangeDateTime | Should -Be '2026-01-15T09:00:00Z'
            $global:FakeExchangeWorld.Mailboxes[$ids.BobId].ForwardingSmtpAddress | Should -BeNullOrEmpty
            Test-Path $audit | Should -BeFalse
        }

        It 'R16c: an offboard step resealed onto a protected account under the label role is refused, and protection reads the provider kind' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $signin = $model.Steps | Where-Object { $_.Provider -eq 'User.SignIn' }
            $target = @{ Kind = 'role'; Id = $ids.BobId; Name = 'Global Reader' }
            $signin.Target = $target
            $signin.Before = Get-Snapshot 'User.SignIn' $target $ids.AliceId
            $signin.Fingerprint = Get-Fp $target $signin.Before
            Write-PlanTable $model $file
            Set-ForgedIntegrity $file
            { Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
            (Get-User $ids.BobId).accountEnabled | Should -BeTrue

            # Behind the shape check, the protection preflight reads the account from the provider's kind as well.
            $providers = Invoke-InTenure { @{ 'User.SignIn' = (Get-TenureProviderDefinition -Name 'User.SignIn') } }
            $labelled = [pscustomobject]@{ PlanId = 'p'; Subject = @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com' }; Steps = @([pscustomobject]@{ Id = 'S01'; Provider = 'User.SignIn'; Target = @{ Kind = 'role'; Id = $ids.BobId; Name = 'x' }; After = @{ accountEnabled = $false } }) }
            { Invoke-InTenure { param($p, $v) Assert-TenurePlanProtection -Plan $p -Providers $v -ProtectedUsers @('bob@example.com') } @($labelled, $providers) } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
        }
    }

    Context 'R1, R2, R14, TenantId: what a resealed plan still meets' {
        It 'R1a: an offboard step resealed as an Update of the Global Administrator role is refused: the role provider only removes' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $victim = $model.Steps | Where-Object { $_.Provider -eq 'Group.Member' } | Select-Object -First 1
            $role = @{ Kind = 'role'; Id = $ids.GlobalAdminRoleId; Name = 'Global Administrator' }
            $victim.Provider = 'DirectoryRole.Member'
            $victim.Target = $role
            $victim.Before = Get-Snapshot 'DirectoryRole.Member' $role $ids.AliceId
            $victim.After = @{ userId = $ids.AliceId; member = $true }
            $victim.Action = 'Update'
            $victim.Fingerprint = Get-Fp $role $victim.Before
            $victim.Risk = 'High'
            Write-PlanTable $model $file
            Set-ForgedIntegrity $file
            $failure = { Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -PassThru
            $failure.Exception.Message | Should -Match "Action 'Update'.*allows Remove, NoOp"
            $global:FakeGraphWorld.DirectoryRoles[0].members | Should -Not -Contain $ids.AliceId
        }

        It 'R1b: the same with the Operation flipped to Custom and a third account is refused the same way' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $model.Operation = 'Custom'
            $victim = $model.Steps | Where-Object { $_.Provider -eq 'Group.Member' } | Select-Object -First 1
            $role = @{ Kind = 'role'; Id = $ids.GlobalAdminRoleId; Name = 'Global Administrator' }
            $victim.Provider = 'DirectoryRole.Member'
            $victim.Target = $role
            $victim.Before = Get-Snapshot 'DirectoryRole.Member' $role $ids.BobId
            $victim.After = @{ userId = $ids.BobId; member = $true }
            $victim.Action = 'Update'
            $victim.Fingerprint = Get-Fp $role $victim.Before
            Write-PlanTable $model $file
            Set-ForgedIntegrity $file
            { Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
            $global:FakeGraphWorld.DirectoryRoles[0].members | Should -Not -Contain $ids.BobId
        }

        It 'R1c: a resealed role step labelled Remove (an action the provider allows) whose After says member = $true fails at the provider: no role is granted' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $victim = $model.Steps | Where-Object { $_.Provider -eq 'Group.Member' } | Select-Object -First 1
            $role = @{ Kind = 'role'; Id = $ids.GlobalAdminRoleId; Name = 'Global Administrator' }
            $victim.Provider = 'DirectoryRole.Member'
            $victim.Target = $role
            $victim.Before = Get-Snapshot 'DirectoryRole.Member' $role $ids.AliceId
            $victim.After = @{ userId = $ids.AliceId; member = $true }
            $victim.Action = 'Remove'
            $victim.Fingerprint = Get-Fp $role $victim.Before
            $victim.Risk = 'High'
            Write-PlanTable $model $file
            Set-ForgedIntegrity $file
            $result = Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false -Force -ContinueOnError
            $forged = $result.Plan.Steps | Where-Object { $_.Id -eq $victim.Id }
            $forged.Status | Should -Be 'Failed'
            $forged.Result.Error | Should -Match '^Tenure\.Provider\.Unsupported: .*Tenure removes directory roles and never grants them'
            $global:FakeGraphWorld.DirectoryRoles[0].members | Should -Not -Contain $ids.AliceId
            @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method POST -UriLike '*directoryRoles*').Count | Should -Be 0
        }

        It 'R2: a resealed plan whose recorded policy was removed is refused without -Policy, and checked against it with -Policy' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $model.Subject.Id = $ids.BobId; $model.Subject.UserPrincipalName = 'bob@example.com'; $model.Subject.DisplayName = 'Bob Manager'
            $model.PolicySnapshot = $null; $model.PolicyHash = $null
            $signin = $model.Steps | Where-Object { $_.Provider -eq 'User.SignIn' }
            $target = @{ Kind = 'user'; Id = $ids.BobId; Name = 'bob@example.com' }
            $signin.Target = $target; $signin.Before = Get-Snapshot 'User.SignIn' $target $ids.BobId; $signin.Fingerprint = Get-Fp $target $signin.Before; $signin.Id = 'S01'; $signin.DependsOn = @()
            $model.Steps = @($signin)
            Write-PlanTable $model $file
            Set-ForgedIntegrity $file
            { Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.PolicyMissing'
            { Test-TenurePlan -Plan $file } | Should -Throw -ErrorId 'Tenure.Plan.PolicyMissing'
            { Invoke-TenurePlan -Plan $file -Policy $policy -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.PolicyMismatch' -Because 'a plan that records no policy cannot be matched to one'
            (Get-User $ids.BobId).accountEnabled | Should -BeTrue
            Test-Path $audit | Should -BeFalse
        }

        It 'R14: a -Policy object without a Hash is a mismatch, not a replacement for the recorded protected users' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $step = New-TenureStep -Provider 'User.SignIn' -Target @{ Kind = 'user'; Id = $ids.BobId; Name = 'bob@example.com' } -Desired @{ accountEnabled = $false } -Key 'off'
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.BobId; UserPrincipalName = 'bob@example.com'; DisplayName = 'Bob' } -Step $step -Policy $policy
            { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            $failure = { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -Policy @{ Defaults = @{ protectedUsers = @() } } } | Should -Throw -ErrorId 'Tenure.Plan.PolicyMismatch' -PassThru
            $failure.Exception.Message | Should -Match 'has no Hash'
            { Test-TenurePlan -Plan $plan -Policy @{ Defaults = @{ protectedUsers = @() } } } | Should -Throw -ErrorId 'Tenure.Plan.PolicyMismatch'
            (Get-User $ids.BobId).accountEnabled | Should -BeTrue
        }

        It 'TenantId: a plan that names no tenant is refused by Invoke-TenurePlan and Test-TenurePlan' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $model.CreatedBy.TenantId = ''
            Write-PlanTable $model $file
            Set-ForgedIntegrity $file
            $failure = { Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.WrongTenant' -PassThru
            $failure.Exception.Message | Should -Match 'names no tenant'
            { Test-TenurePlan -Plan $file } | Should -Throw -ErrorId 'Tenure.Plan.WrongTenant'
            (Get-User $ids.AliceId).accountEnabled | Should -BeTrue
        }
    }

    Context 'R3, R9, R10, R11: what the plan file says is not the whole story' {
        It 'R3: a plan applied as an object leaves its file at Planned; the file is refused afterwards because the audit log shows it Applied' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval -GrantOneDriveTo none
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $first = Invoke-TenurePlan -Plan (Import-TenurePlan -Path $file) -AuditPath $audit -Confirm:$false
            $first.Plan.Status | Should -Be 'Applied'
            (Import-TenurePlan -Path $file).Status | Should -Be 'Planned'
            # The user is reinstated by hand; running the old file again must not offboard them a second time.
            (Get-User $ids.AliceId)['accountEnabled'] = $true
            $failure = { Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.AlreadyApplied' -PassThru
            $failure.Exception.Message | Should -Match 'already finished Applied'
            { Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false -WhatIf } | Should -Throw -ErrorId 'Tenure.Plan.AlreadyApplied'
            (Get-User $ids.AliceId).accountEnabled | Should -BeTrue
        }

        It 'R9: -AssumeFired from a run on a plan object still marks the step when a later run starts from the original file' {
            $policy = New-Pol { param($r) foreach ($k in 'removeDirectoryRoles', 'removeFromGroups', 'removeLicenses') { $r['defaults']['offboard'][$k] = $false } }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -GrantOneDriveTo none
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $password = Get-Step $plan 'password'
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = $password.Id; Provider = 'User.Password'; Action = 'Invoke'; Outcome = 'Attempting' } $audit | Out-Null
            $assumed = Invoke-TenurePlan -Plan (Import-TenurePlan -Path $file) -AuditPath $audit -Confirm:$false -Resume -AssumeFired $password.Id
            $assumed.Plan.Status | Should -Be 'PartiallyApplied'
            (Import-TenurePlan -Path $file).Status | Should -Be 'Planned' -Because 'the run used an object, so the file never heard of it'

            $later = Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false
            (Get-Step $later.Plan 'password').Status | Should -Be 'Skipped'
            (Get-Step $later.Plan 'password').Result.Assumed | Should -BeTrue
            (Get-Step $later.Plan 'password').Result.Note | Should -Match 'assumed fired in that run'
            $later.Plan.Status | Should -Be 'PartiallyApplied' -Because 'a plan with a step only assumed to have fired never ends Applied'
            (Import-TenurePlan -Path $file).Steps | Where-Object { $_.Key -eq 'password' } | ForEach-Object { $_.Result.Assumed | Should -BeTrue }
        }

        It 'R10: New-TenurePlan -Inputs $null seals a plan that its own Import-TenurePlan reads back' {
            $step = New-TenureStep -Provider 'User.SignIn' -Target @{ Kind = 'user'; Id = $ids.AliceId; Name = 'alice@example.com' } -Desired @{ accountEnabled = $false } -Key 'off'
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Inputs $null -Policy (New-Pol)
            $plan.Inputs.Count | Should -Be 0
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            (Import-TenurePlan -Path $file).Integrity | Should -Be $plan.Integrity
        }

        It 'R11: Test-TenurePlan reports an Invoke step that only the plan file calls done as Unverified, not Satisfied' {
            $policy = New-Pol { param($r) foreach ($k in 'removeDirectoryRoles', 'removeFromGroups', 'removeLicenses') { $r['defaults']['offboard'][$k] = $false } }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -GrantOneDriveTo none
            (Get-Step $plan 'sessions').Status = 'Applied'
            $check = Test-TenurePlan -Plan $plan
            @($check.Unverified | ForEach-Object Key) | Should -Contain 'sessions'
            @($check.Satisfied | ForEach-Object Key) | Should -Not -Contain 'sessions'
        }
    }

    Context 'R4, R5, R6: the plan does not trip over its own earlier steps' {
        It 'R4: a re-run of a role holder''s offboarding re-evaluates the Global Administrator check its own role removal changed' {
            # The real Global Administrator template id, so the check sees alice as one.
            $ga = $global:FakeGraphWorld.DirectoryRoles[0]; $ga['members'] = [string[]]@($ga['members'] + $ids.AliceId); $ga['roleTemplateId'] = '62e90394-69f5-4237-9190-012177145e10'
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox
            1..4 | ForEach-Object { Add-FakeGraphFault -World $global:FakeGraphWorld -Status 503 -Method DELETE -UriLike "*groups/$($ids.SalesGroupId)/members/*" }
            $first = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive 3>$null
            (Get-Step $first.Plan 'ga').Result.Note | Should -Match 'Severity Warn'
            (Get-Step $first.Plan "role:$($ids.GlobalAdminRoleId)").Status | Should -Be 'Applied'
            (Get-Step $first.Plan "group:$($ids.SalesGroupId)").Status | Should -Be 'Failed'
            @((Test-TenurePlan -Plan $plan).Satisfied | ForEach-Object Key) | Should -Contain 'ga' -Because 'Test-TenurePlan compares the check with the live state too'

            $second = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive
            (Get-Step $second.Plan 'ga').Status | Should -Be 'Skipped'
            (Get-Step $second.Plan 'ga').Result.Note | Should -Match "re-evaluated against the live state.*step $((Get-Step $plan "role:$($ids.GlobalAdminRoleId)").Id).*it passes"
            (Get-Step $second.Plan "group:$($ids.SalesGroupId)").Status | Should -Be 'Applied'
            @((Get-FakeGroup $ids.SalesGroupId).members) | Should -Not -Contain $ids.AliceId
        }

        It 'R4: re-evaluated and failing (the role was granted again since), the check refuses and the run stops' {
            # The real Global Administrator template id, so the check sees alice as one.
            $ga = $global:FakeGraphWorld.DirectoryRoles[0]; $ga['members'] = [string[]]@($ga['members'] + $ids.AliceId); $ga['roleTemplateId'] = '62e90394-69f5-4237-9190-012177145e10'
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox
            1..4 | ForEach-Object { Add-FakeGraphFault -World $global:FakeGraphWorld -Status 503 -Method DELETE -UriLike "*groups/$($ids.SalesGroupId)/members/*" }
            $null = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive 3>$null
            $ga['members'] = [string[]]@($ga['members'] + $ids.AliceId)
            $second = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive -ContinueOnError
            (Get-Step $second.Plan 'ga').Status | Should -Be 'Refused'
            (Get-Step $second.Plan 'ga').Result.Note | Should -Match 'does not pass'
            (Get-Step $second.Plan "group:$($ids.SalesGroupId)").Status | Should -Not -Be 'Applied'
            @((Get-FakeGroup $ids.SalesGroupId).members) | Should -Contain $ids.AliceId
        }

        It 'R5: the sign-in step empties a dynamic group (FakeGraph applies the rule); its no-op step is Skipped, and the wipe runs' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            (Get-Step $plan "group:$($ids.DynamicGroupId)").Action | Should -Be 'NoOp'
            $result = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive
            @((Get-FakeGroup $ids.DynamicGroupId).members) | Should -Not -Contain $ids.AliceId -Because 'disabling the account took alice out of the rule'
            (Get-Step $result.Plan "group:$($ids.DynamicGroupId)").Status | Should -Be 'Skipped'
            ($global:FakeGraphWorld.ManagedDevices | Where-Object { $_.id -eq $ids.CompanyDeviceId }).wiped | Should -BeTrue
            $result.Plan.Status | Should -Be 'Applied' -Because (Get-Statuses $result.Plan)
        }

        It 'R6: a group removal that takes an inherited license (FakeGraph removes it) does not drift the license step, and the wipe runs' {
            $alice = Get-User $ids.AliceId
            $alice['assignedLicenses'].Add(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() })
            $alice['licenseAssignmentStates'].Add(@{ skuId = $ids.SkuVoiceId; assignedByGroup = $ids.AllStaffGroupId; state = 'Active'; error = 'None' })
            (Get-FakeGroup $ids.AllStaffGroupId)['assignedLicenses'] = @(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() })
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $result = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive
            (Get-Step $result.Plan "group:$($ids.AllStaffGroupId)").Status | Should -Be 'Applied'
            (Get-Step $result.Plan 'licenses').Status | Should -Be 'Applied'
            @((Get-User $ids.AliceId).assignedLicenses).Count | Should -Be 0 -Because 'the group took MCOEV with it and the step removed SPE_E3'
            ($global:FakeGraphWorld.ManagedDevices | Where-Object { $_.id -eq $ids.CompanyDeviceId }).wiped | Should -BeTrue
        }

        It 'a re-run after a session revoke does not read its own revoke as drift' {
            $policy = New-Pol { param($r) foreach ($k in 'removeDirectoryRoles', 'removeFromGroups', 'removeLicenses') { $r['defaults']['offboard'][$k] = $false } }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -GrantOneDriveTo none
            $sessions = Get-Step $plan 'sessions'
            $null = Invoke-InTenure { param($t) & (Get-TenureProviderDefinition -Name 'User.Sessions').Set $t $null $null @{} } @($sessions.Target)
            @((Test-TenurePlan -Plan $plan).Drifted).Count | Should -Be 0
            $result = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false
            (Get-Step $result.Plan 'sessions').Status | Should -Be 'Applied'
        }
    }

    Context 'R7: a role change and the last license with Exchange Online' {
        It 'R7a: a move to a role without Exchange Online that removes the only direct mailbox license is refused, naming the license' {
            $policy = New-Pol { param($r) $r['roles']['voice'] = @{ licenses = @('MCOEV') } }
            $failure = { New-TenureRoleChangePlan -User 'alice@example.com' -Role voice -FromRole sales -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.MailboxUnlicensed' -PassThru
            $failure.Exception.Message | Should -Match 'SPE_E3 \(assigned directly\)'
            $failure.Exception.Message | Should -Match 'AllowMailboxLoss'

            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role voice -FromRole sales -Policy $policy -AllowMailboxLoss
            (Get-Step $plan 'licenses').Risk | Should -Be 'Destructive'
            @($plan.Warnings | Where-Object { $_ -match 'leaves alice@example.com no license that gives an Exchange Online mailbox' }).Count | Should -Be 1
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false | Out-Null
            (Get-Step $plan 'licenses').Status | Should -Be 'Refused' -Because 'a Destructive step needs its own confirmation or -AllowDestructive'
            @((Get-User $ids.AliceId).assignedLicenses | ForEach-Object { $_.skuId }) | Should -Contain $ids.SkuE3Id
        }

        It 'R7b: a move that drops the group carrying the only mailbox license is refused, naming the license and the group' {
            Set-GroupLicensedAlice
            $policy = New-Pol { param($r) $r['roles']['voice'] = @{ licenses = @('MCOEV') } }
            $failure = { New-TenureRoleChangePlan -User 'alice@example.com' -Role voice -FromRole sales -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.MailboxUnlicensed' -PassThru
            $failure.Exception.Message | Should -Match "SPE_E3 \(through group 'All Staff'\)"

            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role voice -FromRole sales -Policy $policy -AllowMailboxLoss
            (Get-Step $plan "group:$($ids.AllStaffGroupId)").Risk | Should -Be 'Destructive'
            (Get-Step $plan "group:$($ids.AllStaffGroupId)").Reason | Should -Match 'carries the license that gives the mailbox'
        }

        It 'a move that keeps a mailbox license (the new role brings one) is planned as before' {
            $policy = New-Pol { param($r) $r['roles']['desk'] = @{ licenses = @('EXCHANGEDESKLESS') } }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role desk -FromRole sales -Policy $policy
            (Get-Step $plan 'licenses').Risk | Should -Not -Be 'Destructive'
            @($plan.Warnings | Where-Object { $_ -match 'Exchange Online mailbox' }).Count | Should -Be 0
        }
    }

    Context 'R8, R13, R15: resume, dependencies and read-back' {
        It 'R8: a create whose earlier attempt was refused (403) never adopts an account created hours later, and nothing else runs' {
            $policy = New-Pol { param($r) $r['roles']['solo'] = @{ licenses = @('SPE_E3') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role solo -Policy $policy -TemporaryAccessPass
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Provider = 'Check.UserAbsent'; Action = 'NoOp'; Outcome = 'Skipped'; Note = 'check passed' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S02'; Provider = 'User.Create'; Action = 'Create'; Outcome = 'Attempting'; Note = 'Set is about to run' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S02'; Provider = 'User.Create'; Action = 'Create'; Outcome = 'Failed'; Error = 'Tenure.Graph.Forbidden: Insufficient privileges to complete the operation.' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanFinished' } $audit | Out-Null
            $null = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body (@{ userPrincipalName = 'erin@example.com'; displayName = 'Erin Other'; mailNickname = 'erin'; accountEnabled = $true; usageLocation = 'US'; passwordProfile = @{ password = 'Xx1!aaaaaaaaaaaaaaaa'; forceChangePasswordNextSignIn = $true } } | ConvertTo-Json -Compress)
            (Get-User 'erin@example.com')['createdDateTime'] = [datetime]::UtcNow.AddHours(3).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $result = Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false
            (Get-Step $result.Plan 'absent').Status | Should -Be 'Refused' -Because 'the name is taken and this plan never created anything'
            $result.Plan.Subject.Id | Should -BeNullOrEmpty
            $result.Secrets.Count | Should -Be 0
            @((Get-User 'erin@example.com')['assignedLicenses']).Count | Should -Be 0
        }

        It 'R8: an attempt that ended in a timeout may have landed: an account created during it is adopted' {
            $policy = New-Pol { param($r) $r['roles']['solo'] = @{ licenses = @('SPE_E3') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role solo -Policy $policy
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Provider = 'Check.UserAbsent'; Action = 'NoOp'; Outcome = 'Skipped' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S02'; Provider = 'User.Create'; Action = 'Create'; Outcome = 'Attempting' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S02'; Provider = 'User.Create'; Action = 'Create'; Outcome = 'Failed'; Error = 'Tenure.Graph.Failed: Graph POST users returned 504 (GatewayTimeout): timed out.' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanFinished' } $audit | Out-Null
            $null = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body (@{ userPrincipalName = 'erin@example.com'; displayName = 'Erin New'; mailNickname = 'erin'; accountEnabled = $true; usageLocation = 'US'; passwordProfile = @{ password = 'Xx1!aaaaaaaaaaaaaaaa'; forceChangePasswordNextSignIn = $true } } | ConvertTo-Json -Compress)
            $result = Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false
            Get-Statuses $result.Plan | Should -Be 'absent=Skipped create=Skipped licenses=Applied'
            $result.Plan.Subject.Id | Should -Be (Get-User 'erin@example.com')['id']
        }

        It 'R13: a mailbox conversion Applied in an earlier run, undone since and declined now, does not let the license removal run' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none
            1..4 | ForEach-Object { Add-FakeGraphFault -World $global:FakeGraphWorld -Status 503 -Method POST -UriLike '*assignLicense*' }
            $first = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false -AllowDestructive
            (Get-Step $first.Plan 'mailboxType').Status | Should -Be 'Applied'
            (Get-Step $first.Plan 'licenses').Status | Should -Be 'Failed'
            # Someone converts the mailbox back; at the next run the operator declines the conversion and accepts the rest.
            $global:FakeExchangeWorld.Mailboxes[$ids.AliceId].RecipientTypeDetails = 'UserMailbox'
            $cmdlet = New-TestCmdlet -ShouldProcess { param($t, $a) -not ($t -like '*Mailbox.Type*') }
            $null = Invoke-TestCore -Plan $plan -Cmdlet $cmdlet -AuditPath $audit -With @{ AllowDestructive = $true; Policy = $policy }
            (Get-Step $plan 'mailboxType').Status | Should -Be 'Declined' -Because 'the plan records the answer, so the earlier Applied cannot stand in for it'
            (Get-Step $plan 'licenses').Status | Should -Be 'Refused'
            (Get-Step $plan 'licenses').Result.Note | Should -Match "dependency $((Get-Step $plan 'mailboxType').Id) not applied"
            $global:FakeExchangeWorld.Mailboxes[$ids.AliceId].RecipientTypeDetails | Should -Be 'UserMailbox'
            @((Get-User $ids.AliceId).assignedLicenses).Count | Should -Be 1 -Because 'the mailbox stays licensed'
        }

        It 'R13: a dependency this run did not apply is met when its desired state holds now (read live)' {
            $policy = New-Pol
            $mailbox = @{ Kind = 'mailbox'; Id = $ids.AliceId; Name = 'alice@example.com' }
            $steps = @(
                New-TenureStep -Provider 'User.SignIn' -Target @{ Kind = 'user'; Id = $ids.AliceId; Name = 'alice@example.com' } -Desired @{ accountEnabled = $false } -Key 'off'
                New-TenureStep -Provider 'Mailbox.Hidden' -Target $mailbox -Desired @{ hiddenFromAddressLists = $true } -Key 'hide' -DependsOn 'off'
                New-TenureStep -Provider 'Mailbox.Forwarding' -Target $mailbox -Desired @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $true } -Key 'fwd' -DependsOn 'hide'
            )
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $steps -Policy $policy
            # Someone hides the mailbox by hand; at the run the operator declines the sign-in step.
            $global:FakeExchangeWorld.Mailboxes[$ids.AliceId].HiddenFromAddressListsEnabled = $true
            $cmdlet = New-TestCmdlet -ShouldProcess { param($t, $a) -not $t.StartsWith('[S01]') }
            $null = Invoke-TestCore -Plan $plan -Cmdlet $cmdlet -AuditPath $audit -With @{ ContinueOnError = $true; Policy = $policy }
            Get-Statuses $plan | Should -Be 'off=Declined hide=Refused fwd=Applied'
            (Get-Step $plan 'fwd').Result.Note | Should -Match 'dependency S02 was not applied in this run, but its desired state holds now'
            (Get-User $ids.AliceId).accountEnabled | Should -BeTrue
        }

        It 'R15: a membership change for someone other than the subject reads back that user, and the audit log records it Applied' {
            $step = New-TenureStep -Provider 'Group.Member' -Target @{ Kind = 'group'; Id = $ids.SalesGroupId; Name = 'Sales' } -Desired @{ userId = $ids.CarolId; member = $true } -Context @{ Subject = @{ Id = $ids.AliceId } } -Key 'add'
            $step.Before.userId | Should -Be $ids.CarolId -Because 'the snapshot is of the user the step acts on'
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy (New-Pol)
            $result = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false
            $result.Plan.Steps[0].Status | Should -Be 'Applied'
            @((Get-FakeGroup $ids.SalesGroupId).members) | Should -Contain $ids.CarolId
            $entry = @(Get-TenureAudit -Path $audit | Where-Object { $_.StepId -eq 'S01' })[-1]
            $entry.Outcome | Should -Be 'Applied'
            $entry.Observed.userId | Should -Be $ids.CarolId
        }
    }

    Context 'protectedUsers entries are checked when a plan is built' {
        It 'an entry that matches no user is a plan warning that names it; entries that match by UPN, mail or id are not' {
            (Get-User $ids.CarolId)['mail'] = 'carol.admin@example.com'
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('brekglass@example.com', 'carol.admin@example.com', $ids.BobId) }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $named = @($plan.Warnings | Where-Object { $_ -like '*protectedUsers entry*' })
            $named.Count | Should -Be 1
            $named[0] | Should -Match "'brekglass@example.com' matches no user in this tenant, so it protects no one"
        }
    }

    Context 'IDs: identifiers are strings, and mailboxes and drives are named by object id' {
        It 'IDs: a membership step whose userId is not a string (a guid that stringifies to a protected id) is refused at build and at apply' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $sales = @{ Kind = 'group'; Id = $ids.SalesGroupId; Name = 'Sales' }
            { New-TenureStep -Provider 'Group.Member' -Target $sales -Desired @{ userId = [guid]$ids.BobId; member = $true } -Key 'add' } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
            $step = New-TenureStep -Provider 'Group.Member' -Target $sales -Desired @{ userId = $ids.CarolId; member = $true } -Key 'add'
            $step.After['userId'] = [guid]$ids.BobId
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy $policy
            $failure = { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -PassThru
            $failure.Exception.Message | Should -Match 'userId'
            { Test-TenurePlan -Plan $plan } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
            @((Get-FakeGroup $ids.SalesGroupId).members) | Should -Not -Contain $ids.BobId
            Test-Path $audit | Should -BeFalse
        }

        It 'IDs: a step whose Target.Id is not a string is refused at apply, in a Custom plan too' {
            $policy = New-Pol
            $step = New-TenureStep -Provider 'User.SignIn' -Target @{ Kind = 'user'; Id = $ids.BobId; Name = 'bob@example.com' } -Desired @{ accountEnabled = $false } -Key 'off'
            $step.Target['Id'] = [guid]$ids.BobId
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy $policy
            { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
            (Get-User $ids.BobId).accountEnabled | Should -BeTrue
        }

        It 'IDs: a mailbox step named by a protected user''s alias is refused at build and at apply' {
            $policy = New-Pol { param($r) $r['defaults']['protectedUsers'] = @('bob@example.com') }
            $desired = @{ forwardingSmtpAddress = 'drop@attacker.example'; deliverToMailboxAndForward = $true }
            { New-TenureStep -Provider 'Mailbox.Forwarding' -Target @{ Kind = 'mailbox'; Id = 'bob'; Name = 'Shared inbox' } -Desired $desired -Key 'fwd' } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
            $step = New-TenureStep -Provider 'Mailbox.Forwarding' -Target @{ Kind = 'mailbox'; Id = $ids.AliceId; Name = 'Shared inbox' } -Desired $desired -Key 'fwd'
            $step.Target['Id'] = 'bob'
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy $policy
            $failure = { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -PassThru
            $failure.Exception.Message | Should -Match 'object id'
            $global:FakeExchangeWorld.Mailboxes[$ids.BobId].ForwardingSmtpAddress | Should -BeNullOrEmpty
            $global:FakeExchangeWorld.Mailboxes[$ids.AliceId].ForwardingSmtpAddress | Should -BeNullOrEmpty
        }

        It 'IDs: a drive step named by a user principal name is refused at build' {
            { New-TenureStep -Provider 'OneDrive.Access' -Target @{ Kind = 'drive'; Id = 'bob@example.com'; Name = 'bob@example.com' } -Desired @{ granteeEmail = 'carol@example.com'; role = 'read'; present = $true } -Key 'od' } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
        }
    }

    Context 'Role-assignable groups: Tenure never grants a role through a group' {
        BeforeEach {
            $global:FakeGraphWorld.Groups.Add(@{
                    id = $script:RoleGroupId; displayName = 'Tier 1 Admins'; mail = $null; mailNickname = 'tier1admins'
                    mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null; isAssignableToRole = $true
                    members = [string[]]@(); owners = [string[]]@()
                })
        }

        It 'Roles: a Custom add to a role-assignable group fails at the provider before any write, and nobody is added' {
            $step = New-TenureStep -Provider 'Group.Member' -Target @{ Kind = 'group'; Id = $script:RoleGroupId; Name = 'Tier 1 Admins' } -Desired @{ userId = $ids.CarolId; member = $true } -Key 'add'
            $step.Before.isAssignableToRole | Should -BeTrue
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy (New-Pol)
            $result = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false
            $result.Plan.Steps[0].Status | Should -Be 'Failed'
            $result.Plan.Steps[0].Result.Error | Should -Match '^Tenure\.Provider\.Unsupported: .*never grants .*role-assignable'
            @((Get-FakeGroup $script:RoleGroupId).members).Count | Should -Be 0
            @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method POST -UriLike "*groups/$($script:RoleGroupId)/members*").Count | Should -Be 0
        }

        It 'Roles: an offboard group step resealed into an add to a role-assignable group fails the same way' {
            $policy = New-Pol
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            $file = New-PlanFile
            Export-TenurePlan -Plan $plan -Path $file
            $model = Read-PlanTable $file
            $victim = $model.Steps | Where-Object { $_.Provider -eq 'Group.Member' } | Select-Object -First 1
            $target = @{ Kind = 'group'; Id = $script:RoleGroupId; Name = 'Tier 1 Admins' }
            $victim.Target = $target
            $victim.Before = Get-Snapshot 'Group.Member' $target $ids.AliceId
            $victim.After = @{ userId = $ids.AliceId; member = $true }
            $victim.Action = 'Update'
            $victim.Fingerprint = Get-Fp $target $victim.Before
            Write-PlanTable $model $file
            Set-ForgedIntegrity $file
            $result = Invoke-TenurePlan -Plan $file -AuditPath $audit -Confirm:$false -ContinueOnError
            ($result.Plan.Steps | Where-Object { $_.Id -eq $victim.Id }).Status | Should -Be 'Failed'
            @((Get-FakeGroup $script:RoleGroupId).members) | Should -Not -Contain $ids.AliceId
        }

        It 'Roles: a builder leaves out the add to a role-assignable group, with a warning' {
            $policy = New-Pol { param($r) $r['roles']['admins'] = @{ licenses = @('SPE_E3'); groups = @('Tier 1 Admins', 'All Staff') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role admins -Policy $policy
            @($plan.Steps | ForEach-Object Key) | Should -Not -Contain "group:$($script:RoleGroupId)"
            @($plan.Warnings | Where-Object { $_ -match "'Tier 1 Admins' can be assigned to a directory role" }).Count | Should -Be 1
        }

        It 'Roles: removing a user from a role-assignable group is still allowed' {
            $group = Get-FakeGroup $script:RoleGroupId
            $group['members'] = [string[]]@($ids.AliceId)
            $step = New-TenureStep -Provider 'Group.Member' -Target @{ Kind = 'group'; Id = $script:RoleGroupId; Name = 'Tier 1 Admins' } -Desired @{ userId = $ids.AliceId; member = $false } -Key 'remove'
            $plan = New-TenurePlan -Operation Custom -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice' } -Step $step -Policy (New-Pol)
            (Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false).Plan.Steps[0].Status | Should -Be 'Applied'
            @((Get-FakeGroup $script:RoleGroupId).members).Count | Should -Be 0
        }
    }

    Context 'Mailbox licenses: a role change counts service plans and seats, not SKU ids' {
        It 'Seats: a kept group whose license has the Exchange plan disabled does not keep the mailbox: the change is refused' {
            # alice holds SPE_E3 directly and through All Staff, whose assignment disables EXCHANGE_S_ENTERPRISE.
            $exchangePlan = '31000000-0000-4000-8000-000000000001'
            (Get-FakeGroup $ids.AllStaffGroupId)['assignedLicenses'] = @(@{ skuId = $ids.SkuE3Id; disabledPlans = @($exchangePlan) })
            (Get-User $ids.AliceId)['licenseAssignmentStates'].Add(@{ skuId = $ids.SkuE3Id; assignedByGroup = $ids.AllStaffGroupId; state = 'Active'; error = 'None' })
            $policy = New-Pol { param($r) $r['roles']['voice'] = @{ licenses = @('MCOEV') } }
            $failure = { New-TenureRoleChangePlan -User 'alice@example.com' -Role voice -FromRole sales -KeepGroup 'All Staff' -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.MailboxUnlicensed' -PassThru
            $failure.Exception.Message | Should -Match 'SPE_E3 \(assigned directly\)'
        }

        It 'Seats: a kept group whose license keeps the Exchange plan keeps the mailbox' {
            (Get-FakeGroup $ids.AllStaffGroupId)['assignedLicenses'] = @(@{ skuId = $ids.SkuE3Id; disabledPlans = @() })
            (Get-User $ids.AliceId)['licenseAssignmentStates'].Add(@{ skuId = $ids.SkuE3Id; assignedByGroup = $ids.AllStaffGroupId; state = 'Active'; error = 'None' })
            $policy = New-Pol { param($r) $r['roles']['voice'] = @{ licenses = @('MCOEV') } }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role voice -FromRole sales -KeepGroup 'All Staff' -Policy $policy
            (Get-Step $plan 'licenses').Risk | Should -Not -Be 'Destructive'
        }

        It 'Seats: a new group whose license has no free seats does not keep the mailbox: refused, naming the SKU and the shortage' {
            $global:FakeGraphWorld.Groups.Add(@{
                    id = $script:DeskGroupId; displayName = 'Desk Users'; mail = $null; mailNickname = 'deskusers'
                    mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
                    members = [string[]]@(); owners = [string[]]@(); assignedLicenses = @(@{ skuId = $ids.SkuDeskId; disabledPlans = @() })
                })
            $policy = New-Pol { param($r) $r['roles']['desk'] = @{ groups = @('Desk Users') } }
            $failure = { New-TenureRoleChangePlan -User 'alice@example.com' -Role desk -FromRole sales -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.MailboxUnlicensed' -PassThru
            $failure.Exception.Message | Should -Match "EXCHANGEDESKLESS through group 'Desk Users' has no free seats \(5 enabled, 5 consumed\)"
        }

        It 'Seats: a new group whose license has free seats keeps the mailbox' {
            $global:FakeGraphWorld.Groups.Add(@{
                    id = $script:DeskGroupId; displayName = 'Desk Users'; mail = $null; mailNickname = 'deskusers'
                    mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
                    members = [string[]]@(); owners = [string[]]@(); assignedLicenses = @(@{ skuId = $ids.SkuE3Id; disabledPlans = @() })
                })
            $policy = New-Pol { param($r) $r['roles']['desk'] = @{ groups = @('Desk Users') } }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role desk -FromRole sales -Policy $policy
            @($plan.Steps | ForEach-Object Key) | Should -Contain "group:$($script:DeskGroupId)"
        }
    }

    Context 'Adoption: the window of an attempt with no later entry ends' {
        It 'Adoption: after a run killed right after Attempting, a name taken after the longest possible request is not adopted on resume' {
            $policy = New-Pol { param($r) $r['roles']['solo'] = @{ licenses = @('SPE_E3') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'erin@example.com' -DisplayName 'Erin New' -Role solo -Policy $policy
            Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Provider = 'Check.UserAbsent'; Action = 'NoOp'; Outcome = 'Skipped' } $audit | Out-Null
            Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S02'; Provider = 'User.Create'; Action = 'Create'; Outcome = 'Attempting' } $audit | Out-Null
            $null = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body (@{ userPrincipalName = 'erin@example.com'; displayName = 'Erin Other'; mailNickname = 'erin'; accountEnabled = $true; usageLocation = 'US'; passwordProfile = @{ password = 'Xx1!aaaaaaaaaaaaaaaa'; forceChangePasswordNextSignIn = $true } } | ConvertTo-Json -Compress)
            (Get-User 'erin@example.com')['createdDateTime'] = [datetime]::UtcNow.AddHours(2).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $result = Invoke-TenurePlan -Plan $plan -Policy $policy -AuditPath $audit -Confirm:$false -Resume
            (Get-Step $result.Plan 'create').Status | Should -Be 'Drifted'
            (Get-Step $result.Plan 'create').Result.Note | Should -Match 'not the account this plan created'
            $result.Plan.Subject.Id | Should -BeNullOrEmpty
            @((Get-User 'erin@example.com')['assignedLicenses']).Count | Should -Be 0
        }
    }
}
