# Contract tests for the apply engine (docs/SPEC.md section 5.4).
# Fake providers only; no tenant. Every run passes -AuditPath under TestDrive, and
# TENURE_AUDIT_PATH points at a sentinel file under TestDrive so a code path that ignored
# -AuditPath would be caught here instead of writing to $HOME.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'PlanFixtures.ps1')
    Import-TenureForTest
    # Plans here name made-up users and run without FakeGraph: the protection preflight compares names only.
    Disable-TestIdentityLookup

    # Never prompt: ShouldProcess with ConfirmImpact High would otherwise wait for input.
    $script:SavedConfirmPreference = $global:ConfirmPreference
    $global:ConfirmPreference = 'None'
    $script:SavedAuditEnv = $env:TENURE_AUDIT_PATH
    $script:FakeNames = @('Fake.State', 'Fake.Group', 'Fake.RoleMember', 'Fake.Invoke', 'Fake.Destroy', 'Fake.CheckRefuse', 'Fake.CheckWarn', 'Fake.Liar', 'Fake.Boom', 'Fake.Create', 'Fake.Mail', 'Fake.Noisy', 'Fake.Fuzzy', 'Fake.Watch', 'Fake.Nested', 'Fake.Reread', 'Fake.Assign', 'Fake.Laggy', 'Fake.Role')

    function New-World {
        Set-TenureTestSession
        $script:state = @{}
        $script:log = [System.Collections.Generic.List[string]]::new()
        $script:audit = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $script:sentinel = Join-Path $TestDrive 'env-sentinel.jsonl'
        $env:TENURE_AUDIT_PATH = $script:sentinel
        Register-TestProvider (New-RecordingProvider -Name 'Fake.State' -State $script:state -Log $script:log)
        # The same fake for steps on a group and on a role: a provider acts on one kind of target.
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Group' -State $script:state -Log $script:log -Overrides @{ TargetKind = 'group' })
        Register-TestProvider (New-RecordingProvider -Name 'Fake.RoleMember' -State $script:state -Log $script:log -Overrides @{ TargetKind = 'role' })
    }

    function Add-User([string]$Id, [hashtable]$Values) {
        if (-not $Values) { $Values = @{ accountEnabled = $true; department = 'Sales' } }
        $script:state[$Id] = $Values.Clone()
    }

    function New-DisableStep([string]$Id, [string]$UserId, [string[]]$DependsOn = @(), [string]$Provider = 'Fake.State', [hashtable]$After) {
        if (-not $After) { $After = @{ accountEnabled = $false } }
        New-TestStep -Id $Id -Provider $Provider -Target @{ Kind = 'user'; Id = $UserId; Name = $UserId } -Before (Get-TestSnapshot -State $script:state -Id $UserId) -After $After -DependsOn $DependsOn
    }

    function Invoke-Apply {
        param([Parameter(Mandatory)][object]$Plan, [hashtable]$With = @{})
        $parameters = @{ Plan = $Plan; AuditPath = $script:audit; Confirm = $false }
        foreach ($key in $With.Keys) { $parameters[$key] = $With[$key] }
        Invoke-TenurePlan @parameters
    }

    function New-CheckStep([string]$Id, [string]$Provider, [string[]]$DependsOn = @()) {
        New-TestStep -Id $Id -Provider $Provider -Action 'Check' -Target @{ Kind = 'user'; Id = 'guard'; Name = 'guard' } -Before (Get-TestSnapshot -State $script:state -Id 'guard') -After @{ ok = $true } -DependsOn $DependsOn
    }

    function New-InvokeStep([string]$Id, [string]$UserId) {
        New-TestStep -Id $Id -Provider 'Fake.Invoke' -Action 'Invoke' -Target @{ Kind = 'user'; Id = $UserId; Name = $UserId } -Before (Get-TestSnapshot -State $script:state -Id $UserId) -After @{ revoke = $true }
    }

    function Get-Outcome([string]$Path) {
        @(Get-TenureAudit -Path $Path | ForEach-Object { if ($_.StepId) { "$($_.Outcome):$($_.StepId)" } else { $_.Outcome } }) -join ','
    }
}

AfterAll {
    $global:ConfirmPreference = $script:SavedConfirmPreference
    $env:TENURE_AUDIT_PATH = $script:SavedAuditEnv
    Unregister-TestProvider -Name $script:FakeNames
    Clear-TenureTestSession
}

Describe 'Invoke-TenurePlan acceptance' {
    BeforeEach {
        New-World
        foreach ($id in 'u1', 'u2', 'u3', 'u4') { Add-User $id }
        $script:plan = New-TestPlan -Steps @(
            New-DisableStep 'S01' 'u1'
            New-DisableStep 'S02' 'u2'
            New-DisableStep 'S03' 'u3'
            New-DisableStep 'S04' 'u4'
        )
        # Someone changes u3 after the plan was built.
        $script:state['u3']['department'] = 'Changed elsewhere'
    }

    It 'applies 1 and 2, marks 3 Drifted, leaves 4 Pending, and writes a valid chain' {
        $result = Invoke-Apply $script:plan

        Get-TestStatus $script:plan | Should -Be 'Applied,Applied,Drifted,Pending'
        $script:plan.Status | Should -Be 'PartiallyApplied'
        [object]::ReferenceEquals($result.Plan, $script:plan) | Should -BeTrue -Because 'the engine mutates and returns the given plan'
        $result.PSObject.TypeNames[0] | Should -Be 'Tenure.ApplyResult'
        $result.Summary.Applied | Should -Be 2
        $result.Summary.Drifted | Should -Be 1
        $result.Summary.Pending | Should -Be 1
        ($result.Summary.Skipped + $result.Summary.Failed + $result.Summary.DryRun + $result.Summary.Refused) | Should -Be 0
        $result.AuditPath | Should -Be $script:audit

        @($script:log) | Should -Be @('Fake.State:u1', 'Fake.State:u2')
        $script:state['u3']['accountEnabled'] | Should -BeTrue
        $script:state['u4']['accountEnabled'] | Should -BeTrue
        $script:plan.Steps[2].Result.Note | Should -Match 'drift'
        $script:plan.Steps[2].Result.Observed.department | Should -Be 'Changed elsewhere'
        $script:plan.Steps[3].Result | Should -BeNullOrEmpty

        Get-Outcome $script:audit | Should -Be 'PlanStarted,Applied:S01,Applied:S02,Drifted:S03,PlanFinished'
        $check = Test-TenureAudit -Path $script:audit
        $check.Valid | Should -BeTrue
        $check.Entries | Should -Be 5
        $finished = @(Get-TenureAudit -Path $script:audit -Last 1)[0]
        $finished.Observed.Status | Should -Be 'PartiallyApplied'
        $finished.Observed.Summary.Applied | Should -Be 2
        Test-Path $script:sentinel | Should -BeFalse -Because '-AuditPath must win over TENURE_AUDIT_PATH and the default'
    }

    It 'applies through drift with -Force and notes it' {
        Invoke-Apply $script:plan -With @{ Force = $true } | Out-Null
        Get-TestStatus $script:plan | Should -Be 'Applied,Applied,Applied,Applied'
        $script:plan.Status | Should -Be 'Applied'
        $script:plan.Steps[2].Result.Note | Should -Match 'drift overridden'
        $script:state['u3']['accountEnabled'] | Should -BeFalse
    }

    It 'calls no Set and writes no audit file under -WhatIf, and leaves the given plan untouched' {
        $result = Invoke-TenurePlan -Plan $script:plan -AuditPath $script:audit -WhatIf
        $script:log.Count | Should -Be 0
        Test-Path $script:audit | Should -BeFalse
        Test-Path $script:sentinel | Should -BeFalse
        Get-TestStatus $script:plan | Should -Be 'Pending,Pending,Pending,Pending'
        $script:plan.Status | Should -Be 'Planned'
        @($script:plan.Steps | Where-Object { $null -ne $_.Result }).Count | Should -Be 0
        [object]::ReferenceEquals($result.Plan, $script:plan) | Should -BeFalse
        Get-TestStatus $result.Plan | Should -Be 'Pending,Pending,Drifted,Pending'
        foreach ($id in 'u1', 'u2', 'u4') { $script:state[$id]['accountEnabled'] | Should -BeTrue }
    }
}

Describe 'Invoke-TenurePlan step rules' {
    BeforeEach { New-World }

    It 'records a dry run: no Set, DryRun outcomes with Mode DryRun, dependencies honored' {
        Add-User 'u1'; Add-User 'u2'
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2' -DependsOn 'S01'))
        $result = Invoke-Apply $plan -With @{ DryRun = $true }
        $script:log.Count | Should -Be 0
        Get-TestStatus $plan | Should -Be 'DryRun,DryRun'
        $plan.Status | Should -Be 'DryRun'
        $result.Summary.DryRun | Should -Be 2
        $plan.Steps[0].Result.Observed.accountEnabled | Should -BeTrue
        Get-Outcome $script:audit | Should -Be 'PlanStarted,DryRun:S01,DryRun:S02,PlanFinished'
        @(Get-TenureAudit -Path $script:audit | Where-Object Mode -ne 'DryRun').Count | Should -Be 0
        (Test-TenureAudit -Path $script:audit).Valid | Should -BeTrue
    }

    It 'skips a step whose desired state already holds' {
        Add-User 'u1' @{ accountEnabled = $false; department = 'Sales' }
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        $result = Invoke-Apply $plan
        $plan.Steps[0].Status | Should -Be 'Skipped'
        $plan.Steps[0].Result.Note | Should -Match 'already satisfied'
        $script:log.Count | Should -Be 0
        $plan.Status | Should -Be 'Applied'
        $result.Summary.Skipped | Should -Be 1
        Get-Outcome $script:audit | Should -Be 'PlanStarted,Skipped:S01,PlanFinished'
    }

    It 'refuses a step whose dependency did not apply, and stops (declined confirmation)' {
        Add-User 'u1'; Add-User 'u2'; Add-User 'u3'
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2' -DependsOn 'S01'), (New-DisableStep 'S03' 'u3'))
        # A cmdlet stand-in whose ShouldProcess declines S01, like answering No at the prompt.
        $cmdlet = [pscustomobject]@{}
        $cmdlet | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value { param($target, $action) -not $target.StartsWith('[S01]') }
        $result = Invoke-InTenure { param($p, $c, $a) Invoke-TenurePlanCore -Plan $p -Cmdlet $c -AuditPath $a -ConfirmSuppressed $false } @($plan, $cmdlet, $script:audit)
        Get-TestStatus $plan | Should -Be 'Declined,Refused,Pending'
        $plan.Steps[1].Result.Note | Should -Be 'dependency S01 not applied'
        $plan.Steps[0].Result.Note | Should -Match 'declined at the confirmation prompt'
        $plan.Steps[0].Result.Attempted | Should -BeFalse
        $result.Summary.Declined | Should -Be 1
        $script:log.Count | Should -Be 0
        $result.Summary.Refused | Should -Be 1
        Get-Outcome $script:audit | Should -Be 'PlanStarted,Refused:S02,PlanFinished' -Because 'a declined step writes nothing to the audit log'
    }

    It 'continues past Failed, Drifted and Refused steps with -ContinueOnError, refusing dependants' {
        Add-User 'u1'; Add-User 'u2'; Add-User 'u3'; Add-User 'u4'; Add-User 'u5'
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Boom' -State $script:state -Log $script:log -Overrides @{ Set = { param($Target, $Desired, $Current, $Context) throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Graph said no'), 'Tenure.Graph.Failed', 'NotSpecified', $null) } })
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Destroy' -State $script:state -Log $script:log -Overrides @{ Risk = 'Destructive'; Reversible = $false })
        $plan = New-TestPlan -Steps @(
            New-DisableStep 'S01' 'u1' -Provider 'Fake.Boom'
            New-DisableStep 'S02' 'u2' -DependsOn 'S01'
            New-DisableStep 'S03' 'u3'
            New-DisableStep 'S04' 'u4' -Provider 'Fake.Destroy'
            New-DisableStep 'S05' 'u5'
        )
        $script:state['u3']['department'] = 'Moved'
        Invoke-Apply $plan -With @{ ContinueOnError = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Failed,Refused,Drifted,Refused,Applied'
        $plan.Steps[0].Result.Error | Should -Be 'Tenure.Graph.Failed: Graph said no'
        $plan.Steps[1].Result.Note | Should -Be 'dependency S01 not applied'
        $plan.Status | Should -Be 'PartiallyApplied'
        @($script:log) | Should -Be @('Fake.State:u5')
        (Test-TenureAudit -Path $script:audit).Entries | Should -Be 7
    }

    It 'stops at the first Failed step without -ContinueOnError' {
        Add-User 'u1'; Add-User 'u2'
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Boom' -State $script:state -Log $script:log -Overrides @{ Set = { param($Target, $Desired, $Current, $Context) throw 'kaboom' } })
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1' -Provider 'Fake.Boom'), (New-DisableStep 'S02' 'u2'))
        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Failed,Pending'
        $plan.Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Error | Should -Match 'kaboom'
    }

    It 'fails a step whose Set does not reach the desired state (post-condition)' {
        Add-User 'u1'
        $liarSet = { param($Target, $Desired, $Current, $Context) [pscustomobject]@{ accountEnabled = $false } }
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Liar' -State $script:state -Log $script:log -Overrides @{ Set = $liarSet })
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Liar')
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Note | Should -Match 'post-condition not met'
        $plan.Steps[0].Result.Error | Should -Match '^Tenure\.Apply\.PostConditionFailed'
        $plan.Steps[0].Result.Observed.accountEnabled | Should -BeTrue -Because 'Observed is what Get read back, not what Set claimed'
    }

    It 'treats a non-terminating error from a provider as a failure' {
        Add-User 'u1'
        $noisyGet = { param($Target, $Context) Write-Error 'partial read'; [pscustomobject]@{ accountEnabled = $true; department = 'Sales' } }
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Noisy' -State $script:state -Log $script:log -Overrides @{ Get = $noisyGet })
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Noisy')
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Error | Should -Match 'partial read'
        $script:log.Count | Should -Be 0
    }

    It 'fails a step whose Test returns something other than a bool' {
        Add-User 'u1'
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Fuzzy' -State $script:state -Log $script:log -Overrides @{ Test = { param($Current, $Desired) 'false' } })
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Fuzzy')
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Error | Should -Match '^Tenure\.Provider\.InvalidResult'
        $script:log.Count | Should -Be 0 -Because "a Test returning the string 'false' must not be read as true or false"
    }
}

Describe 'Invoke-TenurePlan resume' {
    BeforeEach {
        New-World
        Add-User 'u1'; Add-User 'u2'
        $script:fires = @{ Count = 0 }
        $script:toggle = @{ Fail = $true }
        $fires = $script:fires
        $toggle = $script:toggle
        $invokeSet = { param($Target, $Desired, $Current, $Context) $fires.Count++; [pscustomobject]@{ revokedAt = 'now' } }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Invoke' -State $script:state -Log $script:log -Overrides @{ Kind = 'Invoke'; Set = $invokeSet; Test = { param($Current, $Desired) $false } })
        $state = $script:state
        $boomSet = {
            param($Target, $Desired, $Current, $Context)
            if ($toggle.Fail) { throw 'not yet' }
            foreach ($key in $Desired.Keys) { $state[$Target.Id][$key] = $Desired[$key] }
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Boom' -State $script:state -Log $script:log -Overrides @{ Set = $boomSet })
    }

    It 'skips an Invoke step applied in an earlier run and never fires it again' {
        $plan = New-TestPlan -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.Invoke' -Action 'Invoke' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -Before (Get-TestSnapshot -State $script:state -Id 'u1') -After @{ revoke = $true }
            New-DisableStep 'S02' 'u2' -Provider 'Fake.Boom'
        )
        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Applied,Failed'
        $script:fires.Count | Should -Be 1

        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Skipped,Failed'
        $plan.Steps[0].Result.Note | Should -Match 'already applied'
        $script:fires.Count | Should -Be 1

        # Third run: the Invoke step is now Skipped, which still means "already fired".
        $script:toggle.Fail = $false
        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Skipped,Applied'
        $plan.Status | Should -Be 'Applied'
        $script:fires.Count | Should -Be 1
    }

    It 'never fires an Invoke step the plan records as Skipped against a fresh audit log, and does not take the plan''s word for it either' {
        $plan = New-TestPlan -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.Invoke' -Action 'Invoke' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -Before (Get-TestSnapshot -State $script:state -Id 'u1') -After @{ revoke = $true } -Status 'Skipped' -Result @{ At = [datetime]::UtcNow.ToString('o'); DurationMs = 1; Observed = $null; Error = $null; Note = 'already applied in an earlier run'; Attempted = $false; Uncertain = $false }
            New-DisableStep 'S02' 'u2'
        ) -Status 'PartiallyApplied'
        Invoke-Apply $plan | Out-Null
        $script:fires.Count | Should -Be 0 -Because 'the plan status alone must stop a second firing when the audit log has no history'
        Get-TestStatus $plan | Should -Be 'Refused,Pending' -Because 'a status edited to Skipped must not silence the step either: it is in doubt'
        $plan.Steps[0].Result.Note | Should -Match 'audit log .* has no record of it'
        $plan.Steps[0].Result.Note | Should -Match '-AssumeFired S01'

        Invoke-Apply $plan -With @{ AssumeFired = @('S01') } | Out-Null
        Get-TestStatus $plan | Should -Be 'Skipped,Applied'
        $plan.Status | Should -Be 'PartiallyApplied'
        $script:fires.Count | Should -Be 0
    }

    It 'skips an applied State step on resume instead of reporting our own write as drift' {
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2' -Provider 'Fake.Boom'))
        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Applied,Failed'
        $plan.Status | Should -Be 'PartiallyApplied'

        $script:toggle.Fail = $false
        $result = Invoke-Apply $plan
        Get-TestStatus $plan | Should -Be 'Skipped,Applied'
        $plan.Steps[0].Result.Note | Should -Match 'earlier run; still satisfied'
        $plan.Status | Should -Be 'Applied'
        $result.Summary.Applied | Should -Be 1
        @($script:log | Where-Object { $_ -eq 'Fake.State:u1' }).Count | Should -Be 1

        { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Plan.AlreadyApplied'
    }

    It 'still detects drift on an applied State step that someone reverted to a third state' {
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2' -Provider 'Fake.Boom'))
        Invoke-Apply $plan | Out-Null
        $script:state['u1'] = @{ accountEnabled = $true; department = 'Elsewhere' }
        $script:toggle.Fail = $false
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Drifted'
        $plan.Steps[1].Status | Should -Be 'Failed' -Because 'the run stopped at S01, so S02 keeps its earlier status'
    }
}

Describe 'Invoke-TenurePlan preflight' {
    BeforeEach {
        New-World
        Add-User 'u1'
    }

    It 'refuses a plan older than -MaxAge; -AllowStale overrides and -Force does not' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1') -CreatedAt ([datetime]::UtcNow.AddHours(-25).ToString('o'))
        { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Plan.Stale'
        { Invoke-Apply $plan -With @{ Force = $true } } | Should -Throw -ErrorId 'Tenure.Plan.Stale' -Because '-Force overrides drift only'
        Test-Path $script:audit | Should -BeFalse
        $script:log.Count | Should -Be 0
        Invoke-Apply $plan -With @{ AllowStale = $true } | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
    }

    It 'does not override drift with -AllowStale' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1') -CreatedAt ([datetime]::UtcNow.AddHours(-25).ToString('o'))
        $script:state['u1']['department'] = 'Moved'
        Invoke-Apply $plan -With @{ AllowStale = $true } | Out-Null
        $plan.Steps[0].Status | Should -Be 'Drifted'
        $script:log.Count | Should -Be 0
    }

    It 'honors a custom -MaxAge and accepts a [datetime] CreatedAt' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1') -CreatedAt ([datetime]::UtcNow.AddHours(-2))
        { Invoke-Apply $plan -With @{ MaxAge = [timespan]::FromHours(1) } } | Should -Throw -ErrorId 'Tenure.Plan.Stale'
        Invoke-Apply $plan -With @{ MaxAge = [timespan]::FromHours(3) } | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
    }

    It 'refuses a plan created in the future unless -AllowStale' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1') -CreatedAt ([datetime]::UtcNow.AddDays(30).ToString('o'))
        { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Plan.Stale'
        { Invoke-Apply $plan -With @{ Force = $true } } | Should -Throw -ErrorId 'Tenure.Plan.Stale'
        Invoke-Apply $plan -With @{ AllowStale = $true } | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
    }

    It 'refuses an Applied plan, even with -Force, before writing anything' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' ) -Status 'Applied'
        { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Plan.AlreadyApplied'
        { Invoke-Apply $plan -With @{ Force = $true } } | Should -Throw -ErrorId 'Tenure.Plan.AlreadyApplied'
        Test-Path $script:audit | Should -BeFalse
    }

    It 'fails in preflight when a needed backend is not connected, with no audit entry and no Set' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Mail' -State $script:state -Log $script:log -Overrides @{ Backend = 'Exchange' })
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u1' -Provider 'Fake.Mail'))
        Set-TenureTestSession -Exchange $false
        { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
        Test-Path $script:audit | Should -BeFalse
        $script:log.Count | Should -Be 0
        Get-TestStatus $plan | Should -Be 'Pending,Pending'
    }

    It 'fails in preflight when a provider is not registered' {
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-TestStep -Id 'S02' -Provider 'Fake.Missing' -Kind 'State' -Action 'Create'))
        { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Provider.NotRegistered'
        Test-Path $script:audit | Should -BeFalse
        $script:log.Count | Should -Be 0
    }

    It 'rejects objects that are not plans and plans that break the step contract' {
        { Invoke-Apply ([pscustomobject]@{ Steps = @() }) } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'

        $noFingerprint = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -Before ([pscustomobject]@{ accountEnabled = $true }) -After @{ accountEnabled = $false } -Fingerprint '')
        { Invoke-Apply $noFingerprint } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -Because 'an empty Fingerprint would silently disable the drift check'

        $forward = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1' -DependsOn 'S02'), (New-DisableStep 'S02' 'u1'))
        { Invoke-Apply $forward } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'

        $duplicate = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S01' 'u1'))
        { Invoke-Apply $duplicate } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'

        $wrongKind = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Kind 'Invoke' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -Before (Get-TestSnapshot -State $script:state -Id 'u1'))
        { Invoke-Apply $wrongKind } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -Because "the provider's Kind decides what the engine does, not the plan file"

        $secret = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -After @{ password = (New-TestSecureString 'Q7-plan-secret-x') })
        $failure = { Invoke-Apply $secret } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -PassThru
        $failure.Exception.Message | Should -Not -Match 'Q7-plan-secret-x'

        Test-Path $script:audit | Should -BeFalse
        $script:log.Count | Should -Be 0
    }

    It 'refuses a -Policy whose hash differs from the plan PolicyHash' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1') -PolicyHash ('a' * 64)
        $policy = [pscustomobject]@{ PSTypeName = 'Tenure.Policy'; Hash = ('b' * 64) }
        { Invoke-Apply $plan -With @{ Policy = $policy } } | Should -Throw -ErrorId 'Tenure.Plan.PolicyMismatch'
        Test-Path $script:audit | Should -BeFalse
    }

    It 'passes -Policy to providers as Context.Policy' {
        $seen = @{}
        $state = $script:state
        $get = { param($Target, $Context) $seen.Policy = $Context.Policy; $seen.Mode = $Context.Mode; $seen.StepId = $Context.StepId; [pscustomobject]$state[$Target.Id].Clone() }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.State' -State $script:state -Log $script:log -Overrides @{ Get = $get })
        $policy = [pscustomobject]@{ PSTypeName = 'Tenure.Policy'; Hash = ('a' * 64) }
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1') -PolicyHash ('a' * 64)
        Invoke-Apply $plan -With @{ Policy = $policy } | Out-Null
        [object]::ReferenceEquals($seen.Policy, $policy) | Should -BeTrue
        $seen.Mode | Should -Be 'Apply'
        $seen.StepId | Should -Be 'S01'
    }

    It 'reports an unwritable audit path before step 1' {
        $file = Join-Path $TestDrive 'plain-file.txt'
        Set-Content -LiteralPath $file -Value 'x'
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        { Invoke-TenurePlan -Plan $plan -AuditPath (Join-Path $file 'audit.jsonl') -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable'
        $script:log.Count | Should -Be 0
        $plan.Steps[0].Status | Should -Be 'Pending'
    }
}

Describe 'Invoke-TenurePlan destructive and check steps' {
    BeforeEach {
        New-World
        Add-User 'u1'; Add-User 'u2'
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Destroy' -State $script:state -Log $script:log -Overrides @{ Risk = 'Destructive'; Reversible = $false })
    }

    It 'refuses a Destructive step under -Confirm:$false without -AllowDestructive, and stops' {
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1' -Provider 'Fake.Destroy'), (New-DisableStep 'S02' 'u2'))
        $global:ConfirmPreference = 'High'
        try {
            Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false | Out-Null
        } finally {
            $global:ConfirmPreference = 'None'
        }
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Note | Should -Match 'AllowDestructive'
        $script:log.Count | Should -Be 0
        Get-Outcome $script:audit | Should -Be 'PlanStarted,Refused:S01,PlanFinished'
    }

    It 'applies a Destructive step with -AllowDestructive' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Destroy')
        Invoke-Apply $plan -With @{ AllowDestructive = $true } | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
        @($script:log) | Should -Be @('Fake.Destroy:u1')
    }

    It 'treats $ConfirmPreference None as suppressed confirmation too' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Destroy')
        Invoke-TenurePlan -Plan $plan -AuditPath $script:audit | Out-Null
        $plan.Steps[0].Status | Should -Be 'Refused'
        $script:log.Count | Should -Be 0
    }

    It 'uses the provider risk when a plan step claims a lower one' {
        $step = New-DisableStep 'S01' 'u1' -Provider 'Fake.Destroy'
        $step.Risk = 'Low'
        $plan = New-TestPlan -Steps @($step)
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Refused'
        $script:log.Count | Should -Be 0
    }

    It 'stops at a failing Refuse check even with -ContinueOnError' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.CheckRefuse' -State $script:state -Log $script:log -Overrides @{ Kind = 'Check'; Severity = 'Refuse' })
        $script:state['guard'] = @{ ok = $false }
        $plan = New-TestPlan -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.CheckRefuse' -Action 'Check' -Target @{ Kind = 'user'; Id = 'guard'; Name = 'guard' } -Before (Get-TestSnapshot -State $script:state -Id 'guard') -After @{ ok = $true }
            New-DisableStep 'S02' 'u1'
        )
        Invoke-Apply $plan -With @{ ContinueOnError = $true; Force = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Note | Should -Match 'Severity Refuse'
        $plan.Status | Should -Be 'Failed'
        $script:log.Count | Should -Be 0
    }

    It 'skips a failing Warn check with a warning and carries on; a passing check is Skipped' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.CheckWarn' -State $script:state -Log $script:log -Overrides @{ Kind = 'Check'; Severity = 'Warn'; TargetKind = 'mailbox' })
        $script:state['6d000000-0000-4000-8000-0000000000b1'] = @{ small = $false }
        $script:state['6d000000-0000-4000-8000-0000000000b2'] = @{ small = $true }
        $plan = New-TestPlan -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.CheckWarn' -Action 'Check' -Target @{ Kind = 'mailbox'; Id = '6d000000-0000-4000-8000-0000000000b1'; Name = 'mailbox' } -Before (Get-TestSnapshot -State $script:state -Id '6d000000-0000-4000-8000-0000000000b1') -After @{ small = $true } -Reason 'Mailbox is small enough to convert'
            New-TestStep -Id 'S02' -Provider 'Fake.CheckWarn' -Action 'Check' -Target @{ Kind = 'mailbox'; Id = '6d000000-0000-4000-8000-0000000000b2'; Name = 'other' } -Before (Get-TestSnapshot -State $script:state -Id '6d000000-0000-4000-8000-0000000000b2') -After @{ small = $true }
            New-DisableStep 'S03' 'u1'
        )
        $warnings = $null
        Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false -WarningVariable warnings 3>$null | Out-Null
        Get-TestStatus $plan | Should -Be 'Skipped,Skipped,Applied'
        $plan.Steps[0].Result.Note | Should -Match 'Severity Warn'
        $plan.Steps[1].Result.Note | Should -Be 'check passed'
        @($warnings).Count | Should -Be 1
        "$($warnings[0])" | Should -Match 'S01'
        "$($warnings[0])" | Should -Match 'Mailbox is small enough'
    }
}

Describe 'Invoke-TenurePlan subject id substitution' {
    BeforeEach {
        New-World
        $state = $script:state
        $log = $script:log
        $createSet = {
            param($Target, $Desired, $Current, $Context)
            $log.Add("Fake.Create:$($Target.Id)")
            $newId = 'aaaaaaaa-0000-4000-8000-000000000001'
            $record = @{ id = $newId; displayName = $Desired.displayName }
            $state[$newId] = $record
            $state[$Target.Id] = $record
            [pscustomobject]$record.Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Create' -State $script:state -Log $script:log -Overrides @{ Set = $createSet })
        $script:onboard = New-TestPlan -Operation 'Onboard' -Subject @{ Id = $null; UserPrincipalName = 'new.hire@example.com'; DisplayName = 'New Hire' } -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.Create' -Action 'Create' -Target @{ Kind = 'user'; Id = 'new.hire@example.com'; Name = 'new.hire@example.com' } -After @{ displayName = 'New Hire' }
            New-TestStep -Id 'S02' -Action 'Update' -Target @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'new.hire@example.com' } -After @{ department = 'Sales' } -DependsOn 'S01'
        )
    }

    It 'fills {{subjectId}} from the created user and records the subject id' {
        Invoke-Apply $script:onboard | Out-Null
        Get-TestStatus $script:onboard | Should -Be 'Applied,Applied'
        $script:onboard.Subject.Id | Should -Be 'aaaaaaaa-0000-4000-8000-000000000001'
        $script:onboard.Steps[1].Target.Id | Should -Be '{{subjectId}}' -Because 'the plan keeps the placeholder its integrity value covers; each run fills it in from Subject.Id'
        @($script:log) | Should -Be @('Fake.Create:new.hire@example.com', 'Fake.State:aaaaaaaa-0000-4000-8000-000000000001')
        $entry = @(Get-TenureAudit -Path $script:audit | Where-Object StepId -eq 'S02')[0]
        $entry.Target.Id | Should -Be 'aaaaaaaa-0000-4000-8000-000000000001'
    }

    It 'does not change a shared Target hashtable in place' {
        $shared = $script:onboard.Steps[1].Target
        Invoke-Apply $script:onboard | Out-Null
        $shared.Id | Should -Be '{{subjectId}}'
    }

    It 'refuses a step whose target is still a placeholder' {
        $plan = New-TestPlan -Subject @{ Id = $null; UserPrincipalName = 'x@example.com'; DisplayName = 'X' } -Steps @(
            New-TestStep -Id 'S01' -Target @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'x@example.com' } -After @{ department = 'Sales' }
        )
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Refused'
        $plan.Steps[0].Result.Note | Should -Match 'placeholder'
        $script:log.Count | Should -Be 0
    }

    It 'resolves {{subjectId}} inside After after a Create, without changing the shared hashtable' {
        $script:state['g1'] = @{ name = 'Sales' }
        $groupAfter = @{ userId = '{{subjectId}}' }
        $plan = New-TestPlan -Operation 'Onboard' -Subject @{ Id = $null; UserPrincipalName = 'new.hire@example.com'; DisplayName = 'New Hire' } -Steps @(
            $script:onboard.Steps[0]
            New-TestStep -Id 'S02' -Provider 'Fake.Group' -Action 'Update' -Target @{ Kind = 'group'; Id = 'g1'; Name = 'Sales' } -Before (Get-TestSnapshot -State $script:state -Id 'g1') -After $groupAfter -DependsOn 'S01'
        )
        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Applied,Applied'
        $script:state['g1']['userId'] | Should -Be 'aaaaaaaa-0000-4000-8000-000000000001'
        $plan.Steps[1].After.userId | Should -Be '{{subjectId}}' -Because 'the plan keeps the placeholder its integrity value covers'
        $groupAfter.userId | Should -Be '{{subjectId}}'
        $entry = @(Get-TenureAudit -Path $script:audit | Where-Object StepId -eq 'S02')[0]
        $entry.After.userId | Should -Be 'aaaaaaaa-0000-4000-8000-000000000001'
    }

    It 'resolves a placeholder nested two levels deep, in any case and with spaces, and inside arrays' {
        $seen = @{}
        $state = $script:state
        $state['g2'] = @{ name = 'Finance' }
        $assignTest = {
            param($Current, $Desired)
            if ($null -eq $Current -or -not $Current.PSObject.Properties['principal']) { return $false }
            ($Current.principal -eq $Desired.assignment.principal.id) -and ($Current.extra -eq ($Desired.extra -join ','))
        }
        $assignSet = {
            param($Target, $Desired, $Current, $Context)
            $seen.Desired = $Desired
            $state[$Target.Id]['principal'] = $Desired.assignment.principal.id
            $state[$Target.Id]['extra'] = $Desired.extra -join ','
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Assign' -State $script:state -Log $script:log -Overrides @{ Test = $assignTest; Set = $assignSet; TargetKind = 'group' })
        $after = @{ assignment = @{ principal = @{ id = '  {{SubjectID}} ' } }; extra = @('{{subjectId}}', 'keep') }
        $plan = New-TestPlan -Subject @{ Id = 'eeeeeeee-0000-4000-8000-000000000005'; UserPrincipalName = 'e@example.com'; DisplayName = 'E' } -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.Assign' -Action 'Update' -Target @{ Kind = 'group'; Id = 'g2'; Name = 'Finance' } -Before (Get-TestSnapshot -State $script:state -Id 'g2') -After $after
        )
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
        $seen.Desired.assignment.principal.id | Should -Be 'eeeeeeee-0000-4000-8000-000000000005'
        @($seen.Desired.extra) | Should -Be @('eeeeeeee-0000-4000-8000-000000000005', 'keep')
        $after.assignment.principal.id | Should -Be '  {{SubjectID}} '
        @($after.extra)[0] | Should -Be '{{subjectId}}'
    }

    It 'leaves a value that only contains the placeholder text alone' {
        $script:state['g3'] = @{ name = 'Ops' }
        $plan = New-TestPlan -Subject @{ Id = 'ffffffff-0000-4000-8000-000000000006'; UserPrincipalName = 'f@example.com'; DisplayName = 'F' } -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.Group' -Action 'Update' -Target @{ Kind = 'group'; Id = 'g3'; Name = 'Ops' } -Before (Get-TestSnapshot -State $script:state -Id 'g3') -After @{ description = 'created for {{subjectId}}' }
        )
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
        $script:state['g3']['description'] | Should -Be 'created for {{subjectId}}'
    }

    It 'refuses a step whose After still holds the placeholder, and reports it in a dry run' {
        $script:state['g1'] = @{ name = 'Sales' }
        $build = {
            New-TestPlan -Subject @{ Id = $null; UserPrincipalName = 'x@example.com'; DisplayName = 'X' } -Steps @(
                New-TestStep -Id 'S01' -Provider 'Fake.Group' -Action 'Update' -Target @{ Kind = 'group'; Id = 'g1'; Name = 'Sales' } -Before (Get-TestSnapshot -State $script:state -Id 'g1') -After @{ userId = '{{subjectId}}' }
            )
        }
        $plan = & $build
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Refused'
        $plan.Steps[0].Result.Note | Should -Match 'placeholder'
        $script:log.Count | Should -Be 0
        $dry = & $build
        Invoke-Apply $dry -With @{ DryRun = $true } | Out-Null
        $dry.Steps[0].Status | Should -Be 'DryRun'
        $dry.Steps[0].Result.Note | Should -Match 'not checked'
    }

    It 'reports placeholder steps as DryRun without reading them in a dry run' {
        Invoke-Apply $script:onboard -With @{ DryRun = $true } | Out-Null
        Get-TestStatus $script:onboard | Should -Be 'DryRun,DryRun'
        $script:onboard.Steps[1].Result.Note | Should -Match 'not checked'
        $script:onboard.Subject.Id | Should -BeNullOrEmpty
        $script:log.Count | Should -Be 0
    }
}

Describe 'Invoke-TenurePlan NoOp steps' {
    BeforeEach { New-World }

    It 'skips a NoOp step that is still satisfied' {
        Add-User 'u1' @{ accountEnabled = $false }
        $step = New-DisableStep 'S01' 'u1'
        $step.Action = 'NoOp'
        $plan = New-TestPlan -Steps @($step)
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Skipped'
    }

    It 'never calls Set for a NoOp step that is no longer satisfied' {
        Add-User 'u1' @{ accountEnabled = $true }
        $step = New-DisableStep 'S01' 'u1'
        $step.Action = 'NoOp'
        $plan = New-TestPlan -Steps @($step)
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Refused'
        $plan.Steps[0].Result.Note | Should -Match 're-plan'
        $script:log.Count | Should -Be 0
    }
}

Describe 'Invoke-TenurePlan audit path and output file' {
    BeforeEach {
        New-World
        Add-User 'u1'
    }

    It 'uses TENURE_AUDIT_PATH when -AuditPath is not given' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        $result = Invoke-TenurePlan -Plan $plan -Confirm:$false
        $result.AuditPath | Should -Be $script:sentinel
        (Test-TenureAudit -Path $script:sentinel).Entries | Should -Be 3
        Remove-Item -LiteralPath $script:sentinel
    }

    It 'accepts the plan from the pipeline' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        $result = $plan | Invoke-TenurePlan -AuditPath $script:audit -Confirm:$false
        $result.Plan.Steps[0].Status | Should -Be 'Applied'
    }

    It 'writes the updated plan to -OutFile as JSON without secrets' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        $out = Join-Path $TestDrive 'updated-plan.json'
        Invoke-Apply $plan -With @{ OutFile = $out } | Out-Null
        $text = Get-Content -LiteralPath $out -Raw
        $text | Should -Not -Match "`r"
        $parsed = $text | ConvertFrom-Json
        $parsed.PlanId | Should -Be $plan.PlanId
        $parsed.Status | Should -Be 'Applied'
        $parsed.Steps[0].Status | Should -Be 'Applied'
        $parsed.PSObject.Properties.Name | Should -Not -Contain 'Secrets'
        $text | Should -Not -Match 'Secrets'
    }

    It 'does not write -OutFile under -WhatIf' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        $out = Join-Path $TestDrive 'whatif-plan.json'
        Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -OutFile $out -WhatIf | Out-Null
        Test-Path $out | Should -BeFalse
    }

    It 'refuses an -OutFile in a directory that does not exist before doing anything' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        { Invoke-Apply $plan -With @{ OutFile = (Join-Path $TestDrive 'missing' 'plan.json') } } | Should -Throw -ErrorId 'Tenure.Apply.OutFileUnwritable'
        Test-Path $script:audit | Should -BeFalse
        $script:log.Count | Should -Be 0
    }
}

Describe 'Test-TenurePlan' {
    BeforeEach {
        New-World
        Add-User 'u1'; Add-User 'u2'; Add-User 'u3' @{ accountEnabled = $false; department = 'Sales' }
        $script:plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'), (New-DisableStep 'S03' 'u3'))
        $script:state['u1']['department'] = 'Changed'
    }

    It 'classifies drifted, satisfied and pending steps without writing anything' {
        $check = Test-TenurePlan -Plan $script:plan
        $check.PSObject.TypeNames[0] | Should -Be 'Tenure.PlanTestResult'
        @($check.Drifted.Id) | Should -Be @('S01')
        @($check.Pending.Id) | Should -Be @('S02')
        @($check.Satisfied.Id) | Should -Be @('S03')
        $script:log.Count | Should -Be 0
        Get-TestStatus $script:plan | Should -Be 'Pending,Pending,Pending'
        Test-Path $script:sentinel | Should -BeFalse
        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.jsonl').Count | Should -Be 0
    }

    It 'reports an Invoke step that only the plan file calls applied as Unverified, and a Create of a missing target as pending' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Invoke' -State $script:state -Log $script:log -Overrides @{ Kind = 'Invoke'; Test = { param($Current, $Desired) $false } })
        $plan = New-TestPlan -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.Invoke' -Action 'Invoke' -Target @{ Kind = 'user'; Id = 'u2'; Name = 'u2' } -Before (Get-TestSnapshot -State $script:state -Id 'u2') -After @{} -Status 'Applied'
            New-TestStep -Id 'S02' -Action 'Create' -Target @{ Kind = 'user'; Id = 'nobody'; Name = 'nobody' } -After @{ accountEnabled = $true }
        )
        $check = Test-TenurePlan $plan
        @($check.Unverified.Id) | Should -Be @('S01') -Because 'Test-TenurePlan does not read the audit log, so the file is its only evidence'
        $check.Satisfied.Count | Should -Be 0
        @($check.Pending.Id) | Should -Be @('S02')
        $check.Drifted.Count | Should -Be 0
    }

    It 'warns and counts a step as pending when its state cannot be read' {
        $plan = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Target @{ Kind = 'user'; Id = 'ghost'; Name = 'ghost' } -Before ([pscustomobject]@{ accountEnabled = $true }) -After @{ accountEnabled = $false })
        $warnings = $null
        $check = Test-TenurePlan $plan -WarningVariable warnings 3>$null
        @($check.Pending.Id) | Should -Be @('S01')
        @($warnings).Count | Should -Be 1
    }
}

Describe 'Engine and audit helpers' {
    It 'are defined by Apply.ps1 and Audit.ps1 and not shadowed by a file loaded later' {
        foreach ($file in 'Apply.ps1', 'Audit.ps1') {
            $path = Join-Path $script:TenureSourceRoot 'Private' 'Core' $file
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
            $names = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Name })
            $names.Count | Should -BeGreaterThan 5
            foreach ($name in $names) {
                $definedIn = Invoke-InTenure { param($n) (Get-Item -LiteralPath "function:$n").ScriptBlock.File } @($name)
                $definedIn | Should -Be $path -Because "$name must not be redefined by another source file"
            }
        }
    }
}

Describe 'Refuse checks fail closed' {
    BeforeEach {
        New-World
        Add-User 'u1'
        $script:state['guard'] = @{ ok = $true }
    }

    It 'refuses and stops when the check cannot read its state, even with -ContinueOnError and -Force' {
        $get = { param($Target, $Context) throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('directory unavailable'), 'Tenure.Graph.Failed', 'NotSpecified', $null) }
        Register-TestProvider (New-RecordingProvider -Name 'Fake.CheckRefuse' -State $script:state -Log $script:log -Overrides @{ Kind = 'Check'; Severity = 'Refuse'; Get = $get })
        $plan = New-TestPlan -Steps @((New-CheckStep 'S01' 'Fake.CheckRefuse'), (New-DisableStep 'S02' 'u1'))
        Invoke-Apply $plan -With @{ ContinueOnError = $true; Force = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Error | Should -Match 'directory unavailable'
        $plan.Steps[0].Result.Note | Should -Match 'fails closed'
        $script:log.Count | Should -Be 0
    }

    It 'refuses and stops when the checked target is gone' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.CheckRefuse' -State $script:state -Log $script:log -Overrides @{ Kind = 'Check'; Severity = 'Refuse' })
        $plan = New-TestPlan -Steps @((New-CheckStep 'S01' 'Fake.CheckRefuse'), (New-DisableStep 'S02' 'u1'))
        $script:state.Remove('guard')
        Invoke-Apply $plan -With @{ ContinueOnError = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Error | Should -Match 'TargetNotFound'
    }

    It 'refuses and stops when the checked state drifted, even with -Force' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.CheckRefuse' -State $script:state -Log $script:log -Overrides @{ Kind = 'Check'; Severity = 'Refuse' })
        $plan = New-TestPlan -Steps @((New-CheckStep 'S01' 'Fake.CheckRefuse'), (New-DisableStep 'S02' 'u1'))
        $script:state['guard']['note'] = 'changed after planning'
        Invoke-Apply $plan -With @{ ContinueOnError = $true; Force = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Note | Should -Match 'drift'
        $script:log.Count | Should -Be 0
    }

    It 'refuses and stops when the check Test throws' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.CheckRefuse' -State $script:state -Log $script:log -Overrides @{ Kind = 'Check'; Severity = 'Refuse'; Test = { param($Current, $Desired) throw 'check logic broke' } })
        $plan = New-TestPlan -Steps @((New-CheckStep 'S01' 'Fake.CheckRefuse'), (New-DisableStep 'S02' 'u1'))
        Invoke-Apply $plan -With @{ ContinueOnError = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Error | Should -Match 'check logic broke'
    }

    It 'refuses and stops when the check could not run because its dependency failed' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.CheckRefuse' -State $script:state -Log $script:log -Overrides @{ Kind = 'Check'; Severity = 'Refuse' })
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Boom' -State $script:state -Log $script:log -Overrides @{ Set = { param($Target, $Desired, $Current, $Context) throw 'nope' } })
        Add-User 'u2'
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u2' -Provider 'Fake.Boom'), (New-CheckStep 'S02' 'Fake.CheckRefuse' -DependsOn 'S01'), (New-DisableStep 'S03' 'u1'))
        Invoke-Apply $plan -With @{ ContinueOnError = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Failed,Refused,Pending'
        $script:log.Count | Should -Be 0
    }

    It 'still lets -ContinueOnError carry on past a Warn check that cannot read its state' {
        $get = { param($Target, $Context) throw 'directory unavailable' }
        Register-TestProvider (New-RecordingProvider -Name 'Fake.CheckWarn' -State $script:state -Log $script:log -Overrides @{ Kind = 'Check'; Severity = 'Warn'; Get = $get })
        $plan = New-TestPlan -Steps @((New-CheckStep 'S01' 'Fake.CheckWarn'), (New-DisableStep 'S02' 'u1'))
        Invoke-Apply $plan -With @{ ContinueOnError = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Failed,Applied'
    }
}

Describe 'Write-ahead audit entries, plan file progress and resume guards' {
    BeforeEach {
        New-World
        Add-User 'u1'; Add-User 'u2'; Add-User 'u3'
        $script:fires = @{ Count = 0 }
        $fires = $script:fires
        $invokeSet = { param($Target, $Desired, $Current, $Context) $fires.Count++; [pscustomobject]@{ revoked = $true } }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Invoke' -State $script:state -Log $script:log -Overrides @{ Kind = 'Invoke'; Set = $invokeSet; Test = { param($Current, $Desired) $false } })
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Destroy' -State $script:state -Log $script:log -Overrides @{ Risk = 'Destructive'; Reversible = $false })
    }

    It 'writes an Attempting entry before Set for Invoke, Create and Destructive steps only (a)' {
        $plan = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2' -Provider 'Fake.Destroy'), (New-DisableStep 'S03' 'u3'))
        Invoke-Apply $plan -With @{ AllowDestructive = $true } | Out-Null
        Get-Outcome $script:audit | Should -Be 'PlanStarted,Attempting:S01,Applied:S01,Attempting:S02,Applied:S02,Applied:S03,PlanFinished'
        (Test-TenureAudit -Path $script:audit).Valid | Should -BeTrue
    }

    It 'never calls Set when the write-ahead entry cannot be written (a)' -Skip:((-not $IsWindows) -and ((& id -u) -eq '0')) {
        $audit = $script:audit
        $state = $script:state
        $fires = $script:fires
        $lockingGet = { param($Target, $Context) (Get-Item -LiteralPath $audit).IsReadOnly = $true; [pscustomobject]$state[$Target.Id].Clone() }.GetNewClosure()
        $invokeSet = { param($Target, $Desired, $Current, $Context) $fires.Count++; [pscustomobject]@{ revoked = $true } }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Invoke' -State $script:state -Log $script:log -Overrides @{ Kind = 'Invoke'; Set = $invokeSet; Get = $lockingGet; Test = { param($Current, $Desired) $false } })
        $plan = New-TestPlan -Steps @(New-InvokeStep 'S01' 'u1')
        try {
            { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable'
        } finally {
            (Get-Item -LiteralPath $audit).IsReadOnly = $false
        }
        $script:fires.Count | Should -Be 0
        $plan.Steps[0].Status | Should -Be 'Pending'
    }

    It 'rewrites the plan file after every status change, with Attempted set before Set runs (b)' {
        $planFile = Join-Path $TestDrive 'progress.json'
        $seen = @{}
        $state = $script:state
        $watchSet = {
            param($Target, $Desired, $Current, $Context)
            $file = Get-Content -LiteralPath $planFile -Raw | ConvertFrom-Json
            $seen.S01 = $file.Steps[0].Status
            $seen.S02Attempted = $file.Steps[1].Result.Attempted
            foreach ($key in $Desired.Keys) { $state[$Target.Id][$key] = $Desired[$key] }
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Watch' -State $script:state -Log $script:log -Overrides @{ Set = $watchSet })
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2' -Provider 'Fake.Watch'))
        Invoke-Apply $plan -With @{ OutFile = $planFile } | Out-Null
        $seen.S01 | Should -Be 'Applied'
        $seen.S02Attempted | Should -BeTrue
        $saved = Import-TenurePlan -Path $planFile
        Get-TestStatus $saved | Should -Be 'Applied,Applied'
        $saved.Status | Should -Be 'Applied'
        { Invoke-TenurePlan -Plan $planFile -AuditPath $script:audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.AlreadyApplied'
    }

    It 'defaults -OutFile to the plan path, and leaves the file alone under -WhatIf (b)' {
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        $planFile = Join-Path $TestDrive 'from-file.json'
        Export-TenurePlan -Plan $plan -Path $planFile
        $original = [System.IO.File]::ReadAllBytes($planFile)
        Invoke-TenurePlan -Plan $planFile -AuditPath $script:audit -WhatIf | Out-Null
        [System.IO.File]::ReadAllBytes($planFile) | Should -Be $original
        Invoke-TenurePlan -Plan $planFile -AuditPath $script:audit -Confirm:$false | Out-Null
        Get-TestStatus (Import-TenurePlan -Path $planFile) | Should -Be 'Applied,Applied'
    }

    It 'skips an Invoke step the audit log shows as fired, even when the plan says Pending (c)' {
        $plan = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        Invoke-Apply $plan | Out-Null
        $script:fires.Count | Should -Be 1
        $stale = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        $stale.PlanId = $plan.PlanId
        Update-TestPlanIntegrity $stale
        # The audit log shows the plan finished Applied; without -Force the copy is refused outright.
        { Invoke-Apply $stale } | Should -Throw -ErrorId 'Tenure.Plan.AlreadyApplied'
        Invoke-Apply $stale -With @{ Force = $true } | Out-Null
        $stale.Steps[0].Status | Should -Be 'Skipped'
        $stale.Steps[0].Result.Note | Should -Match 'already fired per audit log'
        $script:fires.Count | Should -Be 1
    }

    It 'stops at an Invoke step with an Attempting entry and no outcome; -Resume does not fire one that is not Repeatable (c)' {
        $plan = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Provider = 'Fake.Invoke'; Outcome = 'Attempting' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanFinished' } $script:audit | Out-Null
        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Note | Should -Match '-AssumeFired S01'
        $script:fires.Count | Should -Be 0

        Invoke-Apply $plan -With @{ Resume = $true; ContinueOnError = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending' -Because 'a step that is not Repeatable is never fired again on a guess, and the run stops there even with -ContinueOnError'
        $plan.Steps[0].Result.Error | Should -Match 'Tenure.Apply.Uncertain'
        $script:fires.Count | Should -Be 0
    }

    It '-AssumeFired records a step in doubt as fired, audits that, and the plan never ends Applied (c)' {
        $plan = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Provider = 'Fake.Invoke'; Outcome = 'Attempting' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanFinished' } $script:audit | Out-Null
        Invoke-Apply $plan -With @{ AssumeFired = @('S01') } | Out-Null
        Get-TestStatus $plan | Should -Be 'Skipped,Applied'
        $plan.Steps[0].Result.Assumed | Should -BeTrue
        $plan.Steps[0].Result.Note | Should -Match 'assumed fired'
        $plan.Status | Should -Be 'PartiallyApplied' -Because 'nothing shows the assumed step did its work'
        $script:fires.Count | Should -Be 0
        $started = @(Get-TenureAudit -Path $script:audit | Where-Object Outcome -eq 'PlanStarted')[-1]
        @($started.Observed.Options.AssumeFired) | Should -Be @('S01')
        $entry = @(Get-TenureAudit -Path $script:audit | Where-Object { $_.StepId -eq 'S01' -and $_.Outcome -eq 'Skipped' })[0]
        $entry.Note | Should -Match '-AssumeFired'

        Invoke-Apply $plan | Out-Null
        $plan.Status | Should -Be 'PartiallyApplied' -Because 'Result.Assumed is sticky'
    }

    It '-AssumeFired refuses a step that is not in doubt, and an id that is not an Invoke step of the plan (c)' {
        $plan = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        { Invoke-Apply $plan -With @{ AssumeFired = @('S02') } } | Should -Throw -ErrorId 'Tenure.Apply.InvalidArgument'
        { Invoke-Apply $plan -With @{ AssumeFired = @('S09') } } | Should -Throw -ErrorId 'Tenure.Apply.InvalidArgument'
        Test-Path $script:audit | Should -BeFalse
        Invoke-Apply $plan -With @{ AssumeFired = @('S01'); ContinueOnError = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Error | Should -Match 'Tenure.Apply.InvalidArgument'
        $script:fires.Count | Should -Be 0
    }

    It 'fires a Repeatable Invoke step in doubt again under -Resume, and only then (c)' {
        $fires = $script:fires
        $repeatSet = { param($Target, $Desired, $Current, $Context) $fires.Count++; [pscustomobject]@{ revoked = $true } }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Invoke' -State $script:state -Log $script:log -Overrides @{ Kind = 'Invoke'; Repeatable = $true; Set = $repeatSet; Test = { param($Current, $Desired) $false } })
        $plan = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Provider = 'Fake.Invoke'; Outcome = 'Attempting' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanFinished' } $script:audit | Out-Null
        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Refused,Pending'
        $plan.Steps[0].Result.Note | Should -Match 'safe to repeat: pass -Resume'
        $script:fires.Count | Should -Be 0

        Invoke-Apply $plan -With @{ Resume = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Applied,Applied'
        $plan.Steps[0].Result.Note | Should -Match 'Repeatable, so it runs again'
        $plan.Status | Should -Be 'Applied'
        $script:fires.Count | Should -Be 1
    }

    It 'stops at an Invoke step recorded as interrupted; -Resume alone does not fire one that is not Repeatable (c)' {
        $plan = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2')) -Status 'Failed'
        $plan.Steps[0].Status = 'Failed'
        $plan.Steps[0].Result = @{ At = [datetime]::UtcNow.ToString('o'); DurationMs = 5; Observed = $null; Error = 'Tenure.Apply.Interrupted: the run stopped while Set was in progress; check the target before resuming.'; Note = 'interrupted during Set'; Attempted = $true }
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Refused'
        $script:fires.Count | Should -Be 0
        Invoke-Apply $plan -With @{ Resume = $true } | Out-Null
        $plan.Steps[0].Status | Should -Be 'Refused'
        Invoke-Apply $plan -With @{ AssumeFired = @('S01') } | Out-Null
        $plan.Steps[0].Status | Should -Be 'Skipped'
        $script:fires.Count | Should -Be 0
    }

    It 'refuses an Invoke step whose Set was attempted with no recorded outcome in the plan file (c)' {
        $plan = New-TestPlan -Steps @(New-InvokeStep 'S01' 'u1')
        $plan.Steps[0].Result = @{ At = [datetime]::UtcNow.ToString('o'); DurationMs = $null; Observed = $null; Error = $null; Note = 'Set in progress'; Attempted = $true }
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Refused'
        $script:fires.Count | Should -Be 0
    }

    It 'fires an Invoke step again when its earlier attempt failed with a known error (c)' {
        $plan = New-TestPlan -Steps @(New-InvokeStep 'S01' 'u1') -Status 'Failed'
        $plan.Steps[0].Status = 'Failed'
        $plan.Steps[0].Result = @{ At = [datetime]::UtcNow.ToString('o'); DurationMs = 5; Observed = $null; Error = 'Tenure.Graph.Failed: Graph said no'; Note = 'Set failed'; Attempted = $true }
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Outcome = 'Attempting' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; StepId = 'S01'; Outcome = 'Failed'; Error = 'Tenure.Graph.Failed: Graph said no' } $script:audit | Out-Null
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanFinished' } $script:audit | Out-Null
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
        $script:fires.Count | Should -Be 1
    }

    It 'refuses to start while an earlier run of the same plan is open, unless -Resume (d)' {
        $plan = New-TestPlan -Steps @((New-InvokeStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        Write-TestAudit @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted' } $script:audit | Out-Null
        { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Plan.RunInProgress'
        $script:fires.Count | Should -Be 0
        (Test-TenureAudit -Path $script:audit).Entries | Should -Be 1
        Invoke-Apply $plan -With @{ Resume = $true } | Out-Null
        Get-TestStatus $plan | Should -Be 'Applied,Applied'
        $script:fires.Count | Should -Be 1
    }

    It 'refuses a second run of the same plan started while the first is still running (d)' {
        $seen = @{ Error = $null }
        $state = $script:state
        $audit = $script:audit
        $second = New-TestPlan -Steps @(New-DisableStep 'S01' 'u3')
        $nestedSet = {
            param($Target, $Desired, $Current, $Context)
            try {
                Invoke-TenurePlan -Plan $second -AuditPath $audit -Confirm:$false | Out-Null
                $seen.Error = 'none'
            } catch {
                $seen.Error = $_.FullyQualifiedErrorId
            }
            foreach ($key in $Desired.Keys) { $state[$Target.Id][$key] = $Desired[$key] }
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Nested' -State $script:state -Log $script:log -Overrides @{ Set = $nestedSet })
        $first = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Nested')
        $second.PlanId = $first.PlanId
        Update-TestPlanIntegrity $second
        Invoke-Apply $first | Out-Null
        $first.Steps[0].Status | Should -Be 'Applied'
        $seen.Error | Should -BeLike 'Tenure.Plan.RunInProgress*'
        $script:state['u3']['accountEnabled'] | Should -BeTrue
    }
}

Describe 'Destructive steps get their own confirmation' {
    BeforeEach {
        New-World
        Add-User 'u1'; Add-User 'u2'
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Destroy' -State $script:state -Log $script:log -Overrides @{ Risk = 'Destructive'; Reversible = $false })
        $script:plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2' -Provider 'Fake.Destroy'))
    }

    It 'asks ShouldContinue for a Destructive step even when ShouldProcess says yes to everything' {
        $cmdlet = New-TestCmdlet
        Invoke-TestCore -Plan $script:plan -Cmdlet $cmdlet -AuditPath $script:audit | Out-Null
        Get-TestStatus $script:plan | Should -Be 'Applied,Applied'
        $asked = @($cmdlet.Calls | Where-Object { $_ -like 'ShouldContinue:*' })
        $asked.Count | Should -Be 1
        $asked[0] | Should -Match 'S02'
    }

    It 'refuses the step, naming -AllowDestructive, when the host cannot prompt' {
        $cmdlet = New-TestCmdlet -ShouldContinue { param($query, $caption) throw [System.Management.Automation.Host.HostException]::new('PowerShell is in NonInteractive mode. Read and Prompt functionality is not available.') }
        Invoke-TestCore -Plan $script:plan -Cmdlet $cmdlet -AuditPath $script:audit | Out-Null
        Get-TestStatus $script:plan | Should -Be 'Applied,Refused'
        $script:plan.Steps[1].Result.Note | Should -Match '-AllowDestructive'
        @($script:log) | Should -Be @('Fake.State:u1')
        Get-Outcome $script:audit | Should -Be 'PlanStarted,Applied:S01,Refused:S02,PlanFinished'
    }

    It 'records the step Declined, and leaves it unaudited, when the operator answers No' {
        $cmdlet = New-TestCmdlet -ShouldContinue { param($query, $caption) $false }
        Invoke-TestCore -Plan $script:plan -Cmdlet $cmdlet -AuditPath $script:audit | Out-Null
        Get-TestStatus $script:plan | Should -Be 'Applied,Declined'
        $script:plan.Status | Should -Be 'PartiallyApplied'
        @($script:log) | Should -Be @('Fake.State:u1')
        Get-Outcome $script:audit | Should -Be 'PlanStarted,Applied:S01,PlanFinished'
    }

    It 'does not ask again when -AllowDestructive is given' {
        $cmdlet = New-TestCmdlet
        Invoke-TestCore -Plan $script:plan -Cmdlet $cmdlet -AuditPath $script:audit -With @{ AllowDestructive = $true } | Out-Null
        Get-TestStatus $script:plan | Should -Be 'Applied,Applied'
        @($cmdlet.Calls | Where-Object { $_ -like 'ShouldContinue:*' }).Count | Should -Be 0
    }
}

Describe 'Resume after a Set that landed but was recorded Failed' {
    BeforeEach {
        New-World
        Add-User 'u1'; Add-User 'u2'
    }

    It 're-tests a Failed State step against After before the drift check (a)' {
        $counter = @{ Get = 0 }
        $state = $script:state
        $get = {
            param($Target, $Context)
            $counter.Get++
            if ($counter.Get -eq 2) { throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('replication lag'), 'Tenure.Graph.NotFound', 'ObjectNotFound', $null) }
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Reread' -State $script:state -Log $script:log -Overrides @{ Get = $get })
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Reread')
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Attempted | Should -BeTrue
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Skipped'
        $plan.Steps[0].Result.Note | Should -Match 'satisfied by an earlier run'
        $plan.Status | Should -Be 'Applied'
        $script:log.Count | Should -Be 1
    }

    It 'adopts the id of a user created by an earlier attempt that was recorded Failed (b)' {
        $state = $script:state
        $log = $script:log
        $createSet = {
            param($Target, $Desired, $Current, $Context)
            $log.Add("Fake.Create:$($Target.Id)")
            # Like Graph, the account says when it was created: during this attempt.
            $record = @{ id = 'cccccccc-0000-4000-8000-000000000003'; displayName = $Desired.displayName; createdDateTime = [datetime]::UtcNow.ToString('o') }
            $state['cccccccc-0000-4000-8000-000000000003'] = $record
            $state[$Target.Id] = $record
            throw 'gateway timeout after the user was created'
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Create' -State $script:state -Log $script:log -Overrides @{ Set = $createSet })
        $plan = New-TestPlan -Operation 'Onboard' -Subject @{ Id = $null; UserPrincipalName = 'late@example.com'; DisplayName = 'Late' } -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.Create' -Action 'Create' -Target @{ Kind = 'user'; Id = 'late@example.com'; Name = 'late@example.com' } -After @{ displayName = 'Late' }
            New-TestStep -Id 'S02' -Action 'Update' -Target @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'late@example.com' } -After @{ department = 'Sales' } -DependsOn 'S01'
        )
        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Failed,Pending'
        $plan.Steps[0].Result.Attempted | Should -BeTrue
        $plan.Subject.Id | Should -BeNullOrEmpty

        Invoke-Apply $plan | Out-Null
        Get-TestStatus $plan | Should -Be 'Skipped,Applied'
        $plan.Steps[0].Result.Note | Should -Match 'earlier attempt'
        $plan.Subject.Id | Should -Be 'cccccccc-0000-4000-8000-000000000003'
        @($script:log | Where-Object { $_ -like 'Fake.Create:*' }).Count | Should -Be 1
    }

    It 'never adopts an account that existed before the plan ran (b)' {
        $script:state['taken@example.com'] = @{ id = 'dddddddd-0000-4000-8000-000000000004'; displayName = 'Taken' }
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Create' -State $script:state -Log $script:log)
        $plan = New-TestPlan -Operation 'Onboard' -Subject @{ Id = $null; UserPrincipalName = 'taken@example.com'; DisplayName = 'Taken' } -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.Create' -Action 'Create' -Target @{ Kind = 'user'; Id = 'taken@example.com'; Name = 'taken@example.com' } -After @{ displayName = 'Taken' }
            New-TestStep -Id 'S02' -Action 'Update' -Target @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'taken@example.com' } -After @{ department = 'Sales' } -DependsOn 'S01'
        )
        Invoke-Apply $plan -With @{ Force = $true } | Out-Null
        $plan.Subject.Id | Should -BeNullOrEmpty
        Get-TestStatus $plan | Should -Be 'Drifted,Pending' -Because 'the create step bound its target as absent; an account that exists and that this plan never tried to create is drift, even with -Force'
        $plan.Steps[0].Result.Note | Should -Match 'Force does not override'
        $script:log.Count | Should -Be 0
    }

    It 'sets Result.Attempted only when Set was called' {
        Add-User 'u3' @{ accountEnabled = $false; department = 'Sales' }
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u3'))
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Result.Attempted | Should -BeTrue
        $plan.Steps[1].Result.Attempted | Should -BeFalse
    }
}

Describe 'Plan step fingerprints and apply result details' {
    BeforeEach {
        New-World
        Add-User 'u1'
    }

    It 'refuses an empty fingerprint on every step, a Create and a {{subjectId}} step included' {
        $cases = @(
            @{ Name = 'update'; Step = (New-TestStep -Id 'S01' -Action 'Update' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -Before (Get-TestSnapshot -State $script:state -Id 'u1') -After @{ accountEnabled = $false } -Fingerprint '') }
            @{ Name = 'create'; Step = (New-TestStep -Id 'S01' -Action 'Create' -Target @{ Kind = 'user'; Id = 'u9'; Name = 'u9' } -After @{ accountEnabled = $true } -Fingerprint '') }
            @{ Name = 'placeholder'; Step = (New-TestStep -Id 'S01' -Action 'Update' -Target @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'u1' } -After @{ department = 'Ops' } -Fingerprint '') }
        )
        foreach ($case in $cases) {
            $plan = New-TestPlan -Subject @{ Id = 'u1'; UserPrincipalName = 'u1@example.com'; DisplayName = 'U1' } -Steps @($case.Step)
            { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -Because "a $($case.Name) step without a fingerprint would apply without any binding to its target"
        }
        Test-Path $script:audit | Should -BeFalse
        $script:log.Count | Should -Be 0
    }

    It 'refuses a step without a snapshot unless it is a Create or acts on the {{subjectId}} placeholder' {
        $update = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Action 'Update' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -After @{ accountEnabled = $false })
        { Invoke-Apply $update } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        $check = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Action 'Check' -Kind 'State' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -After @{ accountEnabled = $false })
        { Invoke-Apply $check } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        Test-Path $script:audit | Should -BeFalse

        $create = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Action 'Create' -Target @{ Kind = 'user'; Id = 'u9'; Name = 'u9' } -After @{ accountEnabled = $true })
        Invoke-Apply $create | Out-Null
        $create.Steps[0].Status | Should -Be 'Applied'
        $placeholder = New-TestPlan -Subject @{ Id = 'u1'; UserPrincipalName = 'u1@example.com'; DisplayName = 'U1' } -Steps @(New-TestStep -Id 'S01' -Action 'Update' -Target @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'u1' } -After @{ department = 'Ops' })
        Invoke-Apply $placeholder | Out-Null
        $placeholder.Steps[0].Status | Should -Be 'Applied'
    }

    It 'a Create step drifts, even with -Force, when its target exists and this plan never attempted it' {
        Add-User 'u9' @{ accountEnabled = $true }
        $create = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Action 'Create' -Target @{ Kind = 'user'; Id = 'u9'; Name = 'u9' } -After @{ accountEnabled = $false })
        Invoke-Apply $create -With @{ Force = $true } | Out-Null
        $create.Steps[0].Status | Should -Be 'Drifted'
        $script:log.Count | Should -Be 0
    }

    It 'returns AuditHead, the Seq and Hash of the last entry written' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        $result = Invoke-Apply $plan
        $last = @(Get-TenureAudit -Path $script:audit)[-1]
        $result.AuditHead.Seq | Should -Be $last.Seq
        $result.AuditHead.Hash | Should -Be $last.Hash
        $whatIf = Invoke-TenurePlan -Plan (New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')) -AuditPath $script:audit -WhatIf
        $whatIf.AuditHead | Should -BeNullOrEmpty
    }

    It 'keeps the last result of the session for Get-TenureApplyResult' {
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        $result = Invoke-Apply $plan
        [object]::ReferenceEquals((Get-TenureApplyResult), $result) | Should -BeTrue
        Invoke-TenurePlan -Plan (New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')) -AuditPath $script:audit -WhatIf | Out-Null
        [object]::ReferenceEquals((Get-TenureApplyResult), $result) | Should -BeTrue -Because 'a -WhatIf run must not replace a result that may hold secrets'
    }
}

Describe 'Fingerprints bind the target' {
    BeforeEach {
        New-World
        Add-User 'u1'; Add-User 'u2'
    }

    It 'reports a step retargeted in the plan file as Drifted and applies nothing' {
        $step = New-DisableStep 'S01' 'u1'
        $step.Target = @{ Kind = 'user'; Id = 'u2'; Name = 'u1' }
        $plan = New-TestPlan -Steps @($step)
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Drifted' -Because 'u2 has the same state as u1, so only a target-bound fingerprint can tell them apart'
        $script:log.Count | Should -Be 0
        $script:state['u1']['accountEnabled'] | Should -BeTrue
        $script:state['u2']['accountEnabled'] | Should -BeTrue
        @((Test-TenurePlan -Plan $plan).Drifted.Id) | Should -Be @('S01')
    }
}

Describe 'Subject binding at preflight' {
    BeforeEach {
        New-World
        $script:subjectId = '99999999-0000-4000-8000-000000000009'
        Add-User $script:subjectId
        Add-User 'someone-else'
        $script:state['role1'] = @{ name = 'Helpdesk' }
        $script:subject = @{ Id = $script:subjectId; UserPrincipalName = 'leaver@example.com'; DisplayName = 'Leaver' }
    }

    It 'rejects a <_> plan whose user, mailbox or drive step targets someone else, even with -Force' -ForEach @('Offboard', 'RoleChange') {
        foreach ($kind in 'user', 'mailbox', 'drive') {
            $plan = New-TestPlan -Operation $_ -Subject $script:subject -Steps @(
                New-TestStep -Id 'S01' -Target @{ Kind = 'user'; Id = $script:subjectId; Name = 'leaver' } -Before (Get-TestSnapshot -State $script:state -Id $script:subjectId) -After @{ accountEnabled = $false }
                New-TestStep -Id 'S02' -Target @{ Kind = $kind; Id = 'someone-else'; Name = 'other' } -Before (Get-TestSnapshot -State $script:state -Id 'someone-else') -After @{ accountEnabled = $false }
            )
            $failure = { Invoke-Apply $plan -With @{ Force = $true } } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -PassThru
            $failure.Exception.Message | Should -Match 'S02'
        }
        $script:log.Count | Should -Be 0
        Test-Path $script:audit | Should -BeFalse
    }

    It 'rejects a step whose After.userId names someone other than the subject' {
        $plan = New-TestPlan -Operation 'Offboard' -Subject $script:subject -Steps @(
            New-TestStep -Id 'S01' -Provider 'Fake.RoleMember' -Target @{ Kind = 'role'; Id = 'role1'; Name = 'Helpdesk' } -Before (Get-TestSnapshot -State $script:state -Id 'role1') -After @{ userId = 'someone-else'; member = $false }
        )
        { Invoke-Apply $plan } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        { Test-TenurePlan -Plan $plan } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
    }

    It 'accepts the subject id in any case, the placeholder, and the UPN on an Onboard plan' {
        $plan = New-TestPlan -Operation 'Offboard' -Subject $script:subject -Steps @(
            New-TestStep -Id 'S01' -Target @{ Kind = 'user'; Id = $script:subjectId.ToUpperInvariant(); Name = 'leaver' } -Before (Get-TestSnapshot -State $script:state -Id $script:subjectId) -After @{ accountEnabled = $false }
            New-TestStep -Id 'S02' -Provider 'Fake.RoleMember' -Target @{ Kind = 'role'; Id = 'role1'; Name = 'Helpdesk' } -Before (Get-TestSnapshot -State $script:state -Id 'role1') -After @{ userId = $script:subjectId; member = $false }
        )
        { Invoke-InTenure { param($p) Assert-TenurePlanShape -Plan $p } @($plan) } | Should -Not -Throw
        $onboard = New-TestPlan -Operation 'Onboard' -Subject @{ Id = $null; UserPrincipalName = 'new@example.com'; DisplayName = 'New' } -Steps @(
            New-TestStep -Id 'S01' -Action 'Create' -Target @{ Kind = 'user'; Id = 'new@example.com'; Name = 'new@example.com' } -After @{ accountEnabled = $true }
            New-TestStep -Id 'S02' -Action 'Update' -Target @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'new@example.com' } -After @{ department = 'Sales' } -DependsOn 'S01'
            New-TestStep -Id 'S03' -Provider 'Fake.RoleMember' -Target @{ Kind = 'role'; Id = 'role1'; Name = 'Helpdesk' } -Before (Get-TestSnapshot -State $script:state -Id 'role1') -After @{ userId = '{{subjectId}}'; member = $true } -DependsOn 'S01'
        )
        { Invoke-InTenure { param($p) Assert-TenurePlanShape -Plan $p } @($onboard) } | Should -Not -Throw
        $offboardByUpn = New-TestPlan -Operation 'Offboard' -Subject $script:subject -Steps @(
            New-TestStep -Id 'S01' -Target @{ Kind = 'user'; Id = 'leaver@example.com'; Name = 'leaver' } -Before (Get-TestSnapshot -State $script:state -Id $script:subjectId) -After @{ accountEnabled = $false }
        )
        { Invoke-InTenure { param($p) Assert-TenurePlanShape -Plan $p } @($offboardByUpn) } | Should -Throw -ErrorId 'Tenure.Plan.Invalid' -Because 'only an Onboard plan, whose subject has no id yet, may name the subject by UPN'
    }

    It 'leaves Custom plans unbound' {
        $plan = New-TestPlan -Operation 'Custom' -Subject $script:subject -Steps @(
            New-TestStep -Id 'S01' -Target @{ Kind = 'user'; Id = 'someone-else'; Name = 'other' } -Before (Get-TestSnapshot -State $script:state -Id 'someone-else') -After @{ accountEnabled = $false }
        )
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
    }
}

Describe 'Create read-back under replication lag' {
    BeforeEach {
        New-World
        $script:sleeps = [System.Collections.Generic.List[int]]::new()
        Mock -ModuleName Tenure Start-Sleep { if ($PesterBoundParameters.ContainsKey('Seconds')) { $script:sleeps.Add([int]$Seconds) } }
        $script:lag = @{ Misses = 0; Seen = 0; ReturnId = $true }
        $state = $script:state
        $lag = $script:lag
        $get = {
            param($Target, $Context)
            if ($state.ContainsKey($Target.Id) -and $lag.Seen -ge $lag.Misses) { return [pscustomobject]$state[$Target.Id].Clone() }
            if ($state.ContainsKey($Target.Id)) { $lag.Seen++ }
            throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new("No fake target '$($Target.Id)'."), 'Tenure.Provider.TargetNotFound', 'ObjectNotFound', $Target)
        }.GetNewClosure()
        $set = {
            param($Target, $Desired, $Current, $Context)
            $record = @{ id = '77777777-0000-4000-8000-000000000007'; displayName = $Desired.displayName }
            $state[$Target.Id] = $record
            if ($lag.ReturnId) { return [pscustomobject]$record.Clone() }
            [pscustomobject]@{ displayName = $Desired.displayName }
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Laggy' -State $script:state -Log $script:log -Overrides @{ Get = $get; Set = $set })
        $script:newPlan = {
            New-TestPlan -Operation 'Onboard' -Subject @{ Id = $null; UserPrincipalName = 'lag@example.com'; DisplayName = 'Lag' } -Steps @(
                New-TestStep -Id 'S01' -Provider 'Fake.Laggy' -Action 'Create' -Target @{ Kind = 'user'; Id = 'lag@example.com'; Name = 'lag@example.com' } -After @{ displayName = 'Lag' }
            )
        }
    }

    It 'retries the read-back after 2 and 4 seconds and then succeeds' {
        $script:lag.Misses = 2
        $plan = & $script:newPlan
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
        @($script:sleeps) | Should -Be @(2, 4)
        $plan.Subject.Id | Should -Be '77777777-0000-4000-8000-000000000007'
    }

    It 'falls back to the object Set returned, with its id, after 2, 4 and 8 seconds' {
        $script:lag.Misses = 99
        $plan = & $script:newPlan
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
        @($script:sleeps) | Should -Be @(2, 4, 8)
        $plan.Steps[0].Result.Note | Should -Match 'Set returned'
        $plan.Subject.Id | Should -Be '77777777-0000-4000-8000-000000000007'
    }

    It 'fails when the read-back never works and Set returned no id' {
        $script:lag.Misses = 99
        $script:lag.ReturnId = $false
        $plan = & $script:newPlan
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Error | Should -Match 'TargetNotFound'
        @($script:sleeps) | Should -Be @(2, 4, 8)
        $plan.Subject.Id | Should -BeNullOrEmpty
    }

    It 'does not retry the read-back of a step that is not a Create' {
        $script:state['u1'] = @{ accountEnabled = $true }
        $state = $script:state
        $calls = @{ Get = 0 }
        $get = {
            param($Target, $Context)
            $calls.Get++
            if ($calls.Get -gt 1) { throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('gone'), 'Tenure.Provider.TargetNotFound', 'ObjectNotFound', $Target) }
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Laggy' -State $script:state -Log $script:log -Overrides @{ Get = $get })
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Laggy')
        Invoke-Apply $plan | Out-Null
        $plan.Steps[0].Status | Should -Be 'Failed'
        $script:sleeps.Count | Should -Be 0
    }
}
