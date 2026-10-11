# Fault injection and property tests for the apply engine.
# Fake providers only; every audit path is under TestDrive.
#
# Mutation record. Each mutant was applied to a scratch copy of src/ (never the working
# tree) and the named test file was run; "killed" means at least one test failed.
#
# First mutation round (six mutants, seven runs; the first noplaintext edit was itself
# faulty, so it was redone):
#   noplaintext    Test-TenureStateSafe: skip the plaintext-secret search.
#                  First edit '$false -and A -or B' left B live (operator precedence) and
#                  survived; corrected to 'if ($false)' it was killed by NoSecrets
#                  'is withheld when a buggy provider returns it in the state object'.
#   noredact       Complete-TenurePlanStep: store the provider error unredacted. Killed by
#                  NoSecrets 'stays out of every output when a later step fails ...'.
#   invokeresume   Rule 2: treat only Applied (not Skipped) Invoke steps as fired. Killed
#                  then by Apply 'skips an Invoke step applied in an earlier run ...'.
#   noclone        -WhatIf runs on the caller's plan instead of a copy. Killed by Apply
#                  'calls no Set and writes no audit file under -WhatIf ...'.
#   riskstep       Use the step's Risk instead of max(step, provider). Killed by Apply
#                  'uses the provider risk when a plan step claims a lower one'.
#   nosecretsafe   Skip the state safety check after Get. Killed by NoSecrets
#                  'fails the step with Tenure.Json.SecretRejected ...'.
#
# Second mutation round (22 mutants, all killed; file in parentheses):
#   noplaintext, noredact, noclone, riskstep, nosecretsafe: killed again as above.
#   invokeresume   Survived at first: the audit-log lookup also blocks the re-fire when
#                  the same audit file is used. Killed after adding Apply 'never fires an
#                  Invoke step the plan records as Skipped, even against a fresh audit log'.
#   H1-failopen    Drop the fail-closed rule for Refuse checks (Apply, 5 tests).
#   H2a-nowriteahead       No Attempting entry before Set (Apply, 2 tests).
#   H2b-nopersist          Never rewrite the plan file (Apply, 3 tests).
#   H2c-noauditconsult     Ignore Applied entries in the audit log (Apply, 1 test).
#   H2c-nouncertain        Ignore Attempting/interrupted evidence (Apply, 3 tests).
#   H2d-noopenrun          Skip the open-run check under the lock (Apply, 2 tests).
#   H3-noshouldcontinue    No separate question for Destructive steps (Apply, 3 tests).
#   M1-noresultkept        Do not keep the result on an abnormal end (ApplyFaults, 3 tests).
#   M2a-nofailedretest     Do not re-test Failed State steps on resume (Apply, 1 test).
#   M2b-noadopt            Do not adopt a user created by an earlier attempt (Apply, 1 test).
#   M3-norollback          Do not cut a torn append back (Audit, 1 test).
#   L2a-noerrorclean       Leave secret-bearing records in $Error (NoSecrets, 1 test).
#   L2c-noprotectafterget  No secret-table pass after Get (NoSecrets, 1 test).
#   L6-nofingerprintrule   Accept an empty Fingerprint anywhere (Apply, 1 test).
#   placeholder-substring  Substitute when a value merely contains {{subjectId}} (Apply, 2 tests).
#   placeholder-targetonly Do not substitute inside After (Apply, 3 tests).

BeforeDiscovery {
    # Read at discovery time by -Skip: root ignores file permissions, so the read-only cases cannot fail as intended.
    $script:IsRoot = (-not $IsWindows) -and ((& id -u) -eq '0')
}

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'PlanFixtures.ps1')
    Import-TenureForTest
    # Plans here name made-up users and run without FakeGraph: the protection preflight compares names only.
    Disable-TestIdentityLookup

    $script:SavedConfirmPreference = $global:ConfirmPreference
    $global:ConfirmPreference = 'None'
    $script:SavedAuditEnv = $env:TENURE_AUDIT_PATH
    $script:FakeNames = @('Fake.State', 'Fake.Boom', 'Fake.Reread', 'Fake.Testy', 'Fake.Void', 'Fake.Lost', 'Fake.Invoke', 'Fake.Saboteur')

    function New-World {
        Set-TenureTestSession
        $script:state = @{}
        foreach ($id in 'u1', 'u2', 'u3') { $script:state[$id] = @{ accountEnabled = $true; department = 'Sales' } }
        $script:log = [System.Collections.Generic.List[string]]::new()
        $script:audit = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $env:TENURE_AUDIT_PATH = Join-Path $TestDrive 'env-sentinel.jsonl'
        Register-TestProvider (New-RecordingProvider -Name 'Fake.State' -State $script:state -Log $script:log)
    }

    function New-DisableStep([string]$Id, [string]$UserId, [string]$Provider = 'Fake.State', [string[]]$DependsOn = @()) {
        New-TestStep -Id $Id -Provider $Provider -Target @{ Kind = 'user'; Id = $UserId; Name = $UserId } -Before (Get-TestSnapshot -State $script:state -Id $UserId) -After @{ accountEnabled = $false } -DependsOn $DependsOn
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

Describe 'Apply faults: providers' {
    BeforeEach { New-World }

    It 'leaves later steps Pending and the chain valid when Set throws mid-plan' {
        $boom = { param($Target, $Desired, $Current, $Context) throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Exchange cmdlet failed'), 'Tenure.Exchange.Failed', 'NotSpecified', $null) }
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Boom' -State $script:state -Log $script:log -Overrides @{ Set = $boom })
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2' -Provider 'Fake.Boom'), (New-DisableStep 'S03' 'u3'))
        $result = Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false
        Get-TestStatus $plan | Should -Be 'Applied,Failed,Pending'
        $plan.Status | Should -Be 'PartiallyApplied'
        $plan.Steps[1].Result.Error | Should -Be 'Tenure.Exchange.Failed: Exchange cmdlet failed'
        $result.Summary.Pending | Should -Be 1
        Get-Outcome $script:audit | Should -Be 'PlanStarted,Applied:S01,Failed:S02,PlanFinished'
        (Test-TenureAudit -Path $script:audit).Valid | Should -BeTrue
        $failed = @(Get-TenureAudit -Path $script:audit | Where-Object Outcome -eq 'Failed')[0]
        $failed.Error | Should -Match 'Exchange cmdlet failed'
    }

    It 'fails with the Get error and does not retry Set when Get throws after a successful Set' {
        $counter = @{ Get = 0; Set = 0 }
        $state = $script:state
        $get = {
            param($Target, $Context)
            $counter.Get++
            if ($counter.Get -gt 1) { throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('replication lag: 404'), 'Tenure.Graph.NotFound', 'ObjectNotFound', $null) }
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        $set = {
            param($Target, $Desired, $Current, $Context)
            $counter.Set++
            $state[$Target.Id]['accountEnabled'] = $false
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Reread' -State $script:state -Log $script:log -Overrides @{ Get = $get; Set = $set })
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1' -Provider 'Fake.Reread'), (New-DisableStep 'S02' 'u2'))
        Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false | Out-Null
        Get-TestStatus $plan | Should -Be 'Failed,Pending'
        $plan.Steps[0].Result.Error | Should -Match '^Tenure\.Graph\.NotFound: replication lag'
        $plan.Steps[0].Result.Note | Should -Match 'not retried'
        $counter.Set | Should -Be 1
        (Test-TenureAudit -Path $script:audit).Valid | Should -BeTrue
    }

    It 'fails a step whose Test throws, without calling Set' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Testy' -State $script:state -Log $script:log -Overrides @{ Test = { param($Current, $Desired) throw 'test exploded' } })
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Testy')
        Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false | Out-Null
        $plan.Steps[0].Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Error | Should -Match 'test exploded'
        $script:log.Count | Should -Be 0
    }

    It 'handles a Set that returns $null and changes nothing (post-condition Failed, no crash)' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Void' -State $script:state -Log $script:log -Overrides @{ Set = { param($Target, $Desired, $Current, $Context) $null } })
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Void')
        { Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false } | Should -Not -Throw
        $plan.Steps[0].Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Note | Should -Match 'post-condition'
    }

    It 'handles a provider whose Get returns $null after Set' {
        $counter = @{ Get = 0 }
        $state = $script:state
        $get = { param($Target, $Context) $counter.Get++; if ($counter.Get -gt 1) { return $null }; [pscustomobject]$state[$Target.Id].Clone() }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Lost' -State $script:state -Log $script:log -Overrides @{ Get = $get })
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1' -Provider 'Fake.Lost')
        { Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false } | Should -Not -Throw
        $plan.Steps[0].Status | Should -Be 'Failed'
        $plan.Steps[0].Result.Observed | Should -BeNullOrEmpty
        (Test-TenureAudit -Path $script:audit).Valid | Should -BeTrue
    }

    It 'applies an Invoke step whose Set returns $null' {
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Invoke' -State $script:state -Log $script:log -Overrides @{ Kind = 'Invoke'; Set = { param($Target, $Desired, $Current, $Context) $null }; Test = { param($Current, $Desired) $false } })
        $plan = New-TestPlan -Steps @(New-TestStep -Id 'S01' -Provider 'Fake.Invoke' -Action 'Invoke' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -Before (Get-TestSnapshot -State $script:state -Id 'u1') -After @{})
        Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false | Out-Null
        $plan.Steps[0].Status | Should -Be 'Applied'
        $plan.Steps[0].Result.Observed | Should -BeNullOrEmpty
    }
}

Describe 'Apply faults: audit log' {
    BeforeEach { New-World }

    It 'refuses before step 1 when the audit directory is read-only' -Skip:($IsWindows -or $script:IsRoot) {
        $directory = Join-Path $TestDrive 'locked'
        New-Item -ItemType Directory -Path $directory | Out-Null
        & chmod 0555 $directory
        try {
            $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
            { Invoke-TenurePlan -Plan $plan -AuditPath (Join-Path $directory 'audit.jsonl') -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable'
            $script:log.Count | Should -Be 0
            $plan.Steps[0].Status | Should -Be 'Pending'
            $plan.Status | Should -Be 'Planned'
        } finally {
            & chmod 0755 $directory
        }
    }

    It 'refuses before step 1 when the audit path is under a file' {
        $file = Join-Path $TestDrive 'a-file.txt'
        Set-Content -LiteralPath $file -Value 'x'
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        $failure = { Invoke-TenurePlan -Plan $plan -AuditPath (Join-Path $file 'audit.jsonl') -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable' -PassThru
        $failure.Exception.Message | Should -Match 'a-file.txt'
        $script:log.Count | Should -Be 0
        (Get-Content -LiteralPath $file -Raw).Trim() | Should -Be 'x'
    }

    It 'refuses before step 1 when the last audit line is torn' {
        Set-Content -LiteralPath $script:audit -Value '{"Seq":1,"Ts":"2026-' -NoNewline
        $plan = New-TestPlan -Steps @(New-DisableStep 'S01' 'u1')
        { Invoke-TenurePlan -Plan $plan -AuditPath $script:audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Audit.Corrupt'
        $script:log.Count | Should -Be 0
    }

    It 'stops, keeps statuses accurate and hands back the result when the audit log becomes unwritable mid-run' -Skip:$script:IsRoot {
        $audit = $script:audit
        $state = $script:state
        $sabotage = {
            param($Target, $Desired, $Current, $Context)
            $Context.Secrets[$Context.StepId] = [securestring]::new()
            foreach ($key in $Desired.Keys) { $state[$Target.Id][$key] = $Desired[$key] }
            (Get-Item -LiteralPath $audit).IsReadOnly = $true
            [pscustomobject]$state[$Target.Id].Clone()
        }.GetNewClosure()
        Register-TestProvider (New-RecordingProvider -Name 'Fake.Saboteur' -State $script:state -Log $script:log -Overrides @{ Set = $sabotage })
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1' -Provider 'Fake.Saboteur'), (New-DisableStep 'S02' 'u2'))
        try {
            $failure = { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable' -PassThru
        } finally {
            (Get-Item -LiteralPath $audit).IsReadOnly = $false
        }
        Get-TestStatus $plan | Should -Be 'Applied,Pending'
        $plan.Status | Should -Be 'PartiallyApplied'
        $script:log.Count | Should -Be 0 -Because 'S02 must not run once the audit log cannot record it'
        $partial = $failure.Exception.Data['ApplyResult']
        $partial.PSObject.TypeNames[0] | Should -Be 'Tenure.ApplyResult'
        [object]::ReferenceEquals($partial.Plan, $plan) | Should -BeTrue
        $partial.Secrets.ContainsKey('S01') | Should -BeTrue
        $partial.Summary.Applied | Should -Be 1
        (Test-TenureAudit -Path $audit).Valid | Should -BeTrue
    }

    It 'attaches the partial result and closes the run in the audit log when an unexpected error escapes' {
        Add-Member -InputObject ($cmdlet = [pscustomobject]@{}) -MemberType ScriptMethod -Name ShouldProcess -Value {
            param($target, $action)
            if ($target.StartsWith('[S02]')) { throw 'PowerShell is in NonInteractive mode. Read and Prompt functionality is not available.' }
            $true
        }
        $plan = New-TestPlan -Steps @((New-DisableStep 'S01' 'u1'), (New-DisableStep 'S02' 'u2'))
        $failure = { Invoke-InTenure { param($p, $c, $a) Invoke-TenurePlanCore -Plan $p -Cmdlet $c -AuditPath $a } @($plan, $cmdlet, $script:audit) } | Should -Throw -PassThru
        $failure.Exception.Message | Should -Match 'NonInteractive'
        $failure.Exception.Data['ApplyResult'].Summary.Applied | Should -Be 1
        Get-TestStatus $plan | Should -Be 'Applied,Pending'
        $plan.Status | Should -Be 'PartiallyApplied'
        Get-Outcome $script:audit | Should -Be 'PlanStarted,Applied:S01,PlanFinished' -Because 'exactly one PlanFinished closes the run'
        (Test-TenureAudit -Path $script:audit).Valid | Should -BeTrue
        [object]::ReferenceEquals((Get-TenureApplyResult).Plan, $plan) | Should -BeTrue
    }
}

Describe 'Plan status property' {
    BeforeAll {
        $script:Statuses = @('Pending', 'Applied', 'Skipped', 'Failed', 'DryRun', 'Drifted', 'Refused')
        $script:PlanStatuses = @('Planned', 'DryRun', 'Applied', 'PartiallyApplied', 'Failed')
    }

    It 'returns one of the five plan statuses and Summary counts that sum to the step count, for 300 seeded vectors' {
        $random = [System.Random]::new(20261008)
        for ($trial = 0; $trial -lt 300; $trial++) {
            $count = $random.Next(0, 13)
            $vector = @(for ($i = 0; $i -lt $count; $i++) { $script:Statuses[$random.Next(0, $script:Statuses.Count)] })
            $steps = @(for ($i = 0; $i -lt $count; $i++) {
                    New-TestStep -Id ('S{0:D2}' -f ($i + 1)) -Kind 'State' -Risk 'Low' -Status $vector[$i]
                })
            $plan = New-TestPlan -Steps $steps
            $status = Invoke-InTenure { param($p) Get-TenurePlanStatus -Plan $p } @($plan)
            $summary = Invoke-InTenure { param($p) Get-TenurePlanSummary -Plan $p } @($plan)
            $context = "trial $trial, statuses [$($vector -join ',')]"

            $script:PlanStatuses | Should -Contain $status -Because $context
            ($summary.Values | Measure-Object -Sum).Sum | Should -Be $count -Because $context
            foreach ($name in $script:Statuses) { $summary[$name] | Should -Be @($vector | Where-Object { $_ -ceq $name }).Count -Because $context }

            $bad = @($vector | Where-Object { $_ -in 'Failed', 'Drifted', 'Refused' }).Count
            $applied = $summary.Applied
            if ($bad -gt 0 -and $applied -gt 0) { $status | Should -Be 'PartiallyApplied' -Because $context }
            if ($bad -gt 0 -and $applied -eq 0) { $status | Should -Be 'Failed' -Because $context }
            if ($bad -eq 0 -and $applied -gt 0 -and $summary.Pending -gt 0) { $status | Should -Be 'PartiallyApplied' -Because $context }
            if ($count -gt 0 -and $summary.Pending -eq $count) { $status | Should -Be 'Planned' -Because $context }
            if (($summary.Applied + $summary.Skipped) -eq $count) { $status | Should -Be 'Applied' -Because $context }
            if ($summary.DryRun -gt 0 -and ($summary.DryRun + $summary.Skipped) -eq $count) { $status | Should -Be 'DryRun' -Because $context }
        }
    }
}

Describe 'Apply interrupted by a pipeline stop' {
    BeforeAll {
        # Runs a plan in its own runspace (a stop there must not stop this test run) and
        # returns what the session can still recover afterwards.
        function Invoke-StoppedRun {
            param([Parameter(Mandatory)][ValidateSet('Stop', 'Throw')][string]$How)
            $root = $TestDrive
            $paths = @{
                Audit    = Join-Path $root ("stop-audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
                PlanFile = Join-Path $root ("stop-plan-{0}.json" -f [guid]::NewGuid().ToString('N'))
                Marker   = Join-Path $root ("stop-marker-{0}.txt" -f [guid]::NewGuid().ToString('N'))
            }
            $helpers = Join-Path $script:TenureRepoRoot 'tests' 'helpers'
            $runspace = [runspacefactory]::CreateRunspace()
            $runspace.Open()
            try {
                $run = [powershell]::Create()
                $run.Runspace = $runspace
                [void]$run.AddScript({
                        param($helpers, $paths, $how)
                        . (Join-Path $helpers 'TestHelpers.ps1')
                        . (Join-Path $helpers 'PlanFixtures.ps1')
                        Import-TenureForTest
                        Disable-TestIdentityLookup
                        Set-TenureTestSession
                        $global:ConfirmPreference = 'None'
                        $state = @{ u1 = @{ accountEnabled = $true }; u2 = @{ accountEnabled = $true } }
                        $set = {
                            param($Target, $Desired, $Current, $Context)
                            $secure = [securestring]::new()
                            foreach ($character in 'ZQ9-stopped-secret-4k'.ToCharArray()) { $secure.AppendChar($character) }
                            $Context.Secrets[$Context.StepId] = $secure
                            Set-Content -LiteralPath $paths.Marker -Value 'set started'
                            if ($how -eq 'Throw') { throw [System.Management.Automation.PipelineStoppedException]::new() }
                            Start-Sleep -Seconds 60
                        }.GetNewClosure()
                        Register-TestProvider (New-FakeProviderDefinition -Name 'Fake.Slow' -State $state -Overrides @{ Kind = 'Invoke'; Set = $set; Test = { param($Current, $Desired) $false } })
                        Register-TestProvider (New-FakeProviderDefinition -Name 'Fake.State' -State $state)
                        $plan = New-TestPlan -Steps @(
                            New-TestStep -Id 'S01' -Provider 'Fake.Slow' -Action 'Invoke' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'u1' } -Before (Get-TestSnapshot -State $state -Id 'u1') -After @{ revoke = $true }
                            New-TestStep -Id 'S02' -Provider 'Fake.State' -Target @{ Kind = 'user'; Id = 'u2'; Name = 'u2' } -Before (Get-TestSnapshot -State $state -Id 'u2') -After @{ accountEnabled = $false }
                        )
                        Invoke-TenurePlan -Plan $plan -AuditPath $paths.Audit -OutFile $paths.PlanFile -Confirm:$false
                    }).AddArgument($helpers).AddArgument($paths).AddArgument($How)
                $handle = $run.BeginInvoke()
                if ($How -eq 'Stop') {
                    $deadline = [datetime]::UtcNow.AddSeconds(60)
                    while (-not (Test-Path -LiteralPath $paths.Marker) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
                    $run.Stop()
                } else {
                    try { $run.EndInvoke($handle) } catch { Write-Verbose 'The run ended with the thrown stop.' }
                }
                $run.Dispose()

                $after = [powershell]::Create()
                $after.Runspace = $runspace
                [void]$after.AddScript({
                        $result = Get-TenureApplyResult
                        [pscustomobject]@{
                            HasResult  = $null -ne $result
                            Secret     = if ($result) { [System.Net.NetworkCredential]::new('', $result.Secrets['S01']).Password } else { $null }
                            StepStatus = if ($result) { $result.Plan.Steps[0].Status } else { $null }
                            StepError  = if ($result) { [string]$result.Plan.Steps[0].Result['Error'] } else { $null }
                            Second     = if ($result) { $result.Plan.Steps[1].Status } else { $null }
                        }
                    })
                $recovered = @($after.Invoke())[0]
                $after.Dispose()
            } finally {
                $runspace.Dispose()
            }
            @{ Paths = $paths; Recovered = $recovered }
        }

        function Get-Outcome([string]$Path) {
            @(Get-TenureAudit -Path $Path | ForEach-Object { if ($_.StepId) { "$($_.Outcome):$($_.StepId)" } else { $_.Outcome } }) -join ','
        }
    }

    It 'keeps the secret, closes the audit run and persists the plan when the run is stopped (Ctrl+C)' {
        $outcome = Invoke-StoppedRun -How 'Stop'
        $recovered = $outcome.Recovered
        $recovered.HasResult | Should -BeTrue
        $recovered.Secret | Should -Be 'ZQ9-stopped-secret-4k'
        $recovered.StepStatus | Should -Be 'Failed'
        $recovered.StepError | Should -Match '^Tenure\.Apply\.Interrupted'
        $recovered.Second | Should -Be 'Pending'

        Get-Outcome $outcome.Paths.Audit | Should -Be 'PlanStarted,Attempting:S01,Failed:S01,PlanFinished'
        (Test-TenureAudit -Path $outcome.Paths.Audit).Valid | Should -BeTrue
        $saved = Get-Content -LiteralPath $outcome.Paths.PlanFile -Raw | ConvertFrom-Json
        $saved.Steps[0].Status | Should -Be 'Failed'
        $saved.Steps[0].Result.Attempted | Should -BeTrue
        $saved.Steps[0].Result.Error | Should -Match 'Interrupted'
        (Get-Content -LiteralPath $outcome.Paths.PlanFile -Raw).Contains('ZQ9-stopped-secret-4k') | Should -BeFalse
        [System.IO.File]::ReadAllText($outcome.Paths.Audit).Contains('ZQ9-stopped-secret-4k') | Should -BeFalse
    }

    It 'takes the same path when a provider throws PipelineStoppedException' {
        $outcome = Invoke-StoppedRun -How 'Throw'
        $outcome.Recovered.Secret | Should -Be 'ZQ9-stopped-secret-4k'
        $outcome.Recovered.StepStatus | Should -Be 'Failed'
        Get-Outcome $outcome.Paths.Audit | Should -Be 'PlanStarted,Attempting:S01,Failed:S01,PlanFinished'
    }

    It 'never fires the interrupted Invoke step again on a guess: -Resume stops there, -AssumeFired records it' {
        $outcome = Invoke-StoppedRun -How 'Stop'
        Set-TenureTestSession
        $fires = @{ Count = 0 }
        $state = @{ u1 = @{ accountEnabled = $true }; u2 = @{ accountEnabled = $true } }
        $set = { param($Target, $Desired, $Current, $Context) $fires.Count++; [pscustomobject]@{ revoked = $true } }.GetNewClosure()
        Register-TestProvider (New-FakeProviderDefinition -Name 'Fake.Slow' -State $state -Overrides @{ Kind = 'Invoke'; Set = $set; Test = { param($Current, $Desired) $false } })
        Register-TestProvider (New-FakeProviderDefinition -Name 'Fake.State' -State $state)
        try {
            Invoke-TenurePlan -Plan $outcome.Paths.PlanFile -AuditPath $outcome.Paths.Audit -Confirm:$false | Out-Null
            $fires.Count | Should -Be 0
            (Import-TenurePlan -Path $outcome.Paths.PlanFile).Steps[0].Status | Should -Be 'Refused'
            Invoke-TenurePlan -Plan $outcome.Paths.PlanFile -AuditPath $outcome.Paths.Audit -Resume -Confirm:$false | Out-Null
            $fires.Count | Should -Be 0
            (Import-TenurePlan -Path $outcome.Paths.PlanFile).Steps[0].Status | Should -Be 'Refused' -Because 'Fake.Slow is not Repeatable'
            Invoke-TenurePlan -Plan $outcome.Paths.PlanFile -AuditPath $outcome.Paths.Audit -AssumeFired S01 -Confirm:$false | Out-Null
            $fires.Count | Should -Be 0
            $saved = Import-TenurePlan -Path $outcome.Paths.PlanFile
            Get-TestStatus $saved | Should -Be 'Skipped,Applied'
            $saved.Steps[0].Result['Note'] | Should -Match 'assumed fired'
            $saved.Status | Should -Be 'PartiallyApplied'
        } finally {
            Unregister-TestProvider -Name 'Fake.Slow'
        }
    }
}
