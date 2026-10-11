BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest

    $script:ExamplePath = Join-Path $script:TenureSourceRoot 'Policies' 'example.policy.json'
    $script:state = @{}
    $script:calls = [System.Collections.Generic.List[object]]::new()

    # Provider names are unique to this file so other suites' fakes never collide with them.
    function New-SpyDefinition {
        param([string]$SpyName, [hashtable]$SpyOverrides = @{})
        # The shared fake's Describe reads $Desired.Keys, which fails under strict mode when a step has no
        # -Desired (Invoke steps). This one prints the same text and tolerates a null Desired.
        $safeDescribe = {
            param($Target, $Current, $Desired, $Action)
            $pairs = if ($null -eq $Desired) { '' } else { (($Desired.Keys | Sort-Object | ForEach-Object { "$_=$($Desired[$_])" }) -join ', ') }
            "$Action $($Target.Name): $pairs"
        }
        $overrides = @{ Describe = $safeDescribe }
        foreach ($overrideKey in $SpyOverrides.Keys) { $overrides[$overrideKey] = $SpyOverrides[$overrideKey] }
        $definition = New-FakeProviderDefinition -Name $SpyName -State $script:state -Overrides $overrides
        $baseGet = $definition['Get']
        $baseTest = $definition['Test']
        $log = $script:calls
        $definition['Get'] = { param($Target, $Context) $log.Add(@{ Op = 'Get'; Target = $Target; Context = $Context }); & $baseGet $Target $Context }.GetNewClosure()
        $definition['Test'] = { param($Current, $Desired) $log.Add(@{ Op = 'Test' }); & $baseTest $Current $Desired }.GetNewClosure()
        $definition
    }

    function Register-Fake {
        param([hashtable]$FakeDefinition)
        Invoke-InTenure { param($d) Register-TenureProvider -Definition $d -Force | Out-Null } @($FakeDefinition)
    }

    function Get-Canonical {
        param($CanonicalObject)
        Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @($CanonicalObject)
    }

    function Get-Hash {
        param($HashObject)
        Invoke-InTenure { param($o) Get-TenureHash -InputObject $o } @($HashObject)
    }

    function Get-StepFingerprint {
        param($FingerprintTarget, $FingerprintBefore)
        Invoke-InTenure { param($t, $b) Get-TenureStepFingerprint -Target $t -Before $b } @($FingerprintTarget, $FingerprintBefore)
    }

    function Get-ThrownError {
        param([scriptblock]$HelperBlock)
        try { & $HelperBlock | Out-Null } catch { return $_ }
        $null
    }

    function Reset-PlanTestState {
        $script:state.Clear()
        $script:calls.Clear()
        Clear-TenureTestSession
    }

    function New-UserTarget {
        param([string]$TargetId = 'u1', [string]$TargetName = 'Ada Lovelace')
        @{ Kind = 'user'; Id = $TargetId; Name = $TargetName }
    }

    function New-SubjectTable {
        @{ Id = 'u1'; UserPrincipalName = 'ada@example.com'; DisplayName = 'Ada Lovelace' }
    }

    function New-SamplePlan {
        $script:state['u1'] = @{ displayName = 'Ada'; department = 'Eng'; address = @{ city = 'London'; tags = @('a', 'b') }; seen = [datetime]::Now }
        $first = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ displayName = 'Grace'; extra = @{ deep = @{ x = 1 } }; items = @(@{ n = 1 }, @{ n = 2 }) } -Key 'first'
        $second = New-TenureStep -Provider 'Fake.PlanInvoke' -Target (New-UserTarget) -Key 'second' -DependsOn 'first'
        New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $first, $second -Inputs @{ role = 'sales'; flags = @('x', 'y'); when = '2026-10-08T12:00:00Z' } -Warning 'careful'
    }

    function Get-MinimalPlan {
        $json = @'
{
  "SchemaVersion": 2,
  "PlanId": "11111111-2222-3333-4444-555555555555",
  "CreatedAt": "2026-10-08T12:30:00.0000000Z",
  "CreatedBy": { "Account": "admin@example.com", "TenantId": null, "AuthType": null },
  "ModuleVersion": "0.1.0",
  "Operation": "Custom",
  "Subject": { "Id": null, "UserPrincipalName": "ada@example.com", "DisplayName": "Ada" },
  "PolicyHash": null,
  "PolicySnapshot": null,
  "Inputs": {},
  "Steps": [
    { "Id": "S01", "Key": "a", "Provider": "Fake.PlanState", "Kind": "State", "Target": { "Kind": "user", "Id": "u1", "Name": "Ada" }, "Action": "Update", "Before": null, "After": { "x": 1 }, "Fingerprint": "", "Risk": "Low", "Reversible": true, "Reason": "r1", "DependsOn": [], "Status": "Pending", "Result": null },
    { "Id": "S02", "Key": "b", "Provider": "Fake.PlanState", "Kind": "State", "Target": { "Kind": "user", "Id": "u1", "Name": "Ada" }, "Action": "Update", "Before": null, "After": { "y": 2 }, "Fingerprint": "", "Risk": "Low", "Reversible": true, "Reason": "r2", "DependsOn": ["S01"], "Status": "Pending", "Result": null }
  ],
  "Warnings": [],
  "Status": "Planned",
  "Integrity": "0000000000000000000000000000000000000000000000000000000000000000"
}
'@
        $table = $json | ConvertFrom-Json -AsHashtable -Depth 30
        foreach ($step in $table['Steps']) { $step['Fingerprint'] = Get-StepFingerprint $step['Target'] $step['Before'] }
        $table
    }

    # Seals a plan table the way New-TenurePlan seals a plan: reads it back exactly as Import-TenurePlan would and
    # stores the integrity value. A table that does not even read back is left alone; that is what a refusal
    # test is about, and its own error must come first.
    function Set-PlanTableIntegrity {
        param($PlanTable)
        $text = ConvertTo-Json -InputObject $PlanTable -Depth 20
        try {
            $PlanTable['Integrity'] = Invoke-InTenure {
                param($t)
                $model = ConvertFrom-TenureJsonText -Text $t -ErrorId 'Tenure.Plan.Invalid'
                Get-TenurePlanIntegrity -Plan (ConvertFrom-TenurePlanModel -Model $model)
            } @($text)
        } catch {
            Write-Verbose 'The table does not read back as a plan; left unsealed.'
        }
    }

    function Write-PlanFile {
        param($PlanTable, [string]$FileName = 'plan.json', [switch]$NoSeal)
        if (-not $NoSeal -and $PlanTable -is [System.Collections.IDictionary]) { Set-PlanTableIntegrity $PlanTable }
        $file = Join-Path $TestDrive $FileName
        [System.IO.File]::WriteAllText($file, (ConvertTo-Json -InputObject $PlanTable -Depth 20), [System.Text.UTF8Encoding]::new($false))
        $file
    }

    Register-Fake (New-SpyDefinition -SpyName 'Fake.PlanState')
    Register-Fake (New-SpyDefinition -SpyName 'Fake.PlanRisky' -SpyOverrides @{ Risk = 'High'; Reversible = $false })
    Register-Fake (New-SpyDefinition -SpyName 'Fake.PlanInvoke' -SpyOverrides @{ Kind = 'Invoke'; Risk = 'Medium'; Test = { param($Current, $Desired) $false } })
    $checkDefinition = New-SpyDefinition -SpyName 'Fake.PlanCheck' -SpyOverrides @{ Kind = 'Check'; Severity = 'Warn' }
    $checkDefinition.Remove('Set')
    Register-Fake $checkDefinition
    Register-Fake (New-SpyDefinition -SpyName 'Fake.PlanDenied' -SpyOverrides @{
            Get = { param($Target, $Context) throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('denied'), 'Tenure.Graph.Forbidden', 'PermissionDenied', $Target) }
        })
}

AfterAll {
    foreach ($name in 'Fake.PlanState', 'Fake.PlanRisky', 'Fake.PlanInvoke', 'Fake.PlanCheck', 'Fake.PlanDenied') {
        Invoke-InTenure { param($n) Unregister-TenureProvider -Name $n } @($name)
    }
    Clear-TenureTestSession
}

Describe 'New-TenureStep: snapshot and action' {
    BeforeEach { Reset-PlanTestState }
    It 'is NoOp when the provider Test says the desired state already holds' {
        $script:state['u1'] = @{ displayName = 'Ada'; department = 'Eng' }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ displayName = 'Ada' }
        $step.Action | Should -Be 'NoOp'
        $step.Before.displayName | Should -Be 'Ada'
        $step.Fingerprint | Should -Be (Get-StepFingerprint (New-UserTarget) ([pscustomobject]@{ displayName = 'Ada'; department = 'Eng' }))
        $step.Fingerprint | Should -Be (Get-Hash @{ Target = @{ Kind = 'user'; Id = 'u1' }; Before = @{ displayName = 'Ada'; department = 'Eng' } })
        $step.Fingerprint | Should -Match '^[0-9a-f]{64}$'
    }

    It 'is Update when Test is false, with the Describe text as Reason' {
        $script:state['u1'] = @{ displayName = 'Ada' }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ displayName = 'Grace' }
        $step.Action | Should -Be 'Update'
        $step.After.displayName | Should -Be 'Grace'
        $step.Reason | Should -Be 'Update Ada Lovelace: displayName=Grace'
    }

    It 'is Create with a null Before and an "absent" fingerprint when the target is missing and -AllowMissing is set' {
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ displayName = 'Ada' } -AllowMissing
        $step.Action | Should -Be 'Create'
        $step.Before | Should -BeNullOrEmpty
        $step.Fingerprint | Should -Be (Get-StepFingerprint (New-UserTarget) $null) -Because 'a Create binds its target as absent'
    }

    It 'rethrows Tenure.Provider.TargetNotFound without -AllowMissing' {
        { New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ displayName = 'Ada' } } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }

    It 'rethrows any other Get error even with -AllowMissing' {
        { New-TenureStep -Provider 'Fake.PlanDenied' -Target (New-UserTarget) -Desired @{ a = 1 } -AllowMissing } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
    }

    It 'treats an Invoke provider as an Invoke action and does not call Test' {
        $script:state['u1'] = @{ sessions = 3 }
        $step = New-TenureStep -Provider 'Fake.PlanInvoke' -Target (New-UserTarget)
        $step.Action | Should -Be 'Invoke'
        $step.Kind | Should -Be 'Invoke'
        @($script:calls | Where-Object { $_.Op -eq 'Test' }).Count | Should -Be 0
        @($script:calls | Where-Object { $_.Op -eq 'Get' }).Count | Should -Be 1
    }

    It 'treats a Check provider as NoOp when satisfied and Check when not' {
        $script:state['u1'] = @{ mailboxGb = 3 }
        (New-TenureStep -Provider 'Fake.PlanCheck' -Target (New-UserTarget) -Desired @{ mailboxGb = 3 }).Action | Should -Be 'NoOp'
        (New-TenureStep -Provider 'Fake.PlanCheck' -Target (New-UserTarget) -Desired @{ mailboxGb = 60 }).Action | Should -Be 'Check'
    }

    It 'uses -Action in place of Update, but NoOp still wins when Test is true' {
        $script:state['u1'] = @{ member = $true }
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ member = $false } -Action Remove).Action | Should -Be 'Remove'
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ member = $true } -Action Remove).Action | Should -Be 'NoOp'
    }

    It 'calls Get with the target and the context, positionally' {
        $script:state['u1'] = @{ a = 1 }
        $null = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 }
        $get = $script:calls | Where-Object { $_.Op -eq 'Get' } | Select-Object -First 1
        $get.Target.Id | Should -Be 'u1'
        $get.Context.Mode | Should -Be 'Plan'
    }

    It 'copies Reversible from the provider' {
        $script:state['u1'] = @{ a = 1 }
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 }).Reversible | Should -BeTrue
        (New-TenureStep -Provider 'Fake.PlanRisky' -Target (New-UserTarget) -Desired @{ a = 2 }).Reversible | Should -BeFalse
    }
}

Describe 'New-TenureStep: -SkipSnapshot' {
    BeforeEach { Reset-PlanTestState }
    It 'requires -Action' {
        { New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
    }

    It 'sets Before to null, binds the target as absent, and calls neither Get nor Test' {
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Create
        $step.Action | Should -Be 'Create'
        $step.Before | Should -BeNullOrEmpty
        $step.Fingerprint | Should -Be (Get-StepFingerprint (New-UserTarget) $null)
        $script:calls.Count | Should -Be 0
    }

    It 'refuses -SkipSnapshot for a step that is neither a Create nor on the {{subjectId}} placeholder' {
        { New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Update } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
        { New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Remove } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
        $script:calls.Count | Should -Be 0
    }

    It 'accepts the {{subjectId}} placeholder as a target id' {
        $target = @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'New hire' }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target $target -Desired @{ a = 1 } -SkipSnapshot -Action Create -Key 'later' -DependsOn 'create'
        $step.Target.Id | Should -Be '{{subjectId}}'
        $step.DependsOn | Should -Be @('create')
    }
}

Describe 'New-TenureStep: the {{subjectId}} placeholder' {
    It 'refuses <Id> without -SkipSnapshot and never calls the provider Get' -ForEach @(
        @{ Id = '{{subjectId}}' }, @{ Id = '{{SUBJECTID}}' }, @{ Id = '{{SubjectId}}' }, @{ Id = '{{subjectid}}' }, @{ Id = ' {{subjectId}} ' }
    ) {
        $target = @{ Kind = 'user'; Id = $Id; Name = 'New hire' }
        $thrown = Get-ThrownError { New-TenureStep -Provider 'Fake.PlanState' -Target $target -Desired @{ a = 1 } }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Step.Invalid'
        $thrown.Exception.Message | Should -Match '-SkipSnapshot'
        $thrown.Exception.Message | Should -Match '-Action'
        $thrown.Exception.Message | Should -Match 'subjectId'
        $script:calls.Count | Should -Be 0
    }

    It 'refuses the placeholder with -AllowMissing too, because the snapshot is the problem' {
        $target = @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'New hire' }
        { New-TenureStep -Provider 'Fake.PlanState' -Target $target -Desired @{ a = 1 } -AllowMissing } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
        { New-TenureStep -Provider 'Fake.PlanState' -Target $target -Desired @{ a = 1 } -AllowMissing -Action Create } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
        $script:calls.Count | Should -Be 0
    }

    It 'refuses the placeholder for Invoke and Check providers without -SkipSnapshot' {
        $target = @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'New hire' }
        { New-TenureStep -Provider 'Fake.PlanInvoke' -Target $target } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
        { New-TenureStep -Provider 'Fake.PlanCheck' -Target $target -Desired @{ a = 1 } } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
        $script:calls.Count | Should -Be 0
    }

    It 'accepts the placeholder in any letter case with -SkipSnapshot and -Action, without calling Get or Test' -ForEach @(
        @{ Id = '{{subjectId}}' }, @{ Id = '{{SUBJECTID}}' }
    ) {
        $target = @{ Kind = 'user'; Id = $Id; Name = 'New hire' }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target $target -Desired @{ a = 1 } -SkipSnapshot -Action Create
        $step.Target.Id | Should -Be $Id
        $step.Action | Should -Be 'Create'
        $script:calls.Count | Should -Be 0
    }

    It 'still reads a real id normally' {
        $script:state['u1'] = @{ a = 1 }
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 }).Action | Should -Be 'NoOp'
        @($script:calls | Where-Object { $_.Op -eq 'Get' }).Count | Should -Be 1
    }
}

Describe 'New-TenureStep: target, provider and key validation' {
    BeforeEach { Reset-PlanTestState }
    It 'rejects <Name> with Tenure.Step.InvalidTarget' -ForEach @(
        @{ Name = 'a missing Kind'; Target = @{ Id = 'u1'; Name = 'x' } }
        @{ Name = 'an unknown Kind'; Target = @{ Kind = 'planet'; Id = 'u1'; Name = 'x' } }
        @{ Name = 'a wrong-case Kind'; Target = @{ Kind = 'User'; Id = 'u1'; Name = 'x' } }
        @{ Name = 'a missing Id'; Target = @{ Kind = 'user'; Name = 'x' } }
        @{ Name = 'an empty Id'; Target = @{ Kind = 'user'; Id = ''; Name = 'x' } }
        @{ Name = 'a null Id'; Target = @{ Kind = 'user'; Id = $null; Name = 'x' } }
        @{ Name = 'a numeric Id'; Target = @{ Kind = 'user'; Id = 5; Name = 'x' } }
        @{ Name = 'a missing Name'; Target = @{ Kind = 'user'; Id = 'u1' } }
        @{ Name = 'an empty Name'; Target = @{ Kind = 'user'; Id = 'u1'; Name = '' } }
    ) {
        { New-TenureStep -Provider 'Fake.PlanState' -Target $Target -Desired @{ a = 1 } -SkipSnapshot -Action Create } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
    }

    It 'accepts each allowed target kind for a provider that acts on it' -ForEach @(
        @{ Kind = 'user' }, @{ Kind = 'group' }, @{ Kind = 'device' }, @{ Kind = 'mailbox' }, @{ Kind = 'drive' }, @{ Kind = 'role' }
    ) {
        Register-Fake (New-FakeProviderDefinition -Name 'Fake.KindProbe' -State $script:state -Overrides @{ TargetKind = $Kind })
        try {
            $step = New-TenureStep -Provider 'Fake.KindProbe' -Target @{ Kind = $Kind; Id = '6d000000-0000-4000-8000-0000000000a1'; Name = 'x' } -Desired @{ a = 1 } -SkipSnapshot -Action Create
            $step.Target.Kind | Should -Be $Kind
        } finally {
            Invoke-InTenure { Unregister-TenureProvider -Name 'Fake.KindProbe' }
        }
    }

    It 'refuses a target whose Kind is not the one the provider acts on' -ForEach @(
        @{ Kind = 'group' }, @{ Kind = 'device' }, @{ Kind = 'mailbox' }, @{ Kind = 'drive' }, @{ Kind = 'role' }
    ) {
        { New-TenureStep -Provider 'Fake.PlanState' -Target @{ Kind = $Kind; Id = 'x1'; Name = 'x' } -Desired @{ a = 1 } -SkipSnapshot -Action Create } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
    }

    It 'refuses an -Action the provider does not allow' {
        Register-Fake (New-FakeProviderDefinition -Name 'Fake.RemoveOnly' -State $script:state -Overrides @{ Actions = @('Remove', 'NoOp') })
        try {
            { New-TenureStep -Provider 'Fake.RemoveOnly' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Create } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
        } finally {
            Invoke-InTenure { Unregister-TenureProvider -Name 'Fake.RemoveOnly' }
        }
    }

    It 'keeps extra keys on the target' {
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target @{ Kind = 'user'; Id = 'u1'; Name = 'x'; Mail = 'a@example.com' } -Desired @{ a = 1 } -SkipSnapshot -Action Create
        $step.Target.Mail | Should -Be 'a@example.com'
    }

    It 'throws Tenure.Provider.NotRegistered for an unknown provider' {
        { New-TenureStep -Provider 'Nope.Thing' -Target (New-UserTarget) -Desired @{ a = 1 } } | Should -Throw -ErrorId 'Tenure.Provider.NotRegistered'
    }

    It 'uses a guid as the default Key and the given Key otherwise' {
        $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Create
        $two = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Create
        [guid]::Parse($one.Key) | Should -Not -BeNullOrEmpty
        $one.Key | Should -Not -Be $two.Key
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Create -Key 'mine').Key | Should -Be 'mine'
    }

    It 'rejects an empty -Key' {
        { New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Create -Key ' ' } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
    }
}

Describe 'New-TenureStep: risk, reason and shape' {
    BeforeEach { Reset-PlanTestState; $script:state['u1'] = @{ a = 1 } }

    It 'raises risk with -Risk' {
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Risk High).Risk | Should -Be 'High'
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Risk Destructive).Risk | Should -Be 'Destructive'
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 }).Risk | Should -Be 'Low'
    }

    It 'never lowers risk and says so in the verbose stream' {
        $output = New-TenureStep -Provider 'Fake.PlanRisky' -Target (New-UserTarget) -Desired @{ a = 2 } -Risk Medium -Verbose 4>&1
        $step = $output | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] }
        $verbose = @($output | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] })
        $step.Risk | Should -Be 'High'
        @($verbose | Where-Object { $_.Message -match 'Ignoring -Risk Medium' }).Count | Should -Be 1
    }

    It 'uses -Reason when given and Describe otherwise' {
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Reason 'Because policy').Reason | Should -Be 'Because policy'
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 }).Reason | Should -Be 'Update Ada Lovelace: a=2'
        (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Reason '').Reason | Should -Be 'Update Ada Lovelace: a=2'
    }

    It 'returns a Tenure.Step with exactly the SPEC 2.3 fields plus Key' {
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -DependsOn 'k1', 'k2'
        $step.PSObject.TypeNames[0] | Should -Be 'Tenure.Step'
        @($step.PSObject.Properties.Name) | Should -Be @('Id', 'Key', 'Provider', 'Kind', 'Target', 'Action', 'Before', 'After', 'Fingerprint', 'Risk', 'Reversible', 'Reason', 'DependsOn', 'Status', 'Result')
        $step.Id | Should -BeNullOrEmpty
        $step.Provider | Should -Be 'Fake.PlanState'
        $step.Kind | Should -Be 'State'
        $step.Status | Should -Be 'Pending'
        $step.Result | Should -BeNullOrEmpty
        , $step.DependsOn | Should -BeOfType [string[]]
        $step.DependsOn | Should -Be @('k1', 'k2')
        $step.Target | Should -BeOfType [hashtable]
    }

    It 'gives a string[] DependsOn even with no dependencies' {
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 }
        , $step.DependsOn | Should -BeOfType [string[]]
        @($step.DependsOn).Count | Should -Be 0
    }

    It 'fills missing Context keys with defaults and passes caller keys through' {
        $null = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -Context @{ Subject = 'sentinel' }
        $context = ($script:calls | Where-Object { $_.Op -eq 'Get' } | Select-Object -First 1).Context
        $context.Subject | Should -Be 'sentinel'
        $context.Mode | Should -Be 'Plan'
        $context.ContainsKey('Policy') | Should -BeTrue
        $context.Policy | Should -BeNullOrEmpty
        $context.ContainsKey('Session') | Should -BeTrue
        $context.Secrets | Should -BeOfType [hashtable]
        $context.Secrets.Count | Should -Be 0
    }

    It 'does not share Target or Desired with the caller' {
        $target = New-UserTarget
        $desired = @{ a = 2; nested = @{ b = 1 } }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target $target -Desired $desired
        $target['Name'] = 'changed'
        $desired['nested']['b'] = 99
        $step.Target.Name | Should -Be 'Ada Lovelace'
        $step.After.nested.b | Should -Be 1
    }
}

Describe 'Ordered dictionaries in steps and plans' {
    BeforeEach { Reset-PlanTestState }

    It 'New-TenureStep accepts an [ordered] Desired, keeps its order and does not share it with the caller' {
        $desired = [ordered]@{ zeta = 1; alpha = [ordered]@{ y = 2; x = 1 }; mid = @(3, 2, 1) }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired $desired -SkipSnapshot -Action Create
        $step.After | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        @($step.After.Keys) | Should -Be @('zeta', 'alpha', 'mid')
        $step.After['alpha'] | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        @($step.After['alpha'].Keys) | Should -Be @('y', 'x')
        [object]::ReferenceEquals($step.After, $desired) | Should -BeFalse
        $desired['alpha']['x'] = 99
        $step.After['alpha']['x'] | Should -Be 1
    }

    It 'New-TenureStep accepts an [ordered] Target' {
        $target = [ordered]@{ Kind = 'user'; Id = 'u1'; Name = 'Ada Lovelace'; Mail = 'ada@example.com' }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target $target -Desired @{ a = 1 } -SkipSnapshot -Action Create
        $step.Target.Id | Should -Be 'u1'
        $step.Target.Mail | Should -Be 'ada@example.com'
        $target['Name'] = 'changed'
        $step.Target.Name | Should -Be 'Ada Lovelace'
    }

    It 'New-TenureStep accepts an [ordered] nested inside a hashtable Desired and inside an array' {
        $desired = @{ outer = @{ inner = [ordered]@{ b = 2; a = 1 } }; list = @([ordered]@{ n = 1 }, @{ n = 2 }) }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired $desired -SkipSnapshot -Action Create
        @($step.After.outer.inner.Keys) | Should -Be @('b', 'a')
        $step.After.list[0].n | Should -Be 1
        $desired['outer']['inner']['a'] = 99
        $step.After.outer.inner.a | Should -Be 1
    }

    It 'New-TenureStep accepts the ordinal OrderedDictionary that canonical JSON produces, keeping keys that differ by case' {
        $canonical = Invoke-InTenure { ConvertTo-TenureCanonical -InputObject @{ b = 1; a = @{ c = 2 } } }
        $canonical | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired $canonical -SkipSnapshot -Action Create
        @($step.After.Keys) | Should -Be @('a', 'b')
        $step.After['a']['c'] | Should -Be 2

        $ordinal = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
        $ordinal['B'] = 1
        $ordinal['b'] = 2
        $both = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired $ordinal -SkipSnapshot -Action Create
        @($both.After.Keys) | Should -Be @('B', 'b')
        $both.After['B'] | Should -Be 1
        $both.After['b'] | Should -Be 2
    }

    It 'New-TenurePlan copies a step whose After, Before and Target are ordered dictionaries, and the plan survives Export and Import' {
        $ordinal = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
        $ordinal['zeta'] = 1
        $ordinal['Alpha'] = [ordered]@{ k = 'v' }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired $ordinal -SkipSnapshot -Action Create
        $step.Before = [ordered]@{ was = 'old'; nested = [ordered]@{ n = 1 } }
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step
        @($plan.Steps[0].After.Keys) | Should -Be @('zeta', 'Alpha')
        @($plan.Steps[0].Before.Keys) | Should -Be @('was', 'nested')
        [object]::ReferenceEquals($plan.Steps[0].Before, $step.Before) | Should -BeFalse
        $step.Before['was'] = 'changed'
        $plan.Steps[0].Before['was'] | Should -Be 'old'

        $file = Join-Path $TestDrive ('ordered-' + [guid]::NewGuid().ToString('N') + '.json')
        Export-TenurePlan -Plan $plan -Path $file
        Get-Canonical (Import-TenurePlan -Path $file) | Should -Be (Get-Canonical $plan)
    }

    It 'Copy-TenureValue rebuilds <Name> without relying on Clone, keeping type, order and case sensitivity' -ForEach @(
        @{ Name = 'an [ordered] dictionary'; Make = { [ordered]@{ b = 1; a = 2; c = 3 } }; Type = [System.Collections.Specialized.OrderedDictionary]; Keys = @('b', 'a', 'c') }
        @{ Name = 'an empty [ordered] dictionary'; Make = { [ordered]@{} }; Type = [System.Collections.Specialized.OrderedDictionary]; Keys = @() }
        @{ Name = 'a hashtable'; Make = { @{ only = 1 } }; Type = [hashtable]; Keys = @('only') }
        @{ Name = 'a generic dictionary'; Make = { $d = [System.Collections.Generic.Dictionary[string, object]]::new(); $d['x'] = 1; $d['y'] = 2; $d }; Type = [System.Collections.Specialized.OrderedDictionary]; Keys = @('x', 'y') }
    ) {
        $source = & $Make
        $copy = Invoke-InTenure { param($v) Copy-TenureValue -InputObject $v } @($source)
        , $copy | Should -BeOfType $Type
        [object]::ReferenceEquals($copy, $source) | Should -BeFalse
        @($copy.Keys | Sort-Object) | Should -Be @($Keys | Sort-Object)
        if ($Type -eq [System.Collections.Specialized.OrderedDictionary]) { @($copy.Keys) | Should -Be $Keys }
    }

    It 'Copy-TenureValue keeps keys that differ only by case in an ordinal dictionary and in an ordinal hashtable' {
        $ordinalHashtable = [hashtable]::new([System.StringComparer]::Ordinal)
        $ordinalHashtable['K'] = 1
        $ordinalHashtable['k'] = 2
        $copy = Invoke-InTenure { param($v) Copy-TenureValue -InputObject $v } @($ordinalHashtable)
        $copy.Count | Should -Be 2
        $copy['K'] | Should -Be 1
        $copy['k'] | Should -Be 2

        $ordinalGeneric = [System.Collections.Generic.Dictionary[string, object]]::new()
        $ordinalGeneric['K'] = 1
        $ordinalGeneric['k'] = 2
        $copyGeneric = Invoke-InTenure { param($v) Copy-TenureValue -InputObject $v } @($ordinalGeneric)
        $copyGeneric.Count | Should -Be 2
    }

    It 'Copy-TenureValue keeps an [ordered] dictionary case-insensitive, like the original' {
        $copy = Invoke-InTenure { param($v) Copy-TenureValue -InputObject $v } @([ordered]@{ Name = 'x' })
        $copy.Contains('name') | Should -BeTrue
        $copy['NAME'] | Should -Be 'x'
    }

    It 'Copy-TenureValue handles an ordered dictionary with non-string keys without confusing keys and indexes' {
        $source = [System.Collections.Specialized.OrderedDictionary]::new()
        $source.Add(5, 'five')
        $source.Add(1, 'one')
        $copy = Invoke-InTenure { param($v) Copy-TenureValue -InputObject $v } @($source)
        @($copy.Keys) | Should -Be @(5, 1)
        @($copy.Values) | Should -Be @('five', 'one')
    }
}

Describe 'Get-TenureStepFingerprint' {
    BeforeEach { Reset-PlanTestState }

    It 'is never empty: with no Before it binds the target as absent' {
        $absent = Get-StepFingerprint (New-UserTarget) $null
        $absent | Should -Match '^[0-9a-f]{64}$'
        $absent | Should -Be (Get-Hash @{ Target = @{ Kind = 'user'; Id = 'u1' }; Before = $null })
        $absent | Should -Not -Be (Get-StepFingerprint (New-UserTarget -TargetId 'u2') $null)
    }

    It 'is the SHA-256 of the canonical JSON of the target Kind and Id plus Before' {
        $before = [pscustomobject]@{ displayName = 'Ada'; nested = @{ b = 2; a = 1 } }
        $fingerprint = Get-StepFingerprint (New-UserTarget) $before
        $fingerprint | Should -Match '^[0-9a-f]{64}$'
        $fingerprint | Should -Be (Get-Hash @{ Target = @{ Kind = 'user'; Id = 'u1' }; Before = $before })
    }

    It 'differs when the same Before belongs to a different Target.Id' {
        $before = [pscustomobject]@{ displayName = 'Ada' }
        $one = Get-StepFingerprint @{ Kind = 'user'; Id = 'u1'; Name = 'Ada' } $before
        $two = Get-StepFingerprint @{ Kind = 'user'; Id = 'u2'; Name = 'Ada' } $before
        $two | Should -Not -Be $one
    }

    It 'differs when the same Before and Id belong to a different Target.Kind' {
        $before = [pscustomobject]@{ displayName = 'Ada' }
        (Get-StepFingerprint @{ Kind = 'user'; Id = 'x1'; Name = 'n' } $before) | Should -Not -Be (Get-StepFingerprint @{ Kind = 'group'; Id = 'x1'; Name = 'n' } $before)
    }

    It 'is the same when only Target.Name (display text) or other extra target keys differ' {
        $before = [pscustomobject]@{ displayName = 'Ada' }
        $one = Get-StepFingerprint @{ Kind = 'user'; Id = 'u1'; Name = 'Ada Lovelace' } $before
        $two = Get-StepFingerprint @{ Kind = 'user'; Id = 'u1'; Name = 'Someone Else'; Mail = 'x@example.com' } $before
        $two | Should -Be $one
    }

    It 'differs when Before differs' {
        (Get-StepFingerprint (New-UserTarget) ([pscustomobject]@{ a = 1 })) | Should -Not -Be (Get-StepFingerprint (New-UserTarget) ([pscustomobject]@{ a = 2 }))
    }

    It 'does not depend on key order, on hashtable versus PSCustomObject, or on target key order' {
        $plain = Get-StepFingerprint @{ Kind = 'user'; Id = 'u1'; Name = 'n' } ([pscustomobject]@{ zeta = 1; alpha = @{ y = 2; x = 1 }; mid = @(3, 2, 1) })
        $shuffled = Get-StepFingerprint ([ordered]@{ Name = 'n'; Id = 'u1'; Kind = 'user' }) ([ordered]@{ mid = @(3, 2, 1); alpha = [ordered]@{ x = 1; y = 2 }; zeta = 1 })
        $shuffled | Should -Be $plain
    }

    It 'refuses a SecureString in Before (never hashes a secret)' {
        $secret = ConvertTo-SecureString -String 'not-a-real-secret' -AsPlainText -Force
        { Get-StepFingerprint (New-UserTarget) ([pscustomobject]@{ pw = $secret }) } | Should -Throw -ErrorId 'Tenure.Json.SecretRejected'
    }

    It 'tolerates a target without Kind or Id instead of failing on a missing property' {
        Get-StepFingerprint @{ Name = 'n' } ([pscustomobject]@{ a = 1 }) | Should -Match '^[0-9a-f]{64}$'
    }

    Context 'as used by New-TenureStep' {
        It 'gives the step the helper fingerprint of its own Target and Before' {
            $script:state['u1'] = @{ displayName = 'Ada'; department = 'Eng' }
            $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ displayName = 'Grace' }
            $step.Fingerprint | Should -Be (Get-StepFingerprint $step.Target $step.Before)
            $step.Fingerprint | Should -Not -Be (Get-Hash $step.Before) -Because 'the old Before-only hash is gone'
        }

        It 'gives two targets with identical state different fingerprints' {
            $script:state['u1'] = @{ displayName = 'Ada' }
            $script:state['u2'] = @{ displayName = 'Ada' }
            $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget -TargetId 'u1') -Desired @{ displayName = 'Grace' }
            $two = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget -TargetId 'u2') -Desired @{ displayName = 'Grace' }
            $two.Fingerprint | Should -Not -Be $one.Fingerprint
        }

        It 'binds the target as absent for -SkipSnapshot and for a missing target allowed by -AllowMissing' {
            $absent = Get-StepFingerprint (New-UserTarget) $null
            (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Create).Fingerprint | Should -Be $absent
            (New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -AllowMissing).Fingerprint | Should -Be $absent
        }

        It 'does not change when only the display Name of the target changes' {
            $script:state['u1'] = @{ displayName = 'Ada' }
            $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget -TargetName 'Ada Lovelace') -Desired @{ displayName = 'Grace' }
            $two = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget -TargetName 'Renamed') -Desired @{ displayName = 'Grace' }
            $two.Fingerprint | Should -Be $one.Fingerprint
        }

        It 'survives the plan copy unchanged' {
            $script:state['u1'] = @{ displayName = 'Ada' }
            $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ displayName = 'Grace' }
            $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step
            $plan.Steps[0].Fingerprint | Should -Be $step.Fingerprint
            Get-StepFingerprint $plan.Steps[0].Target $plan.Steps[0].Before | Should -Be $plan.Steps[0].Fingerprint
        }
    }

    Context 'an edited plan file' {
        It 'no longer matches its fingerprint when a step is retargeted by changing Target.Id (Name and Fingerprint kept)' {
            $script:state['u1'] = @{ displayName = 'Ada' }
            $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ displayName = 'Grace' }
            $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step
            $file = Join-Path $TestDrive ('retarget-' + [guid]::NewGuid().ToString('N') + '.json')
            Export-TenurePlan -Plan $plan -Path $file

            $honest = Import-TenurePlan -Path $file
            Get-StepFingerprint $honest.Steps[0].Target $honest.Steps[0].Before | Should -Be $honest.Steps[0].Fingerprint

            $edited = (Get-Content -LiteralPath $file -Raw) -replace '"Id": "u1"', '"Id": "u-victim"'
            $edited | Should -Not -Be (Get-Content -LiteralPath $file -Raw) -Because 'the edit must change the file'
            $editedFile = Join-Path $TestDrive ('retargeted-' + [guid]::NewGuid().ToString('N') + '.json')
            [System.IO.File]::WriteAllText($editedFile, $edited)
            { Import-TenurePlan -Path $editedFile } | Should -Throw -ErrorId 'Tenure.Plan.Tampered' -Because 'the integrity value covers the target'
            # Behind the integrity check, the fingerprint is the second line: it no longer matches either.
            $model = Get-Content -LiteralPath $editedFile -Raw | ConvertFrom-Json -AsHashtable
            $model.Steps[0].Target.Id | Should -Be 'u-victim'
            $model.Steps[0].Fingerprint | Should -Be $honest.Steps[0].Fingerprint
            Get-StepFingerprint $model.Steps[0].Target ([pscustomobject]$model.Steps[0].Before) | Should -Not -Be $model.Steps[0].Fingerprint
        }
    }
}

Describe 'New-TenurePlan' {
    BeforeEach { Reset-PlanTestState; $script:state['u1'] = @{ a = 1 } }

    It 'assigns ids in order and rewrites DependsOn from keys to ids' {
        $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Key 'one'
        $two = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 3 } -Key 'two' -DependsOn 'one'
        $three = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 4 } -Key 'three' -DependsOn 'one', 'two'
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $one, $two, $three
        @($plan.Steps | ForEach-Object Id) | Should -Be @('S01', 'S02', 'S03')
        @($plan.Steps[0].DependsOn).Count | Should -Be 0
        $plan.Steps[1].DependsOn | Should -Be @('S01')
        $plan.Steps[2].DependsOn | Should -Be @('S01', 'S02')
        , $plan.Steps[2].DependsOn | Should -BeOfType [string[]]
        @($plan.Steps | ForEach-Object Key) | Should -Be @('one', 'two', 'three')
    }

    It 'does not modify the steps it is given, so the same steps can build another plan' {
        $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Key 'one'
        $two = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 3 } -Key 'two' -DependsOn 'one'
        $first = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $one, $two
        $second = New-TenurePlan -Operation Offboard -Subject (New-SubjectTable) -Step $one, $two
        $one.Id | Should -BeNullOrEmpty
        $two.DependsOn | Should -Be @('one')
        $second.Steps[1].DependsOn | Should -Be @('S01')
        $first.PlanId | Should -Not -Be $second.PlanId
        $first.Steps[0].Target['Name'] = 'changed'
        $second.Steps[0].Target.Name | Should -Be 'Ada Lovelace'
        $one.Target.Name | Should -Be 'Ada Lovelace'
    }

    It 'numbers past 99 as S100' {
        $steps = foreach ($i in 1..101) { New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = $i } -SkipSnapshot -Action Create -Key "k$i" }
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $steps
        $plan.Steps[98].Id | Should -Be 'S99'
        $plan.Steps[99].Id | Should -Be 'S100'
        $plan.Steps[100].Id | Should -Be 'S101'
    }

    It 'accepts an empty step list' {
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @()
        @($plan.Steps).Count | Should -Be 0
        , $plan.Steps | Should -BeOfType [object[]]
    }

    It 'refuses a dependency on a later step' {
        $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Key 'one' -DependsOn 'two'
        $two = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 3 } -Key 'two'
        { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $one, $two } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
    }

    It 'refuses a dependency on itself' {
        $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Key 'one' -DependsOn 'one'
        { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $one } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
    }

    It 'refuses a dependency on an unknown key and names the key' {
        $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Key 'one' -DependsOn 'ghost'
        $thrown = Get-ThrownError { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $one }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Message | Should -Match 'ghost'
    }

    It 'refuses duplicate step keys' {
        $one = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Key 'same'
        $two = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 3 } -Key 'same'
        { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $one, $two } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
    }

    It 'refuses something that is not a Tenure.Step' {
        { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step ([pscustomobject]@{ Key = 'x' }) } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
    }

    It 'refuses Inputs that contain a SecureString, however deep' {
        $secret = ConvertTo-SecureString -String 'not-a-real-secret' -AsPlainText -Force
        $thrown = Get-ThrownError { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @() -Inputs @{ outer = @{ inner = @(1, @{ pw = $secret }) } } }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Message | Should -Match 'secrets'
    }

    It 'refuses Inputs that contain a PSCredential' {
        $credential = [pscredential]::new('user', (ConvertTo-SecureString -String 'x' -AsPlainText -Force))
        { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @() -Inputs @{ cred = $credential } } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
    }

    Context 'secrets inside steps' {
        BeforeAll { $script:secret = ConvertTo-SecureString -String 'not-a-real-secret' -AsPlainText -Force }

        It 'refuses a SecureString in a step After, however deep, naming the step key' {
            $clean = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 } -Key 'clean'
            $dirty = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ outer = @{ list = @(1, @{ pw = $script:secret }) } } -Key 'dirty'
            $thrown = Get-ThrownError { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $clean, $dirty }
            $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
            $thrown.Exception.Message | Should -Match 'Steps may not contain secrets'
            $thrown.Exception.Message | Should -Match "'dirty'"
        }

        It 'refuses a PSCredential in a step After' {
            $credential = [pscredential]::new('user', $script:secret)
            $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ cred = $credential } -Key 'cred'
            { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        }

        It 'refuses a SecureString in an extra Target key' {
            $target = @{ Kind = 'user'; Id = 'u1'; Name = 'x'; Token = $script:secret }
            $step = New-TenureStep -Provider 'Fake.PlanState' -Target $target -Desired @{ a = 1 } -SkipSnapshot -Action Create
            { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        }

        It 'refuses a SecureString placed in <Field> after the step was built' -ForEach @(
            @{ Field = 'Before' }, @{ Field = 'Reason' }, @{ Field = 'Result' }
        ) {
            $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 1 } -SkipSnapshot -Action Create
            $step.$Field = switch ($Field) {
                'Before' { [pscustomobject]@{ pw = $script:secret } }
                'Reason' { $script:secret }
                'Result' { @{ Observed = [pscustomobject]@{ pw = $script:secret } } }
            }
            $thrown = Get-ThrownError { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step }
            $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
            $thrown.Exception.Message | Should -Match 'Steps may not contain secrets'
        }

        It 'does not build a plan object at all when a step holds a secret' {
            $dirty = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ pw = $script:secret } -SkipSnapshot -Action Create
            $plan = $null
            try { $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $dirty } catch { $null = $_ }
            $plan | Should -BeNullOrEmpty
        }

        It 'still accepts steps that carry ordinary text, including the word password' {
            $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ passwordPolicy = 'reset required' } -SkipSnapshot -Action Create -Reason 'password reset'
            (New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step).Steps.Count | Should -Be 1
        }
    }

    It 'rejects an unknown Operation' {
        { New-TenurePlan -Operation Explode -Subject (New-SubjectTable) -Step @() } | Should -Throw
    }

    It 'requires Id, UserPrincipalName and DisplayName in Subject, and allows a null Id' {
        { New-TenurePlan -Operation Custom -Subject @{ Id = 'u1'; DisplayName = 'x' } -Step @() } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        { New-TenurePlan -Operation Custom -Subject @{ UserPrincipalName = 'a@example.com'; DisplayName = 'x' } -Step @() } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        { New-TenurePlan -Operation Custom -Subject @{ Id = 'u1'; UserPrincipalName = ''; DisplayName = 'x' } -Step @() } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        $plan = New-TenurePlan -Operation Onboard -Subject @{ Id = $null; UserPrincipalName = 'new@example.com'; DisplayName = 'New Hire' } -Step @()
        $plan.Subject.Id | Should -BeNullOrEmpty
        $plan.Subject.ContainsKey('Id') | Should -BeTrue
    }

    It 'returns a Tenure.Plan with exactly the SPEC 2.4 fields' {
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ a = 2 }
        $plan = New-TenurePlan -Operation RoleChange -Subject (New-SubjectTable) -Step $step -Inputs @{ role = 'sales' }
        $plan.PSObject.TypeNames[0] | Should -Be 'Tenure.Plan'
        @($plan.PSObject.Properties.Name) | Should -Be @('SchemaVersion', 'PlanId', 'CreatedAt', 'CreatedBy', 'ModuleVersion', 'Operation', 'Subject', 'PolicyHash', 'PolicySnapshot', 'Inputs', 'Steps', 'Warnings', 'Status', 'Integrity')
        $plan.SchemaVersion | Should -Be 2
        $plan.Integrity | Should -Be (Invoke-InTenure { param($p) Get-TenurePlanIntegrity -Plan $p } @($plan))
        $plan.PolicySnapshot | Should -BeNullOrEmpty -Because 'no -Policy was given'
        [guid]::Parse($plan.PlanId) | Should -Not -BeNullOrEmpty
        $plan.CreatedAt | Should -BeOfType [datetime]
        $plan.CreatedAt.Kind | Should -Be 'Utc'
        ([datetime]::UtcNow - $plan.CreatedAt).TotalMinutes | Should -BeLessThan 1
        $plan.ModuleVersion | Should -Be (Import-PowerShellDataFile $script:TenureManifest).ModuleVersion
        $plan.Operation | Should -Be 'RoleChange'
        $plan.Status | Should -Be 'Planned'
        $plan.PolicyHash | Should -BeNullOrEmpty
        $plan.Inputs.role | Should -Be 'sales'
        , $plan.Warnings | Should -BeOfType [string[]]
        @($plan.Warnings).Count | Should -Be 0
        $plan.Subject | Should -BeOfType [hashtable]
        @($plan.Subject.Keys | Sort-Object) | Should -Be @('DisplayName', 'Id', 'UserPrincipalName')
        $plan.Steps[0].PSObject.TypeNames[0] | Should -Be 'Tenure.Step'
    }

    It 'records warnings' {
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @() -Warning 'one', 'two'
        $plan.Warnings | Should -Be @('one', 'two')
    }

    It 'reports (not connected) in CreatedBy without a session' {
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @()
        $plan.CreatedBy.Account | Should -Be '(not connected)'
        $plan.CreatedBy.TenantId | Should -BeNullOrEmpty
        $plan.CreatedBy.AuthType | Should -BeNullOrEmpty
        $plan.CreatedBy.ContainsKey('TenantId') | Should -BeTrue
    }

    It 'takes CreatedBy from the session when connected' {
        Set-TenureTestSession -Account 'admin@example.com' -TenantId '00000000-0000-0000-0000-00000000beef'
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @()
        $plan.CreatedBy.Account | Should -Be 'admin@example.com'
        $plan.CreatedBy.TenantId | Should -Be '00000000-0000-0000-0000-00000000beef'
        $plan.CreatedBy.AuthType | Should -Be 'Test'
    }

    It 'records the policy hash from a Tenure.Policy or a policy path' {
        $policy = Get-TenurePolicy -Path $script:ExamplePath
        (New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @() -Policy $policy).PolicyHash | Should -Be $policy.Hash
        (New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @() -Policy $script:ExamplePath).PolicyHash | Should -Be $policy.Hash
        { New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @() -Policy 42 } | Should -Throw -ErrorId 'Tenure.Policy.Invalid'
    }

    It 'copies Inputs so later edits do not change the plan' {
        $inputs = @{ list = @('a'); nested = @{ k = 1 } }
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step @() -Inputs $inputs
        $inputs['nested']['k'] = 2
        $plan.Inputs.nested.k | Should -Be 1
    }
}

Describe 'Export-TenurePlan' {
    BeforeEach { Reset-PlanTestState; $script:plan = New-SamplePlan }

    It 'writes the plan through the temporary file writer, which flushes to disk before the rename' {
        $file = Join-Path $TestDrive 'flushed.json'
        Export-TenurePlan -Plan $script:plan -Path $file
        $temporary = Join-Path $TestDrive 'direct.tmp'
        Invoke-InTenure { param($p) Write-TenureTemporaryFile -Path $p -Text "x`n" } @($temporary)
        [System.IO.File]::ReadAllBytes($temporary) | Should -Be @(120, 10)
        { Invoke-InTenure { param($p) Write-TenureTemporaryFile -Path $p -Text 'y' } @($temporary) } | Should -Throw -Because 'a temporary name is never reused or overwritten'
        Mock -ModuleName Tenure Write-TenureTemporaryFile { [System.IO.File]::WriteAllText($Path, $Text) }
        Export-TenurePlan -Plan $script:plan -Path (Join-Path $TestDrive 'mocked.json')
        Should -Invoke -ModuleName Tenure -CommandName Write-TenureTemporaryFile -Times 1 -Exactly
        Invoke-InTenure { param($p, $f) Save-TenurePlanFile -Plan $p -Path $f } @($script:plan, (Join-Path $TestDrive 'saved.json'))
        Should -Invoke -ModuleName Tenure -CommandName Write-TenureTemporaryFile -Times 2 -Exactly
        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.tmp' | Where-Object Name -ne 'direct.tmp').Count | Should -Be 0
    }

    It 'writes UTF-8 without a BOM, LF line endings and a trailing newline' {
        $file = Join-Path $TestDrive 'export.json'
        Export-TenurePlan -Plan $script:plan -Path $file
        $bytes = [System.IO.File]::ReadAllBytes($file)
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
        @($bytes | Where-Object { $_ -eq 13 }).Count | Should -Be 0
        $bytes[-1] | Should -Be 10
        $parsed = [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $parsed.SchemaVersion | Should -Be 2
        $parsed.Integrity | Should -Be $script:plan.Integrity
        @($parsed.Steps).Count | Should -Be 2
        $parsed.Steps[1].DependsOn | Should -Be @('S01')
    }

    It 'writes dates as UTC round-trip strings' {
        $file = Join-Path $TestDrive 'dates.json'
        Export-TenurePlan -Plan $script:plan -Path $file
        $text = Get-Content -LiteralPath $file -Raw
        $text | Should -Match '"CreatedAt": "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z"'
    }

    It 'produces the same bytes for the same plan' {
        $one = Join-Path $TestDrive 'same-1.json'
        $two = Join-Path $TestDrive 'same-2.json'
        Export-TenurePlan -Plan $script:plan -Path $one
        Export-TenurePlan -Plan $script:plan -Path $two
        [System.IO.File]::ReadAllBytes($one) | Should -Be ([System.IO.File]::ReadAllBytes($two))
    }

    It 'refuses to overwrite an existing file and leaves it untouched' {
        $file = Join-Path $TestDrive 'exists.json'
        Set-Content -LiteralPath $file -Value 'precious'
        { Export-TenurePlan -Plan $script:plan -Path $file } | Should -Throw -ErrorId 'Tenure.Plan.Exists'
        (Get-Content -LiteralPath $file -Raw).Trim() | Should -Be 'precious'
    }

    It 'overwrites with -Force and leaves no temporary file behind' {
        $folder = Join-Path $TestDrive 'force'
        $null = New-Item -ItemType Directory -Path $folder
        $file = Join-Path $folder 'plan.json'
        Set-Content -LiteralPath $file -Value 'old'
        Export-TenurePlan -Plan $script:plan -Path $file -Force
        (Get-Content -LiteralPath $file -Raw) | Should -Match 'SchemaVersion'
        @(Get-ChildItem -LiteralPath $folder).Count | Should -Be 1
    }

    It 'writes nothing with -WhatIf' {
        $file = Join-Path $TestDrive 'whatif.json'
        Export-TenurePlan -Plan $script:plan -Path $file -WhatIf
        Test-Path -LiteralPath $file | Should -BeFalse
    }

    It 'accepts the plan from the pipeline' {
        $file = Join-Path $TestDrive 'pipeline.json'
        $script:plan | Export-TenurePlan -Path $file
        Test-Path -LiteralPath $file | Should -BeTrue
    }

    It 'refuses a plan that holds a SecureString and writes no file' {
        # New-TenurePlan refuses secrets in steps, so inject one afterwards: the Export guard must hold on its own.
        $secret = ConvertTo-SecureString -String 'not-a-real-secret' -AsPlainText -Force
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired @{ password = 'placeholder' } -SkipSnapshot -Action Create
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step
        $plan.Steps[0].After['password'] = $secret
        $file = Join-Path $TestDrive 'secret.json'
        { Export-TenurePlan -Plan $plan -Path $file } | Should -Throw -ErrorId 'Tenure.Json.SecretRejected'
        Test-Path -LiteralPath $file | Should -BeFalse
    }

    It 'refuses a plan nested deeper than ConvertTo-Json depth 20 instead of truncating it' {
        $deep = @{ leaf = 1 }
        foreach ($i in 1..30) { $deep = @{ down = $deep } }
        $step = New-TenureStep -Provider 'Fake.PlanState' -Target (New-UserTarget) -Desired $deep -SkipSnapshot -Action Create
        $plan = New-TenurePlan -Operation Custom -Subject (New-SubjectTable) -Step $step
        $file = Join-Path $TestDrive 'deep.json'
        { Export-TenurePlan -Plan $plan -Path $file } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        Test-Path -LiteralPath $file | Should -BeFalse
    }

    It 'refuses something that is not a plan' {
        { Export-TenurePlan -Plan @{ a = 1 } -Path (Join-Path $TestDrive 'nope.json') } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        { Export-TenurePlan -Plan $null -Path (Join-Path $TestDrive 'nope.json') } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
    }

    It 'reports an unwritable location as Tenure.Plan.WriteFailed' {
        { Export-TenurePlan -Plan $script:plan -Path (Join-Path $TestDrive 'no-such-folder' 'plan.json') } | Should -Throw -ErrorId 'Tenure.Plan.WriteFailed'
    }

    It 'supports ShouldProcess with Medium impact' {
        $attribute = (Get-Command Export-TenurePlan).ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attribute.SupportsShouldProcess | Should -BeTrue
        $attribute.ConfirmImpact | Should -Be 'Medium'
    }
}

Describe 'Import-TenurePlan: refusals' {
    BeforeEach { Reset-PlanTestState }
    It 'throws Tenure.Plan.NotFound for a missing file' {
        { Import-TenurePlan -Path (Join-Path $TestDrive 'missing.json') } | Should -Throw -ErrorId 'Tenure.Plan.NotFound'
    }

    It 'throws Tenure.Plan.Invalid at $ for malformed JSON: <Name>' -ForEach @(
        @{ Name = 'truncated'; Text = '{ "SchemaVersion": 1, ' }
        @{ Name = 'empty'; Text = '' }
        @{ Name = 'a top-level array'; Text = '[1]' }
        @{ Name = 'a top-level string'; Text = '"plan"' }
    ) {
        $file = Join-Path $TestDrive 'bad.json'
        [System.IO.File]::WriteAllText($file, $Text)
        $thrown = Get-ThrownError { Import-TenurePlan -Path $file }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be '$'
    }

    It 'refuses a newer schema version (3) with Tenure.Plan.UnsupportedSchema' {
        $table = Get-MinimalPlan
        $table['SchemaVersion'] = 3
        { Import-TenurePlan -Path (Write-PlanFile $table) } | Should -Throw -ErrorId 'Tenure.Plan.UnsupportedSchema'
    }

    It 'refuses a schema 1 file from an earlier version: it has no integrity value, so it must be planned again' {
        $table = Get-MinimalPlan
        $table['SchemaVersion'] = 1
        $table.Remove('Integrity')
        $thrown = Get-ThrownError { Import-TenurePlan -Path (Write-PlanFile $table -NoSeal) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.UnsupportedSchema'
        $thrown.Exception.Message | Should -Match 'Build the plan again'
    }

    It 'refuses a file edited after it was built with Tenure.Plan.Tampered: <Name>' -ForEach @(
        @{ Name = 'a desired state'; Edit = { param($t) $t['Steps'][0]['After']['x'] = 2 } }
        @{ Name = 'a provider'; Edit = { param($t) $t['Steps'][1]['Provider'] = 'Fake.PlanRisky' } }
        @{ Name = 'an action'; Edit = { param($t) $t['Steps'][0]['Action'] = 'Remove' } }
        @{ Name = 'a target id'; Edit = { param($t) $t['Steps'][0]['Target']['Id'] = 'u2' } }
        @{ Name = 'a risk'; Edit = { param($t) $t['Steps'][0]['Risk'] = 'High' } }
        @{ Name = 'a reason'; Edit = { param($t) $t['Steps'][0]['Reason'] = 'harmless' } }
        @{ Name = 'a dependency removed'; Edit = { param($t) $t['Steps'][1]['DependsOn'] = @() } }
        @{ Name = 'a step removed'; Edit = { param($t) $t['Steps'] = @($t['Steps'][0]) } }
        @{ Name = 'two steps swapped'; Edit = { param($t) $a = $t['Steps'][0]; $b = $t['Steps'][1]; $a['Id'] = 'S02'; $b['Id'] = 'S01'; $b['DependsOn'] = @(); $a['DependsOn'] = @('S01'); $t['Steps'] = @($b, $a) } }
        @{ Name = 'the subject'; Edit = { param($t) $t['Subject']['UserPrincipalName'] = 'eve@example.com' } }
        @{ Name = 'the plan id'; Edit = { param($t) $t['PlanId'] = '99999999-2222-3333-4444-555555555555' } }
        @{ Name = 'the creation time'; Edit = { param($t) $t['CreatedAt'] = '2026-10-09T12:30:00.0000000Z' } }
        @{ Name = 'the tenant'; Edit = { param($t) $t['CreatedBy']['TenantId'] = '00000000-0000-0000-0000-0000000000aa' } }
        @{ Name = 'the recorded protected users'; Edit = { param($t) $t['PolicySnapshot'] = @{ ProtectedUsers = @(); ManagedSet = @{ Licenses = @(); Groups = @() } } } }
        @{ Name = 'the integrity value itself'; Edit = { param($t) $t['Integrity'] = ('f' * 64) } }
    ) {
        $table = Get-MinimalPlan
        Set-PlanTableIntegrity $table
        & $Edit $table
        { Import-TenurePlan -Path (Write-PlanFile $table -NoSeal) } | Should -Throw -ErrorId 'Tenure.Plan.Tampered'
    }

    It 'accepts edits to the fields the apply engine writes: statuses and results' {
        $table = Get-MinimalPlan
        Set-PlanTableIntegrity $table
        $table['Status'] = 'PartiallyApplied'
        $table['Steps'][0]['Status'] = 'Applied'
        $table['Steps'][0]['Result'] = @{ At = '2026-10-08T12:31:00.0000000Z'; DurationMs = 3; Observed = @{ x = 1 }; Error = $null; Note = 'ok'; Attempted = $true }
        (Import-TenurePlan -Path (Write-PlanFile $table -NoSeal)).Steps[0].Status | Should -Be 'Applied'
    }

    It 'checks the schema version before anything else' {
        $table = Get-MinimalPlan
        $table['SchemaVersion'] = 7
        $table.Remove('Steps')
        { Import-TenurePlan -Path (Write-PlanFile $table) } | Should -Throw -ErrorId 'Tenure.Plan.UnsupportedSchema'
    }

    It 'rejects a missing, zero or non-integer schema version' -ForEach @(
        @{ Value = $null; Remove = $true }, @{ Value = 0; Remove = $false }, @{ Value = '1'; Remove = $false }, @{ Value = 1.5; Remove = $false }, @{ Value = $true; Remove = $false }
    ) {
        $table = Get-MinimalPlan
        if ($Remove) { $table.Remove('SchemaVersion') } else { $table['SchemaVersion'] = $Value }
        $thrown = Get-ThrownError { Import-TenurePlan -Path (Write-PlanFile $table) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be '$.SchemaVersion'
    }

    It 'rejects a plan missing <Field>' -ForEach @(
        foreach ($field in 'PlanId', 'CreatedAt', 'CreatedBy', 'ModuleVersion', 'Operation', 'Subject', 'Steps', 'Status', 'Integrity') { @{ Field = $field } }
    ) {
        $table = Get-MinimalPlan
        $table.Remove($Field)
        $thrown = Get-ThrownError { Import-TenurePlan -Path (Write-PlanFile $table) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be ('$.' + $Field)
        $thrown.Exception.Message.StartsWith('$.' + $Field + ':') | Should -BeTrue
    }

    It 'rejects a step missing <Field>' -ForEach @(
        foreach ($field in 'Id', 'Provider', 'Kind', 'Target', 'Action', 'Fingerprint', 'Risk', 'Reversible', 'Status') { @{ Field = $field } }
    ) {
        $table = Get-MinimalPlan
        $table['Steps'][0].Remove($Field)
        $thrown = Get-ThrownError { Import-TenurePlan -Path (Write-PlanFile $table) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be ('$.Steps[0].' + $Field)
    }

    It 'rejects <Name> with the right path' -ForEach @(
        @{ Name = 'a bad Operation'; Edit = { param($t) $t['Operation'] = 'Explode' }; Path = '$.Operation' }
        @{ Name = 'a bad plan Status'; Edit = { param($t) $t['Status'] = 'Done' }; Path = '$.Status' }
        @{ Name = 'a bad PlanId'; Edit = { param($t) $t['PlanId'] = 'nope' }; Path = '$.PlanId' }
        @{ Name = 'a bad CreatedAt'; Edit = { param($t) $t['CreatedAt'] = 'yesterday' }; Path = '$.CreatedAt' }
        @{ Name = 'a string Steps'; Edit = { param($t) $t['Steps'] = 'none' }; Path = '$.Steps' }
        @{ Name = 'a non-object step'; Edit = { param($t) $t['Steps'][0] = 5 }; Path = '$.Steps[0]' }
        @{ Name = 'a bad step Action'; Edit = { param($t) $t['Steps'][0]['Action'] = 'Nuke' }; Path = '$.Steps[0].Action' }
        @{ Name = 'a bad step Risk'; Edit = { param($t) $t['Steps'][1]['Risk'] = 'Scary' }; Path = '$.Steps[1].Risk' }
        @{ Name = 'a bad step Status'; Edit = { param($t) $t['Steps'][1]['Status'] = 'Sleeping' }; Path = '$.Steps[1].Status' }
        @{ Name = 'a bad step Kind'; Edit = { param($t) $t['Steps'][0]['Kind'] = 'Magic' }; Path = '$.Steps[0].Kind' }
        @{ Name = 'a bad step Id'; Edit = { param($t) $t['Steps'][0]['Id'] = 's1' }; Path = '$.Steps[0].Id' }
        @{ Name = 'a bad Fingerprint'; Edit = { param($t) $t['Steps'][0]['Fingerprint'] = 'abc' }; Path = '$.Steps[0].Fingerprint' }
        @{ Name = 'an empty Fingerprint'; Edit = { param($t) $t['Steps'][0]['Fingerprint'] = '' }; Path = '$.Steps[0].Fingerprint' }
        @{ Name = 'a malformed Integrity'; Edit = { param($t) $t['Integrity'] = 'abc' }; Path = '$.Integrity' }
        @{ Name = 'a PolicySnapshot that is a string'; Edit = { param($t) $t['PolicySnapshot'] = 'none' }; Path = '$.PolicySnapshot' }
        @{ Name = 'protected users that are not strings'; Edit = { param($t) $t['PolicySnapshot'] = @{ ProtectedUsers = @(1); ManagedSet = @{ Licenses = @(); Groups = @() } } }; Path = '$.PolicySnapshot.ProtectedUsers[0]' }
        @{ Name = 'a non-boolean Reversible'; Edit = { param($t) $t['Steps'][0]['Reversible'] = 'yes' }; Path = '$.Steps[0].Reversible' }
        @{ Name = 'a bad target Kind'; Edit = { param($t) $t['Steps'][0]['Target']['Kind'] = 'planet' }; Path = '$.Steps[0].Target.Kind' }
        @{ Name = 'a subject without a UserPrincipalName'; Edit = { param($t) $t['Subject'].Remove('UserPrincipalName') }; Path = '$.Subject.UserPrincipalName' }
        @{ Name = 'a string Warnings'; Edit = { param($t) $t['Warnings'] = 'careful' }; Path = '$.Warnings' }
        @{ Name = 'a string Inputs'; Edit = { param($t) $t['Inputs'] = 'x' }; Path = '$.Inputs' }
    ) {
        $table = Get-MinimalPlan
        & $Edit $table
        $thrown = Get-ThrownError { Import-TenurePlan -Path (Write-PlanFile $table) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be $Path
    }

    It 'rejects duplicate step ids' {
        $table = Get-MinimalPlan
        $table['Steps'][1]['Id'] = 'S01'
        $thrown = Get-ThrownError { Import-TenurePlan -Path (Write-PlanFile $table) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be '$.Steps[1].Id'
    }

    It 'rejects a DependsOn that points forward, at itself or at an unknown step' -ForEach @(
        @{ Step = 0; Target = 'S02'; Path = '$.Steps[0].DependsOn[0]' }
        @{ Step = 1; Target = 'S02'; Path = '$.Steps[1].DependsOn[0]' }
        @{ Step = 1; Target = 'S09'; Path = '$.Steps[1].DependsOn[0]' }
    ) {
        $table = Get-MinimalPlan
        $table['Steps'][$Step]['DependsOn'] = @($Target)
        $thrown = Get-ThrownError { Import-TenurePlan -Path (Write-PlanFile $table) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be $Path
    }

    It 'rejects keys that differ only by case inside an object, because one value would be lost' {
        $json = (Get-Content -LiteralPath (Write-PlanFile (Get-MinimalPlan)) -Raw) -replace '"x": 1', '"x": 1, "X": 2'
        $file = Join-Path $TestDrive 'case.json'
        [System.IO.File]::WriteAllText($file, $json)
        $thrown = Get-ThrownError { Import-TenurePlan -Path $file }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be '$.Steps[0].After'
    }
}

Describe 'Import-TenurePlan: normalization' {
    BeforeEach { Reset-PlanTestState }
    It 'loads a minimal plan with types normalized' {
        $plan = Import-TenurePlan -Path (Write-PlanFile (Get-MinimalPlan))
        $plan.PSObject.TypeNames[0] | Should -Be 'Tenure.Plan'
        $plan.SchemaVersion | Should -Be 2
        $plan.Integrity | Should -Match '^[0-9a-f]{64}$'
        $plan.CreatedAt | Should -BeOfType [datetime]
        $plan.CreatedAt.Kind | Should -Be 'Utc'
        $plan.CreatedAt.ToString('o') | Should -Be '2026-10-08T12:30:00.0000000Z'
        $plan.Subject | Should -BeOfType [hashtable]
        $plan.CreatedBy | Should -BeOfType [hashtable]
        $plan.Inputs | Should -BeOfType [hashtable]
        , $plan.Warnings | Should -BeOfType [string[]]
        , $plan.Steps | Should -BeOfType [object[]]
        $plan.Steps[0].PSObject.TypeNames[0] | Should -Be 'Tenure.Step'
        $plan.Steps[0].Target | Should -BeOfType [hashtable]
        $plan.Steps[0].After | Should -BeOfType [hashtable]
        $plan.Steps[0].Before | Should -BeNullOrEmpty
        , $plan.Steps[0].DependsOn | Should -BeOfType [string[]]
        $plan.Steps[1].DependsOn | Should -Be @('S01')
        $plan.Steps[0].Status | Should -Be 'Pending'
    }

    It 'keeps Steps an array for one step and for none' {
        $one = Get-MinimalPlan
        $one['Steps'] = @($one['Steps'][0])
        $loaded = Import-TenurePlan -Path (Write-PlanFile $one -FileName 'one.json')
        , $loaded.Steps | Should -BeOfType [object[]]
        @($loaded.Steps).Count | Should -Be 1
        $none = Get-MinimalPlan
        $none['Steps'] = @()
        $empty = Import-TenurePlan -Path (Write-PlanFile $none -FileName 'none.json')
        , $empty.Steps | Should -BeOfType [object[]]
        @($empty.Steps).Count | Should -Be 0
    }

    It 'fills absent optional parts with empty values' {
        $table = Get-MinimalPlan
        foreach ($name in 'Warnings', 'Inputs', 'PolicyHash') { $table.Remove($name) }
        foreach ($step in $table['Steps']) { foreach ($name in 'DependsOn', 'Key', 'Reason', 'Before', 'After', 'Result') { $step.Remove($name) } }
        $plan = Import-TenurePlan -Path (Write-PlanFile $table)
        , $plan.Warnings | Should -BeOfType [string[]]
        @($plan.Warnings).Count | Should -Be 0
        $plan.Inputs | Should -BeOfType [hashtable]
        $plan.Inputs.Count | Should -Be 0
        $plan.PolicyHash | Should -BeNullOrEmpty
        $step = $plan.Steps[1]
        , $step.DependsOn | Should -BeOfType [string[]]
        @($step.DependsOn).Count | Should -Be 0
        $step.PSObject.Properties['Key'] | Should -Not -BeNullOrEmpty
        $step.Key | Should -BeNullOrEmpty
        $step.Reason | Should -Be ''
        $step.Result | Should -BeNullOrEmpty
    }

    It 'matches plan and step property names without regard to case' {
        $text = (Get-Content -LiteralPath (Write-PlanFile (Get-MinimalPlan)) -Raw) -replace '"SchemaVersion"', '"schemaVersion"' -replace '"Steps"', '"steps"' -replace '"DependsOn"', '"dependsOn"'
        $file = Join-Path $TestDrive 'camel.json'
        [System.IO.File]::WriteAllText($file, $text)
        $plan = Import-TenurePlan -Path $file
        @($plan.Steps).Count | Should -Be 2
        $plan.Steps[1].DependsOn | Should -Be @('S01')
    }

    It 'turns a Result into a hashtable with a PSCustomObject Observed' {
        $table = Get-MinimalPlan
        $table['Status'] = 'PartiallyApplied'
        $table['Steps'][0]['Status'] = 'Applied'
        $table['Steps'][0]['Result'] = @{ At = '2026-10-08T12:31:00.0000000Z'; DurationMs = 12; Observed = @{ displayName = 'Grace'; nested = @{ n = 1 } }; Error = $null; Note = 'ok' }
        $plan = Import-TenurePlan -Path (Write-PlanFile $table)
        $result = $plan.Steps[0].Result
        $result | Should -BeOfType [hashtable]
        $result.DurationMs | Should -Be 12
        $result.Note | Should -Be 'ok'
        $result.Observed | Should -BeOfType [pscustomobject]
        $result.Observed.nested | Should -BeOfType [pscustomobject]
        $result.Observed.nested.n | Should -Be 1
        $plan.Status | Should -Be 'PartiallyApplied'
    }

    It 'turns Result.At <Text> into the UTC instant <Expected>' -ForEach @(
        @{ Text = '2026-10-08T12:31:00.1234567Z'; Expected = '2026-10-08T12:31:00.1234567Z' }
        @{ Text = '2026-10-08T14:31:00+02:00'; Expected = '2026-10-08T12:31:00.0000000Z' }
        @{ Text = '2026-10-08T12:31:00'; Expected = '2026-10-08T12:31:00.0000000Z' }
        @{ Text = '2026-10-08'; Expected = '2026-10-08T00:00:00.0000000Z' }
    ) {
        $table = Get-MinimalPlan
        $table['Steps'][0]['Status'] = 'Applied'
        $table['Steps'][0]['Result'] = @{ At = $Text; DurationMs = 1; Observed = $null; Error = $null; Note = '' }
        $planFile = Write-PlanFile $table -FileName ('at-' + [guid]::NewGuid().ToString('N') + '.json')
        $json = Get-Content -LiteralPath $planFile -Raw
        $json | Should -Match ([regex]::Escape('"At": "' + $Text + '"')) -Because 'the file must hold the exact text under test'
        $at = (Import-TenurePlan -Path $planFile).Steps[0].Result.At
        $at | Should -BeOfType [datetime]
        $at.Kind | Should -Be 'Utc'
        $at.ToString('o') | Should -Be $Expected
    }

    It 'leaves a null Result.At and an absent one alone' {
        $table = Get-MinimalPlan
        $table['Steps'][0]['Result'] = @{ At = $null; DurationMs = 1 }
        $table['Steps'][1]['Result'] = @{ DurationMs = 2 }
        $plan = Import-TenurePlan -Path (Write-PlanFile $table)
        $plan.Steps[0].Result.At | Should -BeNullOrEmpty
        $plan.Steps[0].Result.ContainsKey('At') | Should -BeTrue
        $plan.Steps[1].Result.ContainsKey('At') | Should -BeFalse
    }

    It 'rejects an unparseable Result.At (<Name>) with Tenure.Plan.Invalid at its path' -ForEach @(
        @{ Name = 'text'; Value = 'not a date' }
        @{ Name = 'empty'; Value = '' }
        @{ Name = 'a number'; Value = 42 }
        @{ Name = 'a boolean'; Value = $true }
        @{ Name = 'an object'; Value = @{ when = 'now' } }
        @{ Name = 'an array'; Value = @('2026-10-08T12:31:00Z') }
    ) {
        $table = Get-MinimalPlan
        $table['Steps'][1]['Result'] = @{ At = $Value; DurationMs = 1 }
        $thrown = Get-ThrownError { Import-TenurePlan -Path (Write-PlanFile $table) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Plan.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be '$.Steps[1].Result.At'
    }

    It 'keeps strings that look like dates as strings' {
        $table = Get-MinimalPlan
        $table['Inputs'] = @{ when = '2026-10-08T12:00:00Z' }
        $file = Write-PlanFile $table -FileName 'dates-as-strings.json'
        Get-Content -LiteralPath $file -Raw | Should -Match ([regex]::Escape('"when": "2026-10-08T12:00:00Z"'))
        $loaded = (Import-TenurePlan -Path $file).Inputs.when
        $loaded | Should -BeOfType [string]
        $loaded | Should -Be '2026-10-08T12:00:00Z'
    }
}

Describe 'Export then Import' {
    BeforeEach {
        Reset-PlanTestState
        $script:plan = New-SamplePlan
        $script:file = Join-Path $TestDrive ('roundtrip-' + [guid]::NewGuid().ToString('N') + '.json')
        Export-TenurePlan -Plan $script:plan -Path $script:file
        $script:imported = Import-TenurePlan -Path $script:file
    }

    It 'gives the same canonical JSON as the original plan' {
        Get-Canonical $script:imported | Should -Be (Get-Canonical $script:plan)
    }

    It 'keeps every fingerprint valid against the imported Before' {
        foreach ($step in $script:imported.Steps) {
            if ($null -eq $step.Before) { $step.Fingerprint | Should -Be '' } else { Get-StepFingerprint $step.Target $step.Before | Should -Be $step.Fingerprint }
        }
        $script:imported.Steps[0].Fingerprint | Should -Match '^[0-9a-f]{64}$'
    }

    It 'restores nested objects as hashtables in After and PSCustomObjects in Before' {
        $first = $script:imported.Steps[0]
        $first.Target | Should -BeOfType [hashtable]
        $first.After | Should -BeOfType [hashtable]
        $first.After.extra | Should -BeOfType [hashtable]
        $first.After.extra.deep | Should -BeOfType [hashtable]
        $first.After.items[0] | Should -BeOfType [hashtable]
        $first.After.items[1].n | Should -Be 2
        $first.Before | Should -BeOfType [pscustomobject]
        $first.Before.address | Should -BeOfType [pscustomobject]
        $first.Before.address.city | Should -Be 'London'
        @($first.Before.address.tags) | Should -Be @('a', 'b')
    }

    It 'keeps the values the plan was built with' {
        $script:imported.PlanId | Should -Be $script:plan.PlanId
        $script:imported.CreatedAt | Should -Be $script:plan.CreatedAt
        $script:imported.Operation | Should -Be 'Custom'
        $script:imported.Warnings | Should -Be @('careful')
        $script:imported.Inputs.flags | Should -Be @('x', 'y')
        $script:imported.Inputs.when | Should -Be '2026-10-08T12:00:00Z'
        $script:imported.Steps[1].DependsOn | Should -Be @('S01')
        $script:imported.Steps[1].Action | Should -Be 'Invoke'
        @($script:imported.Steps | ForEach-Object Key) | Should -Be @('first', 'second')
    }

    It 'writes a Result.At that is a [datetime] as a UTC round-trip string and reads it back as the same instant' -ForEach @(
        @{ Kind = 'Utc' }, @{ Kind = 'Local' }
    ) {
        $stamp = if ($Kind -eq 'Utc') { [datetime]::UtcNow } else { [datetime]::Now }
        $script:plan.Steps[0].Status = 'Applied'
        $script:plan.Steps[0].Result = @{ At = $stamp; DurationMs = 5; Observed = [pscustomobject]@{ displayName = 'Grace' }; Error = $null; Note = 'ok' }
        $script:plan.Status = 'PartiallyApplied'
        $file = Join-Path $TestDrive ('result-' + [guid]::NewGuid().ToString('N') + '.json')
        Export-TenurePlan -Plan $script:plan -Path $file
        (Get-Content -LiteralPath $file -Raw) | Should -Match '"At": "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z"'
        $back = Import-TenurePlan -Path $file
        $back.Steps[0].Result.At | Should -BeOfType [datetime]
        $back.Steps[0].Result.At.Kind | Should -Be 'Utc'
        $back.Steps[0].Result.At.Ticks | Should -Be $stamp.ToUniversalTime().Ticks
        Get-Canonical $back | Should -Be (Get-Canonical $script:plan)
    }

    It 'can be exported again to an identical file' {
        $again = Join-Path $TestDrive ('again-' + [guid]::NewGuid().ToString('N') + '.json')
        Export-TenurePlan -Plan $script:imported -Path $again
        [System.IO.File]::ReadAllBytes($again) | Should -Be ([System.IO.File]::ReadAllBytes($script:file))
    }
}
