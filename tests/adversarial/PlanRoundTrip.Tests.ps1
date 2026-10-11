# Property test for the plan file: for any generated plan,
# Export -> Import gives back the same plan in canonical form, and every fingerprint
# still matches its Before. Each case has its own seed so a failure is reproducible.

BeforeDiscovery {
    $script:Cases = foreach ($index in 1..50) { @{ Index = $index; Seed = 20261100 + $index } }
}

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest

    $script:ExamplePath = Join-Path $script:TenureSourceRoot 'Policies' 'example.policy.json'
    $script:rtState = @{}

    # Equality that never throws on mixed types: compare the JSON of both sides.
    $script:SafeTest = {
        param($Current, $Desired)
        if ($null -eq $Current) { return $false }
        if ($null -eq $Desired) { return $true }
        foreach ($key in $Desired.Keys) {
            if (-not $Current.PSObject.Properties[$key]) { return $false }
            $left = ConvertTo-Json -InputObject $Current.$key -Depth 8 -Compress
            $right = ConvertTo-Json -InputObject $Desired[$key] -Depth 8 -Compress
            if ($left -cne $right) { return $false }
        }
        $true
    }
    $script:SafeDescribe = { param($Target, $Current, $Desired, $Action) "$Action $($Target.Name)" }

    function Register-Fake {
        param([hashtable]$FakeDefinition)
        Invoke-InTenure { param($d) Register-TenureProvider -Definition $d -Force | Out-Null } @($FakeDefinition)
    }

    # One fake of each provider kind per target kind: a provider acts on one kind of object, and the generator
    # picks the target kind at random. The names end in the kind, for example Fake.RtStateGroup.
    $script:RtKinds = @('user', 'group', 'device', 'mailbox', 'drive', 'role')
    $script:RtNames = [System.Collections.Generic.List[string]]::new()
    foreach ($targetKind in $script:RtKinds) {
        $suffix = $targetKind.Substring(0, 1).ToUpperInvariant() + $targetKind.Substring(1)
        Register-Fake (New-FakeProviderDefinition -Name "Fake.RtState$suffix" -State $script:rtState -Overrides @{ TargetKind = $targetKind; Test = $script:SafeTest; Describe = $script:SafeDescribe })
        Register-Fake (New-FakeProviderDefinition -Name "Fake.RtInvoke$suffix" -State $script:rtState -Overrides @{ TargetKind = $targetKind; Kind = 'Invoke'; Risk = 'High'; Reversible = $false; Test = { param($Current, $Desired) $false }; Describe = $script:SafeDescribe })
        $check = New-FakeProviderDefinition -Name "Fake.RtCheck$suffix" -State $script:rtState -Overrides @{ TargetKind = $targetKind; Kind = 'Check'; Severity = 'Warn'; Test = $script:SafeTest; Describe = $script:SafeDescribe }
        $check.Remove('Set')
        Register-Fake $check
        foreach ($prefix in 'Fake.RtState', 'Fake.RtInvoke', 'Fake.RtCheck') { $script:RtNames.Add("$prefix$suffix") }
    }
    function Get-RtProvider([string]$Prefix, [hashtable]$Target) { $Prefix + $Target.Kind.Substring(0, 1).ToUpperInvariant() + $Target.Kind.Substring(1) }

    $script:StringPool = @(
        'alpha', '', 'with "quotes"', 'back\slash', "line1`nline2", "tab`there", ('caf' + [char]0xE9), [string][char]0x4E2D,
        '<tag>&amp;', 'looks-like-date 2026-10-08T12:00:00Z', '2026-10-08T12:00:00Z', '{{subjectId}}', ('smile' + [char]::ConvertFromUtf32(0x1F600)), '  padded  ', 'null', 'true', '42'
    )
    $script:KeyPool = @('alpha', 'Beta', 'gamma', 'key with space', 'x.y', '$dollar', '_under', ('caf' + [char]0xE9), 'id')

    function New-RandomScalar {
        param($Rng)
        switch ($Rng.Next(0, 9)) {
            0 { $Rng.Next(-1000, 1000) }
            1 { [long]5000000000 + $Rng.Next(0, 100000) }
            2 { @(0.5, -2.25, 3.0, 1.0E-3)[$Rng.Next(0, 4)] }
            3 { [bool]($Rng.Next(0, 2)) }
            4 { $null }
            5 { $script:StringPool[$Rng.Next(0, $script:StringPool.Count)] }
            6 { [datetime]::new(2026, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc).AddMinutes($Rng.Next(0, 500000)).AddTicks($Rng.Next(0, 10000000)) }
            7 { [datetime]::new(2026, 1, 1, 0, 0, 0, [System.DateTimeKind]::Local).AddMinutes($Rng.Next(0, 500000)) }
            8 { [guid]::new(('{0:x8}-0000-4000-8000-000000000000' -f $Rng.Next())) }
        }
    }

    function New-RandomValue {
        param($Rng, [int]$Depth)
        $choice = $Rng.Next(0, 10)
        if ($Depth -ge 3 -or $choice -lt 6) { return New-RandomScalar $Rng }
        if ($choice -lt 8) { return New-RandomTable $Rng ($Depth + 1) }
        $list = [System.Collections.Generic.List[object]]::new()
        $length = $Rng.Next(0, 4)
        for ($n = 0; $n -lt $length; $n++) { $list.Add((New-RandomValue $Rng ($Depth + 1))) }
        , $list.ToArray()
    }

    function New-RandomTable {
        param($Rng, [int]$Depth, [int]$MinKeys = 0)
        $table = @{}
        $wanted = $Rng.Next($MinKeys, 6)
        $keys = $script:KeyPool | Sort-Object { $Rng.Next() } | Select-Object -First $wanted
        foreach ($key in $keys) { $table[$key] = New-RandomValue $Rng $Depth }
        $table
    }

    # A plan of 0..12 steps with mixed actions, nested After values and DependsOn on earlier steps.
    function New-RandomPlan {
        param([int]$PlanSeed)
        $rng = [System.Random]::new($PlanSeed)
        $script:rtState.Clear()
        $count = $rng.Next(0, 13)
        $steps = [System.Collections.Generic.List[object]]::new()
        $kinds = @('user', 'group', 'device', 'mailbox', 'drive', 'role')
        for ($i = 0; $i -lt $count; $i++) {
            # Shaped like an object id: a mailbox or drive is named by one.
            $id = '{0:x8}-0000-4000-8000-{1:d12}' -f $PlanSeed, $i
            $target = @{ Kind = $kinds[$rng.Next(0, $kinds.Count)]; Id = $id; Name = "Target $i" }
            $key = "k$i"
            $earlier = [int[]]@(if ($i -gt 0) { 0..($i - 1) })
            $dependencyCount = $rng.Next(0, [Math]::Min(3, $earlier.Count) + 1)
            $dependsOn = @($earlier | Sort-Object { $rng.Next() } | Select-Object -First $dependencyCount | ForEach-Object { "k$_" })
            $arguments = @{ Target = $target; Key = $key; DependsOn = $dependsOn }
            if ($rng.Next(0, 3) -eq 0) { $arguments['Reason'] = $script:StringPool[$rng.Next(0, $script:StringPool.Count)] }
            if ($rng.Next(0, 4) -eq 0) { $arguments['Risk'] = @('Low', 'Medium', 'High', 'Destructive')[$rng.Next(0, 4)] }

            switch ($rng.Next(0, 6)) {
                0 {
                    $script:rtState[$id] = New-RandomTable $rng 0
                    $steps.Add((New-TenureStep -Provider (Get-RtProvider 'Fake.RtState' $arguments['Target']) -Desired (New-RandomTable $rng 0) @arguments))
                }
                1 {
                    $current = @{ name = "n$i"; count = $rng.Next(0, 10); enabled = [bool]($rng.Next(0, 2)); nested = New-RandomTable $rng 1 }
                    $script:rtState[$id] = $current
                    $steps.Add((New-TenureStep -Provider (Get-RtProvider 'Fake.RtState' $arguments['Target']) -Desired @{ name = $current.name; count = $current.count } @arguments))
                }
                2 {
                    $steps.Add((New-TenureStep -Provider (Get-RtProvider 'Fake.RtState' $arguments['Target']) -Desired (New-RandomTable $rng 0 1) -AllowMissing @arguments))
                }
                3 {
                    # Without a snapshot a step must be a Create or act on the user an earlier step creates.
                    $action = @('Create', 'Update', 'Remove')[$rng.Next(0, 3)]
                    if ($action -cne 'Create' -or $rng.Next(0, 3) -eq 0) { $arguments['Target'] = @{ Kind = 'user'; Id = '{{subjectId}}'; Name = "Placeholder $i" } }
                    $desired = if ($rng.Next(0, 4) -eq 0) { $null } else { New-RandomTable $rng 0 }
                    $steps.Add((New-TenureStep -Provider (Get-RtProvider 'Fake.RtState' $arguments['Target']) -Desired $desired -SkipSnapshot -Action $action @arguments))
                }
                4 {
                    $script:rtState[$id] = New-RandomTable $rng 0
                    $steps.Add((New-TenureStep -Provider (Get-RtProvider 'Fake.RtInvoke' $arguments['Target']) @arguments))
                }
                5 {
                    $script:rtState[$id] = @{ mailboxGb = $rng.Next(0, 100); archive = [bool]($rng.Next(0, 2)) }
                    $desired = if ($rng.Next(0, 2) -eq 0) { @{ archive = $script:rtState[$id].archive } } else { @{ mailboxGb = 500 } }
                    $steps.Add((New-TenureStep -Provider (Get-RtProvider 'Fake.RtCheck' $arguments['Target']) -Desired $desired @arguments))
                }
            }
        }

        $subject = @{ Id = $(if ($rng.Next(0, 2) -eq 0) { $null } else { [guid]::new(('{0:x8}-1111-4111-8111-111111111111' -f $rng.Next())).ToString() }); UserPrincipalName = "user$PlanSeed@example.com"; DisplayName = "User $PlanSeed" }
        $warningCount = $rng.Next(0, 3)
        $planArguments = @{
            Operation = @('Onboard', 'RoleChange', 'Offboard', 'Custom')[$rng.Next(0, 4)]
            Subject   = $subject
            Step      = $steps.ToArray()
            Inputs    = New-RandomTable $rng 0
            Warning   = [string[]]@(for ($n = 0; $n -lt $warningCount; $n++) { $script:StringPool[$rng.Next(0, $script:StringPool.Count)] })
        }
        if ($rng.Next(0, 2) -eq 0) { $planArguments['Policy'] = $script:ExamplePath }
        New-TenurePlan @planArguments
    }

    function Get-Canonical {
        param($CanonicalObject)
        Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @($CanonicalObject)
    }

    function Get-StepFingerprint {
        param($FingerprintTarget, $FingerprintBefore)
        Invoke-InTenure { param($t, $b) Get-TenureStepFingerprint -Target $t -Before $b } @($FingerprintTarget, $FingerprintBefore)
    }
}

AfterAll {
    foreach ($name in $script:RtNames) {
        Invoke-InTenure { param($n) Unregister-TenureProvider -Name $n } @($name)
    }
}

Describe 'Plan file round trip' {
    It 'plan <Index> (seed <Seed>) survives Export and Import in canonical form' -ForEach $script:Cases {
        $plan = New-RandomPlan $Seed
        $file = Join-Path $TestDrive "plan-$Index.json"
        Export-TenurePlan -Plan $plan -Path $file
        $imported = Import-TenurePlan -Path $file

        Get-Canonical $imported | Should -Be (Get-Canonical $plan)
        $imported.Integrity | Should -BeExactly $plan.Integrity -Because 'Import-TenurePlan recomputed it and found it unchanged'
        @($imported.Steps).Count | Should -Be @($plan.Steps).Count

        for ($i = 0; $i -lt @($plan.Steps).Count; $i++) {
            $original = $plan.Steps[$i]
            $step = $imported.Steps[$i]
            $step.Id | Should -Be ('S{0:D2}' -f ($i + 1))
            $step.Fingerprint | Should -Be $original.Fingerprint
            $step.Fingerprint | Should -Match '^[0-9a-f]{64}$' -Because 'every step binds its target, with or without a snapshot'
            Get-StepFingerprint $step.Target $step.Before | Should -Be $step.Fingerprint
            foreach ($dependency in $step.DependsOn) {
                [int]$dependency.Substring(1) | Should -BeLessThan ($i + 1)
            }
        }
    }

    It 'exporting the imported plan gives the same bytes as the first export (50 seeded plans)' {
        $failures = [System.Collections.Generic.List[string]]::new()
        foreach ($index in 1..50) {
            $plan = New-RandomPlan (20261200 + $index)
            $first = Join-Path $TestDrive "first-$index.json"
            $second = Join-Path $TestDrive "second-$index.json"
            Export-TenurePlan -Plan $plan -Path $first
            Export-TenurePlan -Plan (Import-TenurePlan -Path $first) -Path $second
            $same = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($first)) -ceq [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($second))
            if (-not $same) { $failures.Add("plan $index (seed $(20261200 + $index)) differs after a second export") }
        }
        $failures | Should -BeNullOrEmpty -Because ($failures -join "`n")
    }

    It 'the generator produces a mix of actions, empty and non-empty plans' {
        $actions = [System.Collections.Generic.HashSet[string]]::new()
        $sizes = [System.Collections.Generic.HashSet[int]]::new()
        $withDependencies = 0
        $withFingerprint = 0
        foreach ($index in 1..50) {
            $plan = New-RandomPlan (20261100 + $index)
            $null = $sizes.Add(@($plan.Steps).Count)
            foreach ($step in $plan.Steps) {
                $null = $actions.Add($step.Action)
                if (@($step.DependsOn).Count -gt 0) { $withDependencies++ }
                if ($step.Fingerprint) { $withFingerprint++ }
            }
        }
        foreach ($expected in 'Create', 'Update', 'Remove', 'Invoke', 'Check', 'NoOp') { $actions | Should -Contain $expected }
        $sizes | Should -Contain 0
        ($sizes | Measure-Object -Maximum).Maximum | Should -BeGreaterOrEqual 10
        $withDependencies | Should -BeGreaterThan 20
        $withFingerprint | Should -BeGreaterThan 20
    }
}
