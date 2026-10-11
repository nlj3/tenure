BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest
    function Register($definition, [switch]$Force) { Invoke-InTenure { param($d, $f) Register-TenureProvider -Definition $d -Force:$f } @($definition, [bool]$Force) }
    function Unregister($name) { Invoke-InTenure { param($n) Unregister-TenureProvider -Name $n } @($name) }
}

AfterAll {
    foreach ($name in 'Fake.State', 'Fake.Check', 'Fake.Invoke') { Unregister $name }
}

Describe 'Register-TenureProvider' {
    AfterEach { foreach ($name in 'Fake.State', 'Fake.Check', 'Fake.Invoke') { Unregister $name } }

    It 'registers a valid State provider and returns a Tenure.Provider' {
        $provider = Register (New-FakeProviderDefinition)
        $provider.PSObject.TypeNames[0] | Should -Be 'Tenure.Provider'
        $provider.Name | Should -Be 'Fake.State'
        $provider.Kind | Should -Be 'State'
        $provider.Scopes | Should -Be @('Fake.ReadWrite.All')
        (Get-TenureProvider -Name 'Fake.State').Name | Should -Be 'Fake.State'
    }

    It 'rejects a definition without Test' {
        $definition = New-FakeProviderDefinition
        $definition.Remove('Test')
        { Register $definition } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
    }

    It 'rejects a State provider without Set' {
        $definition = New-FakeProviderDefinition
        $definition.Remove('Set')
        { Register $definition } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
    }

    It 'rejects a Check provider that defines Set or lacks Severity' {
        $withSet = New-FakeProviderDefinition -Name 'Fake.Check' -Overrides @{ Kind = 'Check'; Severity = 'Warn' }
        { Register $withSet } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        $noSeverity = New-FakeProviderDefinition -Name 'Fake.Check' -Overrides @{ Kind = 'Check' }
        $noSeverity.Remove('Set')
        { Register $noSeverity } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
    }

    It 'accepts a Check provider with Severity and no Set' {
        $definition = New-FakeProviderDefinition -Name 'Fake.Check' -Overrides @{ Kind = 'Check'; Severity = 'Refuse' }
        $definition.Remove('Set')
        (Register $definition).Severity | Should -Be 'Refuse'
    }

    It 'rejects Severity on a non-Check provider' {
        { Register (New-FakeProviderDefinition -Overrides @{ Severity = 'Warn' }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
    }

    It 'rejects bad Name, Kind, Backend, Risk and Reversible values' {
        { Register (New-FakeProviderDefinition -Name 'lowercase.name') } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        { Register (New-FakeProviderDefinition -Overrides @{ Kind = 'Magic' }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        { Register (New-FakeProviderDefinition -Overrides @{ Backend = 'SharePoint' }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        { Register (New-FakeProviderDefinition -Overrides @{ Risk = 'Scary' }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        { Register (New-FakeProviderDefinition -Overrides @{ Reversible = 'yes' }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
    }

    It 'rejects unknown keys (typos must not pass)' {
        { Register (New-FakeProviderDefinition -Overrides @{ Scoeps = @('x') }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
    }

    It 'lists every problem in one error' {
        $definition = New-FakeProviderDefinition -Overrides @{ Kind = 'Magic'; Risk = 'Scary' }
        $error = { Register $definition } | Should -Throw -PassThru
        $error.Exception.Data['Problems'].Count | Should -BeGreaterOrEqual 2
    }

    It 'requires a TargetKind, one of the six target kinds' {
        $missing = New-FakeProviderDefinition
        $missing.Remove('TargetKind')
        { Register $missing } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        { Register (New-FakeProviderDefinition -Overrides @{ TargetKind = 'User' }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        { Register (New-FakeProviderDefinition -Overrides @{ TargetKind = @('user', 'group') }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        (Register (New-FakeProviderDefinition -Overrides @{ TargetKind = 'mailbox' }) -Force).TargetKind | Should -BeExactly 'mailbox'
    }

    It 'requires Actions that fit the Kind' {
        $missing = New-FakeProviderDefinition
        $missing.Remove('Actions')
        { Register $missing } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        { Register (New-FakeProviderDefinition -Overrides @{ Actions = @('Invoke') }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        { Register (New-FakeProviderDefinition -Name 'Fake.Invoke' -Overrides @{ Kind = 'Invoke'; Actions = @('Update') }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        $check = New-FakeProviderDefinition -Name 'Fake.Check' -Overrides @{ Kind = 'Check'; Severity = 'Warn'; Actions = @('Check', 'Update') }
        $check.Remove('Set')
        { Register $check } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        @((Register (New-FakeProviderDefinition -Overrides @{ Actions = @('Remove', 'NoOp') }) -Force).Actions) | Should -Be @('Remove', 'NoOp')
    }

    It 'takes AffectedBy only on a Check provider, as provider names, and requires it there' {
        { Register (New-FakeProviderDefinition -Overrides @{ AffectedBy = @('User.SignIn') }) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        $undeclared = New-FakeProviderDefinition -Name 'Fake.Check' -Overrides @{ Kind = 'Check'; Severity = 'Warn' }
        $undeclared.Remove('Set')
        $undeclared.Remove('AffectedBy')
        { Register $undeclared } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        $bad = New-FakeProviderDefinition -Name 'Fake.Check' -Overrides @{ Kind = 'Check'; Severity = 'Warn'; AffectedBy = @('not a name') }
        $bad.Remove('Set')
        { Register $bad } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDefinition'
        $good = New-FakeProviderDefinition -Name 'Fake.Check' -Overrides @{ Kind = 'Check'; Severity = 'Warn'; AffectedBy = @('User.SignIn') }
        $good.Remove('Set')
        @((Register $good -Force).AffectedBy) | Should -Be @('User.SignIn')
    }

    It 'refuses duplicates unless -Force' {
        Register (New-FakeProviderDefinition) | Out-Null
        { Register (New-FakeProviderDefinition) } | Should -Throw -ErrorId 'Tenure.Provider.Duplicate'
        (Register (New-FakeProviderDefinition -Overrides @{ Risk = 'High' }) -Force).Risk | Should -Be 'High'
    }
}

Describe 'Get-TenureProvider' {
    BeforeAll {
        Register (New-FakeProviderDefinition) | Out-Null
        Register (New-FakeProviderDefinition -Name 'Fake.Invoke' -Overrides @{ Kind = 'Invoke' }) | Out-Null
    }
    AfterAll { Unregister 'Fake.State'; Unregister 'Fake.Invoke' }

    It 'returns all providers without -Name' {
        @(Get-TenureProvider | Where-Object Name -like 'Fake.*').Count | Should -Be 2
    }

    It 'supports wildcards' {
        @(Get-TenureProvider -Name 'Fake.*').Count | Should -Be 2
        @(Get-TenureProvider -Name 'Nope.*').Count | Should -Be 0
    }

    It 'throws Tenure.Provider.NotRegistered for an exact unknown name' {
        { Get-TenureProvider -Name 'Nope.Thing' } | Should -Throw -ErrorId 'Tenure.Provider.NotRegistered'
    }

    It 'accepts names from the pipeline' {
        @('Fake.State', 'Fake.Invoke' | Get-TenureProvider).Count | Should -Be 2
    }
}

Describe 'The registered providers declare what they act on' {
    It '<Name> acts on a <TargetKind> with actions <Actions>' -ForEach @(
        @{ Name = 'Calendar.CancelMeetings'; TargetKind = 'mailbox'; Actions = 'Invoke' }
        @{ Name = 'Check.MailboxSharedEligibility'; TargetKind = 'mailbox'; Actions = 'Check,NoOp' }
        @{ Name = 'Check.SubjectAllowed'; TargetKind = 'user'; Actions = 'Check,NoOp' }
        @{ Name = 'Check.SubjectNotGlobalAdmin'; TargetKind = 'user'; Actions = 'Check,NoOp' }
        @{ Name = 'Check.UserAbsent'; TargetKind = 'user'; Actions = 'Check,NoOp' }
        @{ Name = 'Device.Retire'; TargetKind = 'device'; Actions = 'Invoke' }
        @{ Name = 'Device.Wipe'; TargetKind = 'device'; Actions = 'Invoke' }
        @{ Name = 'DirectoryRole.Member'; TargetKind = 'role'; Actions = 'Remove,NoOp' }
        @{ Name = 'DistributionGroup.Member'; TargetKind = 'group'; Actions = 'Update,Remove,NoOp' }
        @{ Name = 'Group.Member'; TargetKind = 'group'; Actions = 'Update,Remove,NoOp' }
        @{ Name = 'Mailbox.AutoReply'; TargetKind = 'mailbox'; Actions = 'Update,NoOp' }
        @{ Name = 'Mailbox.Delegate'; TargetKind = 'mailbox'; Actions = 'Update,Remove,NoOp' }
        @{ Name = 'Mailbox.Forwarding'; TargetKind = 'mailbox'; Actions = 'Update,NoOp' }
        @{ Name = 'Mailbox.Hidden'; TargetKind = 'mailbox'; Actions = 'Update,NoOp' }
        @{ Name = 'Mailbox.Type'; TargetKind = 'mailbox'; Actions = 'Update,NoOp' }
        @{ Name = 'OneDrive.Access'; TargetKind = 'drive'; Actions = 'Update,Remove,NoOp' }
        @{ Name = 'User.Attributes'; TargetKind = 'user'; Actions = 'Update,NoOp' }
        @{ Name = 'User.Create'; TargetKind = 'user'; Actions = 'Create,NoOp' }
        @{ Name = 'User.LeaveDate'; TargetKind = 'user'; Actions = 'Update,NoOp' }
        @{ Name = 'User.Licenses'; TargetKind = 'user'; Actions = 'Update,NoOp' }
        @{ Name = 'User.Manager'; TargetKind = 'user'; Actions = 'Update,Remove,NoOp' }
        @{ Name = 'User.Password'; TargetKind = 'user'; Actions = 'Invoke' }
        @{ Name = 'User.Sessions'; TargetKind = 'user'; Actions = 'Invoke' }
        @{ Name = 'User.SignIn'; TargetKind = 'user'; Actions = 'Update,NoOp' }
        @{ Name = 'User.TemporaryAccessPass'; TargetKind = 'user'; Actions = 'Invoke' }
    ) {
        $provider = Get-TenureProvider -Name $Name
        $provider.TargetKind | Should -BeExactly $TargetKind
        @($provider.Actions) -join ',' | Should -BeExactly $Actions
    }

    It 'a check names the providers whose steps change what it reads' -ForEach @(
        @{ Name = 'Check.SubjectNotGlobalAdmin'; AffectedBy = 'DirectoryRole.Member' }
        @{ Name = 'Check.SubjectAllowed'; AffectedBy = '' }
        @{ Name = 'Check.UserAbsent'; AffectedBy = 'User.Create' }
        @{ Name = 'Check.MailboxSharedEligibility'; AffectedBy = 'Mailbox.Type' }
    ) {
        @((Get-TenureProvider -Name $Name).AffectedBy) -join ',' | Should -BeExactly $AffectedBy
    }

    It 'every registered provider is listed above' {
        @(Get-TenureProvider | Where-Object { $_.Name -notlike 'Fake.*' }).Count | Should -Be 25
    }
}
