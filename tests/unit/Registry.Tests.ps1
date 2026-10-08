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
