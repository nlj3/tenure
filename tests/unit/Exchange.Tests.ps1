BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest
    function Invoke-Exchange { Invoke-InTenure { param($p) Invoke-TenureExchange @p } @(, $args[0]) }
    function global:Set-TenureTestMailbox { param($Identity, $Type, [switch]$Explode) if ($Explode) { throw 'kaboom' }; [pscustomobject]@{ Identity = $Identity; Type = $Type } }
}

AfterAll {
    Remove-Item -Path 'Function:\global:Set-TenureTestMailbox' -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Invoke-TenureExchange' {
    BeforeEach { Set-TenureTestSession }

    It 'refuses when Exchange is not connected' {
        Set-TenureTestSession -Exchange $false
        { Invoke-Exchange @{ Command = 'Set-TenureTestMailbox' } } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
    }

    It 'throws CommandUnavailable for a cmdlet that does not exist in the session' {
        { Invoke-Exchange @{ Command = 'Set-TenureNoSuchCmdlet' } } | Should -Throw -ErrorId 'Tenure.Exchange.CommandUnavailable'
    }

    It 'rejects command names that are not Verb-Noun' {
        { Invoke-Exchange @{ Command = 'rm -rf' } } | Should -Throw
    }

    It 'splats parameters and returns the cmdlet output' {
        $result = Invoke-Exchange @{ Command = 'Set-TenureTestMailbox'; Parameters = @{ Identity = 'alice@example.com'; Type = 'Shared' } }
        $result.Identity | Should -Be 'alice@example.com'
        $result.Type | Should -Be 'Shared'
    }

    It 'wraps cmdlet failures as Tenure.Exchange.Failed with the inner record' {
        $error = { Invoke-Exchange @{ Command = 'Set-TenureTestMailbox'; Parameters = @{ Identity = 'x'; Explode = $true } } } | Should -Throw -ErrorId 'Tenure.Exchange.Failed' -PassThru
        $error.Exception.Message | Should -Match 'kaboom'
        $error.Exception.Data['Inner'] | Should -Not -BeNullOrEmpty
    }
}
