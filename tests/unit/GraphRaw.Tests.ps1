BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest
}

Describe 'Invoke-TenureGraphRaw' {
    It 'forces Debug off for the SDK call even when the caller turned it on (bodies would leak secrets)' {
        $global:TenureRawDebugSeen = $null
        Mock -ModuleName Tenure Invoke-MgGraphRequest {
            $global:TenureRawDebugSeen = @{ DebugParam = $PesterBoundParameters['Debug']; Preference = [string]$DebugPreference }
            [pscustomobject]@{ id = 'x' }
        }
        $previous = $global:DebugPreference
        try {
            $global:DebugPreference = 'Continue'
            Invoke-InTenure { Invoke-TenureGraphRaw -Method 'GET' -Uri 'https://graph.microsoft.com/v1.0/me' } | Out-Null
        } finally {
            $global:DebugPreference = $previous
        }
        $global:TenureRawDebugSeen | Should -Not -BeNullOrEmpty
        # The explicit -Debug:$false is the guard that reaches the SDK; a Pester mock body does
        # not inherit the caller's local preference the way a real cmdlet does, so only the
        # bound parameter is asserted here.
        $global:TenureRawDebugSeen.ContainsKey('DebugParam') | Should -BeTrue
        [bool]$global:TenureRawDebugSeen.DebugParam | Should -BeFalse
        Remove-Variable -Name TenureRawDebugSeen -Scope Global -ErrorAction SilentlyContinue
    }
}
