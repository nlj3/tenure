@{
    RootModule           = 'Tenure.psm1'
    ModuleVersion        = '0.1.0'
    CompatiblePSEditions = @('Core')
    GUID                 = 'a7b4344c-6ff0-4bd4-995a-b18b04872149'
    Author               = 'Noel Jackson'
    CompanyName          = 'Noel Jackson'
    Copyright            = '(c) 2026 Noel Jackson. MIT License.'
    Description          = 'Plan-then-apply account lifecycle for Microsoft 365. Onboard, change role and offboard users with a reviewable plan, dry run, drift detection and a hash-chained audit log.'
    PowerShellVersion    = '7.2'
    RequiredModules      = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.25.0' }
        @{ ModuleName = 'ExchangeOnlineManagement'; ModuleVersion = '3.4.0' }
    )
    FunctionsToExport    = @(
        'Get-TenureProvider'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Microsoft365', 'M365', 'EntraID', 'ExchangeOnline', 'Intune', 'Offboarding', 'Onboarding', 'Lifecycle', 'JML', 'Graph', 'PSEdition_Core', 'Windows', 'Linux', 'MacOS')
            LicenseUri   = 'https://github.com/nlj3/tenure/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/nlj3/tenure'
            ReleaseNotes = 'See CHANGELOG.md'
            Prerelease   = ''
        }
    }
}
