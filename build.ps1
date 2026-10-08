#Requires -Version 7.2
<#
.SYNOPSIS
    Build, analyze, test and package the Tenure module.
.EXAMPLE
    ./build.ps1 -Task CI
.EXAMPLE
    ./build.ps1 -Task Test
.EXAMPLE
    ./build.ps1 -Task Build -Version 1.2.0
#>
[CmdletBinding()]
param(
    [ValidateSet('Bootstrap', 'Analyze', 'Test', 'Integration', 'Build', 'CI', 'Clean')]
    [string]$Task = 'CI',

    # Module version to stamp into the built manifest (Build task). Defaults to the source manifest.
    [string]$Version,

    # Prerelease label (for example 'beta1') to stamp into the built manifest.
    [string]$Prerelease,

    [switch]$NoCoverage
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Script-scoped copies so the nested task functions read them explicitly.
$script:BuildVersion = $Version
$script:BuildPrerelease = $Prerelease
$script:BuildNoCoverage = [bool]$NoCoverage

$root = $PSScriptRoot
$source = Join-Path $root 'src' 'Tenure'
$outRoot = Join-Path $root 'out'
$outModule = Join-Path $outRoot 'Tenure'
$results = Join-Path $root 'testResults'

$requirements = @(
    @{ Name = 'Pester'; MinimumVersion = '5.5.0'; MaximumVersion = '5.99.99' }
    @{ Name = 'PSScriptAnalyzer'; MinimumVersion = '1.21.0' }
    @{ Name = 'Microsoft.Graph.Authentication'; MinimumVersion = '2.25.0' }
    @{ Name = 'ExchangeOnlineManagement'; MinimumVersion = '3.4.0' }
)

function Write-Step([string]$Message) {
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-Requirement([hashtable]$Requirement) {
    $candidates = Get-Module -ListAvailable -Name $Requirement.Name | Where-Object { $_.Version -ge [version]$Requirement.MinimumVersion }
    if ($Requirement.ContainsKey('MaximumVersion')) {
        $candidates = $candidates | Where-Object { $_.Version -le [version]$Requirement.MaximumVersion }
    }
    [bool]($candidates | Select-Object -First 1)
}

function Invoke-Bootstrap {
    Write-Step 'Bootstrap: installing missing dependencies to CurrentUser'
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
    foreach ($requirement in $requirements) {
        if (Test-Requirement $requirement) {
            Write-Host "  ok   $($requirement.Name)"
            continue
        }
        Write-Host "  get  $($requirement.Name)"
        $install = @{ Name = $requirement.Name; Scope = 'CurrentUser'; Force = $true; AllowClobber = $true; MinimumVersion = $requirement.MinimumVersion }
        if ($requirement.ContainsKey('MaximumVersion')) { $install.MaximumVersion = $requirement.MaximumVersion }
        if ($requirement.Name -eq 'Pester') { $install.SkipPublisherCheck = $true }
        Install-Module @install
    }
}

function Assert-Requirement {
    $missing = @($requirements | Where-Object { -not (Test-Requirement $_) } | ForEach-Object { $_.Name })
    if ($missing.Count -gt 0) {
        throw "Missing dependencies: $($missing -join ', '). Run ./build.ps1 -Task Bootstrap."
    }
}

function Invoke-Analyze {
    Write-Step 'Analyze: PSScriptAnalyzer'
    Import-Module PSScriptAnalyzer -MinimumVersion 1.21.0
    $settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
    $findings = @(
        Invoke-ScriptAnalyzer -Path $source -Recurse -Settings $settings
        Invoke-ScriptAnalyzer -Path (Join-Path $root 'build.ps1') -Settings $settings
    )
    if ($findings.Count -gt 0) {
        $findings | Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message | Out-String -Width 200 | Write-Host
        $errors = @($findings | Where-Object Severity -eq 'Error')
        $warnings = @($findings | Where-Object Severity -eq 'Warning')
        throw "PSScriptAnalyzer: $($errors.Count) error(s), $($warnings.Count) warning(s). The gate allows neither."
    }
    Write-Host '  clean'
}

function Import-Pester {
    # A different Pester major already loaded in this process (for example via command
    # auto-loading) cannot coexist with 5.x; unload it first.
    $loaded = Get-Module -Name Pester
    if ($loaded -and ($loaded.Version -lt [version]'5.5.0' -or $loaded.Version -ge [version]'6.0.0')) {
        Remove-Module -Name Pester -Force
    }
    Import-Module Pester -MinimumVersion 5.5.0 -MaximumVersion 5.99.99
}

function Invoke-Test {
    Write-Step 'Test: Pester unit and adversarial suites (no tenant required)'
    Import-Pester
    New-Item -ItemType Directory -Path $results -Force | Out-Null

    $configuration = New-PesterConfiguration
    $configuration.Run.Path = @((Join-Path $root 'tests' 'unit'), (Join-Path $root 'tests' 'adversarial'))
    $configuration.Run.PassThru = $true
    $configuration.Run.Exit = $false
    $configuration.Filter.ExcludeTag = @('Integration')
    $configuration.Output.Verbosity = 'Normal'
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputFormat = 'NUnitXml'
    $configuration.TestResult.OutputPath = Join-Path $results 'unit.xml'
    if (-not $script:BuildNoCoverage) {
        $configuration.CodeCoverage.Enabled = $true
        $configuration.CodeCoverage.Path = @(Join-Path $source '*.ps1'; Join-Path $source 'Private' '*' '*.ps1'; Join-Path $source 'Public' '*.ps1')
        $configuration.CodeCoverage.OutputFormat = 'JaCoCo'
        $configuration.CodeCoverage.OutputPath = Join-Path $results 'coverage.xml'
        $configuration.CodeCoverage.CoveragePercentTarget = 70
    }

    $run = Invoke-Pester -Configuration $configuration
    if ($run.FailedCount -gt 0 -or $run.Result -ne 'Passed') {
        throw "Pester: $($run.FailedCount) failed, $($run.PassedCount) passed."
    }
    Write-Host "  $($run.PassedCount) passed, $($run.SkippedCount) skipped"
}

function Invoke-Integration {
    Write-Step 'Integration: live tenant suite'
    if ($env:TENURE_INTEGRATION -ne '1') {
        throw 'Integration tests run only with TENURE_INTEGRATION=1 and a tenant you own. See tests/integration/README.md.'
    }
    Import-Pester
    New-Item -ItemType Directory -Path $results -Force | Out-Null
    $configuration = New-PesterConfiguration
    $configuration.Run.Path = @(Join-Path $root 'tests' 'integration')
    $configuration.Run.PassThru = $true
    $configuration.Run.Exit = $false
    $configuration.Filter.Tag = @('Integration')
    $configuration.Output.Verbosity = 'Detailed'
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputPath = Join-Path $results 'integration.xml'
    $run = Invoke-Pester -Configuration $configuration
    if ($run.FailedCount -gt 0) { throw "Integration: $($run.FailedCount) failed." }
}

function Invoke-Clean {
    Write-Step 'Clean'
    foreach ($path in $outRoot, $results) {
        if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
}

function Invoke-Build {
    Write-Step 'Build: stage module to out/Tenure and validate the manifest'
    if (Test-Path $outModule) { Remove-Item -LiteralPath $outModule -Recurse -Force }
    New-Item -ItemType Directory -Path $outModule -Force | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $outModule -Recurse -Force

    $manifestPath = Join-Path $outModule 'Tenure.psd1'
    $publicFunctions = @(Get-ChildItem -Path (Join-Path $source 'Public') -Filter '*.ps1' -File | ForEach-Object { $_.BaseName } | Sort-Object)
    $update = @{ Path = $manifestPath; FunctionsToExport = $publicFunctions }
    if ($script:BuildVersion) { $update.ModuleVersion = $script:BuildVersion }
    if ($script:BuildPrerelease) { $update.Prerelease = $script:BuildPrerelease }
    Update-ModuleManifest @update

    $manifest = Test-ModuleManifest -Path $manifestPath
    $exported = @($manifest.ExportedFunctions.Keys | Sort-Object)
    if (Compare-Object $exported $publicFunctions) {
        throw "Built manifest exports [$($exported -join ', ')] but Public/ contains [$($publicFunctions -join ', ')]."
    }
    Write-Host "  Tenure $($manifest.Version)$(if ($script:BuildPrerelease) { "-$($script:BuildPrerelease)" }) with $($publicFunctions.Count) public function(s) -> $outModule"
}

switch ($Task) {
    'Bootstrap' { Invoke-Bootstrap }
    'Analyze' { Assert-Requirement; Invoke-Analyze }
    'Test' { Assert-Requirement; Invoke-Test }
    'Integration' { Assert-Requirement; Invoke-Integration }
    'Build' { Assert-Requirement; Invoke-Build }
    'Clean' { Invoke-Clean }
    'CI' { Assert-Requirement; Invoke-Analyze; Invoke-Test; Invoke-Build }
}
