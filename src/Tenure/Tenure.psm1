#Requires -Version 7.2
Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot
$script:ModuleVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'Tenure.psd1')).ModuleVersion
$script:Providers = [ordered]@{}
$script:Session = $null

# Load order matters: core helpers first (Register-TenureProvider, seams), then the
# provider files that call Register-TenureProvider at load, then public surface.
foreach ($relative in @('Private/Core', 'Private/Providers', 'Public')) {
    $directory = Join-Path $PSScriptRoot $relative
    if (-not (Test-Path -LiteralPath $directory)) { continue }
    foreach ($file in (Get-ChildItem -LiteralPath $directory -Filter '*.ps1' -File | Sort-Object -Property Name)) {
        try {
            . $file.FullName
        } catch {
            throw "Tenure failed to load $($file.FullName): $($_.Exception.Message)"
        }
    }
}

$publicFunctions = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File | ForEach-Object { $_.BaseName })
Export-ModuleMember -Function $publicFunctions
