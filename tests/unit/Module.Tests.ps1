BeforeDiscovery {
    $script:PublicFunctionNames = @(Get-ChildItem (Join-Path $PSScriptRoot '..' '..' 'src' 'Tenure' 'Public') -Filter '*.ps1' -File | ForEach-Object BaseName | Sort-Object)
}

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest
}

Describe 'Tenure module' {
    It 'imports and exposes exactly the functions in Public/' {
        $expected = @(Get-ChildItem (Join-Path $script:TenureSourceRoot 'Public') -Filter '*.ps1' -File | ForEach-Object BaseName | Sort-Object)
        $actual = @((Get-Module Tenure).ExportedFunctions.Keys | Sort-Object)
        $actual | Should -Be $expected
    }

    It 'lists every public function in the manifest FunctionsToExport (no wildcards)' {
        $manifest = Import-PowerShellDataFile $script:TenureManifest
        $declared = @($manifest.FunctionsToExport | Sort-Object)
        $expected = @(Get-ChildItem (Join-Path $script:TenureSourceRoot 'Public') -Filter '*.ps1' -File | ForEach-Object BaseName | Sort-Object)
        $declared | Should -Be $expected
        $declared | Should -Not -Contain '*'
    }

    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path $script:TenureManifest -ErrorAction Stop } | Should -Not -Throw
    }

    It 'imports in under 1.5 seconds' {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Import-Module $script:TenureManifest -Force
        $stopwatch.ElapsedMilliseconds | Should -BeLessThan 1500
    }

    It 'has comment-based help with a synopsis and an example on <_>' -ForEach $script:PublicFunctionNames {
        $help = Get-Help -Name $_ -Full
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis.Trim() | Should -Not -Match "^$_\b"
        @($help.examples.example).Count | Should -BeGreaterOrEqual 1
    }

    It 'requires only the two agreed modules' {
        $manifest = Import-PowerShellDataFile $script:TenureManifest
        @($manifest.RequiredModules | ForEach-Object { $_.ModuleName } | Sort-Object) | Should -Be @('ExchangeOnlineManagement', 'Microsoft.Graph.Authentication')
    }
}

Describe 'Release workflow' {
    It 'passes the tag name and other event values to scripts through environment variables, never pasted into the script text' {
        $path = Join-Path $script:TenureRepoRoot '.github' 'workflows' 'release.yml'
        $lines = Get-Content -LiteralPath $path
        $inRun = $false
        $runIndent = 0
        $offenders = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $indent = $line.Length - $line.TrimStart().Length
            if ($line -match '^\s*(-\s+)?run:\s*(.*)$') {
                $inRun = $true
                $runIndent = $indent
                if ($Matches[2] -and $Matches[2] -ne '|' -and $Matches[2].Contains('${{')) { $offenders.Add("line $($i + 1): $line") }
                continue
            }
            if ($inRun -and $line.Trim().Length -gt 0 -and $indent -le $runIndent) { $inRun = $false }
            if ($inRun -and $line.Contains('${{')) { $offenders.Add("line $($i + 1): $line") }
        }
        $offenders | Should -BeNullOrEmpty -Because 'a value expanded into the script text can inject commands'
        (Get-Content -LiteralPath $path -Raw) | Should -Match 'TAG_NAME: \$\{\{ github\.event\.release\.tag_name \}\}'
    }
}

