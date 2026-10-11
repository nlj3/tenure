# Pressure test for the policy loader: whatever is done to a valid
# policy, the loader either loads it or throws Tenure.Policy.Invalid. A raw .NET or
# PowerShell exception, or any other Tenure id, is a bug.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest

    $script:ExamplePath = Join-Path $script:TenureSourceRoot 'Policies' 'example.policy.json'

    function Get-ExampleTable {
        Get-Content -LiteralPath $script:ExamplePath -Raw | ConvertFrom-Json -AsHashtable -Depth 30
    }

    # Every child slot (hashtable key or array index) under a node, depth first, with its path trail.
    function Get-Slot {
        param($SlotNode, [object[]]$SlotTrail)
        if ($SlotNode -is [hashtable]) {
            foreach ($slotKey in @($SlotNode.Keys | Sort-Object)) {
                [pscustomobject]@{ Parent = $SlotNode; Key = $slotKey; Trail = @($SlotTrail) + @($slotKey) }
                Get-Slot $SlotNode[$slotKey] (@($SlotTrail) + @($slotKey))
            }
        } elseif ($SlotNode -is [array]) {
            for ($slotIndex = 0; $slotIndex -lt $SlotNode.Count; $slotIndex++) {
                [pscustomobject]@{ Parent = $SlotNode; Key = $slotIndex; Trail = @($SlotTrail) + @($slotIndex) }
                Get-Slot $SlotNode[$slotIndex] (@($SlotTrail) + @($slotIndex))
            }
        }
    }

    function Test-UnderscorePath {
        param([object[]]$PathTrail)
        foreach ($segment in $PathTrail) { if (([string]$segment).StartsWith('_')) { return $true } }
        $false
    }

    # Applies one random mutation. Returns what was done and whether the result must be rejected.
    function Invoke-RandomMutation {
        param($MutationRandom, [hashtable]$MutationRoot)
        $slots = @(Get-Slot $MutationRoot @())
        $kind = $MutationRandom.Next(0, 5)
        switch ($kind) {
            0 {
                $candidates = @($slots | Where-Object { $_.Parent -is [hashtable] })
                $slot = $candidates[$MutationRandom.Next(0, $candidates.Count)]
                $slot.Parent.Remove($slot.Key)
                return @{ Kind = 'delete key'; Where = ($slot.Trail -join '.'); MustFail = ($slot.Trail.Count -eq 1 -and $slot.Key -eq 'version') }
            }
            1 {
                $slot = $slots[$MutationRandom.Next(0, $slots.Count)]
                $current = $slot.Parent[$slot.Key]
                $replacement = if ($null -eq $current) { 5 }
                elseif ($current -is [string]) { 42 }
                elseif ($current -is [bool]) { 'yes' }
                elseif ($current -is [array]) { 'text' }
                elseif ($current -is [hashtable]) { , @(1, 2) }
                else { 'twenty' }
                $slot.Parent[$slot.Key] = $replacement
                return @{ Kind = 'flip type'; Where = ($slot.Trail -join '.'); MustFail = -not (Test-UnderscorePath $slot.Trail) }
            }
            2 {
                $containers = @(@{ Table = $MutationRoot; Trail = @() }) + @($slots | Where-Object { $_.Parent[$_.Key] -is [hashtable] } | ForEach-Object { @{ Table = $_.Parent[$_.Key]; Trail = $_.Trail } })
                $container = $containers[$MutationRandom.Next(0, $containers.Count)]
                $value = @(1, 'text', $true, $null, @(1), @{ a = 1 })[$MutationRandom.Next(0, 6)]
                $container.Table['bogusKey'] = $value
                return @{ Kind = 'insert unknown key'; Where = (@($container.Trail) + 'bogusKey' -join '.'); MustFail = -not (Test-UnderscorePath $container.Trail) }
            }
            3 {
                $stringSlots = @($slots | Where-Object { $_.Parent[$_.Key] -is [string] })
                $slot = $stringSlots[$MutationRandom.Next(0, $stringSlots.Count)]
                $slot.Parent[$slot.Key] = $MutationRandom.Next(0, 1000)
                return @{ Kind = 'string to number'; Where = ($slot.Trail -join '.'); MustFail = -not (Test-UnderscorePath $slot.Trail) }
            }
            default {
                $MutationRoot['version'] = 2
                return @{ Kind = 'version 2'; Where = 'version'; MustFail = $true }
            }
        }
    }

    function Get-Outcome {
        param([scriptblock]$OutcomeBlock)
        try {
            $null = & $OutcomeBlock
            return @{ Loaded = $true }
        } catch {
            return @{ Loaded = $false; Id = $_.FullyQualifiedErrorId; DataId = $_.Exception.Data['TenureId']; Type = $_.Exception.GetType().FullName; Message = $_.Exception.Message; Path = $_.Exception.Data['Path'] }
        }
    }
}

Describe 'Policy loader fuzz' {
    It 'loads or throws Tenure.Policy.Invalid for 200 seeded mutations of the example policy' {
        $mutationRandom = [System.Random]::new(20261008)
        $failures = [System.Collections.Generic.List[string]]::new()
        $loaded = 0
        $rejected = 0
        foreach ($round in 1..200) {
            $root = Get-ExampleTable
            $mutation = Invoke-RandomMutation $mutationRandom $root
            $label = 'round {0}: {1} at {2}' -f $round, $mutation.Kind, $mutation.Where
            $mutated = ConvertTo-Json -InputObject $root -Depth 20 -Compress
            $outcome = Get-Outcome { Get-TenurePolicy -InputObject $root }
            if ($outcome.Loaded) {
                $loaded++
                if ($mutation.MustFail) { $failures.Add("$label loaded but must be rejected: $mutated") }
            } else {
                $rejected++
                if ($outcome.Id -ne 'Tenure.Policy.Invalid' -or $outcome.DataId -ne 'Tenure.Policy.Invalid') {
                    $failures.Add("$label threw $($outcome.Type) with id '$($outcome.Id)': $($outcome.Message) :: $mutated")
                } elseif (-not $outcome.Message.StartsWith($outcome.Path + ':')) {
                    $failures.Add("$label message does not start with its path '$($outcome.Path)': $($outcome.Message)")
                }
            }
        }
        $failures | Should -BeNullOrEmpty -Because ($failures -join "`n")
        # The corpus must exercise both outcomes or the test proves little.
        $loaded | Should -BeGreaterThan 5
        $rejected | Should -BeGreaterThan 100
    }

    It 'loads or throws Tenure.Policy.Invalid for 100 seeded single-character corruptions of the example file' {
        $text = Get-Content -LiteralPath $script:ExamplePath -Raw
        $junk = [char[]]@('"', '{', '}', '[', ']', ',', ':', '\', "`n", 'x', '0', '-', '_', [char]0xE9, ' ')
        $mutationRandom = [System.Random]::new(20261009)
        $failures = [System.Collections.Generic.List[string]]::new()
        foreach ($round in 1..100) {
            $position = $mutationRandom.Next(0, $text.Length)
            $replacement = $junk[$mutationRandom.Next(0, $junk.Length)]
            $corrupted = $text.Substring(0, $position) + $replacement + $text.Substring($position + 1)
            $file = Join-Path $TestDrive "corrupt-$round.json"
            [System.IO.File]::WriteAllText($file, $corrupted, [System.Text.UTF8Encoding]::new($false))
            $outcome = Get-Outcome { Get-TenurePolicy -Path $file }
            if (-not $outcome.Loaded -and ($outcome.Id -ne 'Tenure.Policy.Invalid')) {
                $failures.Add("round ${round}: replaced character $position with '$replacement' -> $($outcome.Type) '$($outcome.Id)': $($outcome.Message)")
            }
        }
        $failures | Should -BeNullOrEmpty -Because ($failures -join "`n")
    }

    It 'rejects every truncation of the example file with Tenure.Policy.Invalid at the root' {
        $text = Get-Content -LiteralPath $script:ExamplePath -Raw
        $lastBrace = $text.LastIndexOf('}')
        $mutationRandom = [System.Random]::new(20261010)
        $failures = [System.Collections.Generic.List[string]]::new()
        foreach ($round in 1..60) {
            $cut = $mutationRandom.Next(0, $lastBrace)
            $file = Join-Path $TestDrive "cut-$round.json"
            [System.IO.File]::WriteAllText($file, $text.Substring(0, $cut), [System.Text.UTF8Encoding]::new($false))
            $outcome = Get-Outcome { Get-TenurePolicy -Path $file }
            if ($outcome.Loaded -or $outcome.Id -ne 'Tenure.Policy.Invalid' -or $outcome.Path -ne '$') {
                $failures.Add("round ${round}: cut at $cut -> loaded=$($outcome.Loaded) id='$($outcome.Id)' path='$($outcome.Path)'")
            }
        }
        $failures | Should -BeNullOrEmpty -Because ($failures -join "`n")
    }

    It 'rejects bytes that are not UTF-8 text' {
        $file = Join-Path $TestDrive 'binary.json'
        [System.IO.File]::WriteAllBytes($file, [byte[]]@(0x7B, 0x22, 0xFF, 0xFE, 0xC3, 0x28, 0x22, 0x7D))
        $outcome = Get-Outcome { Get-TenurePolicy -Path $file }
        $outcome.Loaded | Should -BeFalse
        $outcome.Id | Should -Be 'Tenure.Policy.Invalid'
        $outcome.Path | Should -Be '$'
    }

    It 'rejects objects that are not JSON-shaped with Tenure.Policy.Invalid' {
        $cycle = @{ version = 1 }
        $cycle['self'] = $cycle
        $cases = @{
            'a cycle'        = $cycle
            'a script block' = @{ version = 1; _comment = { 1 } }
            'a date'         = @{ version = 1; roles = @{ r = @{ department = [datetime]::UtcNow } } }
            'a guid'         = @{ version = 1; _comment = [guid]::NewGuid() }
            'NaN'            = @{ version = 1; defaults = @{ passwordLength = [double]::NaN } }
            'infinity'       = @{ version = 1; defaults = @{ passwordLength = [double]::PositiveInfinity } }
        }
        foreach ($name in $cases.Keys) {
            $candidate = $cases[$name]
            $outcome = Get-Outcome { Get-TenurePolicy -InputObject $candidate }
            $outcome.Loaded | Should -BeFalse -Because $name
            $outcome.Id | Should -Be 'Tenure.Policy.Invalid' -Because $name
        }
    }

    It 'rejects very large integers for passwordLength with Tenure.Policy.Invalid, not a raw cast error' {
        $outcome = Get-Outcome { Get-TenurePolicy -InputObject @{ version = 1; defaults = @{ passwordLength = [long]::MaxValue - 1000 } } }
        $outcome.Loaded | Should -BeFalse
        $outcome.Id | Should -Be 'Tenure.Policy.Invalid'
        $outcome.Path | Should -Be '$.defaults.passwordLength'
    }

    It 'loads passwordLength exactly when it is a whole number from 8 to 256 (300 seeded values)' {
        $mutationRandom = [System.Random]::new(20261011)
        $values = @(7, 8, 9, 255, 256, 257, 0, -8, [int]::MinValue, [int]::MaxValue, 8.0, 7.999, 256.0000001) + @(1..290 | ForEach-Object { $mutationRandom.Next(-300, 600) })
        $failures = [System.Collections.Generic.List[string]]::new()
        foreach ($value in $values) {
            $outcome = Get-Outcome { Get-TenurePolicy -InputObject @{ version = 1; defaults = @{ passwordLength = $value } } }
            $expected = ($value -is [int] -or [math]::Floor($value) -eq $value) -and $value -ge 8 -and $value -le 256
            if ($outcome.Loaded -ne $expected) { $failures.Add("passwordLength $value loaded=$($outcome.Loaded) expected=$expected") }
            elseif (-not $outcome.Loaded -and $outcome.Id -ne 'Tenure.Policy.Invalid') { $failures.Add("passwordLength $value threw '$($outcome.Id)'") }
        }
        $failures | Should -BeNullOrEmpty -Because ($failures -join "`n")
    }

    It 'rejects a list entry that is empty or whitespace wherever the loader reads name lists' {
        foreach ($bad in '', ' ', "`t", "`n") {
            $table = Get-ExampleTable
            $table['roles']['sales']['licenses'] = @('SPE_E3', $bad)
            $table['roles']['warehouse']['groups'] = @($bad)
            $table['defaults']['protectedUsers'] = @($bad, 'x@example.com')
            $table['defaults']['offboard']['keepGroups'] = @('A', 'B', $bad)
            $outcome = Get-Outcome { Get-TenurePolicy -InputObject $table }
            $outcome.Loaded | Should -BeFalse
            $outcome.Id | Should -Be 'Tenure.Policy.Invalid'
        }
    }
}
