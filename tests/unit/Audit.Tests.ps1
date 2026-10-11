# Contract tests for the audit log writer and readers (docs/SPEC.md section 2.5, ADR-0003).
# Every path is under TestDrive; TENURE_AUDIT_PATH points at a TestDrive sentinel so the
# default ~/.tenure/audit.jsonl is never touched.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'PlanFixtures.ps1')
    Import-TenureForTest
    Set-TenureTestSession
    $script:SavedAuditEnv = $env:TENURE_AUDIT_PATH

    function Write-Entry([hashtable]$Entry, [string]$Path) {
        Invoke-InTenure { param($e, $p) Write-TenureAudit -Entry $e -Path $p } @($Entry, $Path)
    }

    function New-Chain([string]$Path, [int]$Count = 5, [string]$PlanId = '22222222-0000-4000-8000-000000000001') {
        for ($i = 1; $i -le $Count; $i++) {
            Write-Entry @{
                PlanId    = $PlanId
                Operation = 'Offboard'
                StepId    = 'S{0:D2}' -f $i
                Provider  = 'Fake.State'
                Target    = @{ Kind = 'user'; Id = "u$i"; Name = "user$i@example.com" }
                Action    = 'Update'
                Outcome   = 'Applied'
                Before    = [pscustomobject]@{ accountEnabled = $true; createdDateTime = '2026-10-08T12:00:00+02:00'; quota = 1.50 }
                After     = @{ accountEnabled = $false }
                Observed  = [pscustomobject]@{ accountEnabled = $false }
                DurationMs = 12
            } $Path | Out-Null
        }
    }

    function Get-Line([string]$Path) { [System.IO.File]::ReadAllText($Path).Split("`n") | Where-Object { $_ -ne '' } }
}

AfterAll {
    $env:TENURE_AUDIT_PATH = $script:SavedAuditEnv
    Clear-TenureTestSession
}

Describe 'Write-TenureAudit' {
    BeforeEach {
        $script:path = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $script:sentinel = Join-Path $TestDrive 'env-sentinel.jsonl'
        $env:TENURE_AUDIT_PATH = $script:sentinel
    }

    It 'chains five entries: Seq 1..5, zero PrevHash first, each PrevHash the previous Hash' {
        New-Chain $script:path
        $entries = @(Get-TenureAudit -Path $script:path)
        $entries.Count | Should -Be 5
        @($entries.Seq) | Should -Be @(1, 2, 3, 4, 5)
        $entries[0].PrevHash | Should -Be ('0' * 64)
        for ($i = 1; $i -lt 5; $i++) { $entries[$i].PrevHash | Should -Be $entries[$i - 1].Hash }
        $entries[0].PSObject.TypeNames[0] | Should -Be 'Tenure.AuditEntry'
        $check = Test-TenureAudit -Path $script:path
        $check.Valid | Should -BeTrue
        $check.Entries | Should -Be 5
        $check.FirstBrokenSeq | Should -BeNullOrEmpty
        Test-Path $script:sentinel | Should -BeFalse
    }

    It 'returns the entry with Hash = sha256(PrevHash + canonical JSON of the entry without Hash)' {
        $entry = Write-Entry @{ PlanId = 'p'; Outcome = 'PlanStarted'; Note = 'hello' } $script:path
        $entry.PSObject.TypeNames[0] | Should -Be 'Tenure.AuditEntry'
        $entry.Seq | Should -Be 1
        $entry.Mode | Should -Be 'Apply'
        $entry.Actor.Account | Should -Be 'admin@example.com'
        $entry.Host | Should -Be ([System.Environment]::MachineName)
        $entry.ModuleVersion | Should -Be (Get-Module Tenure).Version.ToString()
        $without = [ordered]@{}
        foreach ($property in $entry.PSObject.Properties) { if ($property.Name -ne 'Hash') { $without[$property.Name] = $property.Value } }
        $canonical = Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $without)
        Get-TestHash -InputObject (('0' * 64) + $canonical) | Should -Be $entry.Hash
    }

    It 'writes one compact JSON object per line, UTF-8 without BOM, LF only, ending with LF' {
        New-Chain $script:path -Count 2
        $bytes = [System.IO.File]::ReadAllBytes($script:path)
        $bytes[0] | Should -Be ([byte][char]'{')
        $bytes[-1] | Should -Be 10
        $bytes | Should -Not -Contain 13
        foreach ($line in (Get-Line $script:path)) {
            $line | Should -Match '^\{.*,"Hash":"[0-9a-f]{64}"\}$'
            { $line | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    It 'continues Seq and PrevHash when appending to an existing file' {
        New-Chain $script:path -Count 2
        Import-TenureForTest
        Set-TenureTestSession
        $third = Write-Entry @{ Outcome = 'PlanFinished' } $script:path
        $third.Seq | Should -Be 3
        $third.PrevHash | Should -Be (@(Get-TenureAudit -Path $script:path))[1].Hash
        (Test-TenureAudit -Path $script:path).Valid | Should -BeTrue
    }

    It 'starts a new line when the file does not end with a newline' {
        New-Chain $script:path -Count 1
        $text = [System.IO.File]::ReadAllText($script:path).TrimEnd("`n")
        [System.IO.File]::WriteAllText($script:path, $text)
        Write-Entry @{ Outcome = 'PlanFinished' } $script:path | Out-Null
        @(Get-Line $script:path).Count | Should -Be 2
        (Test-TenureAudit -Path $script:path).Valid | Should -BeTrue
    }

    It 'creates missing directories on first write' {
        $deep = Join-Path $TestDrive 'a' 'b' 'c' 'audit.jsonl'
        Write-Entry @{ Outcome = 'PlanStarted' } $deep | Out-Null
        Test-Path $deep | Should -BeTrue
    }

    It 'refuses a SecureString anywhere in the entry and writes nothing' {
        New-Chain $script:path -Count 1
        $before = [System.IO.File]::ReadAllBytes($script:path)
        $secret = New-TestSecureString 'W4-audit-secret-q'
        { Write-Entry @{ Outcome = 'Applied'; Observed = @{ nested = @{ password = $secret } } } $script:path } | Should -Throw -ErrorId 'Tenure.Json.SecretRejected'
        [System.IO.File]::ReadAllBytes($script:path) | Should -Be $before
    }

    It 'rejects unknown keys, writer-owned keys and bad Outcome or Mode values' {
        { Write-Entry @{ Outcome = 'Applied'; Outcom = 'x' } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.InvalidEntry'
        { Write-Entry @{ Outcome = 'Applied'; Seq = 99 } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.InvalidEntry'
        { Write-Entry @{ Outcome = 'Applied'; Hash = ('f' * 64) } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.InvalidEntry'
        { Write-Entry @{ Outcome = 'Done' } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.InvalidEntry'
        { Write-Entry @{ Note = 'no outcome' } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.InvalidEntry'
        { Write-Entry @{ Outcome = 'Applied'; Mode = 'Plan' } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.InvalidEntry'
        Test-Path $script:path | Should -BeFalse
    }

    It 'throws Tenure.Audit.Unwritable for a path under a file' {
        $file = Join-Path $TestDrive 'not-a-directory.txt'
        Set-Content -LiteralPath $file -Value 'x'
        { Write-Entry @{ Outcome = 'PlanStarted' } (Join-Path $file 'audit.jsonl') } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable'
    }

    It 'throws Tenure.Audit.Unwritable when the path is a directory' {
        $directory = Join-Path $TestDrive 'is-a-directory'
        New-Item -ItemType Directory -Path $directory | Out-Null
        { Write-Entry @{ Outcome = 'PlanStarted' } $directory } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable'
    }

    It 'refuses to append after a torn or garbage last line' {
        New-Chain $script:path -Count 2
        [System.IO.File]::AppendAllText($script:path, '{"Seq":3,"Ts":"2026-10-08T')
        { Write-Entry @{ Outcome = 'PlanStarted' } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.Corrupt'
    }

    It 'says which line is torn and gives the command that keeps the lines before it' {
        New-Chain $script:path -Count 3
        [System.IO.File]::AppendAllText($script:path, '{"Seq":4,"Ts":"2026-10-08T')
        $failure = { Write-Entry @{ Outcome = 'PlanStarted' } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.Corrupt' -PassThru
        $failure.Exception.Message | Should -Match '^Line 4, the last line'
        $failure.Exception.Message | Should -Match ([regex]::Escape("Get-Content -LiteralPath '$($script:path)' -TotalCount 3 | Set-Content -LiteralPath '$($script:path).repaired'"))
        $failure.Exception.Data['Line'] | Should -Be 4

        # The documented repair works: the copy is a valid chain the writer appends to.
        Get-Content -LiteralPath $script:path -TotalCount 3 | Set-Content -LiteralPath "$($script:path).repaired"
        (Test-TenureAudit -Path "$($script:path).repaired").Valid | Should -BeTrue
        (Write-Entry @{ Outcome = 'PlanStarted' } "$($script:path).repaired").Seq | Should -Be 4
    }

    It 'treats an empty or whitespace-only file as a new chain' {
        [System.IO.File]::WriteAllText($script:path, "`n`n")
        (Write-Entry @{ Outcome = 'PlanStarted' } $script:path).Seq | Should -Be 1
        (Test-TenureAudit -Path $script:path).Valid | Should -BeTrue
    }

    It 'keeps the chain valid with two writers appending at the same time' -Skip:(-not (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)) {
        $manifest = $script:TenureManifest
        $jobs = foreach ($writer in 1, 2) {
            Start-ThreadJob -ArgumentList $manifest, $script:path, $writer -ScriptBlock {
                param($manifest, $path, $writer)
                Import-Module $manifest -Force
                $module = Get-Module -Name Tenure
                for ($i = 1; $i -le 15; $i++) {
                    & $module { param($p, $w, $n) Write-TenureAudit -Entry @{ Outcome = 'Applied'; StepId = ('S{0:D2}' -f $n); Note = "writer $w" } -Path $p } $path $writer $i | Out-Null
                }
            }
        }
        $jobs | Wait-Job -Timeout 120 | Out-Null
        $jobErrors = $null
        $jobs | Receive-Job -ErrorVariable jobErrors -ErrorAction SilentlyContinue | Out-Null
        @($jobs | Where-Object State -ne 'Completed').Count | Should -Be 0
        $jobs | Remove-Job -Force
        @($jobErrors).Count | Should -Be 0
        $check = Test-TenureAudit -Path $script:path
        $check.Entries | Should -Be 30
        $check.Valid | Should -BeTrue
    }
}

Describe 'Test-TenureAudit' {
    BeforeEach {
        $script:path = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $env:TENURE_AUDIT_PATH = Join-Path $TestDrive 'env-sentinel.jsonl'
        New-Chain $script:path
    }

    It 'reports Seq 3 when one byte of line 3 is flipped' {
        $bytes = [System.IO.File]::ReadAllBytes($script:path)
        $lineStarts = @(0) + @(for ($i = 0; $i -lt $bytes.Length - 1; $i++) { if ($bytes[$i] -eq 10) { $i + 1 } })
        $line3 = $lineStarts[2]
        $text = [System.Text.Encoding]::UTF8.GetString($bytes, $line3, $lineStarts[3] - $line3)
        $offset = $line3 + $text.IndexOf('user3@example.com')
        $bytes[$offset] = $bytes[$offset] -bxor 0x01
        [System.IO.File]::WriteAllBytes($script:path, $bytes)

        $check = Test-TenureAudit -Path $script:path
        $check.Valid | Should -BeFalse
        $check.FirstBrokenSeq | Should -Be 3
        $check.Entries | Should -Be 5
    }

    It 'names a torn last line in Problem and gives the repair command; an edit elsewhere is not to be repaired' {
        [System.IO.File]::AppendAllText($script:path, '{"Seq":6,"Ts":"2026-')
        $check = Test-TenureAudit -Path $script:path
        $check.Valid | Should -BeFalse
        $check.FirstBrokenSeq | Should -Be 6
        $check.Problem | Should -Match '^Line 6, the last line, is not a complete audit entry'
        $check.Problem | Should -Match '-TotalCount 5'

        $lines = @(Get-Line $script:path)
        $lines[1] = $lines[1].Replace('"Outcome":"Applied"', '"Outcome":"Skipped"')
        [System.IO.File]::WriteAllText($script:path, ($lines -join "`n") + "`n")
        $edited = Test-TenureAudit -Path $script:path
        $edited.FirstBrokenSeq | Should -Be 2
        $edited.Problem | Should -Match 'line 2'
        $edited.Problem | Should -Match 'Do not repair it by hand'
        (Test-TenureAudit -Path (Join-Path $TestDrive 'missing.jsonl')).Problem | Should -BeNullOrEmpty
    }

    It 'reports the edited Seq when a value is changed and the line stays valid JSON' {
        $lines = @(Get-Line $script:path)
        $lines[3] = $lines[3].Replace('"Outcome":"Applied"', '"Outcome":"Skipped"')
        [System.IO.File]::WriteAllText($script:path, ($lines -join "`n") + "`n")
        (Test-TenureAudit -Path $script:path).FirstBrokenSeq | Should -Be 4
    }

    It 'reports the edited Seq when a Hash is replaced' {
        $lines = @(Get-Line $script:path)
        $lines[4] = $lines[4] -replace '"Hash":"[0-9a-f]{64}"', ('"Hash":"' + ('a' * 64) + '"')
        [System.IO.File]::WriteAllText($script:path, ($lines -join "`n") + "`n")
        (Test-TenureAudit -Path $script:path).FirstBrokenSeq | Should -Be 5
    }

    It 'reports a break when line 2 is deleted' {
        $lines = [System.Collections.Generic.List[string]]@(Get-Line $script:path)
        $lines.RemoveAt(1)
        [System.IO.File]::WriteAllText($script:path, ($lines -join "`n") + "`n")
        $check = Test-TenureAudit -Path $script:path
        $check.Valid | Should -BeFalse
        $check.FirstBrokenSeq | Should -Be 2
        $check.Entries | Should -Be 4
    }

    It 'reports a break when two lines are swapped or a line is duplicated' {
        $lines = @(Get-Line $script:path)
        [System.IO.File]::WriteAllText($script:path, (@($lines[0], $lines[2], $lines[1], $lines[3], $lines[4]) -join "`n") + "`n")
        (Test-TenureAudit -Path $script:path).FirstBrokenSeq | Should -Be 2
        [System.IO.File]::WriteAllText($script:path, (@($lines[0], $lines[1], $lines[1], $lines[2]) -join "`n") + "`n")
        (Test-TenureAudit -Path $script:path).FirstBrokenSeq | Should -Be 3
    }

    It 'reports the garbage line position without throwing' {
        $lines = @(Get-Line $script:path)
        [System.IO.File]::WriteAllText($script:path, (@($lines[0], $lines[1], 'not json at all', $lines[2]) -join "`n") + "`n")
        $check = Test-TenureAudit -Path $script:path
        $check.FirstBrokenSeq | Should -Be 3
        $check.Entries | Should -Be 4
    }

    It 'accepts CRLF line endings (the content is unchanged)' {
        $lines = @(Get-Line $script:path)
        [System.IO.File]::WriteAllText($script:path, ($lines -join "`r`n") + "`r`n")
        (Test-TenureAudit -Path $script:path).Valid | Should -BeTrue
    }

    It 'is valid with zero entries for a missing or empty file' {
        $missing = Test-TenureAudit -Path (Join-Path $TestDrive 'nope.jsonl')
        $missing.Valid | Should -BeTrue
        $missing.Entries | Should -Be 0
        $missing.FirstBrokenSeq | Should -BeNullOrEmpty
        $empty = Join-Path $TestDrive 'empty.jsonl'
        [System.IO.File]::WriteAllText($empty, '')
        (Test-TenureAudit -Path $empty).Entries | Should -Be 0
        (Test-TenureAudit -Path $empty).Valid | Should -BeTrue
    }
}

Describe 'Get-TenureAudit' {
    BeforeEach {
        $script:path = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $env:TENURE_AUDIT_PATH = Join-Path $TestDrive 'env-sentinel.jsonl'
        $script:planA = '33333333-0000-4000-8000-00000000000a'
        $script:planB = '33333333-0000-4000-8000-00000000000b'
        foreach ($plan in $script:planA, $script:planB, $script:planA, $script:planB, $script:planA) {
            Write-Entry @{ PlanId = $plan; Outcome = 'Applied' } $script:path | Out-Null
        }
    }

    It 'returns entries in file order' {
        @((Get-TenureAudit -Path $script:path).Seq) | Should -Be @(1, 2, 3, 4, 5)
    }

    It 'filters by PlanId' {
        @((Get-TenureAudit -Path $script:path -PlanId $script:planA).Seq) | Should -Be @(1, 3, 5)
    }

    It 'applies -Last after the other filters' {
        @((Get-TenureAudit -Path $script:path -Last 2).Seq) | Should -Be @(4, 5)
        @((Get-TenureAudit -Path $script:path -PlanId $script:planA -Last 2).Seq) | Should -Be @(3, 5)
        @((Get-TenureAudit -Path $script:path -Last 50).Seq) | Should -Be @(1, 2, 3, 4, 5)
    }

    It 'filters by -Since' {
        $third = @(Get-TenureAudit -Path $script:path)[2]
        $since = Invoke-InTenure { param($v) ConvertFrom-TenureTimestamp -Value $v } @($third.Ts)
        @((Get-TenureAudit -Path $script:path -Since $since).Seq) | Should -Be @(3, 4, 5)
        @(Get-TenureAudit -Path $script:path -Since ([datetime]::UtcNow.AddMinutes(5))).Count | Should -Be 0
    }

    It 'throws Tenure.Audit.Corrupt with the line number for a garbage line' {
        [System.IO.File]::AppendAllText($script:path, "this is not json`n")
        $failure = { Get-TenureAudit -Path $script:path } | Should -Throw -ErrorId 'Tenure.Audit.Corrupt' -PassThru
        $failure.Exception.Message | Should -Match 'Line 6'
        [System.IO.File]::WriteAllText($script:path, "[1,2]`n")
        { Get-TenureAudit -Path $script:path } | Should -Throw -ErrorId 'Tenure.Audit.Corrupt'
    }

    It 'returns nothing, without an error, for a missing file' {
        @(Get-TenureAudit -Path (Join-Path $TestDrive 'missing.jsonl') -ErrorAction Stop).Count | Should -Be 0
    }
}

Describe 'Audit path resolution' {
    BeforeEach {
        $script:sentinel = Join-Path $TestDrive 'env-audit.jsonl'
        $env:TENURE_AUDIT_PATH = $script:sentinel
    }

    It 'prefers -Path, then TENURE_AUDIT_PATH, then ~/.tenure/audit.jsonl' {
        $explicit = Join-Path $TestDrive 'explicit.jsonl'
        Invoke-InTenure { param($p) Resolve-TenureAuditPath -Path $p } @($explicit) | Should -Be $explicit
        Invoke-InTenure { Resolve-TenureAuditPath } | Should -Be $script:sentinel
        $env:TENURE_AUDIT_PATH = $null
        Invoke-InTenure { Resolve-TenureAuditPath } | Should -Be (Join-Path $HOME '.tenure' 'audit.jsonl')
    }

    It 'never uses the environment or default path when -Path is given' {
        $explicit = Join-Path $TestDrive 'explicit-write.jsonl'
        Write-Entry @{ Outcome = 'PlanStarted' } $explicit | Out-Null
        (Test-TenureAudit -Path $explicit).Entries | Should -Be 1
        Test-Path $script:sentinel | Should -BeFalse
        @(Get-TenureAudit -Path $explicit).Count | Should -Be 1
    }

    It 'uses TENURE_AUDIT_PATH for Get-TenureAudit and Test-TenureAudit without -Path' {
        Write-Entry @{ Outcome = 'PlanStarted' } $null | Out-Null
        Test-Path $script:sentinel | Should -BeTrue
        @(Get-TenureAudit).Count | Should -Be 1
        (Test-TenureAudit).Entries | Should -Be 1
    }

    It 'rejects a path on a non-file-system drive' {
        { Invoke-InTenure { Resolve-TenureAuditPath -Path 'Env:\TENURE_X' } } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable'
    }
}

Describe 'Audit entries keep their values and format' {
    BeforeEach {
        $script:path = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $env:TENURE_AUDIT_PATH = Join-Path $TestDrive 'env-sentinel.jsonl'
    }

    It 'stamps Format 1 on every entry, inside the hashed text' {
        New-Chain $script:path -Count 2
        Write-Entry @{ Outcome = 'Attempting'; StepId = 'S03' } $script:path | Out-Null
        foreach ($line in (Get-Line $script:path)) { $line | Should -Match '"Format":1,' }
        @(Get-TenureAudit -Path $script:path | ForEach-Object { $_.Format }) | Should -Be @(1, 1, 1)
        (Test-TenureAudit -Path $script:path).Valid | Should -BeTrue
    }

    It 'returns values exactly as written: date-like strings stay strings' {
        New-Chain $script:path -Count 1
        $entry = @(Get-TenureAudit -Path $script:path)[0]
        $entry.Before.createdDateTime | Should -BeOfType [string]
        $entry.Before.createdDateTime | Should -Be '2026-10-08T12:00:00+02:00'
        $entry.Ts | Should -BeOfType [string]
        $entry.Ts | Should -Match 'Z$'
        $entry.Seq | Should -Be 1
    }
}

Describe 'Torn audit appends are rolled back' {
    BeforeEach {
        $script:path = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $env:TENURE_AUDIT_PATH = Join-Path $TestDrive 'env-sentinel.jsonl'
        $script:tear = @{ Next = $false }
        Mock -ModuleName Tenure Write-TenureAuditLine {
            if ($script:tear.Next) {
                $script:tear.Next = $false
                $Stream.Write($Bytes, 0, [int]($Bytes.Length / 2))
                $Stream.Flush()
                throw [System.IO.IOException]::new('No space left on device')
            }
            $Stream.Write($Bytes, 0, $Bytes.Length)
        }
    }

    It 'rolls the file back when an append fails half way, so the next write still chains' {
        New-Chain $script:path -Count 2
        $before = [System.IO.File]::ReadAllBytes($script:path)
        $script:tear.Next = $true
        { Write-Entry @{ Outcome = 'Applied'; StepId = 'S09'; Note = 'this write is torn' } $script:path } | Should -Throw -ErrorId 'Tenure.Audit.Unwritable'
        [System.IO.File]::ReadAllBytes($script:path) | Should -Be $before
        (Write-Entry @{ Outcome = 'PlanFinished' } $script:path).Seq | Should -Be 3
        (Test-TenureAudit -Path $script:path).Valid | Should -BeTrue
    }
}

Describe 'Cloud-synced audit folders' {
    It 'warns once per path when the audit log is under a cloud-synced folder' {
        $synced = Join-Path $TestDrive 'Dropbox' ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $first = @(Invoke-InTenure { param($p) Resolve-TenureAuditPath -Path $p 3>&1 } @($synced))
        $second = @(Invoke-InTenure { param($p) Resolve-TenureAuditPath -Path $p 3>&1 } @($synced))
        @($first | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should -Be 1
        @($second | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should -Be 0
        "$(@($first | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })[0])" | Should -Match 'local'
    }

    It 'recognizes OneDrive, iCloud Drive, Google Drive and Library/CloudStorage folders' {
        foreach ($folder in @('OneDrive - Example', 'iCloud Drive', 'Google Drive', (Join-Path 'Library' 'CloudStorage'))) {
            $path = Join-Path $TestDrive $folder ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
            $out = @(Invoke-InTenure { param($p) Resolve-TenureAuditPath -Path $p 3>&1 } @($path))
            @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should -Be 1 -Because $folder
        }
    }

    It 'on macOS treats Desktop and Documents in the home folder as possibly synced by iCloud' {
        $fakeHome = Join-Path $TestDrive 'home'
        $mac = { param($p, $h, $m) Get-TenureMacSyncedFolder -Path $p -HomePath $h -MacOS $m }
        Invoke-InTenure $mac @((Join-Path $fakeHome 'Documents' 'tenure' 'audit.jsonl'), $fakeHome, $true) | Should -Be 'Documents'
        Invoke-InTenure $mac @((Join-Path $fakeHome 'Desktop' 'audit.jsonl'), $fakeHome, $true) | Should -Be 'Desktop'
        Invoke-InTenure $mac @((Join-Path $fakeHome 'DOCUMENTS' 'audit.jsonl'), $fakeHome, $true) | Should -Be 'Documents' -Because 'macOS volumes ignore case'
        Invoke-InTenure $mac @((Join-Path $fakeHome 'Documents2' 'audit.jsonl'), $fakeHome, $true) | Should -BeNullOrEmpty
        Invoke-InTenure $mac @((Join-Path $fakeHome '.tenure' 'audit.jsonl'), $fakeHome, $true) | Should -BeNullOrEmpty
        Invoke-InTenure $mac @((Join-Path $fakeHome 'Documents' 'audit.jsonl'), $fakeHome, $false) | Should -BeNullOrEmpty -Because 'only macOS syncs these folders in place'
    }

    It 'warns, and does not refuse, for an audit log under ~/Documents on macOS' -Skip:(-not $IsMacOS) {
        $path = Join-Path $HOME 'Documents' ("tenure-audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $out = @(Invoke-InTenure { param($p) Resolve-TenureAuditPath -Path $p 3>&1 } @($path))
        $warnings = @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $warnings.Count | Should -Be 1
        "$($warnings[0])" | Should -Match 'iCloud Drive'
        @($out | Where-Object { $_ -is [string] }) | Should -Be @($path)
        Test-Path -LiteralPath $path | Should -BeFalse -Because 'resolving a path never creates the file'
    }

    It 'does not warn for an ordinary local folder' {
        $path = Join-Path $TestDrive 'logs' 'audit.jsonl'
        $out = @(Invoke-InTenure { param($p) Resolve-TenureAuditPath -Path $p 3>&1 } @($path))
        @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should -Be 0
    }
}

Describe 'What the audit log says about a plan (Get-TenureAuditHistory)' {
    BeforeEach {
        $script:path = Join-Path $TestDrive ('history-{0}.jsonl' -f [guid]::NewGuid().ToString('N'))
        $script:planId = [guid]::NewGuid().ToString()
    }

    BeforeAll {
        function Get-History { Invoke-InTenure { param($p, $id) Get-TenureAuditHistory -Line @(Read-TenureAuditFile -Path $p) -PlanId $id -Path $p } @($script:path, $script:planId) }
        function Add-Entry([hashtable]$Entry) { $Entry['PlanId'] = $script:planId; Write-Entry $Entry $script:path | Out-Null }
    }

    It 'records each attempt with the entry that ended it, and whether that entry was a refused request' {
        Add-Entry @{ Outcome = 'PlanStarted' }
        Add-Entry @{ StepId = 'S01'; Outcome = 'Attempting'; Mode = 'Apply' }
        Add-Entry @{ StepId = 'S01'; Outcome = 'Failed'; Error = 'Tenure.Graph.Forbidden: no.'; Mode = 'Apply' }
        Add-Entry @{ StepId = 'S02'; Outcome = 'Attempting'; Mode = 'Apply' }
        Add-Entry @{ StepId = 'S02'; Outcome = 'Failed'; Error = 'Tenure.Graph.Failed: Graph POST users returned 504 (GatewayTimeout).'; Mode = 'Apply' }
        Add-Entry @{ StepId = 'S03'; Outcome = 'Attempting'; Mode = 'Apply' }
        Add-Entry @{ Outcome = 'PlanFinished'; Observed = @{ Status = 'Failed' }; Mode = 'Apply' }
        $history = Get-History
        $history.Attempts['S01'][0].Failed | Should -BeTrue
        $history.Attempts['S02'][0].Failed | Should -BeFalse -Because 'a timeout may have landed'
        $history.Attempts['S03'][0].End | Should -Not -BeNullOrEmpty -Because 'the PlanFinished ended it'
        $history.Attempts['S03'][0].Failed | Should -BeFalse
        @($history.Changed | Sort-Object) | Should -Be @('S02', 'S03') -Because 'an attempt that was refused changed nothing'
        $history.FinishedApplied | Should -BeFalse
    }

    It 'ends an attempt left open by a run that died at the next PlanStarted' {
        Add-Entry @{ Outcome = 'PlanStarted' }
        Add-Entry @{ StepId = 'S01'; Outcome = 'Attempting'; Mode = 'Apply' }
        Add-Entry @{ Outcome = 'PlanStarted' }
        $history = Get-History
        $history.Attempts['S01'][0].End | Should -Not -BeNullOrEmpty
        $history.OpenRun | Should -BeTrue
    }

    It 'sees a plan that finished Applied in an Apply run, and not one that only finished a dry run' {
        Add-Entry @{ Outcome = 'PlanStarted' }
        Add-Entry @{ Outcome = 'PlanFinished'; Observed = @{ Status = 'DryRun' }; Mode = 'DryRun' }
        (Get-History).FinishedApplied | Should -BeFalse
        Add-Entry @{ Outcome = 'PlanStarted' }
        Add-Entry @{ Outcome = 'PlanFinished'; Observed = @{ Status = 'Applied' }; Mode = 'Apply' }
        (Get-History).FinishedApplied | Should -BeTrue
    }

    It 'marks a step assumed when a run that named it in -AssumeFired skipped it, until a later run applies it' {
        Add-Entry @{ Outcome = 'PlanStarted'; Observed = @{ Options = @{ AssumeFired = @('S02') } } }
        Add-Entry @{ StepId = 'S02'; Outcome = 'Skipped'; Mode = 'Apply' }
        Add-Entry @{ StepId = 'S03'; Outcome = 'Skipped'; Mode = 'Apply' }
        Add-Entry @{ Outcome = 'PlanFinished'; Observed = @{ Status = 'PartiallyApplied' }; Mode = 'Apply' }
        $history = Get-History
        @($history.Assumed) | Should -Be @('S02')
        Add-Entry @{ Outcome = 'PlanStarted' }
        Add-Entry @{ StepId = 'S02'; Outcome = 'Applied'; Mode = 'Apply' }
        @((Get-History).Assumed).Count | Should -Be 0
    }

    It 'Test-TenureDefinitiveFailure tells a refused request from one that may have landed' -ForEach @(
        @{ Text = 'Tenure.Graph.Forbidden: no.'; Expected = $true }
        @{ Text = 'Tenure.Provider.InvalidDesired: bad.'; Expected = $true }
        @{ Text = 'Tenure.Graph.Failed: Graph POST users returned 400 (Request_BadRequest): taken.'; Expected = $true }
        @{ Text = 'Tenure.Graph.Failed: Graph POST users returned 408.'; Expected = $false }
        @{ Text = 'Tenure.Graph.Failed: Graph POST users returned 503.'; Expected = $false }
        @{ Text = 'Tenure.Graph.Throttled: Graph POST users returned 429.'; Expected = $false }
        @{ Text = 'Tenure.Apply.Interrupted: stopped.'; Expected = $false }
        @{ Text = 'Tenure.Apply.PostConditionFailed: post-condition not met.'; Expected = $false }
        @{ Text = 'System.Management.Automation.RuntimeException: gateway timeout'; Expected = $false }
        @{ Text = ''; Expected = $false }
    ) {
        Invoke-InTenure { param($t) Test-TenureDefinitiveFailure -ErrorText $t } @($Text) | Should -Be $Expected
    }
}
