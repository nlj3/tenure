# Audit log: append-only JSONL with a SHA-256 hash chain (docs/SPEC.md section 2.5, ADR-0003).
#
# Line format. Each line is the canonical JSON of the entry without Hash (keys sorted
# ordinally, compressed), with the Hash member appended as the last member:
#
#   {"Action":...,"Ts":"..."} + ',"Hash":"<64 hex>"}'
#
# Hash = sha256(PrevHash + canonicalJson(entry without Hash)). Because the hashed text
# is stored verbatim, a verifier strips the fixed 75-character Hash suffix and hashes
# the remaining text again. Nothing is re-serialized, so values that ConvertFrom-Json
# would reinterpret (date-like strings, 1.50 versus 1.5) cannot cause a false break.
#
# Locking. Writers open the file with FileShare.None (an exclusive lock on Windows, an
# advisory flock on macOS and Linux) and hold it across read-tail-then-append. The lock
# means nothing on network or cloud-synced folders; the audit log belongs on a local disk.

$script:AuditZeroHash = '0' * 64
$script:AuditFormat = 1
$script:AuditOutcomes = @('Attempting', 'Applied', 'Skipped', 'Failed', 'DryRun', 'Drifted', 'Refused', 'PlanStarted', 'PlanFinished')
$script:AuditEntryKeys = @('PlanId', 'Operation', 'StepId', 'Provider', 'Target', 'Action', 'Actor', 'Outcome', 'Before', 'After', 'Observed', 'Error', 'Note', 'DurationMs', 'Mode')
$script:AuditLockRetries = 100
$script:AuditLockDelayMs = 20
$script:AuditCloudWarned = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:AuditCloudFolders = @('Dropbox', 'iCloud Drive', 'Google Drive', 'Mobile Documents')

function Resolve-TenureAuditPath {
    <#
    .SYNOPSIS
        Returns the absolute file system path of the audit log.
    .DESCRIPTION
        Precedence: -Path, then $env:TENURE_AUDIT_PATH, then ~/.tenure/audit.jsonl
        ($HOME on every OS). Relative paths resolve against the current location.
        Throws Tenure.Audit.Unwritable when the path is not a file system path. Warns once
        per path and session when the path is inside a cloud-synced folder, where the
        writer's file lock is not honored.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path
    )

    $candidate = $Path
    if ([string]::IsNullOrWhiteSpace($candidate)) { $candidate = $env:TENURE_AUDIT_PATH }
    if ([string]::IsNullOrWhiteSpace($candidate)) { $candidate = Join-Path $HOME '.tenure' 'audit.jsonl' }

    $provider = $null
    $drive = $null
    try {
        $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($candidate, [ref]$provider, [ref]$drive)
    } catch {
        throw (New-TenureError -Id 'Tenure.Audit.Unwritable' -Message "The audit path '$candidate' is not valid: $($_.Exception.Message)" -Category InvalidArgument -Data @{ Path = $candidate })
    }
    if ($null -eq $provider -or $provider.Name -ne 'FileSystem') {
        throw (New-TenureError -Id 'Tenure.Audit.Unwritable' -Message "The audit path '$candidate' is not a file system path." -Category InvalidArgument -Data @{ Path = $candidate })
    }

    $folder = Get-TenureCloudFolder -Path $resolved
    if ($folder -and $script:AuditCloudWarned.Add($resolved)) {
        Write-Warning "The audit log '$resolved' is inside a cloud-synced folder ('$folder'). Tenure's file lock is not honored there and sync clients can reorder or duplicate lines. Keep the audit log on a local disk (-AuditPath or TENURE_AUDIT_PATH)."
    } elseif (-not $folder) {
        $maybe = Get-TenureMacSyncedFolder -Path $resolved
        if ($maybe -and $script:AuditCloudWarned.Add($resolved)) {
            Write-Warning "The audit log '$resolved' is in your $maybe folder, which iCloud Drive syncs when its Desktop and Documents Folders option is on (nothing in the path shows it). Tenure's file lock is not honored in a synced folder and sync clients can reorder or duplicate lines. Keep the audit log on a local disk outside Desktop and Documents (-AuditPath or TENURE_AUDIT_PATH)."
        }
    }
    $resolved
}

function Get-TenureMacSyncedFolder {
    <#
    .SYNOPSIS
        On macOS, returns 'Desktop' or 'Documents' when a path is inside that folder of the home directory, else $null.
    .DESCRIPTION
        iCloud Drive's "Desktop and Documents Folders" option syncs those two folders in place,
        so the path carries no sign of it. Tenure cannot tell whether the option is on, so it
        warns for both; it never refuses. -HomePath and -MacOS exist for tests.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()][AllowEmptyString()][string]$HomePath = $HOME,
        [bool]$MacOS = [bool]$IsMacOS
    )

    if (-not $MacOS -or [string]::IsNullOrWhiteSpace($HomePath)) { return $null }
    $separator = [System.IO.Path]::DirectorySeparatorChar
    foreach ($name in 'Desktop', 'Documents') {
        $root = (Join-Path $HomePath $name).TrimEnd('/', '\')
        # macOS volumes are case-insensitive by default.
        if ($Path.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or
            $Path.StartsWith($root + $separator, [System.StringComparison]::OrdinalIgnoreCase) -or
            $Path.StartsWith($root + '/', [System.StringComparison]::OrdinalIgnoreCase)) {
            return $name
        }
    }
    $null
}

function Get-TenureAuditRepairHint {
    <#
    .SYNOPSIS
        The commands that keep the first -KeepLines lines of an audit file in a copy, for messages about a torn last line.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$KeepLines
    )

    $quoted = $Path.Replace("'", "''")
    "To repair it, keep the first $KeepLines line(s) in a copy: Get-Content -LiteralPath '$quoted' -TotalCount $KeepLines | Set-Content -LiteralPath '$quoted.repaired'. Check the copy with Test-TenureAudit -Path '$quoted.repaired', then put it in place of the original and keep the damaged file for the record."
}

function Get-TenureCloudFolder {
    <#
    .SYNOPSIS
        Returns the name of the cloud-synced folder a path is inside (OneDrive, Dropbox,
        iCloud Drive, Google Drive, Library/CloudStorage), or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    $segments = @($Path -split '[\\/]' | Where-Object { $_ -ne '' })
    for ($index = 0; $index -lt $segments.Count; $index++) {
        $segment = $segments[$index]
        if ($segment -like 'OneDrive*') { return $segment }
        foreach ($name in $script:AuditCloudFolders) {
            if ($segment -eq $name) { return $segment }
        }
        if ($segment -eq 'Library' -and $index + 1 -lt $segments.Count -and $segments[$index + 1] -eq 'CloudStorage') { return 'Library/CloudStorage' }
    }
    $null
}

function Get-TenureAuditInnerException {
    <#
    .SYNOPSIS
        Unwraps the MethodInvocationException PowerShell puts around .NET exceptions.
    #>
    [CmdletBinding()]
    [OutputType([System.Exception])]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $exception = $ErrorRecord.Exception
    while ($exception -is [System.Management.Automation.MethodInvocationException] -and $null -ne $exception.InnerException) {
        $exception = $exception.InnerException
    }
    $exception
}

function Test-TenureRetryableIOError {
    <#
    .SYNOPSIS
        True for an IOException that may clear on retry (another process holds the file).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.Exception]$Exception)

    if (-not ($Exception -is [System.IO.IOException])) { return $false }
    if ($Exception -is [System.IO.FileNotFoundException] -or $Exception -is [System.IO.DirectoryNotFoundException] -or $Exception -is [System.IO.PathTooLongException]) { return $false }
    $true
}

function ConvertFrom-TenureAuditLine {
    <#
    .SYNOPSIS
        Splits one audit line into Seq, PrevHash, Hash and the hashed body text, or $null
        when the line is not a well-formed audit entry.
    .DESCRIPTION
        Uses System.Text.Json so no value is reinterpreted. Does not verify the hash.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $match = [regex]::Match($Text, ',"Hash":"([0-9a-f]{64})"\}\z')
    if (-not $match.Success) { return $null }
    $body = $Text.Substring(0, $match.Index) + '}'

    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 256
    $document = $null
    try {
        $document = [System.Text.Json.JsonDocument]::Parse($body, $options)
    } catch {
        Write-Verbose 'Audit line is not valid JSON.'
        return $null
    }
    try {
        $root = $document.RootElement
        if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $null }
        $seqElement = [System.Text.Json.JsonElement]::new()
        $prevElement = [System.Text.Json.JsonElement]::new()
        if (-not $root.TryGetProperty('Seq', [ref]$seqElement)) { return $null }
        if (-not $root.TryGetProperty('PrevHash', [ref]$prevElement)) { return $null }
        if ($seqElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Number) { return $null }
        if ($prevElement.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { return $null }
        $seq = [long]0
        if (-not $seqElement.TryGetInt64([ref]$seq)) { return $null }
        $prevHash = $prevElement.GetString()
        if ($prevHash -cnotmatch '^[0-9a-f]{64}$') { return $null }
        return @{ Seq = $seq; PrevHash = $prevHash; Hash = $match.Groups[1].Value; Body = $body }
    } finally {
        $document.Dispose()
    }
}

function Open-TenureAuditStream {
    <#
    .SYNOPSIS
        Opens (creating if needed) the audit file for exclusive read/write.
    .DESCRIPTION
        FileShare.None is an exclusive lock on Windows and an advisory flock(LOCK_EX) on
        macOS and Linux, so two Tenure writers cannot interleave the read-tail-then-append
        sequence. A held lock is retried for about two seconds. Anything else that
        prevents writing throws Tenure.Audit.Unwritable with the OS message.
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileStream])]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $directory = [System.IO.Path]::GetDirectoryName($Path)
        if (-not [string]::IsNullOrEmpty($directory) -and -not [System.IO.Directory]::Exists($directory)) {
            [void][System.IO.Directory]::CreateDirectory($directory)
        }
    } catch {
        $inner = Get-TenureAuditInnerException -ErrorRecord $_
        throw (New-TenureError -Id 'Tenure.Audit.Unwritable' -Message "Cannot create the audit directory for '$Path': $($inner.Message)" -Category WriteError -Data @{ Path = $Path })
    }

    $attempt = 0
    while ($true) {
        try {
            return [System.IO.FileStream]::new($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        } catch {
            $inner = Get-TenureAuditInnerException -ErrorRecord $_
            if ((Test-TenureRetryableIOError -Exception $inner) -and $attempt -lt $script:AuditLockRetries) {
                $attempt++
                Start-Sleep -Milliseconds $script:AuditLockDelayMs
                continue
            }
            throw (New-TenureError -Id 'Tenure.Audit.Unwritable' -Message "Cannot write the audit log '$Path': $($inner.Message)" -Category WriteError -Data @{ Path = $Path })
        }
    }
}

function Read-TenureAuditTail {
    <#
    .SYNOPSIS
        Reads the last non-blank line of an open audit stream and returns its Seq and
        Hash, plus whether the file ends with a newline.
    .DESCRIPTION
        Returns Seq 0 and the zero hash for an empty (or whitespace-only) file. A last
        line that is not a well-formed entry (for example a torn write) throws
        Tenure.Audit.Corrupt: the writer refuses to chain onto something it cannot read.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.IO.FileStream]$Stream,
        [Parameter(Mandatory)][string]$Path
    )

    $length = $Stream.Length
    $empty = @{ Seq = [long]0; Hash = $script:AuditZeroHash; EndsWithNewline = $true }
    if ($length -eq 0) { return $empty }

    $Stream.Position = $length - 1
    $endsWithNewline = ($Stream.ReadByte() -eq 10)

    $end = $length
    while ($end -gt 0) {
        $Stream.Position = $end - 1
        $byte = $Stream.ReadByte()
        if ($byte -eq 10 -or $byte -eq 13 -or $byte -eq 32 -or $byte -eq 9) { $end-- } else { break }
    }
    if ($end -eq 0) {
        $empty.EndsWithNewline = $endsWithNewline
        return $empty
    }

    $buffer = [byte[]]::new(8192)
    $start = [long]0
    $position = $end
    while ($position -gt 0) {
        $count = [int][math]::Min($buffer.Length, $position)
        $position -= $count
        $Stream.Position = $position
        $read = 0
        while ($read -lt $count) {
            $chunk = $Stream.Read($buffer, $read, $count - $read)
            if ($chunk -le 0) { break }
            $read += $chunk
        }
        $index = [array]::LastIndexOf($buffer, [byte]10, $count - 1, $count)
        if ($index -ge 0) {
            $start = $position + $index + 1
            break
        }
    }

    $lineLength = [int]($end - $start)
    $lineBytes = [byte[]]::new($lineLength)
    $Stream.Position = $start
    $read = 0
    while ($read -lt $lineLength) {
        $chunk = $Stream.Read($lineBytes, $read, $lineLength - $read)
        if ($chunk -le 0) { break }
        $read += $chunk
    }
    $text = [System.Text.Encoding]::UTF8.GetString($lineBytes, 0, $read).TrimStart([char]0xFEFF).TrimEnd("`r")

    $parsed = ConvertFrom-TenureAuditLine -Text $text
    if ($null -eq $parsed -or $parsed.Seq -lt 1) {
        # Count the line: one more than the newlines before it. Only on this error path, so the cost does not matter.
        $lineNumber = [long]1
        $Stream.Position = 0
        $scanned = [long]0
        while ($scanned -lt $start) {
            $count = [int][math]::Min($buffer.Length, $start - $scanned)
            $read = $Stream.Read($buffer, 0, $count)
            if ($read -le 0) { break }
            $index = [array]::IndexOf($buffer, [byte]10, 0, $read)
            while ($index -ge 0) {
                $lineNumber++
                $index = if ($index + 1 -lt $read) { [array]::IndexOf($buffer, [byte]10, $index + 1, $read - $index - 1) } else { -1 }
            }
            $scanned += $read
        }
        $hint = Get-TenureAuditRepairHint -Path $Path -KeepLines ($lineNumber - 1)
        throw (New-TenureError -Id 'Tenure.Audit.Corrupt' -Message "Line $lineNumber, the last line of the audit log '$Path', is not a complete audit entry (a write was cut off, or the line was edited). Refusing to append to it. Run Test-TenureAudit -Path '$Path' to confirm the lines before it are intact. $hint" -Category InvalidData -Data @{ Path = $Path; Line = $lineNumber })
    }
    @{ Seq = $parsed.Seq; Hash = $parsed.Hash; EndsWithNewline = $endsWithNewline }
}

function Write-TenureAuditLine {
    <#
    .SYNOPSIS
        Writes bytes to the audit stream. A seam of its own so tests can tear a write.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.Stream]$Stream,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    $Stream.Write($Bytes, 0, $Bytes.Length)
}

function New-TenureAuditRecord {
    <#
    .SYNOPSIS
        Validates an audit entry hashtable and returns the full record (every field
        present, writer-owned fields filled except Seq, PrevHash and Hash).
    .DESCRIPTION
        Serializes the record once, so a SecureString or credential anywhere in it throws
        Tenure.Json.SecretRejected before any file is opened.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory record; changes no state.')]
    param([Parameter(Mandatory)][hashtable]$Entry)

    foreach ($key in $Entry.Keys) {
        if ($key -cnotin $script:AuditEntryKeys) {
            throw (New-TenureError -Id 'Tenure.Audit.InvalidEntry' -Message "Audit entry key '$key' is not allowed. Seq, Ts, PrevHash, Hash, ModuleVersion, Format and Host are filled by the writer." -Category InvalidArgument)
        }
    }
    $outcome = if ($Entry.ContainsKey('Outcome')) { $Entry['Outcome'] } else { $null }
    if (-not ($outcome -is [string]) -or $outcome -cnotin $script:AuditOutcomes) {
        throw (New-TenureError -Id 'Tenure.Audit.InvalidEntry' -Message "Audit entry Outcome must be one of $($script:AuditOutcomes -join ', ') (got '$outcome')." -Category InvalidArgument)
    }
    $mode = 'Apply'
    if ($Entry.ContainsKey('Mode') -and $null -ne $Entry['Mode']) { $mode = $Entry['Mode'] }
    if (-not ($mode -is [string]) -or $mode -cnotin 'Apply', 'DryRun') {
        throw (New-TenureError -Id 'Tenure.Audit.InvalidEntry' -Message "Audit entry Mode must be Apply or DryRun (got '$mode')." -Category InvalidArgument)
    }

    $actor = $null
    if ($Entry.ContainsKey('Actor')) {
        $actor = $Entry['Actor']
    } elseif ($null -ne $script:Session) {
        $actor = [ordered]@{ Account = $null; TenantId = $null }
        if ($script:Session.PSObject.Properties['Account']) { $actor.Account = $script:Session.Account }
        if ($script:Session.PSObject.Properties['TenantId']) { $actor.TenantId = $script:Session.TenantId }
    }

    $record = [ordered]@{
        Seq           = [long]0
        Ts            = [datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        PrevHash      = $script:AuditZeroHash
        PlanId        = $null
        Operation     = $null
        StepId        = $null
        Provider      = $null
        Target        = $null
        Action        = $null
        Actor         = $actor
        Outcome       = $outcome
        Before        = $null
        After         = $null
        Observed      = $null
        Error         = $null
        Note          = $null
        DurationMs    = $null
        ModuleVersion = [string]$script:ModuleVersion
        Format        = $script:AuditFormat
        Host          = [System.Environment]::MachineName
        Mode          = $mode
    }
    foreach ($key in 'PlanId', 'Operation', 'StepId', 'Provider', 'Target', 'Action', 'Before', 'After', 'Observed', 'Error', 'Note', 'DurationMs') {
        if ($Entry.ContainsKey($key)) { $record[$key] = $Entry[$key] }
    }

    # Serialize once before touching the disk: secrets and absurd nesting fail here.
    $null = Get-TenureCanonicalJson -InputObject $record
    $record
}

function Add-TenureAuditRecord {
    <#
    .SYNOPSIS
        Chains a record onto the tail of an open, locked audit stream and appends it.
    .DESCRIPTION
        Fills Seq and PrevHash from the last line, computes Hash, writes the line in one
        call and flushes to disk. If anything fails after the first byte is written, the
        file is cut back to its original length before the error is rethrown, so a failed
        append never leaves a torn line that would block every later write.
        Returns the hash; the record is updated in place.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.IO.FileStream]$Stream,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Record
    )

    $tail = Read-TenureAuditTail -Stream $Stream -Path $Path
    $Record.Seq = [long]($tail.Seq + 1)
    $Record.PrevHash = $tail.Hash
    $body = Get-TenureCanonicalJson -InputObject $Record
    $hash = Get-TenureHash -InputObject ($Record.PrevHash + $body)
    $line = $body.Substring(0, $body.Length - 1) + ',"Hash":"' + $hash + '"}' + "`n"
    if (-not $tail.EndsWithNewline) { $line = "`n" + $line }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($line)

    # Rollback runs in finally, so it also happens when the pipeline is stopped mid-write
    # (a stop skips catch blocks).
    $originalLength = $Stream.Length
    $written = $false
    try {
        [void]$Stream.Seek(0, [System.IO.SeekOrigin]::End)
        Write-TenureAuditLine -Stream $Stream -Bytes $bytes
        $Stream.Flush($true)
        $written = $true
    } finally {
        if (-not $written) {
            try {
                $Stream.SetLength($originalLength)
                $Stream.Flush($true)
            } catch {
                Write-Verbose "Could not cut the audit log '$Path' back to its original length after a failed append."
            }
        }
    }
    $hash
}

function ConvertTo-TenureAuditEntry {
    <#
    .SYNOPSIS
        Builds the Tenure.AuditEntry object (SPEC section 2.5 order) for a written record.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.AuditEntry')]
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Record,
        [Parameter(Mandatory)][string]$Hash
    )

    [pscustomobject]@{
        PSTypeName    = 'Tenure.AuditEntry'
        Seq           = $Record.Seq
        Ts            = $Record.Ts
        PrevHash      = $Record.PrevHash
        Hash          = $Hash
        PlanId        = $Record.PlanId
        Operation     = $Record.Operation
        StepId        = $Record.StepId
        Provider      = $Record.Provider
        Target        = $Record.Target
        Action        = $Record.Action
        Actor         = $Record.Actor
        Outcome       = $Record.Outcome
        Before        = $Record.Before
        After         = $Record.After
        Observed      = $Record.Observed
        Error         = $Record.Error
        Note          = $Record.Note
        DurationMs    = $Record.DurationMs
        ModuleVersion = $Record.ModuleVersion
        Format        = $Record.Format
        Host          = $Record.Host
        Mode          = $Record.Mode
    }
}

function Invoke-TenureAuditWrite {
    <#
    .SYNOPSIS
        Opens the audit file under its lock, runs -Action with the stream, and maps any
        failure that is not already a Tenure error to Tenure.Audit.Unwritable.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    $stream = Open-TenureAuditStream -Path $Path
    try {
        & $Action $stream
    } catch {
        if (Get-TenureErrorId -ErrorRecord $_) { throw $_ }
        $inner = Get-TenureAuditInnerException -ErrorRecord $_
        throw (New-TenureError -Id 'Tenure.Audit.Unwritable' -Message "Cannot write the audit log '$Path': $($inner.Message)" -Category WriteError -Data @{ Path = $Path })
    } finally {
        $stream.Dispose()
    }
}

function Write-TenureAudit {
    <#
    .SYNOPSIS
        Appends one entry to the audit log and chains it to the previous one.
    .DESCRIPTION
        -Entry may carry PlanId, Operation, StepId, Provider, Target, Action, Actor,
        Outcome (required), Before, After, Observed, Error, Note, DurationMs and Mode
        ('Apply' default, or 'DryRun'). Seq, Ts, PrevHash, Hash, ModuleVersion, Format and
        Host are filled here; Actor defaults to the connected account.

        The whole entry is serialized before the file is opened, so a SecureString or
        credential anywhere in it throws Tenure.Json.SecretRejected and nothing is
        written. Unwritable paths throw Tenure.Audit.Unwritable; a last line that cannot
        be read throws Tenure.Audit.Corrupt. The line is written in one call, as UTF-8
        without BOM with an LF terminator, and flushed to disk before returning; a failed
        write is rolled back.
    .EXAMPLE
        Write-TenureAudit -Entry @{ PlanId = $plan.PlanId; Outcome = 'PlanStarted'; Mode = 'Apply' } -Path $path
    #>
    [CmdletBinding()]
    [OutputType('Tenure.AuditEntry')]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Entry,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path
    )

    $record = New-TenureAuditRecord -Entry $Entry
    $file = Resolve-TenureAuditPath -Path $Path
    $hash = Invoke-TenureAuditWrite -Path $file -Action {
        param($stream)
        Add-TenureAuditRecord -Stream $stream -Path $file -Record $record
    }
    ConvertTo-TenureAuditEntry -Record $record -Hash $hash
}

function Split-TenureAuditText {
    <#
    .SYNOPSIS
        Splits audit file text into non-blank @{ Number; Text } lines (CR and BOM removed).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $lines = $Text.Split("`n")
    for ($index = 0; $index -lt $lines.Length; $index++) {
        $line = $lines[$index].TrimEnd("`r")
        if ($index -eq 0) { $line = $line.TrimStart([char]0xFEFF) }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        [pscustomobject]@{ Number = $index + 1; Text = $line }
    }
}

function Read-TenureAuditFile {
    <#
    .SYNOPSIS
        Returns the non-blank lines of an audit file as @{ Number; Text } objects, in
        file order. A missing file returns nothing.
    .DESCRIPTION
        Opens with FileShare.ReadWrite and retries briefly while a writer holds the lock.
        Throws Tenure.Audit.Unreadable when the file exists but cannot be read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not [System.IO.File]::Exists($Path)) { return }

    $text = $null
    $attempt = 0
    while ($null -eq $text) {
        try {
            $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $reader = [System.IO.StreamReader]::new($stream, [System.Text.UTF8Encoding]::new($false), $true)
                try {
                    $text = $reader.ReadToEnd()
                } finally {
                    $reader.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
        } catch {
            $inner = Get-TenureAuditInnerException -ErrorRecord $_
            if ($inner -is [System.IO.FileNotFoundException] -or $inner -is [System.IO.DirectoryNotFoundException]) { return }
            if ((Test-TenureRetryableIOError -Exception $inner) -and $attempt -lt $script:AuditLockRetries) {
                $attempt++
                Start-Sleep -Milliseconds $script:AuditLockDelayMs
                continue
            }
            throw (New-TenureError -Id 'Tenure.Audit.Unreadable' -Message "Cannot read the audit log '$Path': $($inner.Message)" -Category ReadError -Data @{ Path = $Path })
        }
    }
    Split-TenureAuditText -Text $text
}

function Read-TenureAuditStreamText {
    <#
    .SYNOPSIS
        Reads the whole of an open audit stream as UTF-8 text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.IO.FileStream]$Stream)

    $length = [int]$Stream.Length
    if ($length -eq 0) { return '' }
    $bytes = [byte[]]::new($length)
    $Stream.Position = 0
    $read = 0
    while ($read -lt $length) {
        $chunk = $Stream.Read($bytes, $read, $length - $read)
        if ($chunk -le 0) { break }
        $read += $chunk
    }
    [System.Text.Encoding]::UTF8.GetString($bytes, 0, $read)
}

function Get-TenureAuditHistory {
    <#
    .SYNOPSIS
        Summarizes what the audit log says about one plan: which steps fired, which may
        have fired, and whether a run of the plan is still open.
    .DESCRIPTION
        OpenRun: the last PlanStarted for the plan has no later PlanFinished (any mode).
        For Mode Apply entries, per step id: Applied or Skipped puts the step in Applied;
        Attempting puts it in Uncertain and in Attempted; a later Applied, Skipped or Failed
        with a known error takes it out of Uncertain, while a Failed recorded as
        Tenure.Apply.Interrupted keeps it there. Attempted never shrinks: it is the evidence
        that Set was called for the step in some run; AttemptedAt keeps the Ts of the first
        such entry. CreatedIds maps the id of a Create step
        that was Applied or Skipped to the id it observed (Observed.id), so the engine can
        check that a subject id filled in after the plan was built came from this plan.
        Changed holds the steps with an Applied entry or an attempt that did not end in a
        recorded failure (Set ran, or may have), so a check whose input one of them changes
        is re-evaluated on a later run.
        Attempts maps a step id to its Attempting entries in order, each @{ At; End; Failed }:
        End is the Ts of the next entry for that step, or of the next PlanFinished or
        PlanStarted of the plan, whichever comes first ($null while none exists); Failed says
        that next entry was a Failed whose error shows the request was refused, so Set changed
        nothing (Test-TenureDefinitiveFailure). FinishedApplied
        is true when a PlanFinished of a Mode Apply run recorded the plan as Applied. Assumed
        holds the steps whose last Applied or Skipped entry is a Skip in a run whose PlanStarted
        named them in -AssumeFired. A
        line that names the plan but cannot be parsed throws Tenure.Audit.Corrupt: the engine
        will not guess.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()][object[]]$Line,
        [Parameter(Mandatory)][string]$PlanId,
        [Parameter(Mandatory)][string]$Path
    )

    $applied = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $uncertain = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $attempted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $attemptedAt = @{}
    $createdIds = @{}
    $changed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $assumed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $runAssumed = @()
    $attempts = @{}
    $finishedApplied = $false
    $open = $false
    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 256

    foreach ($item in @($Line)) {
        if ($null -eq $item -or -not $item.Text.Contains($PlanId)) { continue }
        $document = $null
        try {
            $document = [System.Text.Json.JsonDocument]::Parse($item.Text, $options)
        } catch {
            throw (New-TenureError -Id 'Tenure.Audit.Corrupt' -Message "Line $($item.Number) of the audit log '$Path' names plan $PlanId but is not valid JSON. Refusing to guess what that run did; run Test-TenureAudit." -Category InvalidData -Data @{ Path = $Path; Line = $item.Number })
        }
        try {
            $root = $document.RootElement
            if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { continue }
            $fields = @{}
            foreach ($name in 'PlanId', 'Outcome', 'StepId', 'Mode', 'Error', 'Action', 'Ts') {
                $element = [System.Text.Json.JsonElement]::new()
                if ($root.TryGetProperty($name, [ref]$element) -and $element.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                    $fields[$name] = $element.GetString()
                } else {
                    $fields[$name] = $null
                }
            }
            $fields['ObservedId'] = $null
            $fields['ObservedStatus'] = $null
            $fields['AssumeFired'] = [string[]]@()
            $observed = [System.Text.Json.JsonElement]::new()
            $observedId = [System.Text.Json.JsonElement]::new()
            $observedStatus = [System.Text.Json.JsonElement]::new()
            if ($root.TryGetProperty('Observed', [ref]$observed) -and $observed.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                if ($observed.TryGetProperty('id', [ref]$observedId) -and $observedId.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                    $fields['ObservedId'] = $observedId.GetString()
                }
                if ($observed.TryGetProperty('Status', [ref]$observedStatus) -and $observedStatus.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                    $fields['ObservedStatus'] = $observedStatus.GetString()
                }
                # PlanStarted records the run's options; -AssumeFired is the list of steps the operator vouched for.
                $runOptions = [System.Text.Json.JsonElement]::new()
                $named = [System.Text.Json.JsonElement]::new()
                if ($observed.TryGetProperty('Options', [ref]$runOptions) -and $runOptions.ValueKind -eq [System.Text.Json.JsonValueKind]::Object -and
                    $runOptions.TryGetProperty('AssumeFired', [ref]$named) -and $named.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                    $fields['AssumeFired'] = [string[]]@(foreach ($value in $named.EnumerateArray()) { if ($value.ValueKind -eq [System.Text.Json.JsonValueKind]::String) { $value.GetString() } })
                }
            }
        } finally {
            $document.Dispose()
        }
        if ($fields['PlanId'] -cne $PlanId) { continue }
        $outcome = $fields['Outcome']
        if ($outcome -cin 'PlanStarted', 'PlanFinished') {
            # A run ended, or a new one started after a run that died without a PlanFinished: either way an
            # attempt with no later entry of its own ends here.
            foreach ($list in $attempts.Values) {
                foreach ($attempt in $list) { if ($null -eq $attempt.End) { $attempt.End = $fields['Ts'] } }
            }
            $open = ($outcome -ceq 'PlanStarted')
            if ($outcome -ceq 'PlanStarted') { $runAssumed = @($fields['AssumeFired']) }
            if ($outcome -ceq 'PlanFinished' -and $fields['Mode'] -cne 'DryRun' -and $fields['ObservedStatus'] -ceq 'Applied') { $finishedApplied = $true }
            continue
        }
        $stepId = $fields['StepId']
        if ([string]::IsNullOrEmpty($stepId)) { continue }
        if ($fields['Mode'] -ceq 'DryRun') { continue }
        if ($outcome -cne 'Attempting' -and $attempts.ContainsKey($stepId)) {
            $last = $attempts[$stepId][$attempts[$stepId].Count - 1]
            if ($null -eq $last.End) {
                $last.End = $fields['Ts']
                $last.Failed = ($outcome -ceq 'Failed' -and (Test-TenureDefinitiveFailure -ErrorText $fields['Error']))
            }
        }
        if ($outcome -ceq 'Applied') { [void]$changed.Add($stepId) }
        if ($outcome -cin 'Applied', 'Skipped' -and $fields['Action'] -ceq 'Create' -and -not [string]::IsNullOrEmpty($fields['ObservedId'])) {
            $createdIds[$stepId] = $fields['ObservedId']
        }
        switch -CaseSensitive ($outcome) {
            'Attempting' {
                [void]$uncertain.Add($stepId)
                if ($attempted.Add($stepId)) { $attemptedAt[$stepId] = $fields['Ts'] }
                if (-not $attempts.ContainsKey($stepId)) { $attempts[$stepId] = [System.Collections.Generic.List[hashtable]]::new() }
                $attempts[$stepId].Add(@{ At = $fields['Ts']; End = $null; Failed = $false })
            }
            'Applied' { [void]$applied.Add($stepId); [void]$uncertain.Remove($stepId); [void]$assumed.Remove($stepId) }
            'Skipped' {
                [void]$applied.Add($stepId); [void]$uncertain.Remove($stepId)
                # A step skipped in a run that named it in -AssumeFired was assumed fired, not seen to fire.
                if ($runAssumed -ccontains $stepId) { [void]$assumed.Add($stepId) }
            }
            'Failed' {
                $errorText = [string]$fields['Error']
                if ($errorText.StartsWith('Tenure.Apply.Interrupted', [System.StringComparison]::Ordinal)) {
                    [void]$uncertain.Add($stepId)
                } else {
                    [void]$uncertain.Remove($stepId)
                }
            }
        }
    }
    # An attempt that did not end in a recorded failure may have changed the state too.
    foreach ($stepId in @($attempts.Keys)) {
        if (@($attempts[$stepId] | Where-Object { -not $_.Failed }).Count -gt 0) { [void]$changed.Add($stepId) }
    }
    @{ Applied = $applied; Uncertain = $uncertain; Attempted = $attempted; AttemptedAt = $attemptedAt; CreatedIds = $createdIds; Changed = $changed; Attempts = $attempts; Assumed = $assumed; FinishedApplied = $finishedApplied; OpenRun = $open }
}

function Open-TenureAuditRun {
    <#
    .SYNOPSIS
        Starts a run of a plan in the audit log: under the writer lock, reads the plan's
        history, refuses when an earlier run is still open, and appends PlanStarted.
    .DESCRIPTION
        Doing the check and the append under one lock means two shells starting the same
        plan cannot both see "no open run". Throws Tenure.Plan.RunInProgress unless
        -Resume, and Tenure.Plan.AlreadyApplied when a run of the plan already finished
        Applied, unless -Force (Assert-TenureRunAllowed). Returns @{ Entry (the PlanStarted
        Tenure.AuditEntry); History }.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PlanId,
        [Parameter(Mandatory)][hashtable]$Entry,
        [switch]$Resume,
        [switch]$Force
    )

    $record = New-TenureAuditRecord -Entry $Entry
    $file = Resolve-TenureAuditPath -Path $Path
    $stream = Open-TenureAuditStream -Path $file
    try {
        $lines = @(Split-TenureAuditText -Text (Read-TenureAuditStreamText -Stream $stream))
        $history = Get-TenureAuditHistory -Line $lines -PlanId $PlanId -Path $file
        Assert-TenureRunAllowed -History $history -PlanId $PlanId -Path $file -Resume:$Resume -Force:$Force
        $hash = Add-TenureAuditRecord -Stream $stream -Path $file -Record $record
    } catch {
        if (Get-TenureErrorId -ErrorRecord $_) { throw $_ }
        $inner = Get-TenureAuditInnerException -ErrorRecord $_
        throw (New-TenureError -Id 'Tenure.Audit.Unwritable' -Message "Cannot write the audit log '$file': $($inner.Message)" -Category WriteError -Data @{ Path = $file })
    } finally {
        $stream.Dispose()
    }
    @{ Entry = (ConvertTo-TenureAuditEntry -Record $record -Hash $hash); History = $history }
}

function Test-TenureDefinitiveFailure {
    <#
    .SYNOPSIS
        True when a step's recorded error shows that Set changed nothing: the request was refused before it was sent or by the service.
    .DESCRIPTION
        Definitive: a refused or impossible request (Tenure.Graph.Forbidden, NotFound,
        NotConnected; Tenure.Exchange.NotConnected, CommandUnavailable; Tenure.Provider.InvalidDesired,
        Precondition, Unsupported) and Tenure.Graph.Failed with a 4xx status other than 408.
        Anything else may have landed: an interruption, a timeout, a 5xx or throttling that
        outlasted the retries, an unknown exception, a failed read-back or post-condition.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$ErrorText)

    $text = [string]$ErrorText
    foreach ($id in 'Tenure.Graph.Forbidden:', 'Tenure.Graph.NotFound:', 'Tenure.Graph.NotConnected:', 'Tenure.Exchange.NotConnected:', 'Tenure.Exchange.CommandUnavailable:', 'Tenure.Provider.InvalidDesired:', 'Tenure.Provider.Precondition:', 'Tenure.Provider.Unsupported:') {
        if ($text.StartsWith($id, [System.StringComparison]::Ordinal)) { return $true }
    }
    if ($text.StartsWith('Tenure.Graph.Failed:', [System.StringComparison]::Ordinal) -and $text -cmatch ' returned (4\d\d)\b' -and $Matches[1] -cne '408') { return $true }
    $false
}

function Assert-TenureRunAllowed {
    <#
    .SYNOPSIS
        Refuses a run the audit log says must not start: one while an earlier run is open, or one of a plan that already finished Applied.
    .DESCRIPTION
        Tenure.Plan.RunInProgress unless -Resume. Tenure.Plan.AlreadyApplied, unless -Force,
        when a PlanFinished of an earlier Apply run recorded the plan as Applied: the plan file's
        Status is not sealed and a plan applied as an object never writes its file, so the log
        decides, whatever the file says.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][hashtable]$History,
        [Parameter(Mandatory)][string]$PlanId,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Resume,
        [switch]$Force
    )

    if ($History.OpenRun -and -not $Resume) {
        throw (New-TenureError -Id 'Tenure.Plan.RunInProgress' -Message "The audit log '$Path' shows a run of plan $PlanId that started and never finished: another run is in progress, or one died. Check that no other shell is applying this plan, then pass -Resume." -Category ResourceBusy -Data @{ Path = $Path; PlanId = $PlanId })
    }
    if ($History.FinishedApplied -and -not $Force) {
        throw (New-TenureError -Id 'Tenure.Plan.AlreadyApplied' -Message "The audit log '$Path' shows plan $PlanId already finished Applied, whatever its file says. Build a new plan to make further changes, or pass -Force to apply this one again." -Category InvalidOperation -Data @{ Path = $Path; PlanId = $PlanId })
    }
}

function Test-TenureAuditChain {
    <#
    .SYNOPSIS
        Recomputes the hash chain of an audit file from the first line.
    .DESCRIPTION
        An entry is intact when its line is well formed, its Seq is one more than the
        previous entry (1 for the first), its PrevHash is the previous Hash (64 zeros
        for the first), and its Hash equals sha256(PrevHash + body). FirstBrokenSeq is
        the sequence number at the first position that fails: a tampered line reports
        its own Seq, a deleted line reports the missing Seq.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    $lines = @(Read-TenureAuditFile -Path $Path)
    $expected = [long]1
    $previous = $script:AuditZeroHash
    $broken = $null
    $problem = $null
    for ($position = 0; $position -lt $lines.Count; $position++) {
        $line = $lines[$position]
        $parsed = ConvertFrom-TenureAuditLine -Text $line.Text
        $intact = $false
        if ($null -ne $parsed -and $parsed.Seq -eq $expected -and $parsed.PrevHash -ceq $previous) {
            $hash = Get-TenureHash -InputObject ($previous + $parsed.Body)
            $intact = ($hash -ceq $parsed.Hash)
        }
        if (-not $intact) {
            $broken = [int]$expected
            Write-Verbose ("Audit chain breaks at Seq {0} (line {1} of '{2}')." -f $expected, $line.Number, $Path)
            if ($null -eq $parsed -and $position -eq $lines.Count - 1) {
                # A torn tail: the last line is not a whole entry. Everything before it chained correctly.
                $problem = "Line $($line.Number), the last line, is not a complete audit entry: a write was cut off, or the line was edited. The lines before it are intact. $(Get-TenureAuditRepairHint -Path $Path -KeepLines ($line.Number - 1))"
            } else {
                $problem = "The entry expected as Seq $expected, on line $($line.Number), does not chain to the entry before it: the log was edited, or lines were removed, inserted or reordered. Do not repair it by hand; keep the file as evidence, start a new audit log (-AuditPath or TENURE_AUDIT_PATH), and compare the entries with the AuditHead values you kept."
            }
            break
        }
        $previous = $parsed.Hash
        $expected++
    }

    [pscustomobject]@{
        PSTypeName     = 'Tenure.AuditTestResult'
        Valid          = ($null -eq $broken)
        Entries        = $lines.Count
        FirstBrokenSeq = $broken
        Problem        = $problem
    }
}

function ConvertFrom-TenureTimestamp {
    <#
    .SYNOPSIS
        Converts a [datetime], [datetimeoffset] or ISO 8601 string to a UTC [datetime],
        or returns $null when the value cannot be read as a date.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    if ($Value -is [string]) {
        $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    }
    $null
}
