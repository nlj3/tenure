function Test-TenureAudit {
    <#
    .SYNOPSIS
        Verifies the hash chain of the Tenure audit log and reports the first broken entry.
    .DESCRIPTION
        Walks the audit log from the first line. Each entry must have the next sequence
        number, carry the previous entry's hash as PrevHash (64 zeros for the first), and
        hash to its own Hash: sha256(PrevHash + canonical JSON of the entry without Hash).
        An edited, inserted, reordered or deleted line breaks the chain from that point.

        Valid is $true for an intact log, including a missing or empty one. Entries is
        the number of non-blank lines. FirstBrokenSeq is the sequence number at the first
        position that fails (the edited entry, or the missing one), or $null. Problem says,
        for a broken log, which line breaks it and what to do: a last line that is not a
        complete entry (a write cut off by a crash or a full disk) is a torn tail, and the
        message gives the command that keeps the intact lines before it in a copy; any
        other break means the log was edited and should be kept as evidence, not repaired.

        The chain is tamper-evident, not tamper-proof: someone who rewrites the whole
        file can recompute it (ADR-0003). Deleting entries from the end of the file is not
        detectable from the file alone, because what is left is still a valid chain. The
        external anchor is the AuditHead (Seq and Hash of the last entry written) on every
        Invoke-TenurePlan result: keep it somewhere else and check that the entry with that
        Seq is still present and still has that Hash.
    .PARAMETER Path
        The audit log file. Defaults to $env:TENURE_AUDIT_PATH, then ~/.tenure/audit.jsonl.
    .EXAMPLE
        Test-TenureAudit

        Valid Entries FirstBrokenSeq
        ----- ------- --------------
         True     212
    .EXAMPLE
        $head = $result.AuditHead
        $entry = Get-TenureAudit -Path ./audit.jsonl | Where-Object Seq -eq $head.Seq
        (Test-TenureAudit -Path ./audit.jsonl).Valid -and $entry.Hash -eq $head.Hash

        Checks the chain and that the tail recorded by a run is still there.
    .EXAMPLE
        $check = Test-TenureAudit -Path ./audit.jsonl
        if (-not $check.Valid) { $check.Problem }

        Prints which line breaks the chain and what to do about it.
    .OUTPUTS
        Tenure.AuditTestResult with Valid, Entries, FirstBrokenSeq and Problem.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.AuditTestResult')]
    param(
        [string]$Path
    )

    Test-TenureAuditChain -Path (Resolve-TenureAuditPath -Path $Path)
}
