function Get-TenureAudit {
    <#
    .SYNOPSIS
        Reads entries from the Tenure audit log, optionally filtered by plan, time and count.
    .DESCRIPTION
        Returns Tenure.AuditEntry objects in file order. -PlanId and -Since filter first;
        -Last then keeps the last N of what is left. A missing audit file returns nothing.
        Values come back exactly as written (a date-like string stays a string; Ts is the
        UTC round-trip string). A line that is not a strict JSON object, including one
        with a key repeated in a different case, throws Tenure.Audit.Corrupt naming the
        line number. Use Test-TenureAudit to verify the hash chain.

        The path is -Path, else $env:TENURE_AUDIT_PATH, else ~/.tenure/audit.jsonl. Keep
        the audit log on a local file system: its writer lock is not honored on network
        shares or cloud-synced folders.
    .PARAMETER Path
        The audit log file.
    .PARAMETER PlanId
        Only entries of this plan.
    .PARAMETER Last
        Only the last N entries (after the other filters).
    .PARAMETER Since
        Only entries whose timestamp is at or after this time. A time without a zone is
        treated as local time.
    .EXAMPLE
        Get-TenureAudit -PlanId $result.Plan.PlanId | Format-Table Seq, StepId, Provider, Outcome, Error

        Reconstructs one run.
    .EXAMPLE
        Get-TenureAudit -Since (Get-Date).AddDays(-1) -Last 20
    .OUTPUTS
        Tenure.AuditEntry
    #>
    [CmdletBinding()]
    [OutputType('Tenure.AuditEntry')]
    param(
        [string]$Path,

        [string]$PlanId,

        [ValidateRange(1, [int]::MaxValue)]
        [int]$Last,

        [datetime]$Since
    )

    $file = Resolve-TenureAuditPath -Path $Path
    $sinceUtc = $null
    if ($PSBoundParameters.ContainsKey('Since')) { $sinceUtc = $Since.ToUniversalTime() }

    $selected = [System.Collections.Generic.List[object]]::new()
    foreach ($line in @(Read-TenureAuditFile -Path $file)) {
        $model = $null
        try {
            $model = ConvertFrom-TenureJsonText -Text $line.Text -ErrorId 'Tenure.Audit.Corrupt'
        } catch {
            $model = $null
        }
        if (-not ($model -is [System.Collections.IDictionary])) {
            throw (New-TenureError -Id 'Tenure.Audit.Corrupt' -Message "Line $($line.Number) of the audit log '$file' is not a valid audit entry." -Category InvalidData -Data @{ Path = $file; Line = $line.Number })
        }
        if ($PSBoundParameters.ContainsKey('PlanId')) {
            $entryPlanId = Get-TenureApplyMember -InputObject $model -Name 'PlanId'
            if ($null -eq $entryPlanId -or [string]$entryPlanId -ne $PlanId) { continue }
        }
        if ($null -ne $sinceUtc) {
            $ts = ConvertFrom-TenureTimestamp -Value (Get-TenureApplyMember -InputObject $model -Name 'Ts')
            if ($null -eq $ts) {
                throw (New-TenureError -Id 'Tenure.Audit.Corrupt' -Message "Line $($line.Number) of the audit log '$file' has no readable Ts." -Category InvalidData -Data @{ Path = $file; Line = $line.Number })
            }
            if ($ts -lt $sinceUtc) { continue }
        }
        $entry = ConvertTo-TenureObjectTree -InputObject $model
        $entry.PSObject.TypeNames.Insert(0, 'Tenure.AuditEntry')
        $selected.Add($entry)
    }

    $start = 0
    if ($PSBoundParameters.ContainsKey('Last') -and $selected.Count -gt $Last) { $start = $selected.Count - $Last }
    for ($index = $start; $index -lt $selected.Count; $index++) { $selected[$index] }
}
