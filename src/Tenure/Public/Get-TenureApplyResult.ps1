function Get-TenureApplyResult {
    <#
    .SYNOPSIS
        Returns the result of the last Invoke-TenurePlan run in this session, including
        a run that was stopped with Ctrl+C.
    .DESCRIPTION
        Invoke-TenurePlan keeps its Tenure.ApplyResult in module state when a run ends,
        normally or not. Use this after Ctrl+C (or any error that ended a run) to recover
        the plan statuses and any generated secrets, which are returned only as
        SecureString values in Secrets and are not written anywhere else.

        Runs with -WhatIf do not replace the stored result. The result stays in memory
        until the next run or until the module is removed or re-imported.
    .EXAMPLE
        Invoke-TenurePlan $plan    # stopped with Ctrl+C during step S03
        $last = Get-TenureApplyResult
        $last.Plan.Steps | Format-Table Id, Status
        $last.Secrets['S02']   # the generated password, as a SecureString

        Recovers what happened before the stop.
    .OUTPUTS
        Tenure.ApplyResult, or nothing when no run has finished in this session.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.ApplyResult')]
    param()

    $script:LastApplyResult
}
