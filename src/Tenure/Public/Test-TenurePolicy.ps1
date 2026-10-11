function Test-TenurePolicy {
    <#
    .SYNOPSIS
        Checks a policy file and reports every problem without throwing.
    .DESCRIPTION
        Runs the same validation as Get-TenurePolicy but collects all problems instead of
        stopping at the first, which suits an editor or a pre-commit check. A missing file
        or malformed JSON is reported as an invalid result with one error, never as an
        exception. Each error string starts with the JSON path of the problem.
    .PARAMETER Path
        Path to a policy JSON file.
    .EXAMPLE
        Test-TenurePolicy -Path ./tenure.policy.json

        Returns @{ Valid = $true; Errors = @() } for a good file.
    .EXAMPLE
        (Test-TenurePolicy -Path ./tenure.policy.json).Errors

        Lists the problems, for example "$.roles.sales.licenseIds: unknown key 'licenseIds' (allowed: department, groups, jobTitle, licenses, manager)".
    .OUTPUTS
        System.Collections.Hashtable
        Valid (bool) and Errors (string[]).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Path
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    try {
        $fullPath = if ([string]::IsNullOrWhiteSpace($Path)) { '' } else { $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path) }
        $raw = Read-TenurePolicyFile -FullPath $fullPath
        foreach ($problem in @(Get-TenurePolicyProblem -Raw $raw)) { $errors.Add($problem.Message) }
    } catch {
        $problems = $_.Exception.Data['Problems']
        if ($problems) { foreach ($message in $problems) { $errors.Add([string]$message) } } else { $errors.Add($_.Exception.Message) }
    }
    @{ Valid = ($errors.Count -eq 0); Errors = $errors.ToArray() }
}
