function Get-TenurePolicy {
    <#
    .SYNOPSIS
        Loads and validates a Tenure policy from a JSON file or from an object.
    .DESCRIPTION
        A policy holds the per-tenant configuration: the UPN domain, offboarding defaults
        and the role templates (licenses, groups, department, job title) that plans are
        built from. Nothing tenant-specific lives in the module itself.

        The file is checked strictly. Unknown keys are errors at every level, so a typo
        such as "devcies" cannot pass silently. Keys that start with an underscore (for
        example "_comment") are allowed anywhere and ignored. A key you leave out takes the
        default from docs/SPEC.md section 2.1.

        Other checks: passwordLength is an integer from 8 to 256, and the entries of
        licenses, groups, protectedUsers and keepGroups may not be empty or whitespace.

        Group and license names are not looked up here. They are resolved to ids when a
        plan is built, so a misspelled name shows up at plan time.

        The result carries Hash, the SHA-256 of the canonical JSON of the content as loaded
        (before defaults are applied). Plans record it so a changed policy is visible.
    .PARAMETER Path
        Path to a policy JSON file. Relative paths are resolved against the current location.
    .PARAMETER InputObject
        A hashtable or PSCustomObject holding the same structure as the file. The object is
        copied and never modified.
    .EXAMPLE
        $policy = Get-TenurePolicy -Path ./tenure.policy.json
        $policy.Roles.Keys

        Loads a policy file and lists its role names.
    .EXAMPLE
        Get-TenurePolicy -InputObject @{ version = 1; roles = @{ warehouse = @{ licenses = @('EXCHANGEDESKLESS') } } }

        Builds a policy in memory, for example from a tool that generates one.
    .EXAMPLE
        try { Get-TenurePolicy -Path ./tenure.policy.json } catch { $_.Exception.Data['Path'] }

        Prints the JSON path of the first problem, for example $.defaults.offboard.devices.
    .OUTPUTS
        Tenure.Policy
        Properties: Version, Tenant, Defaults, Roles, ManagedSet (Licenses and Groups used
        by any role), Hash and Path (null when loaded from an object).
        Errors: Tenure.Policy.NotFound, Tenure.Policy.Invalid (the message starts with the
        JSON path of the first problem; Exception.Data['Path'] holds it and
        Exception.Data['Problems'] lists every problem).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType('Tenure.Policy')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'InputObject')]
        [AllowNull()]
        [object]$InputObject
    )

    $fullPath = $null
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $fullPath = if ([string]::IsNullOrWhiteSpace($Path)) { '' } else { $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path) }
        $raw = Read-TenurePolicyFile -FullPath $fullPath
    } else {
        $raw = ConvertTo-TenurePolicyRaw -InputObject $InputObject
    }

    $problems = @(Get-TenurePolicyProblem -Raw $raw)
    if ($problems.Count -gt 0) {
        $data = @{ Path = $problems[0].Path; Problems = [string[]]@($problems | ForEach-Object { $_.Message }) }
        if ($fullPath) { $data['FilePath'] = $fullPath }
        throw (New-TenureError -Id 'Tenure.Policy.Invalid' -Message $problems[0].Message -Category InvalidData -Data $data)
    }

    if ($fullPath) { ConvertTo-TenurePolicy -Raw $raw -Path $fullPath } else { ConvertTo-TenurePolicy -Raw $raw -Path $null }
}
