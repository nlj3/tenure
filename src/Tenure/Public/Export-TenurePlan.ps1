function Export-TenurePlan {
    <#
    .SYNOPSIS
        Saves a plan to a JSON file so it can be reviewed, kept, and applied later.
    .DESCRIPTION
        Writes the plan as JSON (schemaVersion 2, depth 20), UTF-8 without a byte order mark,
        LF line endings. Dates are written as UTC ISO 8601 strings and object keys are sorted
        so the same plan always produces the same file. The file is written to a temporary
        name first, flushed to disk and moved into place, so an interrupted write never leaves
        half a plan. The plan's Integrity value is written with it; a plan whose content no
        longer matches that value (edited after it was built) is refused with
        Tenure.Plan.Tampered and nothing is written.

        Before anything is written the plan is run through the canonical JSON writer, which
        refuses a SecureString or PSCredential anywhere in the plan
        (Tenure.Json.SecretRejected). A plan that nests deeper than 20 levels is refused
        rather than silently truncated. An existing file is not overwritten unless -Force.
    .PARAMETER Plan
        The Tenure.Plan to save.
    .PARAMETER Path
        Where to write the file.
    .PARAMETER Force
        Overwrite an existing file.
    .EXAMPLE
        Export-TenurePlan -Plan $plan -Path ./offboard-alex.plan.json

        Saves the plan for review.
    .EXAMPLE
        $plan | Export-TenurePlan -Path ./plan.json -Force -WhatIf

        Shows what would be written, and writes nothing.
    .OUTPUTS
        None. Errors: Tenure.Plan.Invalid, Tenure.Plan.Tampered, Tenure.Plan.Exists,
        Tenure.Plan.WriteFailed, Tenure.Json.SecretRejected.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([void])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object]$Plan,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [switch]$Force
    )

    process {
        if ($null -eq $Plan -or $Plan.PSObject.TypeNames -notcontains 'Tenure.Plan') {
            throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message '-Plan must be a Tenure.Plan from New-TenurePlan or Import-TenurePlan.' -Category InvalidArgument)
        }
        # Surfaces a stray SecureString as Tenure.Json.SecretRejected before any file is touched.
        $null = Get-TenureCanonicalJson -InputObject $Plan
        # A plan edited in memory after it was built would only be refused on import; refuse it here instead.
        $null = Assert-TenurePlanIntegrity -Plan $Plan

        $destination = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
        if ((Test-Path -LiteralPath $destination) -and -not $Force) {
            throw (New-TenureError -Id 'Tenure.Plan.Exists' -Message "A file already exists at '$destination'. Use -Force to overwrite it." -Category ResourceExists -Data @{ FilePath = $destination })
        }

        $exportable = ConvertTo-TenureExportObject -InputObject $Plan
        $json = ConvertTo-Json -InputObject $exportable -Depth 20 -WarningAction SilentlyContinue -WarningVariable truncation
        if (@($truncation).Count -gt 0) {
            throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message 'The plan nests deeper than 20 levels and cannot be saved without losing data.' -Category InvalidData)
        }
        $text = ($json -replace "`r`n", "`n") + "`n"

        if ($PSCmdlet.ShouldProcess($destination, 'Write plan file')) {
            $temporary = '{0}.{1}.tmp' -f $destination, [guid]::NewGuid().ToString('N')
            try {
                Write-TenureTemporaryFile -Path $temporary -Text $text
                [System.IO.File]::Move($temporary, $destination, [bool]$Force)
            } catch {
                if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
                $cause = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
                if ($cause -is [System.IO.IOException] -and -not $Force -and (Test-Path -LiteralPath $destination)) {
                    throw (New-TenureError -Id 'Tenure.Plan.Exists' -Message "A file already exists at '$destination'. Use -Force to overwrite it." -Category ResourceExists -Data @{ FilePath = $destination })
                }
                throw (New-TenureError -Id 'Tenure.Plan.WriteFailed' -Message "Could not write '$destination': $($cause.Message)" -Category WriteError -Data @{ FilePath = $destination })
            }
        }
    }
}
