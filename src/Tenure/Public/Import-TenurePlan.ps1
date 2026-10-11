function Import-TenurePlan {
    <#
    .SYNOPSIS
        Loads a plan file written by Export-TenurePlan and checks it is well formed.
    .DESCRIPTION
        Refuses a file with a schema version other than the one this module writes
        (Tenure.Plan.UnsupportedSchema: a newer one needs a newer module, an older one has no
        integrity value and must be planned again), a file that is missing or has malformed
        required parts (Tenure.Plan.Invalid, with the JSON path of the problem), duplicate step
        ids, a DependsOn that names an unknown step or a step that comes later, and a file
        whose Integrity value does not match its content (Tenure.Plan.Tampered): steps,
        targets, desired states, the subject and the recorded policy facts may not be edited
        after a plan is built. Statuses and results, which the apply engine writes, may change.

        Types are normalized so an imported plan behaves like a freshly built one: Steps is
        always an array, Target and After are hashtables (nested objects too), Before and
        Result.Observed are PSCustomObjects, DependsOn and Warnings are string arrays,
        Inputs is a hashtable, CreatedAt is a UTC [datetime], and the Tenure.Plan and
        Tenure.Step type names are restored. Fingerprints survive the round trip: for every
        step, a fingerprint computed from the step's Target (Kind and Id) and Before equals the
        stored Fingerprint. The importer checks that each fingerprint is a lowercase sha256 hex
        string; the apply engine compares it to the live state.

        Strings that look like dates stay strings. Property names of the plan and step
        records are matched without regard to case.
    .PARAMETER Path
        Path to the plan JSON file.
    .EXAMPLE
        $plan = Import-TenurePlan -Path ./offboard-alex.plan.json
        $plan.Steps | Select-Object Id, Provider, Action

        Loads a saved plan and lists its steps.
    .OUTPUTS
        Tenure.Plan
        Errors: Tenure.Plan.NotFound, Tenure.Plan.Invalid, Tenure.Plan.UnsupportedSchema,
        Tenure.Plan.Tampered.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Plan')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $fullPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw (New-TenureError -Id 'Tenure.Plan.NotFound' -Message "Plan file '$fullPath' was not found." -Category ObjectNotFound -Data @{ FilePath = $fullPath })
    }
    $text = $null
    try {
        $text = [System.IO.File]::ReadAllText($fullPath, [System.Text.UTF8Encoding]::new($false, $true))
    } catch {
        $cause = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
        if ($cause -is [System.Text.DecoderFallbackException]) {
            throw (Get-TenureValidationError -Id 'Tenure.Plan.Invalid' -Path '$' -Message 'the file is not valid UTF-8 text' -Data @{ FilePath = $fullPath })
        }
        throw (New-TenureError -Id 'Tenure.Plan.NotFound' -Message "Plan file '$fullPath' could not be read: $($cause.Message)" -Category ReadError -Data @{ FilePath = $fullPath })
    }

    $model = ConvertFrom-TenureJsonText -Text $text -ErrorId 'Tenure.Plan.Invalid'
    if ($model -isnot [System.Collections.IDictionary]) {
        throw (Get-TenureValidationError -Id 'Tenure.Plan.Invalid' -Path '$' -Message ('a plan file must hold a JSON object (got {0})' -f (Get-TenureValueTypeName $model)))
    }
    if (-not $model.Contains('SchemaVersion')) {
        throw (Get-TenureValidationError -Id 'Tenure.Plan.Invalid' -Path '$.SchemaVersion' -Message 'required property is missing')
    }
    $version = ConvertTo-TenureInteger $model['SchemaVersion']
    if ($null -eq $version -or $version -lt 1) {
        throw (Get-TenureValidationError -Id 'Tenure.Plan.Invalid' -Path '$.SchemaVersion' -Message 'must be a positive integer')
    }
    if ($version -gt $script:PlanSchemaVersion) {
        throw (New-TenureError -Id 'Tenure.Plan.UnsupportedSchema' -Message "The plan file uses schema version $version; this version of Tenure reads version $($script:PlanSchemaVersion). Upgrade the module to apply it." -Category InvalidData -Data @{ SchemaVersion = $version; FilePath = $fullPath })
    }
    if ($version -lt $script:PlanSchemaVersion) {
        # No migration: an older file has no integrity value and may carry steps without a fingerprint, so
        # nothing in it can be trusted to be what was reviewed. Plans are short-lived; build a new one.
        throw (New-TenureError -Id 'Tenure.Plan.UnsupportedSchema' -Message "The plan file uses schema version $version, written by an earlier version of Tenure. This version reads version $($script:PlanSchemaVersion) only, because older plans carry no integrity value. Build the plan again." -Category InvalidData -Data @{ SchemaVersion = $version; FilePath = $fullPath })
    }

    try {
        $plan = ConvertFrom-TenurePlanModel -Model $model
        $null = Assert-TenurePlanIntegrity -Plan $plan
        $plan
    } catch {
        if ($_.Exception.Data.Contains('TenureId')) { $_.Exception.Data['FilePath'] = $fullPath }
        throw
    }
}
