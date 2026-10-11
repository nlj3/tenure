function New-TenurePolicy {
    <#
    .SYNOPSIS
        Writes the example policy file to a path, ready to edit.
    .DESCRIPTION
        Copies the example policy that ships with the module byte for byte. It holds the
        offboarding defaults from the spec, two sample roles (sales and warehouse) and a
        _comment explaining that group and license names are resolved when a plan is built.
        Edit the domain, the protected users and the roles, then check it with
        Test-TenurePolicy. An existing file is not overwritten unless -Force is given.
    .PARAMETER Path
        Where to write the file.
    .PARAMETER Force
        Overwrite the file if it already exists.
    .EXAMPLE
        New-TenurePolicy -Path ./tenure.policy.json

        Creates a starter policy in the current directory.
    .EXAMPLE
        New-TenurePolicy -Path ./tenure.policy.json -WhatIf

        Shows what would be written without writing it.
    .OUTPUTS
        None. Errors: Tenure.Policy.Exists when the file exists and -Force is not given.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([void])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [switch]$Force
    )

    $destination = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
    if ((Test-Path -LiteralPath $destination) -and -not $Force) {
        throw (New-TenureError -Id 'Tenure.Policy.Exists' -Message "A file already exists at '$destination'. Use -Force to overwrite it." -Category ResourceExists -Data @{ FilePath = $destination })
    }
    $source = Join-Path -Path $script:ModuleRoot -ChildPath (Join-Path -Path 'Policies' -ChildPath 'example.policy.json')
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw (New-TenureError -Id 'Tenure.Policy.NotFound' -Message "The example policy is missing from the module at '$source'." -Category ObjectNotFound -Data @{ FilePath = $source })
    }
    if ($PSCmdlet.ShouldProcess($destination, 'Write example policy')) {
        try {
            [System.IO.File]::Copy($source, $destination, [bool]$Force)
        } catch {
            $cause = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
            throw (New-TenureError -Id 'Tenure.Policy.WriteFailed' -Message "Could not write '$destination': $($cause.Message)" -Category WriteError -Data @{ FilePath = $destination })
        }
    }
}
