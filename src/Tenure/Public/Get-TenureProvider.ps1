function Get-TenureProvider {
    <#
    .SYNOPSIS
        Lists the registered Tenure providers: what each one changes, which backend it
        uses, the Graph scopes it needs, and its risk.
    .DESCRIPTION
        Providers are the only components that read or write tenant state. Plan
        builders compose steps from them; Invoke-TenurePlan runs them. Use this to see
        which scopes Connect-Tenure will request, or to audit risk per provider.
    .PARAMETER Name
        One or more provider names. Wildcards are allowed (for example 'Mailbox.*').
    .EXAMPLE
        Get-TenureProvider | Format-Table Name, Kind, Backend, Risk, Reversible
    .EXAMPLE
        Get-TenureProvider -Name 'Device.*' | Select-Object Name, Scopes
    .EXAMPLE
        Get-TenureProvider | Format-Table Name, TargetKind, Actions, AffectedBy

        Shows the kind of object each provider acts on, the step actions it allows, and for a
        check the providers whose steps change what it reads.
    .EXAMPLE
        Get-TenureProvider | Where-Object Repeatable | Select-Object Name

        Lists the Invoke providers that are safe to fire twice, which a resumed run may run
        again when an earlier attempt left no record of its outcome.
    .OUTPUTS
        Tenure.Provider
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Provider')]
    param(
        [Parameter(Position = 0, ValueFromPipeline)]
        [SupportsWildcards()]
        [string[]]$Name
    )

    process {
        $all = @($script:Providers.Values)
        if (-not $Name) { return $all }
        foreach ($pattern in $Name) {
            $matched = @($all | Where-Object { $_.Name -like $pattern })
            if ($matched.Count -eq 0 -and -not [WildcardPattern]::ContainsWildcardCharacters($pattern)) {
                throw (New-TenureError -Id 'Tenure.Provider.NotRegistered' -Message "No provider named '$pattern' is registered." -Category ObjectNotFound)
            }
            $matched
        }
    }
}
