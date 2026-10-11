function Get-TenureConnection {
    <#
    .SYNOPSIS
        Shows the current Tenure session after checking that Microsoft Graph and
        Exchange Online are still connected.
    .DESCRIPTION
        Returns the Tenure.Connection recorded by Connect-Tenure, or $null when there is
        none. Before returning it, the session is checked live: Graph is marked
        disconnected when there is no Graph context or the context now belongs to another
        tenant or account (someone ran Connect-MgGraph since), and Exchange is marked
        disconnected when no Exchange Online connection is in the Connected state or the
        newest one belongs to another tenant. A backend is never marked connected again
        here; run Connect-Tenure for that. Never throws.
    .EXAMPLE
        Get-TenureConnection

        Shows the account, tenant, auth type and whether each backend is connected.
    .EXAMPLE
        (Get-TenureConnection).MissingScopes

        Lists the expected Graph scopes that were not granted at sign-in.
    .OUTPUTS
        Tenure.Connection, or nothing when not connected.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Connection')]
    param()

    $session = $script:Session
    if ($null -eq $session) { return $null }

    try {
        if ($session.PSObject.Properties['Graph'] -and [bool]$session.Graph) {
            $graphConnected = $false
            try {
                $context = Get-TenureGraphContext
                if ($null -ne $context) {
                    $identity = Get-TenureGraphIdentity -Context $context
                    $sameTenant = Test-TenureSameTenant -Left $identity.TenantId -Right ([string](Get-TenureProperty -InputObject $session -Name 'TenantId'))
                    $sessionAccount = [string](Get-TenureProperty -InputObject $session -Name 'Account')
                    $sameAccount = [string]::IsNullOrEmpty($sessionAccount) -or [string]::IsNullOrEmpty($identity.Account) -or ($sessionAccount -ieq $identity.Account)
                    if ($sameTenant -and $sameAccount) {
                        $graphConnected = $true
                    } else {
                        Write-Warning ("The Microsoft Graph context now belongs to {0} in tenant {1}, not the account and tenant Connect-Tenure signed in with. Tenure treats Graph as disconnected; run Connect-Tenure again." -f $identity.Account, $identity.TenantId)
                    }
                }
                $context = $null
            } catch {
                Write-Verbose "Get-TenureConnection: reading the Graph context failed: $($_.Exception.Message)"
            }
            if (-not $graphConnected) {
                Write-Verbose 'Get-TenureConnection: Microsoft Graph is no longer connected.'
                $session.Graph = $false
            }
        }

        if ($session.PSObject.Properties['Exchange'] -and [bool]$session.Exchange) {
            $exchangeConnected = $false
            try {
                $newest = Select-TenureExchangeConnection -Connection @(Get-TenureExchangeConnection)
                if ($null -ne $newest) {
                    $exchangeTenant = [string](Get-TenureProperty -InputObject $newest -Name 'TenantID')
                    if (Test-TenureSameTenant -Left $exchangeTenant -Right ([string](Get-TenureProperty -InputObject $session -Name 'TenantId'))) {
                        $exchangeConnected = $true
                    } else {
                        Write-Warning ("The newest Exchange Online connection belongs to tenant {0}, not the tenant Connect-Tenure signed in to. Tenure treats Exchange as disconnected; run Connect-Tenure again." -f $exchangeTenant)
                    }
                }
            } catch {
                Write-Verbose "Get-TenureConnection: reading the Exchange Online connections failed: $($_.Exception.Message)"
            }
            if (-not $exchangeConnected) {
                Write-Verbose 'Get-TenureConnection: Exchange Online is no longer connected.'
                $session.Exchange = $false
            }
        }

        Copy-TenureConnection -Session $session
    } catch {
        # Fail closed: an unexpected error must not leave the session claiming a backend.
        Write-Verbose "Get-TenureConnection: validation failed, marking both backends disconnected: $($_.Exception.Message)"
        if ($session.PSObject.Properties['Graph']) { $session.Graph = $false }
        if ($session.PSObject.Properties['Exchange']) { $session.Exchange = $false }
        try { Copy-TenureConnection -Session $session } catch { $null }
    }
}
