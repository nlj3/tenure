function Invoke-TenureExchange {
    <#
    .SYNOPSIS
        Exchange seam: runs an Exchange Online cmdlet by name with a parameter hashtable.
    .DESCRIPTION
        Exchange Online cmdlets only exist after Connect-ExchangeOnline, so the command
        is resolved at call time. Error ids: Tenure.Exchange.NotConnected,
        Tenure.Exchange.CommandUnavailable, Tenure.Exchange.Failed (Data.Inner holds the
        original ErrorRecord). Unit tests mock this function.
    .EXAMPLE
        Invoke-TenureExchange -Command 'Set-Mailbox' -Parameters @{ Identity = 'alice@example.com'; Type = 'Shared' }
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z][A-Za-z]+-[A-Z][A-Za-z0-9]+$')]
        [string]$Command,

        [hashtable]$Parameters = @{}
    )

    Assert-TenureConnection -Backend Exchange

    $resolved = Get-Command -Name $Command -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $resolved) {
        throw (New-TenureError -Id 'Tenure.Exchange.CommandUnavailable' -Message "Exchange cmdlet '$Command' is not available in this session. Connect with Connect-Tenure (Exchange included) and check the signed-in Exchange role." -Category ObjectNotFound -Data @{ Command = $Command })
    }

    $splat = @{}
    foreach ($key in $Parameters.Keys) { $splat[$key] = $Parameters[$key] }
    $splat['ErrorAction'] = 'Stop'

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $resolved @splat
        Write-Verbose ("Exchange {0} ({1} ms)" -f $Command, $stopwatch.ElapsedMilliseconds)
        return $result
    } catch {
        throw (New-TenureError -Id 'Tenure.Exchange.Failed' -Message "Exchange cmdlet '$Command' failed: $($_.Exception.Message)" -Category NotSpecified -Data @{ Command = $Command; Inner = $_ } -Inner $_)
    }
}
