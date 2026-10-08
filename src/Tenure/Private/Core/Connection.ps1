function Assert-TenureConnection {
    <#
    .SYNOPSIS
        Throws Tenure.Graph.NotConnected or Tenure.Exchange.NotConnected unless the
        session established by Connect-Tenure has that backend.
    .DESCRIPTION
        The two seams call this before every request. Connect-Tenure (S9) sets
        $script:Session to a Tenure.Connection object with boolean Graph and Exchange
        members. Unit tests mock this function.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Graph', 'Exchange')]
        [string]$Backend
    )

    $connected = $false
    if ($null -ne $script:Session -and $script:Session.PSObject.Properties[$Backend]) {
        $connected = [bool]$script:Session.$Backend
    }
    if (-not $connected) {
        $hint = if ($Backend -eq 'Exchange') { 'Run Connect-Tenure without -SkipExchange.' } else { 'Run Connect-Tenure first.' }
        throw (New-TenureError -Id "Tenure.$Backend.NotConnected" -Message "Not connected to $Backend. $hint" -Category ConnectionError)
    }
}
