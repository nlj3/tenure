function Assert-TenureConnection {
    <#
    .SYNOPSIS
        Throws Tenure.Graph.NotConnected or Tenure.Exchange.NotConnected unless the
        session established by Connect-Tenure has that backend.
    .DESCRIPTION
        The two seams call this before every request. Connect-Tenure sets
        $script:Session to a Tenure.Connection object with boolean Graph and Exchange
        members. Unit tests mock this function.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Graph', 'Exchange')]
        [string]$Backend
    )

    # Connect-Tenure populates $script:Session; Disconnect-Tenure clears it and
    # Get-TenureConnection may downgrade Graph or Exchange to $false. Only the booleans
    # are read here, so the check stays cheap enough for every seam call.
    $connected = $false
    if ($null -ne $script:Session -and $script:Session.PSObject.Properties[$Backend]) {
        $connected = [bool]$script:Session.$Backend
    }
    if (-not $connected) {
        $hint = if ($Backend -eq 'Exchange') { 'Run Connect-Tenure without -SkipExchange.' } else { 'Run Connect-Tenure first.' }
        throw (New-TenureError -Id "Tenure.$Backend.NotConnected" -Message "Not connected to $Backend. $hint" -Category ConnectionError)
    }
}

# ---------------------------------------------------------------------------------
# SDK wrappers. These six functions are the only code in the module that calls the
# SDK connect, context and disconnect cmdlets. Unit tests mock them; they run for real
# only in the integration suite.
# ---------------------------------------------------------------------------------

function Invoke-TenureGraphConnect {
    <#
    .SYNOPSIS
        Splats a parameter hashtable onto Connect-MgGraph and discards its output.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Parameters)

    $splat = @{}
    foreach ($key in $Parameters.Keys) { $splat[$key] = $Parameters[$key] }
    $splat['ErrorAction'] = 'Stop'
    $null = Connect-MgGraph @splat
}

function Get-TenureGraphContext {
    <#
    .SYNOPSIS
        Returns the current Microsoft Graph context (Get-MgContext), or $null.
    .DESCRIPTION
        The context object can carry a client secret or a certificate. Callers copy the
        few fields they need and never keep the object.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param()

    Get-MgContext -ErrorAction Stop
}

function Invoke-TenureGraphDisconnect {
    <#
    .SYNOPSIS
        Calls Disconnect-MgGraph and discards the context it returns.
    #>
    [CmdletBinding()]
    param()

    $null = Disconnect-MgGraph -ErrorAction Stop
}

function Invoke-TenureExchangeConnect {
    <#
    .SYNOPSIS
        Splats a parameter hashtable onto Connect-ExchangeOnline and discards its output.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Parameters)

    $splat = @{}
    foreach ($key in $Parameters.Keys) { $splat[$key] = $Parameters[$key] }
    $splat['ErrorAction'] = 'Stop'
    $null = Connect-ExchangeOnline @splat
}

function Get-TenureExchangeConnection {
    <#
    .SYNOPSIS
        Returns the Exchange Online connections of this PowerShell session
        (Get-ConnectionInformation), one by one. Wrap calls in @(...).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param()

    Get-ConnectionInformation -ErrorAction Stop
}

function Invoke-TenureExchangeDisconnect {
    <#
    .SYNOPSIS
        Calls Disconnect-ExchangeOnline without prompting.
    #>
    [CmdletBinding()]
    param()

    $null = Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
}

# ---------------------------------------------------------------------------------
# Helpers for Connect-Tenure, Disconnect-Tenure and Get-TenureConnection.
# ---------------------------------------------------------------------------------

function Test-TenureWindowsPlatform {
    <#
    .SYNOPSIS
        Returns $true on Windows. A function so tests can exercise both platforms.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    [bool]$IsWindows
}

function ConvertTo-TenureScopeList {
    <#
    .SYNOPSIS
        Trims, de-duplicates (case-insensitive) and sorts (ordinal, case-insensitive) scope names.
    .DESCRIPTION
        Returns a [string[]] wrapped so that an empty or single-item list survives the
        pipeline. Assign the result directly; do not wrap it in @(...).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][AllowEmptyCollection()][object[]]$Scope)

    $set = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in @($Scope)) {
        if ($null -eq $item) { continue }
        $name = ([string]$item).Trim()
        if ($name.Length -gt 0) { $null = $set.Add($name) }
    }
    $list = [string[]]::new($set.Count)
    $set.CopyTo($list)
    , $list
}

function Get-TenureDefaultScope {
    <#
    .SYNOPSIS
        The scopes Connect-Tenure expects when -Scopes is not given: the union of every
        registered provider's Scopes, plus User.Read for delegated sign-in.
    .DESCRIPTION
        User.Read is a delegated permission with no application equivalent, so it is
        left out for app-only connections (it would always be reported as missing).
        Returns a [string[]]; assign it directly, do not wrap it in @(...).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Delegated', 'AppOnly')]
        [string]$AuthType
    )

    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($provider in @(Get-TenureProvider)) {
        foreach ($scope in @($provider.Scopes)) { $all.Add($scope) }
    }
    if ($AuthType -eq 'Delegated') { $all.Add('User.Read') }
    ConvertTo-TenureScopeList -Scope $all.ToArray()
}

function Get-TenureMissingScope {
    <#
    .SYNOPSIS
        Returns the requested scopes that are not in the granted list (case-insensitive),
        as a [string[]]. Assign it directly, do not wrap it in @(...).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowNull()][AllowEmptyCollection()][string[]]$Requested,
        [AllowNull()][AllowEmptyCollection()][string[]]$Granted
    )

    $grantedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($scope in @($Granted)) { if ($scope) { $null = $grantedSet.Add($scope.Trim()) } }
    $missing = @(@($Requested) | Where-Object { $_ -and -not $grantedSet.Contains($_.Trim()) })
    ConvertTo-TenureScopeList -Scope $missing
}

function Get-TenureGraphIdentity {
    <#
    .SYNOPSIS
        Copies Account, TenantId, AuthType and Scopes out of a Graph context.
    .DESCRIPTION
        Only these four fields are read; the context itself (which may hold a client
        secret or certificate) is never stored. AuthType is 'Delegated' or 'AppOnly'.
        For app-only contexts Account falls back to the application (client) id, so the
        audit log still names who acted.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][object]$Context)

    $authType = if ([string](Get-TenureProperty -InputObject $Context -Name 'AuthType') -eq 'Delegated') { 'Delegated' } else { 'AppOnly' }
    $account = [string](Get-TenureProperty -InputObject $Context -Name 'Account')
    if ([string]::IsNullOrWhiteSpace($account) -and $authType -eq 'AppOnly') {
        $account = [string](Get-TenureProperty -InputObject $Context -Name 'ClientId')
    }
    if ([string]::IsNullOrWhiteSpace($account)) { $account = $null }
    $tenantId = [string](Get-TenureProperty -InputObject $Context -Name 'TenantId')
    if ([string]::IsNullOrWhiteSpace($tenantId)) { $tenantId = $null }
    $granted = ConvertTo-TenureScopeList -Scope @(Get-TenureProperty -InputObject $Context -Name 'Scopes')
    @{ Account = $account; TenantId = $tenantId; AuthType = $authType; Scopes = $granted }
}

function Test-TenureSameTenant {
    <#
    .SYNOPSIS
        $false only when both values are GUIDs and they differ. Anything that cannot be
        compared (empty, a domain name) counts as not proven different.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][string]$Left, [AllowNull()][string]$Right)

    $leftGuid = [guid]::Empty
    $rightGuid = [guid]::Empty
    if ([guid]::TryParse([string]$Left, [ref]$leftGuid) -and [guid]::TryParse([string]$Right, [ref]$rightGuid)) {
        return $leftGuid -eq $rightGuid
    }
    $true
}

function Select-TenureExchangeConnection {
    <#
    .SYNOPSIS
        Returns the newest connection whose State is 'Connected' (highest Id), or $null.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([AllowNull()][AllowEmptyCollection()][object[]]$Connection)

    $connected = @(@($Connection) | Where-Object { $null -ne $_ -and [string](Get-TenureProperty -InputObject $_ -Name 'State') -eq 'Connected' })
    if ($connected.Count -eq 0) { return $null }
    $connected | Sort-Object -Property @{ Expression = { [long](Get-TenureProperty -InputObject $_ -Name 'Id') } } -Descending | Select-Object -First 1
}

function Copy-TenureConnection {
    <#
    .SYNOPSIS
        A shallow copy of the session, so callers cannot flip the module's Graph or
        Exchange flags by editing the object they were handed.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Connection')]
    param([Parameter(Mandatory)][object]$Session)

    $copy = $Session.PSObject.Copy()
    foreach ($name in 'Scopes', 'RequestedScopes', 'MissingScopes') {
        $property = $copy.PSObject.Properties[$name]
        if ($property -and $property.Value -is [array]) { $property.Value = [string[]]@($property.Value) }
    }
    $copy
}

function Disconnect-TenureSession {
    <#
    .SYNOPSIS
        Clears the Tenure session, then disconnects Graph and Exchange Online. Never throws.
    .DESCRIPTION
        The session is cleared first so that Tenure counts as disconnected even when a
        disconnect call fails or is interrupted. Failures are written to the verbose
        stream only.
    #>
    [CmdletBinding()]
    param()

    $script:Session = $null
    try {
        Invoke-TenureGraphDisconnect
        Write-Verbose 'Disconnect-Tenure: Microsoft Graph disconnected.'
    } catch {
        Write-Verbose "Disconnect-Tenure: Microsoft Graph disconnect skipped: $($_.Exception.Message)"
    }
    try {
        Invoke-TenureExchangeDisconnect
        Write-Verbose 'Disconnect-Tenure: Exchange Online disconnected.'
    } catch {
        Write-Verbose "Disconnect-Tenure: Exchange Online disconnect skipped: $($_.Exception.Message)"
    }
    $script:Session = $null
}
