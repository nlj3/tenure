function Connect-Tenure {
    <#
    .SYNOPSIS
        Signs in to Microsoft Graph and Exchange Online and records the session that
        every Tenure plan and apply uses.
    .DESCRIPTION
        Connects Microsoft Graph first, then Exchange Online (unless -SkipExchange), and
        stores a Tenure.Connection object that the two seams check before every call.

        Sign-in modes:
        - Interactive (default): browser sign-in, or a device code with -UseDeviceCode.
          Exchange Online signs in as the same account.
        - Certificate: app-only with -ClientId, -TenantId and -CertificateThumbprint or
          -Certificate. Exchange Online also needs -Organization (the tenant's initial
          domain, for example <tenant>.onmicrosoft.com). On macOS and Linux,
          Connect-ExchangeOnline has no -CertificateThumbprint, so pass -Certificate there
          or use -SkipExchange.
        - Client secret: app-only with -ClientId, -TenantId and -ClientSecretCredential
          (the password of the credential is the secret). Exchange Online has no client
          secret sign-in, so this mode requires -SkipExchange.

        Scopes: without -Scopes, Tenure asks for the union of every registered provider's
        Scopes (see Get-TenureProvider) plus User.Read. App-only connections cannot ask
        for scopes at sign-in; their application permissions are granted on the app
        registration, and Tenure only compares them with the expected list (User.Read is
        not expected for app-only). Scopes that were not granted are listed in a warning
        and in MissingScopes; steps that need them fail later with Tenure.Graph.Forbidden.

        If Exchange Online fails after Graph connected, the Graph session is kept (Graph
        true, Exchange false) and Tenure.Exchange.ConnectFailed is thrown.

        Calling Connect-Tenure while connected disconnects the earlier session first.
        Tokens, secrets, certificates and credentials are never stored in the session.

        Error ids: Tenure.Connect.Unsupported, Tenure.Connect.OrganizationRequired,
        Tenure.Connect.Failed, Tenure.Exchange.ConnectFailed.
    .PARAMETER TenantId
        Tenant id (GUID) or a verified domain. Optional for interactive sign-in.
    .PARAMETER UseDeviceCode
        Interactive only: sign in with a device code instead of a browser window.
    .PARAMETER ClientId
        Application (client) id of the app registration used for app-only sign-in.
    .PARAMETER CertificateThumbprint
        Thumbprint (40 hex characters) of a certificate in the current user's store.
    .PARAMETER Certificate
        A certificate object with its private key.
    .PARAMETER Organization
        The tenant's initial domain (for example <tenant>.onmicrosoft.com). Required for
        certificate sign-in unless -SkipExchange is given.
    .PARAMETER ClientSecretCredential
        A credential whose password is the client secret. Its user name is ignored;
        -ClientId names the application.
    .PARAMETER Scopes
        Overrides the expected scope list.
    .PARAMETER SkipExchange
        Connect Microsoft Graph only. Exchange-backed steps will refuse to run.
    .PARAMETER Environment
        Cloud: Global (default), USGov (GCC High), USGovDoD or China.
    .EXAMPLE
        Connect-Tenure

        Interactive sign-in to Graph and Exchange Online with every scope the registered
        providers need.
    .EXAMPLE
        Connect-Tenure -TenantId '<tenant>.onmicrosoft.com' -UseDeviceCode

        Device code sign-in, for a terminal without a browser.
    .EXAMPLE
        $cert = Get-PfxCertificate -FilePath ./tenure-app.pfx
        Connect-Tenure -ClientId '11111111-2222-3333-4444-555555555555' -TenantId '66666666-7777-8888-9999-000000000000' -Certificate $cert -Organization '<tenant>.onmicrosoft.com'

        App-only sign-in with a certificate, Graph and Exchange Online.
    .EXAMPLE
        Connect-Tenure -ClientId '11111111-2222-3333-4444-555555555555' -TenantId '66666666-7777-8888-9999-000000000000' -ClientSecretCredential (Get-Credential) -SkipExchange

        App-only sign-in with a client secret, Graph only.
    .OUTPUTS
        Tenure.Connection: Account, TenantId, AuthType (Delegated or AppOnly), Graph,
        Exchange, Scopes (granted), RequestedScopes, MissingScopes, Environment,
        ConnectedAt (UTC), ExchangeAccount.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    [OutputType('Tenure.Connection')]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$UseDeviceCode,

        [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
        [ValidatePattern('^[0-9A-Fa-f]{40}$')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName = 'CertificateThumbprint')]
        [Parameter(ParameterSetName = 'Certificate')]
        [ValidatePattern('^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')]
        [string]$Organization,

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [ValidateNotNull()]
        [pscredential]$ClientSecretCredential,

        [ValidateNotNullOrEmpty()]
        [string[]]$Scopes,

        [switch]$SkipExchange,

        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
        [string]$Environment = 'Global'
    )

    $mode = $PSCmdlet.ParameterSetName
    $appOnly = $mode -ne 'Interactive'
    $withExchange = -not $SkipExchange

    # Refusals come before anything is disconnected or connected.
    if ($withExchange -and $mode -eq 'ClientSecret') {
        throw (New-TenureError -Id 'Tenure.Connect.Unsupported' -Message 'Exchange Online does not support client secret authentication; use a certificate or -SkipExchange.' -Category InvalidArgument -Data @{ Mode = $mode })
    }
    if ($withExchange -and $mode -in 'CertificateThumbprint', 'Certificate' -and [string]::IsNullOrWhiteSpace($Organization)) {
        throw (New-TenureError -Id 'Tenure.Connect.OrganizationRequired' -Message "Certificate sign-in to Exchange Online needs -Organization (the tenant's initial domain, for example <tenant>.onmicrosoft.com), or use -SkipExchange." -Category InvalidArgument -Data @{ Mode = $mode })
    }
    if ($withExchange -and $mode -eq 'CertificateThumbprint' -and -not (Test-TenureWindowsPlatform)) {
        throw (New-TenureError -Id 'Tenure.Connect.Unsupported' -Message 'Connect-ExchangeOnline accepts -CertificateThumbprint only on Windows. Pass the certificate with -Certificate, or use -SkipExchange.' -Category InvalidArgument -Data @{ Mode = $mode })
    }

    $environments = @{
        Global   = @{ Graph = 'Global'; Exchange = 'O365Default' }
        USGov    = @{ Graph = 'USGov'; Exchange = 'O365USGovGCCHigh' }
        USGovDoD = @{ Graph = 'USGovDoD'; Exchange = 'O365USGovDoD' }
        China    = @{ Graph = 'China'; Exchange = 'O365China' }
    }
    $graphEnvironment = $environments[$Environment].Graph
    $exchangeEnvironment = $environments[$Environment].Exchange

    $requested = if ($PSBoundParameters.ContainsKey('Scopes')) {
        ConvertTo-TenureScopeList -Scope $Scopes
    } else {
        Get-TenureDefaultScope -AuthType $(if ($appOnly) { 'AppOnly' } else { 'Delegated' })
    }

    if ($null -ne $script:Session) {
        Write-Verbose 'Connect-Tenure: an earlier session exists; disconnecting it first.'
        Disconnect-TenureSession
    }

    # Graph.
    $graphParameters = @{ NoWelcome = $true; Environment = $graphEnvironment }
    switch ($mode) {
        'Interactive' {
            $graphParameters.Scopes = $requested
            if ($PSBoundParameters.ContainsKey('TenantId')) { $graphParameters.TenantId = $TenantId }
            if ($UseDeviceCode) { $graphParameters.UseDeviceCode = $true }
        }
        'CertificateThumbprint' {
            $graphParameters.ClientId = $ClientId
            $graphParameters.TenantId = $TenantId
            $graphParameters.CertificateThumbprint = $CertificateThumbprint
        }
        'Certificate' {
            $graphParameters.ClientId = $ClientId
            $graphParameters.TenantId = $TenantId
            $graphParameters.Certificate = $Certificate
        }
        'ClientSecret' {
            # Connect-MgGraph reads the application id from the credential's user name.
            $graphParameters.TenantId = $TenantId
            $graphParameters.ClientSecretCredential = [pscredential]::new($ClientId, $ClientSecretCredential.Password)
        }
    }
    $how = if ($mode -eq 'Interactive' -and $UseDeviceCode) { 'device code' } elseif ($mode -eq 'Interactive') { 'interactive' } else { "app-only ($mode)" }
    Write-Verbose ("Connect-Tenure: connecting to Microsoft Graph ({0}, environment {1}, {2} expected scope(s): {3})." -f $how, $graphEnvironment, $requested.Count, ($requested -join ', '))

    try {
        Invoke-TenureGraphConnect -Parameters $graphParameters
    } catch {
        throw (New-TenureError -Id 'Tenure.Connect.Failed' -Message "Connecting to Microsoft Graph failed: $($_.Exception.Message)" -Category AuthenticationError -Data @{ Stage = 'Graph'; Mode = $mode })
    }
    $graphParameters = $null

    $context = $null
    try {
        $context = Get-TenureGraphContext
    } catch {
        throw (New-TenureError -Id 'Tenure.Connect.Failed' -Message "Microsoft Graph sign-in returned, but reading the context failed: $($_.Exception.Message)" -Category AuthenticationError -Data @{ Stage = 'Graph'; Mode = $mode })
    }
    if ($null -eq $context) {
        throw (New-TenureError -Id 'Tenure.Connect.Failed' -Message 'Microsoft Graph sign-in returned, but there is no Graph context. Run Connect-Tenure again.' -Category AuthenticationError -Data @{ Stage = 'Graph'; Mode = $mode })
    }
    $identity = Get-TenureGraphIdentity -Context $context
    $context = $null

    $missing = Get-TenureMissingScope -Requested $requested -Granted $identity.Scopes
    if ($missing.Count -gt 0) {
        Write-Warning ("Microsoft Graph did not grant {0} expected scope(s): {1}. Steps from providers that need them will fail with Tenure.Graph.Forbidden." -f $missing.Count, ($missing -join ', '))
    }
    Write-Verbose ("Connect-Tenure: Microsoft Graph connected as {0} ({1}) in tenant {2}; {3} scope(s) granted." -f $identity.Account, $identity.AuthType, $identity.TenantId, $identity.Scopes.Count)

    $session = [pscustomobject]@{
        PSTypeName      = 'Tenure.Connection'
        Account         = $identity.Account
        TenantId        = $identity.TenantId
        AuthType        = $identity.AuthType
        Graph           = $true
        Exchange        = $false
        Scopes          = $identity.Scopes
        RequestedScopes = $requested
        MissingScopes   = $missing
        Environment     = $Environment
        ConnectedAt     = [datetime]::UtcNow
        ExchangeAccount = $null
    }
    $script:Session = $session

    if (-not $withExchange) {
        Write-Verbose 'Connect-Tenure: -SkipExchange given; Exchange Online not connected.'
        return (Copy-TenureConnection -Session $session)
    }

    # Exchange Online.
    $exchangeParameters = @{ ShowBanner = $false; ExchangeEnvironmentName = $exchangeEnvironment }
    switch ($mode) {
        'Interactive' {
            if ($identity.AuthType -eq 'Delegated' -and $identity.Account) { $exchangeParameters.UserPrincipalName = $identity.Account }
            if ($UseDeviceCode) { $exchangeParameters.Device = $true }
        }
        'CertificateThumbprint' {
            $exchangeParameters.AppId = $ClientId
            $exchangeParameters.CertificateThumbprint = $CertificateThumbprint
            $exchangeParameters.Organization = $Organization
        }
        'Certificate' {
            $exchangeParameters.AppId = $ClientId
            $exchangeParameters.Certificate = $Certificate
            $exchangeParameters.Organization = $Organization
        }
    }
    Write-Verbose ("Connect-Tenure: connecting to Exchange Online ({0}, environment {1})." -f $how, $exchangeEnvironment)

    $hint = 'Microsoft Graph stays connected. Run Connect-Tenure again, or use -SkipExchange to work without Exchange Online.'
    try {
        Invoke-TenureExchangeConnect -Parameters $exchangeParameters
    } catch {
        throw (New-TenureError -Id 'Tenure.Exchange.ConnectFailed' -Message "Connecting to Exchange Online failed: $($_.Exception.Message) $hint" -Category ConnectionError -Data @{ Stage = 'Exchange'; Mode = $mode })
    }
    $exchangeParameters = $null

    $newest = $null
    try {
        $newest = Select-TenureExchangeConnection -Connection @(Get-TenureExchangeConnection)
    } catch {
        throw (New-TenureError -Id 'Tenure.Exchange.ConnectFailed' -Message "Exchange Online sign-in returned, but reading the connection failed: $($_.Exception.Message) $hint" -Category ConnectionError -Data @{ Stage = 'Exchange'; Mode = $mode })
    }
    if ($null -eq $newest) {
        throw (New-TenureError -Id 'Tenure.Exchange.ConnectFailed' -Message "Exchange Online sign-in returned, but no connection is in the Connected state. $hint" -Category ConnectionError -Data @{ Stage = 'Exchange'; Mode = $mode })
    }

    $exchangeTenant = [string](Get-TenureProperty -InputObject $newest -Name 'TenantID')
    if (-not (Test-TenureSameTenant -Left $exchangeTenant -Right $identity.TenantId)) {
        try { Invoke-TenureExchangeDisconnect } catch { Write-Verbose "Connect-Tenure: Exchange Online disconnect after tenant mismatch failed: $($_.Exception.Message)" }
        throw (New-TenureError -Id 'Tenure.Exchange.ConnectFailed' -Message "Exchange Online connected to tenant $exchangeTenant but Microsoft Graph is connected to tenant $($identity.TenantId); Exchange Online was disconnected. $hint" -Category ConnectionError -Data @{ Stage = 'Exchange'; Mode = $mode; GraphTenantId = $identity.TenantId; ExchangeTenantId = $exchangeTenant })
    }

    $exchangeAccount = [string](Get-TenureProperty -InputObject $newest -Name 'UserPrincipalName')
    if ([string]::IsNullOrWhiteSpace($exchangeAccount)) { $exchangeAccount = [string](Get-TenureProperty -InputObject $newest -Name 'AppId') }
    if ([string]::IsNullOrWhiteSpace($exchangeAccount)) { $exchangeAccount = $null }

    $session.Exchange = $true
    $session.ExchangeAccount = $exchangeAccount
    Write-Verbose ("Connect-Tenure: Exchange Online connected as {0}." -f $exchangeAccount)
    Copy-TenureConnection -Session $session
}
