# Connect-Tenure, Disconnect-Tenure, Get-TenureConnection. The six SDK wrappers in
# Private/Core/Connection.ps1 are mocked; nothing here touches the SDK or a tenant.
# The secret literal below is a seeded fake used only to search for leaks.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest

    $script:TenantGuid = '00000000-0000-0000-0000-00000000beef'
    $script:OtherTenantGuid = '00000000-0000-0000-0000-00000000f00d'
    $script:AppId = '11111111-2222-3333-4444-555555555555'
    $script:Thumbprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'
    $script:Organization = 'example.onmicrosoft.com'
    $script:SecretLiteral = 'fake-secret-Q7v-not-real'
    $script:TokenLiteral = 'eyJ0eXAi.fake-token-literal.sig'
    $script:SessionProperties = @('Account', 'TenantId', 'AuthType', 'Graph', 'Exchange', 'Scopes', 'RequestedScopes', 'MissingScopes', 'Environment', 'ConnectedAt', 'ExchangeAccount')

    $global:TenureConnectCalls = [System.Collections.Generic.List[hashtable]]::new()
    $global:TenureConnectState = @{}

    function New-TestSecureString([string]$Text) {
        $secure = [securestring]::new()
        foreach ($character in $Text.ToCharArray()) { $secure.AppendChar($character) }
        $secure.MakeReadOnly()
        $secure
    }

    function Get-ExpectedDefaultScope([switch]$AppOnly) {
        # Independent oracle: the raw union, compared as a set by the tests.
        $all = @(Get-TenureProvider | ForEach-Object { @($_.Scopes) } | Where-Object { $_ })
        if (-not $AppOnly) { $all += 'User.Read' }
        $all
    }

    function New-FakeGraphContext {
        param(
            [string]$AuthType = 'Delegated',
            [AllowNull()][string]$Account = 'admin@example.com',
            [string]$TenantId = $script:TenantGuid,
            [AllowNull()][string[]]$Scopes,
            [string]$ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
        )
        if ($null -eq $Scopes) { $Scopes = @(Get-ExpectedDefaultScope) }
        # Carries the kinds of fields a real context has that must never be copied.
        [pscustomobject]@{
            AuthType              = $AuthType
            Account               = $Account
            TenantId              = $TenantId
            Scopes                = $Scopes
            ClientId              = $ClientId
            ClientSecret          = New-TestSecureString $script:SecretLiteral
            CertificateThumbprint = $script:Thumbprint
            AccessToken           = $script:TokenLiteral
        }
    }

    function New-FakeExchangeConnection([uint32]$Id = 1, [string]$State = 'Connected', [string]$UserPrincipalName = 'admin@example.com', [string]$TenantID = $script:TenantGuid, [string]$AppId = '') {
        [pscustomobject]@{ Id = $Id; State = $State; UserPrincipalName = $UserPrincipalName; TenantID = $TenantID; AppId = $AppId; TokenStatus = 'Active' }
    }

    function Reset-ConnectWorld {
        $global:TenureConnectCalls.Clear()
        $global:TenureConnectState.Clear()
        $global:TenureConnectState.GraphContext = New-FakeGraphContext
        $global:TenureConnectState.ExchangeConnections = @(New-FakeExchangeConnection)
        $global:TenureConnectState.IsWindows = $true
        Clear-TenureTestSession
    }

    # Returned with the unary comma so a single call stays an array and [0] indexes it.
    function Get-Call([string]$Name) { , @($global:TenureConnectCalls | Where-Object { $_.Name -eq $Name }) }
    function Get-CallNames { @($global:TenureConnectCalls | ForEach-Object { $_.Name }) }
    function Get-ModuleSession { Invoke-InTenure { $script:Session } }

    function Assert-SortedUnique([string[]]$List) {
        for ($i = 1; $i -lt $List.Count; $i++) {
            [string]::Compare($List[$i - 1], $List[$i], [System.StringComparison]::OrdinalIgnoreCase) | Should -BeLessThan 0 -Because "'$($List[$i - 1])' must sort before '$($List[$i])' with no duplicates"
        }
    }

    function Assert-SameSet([string[]]$Actual, [string[]]$Expected) {
        $a = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Actual), [System.StringComparer]::OrdinalIgnoreCase)
        $e = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Expected), [System.StringComparer]::OrdinalIgnoreCase)
        $a.SetEquals($e) | Should -BeTrue -Because "expected [$(@($Expected) -join ', ')] but got [$(@($Actual) -join ', ')]"
    }

    function New-TestCertificate {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=tenure-unit-test', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-5), [datetimeoffset]::UtcNow.AddDays(1))
    }

    Mock -ModuleName Tenure Invoke-TenureGraphConnect {
        $global:TenureConnectCalls.Add(@{ Name = 'GraphConnect'; Parameters = $Parameters.Clone() })
        if ($global:TenureConnectState.ContainsKey('GraphConnectError')) { throw $global:TenureConnectState.GraphConnectError }
    }
    Mock -ModuleName Tenure Get-TenureGraphContext {
        $global:TenureConnectCalls.Add(@{ Name = 'GraphContext' })
        if ($global:TenureConnectState.ContainsKey('GraphContextError')) { throw $global:TenureConnectState.GraphContextError }
        $global:TenureConnectState.GraphContext
    }
    Mock -ModuleName Tenure Invoke-TenureGraphDisconnect {
        $global:TenureConnectCalls.Add(@{ Name = 'GraphDisconnect' })
        if ($global:TenureConnectState.ContainsKey('GraphDisconnectError')) { throw $global:TenureConnectState.GraphDisconnectError }
    }
    Mock -ModuleName Tenure Invoke-TenureExchangeConnect {
        $global:TenureConnectCalls.Add(@{ Name = 'ExchangeConnect'; Parameters = $Parameters.Clone() })
        if ($global:TenureConnectState.ContainsKey('ExchangeConnectError')) { throw $global:TenureConnectState.ExchangeConnectError }
    }
    Mock -ModuleName Tenure Get-TenureExchangeConnection {
        $global:TenureConnectCalls.Add(@{ Name = 'ExchangeConnection' })
        if ($global:TenureConnectState.ContainsKey('ExchangeConnectionError')) { throw $global:TenureConnectState.ExchangeConnectionError }
        $global:TenureConnectState.ExchangeConnections
    }
    Mock -ModuleName Tenure Invoke-TenureExchangeDisconnect {
        $global:TenureConnectCalls.Add(@{ Name = 'ExchangeDisconnect' })
        if ($global:TenureConnectState.ContainsKey('ExchangeDisconnectError')) { throw $global:TenureConnectState.ExchangeDisconnectError }
    }
    Mock -ModuleName Tenure Test-TenureWindowsPlatform { [bool]$global:TenureConnectState.IsWindows }
}

AfterAll {
    Remove-Variable -Name TenureConnectCalls, TenureConnectState -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Connect-Tenure scopes' {
    BeforeEach { Reset-ConnectWorld }
    AfterEach { Invoke-InTenure { Unregister-TenureProvider -Name 'Fake.ScopeProbe' } }

    It 'requests the union of every registered provider scope plus User.Read, sorted and de-duplicated' {
        # A case-variant duplicate and a new scope prove de-duplication and that the registry is read live.
        $definition = New-FakeProviderDefinition -Name 'Fake.ScopeProbe' -Overrides @{ Scopes = @('user.read.all', 'Zz.Probe.All', 'Zz.Probe.All') }
        $null = Invoke-InTenure { param($d) Register-TenureProvider -Definition $d -Force } @($definition)
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -Scopes @(Get-ExpectedDefaultScope)

        $connection = Connect-Tenure -TenantId $script:TenantGuid

        $requested = [string[]]@((Get-Call 'GraphConnect')[0].Parameters.Scopes)
        Assert-SameSet -Actual $requested -Expected @(Get-ExpectedDefaultScope)
        Assert-SortedUnique $requested
        $requested | Should -Contain 'User.Read'
        $requested | Should -Contain 'Zz.Probe.All'
        @($requested | Where-Object { $_ -ieq 'User.Read.All' }).Count | Should -Be 1
        $connection.RequestedScopes | Should -Be $requested
        $connection.MissingScopes.Count | Should -Be 0
    }

    It '-Scopes overrides the provider union' {
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -Scopes @('User.Read.All', 'Group.Read.All')
        $connection = Connect-Tenure -Scopes 'User.Read.All', 'Group.Read.All', 'user.read.all' -SkipExchange
        (Get-Call 'GraphConnect')[0].Parameters.Scopes | Should -Be @('Group.Read.All', 'User.Read.All')
        $connection.RequestedScopes | Should -Be @('Group.Read.All', 'User.Read.All')
        $connection.MissingScopes.Count | Should -Be 0
    }

    It 'sends no scopes for app-only sign-in and does not expect User.Read' {
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -AuthType 'AppOnly' -Account $null -ClientId $script:AppId -Scopes @(Get-ExpectedDefaultScope -AppOnly)
        $connection = Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -Certificate (New-TestCertificate) -SkipExchange -WarningVariable warnings
        (Get-Call 'GraphConnect')[0].Parameters.ContainsKey('Scopes') | Should -BeFalse
        $connection.RequestedScopes | Should -Not -Contain 'User.Read'
        Assert-SameSet -Actual $connection.RequestedScopes -Expected @(Get-ExpectedDefaultScope -AppOnly)
        @($warnings).Count | Should -Be 0
    }
}

Describe 'Connect-Tenure parameter sets' {
    BeforeEach { Reset-ConnectWorld }

    It 'interactive passes TenantId and NoWelcome, not UseDeviceCode, and signs Exchange in as the Graph account' {
        $connection = Connect-Tenure -TenantId $script:TenantGuid

        Get-CallNames | Should -Be @('GraphConnect', 'GraphContext', 'ExchangeConnect', 'ExchangeConnection')
        $graph = (Get-Call 'GraphConnect')[0].Parameters
        $graph.TenantId | Should -Be $script:TenantGuid
        $graph.NoWelcome | Should -BeTrue
        $graph.Environment | Should -Be 'Global'
        $graph.ContainsKey('UseDeviceCode') | Should -BeFalse
        $graph.ContainsKey('ClientId') | Should -BeFalse

        $exchange = (Get-Call 'ExchangeConnect')[0].Parameters
        $exchange.UserPrincipalName | Should -Be 'admin@example.com'
        $exchange.ShowBanner | Should -BeFalse
        $exchange.ExchangeEnvironmentName | Should -Be 'O365Default'
        $exchange.ContainsKey('Device') | Should -BeFalse

        $connection.PSObject.TypeNames | Should -Contain 'Tenure.Connection'
        $connection.AuthType | Should -Be 'Delegated'
        $connection.Account | Should -Be 'admin@example.com'
        $connection.TenantId | Should -Be $script:TenantGuid
        $connection.Graph | Should -BeTrue
        $connection.Exchange | Should -BeTrue
        $connection.ExchangeAccount | Should -Be 'admin@example.com'
        $connection.Environment | Should -Be 'Global'
        $connection.ConnectedAt.Kind | Should -Be ([System.DateTimeKind]::Utc)
        ([datetime]::UtcNow - $connection.ConnectedAt).TotalMinutes | Should -BeLessThan 1
    }

    It 'interactive without -TenantId sends no TenantId' {
        $null = Connect-Tenure
        (Get-Call 'GraphConnect')[0].Parameters.ContainsKey('TenantId') | Should -BeFalse
    }

    It '-UseDeviceCode passes UseDeviceCode to Graph and -Device to Exchange' {
        $null = Connect-Tenure -UseDeviceCode
        (Get-Call 'GraphConnect')[0].Parameters.UseDeviceCode | Should -BeTrue
        (Get-Call 'ExchangeConnect')[0].Parameters.Device | Should -BeTrue
    }

    It 'certificate thumbprint reaches Graph with ClientId and TenantId and Exchange with AppId and Organization' {
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -AuthType 'AppOnly' -Account $null -ClientId $script:AppId -Scopes @(Get-ExpectedDefaultScope -AppOnly)
        $global:TenureConnectState.ExchangeConnections = @(New-FakeExchangeConnection -UserPrincipalName '' -AppId $script:AppId)

        $connection = Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -CertificateThumbprint $script:Thumbprint -Organization $script:Organization

        $graph = (Get-Call 'GraphConnect')[0].Parameters
        $graph.ClientId | Should -Be $script:AppId
        $graph.TenantId | Should -Be $script:TenantGuid
        $graph.CertificateThumbprint | Should -Be $script:Thumbprint
        $graph.NoWelcome | Should -BeTrue
        $graph.ContainsKey('Scopes') | Should -BeFalse

        $exchange = (Get-Call 'ExchangeConnect')[0].Parameters
        $exchange.AppId | Should -Be $script:AppId
        $exchange.CertificateThumbprint | Should -Be $script:Thumbprint
        $exchange.Organization | Should -Be $script:Organization
        $exchange.ShowBanner | Should -BeFalse
        $exchange.ContainsKey('UserPrincipalName') | Should -BeFalse

        $connection.AuthType | Should -Be 'AppOnly'
        $connection.Account | Should -Be $script:AppId -Because 'app-only contexts have no account, so the application id names the actor'
        $connection.ExchangeAccount | Should -Be $script:AppId
        $connection.Exchange | Should -BeTrue
    }

    It 'certificate thumbprint with Exchange is refused before any call where Connect-ExchangeOnline has no -CertificateThumbprint' {
        $global:TenureConnectState.IsWindows = $false
        { Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -CertificateThumbprint $script:Thumbprint -Organization $script:Organization } | Should -Throw -ErrorId 'Tenure.Connect.Unsupported'
        $global:TenureConnectCalls.Count | Should -Be 0

        $global:TenureConnectState.GraphContext = New-FakeGraphContext -AuthType 'AppOnly' -Account $null -ClientId $script:AppId
        $connection = Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -CertificateThumbprint $script:Thumbprint -SkipExchange -WarningAction SilentlyContinue
        $connection.Graph | Should -BeTrue
    }

    It 'certificate object reaches Graph with ClientId and TenantId and Exchange with AppId and Organization' {
        $certificate = New-TestCertificate
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -AuthType 'AppOnly' -Account $null -ClientId $script:AppId -Scopes @(Get-ExpectedDefaultScope -AppOnly)
        $global:TenureConnectState.IsWindows = $false

        $connection = Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -Certificate $certificate -Organization $script:Organization

        $graph = (Get-Call 'GraphConnect')[0].Parameters
        $graph.ClientId | Should -Be $script:AppId
        $graph.TenantId | Should -Be $script:TenantGuid
        [object]::ReferenceEquals($graph.Certificate, $certificate) | Should -BeTrue
        $graph.ContainsKey('CertificateThumbprint') | Should -BeFalse

        $exchange = (Get-Call 'ExchangeConnect')[0].Parameters
        $exchange.AppId | Should -Be $script:AppId
        $exchange.Organization | Should -Be $script:Organization
        [object]::ReferenceEquals($exchange.Certificate, $certificate) | Should -BeTrue
        $exchange.ContainsKey('CertificateThumbprint') | Should -BeFalse
        $connection.Exchange | Should -BeTrue
    }

    It 'client secret with Exchange is refused before any call and leaves an existing session alone' {
        Set-TenureTestSession
        $credential = [pscredential]::new($script:AppId, (New-TestSecureString $script:SecretLiteral))
        $thrown = { Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -ClientSecretCredential $credential } | Should -Throw -ErrorId 'Tenure.Connect.Unsupported' -PassThru
        $thrown.Exception.Message | Should -Match 'client secret'
        $thrown.Exception.Message | Should -Match '-SkipExchange'
        $global:TenureConnectCalls.Count | Should -Be 0
        (Get-ModuleSession).Account | Should -Be 'admin@example.com'
    }

    It 'client secret with -SkipExchange sends the credential under the client id and never touches Exchange' {
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -AuthType 'AppOnly' -Account $null -ClientId $script:AppId -Scopes @(Get-ExpectedDefaultScope -AppOnly)
        $credential = [pscredential]::new('typed-anything', (New-TestSecureString $script:SecretLiteral))

        $connection = Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -ClientSecretCredential $credential -SkipExchange

        Get-CallNames | Should -Be @('GraphConnect', 'GraphContext')
        $graph = (Get-Call 'GraphConnect')[0].Parameters
        $graph.TenantId | Should -Be $script:TenantGuid
        $graph.ContainsKey('ClientId') | Should -BeFalse -Because 'Connect-MgGraph reads the application id from the credential user name'
        $graph.ContainsKey('Scopes') | Should -BeFalse
        $graph.ClientSecretCredential | Should -BeOfType [pscredential]
        $graph.ClientSecretCredential.UserName | Should -Be $script:AppId
        $graph.ClientSecretCredential.GetNetworkCredential().Password | Should -Be $script:SecretLiteral
        $connection.Exchange | Should -BeFalse
    }

    It 'certificate with Exchange and no -Organization is refused before any call (<Name>)' -ForEach @(
        @{ Name = 'thumbprint'; UseThumbprint = $true }
        @{ Name = 'certificate object'; UseThumbprint = $false }
    ) {
        $parameters = @{ ClientId = $script:AppId; TenantId = $script:TenantGuid }
        if ($UseThumbprint) { $parameters.CertificateThumbprint = $script:Thumbprint } else { $parameters.Certificate = New-TestCertificate }
        { Connect-Tenure @parameters } | Should -Throw -ErrorId 'Tenure.Connect.OrganizationRequired'
        $global:TenureConnectCalls.Count | Should -Be 0
    }

    It '-SkipExchange never calls an Exchange wrapper and leaves Exchange false' {
        $connection = Connect-Tenure -SkipExchange
        Get-CallNames | Should -Not -Contain 'ExchangeConnect'
        Get-CallNames | Should -Not -Contain 'ExchangeConnection'
        $connection.Exchange | Should -BeFalse
        $connection.Graph | Should -BeTrue
        { Invoke-InTenure { Assert-TenureConnection -Backend Exchange } } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
    }

    It 'rejects a malformed thumbprint and organization at binding' {
        { Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -CertificateThumbprint 'not-a-thumbprint' -SkipExchange } | Should -Throw
        { Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -CertificateThumbprint $script:Thumbprint -Organization 'no spaces allowed' } | Should -Throw
        $global:TenureConnectCalls.Count | Should -Be 0
    }
}

Describe 'Connect-Tenure failures' {
    BeforeEach { Reset-ConnectWorld }

    It 'a null Graph context throws Tenure.Connect.Failed and records no session' {
        $global:TenureConnectState.GraphContext = $null
        { Connect-Tenure } | Should -Throw -ErrorId 'Tenure.Connect.Failed'
        Get-ModuleSession | Should -BeNullOrEmpty
        Get-CallNames | Should -Not -Contain 'ExchangeConnect'
    }

    It 'a Graph sign-in failure throws Tenure.Connect.Failed without the secret or the credential in the error' {
        $global:TenureConnectState.GraphConnectError = 'AADSTS7000215: Invalid client secret provided.'
        $credential = [pscredential]::new($script:AppId, (New-TestSecureString $script:SecretLiteral))
        $thrown = { Connect-Tenure -ClientId $script:AppId -TenantId $script:TenantGuid -ClientSecretCredential $credential -SkipExchange } | Should -Throw -ErrorId 'Tenure.Connect.Failed' -PassThru
        $thrown.Exception.Message | Should -Match 'AADSTS7000215'
        $thrown.Exception.InnerException | Should -BeNullOrEmpty
        foreach ($key in $thrown.Exception.Data.Keys) {
            $value = $thrown.Exception.Data[$key]
            $value | Should -Not -BeOfType [pscredential]
            $value | Should -Not -BeOfType [securestring]
            [string]$value | Should -Not -Match ([regex]::Escape($script:SecretLiteral))
        }
        $thrown.Exception.Message | Should -Not -Match ([regex]::Escape($script:SecretLiteral))
        Get-ModuleSession | Should -BeNullOrEmpty
    }

    It 'missing granted scopes produce a warning and MissingScopes, and the connection still succeeds' {
        $granted = @(Get-ExpectedDefaultScope | Where-Object { $_ -notin 'Files.ReadWrite.All', 'RoleManagement.ReadWrite.Directory' })
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -Scopes $granted

        $connection = Connect-Tenure -SkipExchange -WarningVariable warnings -WarningAction SilentlyContinue

        $connection.MissingScopes | Should -Be @('Files.ReadWrite.All', 'RoleManagement.ReadWrite.Directory')
        @($warnings).Count | Should -Be 1
        [string]$warnings[0] | Should -Match 'Files\.ReadWrite\.All'
        [string]$warnings[0] | Should -Match 'RoleManagement\.ReadWrite\.Directory'
        $connection.Graph | Should -BeTrue
        Assert-SameSet -Actual $connection.Scopes -Expected $granted
    }

    It 'an Exchange sign-in failure keeps the Graph session and throws Tenure.Exchange.ConnectFailed with the hint' {
        $global:TenureConnectState.ExchangeConnectError = 'User canceled authentication.'
        $thrown = { Connect-Tenure } | Should -Throw -ErrorId 'Tenure.Exchange.ConnectFailed' -PassThru
        $thrown.Exception.Message | Should -Match 'User canceled authentication'
        $thrown.Exception.Message | Should -Match '-SkipExchange'

        $session = Get-ModuleSession
        $session.Graph | Should -BeTrue
        $session.Exchange | Should -BeFalse
        { Invoke-InTenure { Assert-TenureConnection -Backend Graph } } | Should -Not -Throw
        { Invoke-InTenure { Assert-TenureConnection -Backend Exchange } } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
    }

    It 'connection info without a Connected session throws Tenure.Exchange.ConnectFailed and keeps Graph' {
        $global:TenureConnectState.ExchangeConnections = @(New-FakeExchangeConnection -State 'Broken')
        { Connect-Tenure } | Should -Throw -ErrorId 'Tenure.Exchange.ConnectFailed'
        (Get-ModuleSession).Graph | Should -BeTrue
        (Get-ModuleSession).Exchange | Should -BeFalse

        $global:TenureConnectState.ExchangeConnections = @()
        { Connect-Tenure } | Should -Throw -ErrorId 'Tenure.Exchange.ConnectFailed'
    }

    It 'uses the newest Connected Exchange connection' {
        $global:TenureConnectState.ExchangeConnections = @(
            New-FakeExchangeConnection -Id 1 -UserPrincipalName 'old@example.com'
            New-FakeExchangeConnection -Id 3 -State 'Broken' -UserPrincipalName 'broken@example.com'
            New-FakeExchangeConnection -Id 2 -UserPrincipalName 'admin@example.com'
        )
        (Connect-Tenure).ExchangeAccount | Should -Be 'admin@example.com'
    }

    It 'refuses an Exchange connection in another tenant than Graph and disconnects it' {
        $global:TenureConnectState.ExchangeConnections = @(New-FakeExchangeConnection -TenantID $script:OtherTenantGuid)
        $thrown = { Connect-Tenure } | Should -Throw -ErrorId 'Tenure.Exchange.ConnectFailed' -PassThru
        $thrown.Exception.Message | Should -Match $script:OtherTenantGuid
        Get-CallNames | Should -Contain 'ExchangeDisconnect'
        (Get-ModuleSession).Graph | Should -BeTrue
        (Get-ModuleSession).Exchange | Should -BeFalse
    }

    It 'accepts an Exchange connection whose tenant cannot be compared' {
        $global:TenureConnectState.ExchangeConnections = @(New-FakeExchangeConnection -TenantID '')
        (Connect-Tenure).Exchange | Should -BeTrue
    }
}

Describe 'Connect-Tenure environments' {
    BeforeEach { Reset-ConnectWorld }

    It 'maps <Environment> to Graph <Graph> and Exchange <Exchange>' -ForEach @(
        @{ Environment = 'Global'; Graph = 'Global'; Exchange = 'O365Default' }
        @{ Environment = 'USGov'; Graph = 'USGov'; Exchange = 'O365USGovGCCHigh' }
        @{ Environment = 'USGovDoD'; Graph = 'USGovDoD'; Exchange = 'O365USGovDoD' }
        @{ Environment = 'China'; Graph = 'China'; Exchange = 'O365China' }
    ) {
        $connection = Connect-Tenure -Environment $Environment
        (Get-Call 'GraphConnect')[0].Parameters.Environment | Should -BeExactly $Graph
        (Get-Call 'ExchangeConnect')[0].Parameters.ExchangeEnvironmentName | Should -BeExactly $Exchange
        $connection.Environment | Should -Be $Environment
    }

    It 'rejects an unknown environment' {
        { Connect-Tenure -Environment 'Germany' } | Should -Throw
        $global:TenureConnectCalls.Count | Should -Be 0
    }
}

Describe 'Connect-Tenure reconnect' {
    BeforeEach { Reset-ConnectWorld }

    It 'disconnects an existing session before connecting again' {
        Set-TenureTestSession -Account 'previous@example.com'
        $connection = Connect-Tenure
        Get-CallNames | Should -Be @('GraphDisconnect', 'ExchangeDisconnect', 'GraphConnect', 'GraphContext', 'ExchangeConnect', 'ExchangeConnection')
        $connection.Account | Should -Be 'admin@example.com'
        (Get-ModuleSession).Account | Should -Be 'admin@example.com'
    }

    It 'does not disconnect anything when there is no session' {
        $null = Connect-Tenure
        Get-CallNames | Should -Not -Contain 'GraphDisconnect'
        Get-CallNames | Should -Not -Contain 'ExchangeDisconnect'
    }
}

Describe 'Disconnect-Tenure' {
    BeforeEach { Reset-ConnectWorld }

    It 'clears the session even when both disconnects throw, and returns nothing' {
        Set-TenureTestSession
        $global:TenureConnectState.GraphDisconnectError = 'No application to sign out from.'
        $global:TenureConnectState.ExchangeDisconnectError = 'No active connection.'
        $output = @(Disconnect-Tenure)
        $output.Count | Should -Be 0
        Get-CallNames | Should -Be @('GraphDisconnect', 'ExchangeDisconnect')
        Get-ModuleSession | Should -BeNullOrEmpty
        { Invoke-InTenure { Assert-TenureConnection -Backend Graph } } | Should -Throw -ErrorId 'Tenure.Graph.NotConnected'
    }

    It 'is safe to call when not connected' {
        { Disconnect-Tenure } | Should -Not -Throw
        Get-ModuleSession | Should -BeNullOrEmpty
    }

    It 'reports disconnect failures on the verbose stream only' {
        Set-TenureTestSession
        $global:TenureConnectState.GraphDisconnectError = 'graph-disconnect-probe'
        $verbose = @(Disconnect-Tenure -Verbose 4>&1 | ForEach-Object { [string]$_.Message })
        ($verbose -join "`n") | Should -Match 'graph-disconnect-probe'
    }
}

Describe 'Get-TenureConnection' {
    BeforeEach { Reset-ConnectWorld }

    It 'returns $null with no session and calls no wrapper' {
        Get-TenureConnection | Should -BeNullOrEmpty
        $global:TenureConnectCalls.Count | Should -Be 0
    }

    It 'returns the session when both backends are still connected' {
        $null = Connect-Tenure
        $global:TenureConnectCalls.Clear()
        $connection = Get-TenureConnection
        $connection.Graph | Should -BeTrue
        $connection.Exchange | Should -BeTrue
        $connection.PSObject.TypeNames | Should -Contain 'Tenure.Connection'
        Get-CallNames | Should -Be @('GraphContext', 'ExchangeConnection')
    }

    It 're-validates both backends live and downgrades the stored session' {
        $null = Connect-Tenure
        $global:TenureConnectState.GraphContext = $null
        $global:TenureConnectState.ExchangeConnections = @(New-FakeExchangeConnection -State 'Broken')

        $connection = Get-TenureConnection

        $connection.Graph | Should -BeFalse
        $connection.Exchange | Should -BeFalse
        (Get-ModuleSession).Graph | Should -BeFalse
        (Get-ModuleSession).Exchange | Should -BeFalse
        { Invoke-InTenure { Assert-TenureConnection -Backend Graph } } | Should -Throw -ErrorId 'Tenure.Graph.NotConnected'
        { Invoke-InTenure { Assert-TenureConnection -Backend Exchange } } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
    }

    It 'treats a Graph context for another tenant or account as disconnected, with a warning' {
        $null = Connect-Tenure
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -TenantId $script:OtherTenantGuid
        $connection = Get-TenureConnection -WarningVariable warnings -WarningAction SilentlyContinue
        $connection.Graph | Should -BeFalse
        $connection.Exchange | Should -BeTrue
        @($warnings).Count | Should -Be 1

        $global:TenureConnectState.GraphContext = New-FakeGraphContext
        $null = Connect-Tenure
        $global:TenureConnectState.GraphContext = New-FakeGraphContext -Account 'someone.else@example.com'
        (Get-TenureConnection -WarningAction SilentlyContinue).Graph | Should -BeFalse
    }

    It 'treats an Exchange connection in another tenant as disconnected' {
        $null = Connect-Tenure
        $global:TenureConnectState.ExchangeConnections = @(New-FakeExchangeConnection -Id 9 -TenantID $script:OtherTenantGuid)
        $connection = Get-TenureConnection -WarningAction SilentlyContinue
        $connection.Graph | Should -BeTrue
        $connection.Exchange | Should -BeFalse
    }

    It 'never throws: wrapper failures mark the backend disconnected' {
        $null = Connect-Tenure
        $global:TenureConnectState.GraphContextError = 'context exploded'
        $global:TenureConnectState.ExchangeConnectionError = 'connection info exploded'
        $connection = Get-TenureConnection
        $connection.Graph | Should -BeFalse
        $connection.Exchange | Should -BeFalse
    }

    It 'never marks a backend connected again' {
        $null = Connect-Tenure -SkipExchange
        $global:TenureConnectCalls.Clear()
        (Get-TenureConnection).Exchange | Should -BeFalse
        Get-CallNames | Should -Not -Contain 'ExchangeConnection'
    }

    It 'returns a copy: editing it does not change the module session' {
        $null = Connect-Tenure -SkipExchange
        $copy = Get-TenureConnection
        $copy.Exchange = $true
        $copy.Scopes[0] = 'Tampered.All'
        (Get-ModuleSession).Exchange | Should -BeFalse
        (Get-ModuleSession).Scopes | Should -Not -Contain 'Tampered.All'
        (Get-TenureConnection).Exchange | Should -BeFalse
    }
}

Describe 'The session holds no secrets' {
    BeforeEach { Reset-ConnectWorld }

    It 'has exactly the documented properties and no credential, secret, certificate or token (<Name>)' -ForEach @(
        @{ Name = 'client secret' ; Mode = 'ClientSecret' }
        @{ Name = 'certificate' ; Mode = 'Certificate' }
        @{ Name = 'interactive' ; Mode = 'Interactive' }
    ) {
        $parameters = @{}
        switch ($Mode) {
            'ClientSecret' {
                $global:TenureConnectState.GraphContext = New-FakeGraphContext -AuthType 'AppOnly' -Account $null -ClientId $script:AppId -Scopes @(Get-ExpectedDefaultScope -AppOnly)
                $parameters = @{ ClientId = $script:AppId; TenantId = $script:TenantGuid; ClientSecretCredential = [pscredential]::new($script:AppId, (New-TestSecureString $script:SecretLiteral)); SkipExchange = $true }
            }
            'Certificate' {
                $global:TenureConnectState.GraphContext = New-FakeGraphContext -AuthType 'AppOnly' -Account $null -ClientId $script:AppId -Scopes @(Get-ExpectedDefaultScope -AppOnly)
                $parameters = @{ ClientId = $script:AppId; TenantId = $script:TenantGuid; Certificate = New-TestCertificate; Organization = $script:Organization }
            }
        }

        $all = @(Connect-Tenure @parameters -Verbose 4>&1 3>&1)
        $connection = @($all | Where-Object { $_ -is [psobject] -and $_.PSObject.TypeNames -contains 'Tenure.Connection' })[0]
        $streams = ($all | Where-Object { $_ -is [System.Management.Automation.InformationalRecord] } | ForEach-Object { $_.Message }) -join "`n"

        foreach ($candidate in @($connection, (Get-ModuleSession))) {
            @($candidate.PSObject.Properties.Name) | Should -Be $script:SessionProperties
            foreach ($property in $candidate.PSObject.Properties) {
                foreach ($value in @($property.Value)) {
                    $value | Should -Not -BeOfType [pscredential]
                    $value | Should -Not -BeOfType [securestring]
                    $value | Should -Not -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
                }
            }
            $json = ConvertTo-Json -InputObject $candidate -Depth 20
            $json | Should -Not -Match ([regex]::Escape($script:SecretLiteral))
            $json | Should -Not -Match ([regex]::Escape($script:TokenLiteral))
            $json | Should -Not -Match ([regex]::Escape($script:Thumbprint))
            # Scope names may contain words like Password (User-PasswordProfile.ReadWrite.All); look for serialized secret types instead.
            $json | Should -Not -Match 'System\.Security\.SecureString|PSCredential|X509Certificate|"AccessToken"|"ClientSecret"'
        }
        $streams | Should -Not -Match ([regex]::Escape($script:SecretLiteral))
        $streams | Should -Not -Match ([regex]::Escape($script:TokenLiteral))
    }
}

Describe 'Seams after Connect-Tenure' {
    BeforeEach { Reset-ConnectWorld }

    It 'Invoke-TenureGraph passes the real Assert-TenureConnection after a mocked connect, and refuses after disconnect' {
        Mock -ModuleName Tenure Invoke-TenureGraphRaw { @{ Status = 200; Headers = @{}; Body = [pscustomobject]@{ id = 'me' } } }
        { Invoke-InTenure { Invoke-TenureGraph -Method GET -Uri 'me' } } | Should -Throw -ErrorId 'Tenure.Graph.NotConnected'

        $null = Connect-Tenure
        (Invoke-InTenure { Invoke-TenureGraph -Method GET -Uri 'me' }).id | Should -Be 'me'
        { Invoke-InTenure { Assert-TenureConnection -Backend Exchange } } | Should -Not -Throw

        Disconnect-Tenure
        { Invoke-InTenure { Invoke-TenureGraph -Method GET -Uri 'me' } } | Should -Throw -ErrorId 'Tenure.Graph.NotConnected'
    }
}
