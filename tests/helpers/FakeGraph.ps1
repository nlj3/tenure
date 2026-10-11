# FakeGraph: a tiny in-memory Microsoft Graph for Tenure unit tests.
#
# Install it in a test file like this:
#
#   BeforeAll {
#       . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
#       Import-TenureForTest; Set-TenureTestSession
#       $global:FakeGraphWorld = New-FakeGraphWorld
#       Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
#   }
#   BeforeEach { Reset-FakeGraphWorld }
#
# Every function here is defined as global:. Pester runs a module mock body inside the
# module's session state, which cannot see functions defined in the test file's scope.
# Nothing in this file calls a private Tenure function (it runs in test scope).
#
# The world (New-FakeGraphWorld) is a plain hashtable. Fixture ids live in $world.Ids so
# tests reference them by name (AliceId, SalesGroupId, SkuE3Id ...). Seed:
#   alice  regular user, manager bob, direct SPE_E3, member of Sales (Unified), All Staff
#          (security), Everyone Dynamic (dynamic) and Legal DL (mail-enabled security, so
#          Exchange-managed); three managed devices (company, personal, unknown); a drive
#   bob    alice's manager, SPE_E3 assigned by the All Staff group
#   carol  Global Administrator, and the signed-in account (World.Me)
#   dave   soft-deleted (World.DeletedUsers)
#   SKUs   SPE_E3 (10 enabled, 3 consumed), EXCHANGEDESKLESS (5/5, none available), MCOEV (2/0)
#          Service plans (licenseDetails): SPE_E3 has EXCHANGE_S_ENTERPRISE, SHAREPOINTENTERPRISE
#          and TEAMS1; EXCHANGEDESKLESS has EXCHANGE_S_DESKLESS; MCOEV has MCOEV only,
#          so a user holding only MCOEV has no Exchange Online service plan. Plan ids are made up.
#          A service plan id listed in an assignment's disabledPlans reads provisioningStatus Disabled.
#   Groups carry assignedLicenses (group-based licensing), empty in the seed; a test sets them, and
#   isAssignableToRole ($false unless a test sets it).
# SubscribedSkus stay static: assignLicense does not change consumedUnits. GET subscribedSkus reports
# each SKU's service plans with provisioningStatus Success.
#
# Effects Entra has that the fake models:
#   - A user removed from a group loses the licenseAssignmentStates that group gave them, and a SKU
#     left with no assignment leaves assignedLicenses.
#   - PATCH users/{id} re-evaluates dynamic groups whose rule is '(user.accountEnabled -eq true|false)':
#     disabling the account takes the user out of Everyone Dynamic (and out of its licenses).
#
# Behavior worth knowing:
#   - Without $select a resource comes back with all its stored properties; with $select
#     only the listed ones (plus id), and an unknown property name is a 400, like Graph.
#   - Query options other than $select, $filter, $top and $skiptoken are a 400 here, so a
#     "$select" swallowed by double-quoted PowerShell interpolation shows up in a test.
#   - Passwords and Temporary Access Pass values are never stored. World.Calls keeps the
#     request body with passwordProfile.password replaced by "redacted:sha256:<hex>", and
#     World.SecretDigests lists the SHA-256 of every password or pass the fake saw or
#     issued, so a test can prove a secret is the one Graph received without the world
#     ever holding plaintext.
#   - Faults (World.Faults) are served one per request, ahead of normal routing.
#     Add-FakeGraphFault builds a Graph-style error response for the queue. With -Method
#     and/or -UriLike a fault waits for the first request that matches and lets the
#     others through, so a test can fail the write without faking the reads before it.
#     Unfiltered faults (and raw entries enqueued by hand) match every request.
#   - Users carry lastPasswordChangeDateTime and signInSessionsValidFromDateTime (both
#     read-only, as in Graph). Setting a password moves the first, revokeSignInSessions
#     moves the second. Dates are stored the way Graph returns them: UTC, whole seconds,
#     'yyyy-MM-ddTHH:mm:ssZ'. employeeLeaveDateTime is normalized to that form on write.
#   - Directory roles: GET directoryRoles/{id}, GET .../members, GET .../members/{id},
#     POST .../members/$ref (400 "already exist" for a member) and DELETE .../members/{id}/$ref.
#   - Devices: GET deviceManagement/managedDevices/{id} ($select honored, 404 when unknown);
#     devices carry lastSyncDateTime and complianceState; POST .../wipe keeps the request body it
#     received in the device's wipeRequest (never on the wire).
#   - OneDrive: GET users/{id}/drive returns webUrl ($select honored); POST .../root/invite answers
#     400 "already exists" when a recipient already holds every requested role (nothing is added);
#     DELETE drives/{driveId}/root/permissions/{permissionId} removes one permission (404 when unknown).

# ConvertFrom-Json turns ISO date strings into [datetime]; -DateKind String (PowerShell 7.5+) keeps them as the strings Graph sends.
$global:FakeGraphHasDateKind = [bool](Get-Command -Name ConvertFrom-Json).Parameters.ContainsKey('DateKind')

function global:ConvertFrom-FakeGraphJson {
    param([string]$Text, [switch]$AsHashtable)
    $parameters = @{ InputObject = $Text }
    if ($AsHashtable) { $parameters['AsHashtable'] = $true }
    if ($global:FakeGraphHasDateKind) { $parameters['DateKind'] = 'String' }
    ConvertFrom-Json @parameters
}

function global:ConvertTo-FakeGraphBody {
    # Round-trips through JSON so nested objects look like Invoke-MgGraphRequest -OutputType PSObject output.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $json = ConvertTo-Json -InputObject $Value -Depth 20 -Compress
    ConvertFrom-FakeGraphJson -Text $json
}

function global:Get-FakeGraphSha256 {
    param([string]$Text)
    [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}

function global:Stop-FakeGraph {
    # Raises a Graph-style error; Invoke-FakeGraphRequest turns it into a response.
    param([int]$Status, [string]$Code, [string]$Message)
    $exception = [System.Exception]::new($Message)
    $exception.Data['FakeGraphStatus'] = $Status
    $exception.Data['FakeGraphCode'] = $Code
    throw $exception
}

function global:Get-FakeGraphNow {
    # The current time as Graph writes it: UTC, whole seconds.
    [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function global:ConvertTo-FakeGraphDateTime {
    # A DateTimeOffset value from a request body -> Graph's stored form, or a 400 like Graph.
    param([AllowNull()][object]$Value, [string]$Property)
    if ($Value -is [datetime]) { $Value = $Value.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) }
    $parsed = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ($Value -isnot [string] -or -not [datetimeoffset]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Invalid value for property '$Property'; expected an ISO 8601 date and time."
    }
    $parsed.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function global:Stop-FakeGraphNotFound {
    param([string]$Key)
    Stop-FakeGraph -Status 404 -Code 'Request_ResourceNotFound' -Message "Resource '$Key' does not exist or one of its queried reference-property objects are not present."
}

function global:Get-FakeGraphKnownProperty {
    param([string]$Kind)
    $user = 'id', 'userPrincipalName', 'displayName', 'mailNickname', 'givenName', 'surname', 'accountEnabled', 'mail', 'usageLocation',
    'department', 'jobTitle', 'officeLocation', 'companyName', 'employeeId', 'employeeType', 'employeeLeaveDateTime', 'employeeHireDate',
    'assignedLicenses', 'licenseAssignmentStates', 'createdDateTime', 'deletedDateTime', 'otherMails', 'proxyAddresses', 'mobilePhone',
    'businessPhones', 'preferredLanguage', 'onPremisesSyncEnabled', 'userType', 'lastPasswordChangeDateTime', 'signInSessionsValidFromDateTime'
    $group = 'id', 'displayName', 'mail', 'mailNickname', 'mailEnabled', 'securityEnabled', 'groupTypes', 'membershipRule',
    'membershipRuleProcessingState', 'description', 'visibility', 'createdDateTime', 'deletedDateTime', 'assignedLicenses', 'isAssignableToRole'
    $role = 'id', 'displayName', 'roleTemplateId', 'description', 'deletedDateTime'
    switch ($Kind) {
        'user' { $user }
        'group' { $group }
        'role' { $role }
        'device' { 'id', 'deviceName', 'userId', 'userPrincipalName', 'managedDeviceOwnerType', 'operatingSystem', 'managementState', 'lastSyncDateTime', 'complianceState' }
        'drive' { 'id', 'driveType', 'webUrl', 'name', 'description', 'createdDateTime', 'lastModifiedDateTime', 'owner', 'quota' }
        'sku' { 'id', 'skuId', 'skuPartNumber', 'prepaidUnits', 'consumedUnits', 'appliesTo', 'capabilityStatus', 'servicePlans' }
        'directoryObject' { $user + $group + $role | Select-Object -Unique }
        default { @() }
    }
}

function global:ConvertTo-FakeGraphWire {
    # Stored object -> the properties Graph would expose. Internal fields (managerId, members, flags) never leave.
    param([hashtable]$World, [string]$Kind, [hashtable]$Object, [string]$ODataType)
    $wire = [ordered]@{}
    if ($ODataType) { $wire['@odata.type'] = $ODataType }
    switch ($Kind) {
        'user' {
            foreach ($key in @($Object.Keys | Sort-Object)) {
                if ($key -in 'managerId', 'passwordProfile') { continue }
                $wire[$key] = $Object[$key]
            }
        }
        'group' {
            $types = @($Object['groupTypes'])
            $wire['id'] = $Object['id']
            $wire['displayName'] = $Object['displayName']
            $wire['mail'] = $Object['mail']
            $wire['mailNickname'] = $Object['mailNickname']
            $wire['mailEnabled'] = $Object['mailEnabled']
            $wire['securityEnabled'] = $Object['securityEnabled']
            $wire['groupTypes'] = $types
            $wire['membershipRule'] = $Object['membershipRule']
            $wire['membershipRuleProcessingState'] = if ($types -contains 'DynamicMembership') { 'On' } else { $null }
            # Role-assignable groups: their members hold the directory roles assigned to the group ($false unless a test sets it).
            $wire['isAssignableToRole'] = [bool]$Object['isAssignableToRole']
            # Group-based licensing: the SKUs the group assigns to its members (empty unless a test sets them).
            $wire['assignedLicenses'] = @(foreach ($entry in @($Object['assignedLicenses'] | Where-Object { $null -ne $_ })) { [ordered]@{ skuId = $entry.skuId; disabledPlans = @($entry.disabledPlans | Where-Object { $null -ne $_ }) } })
        }
        'role' {
            $wire['id'] = $Object['id']
            $wire['displayName'] = $Object['displayName']
            $wire['roleTemplateId'] = $Object['roleTemplateId']
            $wire['description'] = $Object['description']
        }
        'device' {
            $owner = Find-FakeGraphUser -World $World -Key ([string]$Object['userId'])
            $wire['id'] = $Object['id']
            $wire['deviceName'] = $Object['deviceName']
            $wire['userId'] = $Object['userId']
            $wire['userPrincipalName'] = if ($owner) { $owner['userPrincipalName'] } else { $null }
            $wire['managedDeviceOwnerType'] = $Object['ownerType']
            $wire['operatingSystem'] = $Object['operatingSystem']
            $wire['managementState'] = if ($Object['wiped']) { 'wipePending' } elseif ($Object['retired']) { 'retirePending' } else { 'managed' }
            $wire['lastSyncDateTime'] = $Object['lastSyncDateTime']
            $wire['complianceState'] = $Object['complianceState']
        }
        'drive' {
            $wire['id'] = $Object['id']
            $wire['driveType'] = 'business'
            $wire['webUrl'] = $Object['webUrl']
        }
        'sku' {
            $wire['id'] = 'fake-tenant_' + $Object['skuId']
            $wire['skuId'] = $Object['skuId']
            $wire['skuPartNumber'] = $Object['skuPartNumber']
            $wire['prepaidUnits'] = @{ enabled = $Object['prepaidUnits'].enabled; suspended = 0; warning = 0 }
            $wire['consumedUnits'] = $Object['consumedUnits']
            $wire['appliesTo'] = 'User'
            $wire['capabilityStatus'] = 'Enabled'
            # The tenant's view of each service plan, as subscribedSkus reports it.
            $wire['servicePlans'] = @(foreach ($entry in @($Object['servicePlans'])) { [ordered]@{ servicePlanId = $entry.servicePlanId; servicePlanName = $entry.servicePlanName; provisioningStatus = 'Success'; appliesTo = $entry.appliesTo } })
        }
    }
    $wire
}

function global:Select-FakeGraphProperty {
    param([System.Collections.IDictionary]$Wire, [string]$Kind, [AllowNull()][string]$Select)
    if ([string]::IsNullOrWhiteSpace($Select)) { return $Wire }
    $known = @(Get-FakeGraphKnownProperty -Kind $Kind)
    $out = [ordered]@{}
    if ($Wire.Contains('@odata.type')) { $out['@odata.type'] = $Wire['@odata.type'] }
    $out['id'] = $Wire['id']
    foreach ($raw in ($Select -split ',')) {
        $name = $raw.Trim()
        if (-not $name) { continue }
        $canonical = $known | Where-Object { $_ -ieq $name } | Select-Object -First 1
        if (-not $canonical) {
            Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Could not find a property named '$name' on type 'microsoft.graph.$Kind'."
        }
        # Statement form on purpose: assigning an if-expression would collapse an empty list to $null.
        if ($Wire.Contains($canonical)) { $out[[string]$canonical] = $Wire[$canonical] } else { $out[[string]$canonical] = $null }
    }
    $out
}

function global:Find-FakeGraphUser {
    param([hashtable]$World, [string]$Key, [switch]$Deleted)
    if ([string]::IsNullOrEmpty($Key)) { return $null }
    $list = if ($Deleted) { $World.DeletedUsers } else { $World.Users }
    foreach ($user in $list) {
        if ($user['id'] -eq $Key -or $user['userPrincipalName'] -eq $Key) { return $user }
    }
    return $null
}

function global:Find-FakeGraphGroup {
    param([hashtable]$World, [string]$Key)
    foreach ($group in $World.Groups) { if ($group['id'] -eq $Key) { return $group } }
    return $null
}

function global:Find-FakeGraphRole {
    param([hashtable]$World, [string]$Key)
    foreach ($role in $World.DirectoryRoles) { if ($role['id'] -eq $Key) { return $role } }
    return $null
}

function global:Get-FakeGraphRoleOrFail {
    param([hashtable]$World, [string]$Key)
    $role = Find-FakeGraphRole -World $World -Key $Key
    if (-not $role) { Stop-FakeGraphNotFound -Key $Key }
    $role
}

function global:Get-FakeGraphUserOrFail {
    param([hashtable]$World, [string]$Key)
    $user = Find-FakeGraphUser -World $World -Key $Key
    if (-not $user) { Stop-FakeGraphNotFound -Key $Key }
    $user
}

function global:Get-FakeGraphGroupOrFail {
    param([hashtable]$World, [string]$Key)
    $group = Find-FakeGraphGroup -World $World -Key $Key
    if (-not $group) { Stop-FakeGraphNotFound -Key $Key }
    $group
}

function global:ConvertFrom-FakeGraphQuery {
    param([AllowNull()][string]$Query)
    $parsed = [ordered]@{}
    if ([string]::IsNullOrEmpty($Query)) { return $parsed }
    foreach ($pair in ($Query -split '&')) {
        if (-not $pair) { continue }
        $index = $pair.IndexOf('=')
        $key = if ($index -ge 0) { $pair.Substring(0, $index) } else { $pair }
        $value = if ($index -ge 0) { $pair.Substring($index + 1) } else { '' }
        $key = [uri]::UnescapeDataString($key)
        if ($key -notin '$select', '$filter', '$top', '$skiptoken') {
            Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "FakeGraph does not support the query option '$key' (supported: `$select, `$filter, `$top, `$skiptoken)."
        }
        $parsed[$key] = [uri]::UnescapeDataString($value)
    }
    $parsed
}

# ---- $filter: or / and / not / parentheses, eq / ne / startswith -------------------------

function global:ConvertFrom-FakeGraphFilterToken {
    param([string]$Filter)
    $pattern = [regex]"\G\s*(?:(?<str>'(?:[^']|'')*')|(?<lp>\()|(?<rp>\))|(?<comma>,)|(?<word>[A-Za-z_][A-Za-z0-9_./]*)|(?<num>-?\d+))"
    $tokens = [System.Collections.Generic.List[hashtable]]::new()
    $position = 0
    while ($position -lt $Filter.Length) {
        if ($Filter.Substring($position).Trim().Length -eq 0) { break }
        $match = $pattern.Match($Filter, $position)
        if (-not $match.Success) {
            Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message "Unsupported or invalid query filter clause near '$($Filter.Substring($position).Trim())'."
        }
        if ($match.Groups['str'].Success) {
            $text = $match.Groups['str'].Value
            $tokens.Add(@{ Type = 'str'; Value = $text.Substring(1, $text.Length - 2).Replace("''", "'") })
        } elseif ($match.Groups['lp'].Success) { $tokens.Add(@{ Type = 'lp'; Value = '(' })
        } elseif ($match.Groups['rp'].Success) { $tokens.Add(@{ Type = 'rp'; Value = ')' })
        } elseif ($match.Groups['comma'].Success) { $tokens.Add(@{ Type = 'comma'; Value = ',' })
        } elseif ($match.Groups['num'].Success) { $tokens.Add(@{ Type = 'num'; Value = [int]$match.Groups['num'].Value })
        } else { $tokens.Add(@{ Type = 'word'; Value = $match.Groups['word'].Value }) }
        $position = $match.Index + $match.Length
    }
    , $tokens
}

function global:Read-FakeGraphFilterToken {
    param([hashtable]$State, [string]$Type, [string]$Value)
    if ($State.Pos -ge $State.Tokens.Count) {
        Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message 'Unsupported or invalid query filter clause: unexpected end of filter.'
    }
    $token = $State.Tokens[$State.Pos]
    if ($Type -and $token.Type -ne $Type) {
        Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message "Unsupported or invalid query filter clause: expected $Type but found '$($token.Value)'."
    }
    if ($Value -and "$($token.Value)" -ne $Value) {
        Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message "Unsupported or invalid query filter clause: expected '$Value' but found '$($token.Value)'."
    }
    $State.Pos++
    $token
}

function global:Test-FakeGraphFilterWord {
    param([hashtable]$State, [string]$Word)
    if ($State.Pos -ge $State.Tokens.Count) { return $false }
    $token = $State.Tokens[$State.Pos]
    $token.Type -eq 'word' -and $token.Value -ieq $Word
}

function global:Read-FakeGraphFilterOr {
    param([hashtable]$State)
    $node = Read-FakeGraphFilterAnd -State $State
    while (Test-FakeGraphFilterWord -State $State -Word 'or') {
        $null = Read-FakeGraphFilterToken -State $State
        $node = @{ Op = 'or'; Left = $node; Right = (Read-FakeGraphFilterAnd -State $State) }
    }
    $node
}

function global:Read-FakeGraphFilterAnd {
    param([hashtable]$State)
    $node = Read-FakeGraphFilterUnary -State $State
    while (Test-FakeGraphFilterWord -State $State -Word 'and') {
        $null = Read-FakeGraphFilterToken -State $State
        $node = @{ Op = 'and'; Left = $node; Right = (Read-FakeGraphFilterUnary -State $State) }
    }
    $node
}

function global:Read-FakeGraphFilterUnary {
    param([hashtable]$State)
    if (Test-FakeGraphFilterWord -State $State -Word 'not') {
        $null = Read-FakeGraphFilterToken -State $State
        return @{ Op = 'not'; Left = (Read-FakeGraphFilterUnary -State $State) }
    }
    if ($State.Pos -lt $State.Tokens.Count -and $State.Tokens[$State.Pos].Type -eq 'lp') {
        $null = Read-FakeGraphFilterToken -State $State
        $inner = Read-FakeGraphFilterOr -State $State
        $null = Read-FakeGraphFilterToken -State $State -Type 'rp'
        return $inner
    }
    Read-FakeGraphFilterTerm -State $State
}

function global:Get-FakeGraphFilterProperty {
    param([hashtable]$State, [string]$Name)
    $canonical = @(Get-FakeGraphKnownProperty -Kind $State.Kind) | Where-Object { $_ -ieq $Name } | Select-Object -First 1
    if (-not $canonical) {
        Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message "Unsupported or invalid query filter clause specified for property '$Name' of resource '$($State.Kind)'."
    }
    [string]$canonical
}

function global:Read-FakeGraphFilterTerm {
    param([hashtable]$State)
    $word = Read-FakeGraphFilterToken -State $State -Type 'word'
    if ($word.Value -ieq 'startswith') {
        $null = Read-FakeGraphFilterToken -State $State -Type 'lp'
        $property = Get-FakeGraphFilterProperty -State $State -Name (Read-FakeGraphFilterToken -State $State -Type 'word').Value
        $null = Read-FakeGraphFilterToken -State $State -Type 'comma'
        $literal = Read-FakeGraphFilterToken -State $State -Type 'str'
        $null = Read-FakeGraphFilterToken -State $State -Type 'rp'
        return @{ Op = 'startswith'; Property = $property; Value = $literal.Value }
    }
    $property = Get-FakeGraphFilterProperty -State $State -Name $word.Value
    $operator = (Read-FakeGraphFilterToken -State $State -Type 'word').Value.ToLowerInvariant()
    if ($operator -notin 'eq', 'ne') {
        Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message "Unsupported or invalid query filter clause: operator '$operator' is not supported."
    }
    $literal = Read-FakeGraphFilterToken -State $State
    $value = switch ($literal.Type) {
        'str' { $literal.Value }
        'num' { $literal.Value }
        'word' {
            switch ($literal.Value.ToLowerInvariant()) {
                'true' { $true }
                'false' { $false }
                'null' { $null }
                default { Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message "Unsupported or invalid query filter clause: unexpected value '$($literal.Value)'." }
            }
        }
        default { Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message 'Unsupported or invalid query filter clause: bad literal.' }
    }
    @{ Op = $operator; Property = $property; Value = $value; HasValue = $true }
}

function global:Test-FakeGraphFilter {
    param($Node, [hashtable]$Item)
    switch ($Node.Op) {
        'or' { return ((Test-FakeGraphFilter -Node $Node.Left -Item $Item) -or (Test-FakeGraphFilter -Node $Node.Right -Item $Item)) }
        'and' { return ((Test-FakeGraphFilter -Node $Node.Left -Item $Item) -and (Test-FakeGraphFilter -Node $Node.Right -Item $Item)) }
        'not' { return (-not (Test-FakeGraphFilter -Node $Node.Left -Item $Item)) }
        'startswith' {
            $actual = $Item[$Node.Property]
            return ($actual -is [string] -and $actual.StartsWith([string]$Node.Value, [System.StringComparison]::OrdinalIgnoreCase))
        }
        { $_ -in 'eq', 'ne' } {
            $actual = $Item[$Node.Property]
            $expected = $Node.Value
            $equal = if ($null -eq $expected) { $null -eq $actual }
            elseif ($expected -is [string]) { $actual -is [string] -and [string]::Equals($actual, $expected, [System.StringComparison]::OrdinalIgnoreCase) }
            elseif ($expected -is [bool]) { $actual -is [bool] -and $actual -eq $expected }
            else { $null -ne $actual -and $actual -eq $expected }
            return $(if ($Node.Op -eq 'eq') { $equal } else { -not $equal })
        }
    }
    $false
}

function global:Select-FakeGraphFilteredItem {
    param([object[]]$Items, [string]$Kind, [AllowNull()][string]$Filter)
    if ([string]::IsNullOrWhiteSpace($Filter)) { return @($Items) }
    $tokens = ConvertFrom-FakeGraphFilterToken -Filter $Filter
    $state = @{ Tokens = $tokens; Pos = 0; Kind = $Kind }
    $tree = Read-FakeGraphFilterOr -State $state
    if ($state.Pos -lt $tokens.Count) {
        Stop-FakeGraph -Status 400 -Code 'Request_UnsupportedQuery' -Message "Unsupported or invalid query filter clause near '$($tokens[$state.Pos].Value)'."
    }
    @($Items | Where-Object { Test-FakeGraphFilter -Node $tree -Item $_ })
}

# ---- Collections and paging ---------------------------------------------------------------

function global:New-FakeGraphCollection {
    param([hashtable]$World, [object[]]$Items, [System.Collections.IDictionary]$Query, [string]$BaseUrl)
    $Items = @($Items)
    $size = [int]$World.PageSize
    if ($Query.Contains('$top')) {
        $top = 0
        if (-not [int]::TryParse([string]$Query['$top'], [ref]$top) -or $top -lt 1) {
            Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Invalid value '$($Query['$top'])' for `$top."
        }
        $size = [math]::Min($size, $top)
    }
    $offset = 0
    if ($Query.Contains('$skiptoken')) {
        if (-not [int]::TryParse([string]$Query['$skiptoken'], [ref]$offset) -or $offset -lt 0) {
            Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'Invalid skip token.'
        }
    }
    $page = @($Items | Select-Object -Skip $offset -First $size)
    $body = [ordered]@{ value = $page }
    if ($offset + $size -lt $Items.Count) {
        $parts = foreach ($key in $Query.Keys) {
            if ($key -ieq '$skiptoken') { continue }
            '{0}={1}' -f $key, [uri]::EscapeDataString([string]$Query[$key])
        }
        $parts = @($parts) + ('$skiptoken=' + ($offset + $size))
        $body['@odata.nextLink'] = $BaseUrl + '?' + ($parts -join '&')
    }
    $body
}

# ---- Public: world, faults, request -------------------------------------------------------

function global:New-FakeGraphWorld {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $ids = @{
        AliceId           = '10000000-0000-4000-8000-000000000001'
        BobId             = '10000000-0000-4000-8000-000000000002'
        CarolId           = '10000000-0000-4000-8000-000000000003'
        DaveId            = '10000000-0000-4000-8000-000000000004'
        SalesGroupId      = '20000000-0000-4000-8000-000000000001'
        AllStaffGroupId   = '20000000-0000-4000-8000-000000000002'
        DynamicGroupId    = '20000000-0000-4000-8000-000000000003'
        LegalDlGroupId    = '20000000-0000-4000-8000-000000000004'
        SkuE3Id           = '30000000-0000-4000-8000-000000000001'
        SkuDeskId         = '30000000-0000-4000-8000-000000000002'
        SkuVoiceId        = '30000000-0000-4000-8000-000000000003'
        GlobalAdminRoleId = '40000000-0000-4000-8000-000000000001'
        CompanyDeviceId   = '50000000-0000-4000-8000-000000000001'
        PersonalDeviceId  = '50000000-0000-4000-8000-000000000002'
        UnknownDeviceId   = '50000000-0000-4000-8000-000000000003'
        AliceDriveId      = 'b!fake-drive-alice-0001'
    }
    $created = '2026-01-15T09:00:00Z'
    $list = { param($items) , [System.Collections.Generic.List[hashtable]]::new([hashtable[]]@($items)) }

    $users = [System.Collections.Generic.List[hashtable]]::new()
    $users.Add(@{
            id = $ids.AliceId; userPrincipalName = 'alice@example.com'; displayName = 'Alice Example'; mailNickname = 'alice'
            givenName = 'Alice'; surname = 'Example'; accountEnabled = $true; mail = 'alice@example.com'; usageLocation = 'US'
            department = 'Sales'; jobTitle = 'Account Executive'; officeLocation = 'Remote'; managerId = $ids.BobId
            createdDateTime = $created; lastPasswordChangeDateTime = $created; signInSessionsValidFromDateTime = $created
            assignedLicenses = (& $list @(@{ skuId = $ids.SkuE3Id; disabledPlans = @() }))
            licenseAssignmentStates = (& $list @(@{ skuId = $ids.SkuE3Id; assignedByGroup = $null; state = 'Active'; error = 'None' }))
        })
    $users.Add(@{
            id = $ids.BobId; userPrincipalName = 'bob@example.com'; displayName = 'Bob Manager'; mailNickname = 'bob'
            givenName = 'Bob'; surname = 'Manager'; accountEnabled = $true; mail = 'bob@example.com'; usageLocation = 'US'
            department = 'Sales'; jobTitle = 'Sales Manager'; officeLocation = 'HQ'; managerId = $null
            createdDateTime = $created; lastPasswordChangeDateTime = $created; signInSessionsValidFromDateTime = $created
            assignedLicenses = (& $list @(@{ skuId = $ids.SkuE3Id; disabledPlans = @() }))
            licenseAssignmentStates = (& $list @(@{ skuId = $ids.SkuE3Id; assignedByGroup = $ids.AllStaffGroupId; state = 'Active'; error = 'None' }))
        })
    $users.Add(@{
            id = $ids.CarolId; userPrincipalName = 'carol@example.com'; displayName = 'Carol Admin'; mailNickname = 'carol'
            givenName = 'Carol'; surname = 'Admin'; accountEnabled = $true; mail = 'carol@example.com'; usageLocation = 'US'
            department = 'IT'; jobTitle = 'Administrator'; officeLocation = 'HQ'; managerId = $null
            createdDateTime = $created; lastPasswordChangeDateTime = $created; signInSessionsValidFromDateTime = $created
            assignedLicenses = (& $list @())
            licenseAssignmentStates = (& $list @())
        })

    $deleted = [System.Collections.Generic.List[hashtable]]::new()
    $deleted.Add(@{
            id = $ids.DaveId; userPrincipalName = 'dave@example.com'; displayName = 'Dave Former'; mailNickname = 'dave'
            givenName = 'Dave'; surname = 'Former'; accountEnabled = $false; mail = $null; usageLocation = 'US'
            department = $null; jobTitle = $null; officeLocation = $null; managerId = $null
            createdDateTime = $created; deletedDateTime = '2026-09-01T00:00:00Z'; lastPasswordChangeDateTime = $created; signInSessionsValidFromDateTime = $created
            assignedLicenses = (& $list @())
            licenseAssignmentStates = (& $list @())
        })

    $groups = [System.Collections.Generic.List[hashtable]]::new()
    $groups.Add(@{
            id = $ids.SalesGroupId; displayName = 'Sales'; mail = 'sales@example.com'; mailNickname = 'sales'
            mailEnabled = $true; securityEnabled = $false; groupTypes = [string[]]@('Unified'); membershipRule = $null
            members = [string[]]@($ids.AliceId); owners = [string[]]@($ids.BobId)
        })
    $groups.Add(@{
            id = $ids.AllStaffGroupId; displayName = 'All Staff'; mail = $null; mailNickname = 'allstaff'
            mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
            members = [string[]]@($ids.AliceId, $ids.BobId, $ids.CarolId); owners = [string[]]@()
        })
    $groups.Add(@{
            id = $ids.DynamicGroupId; displayName = 'Everyone Dynamic'; mail = $null; mailNickname = 'everyone-dynamic'
            mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@('DynamicMembership')
            membershipRule = '(user.accountEnabled -eq true)'
            members = [string[]]@($ids.AliceId, $ids.BobId, $ids.CarolId); owners = [string[]]@()
        })
    $groups.Add(@{
            id = $ids.LegalDlGroupId; displayName = 'Legal DL'; mail = 'legal@example.com'; mailNickname = 'legal'
            mailEnabled = $true; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
            members = [string[]]@($ids.AliceId); owners = [string[]]@()
        })

    $skus = [System.Collections.Generic.List[hashtable]]::new()
    $plan = { param($Number, $Name) @{ servicePlanId = ('31000000-0000-4000-8000-{0:D12}' -f $Number); servicePlanName = $Name; appliesTo = 'User' } }
    $skus.Add(@{ skuId = $ids.SkuE3Id; skuPartNumber = 'SPE_E3'; prepaidUnits = @{ enabled = 10 }; consumedUnits = 3
            servicePlans = @((& $plan 1 'EXCHANGE_S_ENTERPRISE'), (& $plan 2 'TEAMS1'), (& $plan 3 'SHAREPOINTENTERPRISE'))
        })
    $skus.Add(@{ skuId = $ids.SkuDeskId; skuPartNumber = 'EXCHANGEDESKLESS'; prepaidUnits = @{ enabled = 5 }; consumedUnits = 5
            servicePlans = @((& $plan 4 'EXCHANGE_S_DESKLESS'))
        })
    $skus.Add(@{ skuId = $ids.SkuVoiceId; skuPartNumber = 'MCOEV'; prepaidUnits = @{ enabled = 2 }; consumedUnits = 0
            servicePlans = @((& $plan 5 'MCOEV'))
        })

    $roles = [System.Collections.Generic.List[hashtable]]::new()
    $roles.Add(@{
            id = $ids.GlobalAdminRoleId; displayName = 'Global Administrator'; roleTemplateId = '41000000-0000-4000-8000-000000000001'
            description = 'Can manage all aspects of the tenant.'; members = [string[]]@($ids.CarolId)
        })

    $devices = [System.Collections.Generic.List[hashtable]]::new()
    $synced = '2026-10-07T08:30:00Z'
    $devices.Add(@{ id = $ids.CompanyDeviceId; deviceName = 'ALICE-LAPTOP'; userId = $ids.AliceId; ownerType = 'company'; operatingSystem = 'Windows'; wiped = $false; retired = $false; lastSyncDateTime = $synced; complianceState = 'compliant' })
    $devices.Add(@{ id = $ids.PersonalDeviceId; deviceName = 'ALICE-PHONE'; userId = $ids.AliceId; ownerType = 'personal'; operatingSystem = 'iOS'; wiped = $false; retired = $false; lastSyncDateTime = $synced; complianceState = 'compliant' })
    $devices.Add(@{ id = $ids.UnknownDeviceId; deviceName = 'ALICE-TABLET'; userId = $ids.AliceId; ownerType = 'unknown'; operatingSystem = 'Android'; wiped = $false; retired = $false; lastSyncDateTime = $synced; complianceState = 'noncompliant' })

    @{
        Users                 = $users
        DeletedUsers          = $deleted
        Groups                = $groups
        SubscribedSkus        = $skus
        DirectoryRoles        = $roles
        ManagedDevices        = $devices
        Drives                = @{ ($ids.AliceId) = @{ id = $ids.AliceDriveId; webUrl = 'https://example-my.sharepoint.com/personal/alice_example_com/Documents'; permissions = [System.Collections.Generic.List[hashtable]]::new() } }
        TapMethods            = @{}
        SignInSessionsRevoked = [System.Collections.Generic.List[string]]::new()
        Calls                 = [System.Collections.Generic.List[hashtable]]::new()
        Faults                = [System.Collections.Generic.Queue[hashtable]]::new()
        SecretDigests         = [System.Collections.Generic.List[hashtable]]::new()
        PageSize              = 2
        Me                    = $ids.CarolId
        Ids                   = $ids
    }
}

function global:Reset-FakeGraphWorld {
    # Re-seeds $global:FakeGraphWorld; call from BeforeEach.
    $global:FakeGraphWorld = New-FakeGraphWorld
}

function global:Add-FakeGraphFault {
    # Queues a Graph-style error response that is served ahead of the next real response(s).
    param(
        [Parameter(Mandatory)][hashtable]$World,
        [Parameter(Mandatory)][int]$Status,
        [string]$Code = 'Fault_Injected',
        [string]$Message = 'Injected by FakeGraph.',
        [hashtable]$Headers = @{},
        [int]$Count = 1,
        # Optional filters: the fault waits for the first request with this verb / a Uri matching this -like pattern.
        [string]$Method,
        [string]$UriLike
    )
    $verb = if ($Method) { $Method.ToUpperInvariant() } else { $null }
    $pattern = if ($UriLike) { $UriLike } else { $null }
    for ($i = 0; $i -lt $Count; $i++) {
        $World.Faults.Enqueue(@{ Status = $Status; Headers = $Headers.Clone(); Body = @{ error = @{ code = $Code; message = $Message } }; Method = $verb; UriLike = $pattern })
    }
}

function global:Test-FakeGraphFaultMatch {
    # A queued fault applies to a request when its optional Method and UriLike filters both match.
    param([hashtable]$Fault, [string]$Method, [string]$Uri)
    $wantedMethod = [string]$Fault['Method']
    $wantedUri = [string]$Fault['UriLike']
    ((-not $wantedMethod) -or $wantedMethod -eq $Method) -and ((-not $wantedUri) -or $Uri -like $wantedUri)
}

function global:Get-FakeGraphCall {
    # Recorded calls, optionally filtered by Method and a -like pattern on the Uri.
    param([Parameter(Mandatory)][hashtable]$World, [string]$Method, [string]$UriLike)
    @($World.Calls | Where-Object {
            (-not $Method -or $_.Method -eq $Method.ToUpperInvariant()) -and (-not $UriLike -or $_.Uri -like $UriLike)
        })
}

function global:ConvertTo-FakeGraphRecordedBody {
    # The request body as the log keeps it: passwordProfile.password never appears in plaintext.
    param([AllowNull()][object]$Body)
    if ($null -eq $Body) { return $null }
    $text = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 32 -Compress }
    if ($text -notmatch 'passwordProfile') { return $text }
    try { $parsed = ConvertFrom-FakeGraphJson -Text $text -AsHashtable } catch { return '[unparseable body withheld]' }
    if ($parsed -is [System.Collections.IDictionary] -and $parsed['passwordProfile'] -is [System.Collections.IDictionary] -and $null -ne $parsed['passwordProfile']['password']) {
        $parsed['passwordProfile']['password'] = 'redacted:sha256:' + (Get-FakeGraphSha256 -Text ([string]$parsed['passwordProfile']['password']))
    }
    ConvertTo-Json -InputObject $parsed -Depth 32 -Compress
}

function global:Assert-FakeGraphPassword {
    # Graph-like complexity check: 8+ characters and at least three of upper, lower, digit, symbol.
    param([hashtable]$World, [string]$UserId, [AllowNull()][string]$Password)
    $classes = 0
    if ($Password -cmatch '[A-Z]') { $classes++ }
    if ($Password -cmatch '[a-z]') { $classes++ }
    if ($Password -match '[0-9]') { $classes++ }
    if ($Password -match '[^A-Za-z0-9]') { $classes++ }
    if ([string]::IsNullOrEmpty($Password) -or $Password.Length -lt 8 -or $classes -lt 3) {
        Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'The specified password does not comply with password complexity requirements. Please provide a different password.'
    }
    $World.SecretDigests.Add(@{ Kind = 'password'; UserId = $UserId; Sha256 = (Get-FakeGraphSha256 -Text $Password) })
}

function global:Get-FakeGraphPayload {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @{} }
    try { $payload = ConvertFrom-FakeGraphJson -Text $Text -AsHashtable } catch {
        Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'Unable to read JSON request payload.'
    }
    if ($payload -isnot [System.Collections.IDictionary]) {
        Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'The request payload must be a JSON object.'
    }
    $payload
}

function global:Get-FakeGraphObjectIdFromReference {
    param([hashtable]$Payload)
    $reference = [string]$Payload['@odata.id']
    if ([string]::IsNullOrWhiteSpace($reference)) {
        Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Property '@odata.id' is required."
    }
    [uri]::UnescapeDataString($reference.TrimEnd('/').Split('/')[-1])
}

function global:Get-FakeGraphPermissionEmail {
    # The recipient address of a stored drive permission, whichever shape it was stored in (lower case), or $null.
    param([hashtable]$Permission)
    foreach ($path in @(@('grantedToV2', 'user'), @('grantedToV2', 'siteUser'), @('grantedTo', 'user'))) {
        $outer = $Permission[$path[0]]
        if ($outer -is [System.Collections.IDictionary] -and $outer[$path[1]] -is [System.Collections.IDictionary] -and $outer[$path[1]]['email']) {
            return ([string]$outer[$path[1]]['email']).ToLowerInvariant()
        }
    }
    if ($Permission['invitation'] -is [System.Collections.IDictionary] -and $Permission['invitation']['email']) { return ([string]$Permission['invitation']['email']).ToLowerInvariant() }
    $null
}

function global:Set-FakeGraphUserProperty {
    # Shared by POST users and PATCH users/{id}. Validates keys, never stores passwordProfile.
    param([hashtable]$World, [hashtable]$User, [hashtable]$Payload)
    $known = @(Get-FakeGraphKnownProperty -Kind 'user')
    foreach ($key in @($Payload.Keys)) {
        if ($key -ieq 'passwordProfile') {
            $profile = $Payload[$key]
            if ($profile -isnot [System.Collections.IDictionary]) {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Property 'passwordProfile' must be an object."
            }
            if ($profile.Contains('password')) {
                Assert-FakeGraphPassword -World $World -UserId $User.id -Password ([string]$profile['password'])
                $User['lastPasswordChangeDateTime'] = Get-FakeGraphNow
            }
            continue
        }
        $canonical = $known | Where-Object { $_ -ieq $key } | Select-Object -First 1
        if (-not $canonical -or $canonical -eq 'id') {
            Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Property '$key' does not exist or cannot be set on type 'microsoft.graph.user'."
        }
        $value = $Payload[$key]
        if ($canonical -in 'lastPasswordChangeDateTime', 'signInSessionsValidFromDateTime') {
            Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Property '$canonical' is read-only and cannot be set."
        }
        if ($canonical -eq 'employeeLeaveDateTime' -and $null -ne $value) {
            $value = ConvertTo-FakeGraphDateTime -Value $value -Property $canonical
        }
        if ($canonical -eq 'accountEnabled' -and $value -isnot [bool]) {
            Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Property 'accountEnabled' must be a boolean."
        }
        if ($canonical -eq 'usageLocation' -and $null -ne $value -and "$value" -cnotmatch '^[A-Za-z]{2}$') {
            Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Invalid usage location '$value'."
        }
        if ($canonical -in 'userPrincipalName', 'mailNickname') {
            foreach ($other in @($World.Users) + @($World.DeletedUsers)) {
                if ($other['id'] -ne $User.id -and $other[$canonical] -eq $value) {
                    Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Another object with the same value for property $canonical already exists."
                }
            }
        }
        $User[[string]$canonical] = $value
    }
}

function global:Remove-FakeGraphGroupLicense {
    # What Entra does when a member leaves a group: the license assignments that group gave the user go, and a SKU
    # with no assignment left leaves assignedLicenses.
    param([hashtable]$User, [string]$GroupId)
    $states = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($state in @($User['licenseAssignmentStates'])) { if ($null -ne $state -and [string]$state['assignedByGroup'] -ne $GroupId) { $states.Add($state) } }
    $assigned = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($license in @($User['assignedLicenses'])) {
        if ($null -eq $license) { continue }
        if (@($states | Where-Object { $_['skuId'] -eq $license['skuId'] }).Count -gt 0 -or @($User['licenseAssignmentStates'] | Where-Object { $_['skuId'] -eq $license['skuId'] }).Count -eq 0) { $assigned.Add($license) }
    }
    $User['licenseAssignmentStates'] = $states
    $User['assignedLicenses'] = $assigned
}

function global:Update-FakeGraphDynamicMembership {
    # Re-evaluates the rule of every dynamic group for one user. The fake understands one rule shape,
    # '(user.accountEnabled -eq true|false)', which is enough to see a sign-in disable take a user out of a group.
    param([hashtable]$World, [hashtable]$User)
    foreach ($group in $World.Groups) {
        if (@($group['groupTypes']) -notcontains 'DynamicMembership') { continue }
        if ([string]$group['membershipRule'] -notmatch '^\(?\s*user\.accountEnabled\s+-eq\s+(true|false)\s*\)?$') { continue }
        $wanted = $Matches[1] -eq 'true'
        $id = [string]$User['id']
        $isMember = @($group['members']) -contains $id
        if (([bool]$User['accountEnabled'] -eq $wanted) -and -not $isMember) {
            $group['members'] = [string[]]@(@($group['members']) + $id)
        } elseif (([bool]$User['accountEnabled'] -ne $wanted) -and $isMember) {
            $group['members'] = [string[]]@(@($group['members']) | Where-Object { $_ -ne $id })
            Remove-FakeGraphGroupLicense -User $User -GroupId ([string]$group['id'])
        }
    }
}

function global:Invoke-FakeGraphRoute {
    param([hashtable]$World, [string]$Verb, [string]$Path, [System.Collections.IDictionary]$Query, [AllowNull()][string]$Text, [string]$Version)

    $baseUrl = "https://graph.microsoft.com/$Version/$Path"
    $select = if ($Query.Contains('$select')) { [string]$Query['$select'] } else { $null }
    $filter = if ($Query.Contains('$filter')) { [string]$Query['$filter'] } else { $null }
    $decode = { param($segment) [uri]::UnescapeDataString($segment) }
    $ok = { param($body, $status = 200) @{ Status = $status; Body = $body } }
    $list = {
        param($items, $kind, $odata)
        $views = foreach ($item in @($items)) {
            if ($null -eq $item) { continue }
            $itemKind = if ($kind -eq 'directoryObject') { $item.__kind } else { $kind }
            $wireKind = if ($itemKind) { $itemKind } else { $kind }
            $wire = ConvertTo-FakeGraphWire -World $World -Kind $wireKind -Object $item.__object -ODataType $item.__odata
            Select-FakeGraphProperty -Wire $wire -Kind $kind -Select $select
        }
        @{ Status = 200; Body = (New-FakeGraphCollection -World $World -Items @($views) -Query $Query -BaseUrl $baseUrl) }
    }
    $wrap = { param($object, $kind, $odata) @{ __object = $object; __kind = $kind; __odata = $odata } }
    $usersOf = { param($ids) @($ids | ForEach-Object { Find-FakeGraphUser -World $World -Key $_ } | Where-Object { $_ } | ForEach-Object { & $wrap $_ 'user' '#microsoft.graph.user' }) }
    $plain = { param($items, $kind) @($items | Where-Object { $null -ne $_ } | ForEach-Object { @{ __object = $_; __kind = $kind; __odata = $null } }) }

    $key = "$Verb $Path"
    switch -Regex ($key) {
        '^GET me$' {
            $me = Get-FakeGraphUserOrFail -World $World -Key ([string]$World.Me)
            return (& $ok (Select-FakeGraphProperty -Wire (ConvertTo-FakeGraphWire -World $World -Kind 'user' -Object $me) -Kind 'user' -Select $select))
        }
        '^GET users$' {
            return (& $list (Select-FakeGraphFilteredItem -Items @($World.Users) -Kind 'user' -Filter $filter | ForEach-Object { @{ __object = $_; __kind = 'user'; __odata = $null } }) 'user')
        }
        '^GET directory/deletedItems/microsoft\.graph\.user$' {
            return (& $list (Select-FakeGraphFilteredItem -Items @($World.DeletedUsers) -Kind 'user' -Filter $filter | ForEach-Object { @{ __object = $_; __kind = 'user'; __odata = '#microsoft.graph.user' } }) 'user')
        }
        '^POST users$' {
            $payload = Get-FakeGraphPayload -Text $Text
            foreach ($required in 'userPrincipalName', 'mailNickname', 'displayName', 'accountEnabled') {
                if (-not $payload.Contains($required) -or $null -eq $payload[$required] -or "$($payload[$required])" -eq '') {
                    Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Required property '$required' is missing."
                }
            }
            $profile = $payload['passwordProfile']
            if ($profile -isnot [System.Collections.IDictionary] -or [string]::IsNullOrEmpty([string]$profile['password'])) {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Required property 'passwordProfile.password' is missing."
            }
            $user = @{
                id = [guid]::NewGuid().ToString(); mail = $null; managerId = $null; createdDateTime = [datetime]::UtcNow.ToString('o')
                lastPasswordChangeDateTime = Get-FakeGraphNow; signInSessionsValidFromDateTime = Get-FakeGraphNow
                assignedLicenses = [System.Collections.Generic.List[hashtable]]::new()
                licenseAssignmentStates = [System.Collections.Generic.List[hashtable]]::new()
            }
            Set-FakeGraphUserProperty -World $World -User $user -Payload $payload
            $World.Users.Add($user)
            return (& $ok (ConvertTo-FakeGraphWire -World $World -Kind 'user' -Object $user) 201)
        }
        '^(GET|PATCH) users/([^/]+)$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[2])
            if ($Matches[1] -eq 'GET') {
                return (& $ok (Select-FakeGraphProperty -Wire (ConvertTo-FakeGraphWire -World $World -Kind 'user' -Object $user) -Kind 'user' -Select $select))
            }
            Set-FakeGraphUserProperty -World $World -User $user -Payload (Get-FakeGraphPayload -Text $Text)
            Update-FakeGraphDynamicMembership -World $World -User $user
            return (& $ok $null 204)
        }
        '^GET users/([^/]+)/manager$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $manager = Find-FakeGraphUser -World $World -Key ([string]$user['managerId'])
            if (-not $manager) { Stop-FakeGraphNotFound -Key 'manager' }
            $wire = ConvertTo-FakeGraphWire -World $World -Kind 'user' -Object $manager -ODataType '#microsoft.graph.user'
            return (& $ok (Select-FakeGraphProperty -Wire $wire -Kind 'directoryObject' -Select $select))
        }
        '^PUT users/([^/]+)/manager/\$ref$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $managerKey = Get-FakeGraphObjectIdFromReference -Payload (Get-FakeGraphPayload -Text $Text)
            $manager = Get-FakeGraphUserOrFail -World $World -Key $managerKey
            for ($cursor = $manager; $cursor; $cursor = Find-FakeGraphUser -World $World -Key ([string]$cursor['managerId'])) {
                if ($cursor['id'] -eq $user['id']) {
                    Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'Setting this manager would create a circular reference.'
                }
            }
            $user['managerId'] = $manager['id']
            return (& $ok $null 204)
        }
        '^DELETE users/([^/]+)/manager/\$ref$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $user['managerId'] = $null
            return (& $ok $null 204)
        }
        '^GET users/([^/]+)/(memberOf|transitiveMemberOf)$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $items = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($group in $World.Groups) { if (@($group['members']) -contains $user['id']) { $items.Add((& $wrap $group 'group' '#microsoft.graph.group')) } }
            foreach ($role in $World.DirectoryRoles) { if (@($role['members']) -contains $user['id']) { $items.Add((& $wrap $role 'role' '#microsoft.graph.directoryRole')) } }
            return (& $list $items 'directoryObject')
        }
        '^GET users/([^/]+)/licenseDetails$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $details = foreach ($assigned in @($user['assignedLicenses'])) {
                $sku = $World.SubscribedSkus | Where-Object { $_['skuId'] -eq $assigned.skuId } | Select-Object -First 1
                # A plan listed in the assignment's disabledPlans reads provisioningStatus Disabled, as in Graph.
                $disabled = @($assigned.disabledPlans | Where-Object { $null -ne $_ })
                $plans = @(if ($sku) { foreach ($entry in @($sku['servicePlans'])) { [ordered]@{ servicePlanId = $entry.servicePlanId; servicePlanName = $entry.servicePlanName; provisioningStatus = $(if ($disabled -contains $entry.servicePlanId) { 'Disabled' } else { 'Success' }); appliesTo = $entry.appliesTo } } })
                [ordered]@{ id = "$($user['id'])_$($assigned.skuId)"; skuId = $assigned.skuId; skuPartNumber = $(if ($sku) { $sku['skuPartNumber'] } else { $null }); servicePlans = $plans }
            }
            return @{ Status = 200; Body = (New-FakeGraphCollection -World $World -Items @($details) -Query $Query -BaseUrl $baseUrl) }
        }
        '^POST users/([^/]+)/assignLicense$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $payload = Get-FakeGraphPayload -Text $Text
            foreach ($required in 'addLicenses', 'removeLicenses') {
                if (-not $payload.Contains($required)) { Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "Property $required is required." }
            }
            $add = @($payload['addLicenses'] | Where-Object { $null -ne $_ })
            $remove = @($payload['removeLicenses'] | Where-Object { $null -ne $_ })
            $states = [System.Collections.Generic.List[hashtable]]::new([hashtable[]]@($user['licenseAssignmentStates']))
            $assigned = [System.Collections.Generic.List[hashtable]]::new([hashtable[]]@($user['assignedLicenses']))
            if ($add.Count -gt 0 -and [string]::IsNullOrEmpty([string]$user['usageLocation'])) {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'License assignment cannot be done for user with invalid usage location.'
            }
            foreach ($entry in $add) {
                $skuId = [string]$entry['skuId']
                if (-not ($World.SubscribedSkus | Where-Object { $_['skuId'] -eq $skuId })) {
                    Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "License $skuId does not correspond to a valid license."
                }
            }
            foreach ($skuId in $remove) {
                $entries = @($states | Where-Object { $_['skuId'] -eq $skuId })
                if (-not ($assigned | Where-Object { $_['skuId'] -eq $skuId })) {
                    Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "User does not have license $skuId to remove."
                }
                $direct = @($entries | Where-Object { -not $_['assignedByGroup'] })
                if ($entries.Count -gt 0 -and $direct.Count -eq 0) {
                    Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "License $skuId cannot be removed directly because it is inherited from a group ($(($entries | ForEach-Object { $_['assignedByGroup'] }) -join ', ')). Remove the user from the group instead."
                }
            }
            foreach ($entry in $add) {
                $skuId = [string]$entry['skuId']
                if (-not ($assigned | Where-Object { $_['skuId'] -eq $skuId })) { $assigned.Add(@{ skuId = $skuId; disabledPlans = @($entry['disabledPlans']) }) }
                if (-not ($states | Where-Object { $_['skuId'] -eq $skuId -and -not $_['assignedByGroup'] })) {
                    $states.Add(@{ skuId = $skuId; assignedByGroup = $null; state = 'Active'; error = 'None' })
                }
            }
            foreach ($skuId in $remove) {
                $kept = [System.Collections.Generic.List[hashtable]]::new()
                foreach ($state in $states) { if (-not ($state.skuId -eq $skuId -and -not $state.assignedByGroup)) { $kept.Add($state) } }
                $states = $kept
                if (-not ($states | Where-Object { $_['skuId'] -eq $skuId })) {
                    $left = [System.Collections.Generic.List[hashtable]]::new()
                    foreach ($license in $assigned) { if ($license['skuId'] -ne $skuId) { $left.Add($license) } }
                    $assigned = $left
                }
            }
            $user['licenseAssignmentStates'] = $states
            $user['assignedLicenses'] = $assigned
            return (& $ok (ConvertTo-FakeGraphWire -World $World -Kind 'user' -Object $user))
        }
        '^POST users/([^/]+)/revokeSignInSessions$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $World.SignInSessionsRevoked.Add([string]$user['id'])
            $user['signInSessionsValidFromDateTime'] = Get-FakeGraphNow
            return (& $ok @{ '@odata.context' = 'https://graph.microsoft.com/v1.0/$metadata#Edm.Boolean'; value = $true })
        }
        '^GET deviceManagement/managedDevices/([^/]+)$' {
            $deviceKey = & $decode $Matches[1]
            $device = $World.ManagedDevices | Where-Object { $_['id'] -eq $deviceKey } | Select-Object -First 1
            if (-not $device) { Stop-FakeGraph -Status 404 -Code 'ResourceNotFound' -Message "Resource not found for the segment 'managedDevices'." }
            return (& $ok (Select-FakeGraphProperty -Wire (ConvertTo-FakeGraphWire -World $World -Kind 'device' -Object $device) -Kind 'device' -Select $select))
        }
        '^GET users/([^/]+)/managedDevices$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            return (& $list (& $plain @($World.ManagedDevices | Where-Object { $_['userId'] -eq $user['id'] }) 'device') 'device')
        }
        '^POST deviceManagement/managedDevices/([^/]+)/(wipe|retire)$' {
            $deviceKey = & $decode $Matches[1]
            $action = $Matches[2]
            $device = $World.ManagedDevices | Where-Object { $_['id'] -eq $deviceKey } | Select-Object -First 1
            if (-not $device) { Stop-FakeGraphNotFound -Key $deviceKey }
            if ($action -eq 'wipe') {
                $device['wipeRequest'] = Get-FakeGraphPayload -Text $Text
                $device['wiped'] = $true
            } else {
                $device['retired'] = $true
            }
            return (& $ok $null 204)
        }
        '^GET users/([^/]+)/drive$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            if (-not $World.Drives.ContainsKey($user['id'])) { Stop-FakeGraph -Status 404 -Code 'ResourceNotFound' -Message "The user's OneDrive has not been provisioned." }
            return (& $ok (Select-FakeGraphProperty -Wire (ConvertTo-FakeGraphWire -World $World -Kind 'drive' -Object $World.Drives[$user['id']]) -Kind 'drive' -Select $select))
        }
        '^POST (?:users/([^/]+)/drive|drives/([^/]+))/root/invite$' {
            $userKey = $Matches[1]
            $driveKey = $Matches[2]
            $drive = $null
            if ($userKey) {
                $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $userKey)
                if ($World.Drives.ContainsKey($user['id'])) { $drive = $World.Drives[$user['id']] }
            } else {
                $drive = $World.Drives.Values | Where-Object { $_['id'] -eq (& $decode $driveKey) } | Select-Object -First 1
            }
            if (-not $drive) { Stop-FakeGraph -Status 404 -Code 'ResourceNotFound' -Message 'The drive could not be found.' }
            $payload = Get-FakeGraphPayload -Text $Text
            $recipients = @($payload['recipients'] | Where-Object { $null -ne $_ })
            $roles = @($payload['roles'] | Where-Object { $null -ne $_ })
            if ($recipients.Count -eq 0 -or $roles.Count -eq 0) {
                Stop-FakeGraph -Status 400 -Code 'invalidRequest' -Message 'recipients and roles are required.'
            }
            # All or nothing: a recipient that already holds every requested role is a 400, and nothing is added.
            foreach ($recipient in $recipients) {
                $email = ([string]$recipient['email']).ToLowerInvariant()
                foreach ($existing in $drive['permissions']) {
                    if ((Get-FakeGraphPermissionEmail -Permission $existing) -ne $email) { continue }
                    $held = @($existing['roles'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
                    if (@($roles | Where-Object { $held -notcontains ([string]$_).ToLowerInvariant() }).Count -eq 0) {
                        Stop-FakeGraph -Status 400 -Code 'invalidRequest' -Message "The permission already exists for this recipient ($email)."
                    }
                }
            }
            $granted = foreach ($recipient in $recipients) {
                $email = [string]$recipient['email']
                $permission = @{
                    id = [guid]::NewGuid().ToString(); roles = $roles; hasPassword = $false
                    grantedToV2 = @{ user = @{ email = $email; displayName = $email } }
                    invitation = @{ email = $email; signInRequired = [bool]$payload['requireSignIn'] }
                }
                $drive['permissions'].Add($permission)
                $permission
            }
            return (& $ok @{ value = @($granted) })
        }
        '^DELETE drives/([^/]+)/root/permissions/([^/]+)$' {
            $driveKey = & $decode $Matches[1]
            $permissionKey = & $decode $Matches[2]
            $drive = $World.Drives.Values | Where-Object { $_['id'] -eq $driveKey } | Select-Object -First 1
            if (-not $drive) { Stop-FakeGraph -Status 404 -Code 'itemNotFound' -Message 'The resource could not be found.' }
            $permissions = $drive['permissions']
            for ($i = 0; $i -lt $permissions.Count; $i++) {
                if ($permissions[$i]['id'] -eq $permissionKey) {
                    $permissions.RemoveAt($i)
                    return (& $ok $null 204)
                }
            }
            Stop-FakeGraph -Status 404 -Code 'itemNotFound' -Message 'The resource could not be found.'
        }
        '^GET drives/([^/]+)/root/permissions$' {
            $driveKey = & $decode $Matches[1]
            $drive = $World.Drives.Values | Where-Object { $_['id'] -eq $driveKey } | Select-Object -First 1
            if (-not $drive) { Stop-FakeGraph -Status 404 -Code 'ResourceNotFound' -Message 'The drive could not be found.' }
            return @{ Status = 200; Body = (New-FakeGraphCollection -World $World -Items @($drive['permissions']) -Query $Query -BaseUrl $baseUrl) }
        }
        '^GET groups$' {
            return (& $list (& $plain (Select-FakeGraphFilteredItem -Items @($World.Groups) -Kind 'group' -Filter $filter) 'group') 'group')
        }
        '^GET groups/([^/]+)$' {
            $group = Get-FakeGraphGroupOrFail -World $World -Key (& $decode $Matches[1])
            return (& $ok (Select-FakeGraphProperty -Wire (ConvertTo-FakeGraphWire -World $World -Kind 'group' -Object $group) -Kind 'group' -Select $select))
        }
        '^GET groups/([^/]+)/(members|owners)$' {
            $group = Get-FakeGraphGroupOrFail -World $World -Key (& $decode $Matches[1])
            return (& $list (& $usersOf @($group[$Matches[2]])) 'directoryObject')
        }
        '^GET groups/([^/]+)/members/([^/]+)$' {
            $group = Get-FakeGraphGroupOrFail -World $World -Key (& $decode $Matches[1])
            $memberKey = & $decode $Matches[2]
            if (@($group['members']) -notcontains $memberKey) { Stop-FakeGraphNotFound -Key $memberKey }
            $member = Get-FakeGraphUserOrFail -World $World -Key $memberKey
            $wire = ConvertTo-FakeGraphWire -World $World -Kind 'user' -Object $member -ODataType '#microsoft.graph.user'
            return (& $ok (Select-FakeGraphProperty -Wire $wire -Kind 'directoryObject' -Select $select))
        }
        '^POST groups/([^/]+)/members/\$ref$' {
            $group = Get-FakeGraphGroupOrFail -World $World -Key (& $decode $Matches[1])
            $types = @($group['groupTypes'])
            if ($types -contains 'DynamicMembership') {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'Members cannot be added to a group with dynamic membership.'
            }
            if ($group['mailEnabled'] -and $types -notcontains 'Unified') {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'Cannot Update a mail-enabled security groups and or distribution list.'
            }
            $memberKey = Get-FakeGraphObjectIdFromReference -Payload (Get-FakeGraphPayload -Text $Text)
            $member = Find-FakeGraphUser -World $World -Key $memberKey
            if (-not $member) { Stop-FakeGraphNotFound -Key $memberKey }
            if (@($group['members']) -contains $member['id']) {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "One or more added object references already exist for the following modified properties: 'members'."
            }
            $group['members'] = [string[]]@(@($group['members']) + [string]$member['id'])
            return (& $ok $null 204)
        }
        '^DELETE groups/([^/]+)/members/([^/]+)/\$ref$' {
            $group = Get-FakeGraphGroupOrFail -World $World -Key (& $decode $Matches[1])
            $memberKey = & $decode $Matches[2]
            $types = @($group['groupTypes'])
            if ($types -contains 'DynamicMembership') {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'Members cannot be removed from a group with dynamic membership.'
            }
            if ($group['mailEnabled'] -and $types -notcontains 'Unified') {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'Cannot Update a mail-enabled security groups and or distribution list.'
            }
            $member = Find-FakeGraphUser -World $World -Key $memberKey
            if (-not $member -or @($group['members']) -notcontains $member['id']) { Stop-FakeGraphNotFound -Key $memberKey }
            $group['members'] = [string[]]@(@($group['members']) | Where-Object { $_ -ne $member['id'] })
            Remove-FakeGraphGroupLicense -User $member -GroupId ([string]$group['id'])
            return (& $ok $null 204)
        }
        '^GET subscribedSkus$' {
            return (& $list (& $plain @($World.SubscribedSkus) 'sku') 'sku')
        }
        '^GET directoryRoles$' {
            return (& $list (& $plain @($World.DirectoryRoles) 'role') 'role')
        }
        '^GET directoryRoles/([^/]+)$' {
            $role = Get-FakeGraphRoleOrFail -World $World -Key (& $decode $Matches[1])
            return (& $ok (Select-FakeGraphProperty -Wire (ConvertTo-FakeGraphWire -World $World -Kind 'role' -Object $role) -Kind 'role' -Select $select))
        }
        '^GET directoryRoles/([^/]+)/members/([^/]+)$' {
            $role = Get-FakeGraphRoleOrFail -World $World -Key (& $decode $Matches[1])
            $memberKey = & $decode $Matches[2]
            $member = Find-FakeGraphUser -World $World -Key $memberKey
            if (-not $member -or @($role['members']) -notcontains $member['id']) { Stop-FakeGraphNotFound -Key $memberKey }
            $wire = ConvertTo-FakeGraphWire -World $World -Kind 'user' -Object $member -ODataType '#microsoft.graph.user'
            return (& $ok (Select-FakeGraphProperty -Wire $wire -Kind 'directoryObject' -Select $select))
        }
        '^POST directoryRoles/([^/]+)/members/\$ref$' {
            $role = Get-FakeGraphRoleOrFail -World $World -Key (& $decode $Matches[1])
            $memberKey = Get-FakeGraphObjectIdFromReference -Payload (Get-FakeGraphPayload -Text $Text)
            $member = Find-FakeGraphUser -World $World -Key $memberKey
            if (-not $member) { Stop-FakeGraphNotFound -Key $memberKey }
            if (@($role['members']) -contains $member['id']) {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message "One or more added object references already exist for the following modified properties: 'members'."
            }
            $role['members'] = [string[]]@(@($role['members']) + [string]$member['id'])
            return (& $ok $null 204)
        }
        '^GET directoryRoles/([^/]+)/members$' {
            $roleKey = & $decode $Matches[1]
            $role = $World.DirectoryRoles | Where-Object { $_['id'] -eq $roleKey } | Select-Object -First 1
            if (-not $role) { Stop-FakeGraphNotFound -Key $roleKey }
            return (& $list (& $usersOf @($role['members'])) 'directoryObject')
        }
        '^DELETE directoryRoles/([^/]+)/members/([^/]+)/\$ref$' {
            $roleKey = & $decode $Matches[1]
            $memberKey = & $decode $Matches[2]
            $role = $World.DirectoryRoles | Where-Object { $_['id'] -eq $roleKey } | Select-Object -First 1
            if (-not $role) { Stop-FakeGraphNotFound -Key $roleKey }
            $member = Find-FakeGraphUser -World $World -Key $memberKey
            if (-not $member -or @($role['members']) -notcontains $member['id']) { Stop-FakeGraphNotFound -Key $memberKey }
            $role['members'] = [string[]]@(@($role['members']) | Where-Object { $_ -ne $member['id'] })
            return (& $ok $null 204)
        }
        '^GET users/([^/]+)/authentication/temporaryAccessPassMethods$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $now = [datetime]::UtcNow
            $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
            $methods = foreach ($method in @($World.TapMethods[$user['id']])) {
                if (-not $method) { continue }
                $start = [datetime]::Parse([string]$method['startDateTime'], [System.Globalization.CultureInfo]::InvariantCulture, $styles)
                $reason = if ($now -lt $start) { 'NotYetValid' } elseif ($now -ge $start.AddMinutes([double]$method['lifetimeInMinutes'])) { 'Expired' } else { 'EnabledByPolicy' }
                $view = [ordered]@{}
                foreach ($name in @($method.Keys | Sort-Object)) { $view[$name] = $method[$name] }
                $view['temporaryAccessPass'] = $null
                $view['isUsable'] = ($reason -eq 'EnabledByPolicy')
                $view['methodUsabilityReason'] = $reason
                $view
            }
            return @{ Status = 200; Body = (New-FakeGraphCollection -World $World -Items @($methods) -Query $Query -BaseUrl $baseUrl) }
        }
        '^POST users/([^/]+)/authentication/temporaryAccessPassMethods$' {
            $user = Get-FakeGraphUserOrFail -World $World -Key (& $decode $Matches[1])
            $payload = Get-FakeGraphPayload -Text $Text
            $lifetime = if ($payload.Contains('lifetimeInMinutes')) { [int]$payload['lifetimeInMinutes'] } else { 60 }
            if ($lifetime -lt 10 -or $lifetime -gt 43200) {
                Stop-FakeGraph -Status 400 -Code 'Request_BadRequest' -Message 'lifetimeInMinutes must be between 10 and 43200.'
            }
            $start = if ($payload.Contains('startDateTime') -and $payload['startDateTime']) { [string]$payload['startDateTime'] } else { [datetime]::UtcNow.ToString('o') }
            $usableOnce = $payload.Contains('isUsableOnce') -and [bool]$payload['isUsableOnce']
            $pass = 'TAP-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
            $stored = @{
                id = [guid]::NewGuid().ToString(); createdDateTime = [datetime]::UtcNow.ToString('o'); startDateTime = $start
                lifetimeInMinutes = $lifetime; isUsableOnce = $usableOnce
            }
            if (-not $World.TapMethods.ContainsKey($user['id'])) { $World.TapMethods[$user['id']] = [System.Collections.Generic.List[hashtable]]::new() }
            $World.TapMethods[$user['id']].Add($stored)
            $World.SecretDigests.Add(@{ Kind = 'tap'; UserId = [string]$user['id']; Sha256 = (Get-FakeGraphSha256 -Text $pass) })
            $issued = [ordered]@{}
            foreach ($name in @($stored.Keys | Sort-Object)) { $issued[$name] = $stored[$name] }
            $issued['temporaryAccessPass'] = $pass
            $issued['isUsable'] = $true
            $issued['methodUsabilityReason'] = 'EnabledByPolicy'
            return (& $ok $issued 201)
        }
    }
    Stop-FakeGraph -Status 404 -Code 'Request_ResourceNotFound' -Message "FakeGraph has no route for $Verb $Path."
}

function global:Invoke-FakeGraphRequest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable]$World,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [AllowNull()][object]$Body
    )
    Set-StrictMode -Version Latest

    $verb = $Method.ToUpperInvariant()
    $requestId = 'fake-request-{0:D4}' -f ($World.Calls.Count + 1)
    $World.Calls.Add(@{ Method = $verb; Uri = $Uri; Body = (ConvertTo-FakeGraphRecordedBody -Body $Body) })

    # Serve the first queued fault that matches this request; the rest keep their order.
    $fault = $null
    for ($remaining = $World.Faults.Count; $remaining -gt 0; $remaining--) {
        $candidate = $World.Faults.Dequeue()
        if ($null -eq $fault -and (Test-FakeGraphFaultMatch -Fault $candidate -Method $verb -Uri $Uri)) { $fault = $candidate } else { $World.Faults.Enqueue($candidate) }
    }
    if ($null -ne $fault) {
        $headers = @{ 'request-id' = @($requestId) }
        if ($fault['Headers']) { foreach ($name in $fault['Headers'].Keys) { $headers[$name] = $fault['Headers'][$name] } }
        return @{ Status = [int]$fault['Status']; Headers = $headers; Body = (ConvertTo-FakeGraphBody -Value $fault['Body']) }
    }

    $version = 'v1.0'
    $relative = $Uri.Trim()
    if ($relative -match '^https?://[^/]+/(v1\.0|beta)/(.*)$') {
        $version = $Matches[1]
        $relative = $Matches[2]
    } else {
        $relative = $relative.TrimStart('/')
        if ($relative -match '^(v1\.0|beta)/(.*)$') {
            $version = $Matches[1]
            $relative = $Matches[2]
        }
    }
    $path = $relative
    $queryText = $null
    $split = $relative.IndexOf('?')
    if ($split -ge 0) {
        $path = $relative.Substring(0, $split)
        $queryText = $relative.Substring($split + 1)
    }
    $path = $path.TrimEnd('/')

    $text = $null
    if ($null -ne $Body) { $text = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 32 -Compress } }

    try {
        $query = ConvertFrom-FakeGraphQuery -Query $queryText
        $response = Invoke-FakeGraphRoute -World $World -Verb $verb -Path $path -Query $query -Text $text -Version $version
    } catch {
        if (-not $_.Exception.Data.Contains('FakeGraphStatus')) { throw }
        $response = @{
            Status = [int]$_.Exception.Data['FakeGraphStatus']
            Body   = @{ error = @{ code = [string]$_.Exception.Data['FakeGraphCode']; message = $_.Exception.Message } }
        }
    }
    @{
        Status  = [int]$response.Status
        Headers = @{ 'request-id' = @($requestId); 'Content-Type' = @('application/json') }
        Body    = (ConvertTo-FakeGraphBody -Value $response.Body)
    }
}
