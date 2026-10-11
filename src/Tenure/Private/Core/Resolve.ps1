function ConvertTo-TenureUriSegment {
    <#
    .SYNOPSIS
        Escapes one value for use as a single path segment (a UPN or an id), so '/', '?', '#' and '..' cannot change the route.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    [uri]::EscapeDataString($Value)
}

function ConvertTo-TenureODataString {
    <#
    .SYNOPSIS
        Escapes a value for use between single quotes in an OData $filter (a single quote is doubled).
        URL-encoding is a separate step: encode the whole filter expression with [uri]::EscapeDataString.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $Value.Replace("'", "''")
}

function Get-TenureGraphProperty {
    <#
    .SYNOPSIS
        Reads one scalar property from a hashtable or an object without tripping strict mode when it is absent.
    .DESCRIPTION
        Graph omits properties that are not set and plan files round-trip hashtables into
        PSCustomObjects. Names match case-insensitively. For array-valued properties wrap
        the call yourself or read them directly: a function return unrolls arrays.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -ieq $Name) { return $InputObject[$key] }
        }
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    $Default
}

function ConvertTo-TenureTable {
    <#
    .SYNOPSIS
        Shallow-copies a hashtable or PSCustomObject into a case-insensitive hashtable ($null gives an empty one).
    .DESCRIPTION
        Provider Desired values are hashtables when a plan is built in memory and
        PSCustomObjects after a plan file is imported. Providers normalize with this first.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$InputObject)

    $table = @{}
    if ($null -eq $InputObject) { return $table }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) { $table[[string]$key] = $InputObject[$key] }
    } else {
        foreach ($property in $InputObject.PSObject.Properties) { $table[$property.Name] = $property.Value }
    }
    $table
}

function Test-TenureObjectId {
    <#
    .SYNOPSIS
        True when a value is a string shaped like an Entra object id (a GUID in its 8-4-4-4-12 form).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][object]$Value)

    ($Value -is [string]) -and ($Value.Trim() -cmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Get-TenureStepIdentifierProblem {
    <#
    .SYNOPSIS
        What is wrong with a step's identifiers, or $null: Target.Id and After.userId must be non-empty strings, and
        a mailbox or drive provider's Target.Id an Entra object id (or the {{subjectId}} placeholder).
    .DESCRIPTION
        The protection check compares strings; a provider that casts another type to a string would act on an
        account the check never saw. Exchange resolves a mailbox named by alias, display name or proxy address,
        and the protection check knows only ids, user principal names and mail addresses, so mailboxes and
        drives are named by object id only. Used by New-TenureStep and the plan shape check.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$Target,
        [AllowNull()][object]$After,
        [AllowNull()][string]$TargetKind
    )

    $id = Get-TenureProperty -InputObject $Target -Name 'Id'
    if ($id -isnot [string] -or [string]::IsNullOrWhiteSpace($id)) { return "Target.Id must be a non-empty string (got $(Get-TenureValueTypeName $id))" }
    if ($TargetKind -cin 'mailbox', 'drive' -and -not (Test-TenureObjectId -Value $id) -and $id.Trim() -ine '{{subjectId}}') {
        return "a $TargetKind is named by the Entra object id of its owner, not '$id' (an alias, address or name can resolve to another account)"
    }
    $hasUserId = if ($After -is [System.Collections.IDictionary]) { $After.Contains('userId') } else { $null -ne $After -and $null -ne $After.PSObject.Properties['userId'] }
    if ($hasUserId) {
        $userId = Get-TenureProperty -InputObject $After -Name 'userId'
        if ($userId -isnot [string] -or [string]::IsNullOrWhiteSpace($userId)) { return "After.userId must be a non-empty string (got $(Get-TenureValueTypeName $userId))" }
    }
    $null
}

function Get-TenureTargetId {
    <#
    .SYNOPSIS
        Returns Target.Id or throws Tenure.Provider.TargetNotFound when the target has no usable id yet.
    .DESCRIPTION
        Steps that depend on an Onboard create step carry a $null (or still-unsubstituted
        placeholder) Id at plan time. Reporting that as TargetNotFound lets the plan builder
        treat the Before snapshot as empty instead of sending a bogus request to Graph.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Target, [Parameter(Mandatory)][string]$Provider)

    $id = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Id')
    if ([string]::IsNullOrWhiteSpace($id) -or $id.StartsWith('{{', [System.StringComparison]::Ordinal)) {
        throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "$Provider has no target id yet; the object is created by an earlier step." -Category ObjectNotFound -Data @{ Provider = $Provider })
    }
    $id
}

function Resolve-TenureUser {
    <#
    .SYNOPSIS
        Looks up a user by UPN or object id and returns the fields plan builders need, with the manager.
    .DESCRIPTION
        Throws Tenure.User.NotFound when Graph answers 404. Manager is $null when the user
        has none. Keys: Id, UserPrincipalName, DisplayName, MailNickname, Mail, AccountEnabled,
        UsageLocation, Department, JobTitle, OfficeLocation, GivenName, Surname, Manager
        (@{ Id; UserPrincipalName; DisplayName; Mail } or $null).
    .EXAMPLE
        Resolve-TenureUser -Identity 'alice@example.com'
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity)

    $select = 'id,userPrincipalName,displayName,mailNickname,mail,accountEnabled,usageLocation,department,jobTitle,officeLocation,givenName,surname'
    try {
        $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $Identity) + '?$select=' + $select)
    } catch {
        if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
            throw (New-TenureError -Id 'Tenure.User.NotFound' -Message "User '$Identity' was not found. Check the user principal name or object id, and that you are connected to the right tenant." -Category ObjectNotFound -Data @{ Identity = $Identity } -Inner $_)
        }
        throw
    }

    $userId = [string](Get-TenureGraphProperty -InputObject $user -Name 'id')
    $manager = $null
    try {
        $raw = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $userId) + '/manager?$select=id,userPrincipalName,displayName,mail')
        $manager = @{
            Id                = Get-TenureGraphProperty -InputObject $raw -Name 'id'
            UserPrincipalName = Get-TenureGraphProperty -InputObject $raw -Name 'userPrincipalName'
            DisplayName       = Get-TenureGraphProperty -InputObject $raw -Name 'displayName'
            Mail              = Get-TenureGraphProperty -InputObject $raw -Name 'mail'
        }
    } catch {
        if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
    }

    @{
        Id                = $userId
        UserPrincipalName = Get-TenureGraphProperty -InputObject $user -Name 'userPrincipalName'
        DisplayName       = Get-TenureGraphProperty -InputObject $user -Name 'displayName'
        MailNickname      = Get-TenureGraphProperty -InputObject $user -Name 'mailNickname'
        Mail              = Get-TenureGraphProperty -InputObject $user -Name 'mail'
        AccountEnabled    = Get-TenureGraphProperty -InputObject $user -Name 'accountEnabled'
        UsageLocation     = Get-TenureGraphProperty -InputObject $user -Name 'usageLocation'
        Department        = Get-TenureGraphProperty -InputObject $user -Name 'department'
        JobTitle          = Get-TenureGraphProperty -InputObject $user -Name 'jobTitle'
        OfficeLocation    = Get-TenureGraphProperty -InputObject $user -Name 'officeLocation'
        GivenName         = Get-TenureGraphProperty -InputObject $user -Name 'givenName'
        Surname           = Get-TenureGraphProperty -InputObject $user -Name 'surname'
        Manager           = $manager
    }
}

function Get-TenureUserIdentity {
    <#
    .SYNOPSIS
        Reads a user's object id, user principal name and mail address, or returns $null when Graph has no such user.
    .DESCRIPTION
        One GET users/{id or UPN}. The apply engine uses it to compare every account a plan changes
        with the signed-in account and the protected users. A 404 (an onboarding's user that does
        not exist yet) gives $null; any other failure is thrown, so the check fails closed.
    .EXAMPLE
        Get-TenureUserIdentity -Identity 'alice@example.com'
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity)

    try {
        $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $Identity.Trim()) + '?$select=id,userPrincipalName,mail')
    } catch {
        if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') { return $null }
        throw
    }
    @{
        Id                = Get-TenureGraphProperty -InputObject $user -Name 'id'
        UserPrincipalName = Get-TenureGraphProperty -InputObject $user -Name 'userPrincipalName'
        Mail              = Get-TenureGraphProperty -InputObject $user -Name 'mail'
    }
}

function Test-TenureProtectedEntry {
    <#
    .SYNOPSIS
        True when a protectedUsers entry names a user in the connected tenant (object id, user principal name or mail address).
    .DESCRIPTION
        One GET users/{entry}, and for an entry with an @ that is not a user principal name, one
        GET users?$filter=mail eq '<entry>'. An entry that matches nobody protects nobody, so a
        plan built from the policy carries a warning that names it. Any failure other than a
        404 is thrown.
    .EXAMPLE
        Test-TenureProtectedEntry -Entry 'breakglass@example.com'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Entry)

    $text = $Entry.Trim()
    if ($null -ne (Get-TenureUserIdentity -Identity $text)) { return $true }
    if (-not $text.Contains('@')) { return $false }
    $filter = "mail eq '$(ConvertTo-TenureODataString -Value $text)'"
    $found = @(Invoke-TenureGraph -Method GET -Uri ('users?$filter=' + [uri]::EscapeDataString($filter) + '&$select=id') -All)
    $found.Count -gt 0
}

function ConvertTo-TenureGroupInfo {
    # Graph group object -> the resolver's hashtable. Private to this file.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][object]$Group)

    $types = @()
    if ($Group.PSObject.Properties['groupTypes'] -and $null -ne $Group.groupTypes) { $types = @($Group.groupTypes) }
    $mailEnabled = [bool](Get-TenureGraphProperty -InputObject $Group -Name 'mailEnabled' -Default $false)
    $isUnified = $types -contains 'Unified'
    @{
        Id                = Get-TenureGraphProperty -InputObject $Group -Name 'id'
        DisplayName       = Get-TenureGraphProperty -InputObject $Group -Name 'displayName'
        Mail              = Get-TenureGraphProperty -InputObject $Group -Name 'mail'
        GroupTypes        = $types
        MembershipRule    = Get-TenureGraphProperty -InputObject $Group -Name 'membershipRule'
        MailEnabled       = $mailEnabled
        SecurityEnabled   = [bool](Get-TenureGraphProperty -InputObject $Group -Name 'securityEnabled' -Default $false)
        IsDynamic         = ($types -contains 'DynamicMembership')
        IsUnified         = $isUnified
        # Distribution lists and mail-enabled security groups: Graph cannot change their membership.
        IsExchangeManaged = ($mailEnabled -and -not $isUnified)
        # A member of a role-assignable group holds the roles assigned to the group.
        IsAssignableToRole = ([bool](Get-TenureGraphProperty -InputObject $Group -Name 'isAssignableToRole' -Default $false))
    }
}

function Resolve-TenureGroup {
    <#
    .SYNOPSIS
        Looks up a group by display name, mail address or object id.
    .DESCRIPTION
        Throws Tenure.Group.NotFound when nothing matches and Tenure.Group.Ambiguous (listing
        ids and display names) when more than one group matches. Never guesses.
        Keys: Id, DisplayName, Mail, GroupTypes, MembershipRule, MailEnabled, SecurityEnabled,
        IsDynamic, IsUnified, IsExchangeManaged, IsAssignableToRole.
    .EXAMPLE
        Resolve-TenureGroup -Identity 'sales@example.com'
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Identity)

    $select = 'id,displayName,mail,groupTypes,membershipRule,mailEnabled,securityEnabled,isAssignableToRole'
    $notFound = {
        param($inner)
        $arguments = @{
            Id       = 'Tenure.Group.NotFound'
            Message  = "Group '$Identity' was not found. Use its display name, mail address or object id."
            Category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
            Data     = @{ Identity = $Identity }
        }
        if ($inner) { $arguments['Inner'] = $inner }
        New-TenureError @arguments
    }

    if ($Identity -cmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        try {
            $group = Invoke-TenureGraph -Method GET -Uri ('groups/' + (ConvertTo-TenureUriSegment -Value $Identity) + '?$select=' + $select)
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') { throw (& $notFound $_) }
            throw
        }
        return (ConvertTo-TenureGroupInfo -Group $group)
    }

    $literal = ConvertTo-TenureODataString -Value $Identity
    $filter = "mail eq '$literal' or displayName eq '$literal'"
    $candidates = @(Invoke-TenureGraph -Method GET -Uri ('groups?$filter=' + [uri]::EscapeDataString($filter) + '&$select=' + $select) -All)
    if ($candidates.Count -eq 0) { throw (& $notFound $null) }
    if ($candidates.Count -gt 1) {
        $listing = ($candidates | ForEach-Object { "$(Get-TenureGraphProperty -InputObject $_ -Name 'id') ($(Get-TenureGraphProperty -InputObject $_ -Name 'displayName'))" }) -join ', '
        throw (New-TenureError -Id 'Tenure.Group.Ambiguous' -Message "Group '$Identity' matches $($candidates.Count) groups: $listing. Use the object id to pick one." -Category InvalidArgument -Data @{ Identity = $Identity; Count = $candidates.Count })
    }
    ConvertTo-TenureGroupInfo -Group $candidates[0]
}

function Get-TenureSubscribedSku {
    <#
    .SYNOPSIS
        Lists the tenant's subscribed SKUs as @{ SkuId; SkuPartNumber; Available }.
    .DESCRIPTION
        Available is enabled minus consumed units, never below 0. Builders use this to map
        SKU ids back to part numbers. Wrap the call in @(...).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    foreach ($sku in @(Invoke-TenureGraph -Method GET -Uri 'subscribedSkus' -All)) {
        $prepaid = Get-TenureGraphProperty -InputObject $sku -Name 'prepaidUnits'
        $enabled = [int](Get-TenureGraphProperty -InputObject $prepaid -Name 'enabled' -Default 0)
        $consumed = [int](Get-TenureGraphProperty -InputObject $sku -Name 'consumedUnits' -Default 0)
        @{
            SkuId         = Get-TenureGraphProperty -InputObject $sku -Name 'skuId'
            SkuPartNumber = Get-TenureGraphProperty -InputObject $sku -Name 'skuPartNumber'
            Available     = [math]::Max(0, $enabled - $consumed)
        }
    }
}

function Get-TenureUserExchangePlan {
    <#
    .SYNOPSIS
        Lists the service plans that give a user an Exchange Online mailbox, as @{ SkuId; SkuPartNumber; ServicePlanName }.
    .DESCRIPTION
        Reads users/{id}/licenseDetails (all pages), which covers licenses assigned directly
        and through groups. A service plan grants a mailbox when its name starts with
        EXCHANGE_S_ (EXCHANGE_S_ENTERPRISE, EXCHANGE_S_STANDARD, EXCHANGE_S_DESKLESS and so
        on), it is not EXCHANGE_S_FOUNDATION (which comes with many licenses and no
        mailbox), and its provisioningStatus is not Disabled. Anything whose shape is not
        known counts, so the answer fails closed: a license whose service plans are not
        reported ('(service plans not reported)') and a service plan without a name
        ('(service plan name not reported)'). The offboard builder treats an empty answer as
        proof that the user has no mailbox, and a non-empty one as a mailbox that removing
        the licenses would delete. The entries are emitted one by one, ordered by part number
        and plan name; wrap the call in @(...).
    .EXAMPLE
        @(Get-TenureUserExchangePlan -UserId $user.Id).Count -eq 0
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$UserId)

    $found = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($detail in @(Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $UserId) + '/licenseDetails') -All)) {
        $skuId = ([string](Get-TenureGraphProperty -InputObject $detail -Name 'skuId')).ToLowerInvariant()
        $part = [string](Get-TenureGraphProperty -InputObject $detail -Name 'skuPartNumber')
        if ([string]::IsNullOrWhiteSpace($part)) { $part = $skuId }
        $plans = @(Get-TenureGraphProperty -InputObject $detail -Name 'servicePlans' | Where-Object { $null -ne $_ })
        if ($plans.Count -eq 0) {
            $found.Add(@{ SkuId = $skuId; SkuPartNumber = $part; ServicePlanName = '(service plans not reported)' })
            continue
        }
        foreach ($plan in $plans) {
            $name = ([string](Get-TenureGraphProperty -InputObject $plan -Name 'servicePlanName')).Trim()
            if ($name.Length -eq 0) {
                $found.Add(@{ SkuId = $skuId; SkuPartNumber = $part; ServicePlanName = '(service plan name not reported)' })
                continue
            }
            if (-not (Test-TenureMailboxServicePlan -Name $name -ProvisioningStatus ([string](Get-TenureGraphProperty -InputObject $plan -Name 'provisioningStatus')))) { continue }
            $found.Add(@{ SkuId = $skuId; SkuPartNumber = $part; ServicePlanName = $name })
        }
    }
    $found.Sort([System.Comparison[hashtable]] {
            param($left, $right)
            $order = [string]::CompareOrdinal([string]$left.SkuPartNumber, [string]$right.SkuPartNumber)
            if ($order -eq 0) { $order = [string]::CompareOrdinal([string]$left.ServicePlanName, [string]$right.ServicePlanName) }
            $order
        })
    $found.ToArray()
}

function Test-TenureMailboxServicePlan {
    <#
    .SYNOPSIS
        True when a service plan gives an Exchange Online mailbox: its name starts with EXCHANGE_S_, it is not
        EXCHANGE_S_FOUNDATION, and its provisioning status is not Disabled.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [AllowNull()][AllowEmptyString()][string]$ProvisioningStatus
    )

    $text = $Name.Trim()
    if (-not $text.StartsWith('EXCHANGE_S_', [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($text -ieq 'EXCHANGE_S_FOUNDATION') { return $false }
    ([string]$ProvisioningStatus).Trim() -ine 'Disabled'
}

function Get-TenureMailboxSku {
    <#
    .SYNOPSIS
        Every subscribed SKU as @{ SkuId; SkuPartNumber; Enabled; Consumed; Available; MailboxPlanIds }.
    .DESCRIPTION
        Reads subscribedSkus (all pages). MailboxPlanIds are the ids (lower case) of the SKU's
        service plans that give an Exchange Online mailbox (Test-TenureMailboxServicePlan). An
        assignment of the SKU gives a mailbox when one of them is not in the assignment's
        disabledPlans. A SKU whose service plans are not reported has none, so it never counts
        as keeping a mailbox. Enabled is prepaidUnits.enabled, Consumed is consumedUnits, and
        Available their difference, never below 0. Wrap the call in @(...).
    .EXAMPLE
        @(Get-TenureMailboxSku) | Where-Object { $_.MailboxPlanIds.Count -gt 0 }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    foreach ($sku in @(Invoke-TenureGraph -Method GET -Uri 'subscribedSkus' -All)) {
        $plans = [System.Collections.Generic.List[string]]::new()
        foreach ($plan in @(Get-TenureGraphProperty -InputObject $sku -Name 'servicePlans' | Where-Object { $null -ne $_ })) {
            if (Test-TenureMailboxServicePlan -Name ([string](Get-TenureGraphProperty -InputObject $plan -Name 'servicePlanName')) -ProvisioningStatus ([string](Get-TenureGraphProperty -InputObject $plan -Name 'provisioningStatus'))) {
                $planId = ([string](Get-TenureGraphProperty -InputObject $plan -Name 'servicePlanId')).ToLowerInvariant()
                if ($planId) { $plans.Add($planId) }
            }
        }
        $enabled = [int](Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $sku -Name 'prepaidUnits') -Name 'enabled' -Default 0)
        $consumed = [int](Get-TenureGraphProperty -InputObject $sku -Name 'consumedUnits' -Default 0)
        @{
            SkuId          = ([string](Get-TenureGraphProperty -InputObject $sku -Name 'skuId')).ToLowerInvariant()
            SkuPartNumber  = [string](Get-TenureGraphProperty -InputObject $sku -Name 'skuPartNumber')
            Enabled        = $enabled
            Consumed       = $consumed
            Available      = [math]::Max(0, $enabled - $consumed)
            MailboxPlanIds = [string[]]$plans.ToArray()
        }
    }
}

function Resolve-TenureSku {
    <#
    .SYNOPSIS
        Maps a SKU part number (case-insensitive) to @{ SkuId; SkuPartNumber; Available }.
    .DESCRIPTION
        Throws Tenure.Sku.NotFound, listing the tenant's part numbers, when there is no match.
    .EXAMPLE
        Resolve-TenureSku -PartNumber 'SPE_E3'
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PartNumber)

    $skus = @(Get-TenureSubscribedSku)
    $found = @($skus | Where-Object { $_.SkuPartNumber -ieq $PartNumber }) | Select-Object -First 1
    if (-not $found) {
        $names = (@($skus | ForEach-Object { $_.SkuPartNumber } | Sort-Object) -join ', ')
        throw (New-TenureError -Id 'Tenure.Sku.NotFound' -Message "SKU '$PartNumber' is not subscribed in this tenant. Subscribed part numbers: $names." -Category ObjectNotFound -Data @{ PartNumber = $PartNumber })
    }
    $found
}

function Get-TenureUserMembership {
    <#
    .SYNOPSIS
        Lists the groups and directory roles a user is a direct member of.
    .DESCRIPTION
        Reads users/{id}/memberOf (all pages) and splits the answer by '@odata.type'.
        Groups carry the same flags as Resolve-TenureGroup (IsDynamic, IsUnified,
        IsExchangeManaged); roles are the activated directory roles the user holds as a
        direct, active member. Both lists are ordered by display name (ordinal, ignoring
        case) and then id, so a plan built from them does not depend on the order Graph
        answers in. Objects of any other type (administrative units) are ignored.
        Returns one hashtable: Groups (list of @{ Id; DisplayName; Mail; GroupTypes;
        MailEnabled; SecurityEnabled; IsDynamic; IsUnified; IsExchangeManaged; IsAssignableToRole }) and
        Roles (list of @{ Id; DisplayName; RoleTemplateId }).
    .EXAMPLE
        (Get-TenureUserMembership -UserId $user.Id).Groups
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$UserId)

    $select = 'id,displayName,mail,groupTypes,mailEnabled,securityEnabled,isAssignableToRole,roleTemplateId'
    $items = @(Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $UserId) + '/memberOf?$select=' + $select) -All)

    $groups = [System.Collections.Generic.List[hashtable]]::new()
    $roles = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($item in $items) {
        $type = [string](Get-TenureGraphProperty -InputObject $item -Name '@odata.type')
        if ($type -ieq '#microsoft.graph.group') {
            $info = ConvertTo-TenureGroupInfo -Group $item
            $groups.Add(@{
                    Id                = [string]$info.Id
                    DisplayName       = [string]$info.DisplayName
                    Mail              = $info.Mail
                    GroupTypes        = $info.GroupTypes
                    MailEnabled       = $info.MailEnabled
                    SecurityEnabled   = $info.SecurityEnabled
                    IsDynamic         = $info.IsDynamic
                    IsUnified         = $info.IsUnified
                    IsExchangeManaged = $info.IsExchangeManaged
                    IsAssignableToRole = $info.IsAssignableToRole
                })
        } elseif ($type -ieq '#microsoft.graph.directoryRole') {
            $roles.Add(@{
                    Id             = [string](Get-TenureGraphProperty -InputObject $item -Name 'id')
                    DisplayName    = [string](Get-TenureGraphProperty -InputObject $item -Name 'displayName')
                    RoleTemplateId = Get-TenureGraphProperty -InputObject $item -Name 'roleTemplateId'
                })
        }
    }

    $byName = [System.Comparison[hashtable]] {
        param($left, $right)
        $order = [string]::Compare([string]$left.DisplayName, [string]$right.DisplayName, [System.StringComparison]::OrdinalIgnoreCase)
        if ($order -eq 0) { $order = [string]::CompareOrdinal([string]$left.Id, [string]$right.Id) }
        $order
    }
    $groups.Sort($byName)
    $roles.Sort($byName)
    @{ Groups = $groups.ToArray(); Roles = $roles.ToArray() }
}

function Get-TenureUserManagedDevice {
    <#
    .SYNOPSIS
        Lists the Intune managed devices whose primary user is the given user.
    .DESCRIPTION
        Reads users/{id}/managedDevices (all pages). Each device is @{ Id; DeviceName;
        Ownership; OperatingSystem }. Ownership is 'company', 'personal' or 'unknown'
        (lower case; anything Graph does not call company or personal is unknown, and
        unknown is never treated as company-owned). Devices are ordered by name, then id.
        The devices are emitted one by one; wrap the call in @(...). A user Graph reports as
        having no managed-device list (404) has no devices.
    .EXAMPLE
        @(Get-TenureUserManagedDevice -UserId $user.Id) | Where-Object Ownership -eq 'company'
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$UserId)

    $select = 'id,deviceName,managedDeviceOwnerType,operatingSystem'
    $raw = @()
    try {
        $raw = @(Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $UserId) + '/managedDevices?$select=' + $select) -All)
    } catch {
        if ((Get-TenureErrorId -ErrorRecord $_) -cne 'Tenure.Graph.NotFound') { throw }
    }

    $devices = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($device in $raw) {
        $ownerType = ([string](Get-TenureGraphProperty -InputObject $device -Name 'managedDeviceOwnerType')).Trim().ToLowerInvariant()
        $ownership = 'unknown'
        if ($ownerType -ceq 'company' -or $ownerType -ceq 'personal') { $ownership = $ownerType }
        $devices.Add(@{
                Id              = [string](Get-TenureGraphProperty -InputObject $device -Name 'id')
                DeviceName      = [string](Get-TenureGraphProperty -InputObject $device -Name 'deviceName')
                Ownership       = $ownership
                OperatingSystem = Get-TenureGraphProperty -InputObject $device -Name 'operatingSystem'
            })
    }
    $devices.Sort([System.Comparison[hashtable]] {
            param($left, $right)
            $order = [string]::Compare([string]$left.DeviceName, [string]$right.DeviceName, [System.StringComparison]::OrdinalIgnoreCase)
            if ($order -eq 0) { $order = [string]::CompareOrdinal([string]$left.Id, [string]$right.Id) }
            $order
        })
    $devices.ToArray()
}

function Get-TenureGroupLicense {
    <#
    .SYNOPSIS
        Lists the SKU ids a group assigns to its members (group-based licensing), lower case; with -Detailed, each
        assignment as @{ SkuId; DisabledPlans }.
    .DESCRIPTION
        Reads groups/{id}?$select=id,assignedLicenses once per group and keeps the answer, with
        each assignment's disabledPlans, in -Cache (a hashtable the caller holds for one plan),
        so a plan reads each group once. Removing a user from a group that carries a license
        removes that license; a service plan the group's assignment lists in disabledPlans is
        off for the members it gives the license to. A group Graph does not find is a
        Tenure.Graph.NotFound error from the seam. The results are emitted one by one, ordered by
        SKU id; wrap the call in @(...).
    .EXAMPLE
        @(Get-TenureGroupLicense -GroupId $group.Id -Cache $cache).Count -gt 0
    .EXAMPLE
        @(Get-TenureGroupLicense -GroupId $group.Id -Detailed) | Where-Object { $_.DisabledPlans -notcontains $planId }
    #>
    [CmdletBinding()]
    [OutputType([string], [hashtable])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$GroupId,
        [AllowNull()][hashtable]$Cache,
        [switch]$Detailed
    )

    $key = $GroupId.ToLowerInvariant()
    $assignments = $null
    if ($null -ne $Cache -and $Cache.ContainsKey($key)) {
        $assignments = $Cache[$key]
    } else {
        $group = Invoke-TenureGraph -Method GET -Uri ('groups/' + (ConvertTo-TenureUriSegment -Value $GroupId) + '?$select=id,assignedLicenses')
        $bySku = [System.Collections.Generic.SortedDictionary[string, hashtable]]::new([System.StringComparer]::Ordinal)
        foreach ($entry in @(Get-TenureGraphProperty -InputObject $group -Name 'assignedLicenses' | Where-Object { $null -ne $_ })) {
            $sku = ([string](Get-TenureGraphProperty -InputObject $entry -Name 'skuId')).ToLowerInvariant()
            if (-not $sku -or $bySku.ContainsKey($sku)) { continue }
            $disabled = [string[]]@(Get-TenureGraphProperty -InputObject $entry -Name 'disabledPlans' | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
            $bySku[$sku] = @{ SkuId = $sku; DisabledPlans = $disabled }
        }
        $assignments = [hashtable[]]@($bySku.Values)
        if ($null -ne $Cache) { $Cache[$key] = $assignments }
    }
    foreach ($assignment in @($assignments)) {
        if ($Detailed) { @{ SkuId = $assignment.SkuId; DisabledPlans = [string[]]@($assignment.DisabledPlans) } } else { $assignment.SkuId }
    }
}

function Get-TenureGroupOwner {
    <#
    .SYNOPSIS
        Lists the owners of a group as @{ Id; UserPrincipalName }.
    .DESCRIPTION
        Reads groups/{id}/owners (all pages). UserPrincipalName is $null for an owner that
        is not a user (a service principal). Owners are ordered by id. They are emitted one
        by one; wrap the call in @(...). A group that does not exist is a
        Tenure.Graph.NotFound error from the seam.
    .EXAMPLE
        @(Get-TenureGroupOwner -GroupId $group.Id).Count
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$GroupId)

    $owners = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($owner in @(Invoke-TenureGraph -Method GET -Uri ('groups/' + (ConvertTo-TenureUriSegment -Value $GroupId) + '/owners?$select=id,userPrincipalName') -All)) {
        $owners.Add(@{
                Id                = [string](Get-TenureGraphProperty -InputObject $owner -Name 'id')
                UserPrincipalName = Get-TenureGraphProperty -InputObject $owner -Name 'userPrincipalName'
            })
    }
    $owners.Sort([System.Comparison[hashtable]] { param($left, $right) [string]::CompareOrdinal([string]$left.Id, [string]$right.Id) })
    $owners.ToArray()
}
