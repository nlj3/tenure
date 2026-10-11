# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureSkuIdList {
    # Lower-case, de-duplicated, ordinally sorted SKU ids. Ordinal on purpose: the order feeds the plan fingerprint
    # and must not depend on the machine's culture. Emits the ids unrolled; wrap the call in @(...).
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Id)

    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($value in @($Id)) {
        $text = ([string]$value).ToLowerInvariant()
        if ($text -and -not $list.Contains($text)) { $list.Add($text) }
    }
    $list.Sort([System.StringComparer]::Ordinal)
    $list.ToArray()
}

function Get-TenureLicenseRequest {
    # Validates Desired and returns it as @{ Add; Remove }, each a lower-case, de-duplicated, sorted list of SKU ids.
    # Desired is a delta, @{ add = <sku ids>; remove = <sku ids> }, never a complete list: a plan can then never
    # remove a license it did not show, even when a license is assigned between planning and applying. Both keys
    # are required (an empty list means none) and nothing else is allowed, so a typo cannot pass as "no change".
    # A part number such as SPE_E3 is refused: the plan builders resolve part numbers to SKU ids.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $invalid = {
        param([string]$Message, [string]$Key)
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message $Message -Category InvalidArgument -Data @{ Provider = 'User.Licenses'; Key = $Key })
    }
    $shape = 'User.Licenses needs Desired = @{ add = <SKU ids>; remove = <SKU ids> } (use an empty list for none).'
    if ($null -eq $Desired -or -not ($Desired -is [System.Collections.IDictionary] -or $Desired -is [System.Management.Automation.PSCustomObject])) {
        & $invalid $shape ''
    }
    $wanted = ConvertTo-TenureTable -InputObject $Desired
    foreach ($key in $wanted.Keys) {
        if ($key -notin 'add', 'remove') {
            & $invalid "User.Licenses does not take '$key'. Allowed: add, remove." ([string]$key)
        }
    }
    $lists = @{}
    foreach ($name in 'add', 'remove') {
        if (-not $wanted.ContainsKey($name)) { & $invalid "$shape Desired.$name is missing." $name }
        $value = $wanted[$name]
        if ($null -eq $value -or $value -is [string] -or $value -is [System.Collections.IDictionary] -or $value -isnot [System.Collections.IList]) {
            & $invalid "Desired.$name of User.Licenses must be a list of SKU ids (use an empty list for none)." $name
        }
        foreach ($item in $value) {
            $text = if ($item -is [string] -or $item -is [guid]) { [string]$item } else { '' }
            if ($text -cnotmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                & $invalid "Desired.$name of User.Licenses holds '$item', which is not a SKU id. SKU ids are GUIDs; resolve part numbers such as SPE_E3 first." $name
            }
        }
        $lists[$name] = [string[]]@(ConvertTo-TenureSkuIdList -Id $value)
    }
    $both = @($lists['add'] | Where-Object { $_ -cin $lists['remove'] })
    if ($both.Count -gt 0) {
        & $invalid "User.Licenses cannot both add and remove SKU id '$($both[0])'." 'add'
    }
    @{ Add = $lists['add']; Remove = $lists['remove'] }
}

function Get-TenureLicenseDelta {
    # What a validated request still has to change on the user's DIRECT assignments: the adds that are not direct
    # yet, and the removes that still are. A remove of a license that is only inherited from a group is nothing to
    # do here (it goes when the group membership or the group's license goes). Ids not in the request are never
    # touched, whatever Current holds.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Current, [Parameter(Mandatory)][hashtable]$Request)

    $have = @(ConvertTo-TenureSkuIdList -Id (ConvertTo-TenureTable -InputObject $Current)['skuIds'])
    @{
        Add    = [string[]]@($Request.Add | Where-Object { $_ -cnotin $have })
        Remove = [string[]]@($Request.Remove | Where-Object { $_ -cin $have })
    }
}

function Get-TenureUserLicenseState {
    # Everything Graph says about a user's licenses: the SKUs assigned directly (skuIds), the service plans the
    # direct assignment of each switches off (directDisabledPlans, lower-case ids), the SKUs inherited from groups
    # (inheritedSkuIds), which group each comes from (inheritedFrom, sorted 'sku|group' pairs) and the usage
    # location. The provider's snapshot keeps only skuIds; the plan builders and Set read the rest from here.
    # A 404 is Tenure.Provider.TargetNotFound.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$UserId)

    try {
        $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $UserId) + '?$select=id,usageLocation,assignedLicenses,licenseAssignmentStates')
    } catch {
        if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
            throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$UserId' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.Licenses'; Identity = $UserId } -Inner $_)
        }
        throw
    }
    $assigned = @()
    if ($user.PSObject.Properties['assignedLicenses'] -and $null -ne $user.assignedLicenses) {
        $assigned = @($user.assignedLicenses | ForEach-Object { ([string](Get-TenureGraphProperty -InputObject $_ -Name 'skuId')).ToLowerInvariant() })
    }
    $states = @()
    if ($user.PSObject.Properties['licenseAssignmentStates'] -and $null -ne $user.licenseAssignmentStates) { $states = @($user.licenseAssignmentStates) }

    # A SKU is direct when it has no state entry at all or at least one entry not assigned by a group;
    # it is inherited when at least one entry names a group. It can be both.
    $direct = [System.Collections.Generic.List[string]]::new()
    foreach ($sku in $assigned) {
        $entries = @($states | Where-Object { ([string](Get-TenureGraphProperty -InputObject $_ -Name 'skuId')).ToLowerInvariant() -ceq $sku })
        $viaUser = @($entries | Where-Object { -not (Get-TenureGraphProperty -InputObject $_ -Name 'assignedByGroup') })
        if ($entries.Count -eq 0 -or $viaUser.Count -gt 0) { $direct.Add($sku) }
    }
    $inherited = @($states | Where-Object { Get-TenureGraphProperty -InputObject $_ -Name 'assignedByGroup' } |
            ForEach-Object { ([string](Get-TenureGraphProperty -InputObject $_ -Name 'skuId')).ToLowerInvariant() })
    # Which group each inherited SKU comes from, so a plan can name it without asking Graph again.
    $pairs = [System.Collections.Generic.List[string]]::new()
    foreach ($state in $states) {
        $groupId = [string](Get-TenureGraphProperty -InputObject $state -Name 'assignedByGroup')
        if (-not $groupId) { continue }
        $pair = ([string](Get-TenureGraphProperty -InputObject $state -Name 'skuId')).ToLowerInvariant() + '|' + $groupId.ToLowerInvariant()
        if (-not $pairs.Contains($pair)) { $pairs.Add($pair) }
    }
    $pairs.Sort([System.StringComparer]::Ordinal)
    $inheritedFrom = @($pairs | ForEach-Object { $parts = $_.Split('|'); [pscustomobject]@{ skuId = $parts[0]; groupId = $parts[1] } })
    # The direct assignment's own state entry names its disabled plans when Graph reports them there; otherwise the
    # assignedLicenses entry does.
    $directDisabled = @{}
    foreach ($sku in $direct) {
        $entry = @($states | Where-Object { ([string](Get-TenureGraphProperty -InputObject $_ -Name 'skuId')).ToLowerInvariant() -ceq $sku -and -not (Get-TenureGraphProperty -InputObject $_ -Name 'assignedByGroup') } | Where-Object { $null -ne (Get-TenureGraphProperty -InputObject $_ -Name 'disabledPlans') })
        $source = if ($entry.Count -gt 0) { $entry[0] } else { @(Get-TenureGraphProperty -InputObject $user -Name 'assignedLicenses' | Where-Object { $null -ne $_ -and ([string](Get-TenureGraphProperty -InputObject $_ -Name 'skuId')).ToLowerInvariant() -ceq $sku })[0] }
        $directDisabled[$sku] = [string[]]@(Get-TenureGraphProperty -InputObject $source -Name 'disabledPlans' | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    }
    [pscustomobject]@{
        skuIds              = [string[]]@(ConvertTo-TenureSkuIdList -Id $direct)
        directDisabledPlans = $directDisabled
        inheritedSkuIds     = [string[]]@(ConvertTo-TenureSkuIdList -Id $inherited)
        inheritedFrom       = $inheritedFrom
        usageLocation       = Get-TenureGraphProperty -InputObject $user -Name 'usageLocation'
    }
}

$null = Register-TenureProvider -Definition @{
    Name        = 'User.Licenses'
    Kind        = 'State'
    Backend     = 'Graph'
    Scopes      = @('User.ReadWrite.All', 'Organization.Read.All')
    Risk        = 'Medium'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Update', 'NoOp')
    Description = 'Adds the SKU ids in Desired.add to the user''s DIRECT license assignments and removes the ones in Desired.remove. Other licenses, and licenses inherited from groups, are never touched.'

    # The snapshot is the SKUs assigned directly, the only ones this provider changes, lower case and ordinally
    # sorted (the order feeds the fingerprint). Inherited licenses and the usage location are left out: an earlier
    # step of the same plan (a group removal) moves the inherited ones, which must not read as drift here.
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Licenses'
        $state = Get-TenureUserLicenseState -UserId $id
        [pscustomobject]@{ skuIds = [string[]]@($state.skuIds) }
    }

    Test        = {
        param($Current, $Desired)
        $request = Get-TenureLicenseRequest -Desired $Desired
        if ($null -eq $Current) { return $false }
        $delta = Get-TenureLicenseDelta -Current $Current -Request $request
        return (($delta.Add.Count -eq 0) -and ($delta.Remove.Count -eq 0))
    }

    # Desired is checked before anything is read or written. Then fresh state is read: what to send comes from
    # what Graph holds now, not from a plan-time snapshot, and is always a subset of the ids the plan listed.
    Set         = {
        param($Target, $Desired, $Current, $Context)
        $request = Get-TenureLicenseRequest -Desired $Desired
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Licenses'
        $provider = Get-TenureProviderDefinition -Name 'User.Licenses'
        $fresh = Get-TenureUserLicenseState -UserId $id
        $delta = Get-TenureLicenseDelta -Current $fresh -Request $request
        if ($delta.Add.Count -gt 0 -and [string]::IsNullOrWhiteSpace([string]$fresh.usageLocation)) {
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message "Cannot assign licenses to '$id': the user has no usage location. Set usageLocation first." -Category InvalidOperation -Data @{ Provider = 'User.Licenses'; Identity = $id })
        }
        if ($delta.Add.Count -gt 0 -or $delta.Remove.Count -gt 0) {
            $body = @{
                addLicenses    = @($delta.Add | ForEach-Object { @{ skuId = $_; disabledPlans = @() } })
                removeLicenses = @($delta.Remove)
            }
            Invoke-TenureGraph -Method POST -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '/assignLicense') -Body $body | Out-Null
        }
        & $provider.Get $Target $Context
    }

    # With no Current (the user is created earlier in the plan) the whole requested delta is listed. A remove of a
    # license that is not assigned directly (inherited from a group, or already gone) is named as left alone.
    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $request = Get-TenureLicenseRequest -Desired $Desired
        $delta = if ($null -eq $Current) { $request } else { Get-TenureLicenseDelta -Current $Current -Request $request }
        $changes = @($delta.Add | ForEach-Object { "+$_" }) + @($delta.Remove | ForEach-Object { "-$_" })
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        $line = if ($changes.Count -eq 0) { "$Action licenses of ${name}: no change" } else { "$Action licenses of ${name}: $($changes -join ' ')" }
        if ($null -ne $Current) {
            $notDirect = @($request.Remove | Where-Object { $_ -cnotin $delta.Remove })
            if ($notDirect.Count -gt 0) { $line += '; not assigned directly, left alone: ' + ($notDirect -join ', ') }
        }
        $line
    }
}
