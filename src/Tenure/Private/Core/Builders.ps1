# Shared helpers for the three plan builders (New-TenureOnboardPlan, New-TenureRoleChangePlan,
# New-TenureOffboardPlan). Builders compose steps: tenant state is read only through provider
# snapshots (New-TenureStep) and the lookup helpers in Resolve.ps1, never through the seams.

function Get-TenureStepContext {
    <#
    .SYNOPSIS
        The Context hashtable every builder hands to New-TenureStep (docs/SPEC.md section 2.2).
    .DESCRIPTION
        ExchangeAddresses is a plan-time table the Exchange providers fill with the address
        of each mailbox they read by Entra id, so the steps of one plan read it once (see
        Get-TenureExchangeAddressCache). GroupLicenses caches each group's license
        assignments (Get-TenureGroupLicense). MemberOf holds the ids users/{id}/memberOf
        listed, once a builder has read them, so the membership providers can refuse a
        member route that contradicts it. All three live only as long as this context.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()][object]$Policy,
        [Parameter(Mandatory)][hashtable]$Subject
    )

    @{ Policy = $Policy; Subject = $Subject; Session = $script:Session; Secrets = @{}; Mode = 'Plan'; ExchangeAddresses = @{}; GroupLicenses = @{}; MemberOf = [string[]]@() }
}

function Test-TenureBuilderExchange {
    <#
    .SYNOPSIS
        True when the current session has an Exchange Online connection.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    ($null -ne $script:Session) -and [bool]$script:Session.PSObject.Properties['Exchange'] -and [bool]$script:Session.Exchange
}

function Get-TenureDistinctName {
    <#
    .SYNOPSIS
        Trimmed, de-duplicated (ignoring case) and sorted (ordinal, ignoring case) copy of a list of names.
    .DESCRIPTION
        Plans must not depend on the order names were typed or listed in a policy, so every
        list a builder acts on goes through here. Blank entries are dropped. The strings are
        emitted one by one; wrap the call in @(...).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$Value)

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Value)) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        $text = $item.Trim()
        if ($seen.Add($text)) { $list.Add($text) }
    }
    $list.Sort([System.StringComparer]::OrdinalIgnoreCase)
    $list.ToArray()
}

function Resolve-TenureBuilderGroup {
    <#
    .SYNOPSIS
        Resolves group names, mail addresses or ids with Resolve-TenureGroup: distinct by id, ordered by display name then id.
    .DESCRIPTION
        An ambiguous or unknown group is the resolver's error (Tenure.Group.Ambiguous,
        Tenure.Group.NotFound), because a plan never guesses. With -SkipMissing an unknown
        name is dropped with an entry in -Warning instead; an ambiguous one still throws.
        The groups are emitted one by one; wrap the call in @(...).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$Identity,
        [AllowNull()][System.Collections.Generic.List[string]]$Warning,
        [string]$Description = 'group',
        [switch]$SkipMissing
    )

    $byId = [System.Collections.Generic.Dictionary[string, hashtable]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @(Get-TenureDistinctName -Value $Identity)) {
        $group = $null
        try {
            $group = Resolve-TenureGroup -Identity $name
        } catch {
            if ($SkipMissing -and (Get-TenureErrorId -ErrorRecord $_) -ceq 'Tenure.Group.NotFound') {
                if ($null -ne $Warning) { $Warning.Add("The $Description '$name' does not match any group, so it was ignored.") }
                continue
            }
            throw
        }
        if (-not $byId.ContainsKey([string]$group.Id)) { $byId[[string]$group.Id] = $group }
    }
    $groups = [System.Collections.Generic.List[hashtable]]::new($byId.Values)
    $groups.Sort([System.Comparison[hashtable]] {
            param($left, $right)
            $order = [string]::Compare([string]$left.DisplayName, [string]$right.DisplayName, [System.StringComparison]::OrdinalIgnoreCase)
            if ($order -eq 0) { $order = [string]::CompareOrdinal(([string]$left.Id).ToLowerInvariant(), ([string]$right.Id).ToLowerInvariant()) }
            $order
        })
    $groups.ToArray()
}

function Resolve-TenureBuilderSku {
    <#
    .SYNOPSIS
        Resolves SKU part numbers with Resolve-TenureSku: distinct by id, ordered by lower-case id.
    .DESCRIPTION
        Each result is @{ SkuId (lower case); SkuPartNumber; Available }. An unsubscribed part
        number is Tenure.Sku.NotFound; with -SkipMissing it is dropped with an entry in
        -Warning instead. The SKUs are emitted one by one; wrap the call in @(...).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$PartNumber,
        [AllowNull()][System.Collections.Generic.List[string]]$Warning,
        [string]$Description = 'license',
        [switch]$SkipMissing
    )

    $byId = [System.Collections.Generic.Dictionary[string, hashtable]]::new([System.StringComparer]::Ordinal)
    foreach ($name in @(Get-TenureDistinctName -Value $PartNumber)) {
        $sku = $null
        try {
            $sku = Resolve-TenureSku -PartNumber $name
        } catch {
            if ($SkipMissing -and (Get-TenureErrorId -ErrorRecord $_) -ceq 'Tenure.Sku.NotFound') {
                if ($null -ne $Warning) { $Warning.Add("The $Description '$name' is not a subscribed SKU in this tenant, so it was ignored.") }
                continue
            }
            throw
        }
        $id = ([string]$sku.SkuId).ToLowerInvariant()
        if (-not $byId.ContainsKey($id)) {
            $byId[$id] = @{ SkuId = $id; SkuPartNumber = [string]$sku.SkuPartNumber; Available = [int]$sku.Available }
        }
    }
    $ids = [string[]]@($byId.Keys)
    [array]::Sort($ids, [System.StringComparer]::Ordinal)
    foreach ($id in $ids) { $byId[$id] }
}

function Get-TenureGroupStepBlocker {
    <#
    .SYNOPSIS
        Returns the warning text when a membership step for the group cannot be built, otherwise $null.
    .DESCRIPTION
        Three reasons: the group is managed in Exchange Online and Exchange is not connected,
        the step would ADD a member to a group with dynamic membership (its rule decides, so
        there is nothing to add by hand), or the step would ADD a member to a role-assignable
        group (its members hold directory roles, and Tenure never grants one). Removing a member
        from a dynamic or role-assignable group is not blocked.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$Group,
        [Parameter(Mandatory)][bool]$Member
    )

    if ($Group.IsExchangeManaged -and -not (Test-TenureBuilderExchange)) {
        return "Group '$($Group.DisplayName)' is a distribution list or mail-enabled security group managed in Exchange Online, and Exchange is not connected, so its membership step was skipped."
    }
    if ($Member -and $Group.IsDynamic) {
        return "Group '$($Group.DisplayName)' has dynamic membership, cannot add: its rule decides who is a member, so the step was skipped."
    }
    if ($Member -and $Group.ContainsKey('IsAssignableToRole') -and $Group.IsAssignableToRole) {
        return "Group '$($Group.DisplayName)' can be assigned to a directory role, and Tenure never grants roles, including through role-assignable groups, so the add was left out. Add the user by hand if that is intended."
    }
    $null
}

function New-TenureMembershipStep {
    <#
    .SYNOPSIS
        Builds the step that adds a user to, or removes a user from, one group.
    .DESCRIPTION
        Routes by group kind: Exchange-managed groups (distribution lists, mail-enabled
        security groups) use DistributionGroup.Member, everything else Group.Member. The step key is
        'group:<group id>'. With -Placeholder the user does not exist yet: the caller passes UserId
        '{{subjectId}}', the snapshot is taken with the subject named by the placeholder (the
        group, and "not a member"), and the step is an Update. An Exchange-managed group's target
        carries Mail, its primary SMTP address: Exchange names the group by it.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Step')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Reads state through the provider Get and returns an in-memory object; changes no state.')]
    param(
        [Parameter(Mandatory)][hashtable]$Group,
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][bool]$Member,
        [Parameter(Mandatory)][hashtable]$Context,
        [string[]]$DependsOn = @(),
        [string]$Reason,
        [ValidateSet('Low', 'Medium', 'High', 'Destructive')][string]$Risk,
        [switch]$Placeholder
    )

    $target = @{ Kind = 'group'; Id = [string]$Group.Id; Name = [string]$Group.DisplayName }
    if ($Group.IsExchangeManaged) { $target['Mail'] = [string]$Group.Mail }
    $stepContext = $Context
    if ($Placeholder) {
        # The user does not exist yet. The snapshot is still taken, with the subject named by the placeholder, so
        # the step binds the group and records "not a member"; the apply engine fills in the id after the create.
        $stepContext = $Context.Clone()
        $subject = @{}
        foreach ($key in @($Context['Subject'].Keys)) { $subject[$key] = $Context['Subject'][$key] }
        $subject['Id'] = '{{subjectId}}'
        $stepContext['Subject'] = $subject
    }
    $arguments = @{
        Provider  = $(if ($Group.IsExchangeManaged) { 'DistributionGroup.Member' } else { 'Group.Member' })
        Target    = $target
        Desired   = @{ userId = $UserId; member = $Member }
        Context   = $stepContext
        Key       = 'group:' + ([string]$Group.Id).ToLowerInvariant()
        DependsOn = $DependsOn
    }
    if ($Placeholder) { $arguments['Action'] = 'Update' }
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $arguments['Reason'] = $Reason }
    if (-not [string]::IsNullOrWhiteSpace($Risk)) { $arguments['Risk'] = $Risk }
    New-TenureStep @arguments
}

function Get-TenureBuilderInput {
    <#
    .SYNOPSIS
        The Inputs record of a plan: the bound parameters of a builder, in a form that does not depend on how they were typed.
    .DESCRIPTION
        -Policy is replaced by the policy file path, or by 'sha256:<hash>' for a policy that
        was not loaded from a file. List parameters become distinct, sorted copies, and switches
        become booleans. -Replace swaps a value for its resolved form (for example the
        user principal name for an object id). Common parameters are left out. Nothing
        secret is ever a builder parameter, so nothing secret can land here.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Bound,
        [Parameter(Mandatory)][object]$Policy,
        [hashtable]$Replace = @{}
    )

    $common = [string[]]@('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ProgressAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'WhatIf', 'Confirm')
    $inputs = @{}
    foreach ($key in $Bound.Keys) {
        $name = [string]$key
        if ($common -contains $name) { continue }
        $value = $Bound[$key]
        if ($Replace.ContainsKey($name)) {
            $value = $Replace[$name]
        } elseif ($name -ceq 'Policy') {
            $value = if (-not [string]::IsNullOrWhiteSpace([string]$Policy.Path)) { [string]$Policy.Path } else { 'sha256:' + $Policy.Hash }
        } elseif ($value -is [System.Management.Automation.SwitchParameter]) {
            $value = [bool]$value.IsPresent
        } elseif ($value -is [string[]]) {
            $value = [string[]]@(Get-TenureDistinctName -Value $value)
        }
        $inputs[$name] = $value
    }
    $inputs
}

function Get-TenureBuilderSubject {
    <#
    .SYNOPSIS
        The plan Subject (@{ Id; UserPrincipalName; DisplayName }) for a user returned by Resolve-TenureUser.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable]$User)

    $displayName = [string]$User.DisplayName
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [string]$User.UserPrincipalName }
    @{ Id = [string]$User.Id; UserPrincipalName = [string]$User.UserPrincipalName; DisplayName = $displayName }
}

function Assert-TenureStepAllowed {
    <#
    .SYNOPSIS
        Throws Tenure.Plan.Refused when a Refuse-severity Check step failed while the plan was being built.
    .DESCRIPTION
        A failed Check step has Action 'Check'. The message carries the check's own text, so
        it says what was refused and why.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][string]$Operation
    )

    if ($Step.Action -ceq 'Check') {
        throw (New-TenureError -Id 'Tenure.Plan.Refused' -Message "Refusing to build the $Operation plan: $($Step.Reason)" -Category InvalidOperation -Data @{ Operation = $Operation; Check = [string]$Step.Provider; Target = [string]$Step.Target.Name })
    }
}

function ConvertTo-TenureRecipientSetting {
    <#
    .SYNOPSIS
        Reads a forwardTo / grantMailboxTo / grantOneDriveTo value: 'manager', 'none' or an address.
    .DESCRIPTION
        Returns @{ Mode = 'manager' | 'none' | 'address'; Address }. The words match without
        regard to case. Anything else is Tenure.Plan.Invalid.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    $text = ([string]$Value).Trim()
    if ($text -ieq 'manager') { return @{ Mode = 'manager'; Address = $null } }
    if ($text -ieq 'none') { return @{ Mode = 'none'; Address = $null } }
    if ($text -cmatch '^[^@\s]+@[^@\s]+\.[^@\s]+\z') { return @{ Mode = 'address'; Address = $text } }
    throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message "$Name must be 'manager', 'none' or a mail address (got '$text')." -Category InvalidArgument -Data @{ Parameter = $Name })
}

function Expand-TenureAutoReplyTemplate {
    <#
    .SYNOPSIS
        Fills {name} placeholders in an auto-reply template in a single pass.
    .DESCRIPTION
        Only the names in -Value are replaced. A value is inserted as it is and never
        expanded again, so a display name that contains braces cannot pull in another
        placeholder. Placeholders with other names stay in the text and are listed in
        Unresolved. Returns @{ Text; Unresolved (distinct names, sorted); Used (names that
        were replaced, distinct) }.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Template,
        [Parameter(Mandatory)][hashtable]$Value
    )

    $builder = [System.Text.StringBuilder]::new()
    $unresolved = [System.Collections.Generic.List[string]]::new()
    $used = [System.Collections.Generic.List[string]]::new()
    $position = 0
    foreach ($match in [regex]::Matches($Template, '\{([A-Za-z][A-Za-z0-9]*)\}')) {
        [void]$builder.Append($Template, $position, $match.Index - $position)
        $name = $match.Groups[1].Value
        if ($Value.ContainsKey($name)) {
            [void]$builder.Append([string]$Value[$name])
            if (-not $used.Contains($name)) { $used.Add($name) }
        } else {
            [void]$builder.Append($match.Value)
            if (-not $unresolved.Contains($name)) { $unresolved.Add($name) }
        }
        $position = $match.Index + $match.Length
    }
    [void]$builder.Append($Template, $position, $Template.Length - $position)
    $unresolved.Sort([System.StringComparer]::Ordinal)
    @{ Text = $builder.ToString(); Unresolved = [string[]]$unresolved.ToArray(); Used = [string[]]$used.ToArray() }
}

function Resolve-TenureBuilderRecipient {
    <#
    .SYNOPSIS
        Turns a parsed forwardTo / grantMailboxTo / grantOneDriveTo setting into a recipient, or $null when the step is left out.
    .DESCRIPTION
        'none' gives $null. An address is used as given (Address and Upn are both that
        address). 'manager' gives the manager's mail address (the user principal name when the
        manager has none) as Address, the manager's user principal name as Upn, and the
        manager's id; a user without a manager gives $null and a warning in -Warning. Mailbox.Delegate
        takes Upn, forwarding and OneDrive sharing take Address.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable]$Setting,
        [AllowNull()][hashtable]$Manager,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$SubjectName,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Warning
    )

    switch ($Setting.Mode) {
        'none' { return $null }
        'address' { return @{ Address = [string]$Setting.Address; Upn = [string]$Setting.Address; Id = $null } }
        default {
            if ($null -eq $Manager) {
                $Warning.Add("$Description is 'manager', but $SubjectName has no manager, so that step was left out.")
                return $null
            }
            $mail = [string]$Manager.Mail
            if ([string]::IsNullOrWhiteSpace($mail)) { $mail = [string]$Manager.UserPrincipalName }
            return @{ Address = $mail; Upn = [string]$Manager.UserPrincipalName; Id = [string]$Manager.Id }
        }
    }
}

function Get-TenureLicenseRemovalReason {
    <#
    .SYNOPSIS
        The reason text of the offboard license step, built from the user's license state (Get-TenureUserLicenseState).
    .DESCRIPTION
        Says which direct licenses the step removes. Licenses inherited from a group are not
        touched by this step; the text says which of them go when this plan removes the user
        from that group (-RemovedGroupId) and which stay because the user stays in the group.
        With -MailboxNotConverted it adds that the plan does not convert the mailbox, so
        removing a license that grants it deletes it after about 30 days. SKU ids are shown
        as part numbers when the tenant still subscribes to them.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$SubjectName,
        [AllowNull()][object]$Before,
        [AllowNull()][hashtable]$GroupName = @{},
        [AllowNull()][AllowEmptyCollection()][string[]]$RemovedGroupId = @(),
        [switch]$MailboxNotConverted
    )

    $direct = @(Get-TenureGraphProperty -InputObject $Before -Name 'skuIds' | Where-Object { $null -ne $_ })
    $inheritedFrom = @(Get-TenureGraphProperty -InputObject $Before -Name 'inheritedFrom' | Where-Object { $null -ne $_ })
    $inheritedOnly = @(Get-TenureGraphProperty -InputObject $Before -Name 'inheritedSkuIds' | Where-Object { $null -ne $_ })
    $removed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($RemovedGroupId)) { if ($id) { [void]$removed.Add($id) } }

    $partNumber = @{}
    if ($direct.Count -gt 0 -or $inheritedFrom.Count -gt 0 -or $inheritedOnly.Count -gt 0) {
        foreach ($sku in @(Get-TenureSubscribedSku)) { $partNumber[([string]$sku.SkuId).ToLowerInvariant()] = [string]$sku.SkuPartNumber }
    }
    $label = {
        param($id)
        $key = ([string]$id).ToLowerInvariant()
        if ($partNumber.ContainsKey($key) -and $partNumber[$key]) { $partNumber[$key] } else { $key }
    }

    $text = if ($direct.Count -gt 0) {
        "Remove the licenses assigned directly to ${SubjectName}: " + ((@($direct | ForEach-Object { & $label $_ }) | Sort-Object) -join ', ') + '.'
    } else {
        "No license is assigned directly to ${SubjectName}, so there is nothing to remove."
    }
    if ($inheritedFrom.Count -gt 0) {
        $going = [System.Collections.Generic.List[string]]::new()
        $staying = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $inheritedFrom) {
            $groupId = ([string](Get-TenureGraphProperty -InputObject $entry -Name 'groupId')).ToLowerInvariant()
            $via = if ($GroupName.ContainsKey($groupId)) { $GroupName[$groupId] } else { "group $groupId" }
            $item = (& $label (Get-TenureGraphProperty -InputObject $entry -Name 'skuId')) + " via $via"
            if ($removed.Contains($groupId)) { $going.Add($item) } else { $staying.Add($item) }
        }
        $text += ' Licenses inherited from groups are not touched by this step.'
        if ($going.Count -gt 0) { $text += ' These go when this plan removes the user from the group: ' + ((@($going) | Sort-Object) -join ', ') + '.' }
        if ($staying.Count -gt 0) { $text += ' These stay, because the user stays in the group: ' + ((@($staying) | Sort-Object) -join ', ') + '.' }
    } elseif ($inheritedOnly.Count -gt 0) {
        $text += ' Licenses inherited from groups are not touched by this step: ' + ((@($inheritedOnly | ForEach-Object { & $label $_ }) | Sort-Object) -join ', ') + '.'
    }
    if ($MailboxNotConverted) {
        $text += ' This plan does not convert the mailbox to a shared mailbox, and a license of the user grants it, so removing the licenses deletes the mailbox after about 30 days.'
    }
    $text
}
