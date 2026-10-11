function New-TenureRoleChangePlan {
    <#
    .SYNOPSIS
        Builds the plan that moves an existing user to a different role: licenses, group memberships, attributes and manager.
    .DESCRIPTION
        Compares what the user holds now with what the new role defines (docs/SPEC.md section 5.3)
        and plans only the difference. Steps, in this order:

        1. licenses: User.Licenses, always present (a NoOp when nothing changes). It adds the
           new role's licenses and removes the managed licenses the user holds now that the new
           role does not list. The step lists both sets explicitly, so applying it never removes
           a license the plan did not show. Licenses assigned through a group are never touched.
        2. group:<id> adds: one step per group of the new role the user is not yet a member of.
        3. group:<id> removes: one step per managed group the user is in that the new role does
           not list.
        4. attributes: User.Attributes with the department and job title, when either has a value.
        5. manager: User.Manager, when a manager is given or the role defines one.

        The managed set is every license and group named by any role in the policy. A role
        change only ever removes items from the managed set, so a group the policy does not
        mention is never removed. -FromRole narrows removal further, to the items of that one
        role. -KeepGroup protects groups from removal. A managed name that no longer matches
        anything in the tenant is a plan warning, not an error. Groups with dynamic membership
        cannot be added to by hand (warning, step skipped); removing from one is a NoOp that
        says why. Distribution lists need an Exchange connection.

        A user listed in the policy's defaults.protectedUsers (by object id, user principal name
        or mail address) is refused with Tenure.Plan.Refused before anything else is read.

        A user who holds a license with Exchange Online (directly or through a group) keeps a
        mailbox only while one such license stays. When the change would take away every one of
        them (the license step removes the direct ones, a group removal the inherited ones) and
        add none, the plan is refused with Tenure.Plan.MailboxUnlicensed, which names each
        license and the group it comes through: Exchange Online deletes the mailbox about 30
        days later. -AllowMailboxLoss builds the plan anyway, with those steps Destructive and a
        warning.
    .PARAMETER User
        The user's user principal name or object id.
    .PARAMETER Role
        The new role (a role name from the policy; Tenure.Policy.RoleNotFound when it is not defined).
    .PARAMETER Policy
        A Tenure.Policy from Get-TenurePolicy, or the path of a policy file.
    .PARAMETER FromRole
        The role the user is leaving. Only this role's licenses and groups can be removed.
    .PARAMETER Manager
        The new manager's user principal name or object id. Overrides the role's manager.
    .PARAMETER Department
        Overrides the role's department.
    .PARAMETER JobTitle
        Overrides the role's job title.
    .PARAMETER KeepGroup
        Groups (display name, mail address or object id) that stay even when the new role does not list them.
    .PARAMETER AllowMailboxLoss
        Builds the plan even when it takes away the user's last license with Exchange Online. The
        steps that do so are Destructive, and the plan carries a warning.
    .EXAMPLE
        New-TenureRoleChangePlan -User alex@example.com -Role support -Policy ./tenure.policy.json | Show-TenurePlan

        Shows what moving Alex from whatever they have now to the support role would change.
    .EXAMPLE
        New-TenureRoleChangePlan -User alex@example.com -Role support -FromRole sales -KeepGroup 'All Staff' -Policy $policy -Manager carol@example.com

        Removes only the sales role's items, keeps All Staff, and sets a new manager.
    .OUTPUTS
        Tenure.Plan
        Operation 'RoleChange'. Errors: Tenure.User.NotFound, Tenure.Plan.Refused, Tenure.Policy.RoleNotFound,
        Tenure.Group.NotFound, Tenure.Group.Ambiguous, Tenure.Sku.NotFound, Tenure.Plan.MailboxUnlicensed,
        Tenure.Plan.Invalid.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Plan')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Reads state through provider snapshots and returns an in-memory plan; changes no state.')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Role,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Policy,

        [string]$FromRole,

        [string]$Manager,

        [string]$Department,

        [string]$JobTitle,

        [string[]]$KeepGroup,

        [switch]$AllowMailboxLoss
    )

    $policyObject = Resolve-TenurePolicyArgument -Policy $Policy
    $newRole = Get-TenurePolicyRole -Policy $policyObject -Name $Role
    $fromRoleDefinition = $null
    if ($PSBoundParameters.ContainsKey('FromRole')) { $fromRoleDefinition = Get-TenurePolicyRole -Policy $policyObject -Name $FromRole }

    $userInfo = Resolve-TenureUser -Identity $User
    $subject = Get-TenureBuilderSubject -User $userInfo
    # Self-protection (SPEC section 8): every step of this plan acts on the subject, so a protected account is refused here.
    $protectedEntry = Find-TenureProtectedUser -Protected @($policyObject.Defaults['protectedUsers']) -Identity @([string]$userInfo.Id, [string]$userInfo.UserPrincipalName, [string]$userInfo.Mail)
    if ($protectedEntry) {
        throw (New-TenureError -Id 'Tenure.Plan.Refused' -Message "Refusing to build the RoleChange plan: $($subject.UserPrincipalName) is protected by policy (protectedUsers entry '$protectedEntry')." -Category InvalidOperation -Data @{ Operation = 'RoleChange'; Target = $subject.UserPrincipalName })
    }
    $context = Get-TenureStepContext -Policy $policyObject -Subject $subject
    $target = @{ Kind = 'user'; Id = $subject.Id; Name = $subject.UserPrincipalName }
    $warnings = [System.Collections.Generic.List[string]]::new()
    $steps = [System.Collections.Generic.List[object]]::new()

    # Resolve everything named in the request before reading the user's state, so a typo stops the plan early.
    $newGroups = @(Resolve-TenureBuilderGroup -Identity $newRole.Groups -Description 'group')
    $newSkus = @(Resolve-TenureBuilderSku -PartNumber $newRole.Licenses -Description 'license')
    $removableGroupNames = if ($null -ne $fromRoleDefinition) { $fromRoleDefinition.Groups } else { $policyObject.ManagedSet.Groups }
    $removableSkuNames = if ($null -ne $fromRoleDefinition) { $fromRoleDefinition.Licenses } else { $policyObject.ManagedSet.Licenses }
    $removableGroups = @(Resolve-TenureBuilderGroup -Identity $removableGroupNames -Description 'managed group' -Warning $warnings -SkipMissing)
    $removableSkus = @(Resolve-TenureBuilderSku -PartNumber $removableSkuNames -Description 'managed license' -Warning $warnings -SkipMissing)
    $keptGroups = @(Resolve-TenureBuilderGroup -Identity $KeepGroup -Description 'group to keep' -Warning $warnings -SkipMissing)

    $caseless = [System.StringComparer]::OrdinalIgnoreCase
    $newGroupIds = [System.Collections.Generic.HashSet[string]]::new($caseless)
    foreach ($group in $newGroups) { [void]$newGroupIds.Add([string]$group.Id) }
    $removableGroupIds = [System.Collections.Generic.HashSet[string]]::new($caseless)
    foreach ($group in $removableGroups) { [void]$removableGroupIds.Add([string]$group.Id) }
    $keptGroupIds = [System.Collections.Generic.HashSet[string]]::new($caseless)
    foreach ($group in $keptGroups) { [void]$keptGroupIds.Add([string]$group.Id) }

    # What the user holds now: direct licenses, licenses inherited from groups (with their groups), and memberships.
    $licenseNow = Get-TenureUserLicenseState -UserId $subject.Id
    $currentSkuIds = @(ConvertTo-TenureSkuIdList -Id (Get-TenureGraphProperty -InputObject $licenseNow -Name 'skuIds'))
    $heldSkuIds = @(ConvertTo-TenureSkuIdList -Id (@($currentSkuIds) + @(Get-TenureGraphProperty -InputObject $licenseNow -Name 'inheritedSkuIds')))
    $membership = Get-TenureUserMembership -UserId $subject.Id
    # What memberOf listed, so a membership read that contradicts it is refused instead of taken as "not a member".
    $context['MemberOf'] = [string[]]@(@($membership.Groups) + @($membership.Roles) | ForEach-Object { [string]$_.Id })
    $currentGroupIds = [System.Collections.Generic.HashSet[string]]::new($caseless)
    $groupNames = @{}
    foreach ($group in $membership.Groups) {
        [void]$currentGroupIds.Add([string]$group.Id)
        $groupNames[([string]$group.Id).ToLowerInvariant()] = [string]$group.DisplayName
    }
    $inheritedFrom = @(Get-TenureGraphProperty -InputObject $licenseNow -Name 'inheritedFrom' | Where-Object { $null -ne $_ })

    # 1. Licenses. The step adds the new role's licenses and removes the managed ones the new role drops, limited to
    #    those the user holds now (a group-inherited one stays, and the step's reason says so), so applying it never
    #    removes a license the plan did not show.
    $newSkuIds = @(ConvertTo-TenureSkuIdList -Id ($newSkus | ForEach-Object { $_.SkuId }))
    $leavingSkuIds = @(@(ConvertTo-TenureSkuIdList -Id ($removableSkus | ForEach-Object { $_.SkuId })) | Where-Object { $_ -cnotin $newSkuIds })
    $licenseDelta = @{
        add    = [string[]]$newSkuIds
        remove = [string[]]@($leavingSkuIds | Where-Object { $_ -cin $heldSkuIds })
    }
    foreach ($sku in $newSkus) {
        if ($sku.SkuId -cnotin $currentSkuIds -and $sku.Available -le 0) {
            $warnings.Add("License $($sku.SkuPartNumber) has no available units; assigning it will fail until more are bought or freed.")
        }
    }
    if ($newSkuIds.Count -gt 0 -and @($newSkuIds | Where-Object { $_ -cnotin $currentSkuIds }).Count -gt 0 -and [string]::IsNullOrWhiteSpace([string](Get-TenureGraphProperty -InputObject $licenseNow -Name 'usageLocation'))) {
        $warnings.Add("$($subject.UserPrincipalName) has no usage location, so assigning licenses will fail until one is set.")
    }

    # 2 and 3. Groups: which to add and which to remove. A dynamic group's removal is a NoOp that says why.
    $groupAdds = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($group in $newGroups) {
        if ($currentGroupIds.Contains([string]$group.Id)) { continue }
        $blocker = Get-TenureGroupStepBlocker -Group $group -Member $true
        if ($blocker) {
            $warnings.Add($blocker)
            continue
        }
        $groupAdds.Add($group)
    }
    $groupRemoves = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($group in $membership.Groups) {
        $id = [string]$group.Id
        if (-not $removableGroupIds.Contains($id) -or $newGroupIds.Contains($id) -or $keptGroupIds.Contains($id)) { continue }
        $blocker = Get-TenureGroupStepBlocker -Group $group -Member $false
        if ($blocker) {
            $warnings.Add($blocker)
            continue
        }
        $groupRemoves.Add($group)
    }

    # The mailbox. Exchange Online deletes a mailbox about 30 days after its last license goes, so a role change
    # that leaves a user who holds a mailbox license (direct or through a group) with none is refused unless
    # -AllowMailboxLoss is given; then the steps that take the last one away are Destructive. What counts is a service
    # plan that gives a mailbox and that the assignment does not switch off (disabledPlans), not a SKU id; a license
    # a new group brings counts only when its SKU has a free seat, because group-based licensing fails quietly.
    $mailboxRiskSkuIds = [string[]]@()
    $exchangeNow = @(Get-TenureUserExchangePlan -UserId $subject.Id)
    if ($exchangeNow.Count -gt 0) {
        $grantingNow = @(ConvertTo-TenureSkuIdList -Id ($exchangeNow | ForEach-Object { $_.SkuId }))
        $partOf = @{}
        foreach ($entry in $exchangeNow) { $partOf[[string]$entry.SkuId] = [string]$entry.SkuPartNumber }
        $skuInfo = @{}
        foreach ($sku in @(Get-TenureMailboxSku)) { $skuInfo[$sku.SkuId] = $sku }
        # True when an assignment of the SKU, with these plans switched off, still gives a mailbox.
        $gives = {
            param([string]$SkuId, [string[]]$Disabled)
            $info = $skuInfo[$SkuId]
            ($null -ne $info) -and @($info.MailboxPlanIds | Where-Object { $_ -cnotin @($Disabled) }).Count -gt 0
        }
        $removedGroupIds = [System.Collections.Generic.HashSet[string]]::new($caseless)
        foreach ($group in $groupRemoves) { if (-not $group.IsDynamic) { [void]$removedGroupIds.Add([string]$group.Id) } }
        $directDisabled = Get-TenureGraphProperty -InputObject $licenseNow -Name 'directDisabledPlans' -Default @{}

        $keeps = 0
        foreach ($sku in $currentSkuIds) {
            if ($sku -cin $licenseDelta.remove) { continue }
            if (& $gives $sku @($directDisabled[$sku])) { $keeps++ }
        }
        foreach ($pair in $inheritedFrom) {
            $groupId = [string](Get-TenureGraphProperty -InputObject $pair -Name 'groupId')
            if ($removedGroupIds.Contains($groupId)) { continue }
            $sku = [string](Get-TenureGraphProperty -InputObject $pair -Name 'skuId')
            $assignment = @(Get-TenureGroupLicense -GroupId $groupId -Cache $context['GroupLicenses'] -Detailed | Where-Object { $_.SkuId -ceq $sku })
            # A group that no longer reports the assignment does not count: fail closed.
            if ($assignment.Count -gt 0 -and (& $gives $sku $assignment[0].DisabledPlans)) { $keeps++ }
        }
        if ($keeps -eq 0) {
            $adds = 0
            $shortages = [System.Collections.Generic.List[string]]::new()
            foreach ($sku in $licenseDelta.add) { if (& $gives $sku @()) { $adds++ } }
            foreach ($group in $groupAdds) {
                foreach ($assignment in @(Get-TenureGroupLicense -GroupId ([string]$group.Id) -Cache $context['GroupLicenses'] -Detailed)) {
                    if (-not (& $gives $assignment.SkuId $assignment.DisabledPlans)) { continue }
                    $info = $skuInfo[$assignment.SkuId]
                    if ($info.Available -gt 0) {
                        $adds++
                    } else {
                        $label = if ($info.SkuPartNumber) { $info.SkuPartNumber } else { $assignment.SkuId }
                        $shortages.Add("$label through group '$($group.DisplayName)' has no free seats ($($info.Enabled) enabled, $($info.Consumed) consumed)")
                    }
                }
            }
            if ($adds -eq 0) {
                $losing = [System.Collections.Generic.List[string]]::new()
                foreach ($sku in $grantingNow) {
                    $label = if ($partOf[$sku]) { $partOf[$sku] } else { $sku }
                    if ($sku -cin $currentSkuIds) { $losing.Add("$label (assigned directly)") }
                    foreach ($pair in @($inheritedFrom | Where-Object { ([string](Get-TenureGraphProperty -InputObject $_ -Name 'skuId')) -ceq $sku })) {
                        $groupId = ([string](Get-TenureGraphProperty -InputObject $pair -Name 'groupId')).ToLowerInvariant()
                        $via = if ($groupNames.ContainsKey($groupId)) { $groupNames[$groupId] } else { $groupId }
                        $losing.Add("$label (through group '$via')")
                    }
                }
                $what = "$($subject.UserPrincipalName) to role '$Role' leaves $($subject.UserPrincipalName) no license that gives an Exchange Online mailbox (now: $($losing -join ', '))"
                if ($shortages.Count -gt 0) { $what += "; $($shortages -join '; ')" }
                if (-not $AllowMailboxLoss) {
                    throw (New-TenureError -Id 'Tenure.Plan.MailboxUnlicensed' -Message "Refusing to build the RoleChange plan: moving $what. Exchange Online deletes a mailbox about 30 days after its last license goes. Give the role a license with Exchange Online, keep the group (-KeepGroup), convert the mailbox to shared first, or pass -AllowMailboxLoss to plan it anyway (the steps that remove the license are then Destructive)." -Category InvalidOperation -Data @{ User = $subject.UserPrincipalName; Role = $Role; Licenses = $losing.ToArray(); Shortages = $shortages.ToArray() })
                }
                $warnings.Add("Moving $what. Exchange Online deletes the mailbox about 30 days after its last license goes. -AllowMailboxLoss was given, so the steps that remove it are Destructive: each needs its own confirmation or -AllowDestructive.")
                $mailboxRiskSkuIds = [string[]]$grantingNow
            }
        }
    }

    $licenseArguments = @{ Provider = 'User.Licenses'; Target = $target; Desired = $licenseDelta; Context = $context; Key = 'licenses' }
    if (@($licenseDelta.remove | Where-Object { $_ -cin $mailboxRiskSkuIds -and $_ -cin $currentSkuIds }).Count -gt 0) { $licenseArguments['Risk'] = 'Destructive' }
    $licenseStep = New-TenureStep @licenseArguments
    # A license the step lists for removal that comes only from a group is left alone; the reason names the group.
    $viaGroup = @(foreach ($pair in $inheritedFrom) {
            $sku = [string](Get-TenureGraphProperty -InputObject $pair -Name 'skuId')
            if ($sku -cnotin $licenseDelta.remove -or $sku -cin $currentSkuIds) { continue }
            $groupId = ([string](Get-TenureGraphProperty -InputObject $pair -Name 'groupId')).ToLowerInvariant()
            $via = if ($groupNames.ContainsKey($groupId)) { $groupNames[$groupId] } else { $groupId }
            "$sku (group-inherited through '$via')"
        })
    if ($viaGroup.Count -gt 0) { $licenseStep.Reason = "$($licenseStep.Reason); this step does not remove a license a group gives: $($viaGroup -join ', ')" }
    $steps.Add($licenseStep)

    foreach ($group in $groupAdds) {
        $steps.Add((New-TenureMembershipStep -Group $group -UserId $subject.Id -Member $true -Context $context))
    }
    foreach ($group in $groupRemoves) {
        $membershipArguments = @{ Group = $group; UserId = $subject.Id; Member = $false; Context = $context }
        if ($group.IsDynamic) {
            $membershipArguments['Reason'] = "Group '$($group.DisplayName)' has dynamic membership: its rule decides who is a member, so there is nothing to remove by hand."
        } elseif ($mailboxRiskSkuIds.Count -gt 0) {
            $groupKey = ([string]$group.Id).ToLowerInvariant()
            $carried = @(Get-TenureGroupLicense -GroupId ([string]$group.Id) -Cache $context['GroupLicenses']) + @($inheritedFrom | Where-Object { ([string](Get-TenureGraphProperty -InputObject $_ -Name 'groupId')) -ceq $groupKey } | ForEach-Object { [string](Get-TenureGraphProperty -InputObject $_ -Name 'skuId') })
            if (@($carried | Where-Object { $_ -cin $mailboxRiskSkuIds }).Count -gt 0) {
                $membershipArguments['Risk'] = 'Destructive'
                $membershipArguments['Reason'] = "Remove $($subject.UserPrincipalName) from group '$($group.DisplayName)'. The group carries the license that gives the mailbox, so the mailbox is deleted about 30 days later (-AllowMailboxLoss)."
            }
        }
        $steps.Add((New-TenureMembershipStep @membershipArguments))
    }

    # 4. Attributes: the parameter first, then the role, otherwise nothing.
    $departmentValue = if ($PSBoundParameters.ContainsKey('Department') -and -not [string]::IsNullOrWhiteSpace($Department)) { $Department.Trim() } else { $newRole.Department }
    $jobTitleValue = if ($PSBoundParameters.ContainsKey('JobTitle') -and -not [string]::IsNullOrWhiteSpace($JobTitle)) { $JobTitle.Trim() } else { $newRole.JobTitle }
    $attributes = @{}
    if (-not [string]::IsNullOrWhiteSpace([string]$departmentValue)) { $attributes['department'] = [string]$departmentValue }
    if (-not [string]::IsNullOrWhiteSpace([string]$jobTitleValue)) { $attributes['jobTitle'] = [string]$jobTitleValue }
    if ($attributes.Count -gt 0) {
        $steps.Add((New-TenureStep -Provider 'User.Attributes' -Target $target -Desired $attributes -Context $context -Key 'attributes'))
    }

    # 5. Manager.
    $managerIdentity = if ($PSBoundParameters.ContainsKey('Manager') -and -not [string]::IsNullOrWhiteSpace($Manager)) { $Manager.Trim() } else { $newRole.Manager }
    $managerUser = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$managerIdentity)) {
        $managerUser = Resolve-TenureUser -Identity ([string]$managerIdentity)
        if ([string]$managerUser.Id -ieq $subject.Id) {
            throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message 'A user cannot be their own manager.' -Category InvalidArgument)
        }
        $steps.Add((New-TenureStep -Provider 'User.Manager' -Target $target -Desired @{ managerId = [string]$managerUser.Id } -Context $context -Key 'manager'))
    }

    $replace = @{ User = $subject.UserPrincipalName }
    if ($null -ne $managerUser -and $PSBoundParameters.ContainsKey('Manager')) { $replace['Manager'] = [string]$managerUser.UserPrincipalName }
    $inputs = Get-TenureBuilderInput -Bound $PSBoundParameters -Policy $policyObject -Replace $replace
    New-TenurePlan -Operation RoleChange -Subject $subject -Step $steps.ToArray() -Policy $policyObject -Inputs $inputs -Warning $warnings.ToArray()
}
