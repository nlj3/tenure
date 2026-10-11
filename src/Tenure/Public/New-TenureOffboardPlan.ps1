function New-TenureOffboardPlan {
    <#
    .SYNOPSIS
        Builds the plan that offboards a user: sign-in off, sessions revoked, mailbox handed over, groups, licenses and devices cleaned up.
    .DESCRIPTION
        Reads the user's live state and turns it, with the policy's defaults.offboard settings,
        into a reviewable plan in the order of docs/SPEC.md section 5.1. Steps that do not apply
        are left out; every step key is shown here. A parameter always beats the policy value.

        1. subject: Check.SubjectAllowed refuses the plan (Tenure.Plan.Refused) when the user is
           the signed-in account or listed in defaults.protectedUsers.
        2. ga: Check.SubjectNotGlobalAdmin warns when the user holds Global Administrator.
        3. signin (User.SignIn, accountEnabled false), password (User.Password, reset and
           discarded), sessions (User.Sessions), role:<id> (DirectoryRole.Member, one per
           directory role).
        4. Mailbox: eligibility (Check.MailboxSharedEligibility), mailboxType (Shared),
           forwarding, autoreply, delegate (FullAccess for the grantee), hidden, calendar
           (cancel meetings the user organized; destructive).
        5. onedrive: OneDrive.Access gives the grantee write access.
        6. group:<id>: one removal per group the user belongs to, except keepGroups and -KeepGroup.
           Dynamic groups are a NoOp that says so; a group the user solely owns is a warning;
           distribution lists go through Exchange. A group that carries a license (its
           assignedLicenses, or the user's license states naming it) is handled like the
           license step: its removal depends on mailboxType, is left out with a warning when
           license removal is off, and its reason says the group carries a license.
        7. licenses: removes the licenses assigned directly. It depends on mailboxType, and its
           reason says which group-inherited licenses go with a group removal and which stay.
           When the plan does not convert the mailbox (-SkipMailbox, or convertMailboxToShared
           false) and a license grants one, this step and every license-carrying group removal
           are Destructive, because the mailbox would be deleted.
        8. device:<id>: Device.Wipe for company-owned and Device.Retire for personal devices
           (wipeCorporateRetirePersonal), or Retire for all (retireAll). A device with unknown
           ownership is retired, never wiped, with a warning.
        9. leave: sets employeeLeaveDateTime when defaults.offboard.setEmployeeLeaveDate is true.

        The mailbox steps need an Exchange connection (Tenure.Exchange.NotConnected otherwise;
        -SkipMailbox leaves them out). A user without a OneDrive gets a warning instead of that
        step. A user without a mailbox gets a warning instead of the mailbox steps only when
        Exchange Online reports the mailbox not found and none of the user's licenses includes
        an Exchange Online service plan; when a license does, the mailbox may exist and the plan
        is refused with Tenure.Plan.MailboxUnknown. Any other Exchange failure while reading the
        mailbox stops the plan too. forwardTo, grantMailboxTo and grantOneDriveTo accept
        'manager', 'none' or an address; 'manager' for a user without a manager leaves the step
        out with a warning. The auto-reply message may use {displayName}, {managerDisplayName}
        and {managerMail}; other placeholders are left as written and reported as a warning.

        The plan records the policy's protected users, so Invoke-TenurePlan and Test-TenurePlan
        check them with or without -Policy; a -Policy given there must be the one the plan was
        built from. The self-protection check's snapshot holds only the verdict, so another
        administrator may apply the plan without drift.
    .PARAMETER User
        The user's user principal name or object id.
    .PARAMETER Policy
        A Tenure.Policy from Get-TenurePolicy, or the path of a policy file.
    .PARAMETER ForwardTo
        'manager', 'none' or a mail address that receives the user's mail. Default: policy forwardTo.
    .PARAMETER GrantMailboxTo
        'manager', 'none' or a user that gets FullAccess to the mailbox. Default: policy grantMailboxTo.
    .PARAMETER GrantOneDriveTo
        'manager', 'none' or a user that gets write access to the OneDrive. Default: policy grantOneDriveTo.
    .PARAMETER Devices
        wipeCorporateRetirePersonal, retireAll or none. Default: policy devices.
    .PARAMETER AutoReplyMessage
        An auto-reply text (with the placeholders above) that replaces the policy's message and turns the auto-reply on.
    .PARAMETER KeepGroup
        Groups (display name, mail address or object id) to leave the user in, on top of the policy's keepGroups.
    .PARAMETER SkipLicenseRemoval
        Do not plan the license removal.
    .PARAMETER SkipMailbox
        Leave out every mailbox step; the plan then does not need an Exchange connection.
    .PARAMETER SkipDevices
        Leave out the device wipe and retire steps.
    .EXAMPLE
        $policy = Get-TenurePolicy -Path ./tenure.policy.json
        New-TenureOffboardPlan -User alex@example.com -Policy $policy | Show-TenurePlan

        Plans the offboarding with the policy's defaults and shows it for review.
    .EXAMPLE
        New-TenureOffboardPlan -User alex@example.com -Policy $policy -ForwardTo mailroom@example.com -GrantMailboxTo none -Devices retireAll -KeepGroup 'All Staff' -SkipLicenseRemoval

        Forwards to a shared address, grants nobody the mailbox, retires every device, keeps one group and leaves licenses alone.
    .OUTPUTS
        Tenure.Plan
        Operation 'Offboard'. Errors: Tenure.User.NotFound, Tenure.Plan.Refused,
        Tenure.Exchange.NotConnected, Tenure.Exchange.Failed, Tenure.Plan.MailboxUnknown,
        Tenure.Plan.Invalid, Tenure.Policy.Invalid, Tenure.Group.Ambiguous.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Plan')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Reads state through provider snapshots and returns an in-memory plan; changes no state.')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Policy,

        [string]$ForwardTo,

        [string]$GrantMailboxTo,

        [string]$GrantOneDriveTo,

        [ValidateSet('wipeCorporateRetirePersonal', 'retireAll', 'none')]
        [string]$Devices,

        [string]$AutoReplyMessage,

        [string[]]$KeepGroup,

        [switch]$SkipLicenseRemoval,

        [switch]$SkipMailbox,

        [switch]$SkipDevices
    )

    $policyObject = Resolve-TenurePolicyArgument -Policy $Policy
    $settings = $policyObject.Defaults['offboard']

    # A parameter beats the policy value.
    $forwardSetting = ConvertTo-TenureRecipientSetting -Name 'ForwardTo' -Value $(if ($PSBoundParameters.ContainsKey('ForwardTo')) { $ForwardTo } else { $settings['forwardTo'] })
    $mailboxGrantSetting = ConvertTo-TenureRecipientSetting -Name 'GrantMailboxTo' -Value $(if ($PSBoundParameters.ContainsKey('GrantMailboxTo')) { $GrantMailboxTo } else { $settings['grantMailboxTo'] })
    $oneDriveGrantSetting = ConvertTo-TenureRecipientSetting -Name 'GrantOneDriveTo' -Value $(if ($PSBoundParameters.ContainsKey('GrantOneDriveTo')) { $GrantOneDriveTo } else { $settings['grantOneDriveTo'] })
    $deviceMode = if ($PSBoundParameters.ContainsKey('Devices')) { @('wipeCorporateRetirePersonal', 'retireAll', 'none') | Where-Object { $_ -ieq $Devices } | Select-Object -First 1 } else { [string]$settings['devices'] }
    $autoReplyTemplate = [string]$settings['autoReply']['message']
    $autoReplyOn = [bool]$settings['autoReply']['enabled']
    if ($PSBoundParameters.ContainsKey('AutoReplyMessage') -and -not [string]::IsNullOrWhiteSpace($AutoReplyMessage)) {
        $autoReplyTemplate = $AutoReplyMessage
        $autoReplyOn = $true
    }

    # Fail before any tenant read when the mailbox cannot be planned.
    if (-not $SkipMailbox -and -not (Test-TenureBuilderExchange)) {
        throw (New-TenureError -Id 'Tenure.Exchange.NotConnected' -Message 'Not connected to Exchange Online, which the mailbox steps of an offboarding plan need. Run Connect-Tenure without -SkipExchange, or pass -SkipMailbox to plan without the mailbox and Exchange groups.' -Category ConnectionError)
    }

    $userInfo = Resolve-TenureUser -Identity $User
    $subject = Get-TenureBuilderSubject -User $userInfo
    $upn = $subject.UserPrincipalName
    $manager = $userInfo.Manager
    $context = Get-TenureStepContext -Policy $policyObject -Subject $subject
    $target = @{ Kind = 'user'; Id = $subject.Id; Name = $upn }
    $warnings = [System.Collections.Generic.List[string]]::new()
    $steps = [System.Collections.Generic.List[object]]::new()

    # 1 and 2. Checks.
    $subjectCheck = New-TenureStep -Provider 'Check.SubjectAllowed' -Target $target -Context $context -Key 'subject'
    Assert-TenureStepAllowed -Step $subjectCheck -Operation 'Offboard'
    $steps.Add($subjectCheck)
    $adminCheck = New-TenureStep -Provider 'Check.SubjectNotGlobalAdmin' -Target $target -Context $context -Key 'ga'
    if ($adminCheck.Action -ceq 'Check') { $warnings.Add($adminCheck.Reason) }
    $steps.Add($adminCheck)

    # 3. Sign-in, password, sessions and directory roles.
    $steps.Add((New-TenureStep -Provider 'User.SignIn' -Target $target -Desired @{ accountEnabled = $false } -Context $context -Key 'signin'))
    if ($settings['resetPassword']) {
        $steps.Add((New-TenureStep -Provider 'User.Password' -Target $target -Desired @{ discard = $true } -Context $context -Key 'password'))
    }
    if ($settings['revokeSessions']) {
        $steps.Add((New-TenureStep -Provider 'User.Sessions' -Target $target -Context $context -Key 'sessions'))
    }
    $membership = $null
    if ($settings['removeDirectoryRoles'] -or $settings['removeFromGroups']) {
        $membership = Get-TenureUserMembership -UserId $subject.Id
        # What memberOf listed, so a membership read that contradicts it is refused instead of taken as "not a member".
        $context['MemberOf'] = [string[]]@(@($membership.Groups) + @($membership.Roles) | ForEach-Object { [string]$_.Id })
    }
    if ($settings['removeDirectoryRoles']) {
        foreach ($role in $membership.Roles) {
            $steps.Add((New-TenureStep -Provider 'DirectoryRole.Member' -Target @{ Kind = 'role'; Id = $role.Id; Name = $role.DisplayName } -Desired @{ userId = $subject.Id; member = $false } -Context $context -Key ('role:' + $role.Id.ToLowerInvariant())))
        }
    }

    # 4. Mailbox. The specs are built in step order; the first read doubles as the "has a mailbox" probe.
    $mailboxTarget = @{ Kind = 'mailbox'; Id = $subject.Id; Name = $upn }
    $mailboxSteps = @{}
    $mailboxMissing = $false
    if (-not $SkipMailbox) {
        $forward = Resolve-TenureBuilderRecipient -Setting $forwardSetting -Manager $manager -Description 'forwardTo' -SubjectName $upn -Warning $warnings
        $mailboxGrantee = Resolve-TenureBuilderRecipient -Setting $mailboxGrantSetting -Manager $manager -Description 'grantMailboxTo' -SubjectName $upn -Warning $warnings

        $specs = [ordered]@{}
        if ($settings['convertMailboxToShared']) {
            $specs['eligibility'] = @{ Provider = 'Check.MailboxSharedEligibility'; Target = $mailboxTarget; Desired = @{ maxSizeBytes = [long]50GB; allowArchive = $false; allowHolds = $false } }
            $specs['mailboxType'] = @{ Provider = 'Mailbox.Type'; Target = $mailboxTarget; Desired = @{ type = 'Shared' } }
        }
        if ($null -ne $forward) {
            $specs['forwarding'] = @{ Provider = 'Mailbox.Forwarding'; Target = $mailboxTarget; Desired = @{ forwardingSmtpAddress = $forward.Address; deliverToMailboxAndForward = [bool]$settings['deliverToMailboxAndForward'] } }
        }
        if ($autoReplyOn) {
            $values = @{ displayName = $subject.DisplayName; managerDisplayName = ''; managerMail = '' }
            if ($null -ne $manager) {
                $values['managerDisplayName'] = [string]$manager.DisplayName
                $values['managerMail'] = if ([string]::IsNullOrWhiteSpace([string]$manager.Mail)) { [string]$manager.UserPrincipalName } else { [string]$manager.Mail }
            }
            $expanded = Expand-TenureAutoReplyTemplate -Template $autoReplyTemplate -Value $values
            if ($null -eq $manager -and ($expanded.Used -ccontains 'managerDisplayName' -or $expanded.Used -ccontains 'managerMail')) {
                $warnings.Add("The auto-reply message names the manager, but $upn has no manager, so the manager fields are empty.")
            }
            if ($expanded.Unresolved.Count -gt 0) {
                $warnings.Add('The auto-reply message has placeholders Tenure does not fill and leaves as written: ' + (($expanded.Unresolved | ForEach-Object { '{' + $_ + '}' }) -join ', ') + '. Change the policy message or pass -AutoReplyMessage.')
            }
            if ([string]::IsNullOrWhiteSpace($expanded.Text)) {
                $warnings.Add('The auto-reply message is empty, so the auto-reply step was left out.')
            } else {
                $specs['autoreply'] = @{ Provider = 'Mailbox.AutoReply'; Target = $mailboxTarget; Desired = @{ autoReplyState = 'Enabled'; internalMessage = $expanded.Text; externalMessage = $expanded.Text; externalAudience = 'All' } }
            }
        }
        if ($settings['hideFromAddressLists']) {
            $specs['hidden'] = @{ Provider = 'Mailbox.Hidden'; Target = $mailboxTarget; Desired = @{ hiddenFromAddressLists = $true } }
        }
        if ($settings['cancelMeetings']) {
            $specs['calendar'] = @{ Provider = 'Calendar.CancelMeetings'; Target = $mailboxTarget; Desired = @{ queryWindowInDays = 120 } }
        }
        $delegateSpec = $null
        if ($null -ne $mailboxGrantee) {
            $delegateTarget = @{ Kind = 'mailbox'; Id = $subject.Id; Name = $upn; Grantee = $mailboxGrantee.Upn }
            $delegateSpec = @{ Provider = 'Mailbox.Delegate'; Target = $delegateTarget; Desired = @{ user = $mailboxGrantee.Upn; accessRights = 'FullAccess'; present = $true } }
        }

        # A missing mailbox shows up as Tenure.Provider.TargetNotFound on the first read: Exchange said the
        # mailbox "couldn't be found". Any other failure (a busy server, a lost session) passes through and the
        # plan is not built. Not found alone is not enough to leave the mailbox steps out; see below.
        foreach ($key in $specs.Keys) {
            $spec = $specs[$key]
            try {
                $mailboxSteps[$key] = New-TenureStep @spec -Context $context -Key $key
            } catch {
                if ((Get-TenureErrorId -ErrorRecord $_) -cne 'Tenure.Provider.TargetNotFound') { throw }
                $mailboxMissing = $true
                break
            }
        }
        if (-not $mailboxMissing -and $null -ne $delegateSpec) {
            if ($specs.Count -eq 0) {
                # Nothing else read the mailbox, so a missing grantee could not be told from a missing mailbox: probe it first.
                try {
                    $null = & (Get-TenureProviderDefinition -Name 'Mailbox.Type').Get $mailboxTarget $context
                } catch {
                    if ((Get-TenureErrorId -ErrorRecord $_) -cne 'Tenure.Provider.TargetNotFound') { throw }
                    $mailboxMissing = $true
                }
            }
            if (-not $mailboxMissing) {
                try {
                    $mailboxSteps['delegate'] = New-TenureStep @delegateSpec -Context $context -Key 'delegate'
                } catch {
                    if ((Get-TenureErrorId -ErrorRecord $_) -ceq 'Tenure.Provider.TargetNotFound') {
                        throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message "The mailbox of $upn exists, but the user to grant it to ('$($mailboxGrantee.Upn)') was not found in Exchange Online. Check -GrantMailboxTo or the policy's grantMailboxTo." -Category InvalidArgument -Inner $_)
                    }
                    throw
                }
            }
        }
        if ($mailboxMissing) {
            # Leaving the mailbox steps out while the licenses go would delete a mailbox that exists after about
            # 30 days, so Exchange's "not found" must be backed by positive evidence: no license the user holds
            # (directly or through a group) includes an Exchange Online service plan.
            $exchangePlans = @(Get-TenureUserExchangePlan -UserId $subject.Id)
            if ($exchangePlans.Count -gt 0) {
                $held = (@($exchangePlans | ForEach-Object { "$($_.SkuPartNumber) ($($_.ServicePlanName))" }) -join ', ')
                throw (New-TenureError -Id 'Tenure.Plan.MailboxUnknown' -Message "Exchange Online found no mailbox for $upn, but the user holds Exchange Online through $held, so the mailbox may exist and the lookup may be wrong. Refusing to plan the offboarding without its mailbox steps: the licenses would be removed and the mailbox deleted about 30 days later. Check the mailbox in Exchange Online and plan again, or pass -SkipMailbox once you have confirmed it has no mailbox." -Category InvalidOperation -Data @{ User = $upn; ServicePlans = [string[]]@($exchangePlans | ForEach-Object { "$($_.SkuPartNumber)/$($_.ServicePlanName)" }) })
            }
            $mailboxSteps.Clear()
            $warnings.Add("$upn has no mailbox (Exchange Online found none and no license of the user includes Exchange Online), so the mailbox steps (shared conversion, forwarding, auto-reply, delegate, address lists, calendar) were left out.")
        } elseif ($mailboxSteps.ContainsKey('eligibility') -and $mailboxSteps['eligibility'].Action -ceq 'Check') {
            $warnings.Add($mailboxSteps['eligibility'].Reason)
        }
    }
    foreach ($key in 'eligibility', 'mailboxType', 'forwarding', 'autoreply', 'delegate', 'hidden', 'calendar') {
        if ($mailboxSteps.ContainsKey($key)) { $steps.Add($mailboxSteps[$key]) }
    }

    # 5. OneDrive.
    $oneDriveGrantee = Resolve-TenureBuilderRecipient -Setting $oneDriveGrantSetting -Manager $manager -Description 'grantOneDriveTo' -SubjectName $upn -Warning $warnings
    if ($null -ne $oneDriveGrantee) {
        try {
            $steps.Add((New-TenureStep -Provider 'OneDrive.Access' -Target @{ Kind = 'drive'; Id = $subject.Id; Name = $upn } -Desired @{ granteeEmail = $oneDriveGrantee.Address; role = 'write'; present = $true } -Context $context -Key 'onedrive'))
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -cne 'Tenure.Provider.TargetNotFound') { throw }
            $warnings.Add("$upn has no OneDrive (OneDrive not provisioned), so the OneDrive access step was left out.")
        }
    }

    # Licenses and the groups that carry them. Removing the user from a group that assigns a license removes
    # that license, and a license removed from a mailbox that was not converted to shared deletes the mailbox
    # after about 30 days. So a removal from such a group is planned like the license step: after the mailbox
    # conversion, left out when licenses stay, and Destructive when the plan does not convert a mailbox that a
    # license grants.
    $removeLicenses = [bool]$settings['removeLicenses'] -and -not $SkipLicenseRemoval
    $licenseNow = $null
    if ($removeLicenses -or $settings['removeFromGroups']) {
        # Direct and group-inherited licenses with their groups (the step's own snapshot keeps only the direct ones).
        $licenseNow = Get-TenureUserLicenseState -UserId $subject.Id
    }
    $mailboxAtRisk = $false
    if (-not $mailboxSteps.ContainsKey('mailboxType') -and -not $mailboxMissing -and ($removeLicenses -or $settings['removeFromGroups'])) {
        $mailboxAtRisk = @(Get-TenureUserExchangePlan -UserId $subject.Id).Count -gt 0
    }
    $inheritedByGroup = @{}
    foreach ($entry in @(Get-TenureGraphProperty -InputObject $licenseNow -Name 'inheritedFrom' | Where-Object { $null -ne $_ })) {
        $groupKey = ([string](Get-TenureGraphProperty -InputObject $entry -Name 'groupId')).ToLowerInvariant()
        if (-not $inheritedByGroup.ContainsKey($groupKey)) { $inheritedByGroup[$groupKey] = [System.Collections.Generic.List[string]]::new() }
        $inheritedByGroup[$groupKey].Add(([string](Get-TenureGraphProperty -InputObject $entry -Name 'skuId')).ToLowerInvariant())
    }
    $partNumbers = @{}
    $skuLabel = {
        param([string[]]$ids)
        if ($partNumbers.Count -eq 0) {
            foreach ($sku in @(Get-TenureSubscribedSku)) { $partNumbers[([string]$sku.SkuId).ToLowerInvariant()] = [string]$sku.SkuPartNumber }
        }
        (@($ids | ForEach-Object { if ($partNumbers.ContainsKey($_) -and $partNumbers[$_]) { $partNumbers[$_] } else { $_ } }) | Sort-Object -Unique) -join ', '
    }

    # 6. Groups.
    $groupNames = @{}
    $licenseGroupIds = [System.Collections.Generic.List[string]]::new()
    if ($settings['removeFromGroups']) {
        $keptGroups = @(Resolve-TenureBuilderGroup -Identity (@($settings['keepGroups']) + @($KeepGroup)) -Description 'group to keep' -Warning $warnings -SkipMissing)
        $keptGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($group in $keptGroups) { [void]$keptGroupIds.Add([string]$group.Id) }
        foreach ($group in $membership.Groups) {
            $groupKey = ([string]$group.Id).ToLowerInvariant()
            $groupNames[$groupKey] = [string]$group.DisplayName
            if ($keptGroupIds.Contains([string]$group.Id)) { continue }
            $blocker = Get-TenureGroupStepBlocker -Group $group -Member $false
            if ($blocker) {
                $warnings.Add($blocker)
                continue
            }
            # The licenses this group assigns: what the group says, and what the user's license states say comes from it.
            $carried = [System.Collections.Generic.List[string]]::new()
            foreach ($sku in @(Get-TenureGroupLicense -GroupId ([string]$group.Id) -Cache $context['GroupLicenses'])) { if (-not $carried.Contains($sku)) { $carried.Add($sku) } }
            if ($inheritedByGroup.ContainsKey($groupKey)) { foreach ($sku in $inheritedByGroup[$groupKey]) { if (-not $carried.Contains($sku)) { $carried.Add($sku) } } }

            $reason = $null
            $membershipArguments = @{ Group = $group; UserId = $subject.Id; Member = $false; Context = $context }
            if ($group.IsDynamic) {
                $reason = "Group '$($group.DisplayName)' has dynamic membership: its rule decides who is a member, so there is nothing to remove by hand ($upn leaves it when the rule stops matching)."
                if ($carried.Count -gt 0) {
                    $warnings.Add("Group '$($group.DisplayName)' has dynamic membership and carries a license ($(& $skuLabel $carried.ToArray())): if its rule stops matching $upn (for example on accountEnabled), $upn loses that license, and a mailbox that was not converted to shared is deleted after about 30 days.")
                }
            } else {
                $owners = @()
                try {
                    $owners = @(Get-TenureGroupOwner -GroupId ([string]$group.Id))
                } catch {
                    if ((Get-TenureErrorId -ErrorRecord $_) -cne 'Tenure.Graph.NotFound') { throw }
                }
                if ($owners.Count -eq 1 -and [string]$owners[0].Id -ieq $subject.Id) {
                    $warnings.Add("Group '$($group.DisplayName)' has $upn as its only owner; removing them leaves the group without an owner.")
                }
                if ($carried.Count -gt 0) {
                    $skus = & $skuLabel $carried.ToArray()
                    if (-not $removeLicenses) {
                        $warnings.Add("Group '$($group.DisplayName)' carries a license ($skus), so removing $upn from it removes that license. License removal is off (-SkipLicenseRemoval or removeLicenses false), so $upn stays in the group.")
                        continue
                    }
                    $reason = "Remove $upn from group '$($group.DisplayName)'. The group carries a license ($skus), so this also removes that license from $upn."
                    if ($mailboxSteps.ContainsKey('mailboxType')) {
                        $membershipArguments['DependsOn'] = 'mailboxType'
                        $reason += ' It runs after the mailbox is converted to shared.'
                    } elseif ($mailboxAtRisk) {
                        $membershipArguments['Risk'] = 'Destructive'
                        $reason += ' This plan does not convert the mailbox to shared, so the mailbox is deleted after about 30 days.'
                    }
                    $licenseGroupIds.Add($groupKey)
                }
            }
            if ($reason) { $membershipArguments['Reason'] = $reason }
            $steps.Add((New-TenureMembershipStep @membershipArguments))
        }
    }

    # 7. Licenses. The step lists, as its remove delta, exactly the licenses assigned directly now, so applying
    #    it can never remove a license assigned after this plan was reviewed.
    if ($removeLicenses) {
        $directSkuIds = [string[]]@(ConvertTo-TenureSkuIdList -Id (Get-TenureGraphProperty -InputObject $licenseNow -Name 'skuIds'))
        $licenseArguments = @{ Provider = 'User.Licenses'; Target = $target; Desired = @{ add = [string[]]@(); remove = $directSkuIds }; Context = $context; Key = 'licenses'; Risk = $(if ($mailboxAtRisk) { 'Destructive' } else { 'High' }) }
        if ($mailboxSteps.ContainsKey('mailboxType')) { $licenseArguments['DependsOn'] = 'mailboxType' }
        $licenseStep = New-TenureStep @licenseArguments
        $licenseStep.Reason = Get-TenureLicenseRemovalReason -SubjectName $upn -Before $licenseNow -GroupName $groupNames -RemovedGroupId $licenseGroupIds.ToArray() -MailboxNotConverted:$mailboxAtRisk
        $steps.Add($licenseStep)
    }
    if ($mailboxAtRisk -and ($removeLicenses -or $licenseGroupIds.Count -gt 0)) {
        $warnings.Add("Licenses are removed, but this plan does not convert the mailbox of $upn to a shared mailbox; an Exchange Online mailbox whose license is removed is deleted after about 30 days. The license steps are Destructive: each needs its own confirmation or -AllowDestructive.")
    }

    # 8. Devices.
    if (-not $SkipDevices -and $deviceMode -cne 'none') {
        foreach ($device in @(Get-TenureUserManagedDevice -UserId $subject.Id)) {
            $name = if ([string]::IsNullOrWhiteSpace($device.DeviceName)) { $device.Id } else { $device.DeviceName }
            $deviceTarget = @{ Kind = 'device'; Id = $device.Id; Name = "$name ($($device.Ownership))" }
            $key = 'device:' + $device.Id.ToLowerInvariant()
            if ($deviceMode -ceq 'wipeCorporateRetirePersonal' -and $device.Ownership -ceq 'company') {
                $steps.Add((New-TenureStep -Provider 'Device.Wipe' -Target $deviceTarget -Desired @{ keepEnrollmentData = $false; keepUserData = $false } -Context $context -Key $key))
                continue
            }
            if ($deviceMode -ceq 'wipeCorporateRetirePersonal' -and $device.Ownership -ceq 'unknown') {
                $warnings.Add("Device $name has unknown ownership, so it is retired and never wiped.")
            }
            $steps.Add((New-TenureStep -Provider 'Device.Retire' -Target $deviceTarget -Context $context -Key $key))
        }
    }

    # 9. Leave date.
    if ($settings['setEmployeeLeaveDate']) {
        $steps.Add((New-TenureStep -Provider 'User.LeaveDate' -Target $target -Desired @{ employeeLeaveDateTime = [datetime]::UtcNow } -Context $context -Key 'leave'))
    }

    $inputs = Get-TenureBuilderInput -Bound $PSBoundParameters -Policy $policyObject -Replace @{ User = $upn }
    New-TenurePlan -Operation Offboard -Subject $subject -Step $steps.ToArray() -Policy $policyObject -Inputs $inputs -Warning $warnings.ToArray()
}
