# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureDistributionMemberDesired {
    # Validates DistributionGroup.Member Desired. Returns @{ UserId = <lowercase id>; Member = [bool] }; member is required.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $provider = 'DistributionGroup.Member'
    Assert-TenureExchangeDesiredKey -Desired $Desired -Allowed @('userId', 'member') -Provider $provider
    $userId = Get-TenureGraphProperty -InputObject $Desired -Name 'userId'
    if ($userId -isnot [string] -or [string]::IsNullOrWhiteSpace($userId)) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$provider needs Desired.userId (the Entra object id of the user)." -Category InvalidArgument -Data @{ Provider = $provider; Key = 'userId' })
    }
    $member = Get-TenureExchangeDesiredBool -Desired $Desired -Name 'member' -Provider $provider -Required
    @{ UserId = $userId.Trim().ToLowerInvariant(); Member = $member }
}

function Get-TenureDistributionGroupAddress {
    # The address that names the group for the Exchange cmdlets: Target.Mail, the group's primary SMTP address.
    # Real Exchange is not trusted to resolve the Entra group id given as -Identity, and a display name is not
    # unique. A target whose Id is itself an address may leave Mail out.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Target)

    $id = (Get-TenureTargetId -Target $Target -Provider 'DistributionGroup.Member').Trim()
    $mail = Get-TenureGraphProperty -InputObject $Target -Name 'Mail'
    if ($mail -is [string] -and -not [string]::IsNullOrWhiteSpace($mail)) { return $mail.Trim() }
    if (-not (Test-TenureExchangeObjectId -Value $id) -and $id.Contains('@')) { return $id }
    throw (New-TenureError -Id 'Tenure.Step.InvalidTarget' -Message "DistributionGroup.Member needs Target.Mail, the primary SMTP address of group '$(Format-TenureExchangeSnippet -Text $id -MaxLength 60)': Exchange is not trusted to resolve an Entra id." -Category InvalidArgument -Data @{ Provider = 'DistributionGroup.Member' })
}

function Read-TenureDistributionGroup {
    # Reads the group by its address and checks it is the group the target names: when Target.Id is an Entra id,
    # the group Exchange returns must carry it, so a stale or edited Target.Mail can never redirect the step.
    [CmdletBinding()]
    [OutputType([object])]
    param([AllowNull()][object]$Target, [Parameter(Mandatory)][object]$Group, [Parameter(Mandatory)][string]$Address)

    $id = (Get-TenureTargetId -Target $Target -Provider 'DistributionGroup.Member').Trim()
    if (Test-TenureExchangeObjectId -Value $id) {
        $found = ([string](Get-TenureGraphProperty -InputObject $Group -Name 'ExternalDirectoryObjectId')).Trim()
        if (-not [string]::Equals($found, $id, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidResult' -Message "DistributionGroup.Member: the group at '$(Format-TenureExchangeSnippet -Text $Address -MaxLength 80)' is '$(Format-TenureExchangeSnippet -Text $found -MaxLength 60)', not the planned group '$id'; refusing to act on it." -Category InvalidResult -Data @{ Provider = 'DistributionGroup.Member'; Identity = $id })
        }
    }
    $Group
}

$null = Register-TenureProvider -Definition @{
    Name        = 'DistributionGroup.Member'
    Kind        = 'State'
    Backend     = 'Exchange'
    Scopes      = @()
    Risk        = 'Medium'
    Reversible  = $true
    TargetKind  = 'group'
    Actions     = @('Update', 'Remove', 'NoOp')
    Description = 'Adds or removes one user in an Exchange-managed group (a distribution list or a mail-enabled security group).'

    # Target: @{ Kind = 'group'; Id = <the Entra group id>; Name = <display name>; Mail = <primary SMTP address> }
    # Desired: @{ userId = <Entra object id>; member = <bool> }
    # Get has no Desired, so the user is Context.Subject.Id (New-TenureStep, the apply engine and Test-TenurePlan set
    # it to the step's Desired.userId, the user it changes); without one, member reads as $false. While a plan
    # is built for a user an earlier step creates, Subject.Id is the {{subjectId}} placeholder: that user cannot
    # be a member yet, so member is $false without listing the members.
    # The group is named by Target.Mail and checked against Target.Id; members are matched on their Entra id,
    # and -Member is always the member's address, never an Entra id.
    Get         = {
        param($Target, $Context)
        $address = Get-TenureDistributionGroupAddress -Target $Target
        $group = Invoke-TenureExchangeRead -Command 'Get-DistributionGroup' -Parameters @{ Identity = $address } -Provider 'DistributionGroup.Member' -Identity $address -Single
        $group = Read-TenureDistributionGroup -Target $Target -Group $group -Address $address
        $userId = [string](Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Subject') -Name 'Id')
        $member = $false
        if ($userId.Trim() -ieq '{{subjectId}}') {
            $userId = '{{subjectId}}'
        } elseif (-not [string]::IsNullOrWhiteSpace($userId)) {
            $userId = $userId.Trim().ToLowerInvariant()
            $members = @(Invoke-TenureExchangeRead -Command 'Get-DistributionGroupMember' -Parameters @{ Identity = $address; ResultSize = 'Unlimited' } -Provider 'DistributionGroup.Member' -Identity $address)
            foreach ($entry in $members) {
                $entryId = [string](Get-TenureGraphProperty -InputObject $entry -Name 'ExternalDirectoryObjectId')
                if ([string]::Equals($entryId.Trim(), $userId, [System.StringComparison]::OrdinalIgnoreCase)) { $member = $true; break }
            }
        }
        $displayName = [string](Get-TenureGraphProperty -InputObject $group -Name 'DisplayName')
        [pscustomobject]@{
            groupId     = Get-TenureExchangeObjectId -InputObject $group
            displayName = $(if ($displayName) { $displayName } else { $null })
            userId      = $(if ([string]::IsNullOrWhiteSpace($userId)) { $null } else { $userId })
            member      = $member
        }
    }

    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureDistributionMemberDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        # Get reads the subject's membership; a snapshot of someone else says nothing about this user.
        $user = [string](Get-TenureGraphProperty -InputObject $Current -Name 'userId')
        if (-not [string]::Equals($user, $wanted.UserId, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        $member = ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $Current -Name 'member') -Name 'member'
        return ($member -eq $wanted.Member)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureDistributionMemberDesired -Desired $Desired
        $address = Get-TenureDistributionGroupAddress -Target $Target
        # Before any write, prove the address names the planned group.
        $group = Invoke-TenureExchangeRead -Command 'Get-DistributionGroup' -Parameters @{ Identity = $address } -Provider 'DistributionGroup.Member' -Identity $address -Single
        $null = Read-TenureDistributionGroup -Target $Target -Group $group -Address $address
        # The admin running Tenure is usually not one of the group's owners (ManagedBy); without
        # the bypass Exchange refuses the change. It needs the Organization Management role.
        $parameters = @{ Identity = $address; BypassSecurityGroupManagerCheck = $true; Confirm = $false }
        if ($wanted.Member) {
            # -Member is the user's address, read from their mailbox by Entra id.
            $userTarget = @{ Kind = 'mailbox'; Id = $wanted.UserId; Name = $wanted.UserId }
            $parameters['Member'] = Resolve-TenureExchangeMailboxAddress -Target $userTarget -Current $null -Context $Context -Command 'Get-EXOMailbox' -Provider 'DistributionGroup.Member'
            try {
                Invoke-TenureExchange -Command 'Add-DistributionGroupMember' -Parameters $parameters | Out-Null
            } catch {
                # Already a member: the goal state.
                if (-not (Test-TenureExchangeError -ErrorRecord $_ -Like '*already a member*')) { throw }
            }
        } else {
            # -Member is the address the group lists for the member with this Entra id. Not listed: nothing to remove.
            $members = @(Invoke-TenureExchangeRead -Command 'Get-DistributionGroupMember' -Parameters @{ Identity = $address; ResultSize = 'Unlimited' } -Provider 'DistributionGroup.Member' -Identity $address)
            $entry = $null
            foreach ($candidate in $members) {
                $candidateId = ([string](Get-TenureGraphProperty -InputObject $candidate -Name 'ExternalDirectoryObjectId')).Trim()
                if ([string]::Equals($candidateId, $wanted.UserId, [System.StringComparison]::OrdinalIgnoreCase)) { $entry = $candidate; break }
            }
            if ($null -ne $entry) {
                $memberAddress = ([string](Get-TenureGraphProperty -InputObject $entry -Name 'PrimarySmtpAddress')).Trim()
                if (-not $memberAddress) {
                    $userTarget = @{ Kind = 'mailbox'; Id = $wanted.UserId; Name = $wanted.UserId }
                    $memberAddress = Resolve-TenureExchangeMailboxAddress -Target $userTarget -Current $null -Context $Context -Command 'Get-EXOMailbox' -Provider 'DistributionGroup.Member'
                }
                $parameters['Member'] = $memberAddress
                try {
                    Invoke-TenureExchange -Command 'Remove-DistributionGroupMember' -Parameters $parameters | Out-Null
                } catch {
                    # Not a member: the goal state.
                    if (-not (Test-TenureExchangeError -ErrorRecord $_ -Like "*isn't a member*")) { throw }
                }
            }
        }
        # Read back the user we just changed, whatever the plan's subject is.
        $readContext = ConvertTo-TenureTable -InputObject $Context
        $readContext['Subject'] = @{ Id = $wanted.UserId }
        & (Get-TenureProviderDefinition -Name 'DistributionGroup.Member').Get $Target $readContext
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $label = Get-TenureExchangeTargetLabel -Target $Target
        try {
            $wanted = ConvertTo-TenureDistributionMemberDesired -Desired $Desired
        } catch {
            return "$Action membership of distribution group ${label}: invalid desired state"
        }
        $user = Format-TenureExchangeSnippet -Text $wanted.UserId -MaxLength 80
        if ($wanted.Member) { "$Action user $user into distribution group $label" } else { "$Action user $user out of distribution group $label" }
    }
}
