# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function Get-TenureGroupMemberFlag {
    # Desired.member as a real boolean, or Tenure.Provider.InvalidDesired. [bool]'false' is $true in PowerShell,
    # so a hand-edited plan saying "false" must not quietly become an add; a missing key must not become a removal.
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][object]$Desired)

    $member = Get-TenureGraphProperty -InputObject $Desired -Name 'member'
    if ($member -isnot [bool]) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'Group.Member needs Desired.member as $true or $false.' -Category InvalidArgument -Data @{ Provider = 'Group.Member'; Key = 'member' })
    }
    $member
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Group.Member'
    Kind        = 'State'
    Backend     = 'Graph'
    Scopes      = @('GroupMember.ReadWrite.All', 'Group.Read.All')
    Risk        = 'Medium'
    Reversible  = $true
    TargetKind  = 'group'
    Actions     = @('Update', 'Remove', 'NoOp')
    Description = 'Adds or removes one user in a Graph-managed group. Dynamic groups and Exchange-managed groups (distribution lists, mail-enabled security groups) are refused, and so is an add to a role-assignable group: Tenure never grants a directory role, directly or through a group.'

    # Target: @{ Kind = 'group'; Id = <group id>; Name = <display name> }
    # Desired: @{ userId = <object id>; member = <bool> }
    # Get has no Desired, so the user is Context.Subject.Id (New-TenureStep, the apply engine and Test-TenurePlan set
    # it to the step's Desired.userId, the user it changes); without one, member reads as $false. While a plan
    # is built for a user an earlier step creates, Subject.Id is the {{subjectId}} placeholder: that user cannot
    # be a member yet, so member is $false without asking, and the snapshot names the user by the placeholder.
    # Context.MemberOf, when a builder passes it, holds the ids of the groups users/{id}/memberOf listed; a
    # 404 on the member route for one of those groups contradicts it, and the read is refused rather than
    # taken as "not a member".
    Get         = {
        param($Target, $Context)
        $groupId = Get-TenureTargetId -Target $Target -Provider 'Group.Member'
        $segment = ConvertTo-TenureUriSegment -Value $groupId
        try {
            $group = Invoke-TenureGraph -Method GET -Uri ('groups/' + $segment + '?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,isAssignableToRole')
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "Group '$groupId' does not exist." -Category ObjectNotFound -Data @{ Provider = 'Group.Member'; Identity = $groupId } -Inner $_)
            }
            throw
        }
        $info = ConvertTo-TenureGroupInfo -Group $group
        $userId = [string](Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Subject') -Name 'Id')
        $member = $false
        if ($userId -and $userId.Trim() -ieq '{{subjectId}}') {
            $userId = '{{subjectId}}'
        } elseif ($userId) {
            try {
                Invoke-TenureGraph -Method GET -Uri ('groups/' + $segment + '/members/' + (ConvertTo-TenureUriSegment -Value $userId) + '?$select=id') | Out-Null
                $member = $true
            } catch {
                if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
                $listed = @(Get-TenureGraphProperty -InputObject $Context -Name 'MemberOf' | Where-Object { $null -ne $_ })
                if (@($listed | Where-Object { [string]::Equals([string]$_, $groupId, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) {
                    throw (New-TenureError -Id 'Tenure.Provider.InconsistentState' -Message "Graph disagrees with itself about user '$userId' in group '$($info.DisplayName)' ($groupId): the user's memberOf lists the group, but the group's member route answers 404. Refusing to treat that as 'not a member'; wait a few minutes for directory replication and build the plan again." -Category InvalidResult -Data @{ Provider = 'Group.Member'; GroupId = $groupId; UserId = $userId })
                }
            }
        }
        [pscustomobject]@{
            userId             = $(if ($userId) { $userId } else { $null })
            member             = $member
            isDynamic          = $info.IsDynamic
            isExchangeManaged  = $info.IsExchangeManaged
            isAssignableToRole = $info.IsAssignableToRole
        }
    }

    Test        = {
        param($Current, $Desired)
        $wantMember = Get-TenureGroupMemberFlag -Desired $Desired
        if ($null -eq $Current) { return $false }
        # Dynamic membership comes from the group's rule; there is nothing to change by hand, so the step is a
        # NoOp (SPEC 5.1 step 14). Exchange-managed groups are NOT treated this way: a step routed here by
        # mistake must fail loudly in Set rather than pass as satisfied.
        $dynamic = Get-TenureGraphProperty -InputObject $Current -Name 'isDynamic'
        if ($dynamic -is [bool] -and $dynamic) { return $true }
        $wantedUser = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'userId')
        $actualUser = [string](Get-TenureGraphProperty -InputObject $Current -Name 'userId')
        # Get reads the subject's membership; if Desired names someone else the answer says nothing about them.
        if ($wantedUser -and $actualUser -and -not [string]::Equals($wantedUser, $actualUser, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        return ([bool](Get-TenureGraphProperty -InputObject $Current -Name 'member' -Default $false) -eq $wantMember)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $groupId = Get-TenureTargetId -Target $Target -Provider 'Group.Member'
        $segment = ConvertTo-TenureUriSegment -Value $groupId
        $userId = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'userId')
        if (-not $userId) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'Group.Member needs Desired.userId.' -Category InvalidArgument -Data @{ Provider = 'Group.Member'; Key = 'userId' })
        }
        $wantMember = Get-TenureGroupMemberFlag -Desired $Desired
        # A member of a role-assignable group holds the group's directory roles, and Tenure never grants a role. The
        # state just read says so before any request; the group read below says so again before the write.
        $refuseRoleGroup = {
            param([string]$Name)
            throw (New-TenureError -Id 'Tenure.Provider.Unsupported' -Message "Refusing to add user '$userId' to group '$Name' ($groupId): the group is role-assignable, so its members hold directory roles, and Tenure never grants a directory role, directly or through role-assignable groups." -Category InvalidOperation -Data @{ Provider = 'Group.Member'; GroupId = $groupId; UserId = $userId })
        }
        if ($wantMember -and (Get-TenureGraphProperty -InputObject $Current -Name 'isAssignableToRole') -eq $true) { & $refuseRoleGroup ([string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')) }

        try {
            $group = Invoke-TenureGraph -Method GET -Uri ('groups/' + $segment + '?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,isAssignableToRole')
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "Group '$groupId' does not exist." -Category ObjectNotFound -Data @{ Provider = 'Group.Member'; Identity = $groupId } -Inner $_)
            }
            throw
        }
        $info = ConvertTo-TenureGroupInfo -Group $group
        if ($info.IsDynamic) {
            throw (New-TenureError -Id 'Tenure.Provider.Unsupported' -Message "Group '$($info.DisplayName)' has dynamic membership; its members come from a rule and cannot be changed here." -Category NotImplemented -Data @{ Provider = 'Group.Member'; GroupId = $groupId })
        }
        if ($info.IsExchangeManaged) {
            throw (New-TenureError -Id 'Tenure.Provider.Unsupported' -Message "Group '$($info.DisplayName)' is a distribution list or mail-enabled security group; Graph cannot change its membership, use Exchange Online." -Category NotImplemented -Data @{ Provider = 'Group.Member'; GroupId = $groupId })
        }
        if ($wantMember -and $info.IsAssignableToRole) { & $refuseRoleGroup ([string]$info.DisplayName) }

        if ($wantMember) {
            try {
                Invoke-TenureGraph -Method POST -Uri ('groups/' + $segment + '/members/$ref') -Body @{ '@odata.id' = 'https://graph.microsoft.com/v1.0/directoryObjects/' + (ConvertTo-TenureUriSegment -Value $userId) } | Out-Null
            } catch {
                # Already a member: Graph answers 400 "... already exist ...". That is the goal state; nothing else is.
                $data = $_.Exception.Data
                if (-not ($data['StatusCode'] -eq 400 -and [string]$data['Message'] -match 'already exist')) { throw }
            }
        } else {
            try {
                Invoke-TenureGraph -Method DELETE -Uri ('groups/' + $segment + '/members/' + (ConvertTo-TenureUriSegment -Value $userId) + '/$ref') | Out-Null
            } catch {
                # Not a member: the goal state.
                if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
            }
        }

        # Read back the user we just changed, whatever the plan's subject is.
        $readContext = ConvertTo-TenureTable -InputObject $Context
        $readContext['Subject'] = @{ Id = $userId }
        & (Get-TenureProviderDefinition -Name 'Group.Member').Get $Target $readContext
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        $userId = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'userId')
        $line = if (Get-TenureGroupMemberFlag -Desired $Desired) { "$Action user $userId in group $name" } else { "$Action user $userId out of group $name" }
        $dynamic = Get-TenureGraphProperty -InputObject $Current -Name 'isDynamic'
        if ($dynamic -is [bool] -and $dynamic) { $line += " (dynamic membership: the group's rule decides)" }
        $line
    }
}
