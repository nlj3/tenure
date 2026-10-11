# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

# GET directoryRoles/{id}/members answers at most this many objects per response (Graph v1.0 docs).
$script:DirectoryRoleMemberPageLimit = 1000

function ConvertTo-TenureRoleMemberDesired {
    # Desired -> @{ userId = <non-empty string>; member = [bool] }. Only a real boolean is accepted for member:
    # [bool]'false' is $true in PowerShell, and a hand-edited plan must not turn a removal into a grant.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $table = ConvertTo-TenureTable -InputObject $Desired
    foreach ($key in $table.Keys) {
        if ($key -notin 'userId', 'member') {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "DirectoryRole.Member does not take '$key'. Allowed: userId, member." -Category InvalidArgument -Data @{ Provider = 'DirectoryRole.Member'; Key = [string]$key })
        }
    }
    $userId = if ($table.ContainsKey('userId')) { $table['userId'] } else { $null }
    if ($userId -isnot [string] -or [string]::IsNullOrWhiteSpace($userId) -or $userId.StartsWith('{{', [System.StringComparison]::Ordinal)) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'DirectoryRole.Member needs Desired.userId (the object id of an existing user).' -Category InvalidArgument -Data @{ Provider = 'DirectoryRole.Member'; Key = 'userId' })
    }
    $member = if ($table.ContainsKey('member')) { $table['member'] } else { $null }
    if ($member -isnot [bool]) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'DirectoryRole.Member needs Desired.member as $true or $false.' -Category InvalidArgument -Data @{ Provider = 'DirectoryRole.Member'; Key = 'member' })
    }
    @{ userId = $userId; member = $member }
}

function Get-TenureDirectoryRole {
    # GET directoryRoles/{id}; a 404 is Tenure.Provider.TargetNotFound (the role is not activated or the id is wrong).
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)][string]$RoleId)

    try {
        Invoke-TenureGraph -Method GET -Uri ('directoryRoles/' + (ConvertTo-TenureUriSegment -Value $RoleId) + '?$select=id,displayName,roleTemplateId')
    } catch {
        if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
            throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "Directory role '$RoleId' does not exist or is not activated in this tenant." -Category ObjectNotFound -Data @{ Provider = 'DirectoryRole.Member'; Identity = $RoleId } -Inner $_)
        }
        throw
    }
}

$null = Register-TenureProvider -Definition @{
    Name        = 'DirectoryRole.Member'
    Kind        = 'State'
    Backend     = 'Graph'
    Scopes      = @('RoleManagement.ReadWrite.Directory')
    Risk        = 'High'
    Reversible  = $true
    TargetKind  = 'role'
    # Remove and NoOp only: Tenure takes directory roles away and never grants one (Set refuses an add).
    Actions     = @('Remove', 'NoOp')
    Description = 'Removes one user as a direct, active member of an activated directory role. Tenure never grants a directory role: an add (member = $true) is refused. PIM-eligible assignments and roles held through a role-assignable group are not seen or changed here.'

    # Target: @{ Kind = 'role'; Id = <activated directoryRole id>; Name = <role display name> }
    # Desired: @{ userId = <object id>; member = <bool> }
    # Get has no Desired, so the user is Context.Subject.Id; without one, member reads as $false and userId as $null.
    # New-TenureStep, the apply engine and Test-TenurePlan set Subject.Id to the step's Desired.userId (the user it changes).
    # Context.MemberOf, when a builder passes it, holds the ids users/{id}/memberOf listed; a "not a member"
    # answer for a role listed there contradicts it, and the read is refused.
    Get         = {
        param($Target, $Context)
        $roleId = Get-TenureTargetId -Target $Target -Provider 'DirectoryRole.Member'
        $segment = ConvertTo-TenureUriSegment -Value $roleId
        $role = Get-TenureDirectoryRole -RoleId $roleId
        $userId = [string](Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Subject') -Name 'Id')
        $member = $false
        if ($userId) {
            # The documented way to read role membership is the member list; search it for the user.
            $members = @(Invoke-TenureGraph -Method GET -Uri ('directoryRoles/' + $segment + '/members?$select=id') -All)
            foreach ($entry in $members) {
                if ([string]::Equals([string](Get-TenureGraphProperty -InputObject $entry -Name 'id'), $userId, [System.StringComparison]::OrdinalIgnoreCase)) { $member = $true; break }
            }
            # A full page may be a truncated answer. "Not a member" must never rest on a list that might be cut
            # short, so ask about the user directly; anything but a 404 is an error, not a "no".
            if (-not $member -and $members.Count -ge $script:DirectoryRoleMemberPageLimit) {
                try {
                    Invoke-TenureGraph -Method GET -Uri ('directoryRoles/' + $segment + '/members/' + (ConvertTo-TenureUriSegment -Value $userId) + '?$select=id') | Out-Null
                    $member = $true
                } catch {
                    if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
                }
            }
            if (-not $member) {
                $listed = @(Get-TenureGraphProperty -InputObject $Context -Name 'MemberOf' | Where-Object { $null -ne $_ })
                if (@($listed | Where-Object { [string]::Equals([string]$_, $roleId, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) {
                    throw (New-TenureError -Id 'Tenure.Provider.InconsistentState' -Message "Graph disagrees with itself about user '$userId' in directory role '$(Get-TenureGraphProperty -InputObject $role -Name 'displayName')' ($roleId): the user's memberOf lists the role, but the role's members do not include the user. Refusing to treat that as 'not a member'; wait a few minutes for directory replication and build the plan again." -Category InvalidResult -Data @{ Provider = 'DirectoryRole.Member'; RoleId = $roleId; UserId = $userId })
                }
            }
        }
        [pscustomobject]@{
            roleId         = Get-TenureGraphProperty -InputObject $role -Name 'id'
            displayName    = Get-TenureGraphProperty -InputObject $role -Name 'displayName'
            roleTemplateId = Get-TenureGraphProperty -InputObject $role -Name 'roleTemplateId'
            userId         = $(if ($userId) { $userId } else { $null })
            member         = $member
        }
    }

    # Satisfied only for a read about the same user: an answer about nobody (or someone else) never counts.
    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureRoleMemberDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        $actualUser = [string](Get-TenureGraphProperty -InputObject $Current -Name 'userId')
        if (-not [string]::Equals($actualUser, $wanted['userId'], [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        $actual = Get-TenureGraphProperty -InputObject $Current -Name 'member'
        return (($actual -is [bool]) -and ($actual -eq $wanted['member']))
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureRoleMemberDesired -Desired $Desired
        $roleId = Get-TenureTargetId -Target $Target -Provider 'DirectoryRole.Member'
        # Granting a role is the most dangerous thing a plan could do, and no Tenure operation needs it, so the
        # provider cannot do it: whatever a plan's step says (even a resealed one labelled Remove), nothing is sent.
        if ($wanted['member']) {
            throw (New-TenureError -Id 'Tenure.Provider.Unsupported' -Message "Refusing to add user '$($wanted['userId'])' to directory role '$roleId': Tenure removes directory roles and never grants them. Grant a role in Entra ID (or through Privileged Identity Management) yourself." -Category InvalidOperation -Data @{ Provider = 'DirectoryRole.Member'; RoleId = $roleId; UserId = $wanted['userId'] })
        }
        $segment = ConvertTo-TenureUriSegment -Value $roleId
        $userSegment = ConvertTo-TenureUriSegment -Value $wanted['userId']
        # Confirm the role first, so a 404 on the write below can only be about the membership.
        Get-TenureDirectoryRole -RoleId $roleId | Out-Null

        try {
            Invoke-TenureGraph -Method DELETE -Uri ('directoryRoles/' + $segment + '/members/' + $userSegment + '/$ref') | Out-Null
        } catch {
            # Not a member (the role exists, checked above): the goal state. The read-back below confirms it.
            if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
        }

        # Read back the user we just changed, whatever the plan's subject is.
        $readContext = ConvertTo-TenureTable -InputObject $Context
        $readContext['Subject'] = @{ Id = $wanted['userId'] }
        & (Get-TenureProviderDefinition -Name 'DirectoryRole.Member').Get $Target $readContext
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $wanted = ConvertTo-TenureRoleMemberDesired -Desired $Desired
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        if ($wanted['member']) { "$Action user $($wanted['userId']) into directory role $name (refused: Tenure removes directory roles and never grants them)" } else { "$Action user $($wanted['userId']) out of directory role $name" }
    }
}
