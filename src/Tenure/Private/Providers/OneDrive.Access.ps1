# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

$null = Register-TenureProvider -Definition @{
    Name        = 'OneDrive.Access'
    Kind        = 'State'
    Backend     = 'Graph'
    Scopes      = @('Files.ReadWrite.All')
    Risk        = 'Medium'
    Reversible  = $true
    TargetKind  = 'drive'
    Actions     = @('Update', 'Remove', 'NoOp')
    Description = 'Grants or removes one person''s direct access to the root of a user''s OneDrive (Graph invite with no invitation email). Set only touches the plan subject''s own OneDrive.'

    # Target: @{ Kind = 'drive'; Id = <Entra user id of the OneDrive owner>; Name = <owner UPN> }
    # Desired: @{ granteeEmail = <address>; role = 'write' | 'read'; present = <bool, default $true> }
    # Grantees are read from direct permissions on the drive root. Sharing links (no single
    # recipient address) are not listed and never removed.
    Get         = {
        param($Target, $Context)
        $userId = Get-TenureTargetId -Target $Target -Provider 'OneDrive.Access'
        try {
            $drive = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $userId) + '/drive?$select=id,driveType,webUrl')
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$userId' has no OneDrive (it was never provisioned) or does not exist." -Category ObjectNotFound -Data @{ Provider = 'OneDrive.Access'; Identity = $userId } -Inner $_)
            }
            throw
        }
        $driveId = [string](Get-TenureGraphProperty -InputObject $drive -Name 'id')
        if ([string]::IsNullOrWhiteSpace($driveId)) {
            throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "Graph returned no drive id for user '$userId'." -Category ObjectNotFound -Data @{ Provider = 'OneDrive.Access'; Identity = $userId })
        }
        try {
            $permissions = @(Invoke-TenureGraph -Method GET -Uri ('drives/' + (ConvertTo-TenureUriSegment -Value $driveId) + '/root/permissions') -All)
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "The OneDrive of user '$userId' ($driveId) could not be read." -Category ObjectNotFound -Data @{ Provider = 'OneDrive.Access'; Identity = $userId } -Inner $_)
            }
            throw
        }

        $grantees = [System.Collections.Generic.List[object]]::new()
        foreach ($permission in $permissions) {
            # Graph puts the address in one of several places depending on how the permission was made.
            $email = $null
            foreach ($path in 'grantedToV2.user', 'grantedToV2.siteUser', 'grantedTo.user', 'invitation') {
                $node = $permission
                foreach ($segment in $path.Split('.')) { $node = Get-TenureGraphProperty -InputObject $node -Name $segment }
                $candidate = [string](Get-TenureGraphProperty -InputObject $node -Name 'email')
                if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                    $email = $candidate.Trim().ToLowerInvariant()
                    break
                }
            }
            if (-not $email) { continue }
            $roleSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($role in @(Get-TenureGraphProperty -InputObject $permission -Name 'roles')) {
                if (-not [string]::IsNullOrWhiteSpace([string]$role)) { $null = $roleSet.Add(([string]$role).Trim().ToLowerInvariant()) }
            }
            $roles = [string[]]::new($roleSet.Count)
            $roleSet.CopyTo($roles)
            [System.Array]::Sort($roles, [System.StringComparer]::Ordinal)
            $grantees.Add([pscustomobject]@{
                    email        = $email
                    roles        = $roles
                    permissionId = [string](Get-TenureGraphProperty -InputObject $permission -Name 'id')
                })
        }
        # Ordinal sort: the plan fingerprint must not depend on the culture of the machine that applies it.
        $byEmailThenId = [System.Comparison[object]] {
            param($left, $right)
            $order = [string]::CompareOrdinal([string]$left.email, [string]$right.email)
            if ($order -eq 0) { $order = [string]::CompareOrdinal([string]$left.permissionId, [string]$right.permissionId) }
            $order
        }
        $grantees.Sort($byEmailThenId)

        $webUrl = Get-TenureGraphProperty -InputObject $drive -Name 'webUrl'
        [pscustomobject]@{
            driveId  = $driveId
            webUrl   = $(if ($null -eq $webUrl) { $null } else { [string]$webUrl })
            grantees = $grantees.ToArray()
        }
    }

    # present $true: some grantee with that address (any case) holds the role or a stronger one.
    # present $false: no grantee with that address at all, whatever its role.
    Test        = {
        param($Current, $Desired)
        if ($null -eq $Current) { return $false }
        $email = ([string](Get-TenureGraphProperty -InputObject $Desired -Name 'granteeEmail')).Trim()
        if (-not $email) { return $false }
        $present = Get-TenureGraphProperty -InputObject $Desired -Name 'present' -Default $true
        if ($null -eq $present) { $present = $true }
        if ($present -isnot [bool]) { return $false }

        $matching = @(@(Get-TenureGraphProperty -InputObject $Current -Name 'grantees') | Where-Object {
                $null -ne $_ -and [string]::Equals([string](Get-TenureGraphProperty -InputObject $_ -Name 'email'), $email, [System.StringComparison]::OrdinalIgnoreCase)
            })
        if (-not $present) { return ($matching.Count -eq 0) }

        $role = ([string](Get-TenureGraphProperty -InputObject $Desired -Name 'role')).Trim().ToLowerInvariant()
        $accepted = switch ($role) {
            'write' { @('write', 'owner') }
            'read' { @('read', 'write', 'owner') }
            default { @() }
        }
        foreach ($grantee in $matching) {
            foreach ($held in @(Get-TenureGraphProperty -InputObject $grantee -Name 'roles')) {
                if ([string]$held -in $accepted) { return $true }
            }
        }
        return $false
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $provider = Get-TenureProviderDefinition -Name 'OneDrive.Access'

        # 1. Desired. Unknown keys are refused: a misspelt 'present' would otherwise default to a grant.
        $options = ConvertTo-TenureTable -InputObject $Desired
        foreach ($key in @($options.Keys)) {
            if ([string]$key -notin 'granteeEmail', 'role', 'present') {
                throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "OneDrive.Access does not accept Desired.$key (allowed: granteeEmail, role, present)." -Category InvalidArgument -Data @{ Provider = 'OneDrive.Access'; Key = [string]$key })
            }
        }
        $email = ([string]$options['granteeEmail']).Trim()
        if ($email -cnotmatch '^[^@\s]+@[^@\s]+$') {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'OneDrive.Access needs Desired.granteeEmail to be an email address.' -Category InvalidArgument -Data @{ Provider = 'OneDrive.Access'; Key = 'granteeEmail' })
        }
        $present = $true
        if ($null -ne $options['present']) {
            if ($options['present'] -isnot [bool]) {
                throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'OneDrive.Access needs Desired.present to be a boolean.' -Category InvalidArgument -Data @{ Provider = 'OneDrive.Access'; Key = 'present' })
            }
            $present = $options['present']
        }
        $role = ([string]$options['role']).Trim().ToLowerInvariant()
        if ($present -and $role -cnotin 'write', 'read') {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "OneDrive.Access needs Desired.role to be 'write' or 'read' when granting." -Category InvalidArgument -Data @{ Provider = 'OneDrive.Access'; Key = 'role' })
        }

        # 2. Only the plan subject's own OneDrive. A grant on someone else's drive would expose that
        #    person's files, so it never goes out, whatever the plan says.
        $ownerId = Get-TenureTargetId -Target $Target -Provider 'OneDrive.Access'
        $subjectId = [string](Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Subject') -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($subjectId) -or -not [string]::Equals($ownerId, $subjectId, [System.StringComparison]::OrdinalIgnoreCase)) {
            $shownSubject = if ($subjectId) { $subjectId } else { 'none' }
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message "Refusing to change OneDrive access: the drive belongs to $ownerId, but the plan subject is $shownSubject. OneDrive.Access only changes the subject's own OneDrive." -Data @{ Provider = 'OneDrive.Access'; DriveOwnerId = $ownerId; SubjectId = $subjectId })
        }

        # 3. Fresh read (drive id and permission ids); nothing to do when already satisfied.
        $current = & $provider.Get $Target $Context
        if (& $provider.Test $current $Desired) { return $current }
        $driveSegment = ConvertTo-TenureUriSegment -Value ([string]$current.driveId)

        if ($present) {
            # Direct permission, no email to the grantee; the grantee must sign in to open anything.
            $body = @{ recipients = @(@{ email = $email }); roles = @($role); requireSignIn = $true; sendInvitation = $false }
            try {
                Invoke-TenureGraph -Method POST -Uri ('drives/' + $driveSegment + '/root/invite') -Body $body | Out-Null
            } catch {
                # Graph answers 400 when the grantee already holds this permission: the goal state.
                $already = (Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.Failed' -and [int]$_.Exception.Data['StatusCode'] -eq 400 -and $_.Exception.Message -match 'already exist'
                if (-not $already) { throw }
            }
        } else {
            $matching = @(@($current.grantees) | Where-Object { $null -ne $_ -and [string]::Equals([string]$_.email, $email, [System.StringComparison]::OrdinalIgnoreCase) })
            # Check every match before deleting any, so a refusal leaves the drive untouched.
            foreach ($grantee in $matching) {
                if (@($grantee.roles) -contains 'owner') {
                    throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message "Refusing to remove $email from the OneDrive of ${ownerId}: that grantee holds the owner role." -Data @{ Provider = 'OneDrive.Access'; DriveOwnerId = $ownerId; Grantee = $email })
                }
                if ([string]::IsNullOrWhiteSpace([string]$grantee.permissionId)) {
                    throw (New-TenureError -Id 'Tenure.Provider.Unsupported' -Message "A permission for $email on the OneDrive of $ownerId has no id, so it cannot be removed here." -Category NotImplemented -Data @{ Provider = 'OneDrive.Access'; DriveOwnerId = $ownerId; Grantee = $email })
                }
            }
            foreach ($grantee in $matching) {
                try {
                    Invoke-TenureGraph -Method DELETE -Uri ('drives/' + $driveSegment + '/root/permissions/' + (ConvertTo-TenureUriSegment -Value ([string]$grantee.permissionId))) | Out-Null
                } catch {
                    # Already gone: the goal state.
                    if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
                }
            }
        }

        & $provider.Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $owner = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        if (-not $owner) { $owner = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Id') }
        $email = ([string](Get-TenureGraphProperty -InputObject $Desired -Name 'granteeEmail')).Trim()
        if (-not $email) { $email = '(no grantee)' }
        $present = Get-TenureGraphProperty -InputObject $Desired -Name 'present' -Default $true
        if ($present -is [bool] -and -not $present) {
            "remove $email's access to $owner's OneDrive"
        } else {
            $role = ([string](Get-TenureGraphProperty -InputObject $Desired -Name 'role')).Trim().ToLowerInvariant()
            if (-not $role) { $role = '(no role)' }
            "grant $email $role access to $owner's OneDrive (no invitation email)"
        }
    }
}
