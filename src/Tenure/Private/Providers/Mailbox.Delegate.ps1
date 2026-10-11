# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureDelegateDesired {
    <#
    .SYNOPSIS
        Validates Mailbox.Delegate Desired. Returns @{ User = <lowercase UPN>; Present = [bool] }.
    .DESCRIPTION
        accessRights may be omitted or must be exactly FullAccess; present is required,
        so a grant is never the result of a missing key.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $provider = 'Mailbox.Delegate'
    Assert-TenureExchangeDesiredKey -Desired $Desired -Allowed @('user', 'accessRights', 'present') -Provider $provider
    $user = Get-TenureGraphProperty -InputObject $Desired -Name 'user'
    if ($user -isnot [string] -or [string]::IsNullOrWhiteSpace($user)) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$provider needs Desired.user (the UPN of the user who gets or loses access)." -Category InvalidArgument -Data @{ Provider = $provider; Key = 'user' })
    }
    $rights = @(ConvertTo-TenureExchangeStringList -Value (Get-TenureGraphProperty -InputObject $Desired -Name 'accessRights') -Split)
    if ($rights.Count -gt 0 -and -not ($rights.Count -eq 1 -and $rights[0] -ieq 'FullAccess')) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$provider grants only FullAccess (got '$(Format-TenureExchangeSnippet -Text ($rights -join ', ') -MaxLength 60)')." -Category InvalidArgument -Data @{ Provider = $provider; Key = 'accessRights' })
    }
    $present = Get-TenureExchangeDesiredBool -Desired $Desired -Name 'present' -Provider $provider -Required
    @{ User = $user.Trim().ToLowerInvariant(); Present = $present }
}

function Get-TenureDelegateGrantee {
    <#
    .SYNOPSIS
        Target.Grantee: the user whose access to the mailbox this step manages. Get has no Desired, so the grantee rides on the target.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Target)

    $grantee = Get-TenureGraphProperty -InputObject $Target -Name 'Grantee'
    if ($grantee -isnot [string] -or [string]::IsNullOrWhiteSpace($grantee)) {
        throw (New-TenureError -Id 'Tenure.Step.InvalidTarget' -Message 'Mailbox.Delegate needs Target.Grantee: the UPN of the user who gets or loses access to the mailbox (the same value as Desired.user).' -Category InvalidArgument -Data @{ Provider = 'Mailbox.Delegate' })
    }
    $grantee.Trim().ToLowerInvariant()
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Mailbox.Delegate'
    Kind        = 'State'
    Backend     = 'Exchange'
    Scopes      = @()
    Risk        = 'Medium'
    Reversible  = $true
    TargetKind  = 'mailbox'
    Actions     = @('Update', 'Remove', 'NoOp')
    Description = 'Grants or removes FullAccess on a mailbox for one user, always with automapping off.'

    # Target: @{ Kind = 'mailbox'; Id = <Entra user id of the mailbox>; Name = <mailbox UPN>; Grantee = <grantee UPN> }
    # Desired: @{ user = <grantee UPN>; accessRights = 'FullAccess'; present = <bool> }
    # Only explicit (not inherited) allow entries count; inherited and deny entries are not ours to change.
    # The mailbox is named by its UPN (read by Entra id first) and the grantee by Target.Grantee, a UPN;
    # either one answering "couldn't be found" is TargetNotFound.
    Get         = {
        param($Target, $Context)
        $null = Get-TenureTargetId -Target $Target -Provider 'Mailbox.Delegate'
        $grantee = Get-TenureDelegateGrantee -Target $Target
        $address = Resolve-TenureExchangeMailboxAddress -Target $Target -Current $null -Context $Context -Command 'Get-EXOMailbox' -Provider 'Mailbox.Delegate'
        $entries = @(Invoke-TenureExchangeRead -Command 'Get-EXOMailboxPermission' -Parameters @{ Identity = $address; User = $grantee } -Provider 'Mailbox.Delegate' -Identity $address -NotFoundName @($address, $grantee))
        $rights = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $entries) {
            if (ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $entry -Name 'IsInherited') -Name 'IsInherited') { continue }
            if (ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $entry -Name 'Deny') -Name 'Deny') { continue }
            foreach ($right in @(ConvertTo-TenureExchangeStringList -Value (Get-TenureGraphProperty -InputObject $entry -Name 'AccessRights') -Split)) { $rights.Add($right) }
        }
        $sorted = [string[]]@(ConvertTo-TenureExchangeStringList -Value $rights.ToArray())
        [pscustomobject]@{
            user         = $grantee
            accessRights = $sorted
            present      = [bool](@($sorted | Where-Object { $_ -ieq 'FullAccess' }).Count -gt 0)
        }
    }

    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureDelegateDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        # Get reads one grantee; a snapshot of someone else says nothing about this one.
        $user = [string](Get-TenureGraphProperty -InputObject $Current -Name 'user')
        if (-not [string]::Equals($user, $wanted.User, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        $present = ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $Current -Name 'present') -Name 'present'
        return ($present -eq $wanted.Present)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureDelegateDesired -Desired $Desired
        $null = Get-TenureTargetId -Target $Target -Provider 'Mailbox.Delegate'
        $grantee = Get-TenureDelegateGrantee -Target $Target
        # The engine reads the result back through Get, which reads Target.Grantee: refuse before writing if they differ.
        if (-not [string]::Equals($grantee, $wanted.User, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "Mailbox.Delegate: Desired.user '$(Format-TenureExchangeSnippet -Text $wanted.User -MaxLength 80)' is not Target.Grantee '$(Format-TenureExchangeSnippet -Text $grantee -MaxLength 80)'." -Category InvalidArgument -Data @{ Provider = 'Mailbox.Delegate'; Key = 'user' })
        }
        $address = Resolve-TenureExchangeMailboxAddress -Target $Target -Current $Current -Context $Context -Command 'Get-EXOMailbox' -Provider 'Mailbox.Delegate'
        $parameters = @{ Identity = $address; User = $wanted.User; AccessRights = 'FullAccess'; InheritanceType = 'All'; Confirm = $false }
        if ($wanted.Present) {
            $parameters['AutoMapping'] = $false
            try {
                Invoke-TenureExchange -Command 'Add-MailboxPermission' -Parameters $parameters | Out-Null
            } catch {
                # The entry already exists: the goal state. The read-back below proves it.
                if (-not (Test-TenureExchangeError -ErrorRecord $_ -Like '*already present*', '*already exists*', '*already has*')) { throw }
            }
        } else {
            try {
                Invoke-TenureExchange -Command 'Remove-MailboxPermission' -Parameters $parameters | Out-Null
            } catch {
                # The entry is not there: the goal state. The read-back below proves it.
                if (-not (Test-TenureExchangeError -ErrorRecord $_ -Like "*isn't present*", '*not present*')) { throw }
            }
        }
        & (Get-TenureProviderDefinition -Name 'Mailbox.Delegate').Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $label = Get-TenureExchangeTargetLabel -Target $Target
        try {
            $wanted = ConvertTo-TenureDelegateDesired -Desired $Desired
        } catch {
            return "$Action mailbox access on ${label}: invalid desired state"
        }
        $user = Format-TenureExchangeSnippet -Text $wanted.User -MaxLength 100
        if ($wanted.Present) {
            "$Action mailbox access on ${label}: grant FullAccess to $user (automapping off)"
        } else {
            "$Action mailbox access on ${label}: remove FullAccess from $user"
        }
    }
}
