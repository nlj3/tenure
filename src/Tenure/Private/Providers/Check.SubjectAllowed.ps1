# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function Get-TenureSubjectRefusal {
    <#
    .SYNOPSIS
        Why a user must not be acted on (the signed-in account, or protected by policy), or $null when they may be.
    .DESCRIPTION
        The signed-in account is compared with the user's user principal name and mail address;
        the protected list with the object id, user principal name and mail address
        (Find-TenureProtectedUser). A user without a user principal name is refused: the check
        fails closed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$User,
        [AllowNull()][AllowEmptyString()][string]$Account,
        [AllowNull()][AllowEmptyCollection()][object[]]$Protected
    )

    $upn = [string](Get-TenureGraphProperty -InputObject $User -Name 'userPrincipalName')
    if ([string]::IsNullOrWhiteSpace($upn)) { return 'the user has no user principal name' }
    $mail = [string](Get-TenureGraphProperty -InputObject $User -Name 'mail')
    $id = [string](Get-TenureGraphProperty -InputObject $User -Name 'id')
    $signedIn = ([string]$Account).Trim()
    if ($signedIn) {
        foreach ($value in $upn, $mail) {
            if (-not [string]::IsNullOrWhiteSpace($value) -and [string]::Equals($value.Trim(), $signedIn, [System.StringComparison]::OrdinalIgnoreCase)) {
                return 'subject is the signed-in account'
            }
        }
    }
    $entry = Find-TenureProtectedUser -Protected @($Protected) -Identity @($id, $upn, $mail)
    if ($entry) { return "subject is protected by policy (protectedUsers entry '$entry')" }
    $null
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Check.SubjectAllowed'
    Kind        = 'Check'
    Backend     = 'Graph'
    Scopes      = @('User.Read.All')
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Check', 'NoOp')
    AffectedBy  = @()
    Severity    = 'Refuse'
    Description = 'Refuses to act on the signed-in account or on a user the policy lists in defaults.protectedUsers, by object id, user principal name or mail address (self-protection, SPEC section 8).'

    # Target: @{ Kind = 'user'; Id = <subject id>; Name = <subject UPN> }
    # Desired: not used. The signed-in account comes from Context.Session and the protected list from
    # Context.ProtectedUsers (the apply engine passes the -Policy list or the one the plan recorded), else
    # from Context.Policy. Neither is stored in the snapshot: it holds who the subject is and the verdict
    # ('refusal', $null when allowed), so a different administrator, or a protected list that changed for
    # someone else, does not drift the step, while a subject that has become protected does.
    # A protectedUsers entry may name the user by object id, user principal name or mail address
    # (Find-TenureProtectedUser), so the snapshot carries all three.
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'Check.SubjectAllowed'
        try {
            $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '?$select=id,userPrincipalName,mail')
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'Check.SubjectAllowed'; Identity = $id } -Inner $_)
            }
            throw
        }
        $account = [string](Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Session') -Name 'Account')
        $protected = $null
        if ($Context -is [System.Collections.IDictionary] -and $Context.Contains('ProtectedUsers')) {
            $protected = @($Context['ProtectedUsers'])
        } else {
            $defaults = Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Policy') -Name 'Defaults'
            $protected = @(Get-TenureGraphProperty -InputObject $defaults -Name 'protectedUsers')
        }
        $mail = [string](Get-TenureGraphProperty -InputObject $user -Name 'mail')
        $identity = [pscustomobject]@{
            id                = Get-TenureGraphProperty -InputObject $user -Name 'id'
            userPrincipalName = Get-TenureGraphProperty -InputObject $user -Name 'userPrincipalName'
            mail              = $(if ([string]::IsNullOrWhiteSpace($mail)) { $null } else { $mail })
        }
        $identity | Add-Member -MemberType NoteProperty -Name 'refusal' -Value (Get-TenureSubjectRefusal -User $identity -Account $account -Protected $protected)
        $identity
    }

    # Fails closed: a snapshot without a subject UPN, or one that carries a refusal, never passes.
    Test        = {
        param($Current, $Desired)
        if ($null -eq $Current) { return $false }
        if ([string]::IsNullOrWhiteSpace([string](Get-TenureGraphProperty -InputObject $Current -Name 'userPrincipalName'))) { return $false }
        $refusal = Get-TenureGraphProperty -InputObject $Current -Name 'refusal'
        return ($null -eq $refusal -or ([string]$refusal).Length -eq 0)
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        $refusal = [string](Get-TenureGraphProperty -InputObject $Current -Name 'refusal')
        if ([string]::IsNullOrWhiteSpace([string](Get-TenureGraphProperty -InputObject $Current -Name 'userPrincipalName'))) { $refusal = 'the user has no user principal name' }
        if ($refusal) { return "Refusing $name as a subject: $refusal" }
        "$name is allowed as a subject: not the signed-in account and not protected by policy"
    }
}
