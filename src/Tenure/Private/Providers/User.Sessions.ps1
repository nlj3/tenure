# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

$null = Register-TenureProvider -Definition @{
    Name        = 'User.Sessions'
    Kind        = 'Invoke'
    Backend     = 'Graph'
    # User.Read.All covers the read of the user; the revoke itself needs User.RevokeSessions.All.
    Scopes      = @('User.RevokeSessions.All', 'User.Read.All')
    Risk        = 'Medium'
    Reversible  = $false
    TargetKind  = 'user'
    Actions     = @('Invoke')
    Repeatable  = $true
    Description = 'Revokes every refresh token and browser session of a user (revokeSignInSessions). Access tokens already issued stay valid until they expire. Desired is ignored.'

    # The snapshot names the user only. signInSessionsValidFromDateTime is left out: the revoke itself moves it, so a
    # resumed run, or a second plan for the same user, would read its own earlier revoke as drift.
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Sessions'
        try {
            $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '?$select=id,userPrincipalName')
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.Sessions'; Identity = $id } -Inner $_)
            }
            throw
        }
        [pscustomobject]@{
            id                = Get-TenureGraphProperty -InputObject $user -Name 'id'
            userPrincipalName = Get-TenureGraphProperty -InputObject $user -Name 'userPrincipalName'
        }
    }

    # Invoke providers are never "satisfied": idempotency comes from the step status (SPEC section 2.2).
    Test        = {
        param($Current, $Desired)
        return $false
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Sessions'
        $response = Invoke-TenureGraph -Method POST -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '/revokeSignInSessions')
        # Graph answers { value: true }. An explicit false means nothing was revoked; never report that as done.
        $value = Get-TenureGraphProperty -InputObject $response -Name 'value'
        if ($value -is [bool] -and -not $value) {
            throw (New-TenureError -Id 'Tenure.Provider.UnexpectedResponse' -Message "Graph answered revokeSignInSessions for '$id' with value = false; the sessions were not revoked." -Category InvalidResult -Data @{ Provider = 'User.Sessions'; Identity = $id })
        }
        & (Get-TenureProviderDefinition -Name 'User.Sessions').Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        "$Action sessions of ${name}: revoke all sign-in sessions (refresh tokens; access tokens expire within an hour)"
    }
}
