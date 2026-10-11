# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenurePasswordDesired {
    # Desired -> @{ discard = [bool]; forceChangePasswordNextSignIn = [bool] }, both $true when absent or $null.
    # Only real booleans are accepted ([bool]'false' is $true in PowerShell). Any other key, including one named
    # 'password', is refused: a plan never carries a password, and the error names the key only, never a value.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $table = ConvertTo-TenureTable -InputObject $Desired
    $result = @{ discard = $true; forceChangePasswordNextSignIn = $true }
    foreach ($key in $table.Keys) {
        $match = @('discard', 'forceChangePasswordNextSignIn') | Where-Object { $_ -ieq $key } | Select-Object -First 1
        if (-not $match) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "User.Password does not take '$key'. Allowed: discard, forceChangePasswordNextSignIn." -Category InvalidArgument -Data @{ Provider = 'User.Password'; Key = [string]$key })
        }
        $value = $table[$key]
        if ($null -eq $value) { continue }
        if ($value -isnot [bool]) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "User.Password needs '$match' as `$true or `$false." -Category InvalidArgument -Data @{ Provider = 'User.Password'; Key = $match })
        }
        $result[$match] = $value
    }
    $result
}

$null = Register-TenureProvider -Definition @{
    Name        = 'User.Password'
    Kind        = 'Invoke'
    Backend     = 'Graph'
    # User.Read.All covers the read of lastPasswordChangeDateTime; the reset itself needs the password-profile scope.
    Scopes      = @('User-PasswordProfile.ReadWrite.All', 'User.Read.All')
    Risk        = 'High'
    Reversible  = $false
    TargetKind  = 'user'
    Actions     = @('Invoke')
    Description = 'Resets a user''s password to a generated value. With discard (the default, used for offboarding) nobody ever learns it; otherwise it is returned as a SecureString on the apply result only.'

    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Password'
        try {
            $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '?$select=id,userPrincipalName,lastPasswordChangeDateTime')
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.Password'; Identity = $id } -Inner $_)
            }
            throw
        }
        [pscustomobject]@{
            id                         = Get-TenureGraphProperty -InputObject $user -Name 'id'
            userPrincipalName          = Get-TenureGraphProperty -InputObject $user -Name 'userPrincipalName'
            # ConvertTo-TenureUtcDateString is defined in User.LeaveDate.ps1.
            lastPasswordChangeDateTime = ConvertTo-TenureUtcDateString -Value (Get-TenureGraphProperty -InputObject $user -Name 'lastPasswordChangeDateTime') -Provider 'User.Password' -Key 'lastPasswordChangeDateTime'
        }
    }

    # Invoke providers are never "satisfied": idempotency comes from the step status (SPEC section 2.2).
    Test        = {
        param($Current, $Desired)
        return $false
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenurePasswordDesired -Desired $Desired
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Password'
        $keep = -not $wanted['discard']
        $secretKey = $null
        if ($keep) {
            # Refuse before generating or sending anything: a password nobody can collect would lock the user out.
            if ($Context -isnot [System.Collections.IDictionary] -or $Context['Secrets'] -isnot [System.Collections.IDictionary]) {
                throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message 'User.Password with discard = $false needs Context.Secrets so the new password can be handed back; none was supplied.' -Category InvalidOperation -Data @{ Provider = 'User.Password' })
            }
            $stepId = [string](Get-TenureGraphProperty -InputObject $Context -Name 'StepId')
            $secretKey = if ($stepId) { $stepId } else { $id }
        }
        $length = 20
        $configured = Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Policy') -Name 'Defaults') -Name 'passwordLength'
        if ($null -ne $configured -and $configured -is [ValueType]) { $length = [math]::Min(128, [math]::Max(12, [int]$configured)) }

        $secret = New-TenurePassword -Length $length
        $handedBack = $false
        try {
            # The plaintext exists only inside this hashtable, built on the line that needs it, and is cleared right after the request.
            $passwordProfile = @{ forceChangePasswordNextSignIn = $wanted['forceChangePasswordNextSignIn']; password = (ConvertFrom-TenureSecureString -SecureString $secret) }
            $body = @{ passwordProfile = $passwordProfile }
            try {
                Invoke-TenureGraph -Method PATCH -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id)) -Body $body | Out-Null
            } finally {
                $passwordProfile['password'] = $null
                $body.Remove('passwordProfile')
            }
            # Only a reset Graph accepted is handed back; a failed one leaves nothing in Context.Secrets.
            if ($keep) {
                $Context['Secrets'][$secretKey] = $secret
                $handedBack = $true
            }
        } finally {
            # A discarded password, or one whose reset failed, is wiped from memory here.
            if (-not $handedBack) { $secret.Dispose() }
        }

        $state = & (Get-TenureProviderDefinition -Name 'User.Password').Get $Target $Context
        [pscustomobject]@{
            id                         = $state.id
            userPrincipalName          = $state.userPrincipalName
            lastPasswordChangeDateTime = $state.lastPasswordChangeDateTime
            discarded                  = -not $handedBack
        }
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $wanted = ConvertTo-TenurePasswordDesired -Desired $Desired
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        if ($wanted['discard']) { return "$Action password of ${name}: reset to a random password (discarded)" }
        $line = "$Action password of ${name}: reset to a random password (returned on the apply result)"
        if ($wanted['forceChangePasswordNextSignIn']) { $line += ', change required at next sign-in' }
        $line
    }
}
