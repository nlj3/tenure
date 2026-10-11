# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

# After a failed POST the user is looked up again. A user found then is someone else's account (its password is
# discarded) only when Graph dates it, by createdDateTime, more than this many seconds before the POST began;
# the margin covers clock skew and whole-second dates. When createdDateTime is missing or unreadable the user is
# taken to be this create's and the password is kept.
$script:UserCreateLandedWindowSeconds = 30

$null = Register-TenureProvider -Definition @{
    Name        = 'User.Create'
    Kind        = 'State'
    Backend     = 'Graph'
    Scopes      = @('User.ReadWrite.All')
    Risk        = 'High'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Create', 'NoOp')
    Description = 'Creates a cloud user with a generated one-time password. The password is returned as a SecureString on the apply result only.'

    # Target: @{ Kind = 'user'; Id = <the UPN, which does not exist yet>; Name }
    Get         = {
        param($Target, $Context)
        $upn = Get-TenureTargetId -Target $Target -Provider 'User.Create'
        # createdDateTime lets the apply engine tell, on resume, an account this plan created from one that was
        # there before it ran.
        $select = 'id,userPrincipalName,displayName,mailNickname,givenName,surname,usageLocation,department,jobTitle,officeLocation,accountEnabled,createdDateTime'
        try {
            $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $upn) + '?$select=' + $select)
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$upn' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.Create'; Identity = $upn } -Inner $_)
            }
            throw
        }
        [pscustomobject]@{
            id                = Get-TenureGraphProperty -InputObject $user -Name 'id'
            userPrincipalName = Get-TenureGraphProperty -InputObject $user -Name 'userPrincipalName'
            displayName       = Get-TenureGraphProperty -InputObject $user -Name 'displayName'
            mailNickname      = Get-TenureGraphProperty -InputObject $user -Name 'mailNickname'
            givenName         = Get-TenureGraphProperty -InputObject $user -Name 'givenName'
            surname           = Get-TenureGraphProperty -InputObject $user -Name 'surname'
            usageLocation     = Get-TenureGraphProperty -InputObject $user -Name 'usageLocation'
            department        = Get-TenureGraphProperty -InputObject $user -Name 'department'
            jobTitle          = Get-TenureGraphProperty -InputObject $user -Name 'jobTitle'
            officeLocation    = Get-TenureGraphProperty -InputObject $user -Name 'officeLocation'
            accountEnabled    = Get-TenureGraphProperty -InputObject $user -Name 'accountEnabled'
            createdDateTime   = Get-TenureGraphProperty -InputObject $user -Name 'createdDateTime'
        }
    }

    Test        = {
        param($Current, $Desired)
        if ($null -eq $Current) { return $false }
        $wanted = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'userPrincipalName')
        $actual = [string](Get-TenureGraphProperty -InputObject $Current -Name 'userPrincipalName')
        return (($wanted.Length -gt 0) -and [string]::Equals($actual, $wanted, [System.StringComparison]::OrdinalIgnoreCase))
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureTable -InputObject $Desired
        foreach ($required in 'userPrincipalName', 'displayName', 'mailNickname') {
            if ([string]::IsNullOrWhiteSpace([string]$wanted[$required])) {
                throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "User.Create needs a value for '$required'." -Category InvalidArgument -Data @{ Provider = 'User.Create'; Key = $required })
            }
        }
        $upn = [string]$wanted['userPrincipalName']

        # Refuse before generating anything: a password with nowhere to go would be lost.
        if ($Context -isnot [System.Collections.IDictionary] -or $Context['Secrets'] -isnot [System.Collections.IDictionary]) {
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message 'User.Create needs Context.Secrets so the generated password can be handed back; none was supplied.' -Category InvalidOperation -Data @{ Provider = 'User.Create' })
        }
        $length = 20
        $configured = Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Policy') -Name 'Defaults') -Name 'passwordLength'
        if ($null -ne $configured -and $configured -is [ValueType]) { $length = [math]::Min(128, [math]::Max(12, [int]$configured)) }
        $stepId = [string](Get-TenureGraphProperty -InputObject $Context -Name 'StepId')
        $secretKey = if ($stepId) { $stepId } else { $upn }

        $body = [ordered]@{}
        foreach ($name in 'userPrincipalName', 'displayName', 'mailNickname', 'givenName', 'surname', 'usageLocation', 'department', 'jobTitle', 'officeLocation') {
            $value = $wanted[$name]
            if ($null -ne $value -and [string]$value -ne '') { $body[$name] = $value }
        }
        $body['accountEnabled'] = $true

        # Evidence for a failed create below: was the UPN already taken before this POST? It never decides whether
        # to POST (Graph's POST is the authority on uniqueness); it only tells a duplicate apart from our own create.
        $lookup = 'users/' + (ConvertTo-TenureUriSegment -Value $upn) + '?$select=id,userPrincipalName,createdDateTime'
        $existedBefore = $false
        try {
            Invoke-TenureGraph -Method GET -Uri $lookup | Out-Null
            $existedBefore = $true
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
        }

        $secret = New-TenurePassword -Length $length
        $Context['Secrets'][$secretKey] = $secret
        # The plaintext is held by this hashtable, built on the line that needs it, and by the JSON string the seam
        # serializes from it, until the request returns; the hashtable entry is cleared right after. The seam never
        # logs a body.
        $passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = (ConvertFrom-TenureSecureString -SecureString $secret) }
        $body['passwordProfile'] = $passwordProfile
        $started = [datetime]::UtcNow
        $created = $null
        try {
            $created = Invoke-TenureGraph -Method POST -Uri 'users' -Body $body
        } catch {
            $failure = $_
            # The seam retries a POST after 429 and 5xx, so a create can land and still error. The password is discarded only if
            # the account existed before this POST (someone else's). A 404 or failed lookup proves nothing (reads lag), so the
            # password is kept and the original error stands: keeping it costs nothing for an absent user, discarding it loses a live credential for an existing one.
            $verdict = 'Unknown'
            if ($existedBefore) {
                $verdict = 'NotOurs'
            } else {
                try {
                    $found = Invoke-TenureGraph -Method GET -Uri $lookup
                    $createdAt = $null
                    # ConvertTo-TenureUtcDateString is defined in User.LeaveDate.ps1.
                    try { $createdAt = ConvertTo-TenureUtcDateString -Value (Get-TenureGraphProperty -InputObject $found -Name 'createdDateTime') -Provider 'User.Create' -Key 'createdDateTime' } catch { $createdAt = $null }
                    $old = $null -ne $createdAt -and [datetime]::Parse($createdAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) -lt $started.AddSeconds(-$script:UserCreateLandedWindowSeconds)
                    if ($old) {
                        $verdict = 'NotOurs'
                    } else {
                        $verdict = 'Ours'
                        $created = $found
                    }
                } catch {
                    $verdict = 'Unknown'
                }
            }
            if ($verdict -eq 'Ours') {
                Write-Verbose ("User.Create: the create request for '{0}' reported failure, but the user now exists; it was created by this request and its password is kept." -f $upn)
            } elseif ($verdict -eq 'NotOurs') {
                # The account was someone else's before this POST: this password never reached it.
                $Context['Secrets'].Remove($secretKey)
                throw $failure
            } else {
                # Cannot tell whether the create landed: keep the password, which may be the only copy, and report the failure.
                throw $failure
            }
        } finally {
            $passwordProfile['password'] = $null
            $body.Remove('passwordProfile')
        }

        $newId = [string](Get-TenureGraphProperty -InputObject $created -Name 'id')
        $newTarget = @{ Kind = 'user'; Id = $newId; Name = $upn }
        $provider = Get-TenureProviderDefinition -Name 'User.Create'
        # Directory replication: a user created a moment ago can answer 404 for a few seconds. Retry the read
        # (never the create) with the seam's backoff. The password stays in Context.Secrets either way: the user exists.
        $maxRetry = 3
        for ($attempt = 0; ; $attempt++) {
            try {
                return (& $provider.Get $newTarget $Context)
            } catch {
                if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Provider.TargetNotFound') { throw }
                if ($attempt -ge $maxRetry -or -not $newId) {
                    throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$upn' was created (id '$newId') but could not be read back after $attempt retries; its password is on the apply result. Run the plan again to continue." -Category ObjectNotFound -Data @{ Provider = 'User.Create'; Identity = $newId } -Inner $_)
                }
                $delay = [int][math]::Pow(2, $attempt + 1)
                Write-Verbose ("User.Create: '{0}' is not readable yet (replication), retry {1}/{2} after {3} s" -f $upn, ($attempt + 1), $maxRetry, $delay)
                Start-Sleep -Seconds $delay
            }
        }
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $upn = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'userPrincipalName')
        if (-not $upn) { $upn = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Id') }
        $displayName = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'displayName')
        $line = "$Action user $upn"
        if ($displayName) { $line += " ($displayName)" }
        $line
    }
}
