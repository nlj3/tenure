# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureTapDesired {
    # Desired -> @{ lifetimeInMinutes = [int] 10..43200 (default 480); isUsableOnce = [bool] (default $true) }.
    # $null values take the default. Only a real boolean is accepted for isUsableOnce ([bool]'false' is $true).
    # Any other key is refused; startDateTime is not supported, the pass is usable as soon as it is issued.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $table = ConvertTo-TenureTable -InputObject $Desired
    $result = @{ lifetimeInMinutes = 480; isUsableOnce = $true }
    foreach ($key in $table.Keys) {
        $match = @('lifetimeInMinutes', 'isUsableOnce') | Where-Object { $_ -ieq $key } | Select-Object -First 1
        if (-not $match) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "User.TemporaryAccessPass does not take '$key'. Allowed: lifetimeInMinutes, isUsableOnce." -Category InvalidArgument -Data @{ Provider = 'User.TemporaryAccessPass'; Key = [string]$key })
        }
        $value = $table[$key]
        if ($null -eq $value) { continue }
        if ($match -eq 'isUsableOnce') {
            if ($value -isnot [bool]) {
                throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'User.TemporaryAccessPass needs isUsableOnce as $true or $false.' -Category InvalidArgument -Data @{ Provider = 'User.TemporaryAccessPass'; Key = $match })
            }
            $result[$match] = $value
            continue
        }
        $whole = ($value -is [int] -or $value -is [long] -or $value -is [int16] -or $value -is [byte] -or (($value -is [double] -or $value -is [decimal]) -and [math]::Floor($value) -eq $value))
        if (-not $whole -or $value -lt 10 -or $value -gt 43200) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'User.TemporaryAccessPass needs lifetimeInMinutes as a whole number from 10 to 43200.' -Category InvalidArgument -Data @{ Provider = 'User.TemporaryAccessPass'; Key = $match })
        }
        $result[$match] = [int]$value
    }
    $result
}

$null = Register-TenureProvider -Definition @{
    Name        = 'User.TemporaryAccessPass'
    Kind        = 'Invoke'
    Backend     = 'Graph'
    Scopes      = @('UserAuthenticationMethod.ReadWrite.All')
    Risk        = 'High'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Invoke')
    Description = 'Issues a Temporary Access Pass. The pass is returned as a SecureString on the apply result only; Graph replaces any pass the user already had.'

    # Desired: @{ lifetimeInMinutes = 480; isUsableOnce = $true } (these defaults apply when a key is absent).
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.TemporaryAccessPass'
        try {
            $methods = @(Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '/authentication/temporaryAccessPassMethods') -All)
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.TemporaryAccessPass'; Identity = $id } -Inner $_)
            }
            throw
        }
        $usable = @($methods | Where-Object { [bool](Get-TenureGraphProperty -InputObject $_ -Name 'isUsable' -Default $false) })
        [pscustomobject]@{ existingCount = $methods.Count; hasUsable = ($usable.Count -gt 0) }
    }

    # Invoke providers are never "satisfied": idempotency comes from the step status.
    Test        = {
        param($Current, $Desired)
        return $false
    }

    # Returns the new method without its pass: @{ id; startDateTime; lifetimeInMinutes; isUsableOnce; methodUsabilityReason }.
    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureTapDesired -Desired $Desired
        $id = Get-TenureTargetId -Target $Target -Provider 'User.TemporaryAccessPass'
        # Refuse before sending: a pass with nowhere to go would be a live credential nobody can hand over.
        if ($Context -isnot [System.Collections.IDictionary] -or $Context['Secrets'] -isnot [System.Collections.IDictionary]) {
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message 'User.TemporaryAccessPass needs Context.Secrets so the pass can be handed back; none was supplied.' -Category InvalidOperation -Data @{ Provider = 'User.TemporaryAccessPass' })
        }
        $stepId = [string](Get-TenureGraphProperty -InputObject $Context -Name 'StepId')
        $secretKey = if ($stepId) { $stepId } else { $id }

        $created = Invoke-TenureGraph -Method POST -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '/authentication/temporaryAccessPassMethods') -Body @{ lifetimeInMinutes = $wanted['lifetimeInMinutes']; isUsableOnce = $wanted['isUsableOnce'] }
        $passProperty = if ($null -ne $created -and $created -isnot [string]) { $created.PSObject.Properties['temporaryAccessPass'] } else { $null }
        if ($null -eq $passProperty -or $passProperty.Value -isnot [string] -or $passProperty.Value.Length -eq 0) {
            throw (New-TenureError -Id 'Tenure.Provider.UnexpectedResponse' -Message "Graph created a Temporary Access Pass method for '$id' but returned no pass value; nothing can be handed back. Issue another pass." -Category InvalidResult -Data @{ Provider = 'User.TemporaryAccessPass'; Identity = $id })
        }
        # Wrapped on the line that reads it, then dropped from the response object; the plaintext is never logged, stored or returned.
        $Context['Secrets'][$secretKey] = ConvertTo-TenureSecureString -PlainText $passProperty.Value
        $created.PSObject.Properties.Remove('temporaryAccessPass')
        $passProperty = $null

        [pscustomobject]@{
            id                    = Get-TenureGraphProperty -InputObject $created -Name 'id'
            # ConvertTo-TenureUtcDateString is defined in User.LeaveDate.ps1.
            startDateTime         = ConvertTo-TenureUtcDateString -Value (Get-TenureGraphProperty -InputObject $created -Name 'startDateTime') -Provider 'User.TemporaryAccessPass' -Key 'startDateTime'
            lifetimeInMinutes     = Get-TenureGraphProperty -InputObject $created -Name 'lifetimeInMinutes'
            isUsableOnce          = Get-TenureGraphProperty -InputObject $created -Name 'isUsableOnce'
            methodUsabilityReason = Get-TenureGraphProperty -InputObject $created -Name 'methodUsabilityReason'
        }
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $wanted = ConvertTo-TenureTapDesired -Desired $Desired
        "$Action Temporary Access Pass for $(Get-TenureGraphProperty -InputObject $Target -Name 'Name') (lifetime $($wanted['lifetimeInMinutes']) minutes, usable once: $($wanted['isUsableOnce']))"
    }
}
