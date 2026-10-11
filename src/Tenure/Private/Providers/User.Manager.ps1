# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

$null = Register-TenureProvider -Definition @{
    Name        = 'User.Manager'
    Kind        = 'State'
    Backend     = 'Graph'
    Scopes      = @('User.ReadWrite.All')
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Update', 'Remove', 'NoOp')
    Description = 'Sets or clears a user''s manager. Desired: @{ managerId = <object id or $null> }.'

    # Graph answers 404 both for "no manager" and for "no such user". A 404 is followed by a read of the user,
    # so a missing user is Tenure.Provider.TargetNotFound (SPEC 2.2) and only a missing manager reads as $null.
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Manager'
        $segment = ConvertTo-TenureUriSegment -Value $id
        $managerId = $null
        try {
            $manager = Invoke-TenureGraph -Method GET -Uri ('users/' + $segment + '/manager?$select=id')
            $managerId = Get-TenureGraphProperty -InputObject $manager -Name 'id'
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
            try {
                Invoke-TenureGraph -Method GET -Uri ('users/' + $segment + '?$select=id') | Out-Null
            } catch {
                if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                    throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.Manager'; Identity = $id } -Inner $_)
                }
                throw
            }
        }
        [pscustomobject]@{ managerId = $managerId }
    }

    Test        = {
        param($Current, $Desired)
        if ($null -eq $Current) { return $false }
        $actual = [string](Get-TenureGraphProperty -InputObject $Current -Name 'managerId')
        $wanted = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'managerId')
        return [string]::Equals($actual, $wanted, [System.StringComparison]::OrdinalIgnoreCase)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Manager'
        $managerId = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'managerId')
        $uri = 'users/' + (ConvertTo-TenureUriSegment -Value $id) + '/manager/$ref'
        if ($managerId) {
            Invoke-TenureGraph -Method PUT -Uri $uri -Body @{ '@odata.id' = 'https://graph.microsoft.com/v1.0/users/' + (ConvertTo-TenureUriSegment -Value $managerId) } | Out-Null
        } else {
            try {
                Invoke-TenureGraph -Method DELETE -Uri $uri | Out-Null
            } catch {
                # Already no manager: the goal state.
                if ((Get-TenureErrorId -ErrorRecord $_) -ne 'Tenure.Graph.NotFound') { throw }
            }
        }
        & (Get-TenureProviderDefinition -Name 'User.Manager').Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        $managerId = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'managerId')
        if ($managerId) { "$Action manager of $name to $managerId" } else { "$Action manager of $name to none" }
    }
}
