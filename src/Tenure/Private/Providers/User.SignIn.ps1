# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureSignInDesired {
    # Desired -> @{ accountEnabled = [bool] }. Only a real boolean is accepted: [bool]'false' is $true in
    # PowerShell, and a hand-edited plan must not turn "disable" into "enable".
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $table = ConvertTo-TenureTable -InputObject $Desired
    foreach ($key in $table.Keys) {
        if ($key -ne 'accountEnabled') {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "User.SignIn cannot set '$key'. Allowed: accountEnabled." -Category InvalidArgument -Data @{ Provider = 'User.SignIn'; Key = [string]$key })
        }
    }
    $enabled = if ($table.ContainsKey('accountEnabled')) { $table['accountEnabled'] } else { $null }
    if ($enabled -isnot [bool]) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'User.SignIn needs Desired.accountEnabled as $true or $false.' -Category InvalidArgument -Data @{ Provider = 'User.SignIn'; Key = 'accountEnabled' })
    }
    @{ accountEnabled = $enabled }
}

$null = Register-TenureProvider -Definition @{
    Name        = 'User.SignIn'
    Kind        = 'State'
    Backend     = 'Graph'
    Scopes      = @('User.EnableDisableAccount.All', 'User.Read.All')
    Risk        = 'High'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Update', 'NoOp')
    Description = 'Enables or disables sign-in for a user (accountEnabled). Disabling stops new sign-ins; existing tokens are revoked by User.Sessions.'

    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.SignIn'
        try {
            $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '?$select=id,userPrincipalName,accountEnabled')
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.SignIn'; Identity = $id } -Inner $_)
            }
            throw
        }
        [pscustomobject]@{
            id                = Get-TenureGraphProperty -InputObject $user -Name 'id'
            userPrincipalName = Get-TenureGraphProperty -InputObject $user -Name 'userPrincipalName'
            accountEnabled    = Get-TenureGraphProperty -InputObject $user -Name 'accountEnabled'
        }
    }

    # A missing or non-boolean accountEnabled on the live side is never "satisfied".
    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureSignInDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        $actual = Get-TenureGraphProperty -InputObject $Current -Name 'accountEnabled'
        return (($actual -is [bool]) -and ($actual -eq $wanted['accountEnabled']))
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureSignInDesired -Desired $Desired
        $id = Get-TenureTargetId -Target $Target -Provider 'User.SignIn'
        Invoke-TenureGraph -Method PATCH -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id)) -Body @{ accountEnabled = $wanted['accountEnabled'] } | Out-Null
        & (Get-TenureProviderDefinition -Name 'User.SignIn').Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $wanted = ConvertTo-TenureSignInDesired -Desired $Desired
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        $actual = Get-TenureGraphProperty -InputObject $Current -Name 'accountEnabled'
        $from = if ($actual -is [bool]) { ([string]$actual).ToLowerInvariant() } else { 'unknown' }
        $to = ([string]$wanted['accountEnabled']).ToLowerInvariant()
        "$Action sign-in of $name (enabled: $from -> $to)"
    }
}
