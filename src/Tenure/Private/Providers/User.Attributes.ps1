# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

# Attributes this provider may change. Anything else in Desired is a typo or a different provider.
$script:UserAttributeKeys = @('department', 'jobTitle', 'officeLocation', 'displayName', 'givenName', 'surname', 'usageLocation', 'companyName', 'employeeId', 'employeeType')

function ConvertTo-TenureUserAttributeTable {
    # Normalizes Desired to a hashtable and throws Tenure.Provider.InvalidDesired for a key outside the allowed list.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $table = ConvertTo-TenureTable -InputObject $Desired
    $canonical = @{}
    foreach ($key in $table.Keys) {
        $match = $script:UserAttributeKeys | Where-Object { $_ -ieq $key } | Select-Object -First 1
        if (-not $match) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "User.Attributes cannot set '$key'. Allowed: $($script:UserAttributeKeys -join ', ')." -Category InvalidArgument -Data @{ Provider = 'User.Attributes'; Key = [string]$key })
        }
        $canonical[$match] = $table[$key]
    }
    $canonical
}

$null = Register-TenureProvider -Definition @{
    Name        = 'User.Attributes'
    Kind        = 'State'
    Backend     = 'Graph'
    Scopes      = @('User.ReadWrite.All')
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Update', 'NoOp')
    Description = 'Sets profile attributes on a user (department, job title, office, names, usage location, company, employee id and type).'

    # Get does not receive Desired, so it reads every allowed attribute; Test only compares the keys in Desired.
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Attributes'
        try {
            $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '?$select=id,' + ($script:UserAttributeKeys -join ','))
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.Attributes'; Identity = $id } -Inner $_)
            }
            throw
        }
        $state = [ordered]@{ id = Get-TenureGraphProperty -InputObject $user -Name 'id' }
        foreach ($key in $script:UserAttributeKeys) { $state[$key] = Get-TenureGraphProperty -InputObject $user -Name $key }
        [pscustomobject]$state
    }

    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureUserAttributeTable -Desired $Desired
        if ($null -eq $Current) { return $false }
        foreach ($key in $wanted.Keys) {
            $actual = [string](Get-TenureGraphProperty -InputObject $Current -Name $key)
            if (-not [string]::Equals($actual, [string]$wanted[$key], [System.StringComparison]::Ordinal)) { return $false }
        }
        return $true
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureUserAttributeTable -Desired $Desired
        $id = Get-TenureTargetId -Target $Target -Provider 'User.Attributes'
        if ($wanted.Count -gt 0) {
            Invoke-TenureGraph -Method PATCH -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id)) -Body $wanted | Out-Null
        }
        & (Get-TenureProviderDefinition -Name 'User.Attributes').Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $wanted = ConvertTo-TenureUserAttributeTable -Desired $Desired
        $pairs = @($wanted.Keys | Sort-Object | ForEach-Object { "$_=$($wanted[$_])" }) -join ', '
        "$Action attributes of $(Get-TenureGraphProperty -InputObject $Target -Name 'Name'): $pairs"
    }
}
