# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureMailboxTypeDesired {
    # Validates Mailbox.Type Desired and returns 'Shared' or 'Regular' (canonical case).
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Desired)

    Assert-TenureExchangeDesiredKey -Desired $Desired -Allowed @('type') -Provider 'Mailbox.Type'
    $value = Get-TenureGraphProperty -InputObject $Desired -Name 'type'
    if ($value -is [string]) {
        foreach ($allowed in 'Shared', 'Regular') {
            if ($value.Trim() -ieq $allowed) { return $allowed }
        }
    }
    throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "Mailbox.Type needs Desired.type 'Shared' or 'Regular' (got '$(Format-TenureExchangeSnippet -Text $value -MaxLength 40)')." -Category InvalidArgument -Data @{ Provider = 'Mailbox.Type'; Key = 'type' })
}

function ConvertTo-TenureMailboxTypeName {
    # RecipientTypeDetails -> 'Shared' | 'Regular'; anything else is reported raw so a room or equipment mailbox is visible, not hidden.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][string]$RecipientTypeDetails)

    if ([string]::IsNullOrWhiteSpace($RecipientTypeDetails)) { return $null }
    $value = $RecipientTypeDetails.Trim()
    if ($value -ieq 'SharedMailbox') { return 'Shared' }
    if ($value -ieq 'UserMailbox') { return 'Regular' }
    $value
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Mailbox.Type'
    Kind        = 'State'
    Backend     = 'Exchange'
    Scopes      = @()
    Risk        = 'High'
    Reversible  = $true
    TargetKind  = 'mailbox'
    Actions     = @('Update', 'NoOp')
    Description = 'Converts a mailbox between a regular (user) mailbox and a shared mailbox. Other mailbox types (room, equipment) are reported as they are and never converted.'

    # Target: @{ Kind = 'mailbox'; Id = <Entra user id>; Name = <UPN> }
    # Desired: @{ type = 'Shared' | 'Regular' }
    # Reads by Entra id (-ExternalDirectoryObjectId); writes name the mailbox by its UPN (see ExchangeHelpers.ps1).
    Get         = {
        param($Target, $Context)
        $mailbox = Read-TenureExchangeMailbox -Target $Target -Context $Context -Command 'Get-EXOMailbox' -Property @('RecipientTypeDetails') -Provider 'Mailbox.Type'
        $upn = [string](Get-TenureGraphProperty -InputObject $mailbox -Name 'UserPrincipalName')
        [pscustomobject]@{
            identity          = Get-TenureExchangeObjectId -InputObject $mailbox
            userPrincipalName = $(if ($upn) { $upn.ToLowerInvariant() } else { $null })
            type              = ConvertTo-TenureMailboxTypeName -RecipientTypeDetails ([string](Get-TenureGraphProperty -InputObject $mailbox -Name 'RecipientTypeDetails'))
        }
    }

    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureMailboxTypeDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        $actual = [string](Get-TenureGraphProperty -InputObject $Current -Name 'type')
        return [string]::Equals($actual, $wanted, [System.StringComparison]::Ordinal)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureMailboxTypeDesired -Desired $Desired
        $id = Get-TenureTargetId -Target $Target -Provider 'Mailbox.Type'
        $provider = Get-TenureProviderDefinition -Name 'Mailbox.Type'
        $state = $Current
        if ($null -eq $state) { $state = & $provider.Get $Target $Context }
        $type = [string](Get-TenureGraphProperty -InputObject $state -Name 'type')
        # Only user and shared mailboxes are converted; a room, equipment or other mailbox is never touched.
        if ($type -cnotin 'Shared', 'Regular') {
            throw (New-TenureError -Id 'Tenure.Provider.Unsupported' -Message "Mailbox '$(Get-TenureExchangeTargetLabel -Target $Target)' is a '$(Format-TenureExchangeSnippet -Text $type -MaxLength 40)' mailbox; Mailbox.Type converts only user and shared mailboxes." -Category NotImplemented -Data @{ Provider = 'Mailbox.Type'; Identity = $id })
        }
        $address = Resolve-TenureExchangeMailboxAddress -Target $Target -Current $state -Context $Context -Command 'Get-EXOMailbox' -Provider 'Mailbox.Type'
        Invoke-TenureExchange -Command 'Set-Mailbox' -Parameters @{ Identity = $address; Type = $wanted } | Out-Null
        & $provider.Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $to = [string](Get-TenureGraphProperty -InputObject $Desired -Name 'type')
        $from = [string](Get-TenureGraphProperty -InputObject $Current -Name 'type')
        if (-not $from) { $from = '?' }
        if (-not $to) { $to = '?' }
        "$Action mailbox type of $(Get-TenureExchangeTargetLabel -Target $Target): $(Format-TenureExchangeSnippet -Text $from -MaxLength 40) -> $(Format-TenureExchangeSnippet -Text $to -MaxLength 40)"
    }
}
