# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureHiddenDesired {
    # Validates Mailbox.Hidden Desired and returns the wanted HiddenFromAddressListsEnabled value.
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][object]$Desired)

    Assert-TenureExchangeDesiredKey -Desired $Desired -Allowed @('hiddenFromAddressLists') -Provider 'Mailbox.Hidden'
    Get-TenureExchangeDesiredBool -Desired $Desired -Name 'hiddenFromAddressLists' -Provider 'Mailbox.Hidden' -Required
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Mailbox.Hidden'
    Kind        = 'State'
    Backend     = 'Exchange'
    Scopes      = @()
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'mailbox'
    Actions     = @('Update', 'NoOp')
    Description = 'Hides a mailbox from the address lists (the global address list), or shows it again.'

    # Target: @{ Kind = 'mailbox'; Id = <Entra user id>; Name = <UPN> }
    # Desired: @{ hiddenFromAddressLists = <bool> }
    # Reads by Entra id (-ExternalDirectoryObjectId); the write names the mailbox by its UPN (see ExchangeHelpers.ps1).
    Get         = {
        param($Target, $Context)
        $mailbox = Read-TenureExchangeMailbox -Target $Target -Context $Context -Command 'Get-EXOMailbox' -Property @('HiddenFromAddressListsEnabled') -Provider 'Mailbox.Hidden'
        $upn = [string](Get-TenureGraphProperty -InputObject $mailbox -Name 'UserPrincipalName')
        [pscustomobject]@{
            identity               = Get-TenureExchangeObjectId -InputObject $mailbox
            userPrincipalName      = $(if ($upn) { $upn.ToLowerInvariant() } else { $null })
            hiddenFromAddressLists = ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $mailbox -Name 'HiddenFromAddressListsEnabled') -Name 'HiddenFromAddressListsEnabled'
        }
    }

    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureHiddenDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        $actual = ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $Current -Name 'hiddenFromAddressLists') -Name 'hiddenFromAddressLists'
        return ($actual -eq $wanted)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureHiddenDesired -Desired $Desired
        $address = Resolve-TenureExchangeMailboxAddress -Target $Target -Current $Current -Context $Context -Command 'Get-EXOMailbox' -Provider 'Mailbox.Hidden'
        Invoke-TenureExchange -Command 'Set-Mailbox' -Parameters @{ Identity = $address; HiddenFromAddressListsEnabled = $wanted } | Out-Null
        & (Get-TenureProviderDefinition -Name 'Mailbox.Hidden').Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $label = Get-TenureExchangeTargetLabel -Target $Target
        try {
            $wanted = ConvertTo-TenureHiddenDesired -Desired $Desired
        } catch {
            return "$Action address list visibility of ${label}: invalid desired state"
        }
        if ($wanted) { "$Action address list visibility of ${label}: hide from address lists" } else { "$Action address list visibility of ${label}: show in address lists" }
    }
}
