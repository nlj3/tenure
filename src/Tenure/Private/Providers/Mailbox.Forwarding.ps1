# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureForwardingDesired {
    <#
    .SYNOPSIS
        Validates Mailbox.Forwarding Desired. Returns @{ Address = <lowercase smtp or $null>; Deliver = [bool] }.
    .DESCRIPTION
        An empty or $null address means "no forwarding". With no forwarding the
        keep-a-copy flag has no effect, so it is always $false then (Set writes $false,
        Test expects $false); otherwise Set and Test would disagree.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    Assert-TenureExchangeDesiredKey -Desired $Desired -Allowed @('forwardingSmtpAddress', 'deliverToMailboxAndForward') -Provider 'Mailbox.Forwarding'
    $raw = Get-TenureGraphProperty -InputObject $Desired -Name 'forwardingSmtpAddress'
    if ($null -ne $raw -and $raw -isnot [string]) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "Mailbox.Forwarding needs Desired.forwardingSmtpAddress as one address or `$null (got $($raw.GetType().Name))." -Category InvalidArgument -Data @{ Provider = 'Mailbox.Forwarding'; Key = 'forwardingSmtpAddress' })
    }
    $address = ConvertTo-TenureExchangeSmtp -Value $raw
    if ($null -ne $address -and -not (Test-TenureExchangeSmtp -Address $address)) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "Mailbox.Forwarding needs Desired.forwardingSmtpAddress as one SMTP address (got '$(Format-TenureExchangeSnippet -Text $raw -MaxLength 60)')." -Category InvalidArgument -Data @{ Provider = 'Mailbox.Forwarding'; Key = 'forwardingSmtpAddress' })
    }
    $deliver = Get-TenureExchangeDesiredBool -Desired $Desired -Name 'deliverToMailboxAndForward' -Provider 'Mailbox.Forwarding'
    if ($null -eq $address) { $deliver = $false }
    @{ Address = $address; Deliver = $deliver }
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Mailbox.Forwarding'
    Kind        = 'State'
    Backend     = 'Exchange'
    Scopes      = @()
    Risk        = 'Medium'
    Reversible  = $true
    TargetKind  = 'mailbox'
    Actions     = @('Update', 'NoOp')
    Description = 'Forwards a mailbox to one SMTP address (optionally keeping a copy), or turns forwarding off. Clears the internal ForwardingAddress, which would otherwise override the SMTP forward.'

    # Target: @{ Kind = 'mailbox'; Id = <Entra user id>; Name = <UPN> }
    # Desired: @{ forwardingSmtpAddress = <address> | $null; deliverToMailboxAndForward = <bool> }
    # Reads by Entra id (-ExternalDirectoryObjectId); the write names the mailbox by its UPN (see ExchangeHelpers.ps1).
    Get         = {
        param($Target, $Context)
        $mailbox = Read-TenureExchangeMailbox -Target $Target -Context $Context -Command 'Get-EXOMailbox' -Property @('ForwardingAddress', 'ForwardingSmtpAddress', 'DeliverToMailboxAndForward') -Provider 'Mailbox.Forwarding'
        $internal = [string](Get-TenureGraphProperty -InputObject $mailbox -Name 'ForwardingAddress')
        [pscustomobject]@{
            forwardingSmtpAddress      = ConvertTo-TenureExchangeSmtp -Value (Get-TenureGraphProperty -InputObject $mailbox -Name 'ForwardingSmtpAddress')
            forwardingAddress          = $(if ([string]::IsNullOrWhiteSpace($internal)) { $null } else { $internal.Trim() })
            deliverToMailboxAndForward = ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $mailbox -Name 'DeliverToMailboxAndForward') -Name 'DeliverToMailboxAndForward'
        }
    }

    # Exchange ignores ForwardingSmtpAddress while ForwardingAddress is set, so a set ForwardingAddress
    # means mail goes somewhere the plan did not say: never satisfied.
    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureForwardingDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        if (-not [string]::IsNullOrWhiteSpace([string](Get-TenureGraphProperty -InputObject $Current -Name 'forwardingAddress'))) { return $false }
        $actual = ConvertTo-TenureExchangeSmtp -Value (Get-TenureGraphProperty -InputObject $Current -Name 'forwardingSmtpAddress')
        if ($null -eq $wanted.Address) {
            if ($null -ne $actual) { return $false }
        } elseif ($null -eq $actual -or -not [string]::Equals($actual, $wanted.Address, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        $deliver = ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $Current -Name 'deliverToMailboxAndForward') -Name 'deliverToMailboxAndForward'
        return ($deliver -eq $wanted.Deliver)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureForwardingDesired -Desired $Desired
        $address = Resolve-TenureExchangeMailboxAddress -Target $Target -Current $Current -Context $Context -Command 'Get-EXOMailbox' -Provider 'Mailbox.Forwarding'
        # Both forwarding fields are always written: ForwardingAddress overrides ForwardingSmtpAddress in Exchange.
        $parameters = @{ Identity = $address; ForwardingSmtpAddress = $wanted.Address; ForwardingAddress = $null; DeliverToMailboxAndForward = $wanted.Deliver }
        Invoke-TenureExchange -Command 'Set-Mailbox' -Parameters $parameters | Out-Null
        & (Get-TenureProviderDefinition -Name 'Mailbox.Forwarding').Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $label = Get-TenureExchangeTargetLabel -Target $Target
        try {
            $wanted = ConvertTo-TenureForwardingDesired -Desired $Desired
        } catch {
            return "$Action forwarding on ${label}: invalid desired state"
        }
        $text = if ($null -eq $wanted.Address) {
            "$Action forwarding on ${label}: turn forwarding off"
        } elseif ($wanted.Deliver) {
            "$Action forwarding on ${label}: forward to $(Format-TenureExchangeSnippet -Text $wanted.Address -MaxLength 100) and keep a copy in the mailbox"
        } else {
            "$Action forwarding on ${label}: forward to $(Format-TenureExchangeSnippet -Text $wanted.Address -MaxLength 100) without keeping a copy"
        }
        $internal = [string](Get-TenureGraphProperty -InputObject $Current -Name 'forwardingAddress')
        if (-not [string]::IsNullOrWhiteSpace($internal)) {
            $text += " (clears ForwardingAddress $(Format-TenureExchangeSnippet -Text $internal -MaxLength 60))"
        }
        $text
    }
}
