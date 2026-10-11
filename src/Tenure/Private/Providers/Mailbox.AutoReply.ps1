# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureAutoReplyDesired {
    <#
    .SYNOPSIS
        Validates Mailbox.AutoReply Desired. Returns @{ State; Internal; External; Audience } in canonical case.
    .DESCRIPTION
        Defaults: externalMessage = internalMessage, externalAudience = 'All'. An enabled
        auto-reply needs a non-empty internal message. A disabled one ignores the messages.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $provider = 'Mailbox.AutoReply'
    Assert-TenureExchangeDesiredKey -Desired $Desired -Allowed @('autoReplyState', 'internalMessage', 'externalMessage', 'externalAudience') -Provider $provider
    $pick = {
        param($name, [string[]]$allowed, $default)
        $value = Get-TenureGraphProperty -InputObject $Desired -Name $name
        if ($null -eq $value -and $null -ne $default) { return $default }
        if ($value -is [string]) {
            foreach ($candidate in $allowed) { if ($value.Trim() -ieq $candidate) { return $candidate } }
        }
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$provider needs Desired.$name as one of $($allowed -join ', ') (got '$(Format-TenureExchangeSnippet -Text $value -MaxLength 40)')." -Category InvalidArgument -Data @{ Provider = $provider; Key = $name })
    }
    $state = & $pick 'autoReplyState' @('Enabled', 'Disabled') $null
    $audience = & $pick 'externalAudience' @('All', 'Known', 'None') 'All'

    $messages = @{}
    foreach ($name in 'internalMessage', 'externalMessage') {
        $value = Get-TenureGraphProperty -InputObject $Desired -Name $name
        if ($null -ne $value -and $value -isnot [string]) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$provider needs Desired.$name as text (got $($value.GetType().Name))." -Category InvalidArgument -Data @{ Provider = $provider; Key = $name })
        }
        $messages[$name] = $value
    }
    $internal = $messages['internalMessage']
    $external = $messages['externalMessage']
    if ($null -eq $external) { $external = $internal }
    if ($state -ceq 'Enabled' -and $null -eq (ConvertTo-TenureExchangePlainText -Value $internal)) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$provider needs a non-empty Desired.internalMessage to enable an auto-reply." -Category InvalidArgument -Data @{ Provider = $provider; Key = 'internalMessage' })
    }
    @{ State = $state; Internal = $internal; External = $external; Audience = $audience }
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Mailbox.AutoReply'
    Kind        = 'State'
    Backend     = 'Exchange'
    Scopes      = @()
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'mailbox'
    Actions     = @('Update', 'NoOp')
    Description = 'Turns the automatic reply of a mailbox on (with internal and external messages and the external audience) or off.'

    # Target: @{ Kind = 'mailbox'; Id = <Entra user id>; Name = <UPN> }
    # Desired: @{ autoReplyState = 'Enabled' | 'Disabled'; internalMessage; externalMessage; externalAudience = 'All' | 'Known' | 'None' }
    # Exchange returns the messages wrapped in HTML, so Get reports them as plain text and Test
    # compares plain text with whitespace removed (see Get-TenureExchangeTextKey).
    # Get-MailboxAutoReplyConfiguration takes -Identity only, so the mailbox is named by its UPN, read by Entra id first.
    Get         = {
        param($Target, $Context)
        $address = Resolve-TenureExchangeMailboxAddress -Target $Target -Current $null -Context $Context -Command 'Get-EXOMailbox' -Provider 'Mailbox.AutoReply'
        $config = Invoke-TenureExchangeRead -Command 'Get-MailboxAutoReplyConfiguration' -Parameters @{ Identity = $address } -Provider 'Mailbox.AutoReply' -Identity $address -Single
        $state = [string](Get-TenureGraphProperty -InputObject $config -Name 'AutoReplyState')
        $audience = [string](Get-TenureGraphProperty -InputObject $config -Name 'ExternalAudience')
        [pscustomobject]@{
            autoReplyState   = $(if ($state) { $state } else { $null })
            internalMessage  = ConvertTo-TenureExchangePlainText -Value (Get-TenureGraphProperty -InputObject $config -Name 'InternalMessage')
            externalMessage  = ConvertTo-TenureExchangePlainText -Value (Get-TenureGraphProperty -InputObject $config -Name 'ExternalMessage')
            externalAudience = $(if ($audience) { $audience } else { $null })
        }
    }

    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureAutoReplyDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        $state = [string](Get-TenureGraphProperty -InputObject $Current -Name 'autoReplyState')
        if (-not [string]::Equals($state, $wanted.State, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        # A disabled auto-reply sends nothing, so its stored messages and audience do not matter.
        if ($wanted.State -ceq 'Disabled') { return $true }
        $audience = [string](Get-TenureGraphProperty -InputObject $Current -Name 'externalAudience')
        if (-not [string]::Equals($audience, $wanted.Audience, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
        $internal = Get-TenureExchangeTextKey -Value (Get-TenureGraphProperty -InputObject $Current -Name 'internalMessage')
        if (-not [string]::Equals($internal, (Get-TenureExchangeTextKey -Value $wanted.Internal), [System.StringComparison]::Ordinal)) { return $false }
        $external = Get-TenureExchangeTextKey -Value (Get-TenureGraphProperty -InputObject $Current -Name 'externalMessage')
        return [string]::Equals($external, (Get-TenureExchangeTextKey -Value $wanted.External), [System.StringComparison]::Ordinal)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureAutoReplyDesired -Desired $Desired
        $address = Resolve-TenureExchangeMailboxAddress -Target $Target -Current $Current -Context $Context -Command 'Get-EXOMailbox' -Provider 'Mailbox.AutoReply'
        $parameters = @{ Identity = $address; AutoReplyState = $wanted.State }
        if ($wanted.State -ceq 'Enabled') {
            $parameters['InternalMessage'] = $wanted.Internal
            $parameters['ExternalMessage'] = $wanted.External
            $parameters['ExternalAudience'] = $wanted.Audience
        }
        Invoke-TenureExchange -Command 'Set-MailboxAutoReplyConfiguration' -Parameters $parameters | Out-Null
        & (Get-TenureProviderDefinition -Name 'Mailbox.AutoReply').Get $Target $Context
    }

    # Message bodies are quoted at most 60 characters long (cut with '...').
    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $label = Get-TenureExchangeTargetLabel -Target $Target
        try {
            $wanted = ConvertTo-TenureAutoReplyDesired -Desired $Desired
        } catch {
            return "$Action auto-reply on ${label}: invalid desired state"
        }
        if ($wanted.State -ceq 'Disabled') { return "$Action auto-reply on ${label}: turn off" }
        $internal = Format-TenureExchangeSnippet -Text (ConvertTo-TenureExchangePlainText -Value $wanted.Internal) -MaxLength 60
        $text = "$Action auto-reply on ${label}: turn on, external audience $($wanted.Audience), message `"$internal`""
        if ((Get-TenureExchangeTextKey -Value $wanted.External) -cne (Get-TenureExchangeTextKey -Value $wanted.Internal)) {
            $external = Format-TenureExchangeSnippet -Text (ConvertTo-TenureExchangePlainText -Value $wanted.External) -MaxLength 60
            $text += ", external message `"$external`""
        }
        $text
    }
}
