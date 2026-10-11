# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureCancelMeetingsWindow {
    # Validates Calendar.CancelMeetings Desired and returns queryWindowInDays (default 120, whole days 1 to 1825).
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowNull()][object]$Desired)

    Assert-TenureExchangeDesiredKey -Desired $Desired -Allowed @('queryWindowInDays') -Provider 'Calendar.CancelMeetings'
    $raw = Get-TenureGraphProperty -InputObject $Desired -Name 'queryWindowInDays'
    if ($null -eq $raw) { return 120 }
    $days = ConvertTo-TenureExchangeInteger -Value $raw
    if ($null -eq $days -or $days -lt 1 -or $days -gt 1825) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "Calendar.CancelMeetings needs Desired.queryWindowInDays as a whole number from 1 to 1825 (got '$(Format-TenureExchangeSnippet -Text $raw -MaxLength 40)')." -Category InvalidArgument -Data @{ Provider = 'Calendar.CancelMeetings'; Key = 'queryWindowInDays' })
    }
    [int]$days
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Calendar.CancelMeetings'
    Kind        = 'Invoke'
    Backend     = 'Exchange'
    Scopes      = @()
    Risk        = 'Destructive'
    Reversible  = $false
    TargetKind  = 'mailbox'
    Actions     = @('Invoke')
    Repeatable  = $true
    Description = 'Cancels every meeting the mailbox owner organized from today for the given number of days. Canceled meetings cannot be restored.'

    # Target: @{ Kind = 'mailbox'; Id = <Entra user id>; Name = <UPN> }
    # Desired: @{ queryWindowInDays = 120 }  (1 to 1825)
    # Get only proves the mailbox exists and names it; the step's idempotency is its status (SPEC section 2.2).
    # Reads by Entra id (-ExternalDirectoryObjectId); Remove-CalendarEvents names the mailbox by its UPN.
    Get         = {
        param($Target, $Context)
        $mailbox = Read-TenureExchangeMailbox -Target $Target -Context $Context -Command 'Get-EXOMailbox' -Property @('RecipientTypeDetails') -Provider 'Calendar.CancelMeetings'
        $upn = [string](Get-TenureGraphProperty -InputObject $mailbox -Name 'UserPrincipalName')
        [pscustomobject]@{
            identity          = Get-TenureExchangeObjectId -InputObject $mailbox
            userPrincipalName = $(if ($upn) { $upn.ToLowerInvariant() } else { $null })
        }
    }

    # Invoke providers are never "satisfied": an Applied step is skipped on resume instead.
    Test        = {
        param($Current, $Desired)
        return $false
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $days = ConvertTo-TenureCancelMeetingsWindow -Desired $Desired
        $id = Get-TenureTargetId -Target $Target -Provider 'Calendar.CancelMeetings'
        $address = Resolve-TenureExchangeMailboxAddress -Target $Target -Current $Current -Context $Context -Command 'Get-EXOMailbox' -Provider 'Calendar.CancelMeetings'
        Invoke-TenureExchange -Command 'Remove-CalendarEvents' -Parameters @{ Identity = $address; CancelOrganizedMeetings = $true; QueryWindowInDays = $days; Confirm = $false } | Out-Null
        # No read-back: there is nothing to read, and a failed read after an irreversible call must not mark it failed.
        $identity = [string](Get-TenureGraphProperty -InputObject $Current -Name 'identity')
        [pscustomobject]@{
            identity                   = $(if ($identity) { $identity } else { $id.ToLowerInvariant() })
            cancelledOrganizedMeetings = $true
            queryWindowInDays          = $days
        }
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $label = Get-TenureExchangeTargetLabel -Target $Target
        try {
            $days = ConvertTo-TenureCancelMeetingsWindow -Desired $Desired
        } catch {
            return "Cancel all meetings organized by ${label}: invalid desired state"
        }
        $unit = if ($days -eq 1) { 'day' } else { 'days' }
        "Cancel all meetings organized by $label for the next $days $unit, irreversible"
    }
}
