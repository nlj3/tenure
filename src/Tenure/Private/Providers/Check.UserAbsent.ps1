# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

$null = Register-TenureProvider -Definition @{
    Name        = 'Check.UserAbsent'
    Kind        = 'Check'
    Backend     = 'Graph'
    Scopes      = @('User.Read.All', 'Directory.Read.All')
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Check', 'NoOp')
    AffectedBy  = @('User.Create')
    Severity    = 'Refuse'
    Description = 'Refuses an onboarding when a user with the same user principal name or mail nickname already exists, or when a user with that user principal name sits in the deleted-items bin.'

    # Target: @{ Kind = 'user'; Id = <the UPN, which should not exist yet>; Name = <the UPN>; MailNickname = <nickname> }
    # Desired: @{ mailNickname = <nickname> }
    # Get has no Desired, so the nickname rides on the target (the way Mailbox.Delegate carries its grantee).
    # It falls back to the local part of the UPN, which is also the builder's default nickname.
    Get         = {
        param($Target, $Context)
        $upn = (Get-TenureTargetId -Target $Target -Provider 'Check.UserAbsent').Trim()
        $nickname = [string](Get-TenureGraphProperty -InputObject $Target -Name 'MailNickname')
        if ([string]::IsNullOrWhiteSpace($nickname)) { $nickname = $upn.Split('@')[0] }
        $nickname = $nickname.Trim()

        $upnLiteral = ConvertTo-TenureODataString -Value $upn
        $nicknameLiteral = ConvertTo-TenureODataString -Value $nickname
        $activeFilter = "userPrincipalName eq '$upnLiteral' or mailNickname eq '$nicknameLiteral'"
        $deletedFilter = "userPrincipalName eq '$upnLiteral'"
        $active = @(Invoke-TenureGraph -Method GET -Uri ('users?$filter=' + [uri]::EscapeDataString($activeFilter) + '&$select=id') -All)
        $deleted = @(Invoke-TenureGraph -Method GET -Uri ('directory/deletedItems/microsoft.graph.user?$filter=' + [uri]::EscapeDataString($deletedFilter) + '&$select=id') -All)
        [pscustomobject]@{
            userPrincipalName = $upn
            mailNickname      = $nickname
            existing          = [int]$active.Count
            deleted           = [int]$deleted.Count
        }
    }

    # A snapshot that is missing, or whose counts are not whole numbers, never counts as absent.
    Test        = {
        param($Current, $Desired)
        if ($null -eq $Current) { return $false }
        $existing = Get-TenureGraphProperty -InputObject $Current -Name 'existing'
        $deleted = Get-TenureGraphProperty -InputObject $Current -Name 'deleted'
        if ($existing -isnot [int] -or $deleted -isnot [int]) { return $false }
        return (($existing -eq 0) -and ($deleted -eq 0))
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $upn = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Id')
        if ($null -eq $Current) { return "No user $upn exists yet" }
        $nickname = [string](Get-TenureGraphProperty -InputObject $Current -Name 'mailNickname')
        $existing = Get-TenureGraphProperty -InputObject $Current -Name 'existing'
        $deleted = Get-TenureGraphProperty -InputObject $Current -Name 'deleted'
        if ($existing -is [int] -and $existing -gt 0) {
            return "User ${upn} cannot be created: a user with that user principal name or mail nickname ($nickname) already exists"
        }
        if ($deleted -is [int] -and $deleted -gt 0) {
            return "User ${upn} cannot be created: a deleted user with that user principal name is still in the recycle bin; restore or purge it first"
        }
        if ($existing -isnot [int] -or $deleted -isnot [int]) {
            return "User ${upn} cannot be created: the lookup returned no counts, so the name cannot be treated as free"
        }
        "No user ${upn} exists yet (mail nickname $nickname is free; nothing soft-deleted)"
    }
}
