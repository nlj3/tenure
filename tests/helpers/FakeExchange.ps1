# FakeExchange: a tiny in-memory Exchange Online for Tenure unit tests.
#
# Install it in a test file like this:
#
#   BeforeAll {
#       . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeExchange.ps1')
#       Import-TenureForTest; Set-TenureTestSession
#       $global:FakeExchangeWorld = New-FakeExchangeWorld
#       Mock -ModuleName Tenure Invoke-TenureExchange {
#           & (Get-Module -Name Tenure) { Assert-TenureConnection -Backend Exchange }
#           Invoke-FakeExchangeCommand -World $global:FakeExchangeWorld -Command $Command -Parameters $Parameters
#       }
#   }
#   BeforeEach { Reset-FakeExchangeWorld }
#
# The mock replaces the Exchange seam itself (Exchange cmdlets only exist after
# Connect-ExchangeOnline, so there is nothing lower to mock). The first line of the mock
# body keeps the seam's own first check, so Set-TenureTestSession -Exchange $false still
# produces Tenure.Exchange.NotConnected before any call reaches the fake. A Pester 5 mock
# body sees neither the module's private functions nor the test file's own functions, so
# the check is invoked through the module object and everything here is global:.
#
# Nothing in this file calls a private Tenure function. Errors are built to look exactly
# like the seam's: an ErrorRecord with FullyQualifiedErrorId and Exception.Data['TenureId']
# 'Tenure.Exchange.Failed', a message "Exchange cmdlet '<name>' failed: <cmdlet message>",
# and Data['Command'] / Data['Inner'].
#
# The world (New-FakeExchangeWorld) is a plain hashtable. Ids live in $world.Ids and
# reuse FakeGraph's fixed GUIDs for alice, bob, carol and the Legal DL, so a plan
# builder test can use one identity for both fakes. Seed:
#   alice      UserMailbox, 12 GB, no archive, no holds, auto-reply off, no forwarding;
#              permissions: NT AUTHORITY\SELF (explicit) and an inherited admin entry
#   bob        UserMailbox, 3 GB (alice's manager in FakeGraph)
#   reception  SharedMailbox, 1 GB, bob has FullAccess
#   Legal DL   MailUniversalDistributionGroup, member alice, managed by bob
#   Finance Security  MailUniversalSecurityGroup, members alice and bob, managed by bob
#   Me         'carol@example.com', the signed-in admin (not a manager of either group)
#
# World keys:
#   Mailboxes          hashtable keyed by ExternalDirectoryObjectId AND UserPrincipalName;
#                      both keys point at the same mailbox hashtable
#   DistributionGroups hashtable keyed by ExternalDirectoryObjectId AND Name
#   Calls              list of @{ Command; Parameters } (every call, faults included)
#   Faults             queue; see Add-FakeExchangeFault and Invoke-FakeExchangeCommand
#   Warnings           list of the warnings Exchange would have printed (no-op adds and removes)
#
# Behavior worth knowing:
#   - Identities are strict, because real Exchange is not trusted to resolve an Entra object
#     id: -Identity, -User, -Member and -ForwardingAddress name a mailbox by its user
#     principal name or primary SMTP address, and a group by its primary SMTP address. An
#     Entra id, an alias or a display name answers "couldn't be found" naming the value.
#     Get-EXOMailbox and Get-EXOMailboxStatistics also take -ExternalDirectoryObjectId (the
#     Entra id), but not together with -Identity.
#   - Parameters are checked per cmdlet. An unknown name fails the way PowerShell would
#     ("A parameter cannot be found that matches parameter name ..."), so a typo in a
#     provider shows up in a test.
#   - Get-EXOMailbox returns a minimum property set plus the names in -Properties; an
#     unknown property name fails. Get-Mailbox returns every property.
#   - TotalItemSize is a string like real EXO: "61.2 GB (65,712,345,678 bytes)".
#   - ForwardingSmtpAddress is stored and returned as 'smtp:user@example.com'.
#   - Auto-reply messages are returned wrapped in <html><body><div>...</div></body></html>.
#   - Remove-MailboxPermission, Remove-DistributionGroupMember and Remove-CalendarEvents
#     ask for confirmation in real Exchange; here they fail unless -Confirm:$false is passed.
#   - Add/Remove-DistributionGroupMember fail with the "manager of the group" error unless
#     Me is in ManagedBy or -BypassSecurityGroupManagerCheck is passed.

function global:New-FakeExchangeError {
    # Builds the ErrorRecord the Exchange seam would throw for a failed cmdlet (or another seam error id).
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$Message,
        [string]$Id = 'Tenure.Exchange.Failed'
    )
    $innerException = [System.Exception]::new($Message)
    $inner = [System.Management.Automation.ErrorRecord]::new($innerException, 'FakeExchange.CmdletError', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
    $text = if ($Id -eq 'Tenure.Exchange.Failed') { "Exchange cmdlet '$Command' failed: $Message" } else { $Message }
    $exception = [System.Exception]::new($text, $innerException)
    $exception.Data['Command'] = $Command
    if ($Id -eq 'Tenure.Exchange.Failed') { $exception.Data['Inner'] = $inner }
    $exception.Data['TenureId'] = $Id
    [System.Management.Automation.ErrorRecord]::new($exception, $Id, [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
}

function global:Stop-FakeExchange {
    # Raises a cmdlet failure; Invoke-FakeExchangeCommand turns it into the seam's error.
    param([Parameter(Mandatory)][string]$Message)
    $exception = [System.Exception]::new($Message)
    $exception.Data['FakeExchangeError'] = $true
    throw $exception
}

function global:Format-FakeExchangeByteSize {
    # 65712345678 -> '61.2 GB (65,712,345,678 bytes)' (binary units, like Exchange's ByteQuantifiedSize).
    param([Parameter(Mandatory)][long]$Bytes)
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $units = @(@{ Name = 'TB'; Size = 1TB }, @{ Name = 'GB'; Size = 1GB }, @{ Name = 'MB'; Size = 1MB }, @{ Name = 'KB'; Size = 1KB })
    $value = "$Bytes B"
    foreach ($unit in $units) {
        if ($Bytes -ge $unit.Size) {
            $value = ([double]$Bytes / $unit.Size).ToString('0.#', $culture) + ' ' + $unit.Name
            break
        }
    }
    '{0} ({1} bytes)' -f $value, $Bytes.ToString('N0', $culture)
}

function global:New-FakeExchangeMailbox {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Alias,
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Guid,
        [string]$RecipientTypeDetails = 'UserMailbox',
        [long]$TotalItemSizeBytes = 1GB
    )
    @{
        Identity                      = $Alias
        Alias                         = $Alias
        Name                          = $Alias
        Guid                          = $Guid
        DisplayName                   = $DisplayName
        PrimarySmtpAddress            = $UserPrincipalName
        UserPrincipalName             = $UserPrincipalName
        ExternalDirectoryObjectId     = $Id
        RecipientTypeDetails          = $RecipientTypeDetails
        ForwardingAddress             = $null
        ForwardingSmtpAddress         = $null
        DeliverToMailboxAndForward    = $false
        HiddenFromAddressListsEnabled = $false
        ArchiveStatus                 = 'None'
        LitigationHoldEnabled         = $false
        InPlaceHolds                  = [string[]]@()
        RetentionHoldEnabled          = $false
        TotalItemSizeBytes            = $TotalItemSizeBytes
        NeverLoggedOn                 = $false
        AutoReply                     = @{ AutoReplyState = 'Disabled'; InternalMessage = $null; ExternalMessage = $null; ExternalAudience = 'All' }
        Permissions                   = [System.Collections.Generic.List[hashtable]]::new()
        CalendarEventsCancelled       = $false
        CancelQueryWindowInDays       = $null
    }
}

function global:New-FakeExchangeWorld {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $ids = @{
        AliceId                = '10000000-0000-4000-8000-000000000001'
        BobId                  = '10000000-0000-4000-8000-000000000002'
        CarolId                = '10000000-0000-4000-8000-000000000003'
        SharedId               = '10000000-0000-4000-8000-000000000101'
        LegalDlGroupId         = '20000000-0000-4000-8000-000000000004'
        FinanceSecurityGroupId = '20000000-0000-4000-8000-000000000005'
    }

    $alice = New-FakeExchangeMailbox -Id $ids.AliceId -Alias 'alice' -UserPrincipalName 'alice@example.com' -DisplayName 'Alice Example' -Guid 'e0000000-0000-4000-8000-000000000001' -TotalItemSizeBytes 12GB
    $alice.Permissions.Add(@{ User = 'NT AUTHORITY\SELF'; AccessRights = [string[]]@('FullAccess', 'ReadPermission'); IsInherited = $false; Deny = $false; InheritanceType = 'All'; AutoMapping = $false })
    $alice.Permissions.Add(@{ User = 'EXAMPLE\Organization Management'; AccessRights = [string[]]@('FullAccess'); IsInherited = $true; Deny = $false; InheritanceType = 'All'; AutoMapping = $false })
    $bob = New-FakeExchangeMailbox -Id $ids.BobId -Alias 'bob' -UserPrincipalName 'bob@example.com' -DisplayName 'Bob Manager' -Guid 'e0000000-0000-4000-8000-000000000002' -TotalItemSizeBytes 3GB
    $bob.Permissions.Add(@{ User = 'NT AUTHORITY\SELF'; AccessRights = [string[]]@('FullAccess', 'ReadPermission'); IsInherited = $false; Deny = $false; InheritanceType = 'All'; AutoMapping = $false })
    $shared = New-FakeExchangeMailbox -Id $ids.SharedId -Alias 'reception' -UserPrincipalName 'reception@example.com' -DisplayName 'Reception' -Guid 'e0000000-0000-4000-8000-000000000101' -RecipientTypeDetails 'SharedMailbox' -TotalItemSizeBytes 1GB
    $shared.Permissions.Add(@{ User = 'bob@example.com'; AccessRights = [string[]]@('FullAccess'); IsInherited = $false; Deny = $false; InheritanceType = 'All'; AutoMapping = $true })

    $mailboxes = @{}
    foreach ($mailbox in $alice, $bob, $shared) {
        $mailboxes[$mailbox.ExternalDirectoryObjectId] = $mailbox
        $mailboxes[$mailbox.UserPrincipalName] = $mailbox
    }

    $legal = @{
        Identity = 'Legal DL'; Name = 'Legal DL'; DisplayName = 'Legal DL'; PrimarySmtpAddress = 'legal@example.com'
        ExternalDirectoryObjectId = $ids.LegalDlGroupId; Guid = 'e0000000-0000-4000-8000-000000000204'
        RecipientTypeDetails = 'MailUniversalDistributionGroup'; ManagedBy = [string[]]@('bob@example.com')
        Members = [System.Collections.Generic.List[hashtable]]::new()
    }
    $legal.Members.Add(@{ ExternalDirectoryObjectId = $ids.AliceId; PrimarySmtpAddress = 'alice@example.com'; Name = 'alice' })
    $finance = @{
        Identity = 'Finance Security'; Name = 'Finance Security'; DisplayName = 'Finance Security'; PrimarySmtpAddress = 'finance-security@example.com'
        ExternalDirectoryObjectId = $ids.FinanceSecurityGroupId; Guid = 'e0000000-0000-4000-8000-000000000205'
        RecipientTypeDetails = 'MailUniversalSecurityGroup'; ManagedBy = [string[]]@('bob@example.com')
        Members = [System.Collections.Generic.List[hashtable]]::new()
    }
    $finance.Members.Add(@{ ExternalDirectoryObjectId = $ids.AliceId; PrimarySmtpAddress = 'alice@example.com'; Name = 'alice' })
    $finance.Members.Add(@{ ExternalDirectoryObjectId = $ids.BobId; PrimarySmtpAddress = 'bob@example.com'; Name = 'bob' })

    $groups = @{}
    foreach ($group in $legal, $finance) {
        $groups[$group.ExternalDirectoryObjectId] = $group
        $groups[$group.Name] = $group
    }

    @{
        Mailboxes          = $mailboxes
        DistributionGroups = $groups
        Calls              = [System.Collections.Generic.List[hashtable]]::new()
        Faults             = [System.Collections.Generic.Queue[object]]::new()
        Warnings           = [System.Collections.Generic.List[string]]::new()
        Me                 = 'carol@example.com'
        Ids                = $ids
    }
}

function global:Reset-FakeExchangeWorld {
    # Re-seeds $global:FakeExchangeWorld; call from BeforeEach.
    $global:FakeExchangeWorld = New-FakeExchangeWorld
}

function global:Add-FakeExchangeFault {
    # Queues a failure for the next call to -Command (any command when -Command is omitted).
    # The error looks like the seam's: id -Id (default Tenure.Exchange.Failed), message -Message.
    param(
        [Parameter(Mandatory)][hashtable]$World,
        [string]$Command,
        [string]$Message = 'Injected by FakeExchange.',
        [string]$Id = 'Tenure.Exchange.Failed',
        [int]$Count = 1
    )
    for ($i = 0; $i -lt $Count; $i++) {
        $World.Faults.Enqueue(@{ Command = $Command; Message = $Message; Id = $Id })
    }
}

function global:Get-FakeExchangeCall {
    # Recorded calls, optionally only those of one command. Emitted one by one: wrap the call in @(...).
    param([Parameter(Mandatory)][hashtable]$World, [string]$Command)
    @($World.Calls | Where-Object { -not $Command -or $_.Command -eq $Command })
}

function global:Set-FakeExchangeMailboxSize {
    # Sets TotalItemSize. Default is the 61.2 GB variant used by the eligibility tests.
    param(
        [Parameter(Mandatory)][hashtable]$World,
        [Parameter(Mandatory)][string]$Identity,
        [long]$Bytes = 65712345678
    )
    $mailbox = Find-FakeExchangeMailbox -World $World -Key $Identity
    if (-not $mailbox) { throw "FakeExchange has no mailbox '$Identity'." }
    $mailbox.TotalItemSizeBytes = $Bytes
}

function global:Get-FakeExchangeMailboxList {
    # Each mailbox once (the Mailboxes table holds two keys per mailbox).
    param([Parameter(Mandatory)][hashtable]$World)
    $seen = @{}
    foreach ($mailbox in $World.Mailboxes.Values) {
        if ($seen.ContainsKey($mailbox.ExternalDirectoryObjectId)) { continue }
        $seen[$mailbox.ExternalDirectoryObjectId] = $true
        $mailbox
    }
}

function global:Get-FakeExchangeGroupList {
    param([Parameter(Mandatory)][hashtable]$World)
    $seen = @{}
    foreach ($group in $World.DistributionGroups.Values) {
        if ($seen.ContainsKey($group.ExternalDirectoryObjectId)) { continue }
        $seen[$group.ExternalDirectoryObjectId] = $true
        $group
    }
}

function global:Find-FakeExchangeMailbox {
    # By user principal name or primary SMTP address (case-insensitive). An Entra object id, an alias or a
    # name is not found: the providers must never rely on Exchange resolving those.
    param([Parameter(Mandatory)][hashtable]$World, [AllowNull()][object]$Key)
    if ($null -eq $Key) { return $null }
    $text = ([string]$Key).Trim()
    if ($text.Length -eq 0) { return $null }
    foreach ($mailbox in (Get-FakeExchangeMailboxList -World $World)) {
        foreach ($field in 'UserPrincipalName', 'PrimarySmtpAddress') {
            if ([string]$mailbox[$field] -ieq $text) { return $mailbox }
        }
    }
    return $null
}

function global:Find-FakeExchangeMailboxByObjectId {
    # By ExternalDirectoryObjectId (the Entra id, case-insensitive), as Get-EXOMailbox -ExternalDirectoryObjectId does.
    param([Parameter(Mandatory)][hashtable]$World, [AllowNull()][object]$Key)
    if ($null -eq $Key) { return $null }
    $text = ([string]$Key).Trim()
    if ($text.Length -eq 0) { return $null }
    foreach ($mailbox in (Get-FakeExchangeMailboxList -World $World)) {
        if ([string]$mailbox['ExternalDirectoryObjectId'] -ieq $text) { return $mailbox }
    }
    return $null
}

function global:Find-FakeExchangeGroup {
    # By primary SMTP address only (case-insensitive). An Entra id or a display name is not found.
    param([Parameter(Mandatory)][hashtable]$World, [AllowNull()][object]$Key)
    if ($null -eq $Key) { return $null }
    $text = ([string]$Key).Trim()
    if ($text.Length -eq 0) { return $null }
    foreach ($group in (Get-FakeExchangeGroupList -World $World)) {
        if ([string]$group['PrimarySmtpAddress'] -ieq $text) { return $group }
    }
    return $null
}

function global:Get-FakeExchangeMailboxOrFail {
    param([Parameter(Mandatory)][hashtable]$World, [AllowNull()][object]$Key)
    $mailbox = Find-FakeExchangeMailbox -World $World -Key $Key
    if (-not $mailbox) { Stop-FakeExchange -Message "The operation couldn't be performed because object '$Key' couldn't be found on 'FAKEPR01A001.PROD.OUTLOOK.COM'." }
    $mailbox
}

function global:Get-FakeExchangeReadTarget {
    # The mailbox a Get-EXOMailbox / Get-EXOMailboxStatistics call names: -Identity (an address) or
    # -ExternalDirectoryObjectId (an Entra id), never both. $null when neither is given.
    param([Parameter(Mandatory)][hashtable]$World, [Parameter(Mandatory)][hashtable]$Parameters)
    $byId = Test-FakeExchangeParameter -Parameters $Parameters -Name 'ExternalDirectoryObjectId'
    $byIdentity = Test-FakeExchangeParameter -Parameters $Parameters -Name 'Identity'
    if ($byId -and $byIdentity) { Stop-FakeExchange -Message 'Parameter set cannot be resolved using the specified named parameters.' }
    if ($byId) {
        $key = Get-FakeExchangeParameter -Parameters $Parameters -Name 'ExternalDirectoryObjectId'
        $mailbox = Find-FakeExchangeMailboxByObjectId -World $World -Key $key
        if (-not $mailbox) { Stop-FakeExchange -Message "The operation couldn't be performed because object '$key' couldn't be found on 'FAKEPR01A001.PROD.OUTLOOK.COM'." }
        return $mailbox
    }
    if ($byIdentity) { return (Get-FakeExchangeMailboxOrFail -World $World -Key (Get-FakeExchangeParameter -Parameters $Parameters -Name 'Identity')) }
    $null
}

function global:Get-FakeExchangeGroupOrFail {
    param([Parameter(Mandatory)][hashtable]$World, [AllowNull()][object]$Key)
    $group = Find-FakeExchangeGroup -World $World -Key $Key
    if (-not $group) { Stop-FakeExchange -Message "The operation couldn't be performed because object '$Key' couldn't be found on 'FAKEPR01A001.PROD.OUTLOOK.COM'." }
    $group
}

function global:Get-FakeExchangeAllowedParameter {
    # Parameter names each fake cmdlet accepts (ErrorAction/WarningAction/Verbose/Debug are always allowed).
    param([Parameter(Mandatory)][string]$Command)
    $write = @('Confirm', 'WhatIf')
    $table = @{
        'Get-Mailbox'                       = @('Identity', 'ResultSize')
        'Get-EXOMailbox'                    = @('Identity', 'ExternalDirectoryObjectId', 'Properties', 'PropertySets', 'ResultSize')
        'Set-Mailbox'                       = @('Identity', 'Type', 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward', 'HiddenFromAddressListsEnabled') + $write
        'Get-MailboxStatistics'             = @('Identity')
        'Get-EXOMailboxStatistics'          = @('Identity', 'ExternalDirectoryObjectId', 'Properties', 'PropertySets')
        'Get-MailboxAutoReplyConfiguration' = @('Identity')
        'Set-MailboxAutoReplyConfiguration' = @('Identity', 'AutoReplyState', 'InternalMessage', 'ExternalMessage', 'ExternalAudience', 'StartTime', 'EndTime') + $write
        'Get-MailboxPermission'             = @('Identity', 'User', 'ResultSize')
        'Get-EXOMailboxPermission'          = @('Identity', 'User', 'ResultSize')
        'Add-MailboxPermission'             = @('Identity', 'User', 'AccessRights', 'InheritanceType', 'AutoMapping', 'Deny') + $write
        'Remove-MailboxPermission'          = @('Identity', 'User', 'AccessRights', 'InheritanceType', 'Deny') + $write
        'Remove-CalendarEvents'             = @('Identity', 'CancelOrganizedMeetings', 'QueryWindowInDays', 'QueryStartDate', 'PreviewOnly') + $write
        'Get-DistributionGroup'             = @('Identity', 'ResultSize')
        'Get-DistributionGroupMember'       = @('Identity', 'ResultSize')
        'Add-DistributionGroupMember'       = @('Identity', 'Member', 'BypassSecurityGroupManagerCheck') + $write
        'Remove-DistributionGroupMember'    = @('Identity', 'Member', 'BypassSecurityGroupManagerCheck') + $write
        'Get-Recipient'                     = @('Identity', 'ResultSize')
    }
    if (-not $table.ContainsKey($Command)) { return $null }
    , [string[]]($table[$Command] + @('ErrorAction', 'WarningAction', 'Verbose', 'Debug'))
}

function global:Get-FakeExchangeParameter {
    # A parameter value, or $Default when the key is absent. Keys match case-insensitively.
    param([hashtable]$Parameters, [string]$Name, [AllowNull()][object]$Default = $null)
    foreach ($key in $Parameters.Keys) { if ([string]$key -ieq $Name) { return $Parameters[$key] } }
    $Default
}

function global:Test-FakeExchangeParameter {
    param([hashtable]$Parameters, [string]$Name)
    foreach ($key in $Parameters.Keys) { if ([string]$key -ieq $Name) { return $true } }
    $false
}

function global:Get-FakeExchangeBool {
    # Binds a [bool] or switch parameter strictly: anything other than a boolean is a binding error.
    param([hashtable]$Parameters, [string]$Name, [bool]$Default = $false)
    if (-not (Test-FakeExchangeParameter -Parameters $Parameters -Name $Name)) { return $Default }
    $value = Get-FakeExchangeParameter -Parameters $Parameters -Name $Name
    if ($value -is [bool]) { return $value }
    if ($value -is [System.Management.Automation.SwitchParameter]) { return $value.IsPresent }
    $type = if ($null -eq $value) { 'null' } else { $value.GetType().Name }
    Stop-FakeExchange -Message "Cannot process argument transformation on parameter '$Name'. Cannot convert value of type $type to type System.Boolean."
}

function global:Assert-FakeExchangeConfirmed {
    # Cmdlets that prompt in real Exchange fail here unless -Confirm:$false was passed (an unattended run cannot answer a prompt).
    param([hashtable]$Parameters, [string]$Command)
    $confirm = Get-FakeExchangeParameter -Parameters $Parameters -Name 'Confirm' -Default $true
    $isFalse = ($confirm -is [bool] -and -not $confirm) -or ($confirm -is [System.Management.Automation.SwitchParameter] -and -not $confirm.IsPresent)
    if (-not $isFalse) { Stop-FakeExchange -Message "$Command asked for confirmation and nobody answered. Pass -Confirm:`$false." }
}

function global:Test-FakeExchangeWhatIf {
    param([hashtable]$Parameters)
    $value = Get-FakeExchangeParameter -Parameters $Parameters -Name 'WhatIf' -Default $false
    ($value -is [bool] -and $value) -or ($value -is [System.Management.Automation.SwitchParameter] -and $value.IsPresent)
}

function global:Assert-FakeExchangeManager {
    param([hashtable]$World, [hashtable]$Group, [hashtable]$Parameters)
    if (Get-FakeExchangeBool -Parameters $Parameters -Name 'BypassSecurityGroupManagerCheck') { return }
    if (@($Group.ManagedBy) -contains $World.Me) { return }
    Stop-FakeExchange -Message "You don't have sufficient permissions. This operation can only be performed by a manager of the group."
}

function global:ConvertTo-FakeExchangeHtml {
    # Exchange returns auto-reply text wrapped in HTML; text that is already HTML is returned as stored.
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text.TrimStart() -match '^<html') { return $Text }
    $body = $Text.Replace("`r`n", "`n").Replace("`n", "<br>`n")
    "<html>`n<body>`n<div>$body</div>`n</body>`n</html>`n"
}

function global:ConvertTo-FakeExchangeMailboxObject {
    # A stored mailbox as Exchange would return it. -Property limits the output to the minimum set plus those names.
    param([hashtable]$Mailbox, [string[]]$Property, [switch]$All)
    $minimum = 'ExternalDirectoryObjectId', 'UserPrincipalName', 'Alias', 'DisplayName', 'PrimarySmtpAddress', 'RecipientType', 'RecipientTypeDetails', 'Identity', 'Name', 'Guid'
    $optional = 'ForwardingAddress', 'ForwardingSmtpAddress', 'DeliverToMailboxAndForward', 'HiddenFromAddressListsEnabled', 'ArchiveStatus', 'LitigationHoldEnabled', 'InPlaceHolds', 'RetentionHoldEnabled'
    $out = [ordered]@{}
    foreach ($name in $minimum) {
        $out[$name] = if ($name -eq 'RecipientType') { 'UserMailbox' } else { $Mailbox[$name] }
    }
    $wanted = if ($All) { $optional } else { @($Property) }
    foreach ($name in $wanted) {
        if ([string]::IsNullOrEmpty($name)) { continue }
        $canonical = $optional + $minimum | Where-Object { $_ -ieq $name } | Select-Object -First 1
        if (-not $canonical) { Stop-FakeExchange -Message "The property '$name' is not a valid property for Get-EXOMailbox." }
        if ($canonical -eq 'InPlaceHolds') { $out[$canonical] = [string[]]@($Mailbox.InPlaceHolds) } else { $out[$canonical] = $Mailbox[$canonical] }
    }
    [pscustomobject]$out
}

function global:ConvertTo-FakeExchangePermissionObject {
    param([hashtable]$Mailbox, [hashtable]$Entry)
    [pscustomobject]@{
        Identity        = $Mailbox.Identity
        User            = $Entry.User
        AccessRights    = [string[]]@($Entry.AccessRights)
        IsInherited     = [bool]$Entry.IsInherited
        Deny            = [bool]$Entry.Deny
        InheritanceType = $Entry.InheritanceType
    }
}

function global:Resolve-FakeExchangeUser {
    # The permission principal for -User: the mailbox user's UPN.
    param([hashtable]$World, [AllowNull()][object]$Key)
    $mailbox = Find-FakeExchangeMailbox -World $World -Key $Key
    if (-not $mailbox) { Stop-FakeExchange -Message "The operation couldn't be performed because object '$Key' couldn't be found on 'FAKEPR01A001.PROD.OUTLOOK.COM'." }
    $mailbox.UserPrincipalName
}

function global:Get-FakeExchangeAccessRight {
    # -AccessRights as a validated string array.
    param([AllowNull()][object]$Value)
    $known = 'FullAccess', 'ReadPermission', 'ChangePermission', 'ChangeOwner', 'DeleteItem', 'ExternalAccount', 'SendAs'
    $rights = @(@($Value) | ForEach-Object { ([string]$_).Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($rights.Count -eq 0) { Stop-FakeExchange -Message 'Cannot validate argument on parameter ''AccessRights''. The argument is null or empty.' }
    foreach ($right in $rights) {
        if (-not ($known | Where-Object { $_ -ieq $right })) { Stop-FakeExchange -Message "Cannot process argument transformation on parameter 'AccessRights'. '$right' is not a valid mailbox right." }
    }
    , [string[]]@($rights | ForEach-Object { $r = $_; $known | Where-Object { $_ -ieq $r } | Select-Object -First 1 })
}

function global:Invoke-FakeExchangeRoute {
    param([hashtable]$World, [string]$Command, [hashtable]$Parameters)

    $identity = Get-FakeExchangeParameter -Parameters $Parameters -Name 'Identity'
    switch ($Command) {
        { $_ -in 'Get-Mailbox', 'Get-EXOMailbox' } {
            $all = ($Command -eq 'Get-Mailbox')
            $properties = [string[]]@(Get-FakeExchangeParameter -Parameters $Parameters -Name 'Properties' -Default @())
            $named = Get-FakeExchangeReadTarget -World $World -Parameters $Parameters
            $mailboxes = if ($null -ne $named) { @($named) } else { @(Get-FakeExchangeMailboxList -World $World) }
            foreach ($mailbox in $mailboxes) { ConvertTo-FakeExchangeMailboxObject -Mailbox $mailbox -Property $properties -All:$all }
            return
        }
        'Set-Mailbox' {
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $identity
            $changes = @{}
            if (Test-FakeExchangeParameter -Parameters $Parameters -Name 'Type') {
                $type = [string](Get-FakeExchangeParameter -Parameters $Parameters -Name 'Type')
                $details = switch ($type) {
                    { $_ -ieq 'Shared' } { 'SharedMailbox' }
                    { $_ -ieq 'Regular' } { 'UserMailbox' }
                    default { Stop-FakeExchange -Message "FakeExchange supports Set-Mailbox -Type Shared or Regular only (got '$type')." }
                }
                $changes['RecipientTypeDetails'] = $details
            }
            if (Test-FakeExchangeParameter -Parameters $Parameters -Name 'ForwardingSmtpAddress') {
                $value = Get-FakeExchangeParameter -Parameters $Parameters -Name 'ForwardingSmtpAddress'
                if ($null -eq $value -or ([string]$value).Trim().Length -eq 0) {
                    $changes['ForwardingSmtpAddress'] = $null
                } else {
                    $address = ([string]$value).Trim()
                    if ($address -imatch '^smtp:') { $address = $address.Substring(5) }
                    if ($address -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
                        Stop-FakeExchange -Message "Cannot bind parameter 'ForwardingSmtpAddress'. Cannot convert value `"$value`" to type `"Microsoft.Exchange.Data.ProxyAddress`"."
                    }
                    $changes['ForwardingSmtpAddress'] = 'smtp:' + $address
                }
            }
            if (Test-FakeExchangeParameter -Parameters $Parameters -Name 'ForwardingAddress') {
                $value = Get-FakeExchangeParameter -Parameters $Parameters -Name 'ForwardingAddress'
                if ($null -eq $value -or ([string]$value).Trim().Length -eq 0) {
                    $changes['ForwardingAddress'] = $null
                } else {
                    $recipient = Find-FakeExchangeMailbox -World $World -Key $value
                    if (-not $recipient) { $recipient = Get-FakeExchangeGroupOrFail -World $World -Key $value }
                    $changes['ForwardingAddress'] = $recipient.Identity
                }
            }
            foreach ($name in 'DeliverToMailboxAndForward', 'HiddenFromAddressListsEnabled') {
                if (Test-FakeExchangeParameter -Parameters $Parameters -Name $name) {
                    $changes[$name] = Get-FakeExchangeBool -Parameters $Parameters -Name $name
                }
            }
            if (Test-FakeExchangeWhatIf -Parameters $Parameters) { return }
            $modified = $false
            foreach ($key in $changes.Keys) {
                if ($mailbox[$key] -cne $changes[$key]) { $modified = $true }
                $mailbox[$key] = $changes[$key]
            }
            if (-not $modified) { $World.Warnings.Add("The command completed successfully but no settings of '$($mailbox.Identity)' have been modified.") }
            return
        }
        { $_ -in 'Get-MailboxStatistics', 'Get-EXOMailboxStatistics' } {
            $mailbox = Get-FakeExchangeReadTarget -World $World -Parameters $Parameters
            if ($null -eq $mailbox) { $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $identity }
            if ($mailbox.NeverLoggedOn) {
                $World.Warnings.Add("The user hasn't logged on to mailbox '$($mailbox.Identity)', so there is no data to return. After the user logs on, this warning will no longer appear.")
                return
            }
            [pscustomobject]@{
                DisplayName          = $mailbox.DisplayName
                MailboxGuid          = $mailbox.Guid
                ItemCount            = 1000
                TotalItemSize        = Format-FakeExchangeByteSize -Bytes ([long]$mailbox.TotalItemSizeBytes)
                TotalDeletedItemSize = Format-FakeExchangeByteSize -Bytes 0
            }
            return
        }
        'Get-MailboxAutoReplyConfiguration' {
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $identity
            [pscustomobject]@{
                Identity         = $mailbox.Identity
                AutoReplyState   = $mailbox.AutoReply.AutoReplyState
                InternalMessage  = ConvertTo-FakeExchangeHtml -Text $mailbox.AutoReply.InternalMessage
                ExternalMessage  = ConvertTo-FakeExchangeHtml -Text $mailbox.AutoReply.ExternalMessage
                ExternalAudience = $mailbox.AutoReply.ExternalAudience
            }
            return
        }
        'Set-MailboxAutoReplyConfiguration' {
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $identity
            $changes = @{}
            $enums = @{ AutoReplyState = @('Enabled', 'Disabled', 'Scheduled'); ExternalAudience = @('None', 'Known', 'All') }
            foreach ($name in $enums.Keys) {
                if (Test-FakeExchangeParameter -Parameters $Parameters -Name $name) {
                    $value = [string](Get-FakeExchangeParameter -Parameters $Parameters -Name $name)
                    $canonical = $enums[$name] | Where-Object { $_ -ieq $value } | Select-Object -First 1
                    if (-not $canonical) { Stop-FakeExchange -Message "Cannot process argument transformation on parameter '$name'. '$value' is not a valid value." }
                    $changes[$name] = $canonical
                }
            }
            foreach ($name in 'InternalMessage', 'ExternalMessage') {
                if (Test-FakeExchangeParameter -Parameters $Parameters -Name $name) {
                    $value = Get-FakeExchangeParameter -Parameters $Parameters -Name $name
                    $changes[$name] = if ($null -eq $value) { $null } else { [string]$value }
                }
            }
            if (Test-FakeExchangeWhatIf -Parameters $Parameters) { return }
            foreach ($key in $changes.Keys) { $mailbox.AutoReply[$key] = $changes[$key] }
            return
        }
        { $_ -in 'Get-MailboxPermission', 'Get-EXOMailboxPermission' } {
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $identity
            $user = $null
            if (Test-FakeExchangeParameter -Parameters $Parameters -Name 'User') {
                $user = Resolve-FakeExchangeUser -World $World -Key (Get-FakeExchangeParameter -Parameters $Parameters -Name 'User')
            }
            foreach ($entry in $mailbox.Permissions) {
                if ($null -ne $user -and $entry.User -ine $user) { continue }
                ConvertTo-FakeExchangePermissionObject -Mailbox $mailbox -Entry $entry
            }
            return
        }
        'Add-MailboxPermission' {
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $identity
            $user = Resolve-FakeExchangeUser -World $World -Key (Get-FakeExchangeParameter -Parameters $Parameters -Name 'User')
            $rights = Get-FakeExchangeAccessRight -Value (Get-FakeExchangeParameter -Parameters $Parameters -Name 'AccessRights')
            $deny = Get-FakeExchangeBool -Parameters $Parameters -Name 'Deny'
            $autoMapping = Get-FakeExchangeBool -Parameters $Parameters -Name 'AutoMapping' -Default $true
            $inheritance = [string](Get-FakeExchangeParameter -Parameters $Parameters -Name 'InheritanceType' -Default 'All')
            if (Test-FakeExchangeWhatIf -Parameters $Parameters) { return }
            $entry = $mailbox.Permissions | Where-Object { $_.User -ieq $user -and -not $_.IsInherited -and [bool]$_.Deny -eq $deny } | Select-Object -First 1
            if ($entry) {
                $missing = @($rights | Where-Object { @($entry.AccessRights) -notcontains $_ })
                if ($missing.Count -eq 0) {
                    $World.Warnings.Add("The appropriate access control entry is already present on the object `"$($mailbox.Identity)`" for account `"$user`".")
                    return
                }
                $entry.AccessRights = [string[]](@($entry.AccessRights) + $missing)
                $entry.AutoMapping = $autoMapping
            } else {
                $entry = @{ User = $user; AccessRights = [string[]]$rights; IsInherited = $false; Deny = $deny; InheritanceType = $inheritance; AutoMapping = $autoMapping }
                $mailbox.Permissions.Add($entry)
            }
            ConvertTo-FakeExchangePermissionObject -Mailbox $mailbox -Entry $entry
            return
        }
        'Remove-MailboxPermission' {
            Assert-FakeExchangeConfirmed -Parameters $Parameters -Command $Command
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $identity
            $user = Resolve-FakeExchangeUser -World $World -Key (Get-FakeExchangeParameter -Parameters $Parameters -Name 'User')
            $rights = Get-FakeExchangeAccessRight -Value (Get-FakeExchangeParameter -Parameters $Parameters -Name 'AccessRights')
            $deny = Get-FakeExchangeBool -Parameters $Parameters -Name 'Deny'
            if (Test-FakeExchangeWhatIf -Parameters $Parameters) { return }
            $entry = $mailbox.Permissions | Where-Object { $_.User -ieq $user -and -not $_.IsInherited -and [bool]$_.Deny -eq $deny } | Select-Object -First 1
            # Wrapped in @(): assigning an if-expression would collapse an empty list to $null.
            $present = @(if ($entry) { $rights | Where-Object { @($entry.AccessRights) -contains $_ } })
            if ($present.Count -eq 0) {
                $World.Warnings.Add("Can't remove the access control entry on the object `"$($mailbox.Identity)`" for account `"$user`" because the ACE isn't present.")
                return
            }
            $entry.AccessRights = [string[]]@($entry.AccessRights | Where-Object { $rights -notcontains $_ })
            if ($entry.AccessRights.Count -eq 0) { [void]$mailbox.Permissions.Remove($entry) }
            return
        }
        'Remove-CalendarEvents' {
            Assert-FakeExchangeConfirmed -Parameters $Parameters -Command $Command
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $identity
            if (-not (Get-FakeExchangeBool -Parameters $Parameters -Name 'CancelOrganizedMeetings') -and -not (Get-FakeExchangeBool -Parameters $Parameters -Name 'PreviewOnly')) {
                Stop-FakeExchange -Message 'Remove-CalendarEvents needs -CancelOrganizedMeetings or -PreviewOnly.'
            }
            $days = Get-FakeExchangeParameter -Parameters $Parameters -Name 'QueryWindowInDays'
            if ($days -isnot [int] -or $days -lt 1 -or $days -gt 1825) {
                Stop-FakeExchange -Message "Cannot validate argument on parameter 'QueryWindowInDays'. The argument '$days' is not between 1 and 1825."
            }
            if ((Get-FakeExchangeBool -Parameters $Parameters -Name 'PreviewOnly') -or (Test-FakeExchangeWhatIf -Parameters $Parameters)) { return }
            $mailbox.CalendarEventsCancelled = $true
            $mailbox.CancelQueryWindowInDays = $days
            return
        }
        'Get-DistributionGroup' {
            $groups = if ($null -ne $identity) { @(Get-FakeExchangeGroupOrFail -World $World -Key $identity) } else { @(Get-FakeExchangeGroupList -World $World) }
            foreach ($group in $groups) {
                [pscustomobject]@{
                    Identity                  = $group.Identity
                    Name                      = $group.Name
                    DisplayName               = $group.DisplayName
                    PrimarySmtpAddress        = $group.PrimarySmtpAddress
                    ExternalDirectoryObjectId = $group.ExternalDirectoryObjectId
                    Guid                      = $group.Guid
                    RecipientTypeDetails      = $group.RecipientTypeDetails
                    ManagedBy                 = [string[]]@($group.ManagedBy)
                }
            }
            return
        }
        'Get-DistributionGroupMember' {
            $group = Get-FakeExchangeGroupOrFail -World $World -Key $identity
            $size = Get-FakeExchangeParameter -Parameters $Parameters -Name 'ResultSize' -Default 1000
            $limit = if ([string]$size -ieq 'Unlimited') { [int]::MaxValue } else { [int]$size }
            $index = 0
            foreach ($member in $group.Members) {
                if ($index -ge $limit) {
                    $World.Warnings.Add('There are more results available than are currently displayed. To view them, increase the value for the ResultSize parameter.')
                    break
                }
                $index++
                [pscustomobject]@{
                    Name                      = $member.Name
                    PrimarySmtpAddress        = $member.PrimarySmtpAddress
                    ExternalDirectoryObjectId = $member.ExternalDirectoryObjectId
                    RecipientType             = 'UserMailbox'
                }
            }
            return
        }
        'Add-DistributionGroupMember' {
            $group = Get-FakeExchangeGroupOrFail -World $World -Key $identity
            $memberKey = Get-FakeExchangeParameter -Parameters $Parameters -Name 'Member'
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $memberKey
            Assert-FakeExchangeManager -World $World -Group $group -Parameters $Parameters
            if ($group.Members | Where-Object { $_.ExternalDirectoryObjectId -ieq $mailbox.ExternalDirectoryObjectId }) {
                Stop-FakeExchange -Message "The recipient `"$($mailbox.Identity)`" is already a member of the group `"$($group.Name)`"."
            }
            if (Test-FakeExchangeWhatIf -Parameters $Parameters) { return }
            $group.Members.Add(@{ ExternalDirectoryObjectId = $mailbox.ExternalDirectoryObjectId; PrimarySmtpAddress = $mailbox.PrimarySmtpAddress; Name = $mailbox.Name })
            return
        }
        'Remove-DistributionGroupMember' {
            Assert-FakeExchangeConfirmed -Parameters $Parameters -Command $Command
            $group = Get-FakeExchangeGroupOrFail -World $World -Key $identity
            $memberKey = Get-FakeExchangeParameter -Parameters $Parameters -Name 'Member'
            $mailbox = Get-FakeExchangeMailboxOrFail -World $World -Key $memberKey
            Assert-FakeExchangeManager -World $World -Group $group -Parameters $Parameters
            $entry = $group.Members | Where-Object { $_.ExternalDirectoryObjectId -ieq $mailbox.ExternalDirectoryObjectId } | Select-Object -First 1
            if (-not $entry) {
                Stop-FakeExchange -Message "The recipient `"$($mailbox.Identity)`" isn't a member of the group `"$($group.Name)`"."
            }
            if (Test-FakeExchangeWhatIf -Parameters $Parameters) { return }
            [void]$group.Members.Remove($entry)
            return
        }
        'Get-Recipient' {
            $mailbox = Find-FakeExchangeMailbox -World $World -Key $identity
            if ($mailbox) {
                [pscustomobject]@{
                    Identity = $mailbox.Identity; Name = $mailbox.Name; DisplayName = $mailbox.DisplayName; PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
                    ExternalDirectoryObjectId = $mailbox.ExternalDirectoryObjectId; RecipientType = 'UserMailbox'; RecipientTypeDetails = $mailbox.RecipientTypeDetails
                }
                return
            }
            $group = Get-FakeExchangeGroupOrFail -World $World -Key $identity
            $type = if ($group.RecipientTypeDetails -eq 'MailUniversalSecurityGroup') { 'MailUniversalSecurityGroup' } else { 'MailUniversalDistributionGroup' }
            [pscustomobject]@{
                Identity = $group.Identity; Name = $group.Name; DisplayName = $group.DisplayName; PrimarySmtpAddress = $group.PrimarySmtpAddress
                ExternalDirectoryObjectId = $group.ExternalDirectoryObjectId; RecipientType = $type; RecipientTypeDetails = $group.RecipientTypeDetails
            }
            return
        }
    }
    throw "FakeExchange route missing for '$Command'."
}

function global:Invoke-FakeExchangeCommand {
    # Stand-in for Invoke-TenureExchange: logs the call, serves a queued fault if one applies, then runs the fake cmdlet.
    #
    # Faults (World.Faults) are looked at first, one per call:
    #   - an ErrorRecord is thrown as is, whatever the command;
    #   - a scriptblock is invoked with (Command, Parameters); if it throws, that is the
    #     failure, otherwise the call proceeds normally (a conditional fault);
    #   - an Add-FakeExchangeFault entry is thrown when its Command is empty or matches;
    #     otherwise it stays at the head of the queue for a later call.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$World,
        [Parameter(Mandatory)][string]$Command,
        [AllowNull()][hashtable]$Parameters
    )
    Set-StrictMode -Version Latest

    if ($null -eq $Parameters) { $Parameters = @{} }
    $World.Calls.Add(@{ Command = $Command; Parameters = $Parameters.Clone() })

    if ($World.Faults.Count -gt 0) {
        $head = $World.Faults.Peek()
        if ($head -is [System.Management.Automation.ErrorRecord]) {
            [void]$World.Faults.Dequeue()
            throw $head
        }
        if ($head -is [scriptblock]) {
            [void]$World.Faults.Dequeue()
            $null = & $head $Command $Parameters
        } elseif ($head -is [hashtable] -and ([string]::IsNullOrEmpty($head.Command) -or $head.Command -ieq $Command)) {
            [void]$World.Faults.Dequeue()
            throw (New-FakeExchangeError -Command $Command -Message $head.Message -Id $head.Id)
        }
    }

    $allowed = Get-FakeExchangeAllowedParameter -Command $Command
    if ($null -eq $allowed) {
        throw (New-FakeExchangeError -Command $Command -Message "FakeExchange does not implement '$Command'." -Id 'Tenure.Exchange.CommandUnavailable')
    }
    foreach ($key in $Parameters.Keys) {
        if (-not ($allowed | Where-Object { $_ -ieq [string]$key })) {
            throw (New-FakeExchangeError -Command $Command -Message "A parameter cannot be found that matches parameter name '$key'.")
        }
    }

    try {
        Invoke-FakeExchangeRoute -World $World -Command $Command -Parameters $Parameters
    } catch {
        if ($_.Exception.Data.Contains('FakeExchangeError')) {
            throw (New-FakeExchangeError -Command $Command -Message $_.Exception.Message)
        }
        throw
    }
}
