# The FakeExchange fixture is test infrastructure for the Exchange providers; these tests
# pin the behavior the provider tests rely on (and that real Exchange Online has).

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeExchange.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')

    function Invoke-Fake([string]$Command, [hashtable]$Parameters = @{}) {
        Invoke-FakeExchangeCommand -World $script:w -Command $Command -Parameters $Parameters
    }
    # Runs a fake command that must fail and returns the ErrorRecord.
    function Get-FakeFailure([string]$Command, [hashtable]$Parameters = @{}) {
        try {
            Invoke-FakeExchangeCommand -World $script:w -Command $Command -Parameters $Parameters | Out-Null
        } catch {
            return $_
        }
        throw "Expected $Command to fail."
    }
}

AfterAll {
    Remove-Variable -Name FakeExchangeWorld -Scope Global -ErrorAction SilentlyContinue
}

Describe 'FakeExchange world' {
    BeforeEach { $script:w = New-FakeExchangeWorld }

    It 'reuses the FakeGraph ids for alice, bob, carol and the Legal DL' {
        $graph = New-FakeGraphWorld
        $w.Ids.AliceId | Should -Be $graph.Ids.AliceId
        $w.Ids.BobId | Should -Be $graph.Ids.BobId
        $w.Ids.CarolId | Should -Be $graph.Ids.CarolId
        $w.Ids.LegalDlGroupId | Should -Be $graph.Ids.LegalDlGroupId
    }

    It 'keys each mailbox by Entra id and by UPN, both pointing at the same object' {
        [object]::ReferenceEquals($w.Mailboxes[$w.Ids.AliceId], $w.Mailboxes['alice@example.com']) | Should -BeTrue
        [object]::ReferenceEquals($w.Mailboxes[$w.Ids.SharedId], $w.Mailboxes['reception@example.com']) | Should -BeTrue
        @(Get-FakeExchangeMailboxList -World $w).Count | Should -Be 3
    }

    It 'seeds alice as a 12 GB user mailbox with no archive, no holds, no forwarding and auto-reply off' {
        $alice = $w.Mailboxes['alice@example.com']
        $alice.RecipientTypeDetails | Should -Be 'UserMailbox'
        $alice.TotalItemSizeBytes | Should -Be 12GB
        $alice.ArchiveStatus | Should -Be 'None'
        $alice.LitigationHoldEnabled | Should -BeFalse
        @($alice.InPlaceHolds).Count | Should -Be 0
        $alice.RetentionHoldEnabled | Should -BeFalse
        $alice.ForwardingSmtpAddress | Should -BeNullOrEmpty
        $alice.AutoReply.AutoReplyState | Should -Be 'Disabled'
        $alice.CalendarEventsCancelled | Should -BeFalse
    }

    It 'seeds a shared mailbox, the Legal DL with alice, and a mail-enabled security group' {
        $w.Mailboxes['reception@example.com'].RecipientTypeDetails | Should -Be 'SharedMailbox'
        [object]::ReferenceEquals($w.DistributionGroups[$w.Ids.LegalDlGroupId], $w.DistributionGroups['Legal DL']) | Should -BeTrue
        @($w.DistributionGroups['Legal DL'].Members | ForEach-Object { $_.ExternalDirectoryObjectId }) | Should -Be @($w.Ids.AliceId)
        $w.DistributionGroups['Finance Security'].RecipientTypeDetails | Should -Be 'MailUniversalSecurityGroup'
        $w.Me | Should -Be 'carol@example.com'
    }

    It 'Set-FakeExchangeMailboxSize defaults to the 61.2 GB variant' {
        Set-FakeExchangeMailboxSize -World $w -Identity 'alice@example.com'
        $w.Mailboxes['alice@example.com'].TotalItemSizeBytes | Should -Be 65712345678
    }

    It 'Reset-FakeExchangeWorld re-seeds the global world' {
        $global:FakeExchangeWorld = New-FakeExchangeWorld
        $global:FakeExchangeWorld.Mailboxes['alice@example.com'].RecipientTypeDetails = 'SharedMailbox'
        Reset-FakeExchangeWorld
        $global:FakeExchangeWorld.Mailboxes['alice@example.com'].RecipientTypeDetails | Should -Be 'UserMailbox'
    }

    It 'formats sizes like Exchange: one decimal, binary units, the exact byte count with separators' {
        Format-FakeExchangeByteSize -Bytes 65712345678 | Should -Be '61.2 GB (65,712,345,678 bytes)'
        Format-FakeExchangeByteSize -Bytes 12GB | Should -Be '12 GB (12,884,901,888 bytes)'
        Format-FakeExchangeByteSize -Bytes 1536 | Should -Be '1.5 KB (1,536 bytes)'
        Format-FakeExchangeByteSize -Bytes 0 | Should -Be '0 B (0 bytes)'
    }
}

Describe 'Invoke-FakeExchangeCommand plumbing' {
    BeforeEach { $script:w = New-FakeExchangeWorld }

    It 'logs every call with a copy of its parameters, including calls that fail' {
        $parameters = @{ Identity = 'alice@example.com' }
        Invoke-Fake 'Get-Mailbox' $parameters | Out-Null
        $parameters['Identity'] = 'changed'
        Get-FakeFailure 'Get-Mailbox' @{ Identity = 'ghost@example.com' } | Out-Null
        $w.Calls.Count | Should -Be 2
        $w.Calls[0].Command | Should -Be 'Get-Mailbox'
        $w.Calls[0].Parameters['Identity'] | Should -Be 'alice@example.com'
        @(Get-FakeExchangeCall -World $w -Command 'Get-Mailbox').Count | Should -Be 2
        @(Get-FakeExchangeCall -World $w -Command 'Set-Mailbox').Count | Should -Be 0
    }

    It 'fails like the seam: Tenure.Exchange.Failed, the cmdlet name in the message, Command and Inner in Data' {
        $failure = Get-FakeFailure 'Get-Mailbox' @{ Identity = 'ghost@example.com' }
        $failure.FullyQualifiedErrorId | Should -Be 'Tenure.Exchange.Failed'
        $failure.Exception.Data['TenureId'] | Should -Be 'Tenure.Exchange.Failed'
        $failure.Exception.Data['Command'] | Should -Be 'Get-Mailbox'
        $failure.Exception.Data['Inner'] | Should -BeOfType [System.Management.Automation.ErrorRecord]
        $failure.Exception.Message | Should -BeLike "Exchange cmdlet 'Get-Mailbox' failed: *couldn't be found*"
    }

    It 'rejects a parameter the cmdlet does not have, like PowerShell binding would' {
        $failure = Get-FakeFailure 'Set-Mailbox' @{ Identity = 'alice@example.com'; HiddenFromAddresslist = $true }
        $failure.Exception.Message | Should -Match "A parameter cannot be found that matches parameter name 'HiddenFromAddresslist'"
        (Get-FakeFailure 'Get-EXOMailbox' @{ Identity = 'alice@example.com'; Confirm = $false }).Exception.Message | Should -Match "'Confirm'"
    }

    It 'throws CommandUnavailable for a cmdlet it does not implement' {
        (Get-FakeFailure 'Set-CASMailbox' @{ Identity = 'alice@example.com' }).FullyQualifiedErrorId | Should -Be 'Tenure.Exchange.CommandUnavailable'
    }

    It 'serves a command-targeted fault only to that command and keeps it queued until then' {
        Add-FakeExchangeFault -World $w -Command 'Set-Mailbox' -Message 'Injected outage.'
        Invoke-Fake 'Get-Mailbox' @{ Identity = 'alice@example.com' } | Should -Not -BeNullOrEmpty
        $w.Faults.Count | Should -Be 1
        $failure = Get-FakeFailure 'Set-Mailbox' @{ Identity = 'alice@example.com'; Type = 'Shared' }
        $failure.Exception.Message | Should -Be "Exchange cmdlet 'Set-Mailbox' failed: Injected outage."
        $w.Faults.Count | Should -Be 0
        $w.Mailboxes['alice@example.com'].RecipientTypeDetails | Should -Be 'UserMailbox' -Because 'a faulted call changes nothing'
    }

    It 'serves an untargeted fault to the next call, and -Id raises another seam error id' {
        Add-FakeExchangeFault -World $w -Id 'Tenure.Exchange.NotConnected' -Message 'Not connected to Exchange.'
        (Get-FakeFailure 'Get-Mailbox' @{ Identity = 'alice@example.com' }).FullyQualifiedErrorId | Should -Be 'Tenure.Exchange.NotConnected'
    }

    It 'throws a queued ErrorRecord as is, and runs a queued scriptblock as a conditional fault' {
        $record = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('raw'), 'Raw.Fault', 'NotSpecified', $null)
        $w.Faults.Enqueue($record)
        (Get-FakeFailure 'Get-Mailbox' @{ Identity = 'alice@example.com' }).FullyQualifiedErrorId | Should -Be 'Raw.Fault'
        $w.Faults.Enqueue({ param($command, $parameters) if ($command -eq 'Set-Mailbox') { throw 'scripted' } })
        Invoke-Fake 'Get-Mailbox' @{ Identity = 'alice@example.com' } | Should -Not -BeNullOrEmpty
        $w.Faults.Count | Should -Be 0 -Because 'a scriptblock fault is used up even when it does not throw'
        $w.Faults.Enqueue({ param($command, $parameters) throw "scripted $command" })
        (Get-FakeFailure 'Get-Mailbox' @{ Identity = 'alice@example.com' }).Exception.Message | Should -Be 'scripted Get-Mailbox'
    }
}

Describe 'Get-Mailbox and Get-EXOMailbox' {
    BeforeEach { $script:w = New-FakeExchangeWorld }

    It 'finds a mailbox by UPN or primary SMTP address, case-insensitively, and Get-EXOMailbox also by -ExternalDirectoryObjectId' {
        foreach ($key in 'ALICE@example.com', 'alice@example.com') {
            (Invoke-Fake 'Get-EXOMailbox' @{ Identity = $key }).ExternalDirectoryObjectId | Should -Be $w.Ids.AliceId
            (Invoke-Fake 'Get-Mailbox' @{ Identity = $key }).ExternalDirectoryObjectId | Should -Be $w.Ids.AliceId
        }
        (Invoke-Fake 'Get-EXOMailbox' @{ ExternalDirectoryObjectId = $w.Ids.AliceId }).UserPrincipalName | Should -Be 'alice@example.com'
        (Invoke-Fake 'Get-EXOMailbox' @{ ExternalDirectoryObjectId = $w.Ids.AliceId.ToUpperInvariant() }).UserPrincipalName | Should -Be 'alice@example.com'
    }

    It 'reports a missing mailbox with "couldn''t be found" from both cmdlets' {
        foreach ($command in 'Get-Mailbox', 'Get-EXOMailbox') {
            (Get-FakeFailure $command @{ Identity = 'ghost@example.com' }).Exception.Message | Should -BeLike "*couldn't be found*"
        }
    }

    It 'Get-EXOMailbox returns the minimum set, plus only the properties asked for' {
        $minimal = Invoke-Fake 'Get-EXOMailbox' @{ Identity = 'alice@example.com' }
        $minimal.PSObject.Properties['RecipientTypeDetails'] | Should -Not -BeNullOrEmpty
        $minimal.PSObject.Properties['ForwardingSmtpAddress'] | Should -BeNullOrEmpty
        $full = Invoke-Fake 'Get-EXOMailbox' @{ Identity = 'alice@example.com'; Properties = [string[]]@('ForwardingSmtpAddress', 'InPlaceHolds') }
        $full.PSObject.Properties['ForwardingSmtpAddress'] | Should -Not -BeNullOrEmpty
        $full.PSObject.Properties['InPlaceHolds'] | Should -Not -BeNullOrEmpty
        $full.PSObject.Properties['HiddenFromAddressListsEnabled'] | Should -BeNullOrEmpty
    }

    It 'Get-EXOMailbox rejects an unknown property, and a comma-joined string is one unknown name' {
        (Get-FakeFailure 'Get-EXOMailbox' @{ Identity = 'alice@example.com'; Properties = [string[]]@('NoSuchThing') }).Exception.Message | Should -Match "NoSuchThing"
        (Get-FakeFailure 'Get-EXOMailbox' @{ Identity = 'alice@example.com'; Properties = 'ArchiveStatus,InPlaceHolds' }).Exception.Message | Should -Match 'ArchiveStatus,InPlaceHolds'
    }

    It 'Get-Mailbox returns every property' {
        $mailbox = Invoke-Fake 'Get-Mailbox' @{ Identity = 'alice@example.com' }
        foreach ($name in 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward', 'HiddenFromAddressListsEnabled', 'ArchiveStatus', 'LitigationHoldEnabled', 'InPlaceHolds', 'RetentionHoldEnabled') {
            $mailbox.PSObject.Properties[$name] | Should -Not -BeNullOrEmpty -Because "$name is a mailbox property"
        }
    }

    It 'without -Identity lists each mailbox once' {
        @(Invoke-Fake 'Get-Mailbox').Count | Should -Be 3
    }
}

Describe 'Set-Mailbox' {
    BeforeEach { $script:w = New-FakeExchangeWorld; $script:alice = $w.Mailboxes['alice@example.com'] }

    It '-Type Shared and -Type Regular flip RecipientTypeDetails' {
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; Type = 'Shared' }
        $alice.RecipientTypeDetails | Should -Be 'SharedMailbox'
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'ALICE@example.com'; Type = 'regular' }
        $alice.RecipientTypeDetails | Should -Be 'UserMailbox'
    }

    It 'an unsupported -Type fails and a no-change call only warns' {
        (Get-FakeFailure 'Set-Mailbox' @{ Identity = 'alice@example.com'; Type = 'Room' }).Exception.Message | Should -Match 'Shared or Regular'
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; Type = 'Regular' }
        $w.Warnings[-1] | Should -Match 'no settings'
    }

    It 'stores ForwardingSmtpAddress in the smtp: form whether or not the caller used the prefix' {
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; ForwardingSmtpAddress = 'bob@example.com' }
        $alice.ForwardingSmtpAddress | Should -BeExactly 'smtp:bob@example.com'
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; ForwardingSmtpAddress = 'SMTP:carol@example.com' }
        $alice.ForwardingSmtpAddress | Should -BeExactly 'smtp:carol@example.com'
        (Invoke-Fake 'Get-EXOMailbox' @{ Identity = 'alice@example.com'; Properties = [string[]]@('ForwardingSmtpAddress') }).ForwardingSmtpAddress | Should -BeExactly 'smtp:carol@example.com'
    }

    It 'clears ForwardingSmtpAddress with $null and rejects something that is not an address' {
        $alice.ForwardingSmtpAddress = 'smtp:bob@example.com'
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; ForwardingSmtpAddress = $null }
        $alice.ForwardingSmtpAddress | Should -BeNullOrEmpty
        (Get-FakeFailure 'Set-Mailbox' @{ Identity = 'alice@example.com'; ForwardingSmtpAddress = 'not an address' }).Exception.Message | Should -Match 'ProxyAddress'
    }

    It 'ForwardingAddress resolves to a recipient identity, clears with $null, and fails for an unknown recipient' {
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; ForwardingAddress = 'bob@example.com' }
        $alice.ForwardingAddress | Should -Be 'bob'
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; ForwardingAddress = $null }
        $alice.ForwardingAddress | Should -BeNullOrEmpty
        (Get-FakeFailure 'Set-Mailbox' @{ Identity = 'alice@example.com'; ForwardingAddress = 'ghost@example.com' }).Exception.Message | Should -BeLike "*couldn't be found*"
    }

    It 'sets DeliverToMailboxAndForward and HiddenFromAddressListsEnabled from booleans only' {
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; DeliverToMailboxAndForward = $true; HiddenFromAddressListsEnabled = $true }
        $alice.DeliverToMailboxAndForward | Should -BeTrue
        $alice.HiddenFromAddressListsEnabled | Should -BeTrue
        (Get-FakeFailure 'Set-Mailbox' @{ Identity = 'alice@example.com'; HiddenFromAddressListsEnabled = 'false' }).Exception.Message | Should -Match 'System.Boolean'
        $alice.HiddenFromAddressListsEnabled | Should -BeTrue
    }

    It 'fails for a missing mailbox and changes nothing under -WhatIf' {
        (Get-FakeFailure 'Set-Mailbox' @{ Identity = 'ghost@example.com'; Type = 'Shared' }).Exception.Message | Should -BeLike "*couldn't be found*"
        Invoke-Fake 'Set-Mailbox' @{ Identity = 'alice@example.com'; Type = 'Shared'; WhatIf = $true }
        $alice.RecipientTypeDetails | Should -Be 'UserMailbox'
    }
}

Describe 'Get-MailboxStatistics and Get-EXOMailboxStatistics' {
    BeforeEach { $script:w = New-FakeExchangeWorld }

    It 'returns TotalItemSize as the Exchange string built from the byte count' {
        Set-FakeExchangeMailboxSize -World $w -Identity 'alice@example.com'
        (Invoke-Fake 'Get-MailboxStatistics' @{ Identity = 'alice@example.com' }).TotalItemSize | Should -BeExactly '61.2 GB (65,712,345,678 bytes)'
        (Invoke-Fake 'Get-EXOMailboxStatistics' @{ ExternalDirectoryObjectId = $w.Ids.AliceId }).TotalItemSize | Should -BeExactly '61.2 GB (65,712,345,678 bytes)'
        (Invoke-Fake 'Get-EXOMailboxStatistics' @{ Identity = 'bob@example.com' }).TotalItemSize | Should -BeExactly '3 GB (3,221,225,472 bytes)'
    }

    It 'returns nothing, with a warning, for a mailbox nobody has signed in to' {
        $w.Mailboxes['alice@example.com'].NeverLoggedOn = $true
        @(Invoke-Fake 'Get-EXOMailboxStatistics' @{ Identity = 'alice@example.com' }).Count | Should -Be 0
        $w.Warnings[-1] | Should -Match "hasn't logged on"
    }

    It 'fails for a missing mailbox' {
        (Get-FakeFailure 'Get-EXOMailboxStatistics' @{ Identity = 'ghost@example.com' }).Exception.Message | Should -BeLike "*couldn't be found*"
    }
}

Describe 'Get-MailboxAutoReplyConfiguration and Set-MailboxAutoReplyConfiguration' {
    BeforeEach { $script:w = New-FakeExchangeWorld }

    It 'starts disabled with empty messages' {
        $config = Invoke-Fake 'Get-MailboxAutoReplyConfiguration' @{ Identity = 'alice@example.com' }
        $config.AutoReplyState | Should -Be 'Disabled'
        $config.InternalMessage | Should -BeNullOrEmpty
        $config.ExternalAudience | Should -Be 'All'
    }

    It 'stores what was set and returns the messages wrapped in HTML, line breaks as br tags' {
        Invoke-Fake 'Set-MailboxAutoReplyConfiguration' @{ Identity = 'alice@example.com'; AutoReplyState = 'enabled'; InternalMessage = "Gone.`nAsk Bob."; ExternalMessage = 'Gone.'; ExternalAudience = 'known' }
        $config = Invoke-Fake 'Get-MailboxAutoReplyConfiguration' @{ Identity = 'alice@example.com' }
        $config.AutoReplyState | Should -Be 'Enabled'
        $config.ExternalAudience | Should -Be 'Known'
        $config.InternalMessage | Should -Match '^<html>'
        $config.InternalMessage | Should -Match 'Gone\.<br>'
        $config.ExternalMessage | Should -Match '<div>Gone\.</div>'
        $w.Mailboxes['alice@example.com'].AutoReply.InternalMessage | Should -Be "Gone.`nAsk Bob."
    }

    It 'changes only the parameters given and rejects an unknown state or audience' {
        Invoke-Fake 'Set-MailboxAutoReplyConfiguration' @{ Identity = 'alice@example.com'; AutoReplyState = 'Enabled'; InternalMessage = 'Gone.' }
        Invoke-Fake 'Set-MailboxAutoReplyConfiguration' @{ Identity = 'alice@example.com'; AutoReplyState = 'Disabled' }
        $w.Mailboxes['alice@example.com'].AutoReply.InternalMessage | Should -Be 'Gone.'
        (Get-FakeFailure 'Set-MailboxAutoReplyConfiguration' @{ Identity = 'alice@example.com'; AutoReplyState = 'On' }).Exception.Message | Should -Match 'AutoReplyState'
        (Get-FakeFailure 'Set-MailboxAutoReplyConfiguration' @{ Identity = 'alice@example.com'; ExternalAudience = 'Everyone' }).Exception.Message | Should -Match 'ExternalAudience'
    }
}

Describe 'Mailbox permissions' {
    BeforeEach { $script:w = New-FakeExchangeWorld; $script:alice = $w.Mailboxes['alice@example.com'] }

    It 'lists every entry without -User, and only that user''s entries with -User' {
        foreach ($command in 'Get-MailboxPermission', 'Get-EXOMailboxPermission') {
            @(Invoke-Fake $command @{ Identity = 'alice@example.com' }).Count | Should -Be 2
            @(Invoke-Fake $command @{ Identity = 'alice@example.com'; User = 'bob@example.com' }).Count | Should -Be 0
        }
        $entry = @(Invoke-Fake 'Get-EXOMailboxPermission' @{ Identity = 'reception@example.com'; User = 'bob@example.com' })
        $entry.Count | Should -Be 1
        $entry[0].User | Should -Be 'bob@example.com'
        @($entry[0].AccessRights) | Should -Be @('FullAccess')
        $entry[0].IsInherited | Should -BeFalse
    }

    It 'fails when -User names nobody' {
        (Get-FakeFailure 'Get-EXOMailboxPermission' @{ Identity = 'alice@example.com'; User = 'ghost@example.com' }).Exception.Message | Should -BeLike "*couldn't be found*"
    }

    It 'Add-MailboxPermission adds an explicit entry and records AutoMapping (on unless turned off, like Exchange)' {
        $added = Invoke-Fake 'Add-MailboxPermission' @{ Identity = 'alice@example.com'; User = 'bob@example.com'; AccessRights = 'FullAccess'; InheritanceType = 'All'; AutoMapping = $false }
        $added.User | Should -Be 'bob@example.com'
        $entry = $alice.Permissions | Where-Object { $_.User -eq 'bob@example.com' }
        @($entry.AccessRights) | Should -Be @('FullAccess')
        $entry.AutoMapping | Should -BeFalse
        Invoke-Fake 'Add-MailboxPermission' @{ Identity = 'bob@example.com'; User = 'alice@example.com'; AccessRights = 'FullAccess' } | Out-Null
        ($w.Mailboxes['bob@example.com'].Permissions | Where-Object { $_.User -eq 'alice@example.com' }).AutoMapping | Should -BeTrue
    }

    It 'adding an entry that exists is a no-op with a warning, not an error' {
        Invoke-Fake 'Add-MailboxPermission' @{ Identity = 'reception@example.com'; User = 'bob@example.com'; AccessRights = 'FullAccess' } | Should -BeNullOrEmpty
        $w.Warnings[-1] | Should -Match 'already present'
        @($w.Mailboxes['reception@example.com'].Permissions).Count | Should -Be 1
    }

    It 'merges a new right into an existing entry and rejects an unknown right' {
        Invoke-Fake 'Add-MailboxPermission' @{ Identity = 'reception@example.com'; User = 'bob@example.com'; AccessRights = [string[]]@('ReadPermission') } | Out-Null
        @(($w.Mailboxes['reception@example.com'].Permissions | Where-Object { $_.User -eq 'bob@example.com' }).AccessRights) | Should -Be @('FullAccess', 'ReadPermission')
        (Get-FakeFailure 'Add-MailboxPermission' @{ Identity = 'alice@example.com'; User = 'bob@example.com'; AccessRights = 'Everything' }).Exception.Message | Should -Match 'Everything'
    }

    It 'Remove-MailboxPermission needs -Confirm:$false' {
        (Get-FakeFailure 'Remove-MailboxPermission' @{ Identity = 'reception@example.com'; User = 'bob@example.com'; AccessRights = 'FullAccess' }).Exception.Message | Should -Match 'confirmation'
        @($w.Mailboxes['reception@example.com'].Permissions).Count | Should -Be 1
    }

    It 'Remove-MailboxPermission removes the right, drops an empty entry, and only warns when the entry is absent' {
        Invoke-Fake 'Remove-MailboxPermission' @{ Identity = 'reception@example.com'; User = 'bob@example.com'; AccessRights = 'FullAccess'; InheritanceType = 'All'; Confirm = $false }
        @($w.Mailboxes['reception@example.com'].Permissions).Count | Should -Be 0
        Invoke-Fake 'Remove-MailboxPermission' @{ Identity = 'reception@example.com'; User = 'bob@example.com'; AccessRights = 'FullAccess'; Confirm = $false }
        $w.Warnings[-1] | Should -Match "isn't present"
    }

    It 'never removes an inherited entry' {
        Invoke-Fake 'Remove-MailboxPermission' @{ Identity = 'alice@example.com'; User = 'alice@example.com'; AccessRights = 'FullAccess'; Confirm = $false }
        @($alice.Permissions | Where-Object { $_.IsInherited }).Count | Should -Be 1
    }
}

Describe 'Remove-CalendarEvents' {
    BeforeEach { $script:w = New-FakeExchangeWorld; $script:alice = $w.Mailboxes['alice@example.com'] }

    It 'cancels organized meetings for the window and records it' {
        Invoke-Fake 'Remove-CalendarEvents' @{ Identity = 'alice@example.com'; CancelOrganizedMeetings = $true; QueryWindowInDays = 120; Confirm = $false }
        $alice.CalendarEventsCancelled | Should -BeTrue
        $alice.CancelQueryWindowInDays | Should -Be 120
    }

    It 'needs -Confirm:$false, -CancelOrganizedMeetings and a window of 1 to 1825 days' {
        (Get-FakeFailure 'Remove-CalendarEvents' @{ Identity = 'alice@example.com'; CancelOrganizedMeetings = $true; QueryWindowInDays = 120 }).Exception.Message | Should -Match 'confirmation'
        (Get-FakeFailure 'Remove-CalendarEvents' @{ Identity = 'alice@example.com'; QueryWindowInDays = 120; Confirm = $false }).Exception.Message | Should -Match 'CancelOrganizedMeetings'
        (Get-FakeFailure 'Remove-CalendarEvents' @{ Identity = 'alice@example.com'; CancelOrganizedMeetings = $true; QueryWindowInDays = 1826; Confirm = $false }).Exception.Message | Should -Match '1825'
        (Get-FakeFailure 'Remove-CalendarEvents' @{ Identity = 'alice@example.com'; CancelOrganizedMeetings = $true; QueryWindowInDays = 0; Confirm = $false }).Exception.Message | Should -Match '1825'
        $alice.CalendarEventsCancelled | Should -BeFalse
    }

    It 'changes nothing with -PreviewOnly or -WhatIf' {
        Invoke-Fake 'Remove-CalendarEvents' @{ Identity = 'alice@example.com'; PreviewOnly = $true; QueryWindowInDays = 10; Confirm = $false }
        Invoke-Fake 'Remove-CalendarEvents' @{ Identity = 'alice@example.com'; CancelOrganizedMeetings = $true; QueryWindowInDays = 10; Confirm = $false; WhatIf = $true }
        $alice.CalendarEventsCancelled | Should -BeFalse
    }
}

Describe 'Distribution groups' {
    BeforeEach { $script:w = New-FakeExchangeWorld; $script:legal = $w.DistributionGroups['Legal DL'] }

    It 'Get-DistributionGroup finds a group by its address and fails for an unknown one' {
        foreach ($key in 'legal@example.com', 'LEGAL@example.com') {
            (Invoke-Fake 'Get-DistributionGroup' @{ Identity = $key }).ExternalDirectoryObjectId | Should -Be $w.Ids.LegalDlGroupId
        }
        (Get-FakeFailure 'Get-DistributionGroup' @{ Identity = 'ghosts@example.com' }).Exception.Message | Should -BeLike "*couldn't be found*"
        @(Invoke-Fake 'Get-DistributionGroup').Count | Should -Be 2
    }

    It 'Get-DistributionGroupMember honors ResultSize (1000 by default, Unlimited, or a number with a warning)' {
        $finance = @{ Identity = 'finance-security@example.com' }
        @(Invoke-Fake 'Get-DistributionGroupMember' $finance).Count | Should -Be 2
        @(Invoke-Fake 'Get-DistributionGroupMember' @{ Identity = 'finance-security@example.com'; ResultSize = 'Unlimited' }).Count | Should -Be 2
        @(Invoke-Fake 'Get-DistributionGroupMember' @{ Identity = 'finance-security@example.com'; ResultSize = 1 }).Count | Should -Be 1
        $w.Warnings[-1] | Should -Match 'more results'
        (Invoke-Fake 'Get-DistributionGroupMember' @{ Identity = 'legal@example.com' }).ExternalDirectoryObjectId | Should -Be $w.Ids.AliceId
    }

    It 'Add-DistributionGroupMember refuses a non-manager without -BypassSecurityGroupManagerCheck' {
        (Get-FakeFailure 'Add-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = 'bob@example.com' }).Exception.Message | Should -Match 'manager of the group'
        @($legal.Members).Count | Should -Be 1
    }

    It 'Add-DistributionGroupMember adds by address with the bypass, and a duplicate is "already a member"' {
        Invoke-Fake 'Add-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = 'bob@example.com'; BypassSecurityGroupManagerCheck = $true; Confirm = $false }
        @($legal.Members | ForEach-Object { $_.ExternalDirectoryObjectId }) | Should -Contain $w.Ids.BobId
        (Get-FakeFailure 'Add-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = 'bob@example.com'; BypassSecurityGroupManagerCheck = $true }).Exception.Message | Should -Match 'already a member'
        (Get-FakeFailure 'Add-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = 'ghost@example.com'; BypassSecurityGroupManagerCheck = $true }).Exception.Message | Should -BeLike "*couldn't be found*"
    }

    It 'a manager of the group needs no bypass' {
        $w.Me = 'bob@example.com'
        Invoke-Fake 'Add-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = 'bob@example.com' }
        @($legal.Members).Count | Should -Be 2
    }

    It 'Remove-DistributionGroupMember needs -Confirm:$false, removes, and a non-member is "isn''t a member"' {
        (Get-FakeFailure 'Remove-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = 'alice@example.com'; BypassSecurityGroupManagerCheck = $true }).Exception.Message | Should -Match 'confirmation'
        Invoke-Fake 'Remove-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = 'alice@example.com'; BypassSecurityGroupManagerCheck = $true; Confirm = $false }
        @($legal.Members).Count | Should -Be 0
        (Get-FakeFailure 'Remove-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = 'alice@example.com'; BypassSecurityGroupManagerCheck = $true; Confirm = $false }).Exception.Message | Should -Match "isn't a member"
    }

    It 'Get-Recipient resolves mailboxes and groups' {
        (Invoke-Fake 'Get-Recipient' @{ Identity = 'reception@example.com' }).RecipientTypeDetails | Should -Be 'SharedMailbox'
        (Invoke-Fake 'Get-Recipient' @{ Identity = 'finance-security@example.com' }).RecipientTypeDetails | Should -Be 'MailUniversalSecurityGroup'
        (Get-FakeFailure 'Get-Recipient' @{ Identity = 'nobody@example.com' }).Exception.Message | Should -BeLike "*couldn't be found*"
    }
}

Describe 'Identity contract (real Exchange is not trusted to resolve an Entra object id)' {
    BeforeEach { $script:w = New-FakeExchangeWorld }

    It '-Identity on <_> must be a UPN or SMTP address: an Entra id or an alias answers "couldn''t be found" naming the value' -ForEach @('Get-Mailbox', 'Get-EXOMailbox', 'Get-EXOMailboxStatistics', 'Get-MailboxStatistics', 'Get-MailboxAutoReplyConfiguration', 'Get-EXOMailboxPermission', 'Get-MailboxPermission') {
        $id = '10000000-0000-4000-8000-000000000001'
        $failure = Get-FakeFailure $_ @{ Identity = $id }
        $failure.Exception.Message | Should -BeLike "*'$id' couldn't be found*"
        (Get-FakeFailure $_ @{ Identity = 'alice' }).Exception.Message | Should -BeLike "*'alice' couldn't be found*"
    }

    It 'writes refuse an Entra id as -Identity and change nothing' {
        $alice = $w.Mailboxes['alice@example.com']
        $id = $w.Ids.AliceId
        (Get-FakeFailure 'Set-Mailbox' @{ Identity = $id; Type = 'Shared' }).Exception.Message | Should -BeLike "*couldn't be found*"
        (Get-FakeFailure 'Set-MailboxAutoReplyConfiguration' @{ Identity = $id; AutoReplyState = 'Enabled' }).Exception.Message | Should -BeLike "*couldn't be found*"
        (Get-FakeFailure 'Add-MailboxPermission' @{ Identity = $id; User = 'bob@example.com'; AccessRights = 'FullAccess' }).Exception.Message | Should -BeLike "*couldn't be found*"
        (Get-FakeFailure 'Remove-CalendarEvents' @{ Identity = $id; CancelOrganizedMeetings = $true; QueryWindowInDays = 10; Confirm = $false }).Exception.Message | Should -BeLike "*couldn't be found*"
        $alice.RecipientTypeDetails | Should -Be 'UserMailbox'
        $alice.AutoReply.AutoReplyState | Should -Be 'Disabled'
        $alice.CalendarEventsCancelled | Should -BeFalse
    }

    It 'distribution group cmdlets take the group address as -Identity and a member address as -Member, never an Entra id' {
        (Get-FakeFailure 'Get-DistributionGroup' @{ Identity = $w.Ids.LegalDlGroupId }).Exception.Message | Should -BeLike "*couldn't be found*"
        (Get-FakeFailure 'Get-DistributionGroup' @{ Identity = 'Legal DL' }).Exception.Message | Should -BeLike "*couldn't be found*"
        (Get-FakeFailure 'Get-DistributionGroupMember' @{ Identity = $w.Ids.LegalDlGroupId }).Exception.Message | Should -BeLike "*couldn't be found*"
        (Get-FakeFailure 'Add-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = $w.Ids.BobId; BypassSecurityGroupManagerCheck = $true }).Exception.Message | Should -BeLike "*'$($w.Ids.BobId)' couldn't be found*"
        (Get-FakeFailure 'Remove-DistributionGroupMember' @{ Identity = 'legal@example.com'; Member = $w.Ids.AliceId; BypassSecurityGroupManagerCheck = $true; Confirm = $false }).Exception.Message | Should -BeLike "*couldn't be found*"
        @($w.DistributionGroups['Legal DL'].Members).Count | Should -Be 1
    }

    It '-User on permission cmdlets must be an address' {
        (Get-FakeFailure 'Get-EXOMailboxPermission' @{ Identity = 'alice@example.com'; User = $w.Ids.BobId }).Exception.Message | Should -BeLike "*'$($w.Ids.BobId)' couldn't be found*"
        (Get-FakeFailure 'Add-MailboxPermission' @{ Identity = 'alice@example.com'; User = $w.Ids.BobId; AccessRights = 'FullAccess' }).Exception.Message | Should -BeLike "*couldn't be found*"
    }

    It 'Get-EXOMailbox and Get-EXOMailboxStatistics take -ExternalDirectoryObjectId; an unknown id is "couldn''t be found" naming the id' {
        foreach ($command in 'Get-EXOMailbox', 'Get-EXOMailboxStatistics') {
            @(Invoke-Fake $command @{ ExternalDirectoryObjectId = $w.Ids.BobId }).Count | Should -Be 1
            $ghost = '99999999-9999-4999-8999-999999999999'
            (Get-FakeFailure $command @{ ExternalDirectoryObjectId = $ghost }).Exception.Message | Should -BeLike "*'$ghost' couldn't be found*"
            (Get-FakeFailure $command @{ ExternalDirectoryObjectId = $w.Ids.BobId; Identity = 'bob@example.com' }).Exception.Message | Should -Match 'Parameter set cannot be resolved'
        }
        (Get-FakeFailure 'Get-Mailbox' @{ ExternalDirectoryObjectId = $w.Ids.BobId }).Exception.Message | Should -Match 'A parameter cannot be found'
    }
}
