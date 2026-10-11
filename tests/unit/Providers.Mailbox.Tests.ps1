# The Exchange Online providers against FakeExchange. The seam itself is mocked
# (Exchange cmdlets do not exist before connect); the mock keeps the seam's connection check.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeExchange.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeExchangeWorld = New-FakeExchangeWorld
    Mock -ModuleName Tenure Invoke-TenureExchange {
        & (Get-Module -Name Tenure) { Assert-TenureConnection -Backend Exchange }
        Invoke-FakeExchangeCommand -World $global:FakeExchangeWorld -Command $Command -Parameters $Parameters
    }

    function Get-Canonical($Object) { Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $Object) }
    function Get-Provider([string]$Name) { Get-TenureProvider -Name $Name }
    function New-MailboxTarget([string]$Id, [string]$Name, [string]$Grantee) {
        $target = @{ Kind = 'mailbox'; Id = $Id; Name = $Name }
        if ($Grantee) { $target.Grantee = $Grantee }
        $target
    }
    function New-Context([string]$SubjectId) {
        $context = @{ Secrets = @{}; StepId = 'S07'; Mode = 'Apply' }
        if ($SubjectId) { $context.Subject = @{ Id = $SubjectId; UserPrincipalName = $null; DisplayName = $null } }
        $context
    }
    function Get-Writes { @($global:FakeExchangeWorld.Calls | Where-Object { $_.Command -notlike 'Get-*' }) }
    function Get-Calls([string]$Command) { @(Get-FakeExchangeCall -World $global:FakeExchangeWorld -Command $Command) }
    function Invoke-Helper([scriptblock]$ScriptBlock, [object[]]$ArgumentList = @()) { Invoke-InTenure -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList }
}

AfterAll {
    Remove-Variable -Name FakeExchangeWorld -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Exchange providers' {
    BeforeEach {
        Reset-FakeExchangeWorld
        $script:w = $global:FakeExchangeWorld
        $script:ids = $script:w.Ids
        $script:alice = $script:w.Mailboxes['alice@example.com']
        $script:aliceTarget = New-MailboxTarget $script:ids.AliceId 'alice@example.com'
    }

    Describe 'Exchange provider registrations' {
        It '<Name> is a <Kind> provider on Exchange, risk <Risk>, reversible <Reversible>, no Graph scopes' -ForEach @(
            @{ Name = 'Mailbox.Type'; Kind = 'State'; Risk = 'High'; Reversible = $true }
            @{ Name = 'Mailbox.Forwarding'; Kind = 'State'; Risk = 'Medium'; Reversible = $true }
            @{ Name = 'Mailbox.AutoReply'; Kind = 'State'; Risk = 'Low'; Reversible = $true }
            @{ Name = 'Mailbox.Delegate'; Kind = 'State'; Risk = 'Medium'; Reversible = $true }
            @{ Name = 'Mailbox.Hidden'; Kind = 'State'; Risk = 'Low'; Reversible = $true }
            @{ Name = 'Calendar.CancelMeetings'; Kind = 'Invoke'; Risk = 'Destructive'; Reversible = $false }
            @{ Name = 'DistributionGroup.Member'; Kind = 'State'; Risk = 'Medium'; Reversible = $true }
            @{ Name = 'Check.MailboxSharedEligibility'; Kind = 'Check'; Risk = 'Low'; Reversible = $true }
        ) {
            $provider = Get-Provider $Name
            $provider.Kind | Should -Be $Kind
            $provider.Backend | Should -Be 'Exchange'
            $provider.Risk | Should -Be $Risk
            $provider.Reversible | Should -Be $Reversible
            @($provider.Scopes).Count | Should -Be 0
            $provider.Description | Should -Not -BeNullOrEmpty
        }

        It 'the eligibility check warns rather than refuses, and has no Set' {
            $provider = Get-Provider 'Check.MailboxSharedEligibility'
            $provider.Severity | Should -Be 'Warn'
            $provider.Set | Should -BeNullOrEmpty
        }
    }

    Describe 'Every Exchange provider Get' {
        BeforeAll {
            $script:cases = @(
                @{ Name = 'Mailbox.Type'; Group = $false }
                @{ Name = 'Mailbox.Forwarding'; Group = $false }
                @{ Name = 'Mailbox.AutoReply'; Group = $false }
                @{ Name = 'Mailbox.Delegate'; Group = $false }
                @{ Name = 'Mailbox.Hidden'; Group = $false }
                @{ Name = 'Calendar.CancelMeetings'; Group = $false }
                @{ Name = 'DistributionGroup.Member'; Group = $true }
                @{ Name = 'Check.MailboxSharedEligibility'; Group = $false }
            )
            # A group is named by its address (Target.Mail): the Legal DL's for its own id, an unknown one otherwise.
            function Get-CaseTarget([hashtable]$Case, [string]$Id) {
                if ($Case.Group) {
                    $mail = if ($Id -eq $script:ids.LegalDlGroupId) { 'legal@example.com' } else { 'no-such-group@example.com' }
                    return @{ Kind = 'group'; Id = $Id; Name = 'Some group'; Mail = $mail }
                }
                New-MailboxTarget $Id 'someone@example.com' 'bob@example.com'
            }
        }

        It 'returns one PSCustomObject, and the same canonical form twice (fingerprint stability)' {
            foreach ($case in $cases) {
                $provider = Get-Provider $case.Name
                $id = if ($case.Group) { $ids.LegalDlGroupId } else { $ids.AliceId }
                $first = & $provider.Get (Get-CaseTarget $case $id) (New-Context $ids.AliceId)
                $first | Should -BeOfType [pscustomobject] -Because $case.Name
                @($first).Count | Should -Be 1 -Because $case.Name
                $second = & $provider.Get (Get-CaseTarget $case $id) (New-Context $ids.AliceId)
                (Get-Canonical $second) | Should -BeExactly (Get-Canonical $first) -Because $case.Name
            }
        }

        It 'maps "couldn''t be found" to Tenure.Provider.TargetNotFound, and a target without an id too' {
            foreach ($case in $cases) {
                $provider = Get-Provider $case.Name
                { & $provider.Get (Get-CaseTarget $case '99999999-9999-4999-8999-999999999999') (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound' -Because $case.Name
                { & $provider.Get (Get-CaseTarget $case $null) (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound' -Because $case.Name
                { & $provider.Get (Get-CaseTarget $case '{{subjectId}}') (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound' -Because $case.Name
            }
        }

        It 'keeps the inner Exchange message on TargetNotFound so a person can see which object was missing' {
            $failure = { & (Get-Provider 'Mailbox.Hidden').Get (New-MailboxTarget 'ghost@example.com' 'ghost') (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound' -PassThru
            $failure.Exception.Message | Should -Match 'ghost@example.com'
            $failure.Exception.InnerException | Should -Not -BeNullOrEmpty
        }

        It 'takes "couldn''t be found" for a missing target only when it names the value the read asked for' {
            $provider = Get-Provider 'Mailbox.Hidden'
            foreach ($message in "The domain controller couldn't be found.", "The operation couldn't be performed because object 'someone-else@example.com' couldn't be found on 'FAKEPR01A001.PROD.OUTLOOK.COM'.") {
                Add-FakeExchangeFault -World $w -Command 'Get-EXOMailbox' -Message $message
                { & $provider.Get $aliceTarget (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed' -Because $message
            }
            Add-FakeExchangeFault -World $w -Command 'Get-EXOMailbox' -Message "The operation couldn't be performed because object '$($ids.AliceId)' couldn't be found on 'FAKEPR01A001.PROD.OUTLOOK.COM'."
            { & $provider.Get $aliceTarget (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'refuses a mailbox Exchange returns for another Entra id instead of acting on it' {
            Mock -ModuleName Tenure Invoke-TenureExchange { [pscustomobject]@{ ExternalDirectoryObjectId = '10000000-0000-4000-8000-000000000002'; UserPrincipalName = 'bob@example.com'; RecipientTypeDetails = 'UserMailbox' } }
            { & (Get-Provider 'Mailbox.Type').Get $aliceTarget (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidResult'
            { & (Get-Provider 'Mailbox.Hidden').Set $aliceTarget @{ hiddenFromAddressLists = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidResult'
        }

        It 'reuses a mailbox address read while a plan is built, and reads it afresh at apply time' {
            $autoReply = Get-Provider 'Mailbox.AutoReply'
            $plan = @{ Mode = 'Plan'; ExchangeAddresses = @{}; Secrets = @{} }
            & (Get-Provider 'Mailbox.Type').Get $aliceTarget $plan | Out-Null
            $plan.ExchangeAddresses[$ids.AliceId] | Should -BeExactly 'alice@example.com'
            & $autoReply.Get $aliceTarget $plan | Out-Null
            @(Get-Calls 'Get-EXOMailbox').Count | Should -Be 1 -Because 'the auto-reply read reuses the address found by the earlier read of the same plan'
            @(Get-Calls 'Get-MailboxAutoReplyConfiguration')[0].Parameters['Identity'] | Should -BeExactly 'alice@example.com'
            $apply = @{ Mode = 'Apply'; ExchangeAddresses = @{ ($ids.AliceId) = 'someone-else@example.com' }; Secrets = @{} }
            & $autoReply.Get $aliceTarget $apply | Out-Null
            @(Get-Calls 'Get-EXOMailbox').Count | Should -Be 2 -Because 'at apply time the address is always read from Exchange by Entra id'
            @(Get-Calls 'Get-MailboxAutoReplyConfiguration')[-1].Parameters['Identity'] | Should -BeExactly 'alice@example.com'
        }

        It 'lets other Exchange failures through unchanged' {
            foreach ($case in $cases) {
                Add-FakeExchangeFault -World $w -Message 'The server is busy.'
                $provider = Get-Provider $case.Name
                $id = if ($case.Group) { $ids.LegalDlGroupId } else { $ids.AliceId }
                { & $provider.Get (Get-CaseTarget $case $id) (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed' -Because $case.Name
            }
        }

        It 'a mailbox Get is unchanged by the earlier offboard steps (no self-inflicted drift after the conversion to shared)' {
            $names = 'Check.MailboxSharedEligibility', 'Mailbox.Forwarding', 'Mailbox.AutoReply', 'Mailbox.Delegate', 'Mailbox.Hidden', 'Calendar.CancelMeetings'
            $target = New-MailboxTarget $ids.AliceId 'alice@example.com' 'bob@example.com'
            $before = @{}
            foreach ($name in $names) { $before[$name] = Get-Canonical (& (Get-Provider $name).Get $target (New-Context $ids.AliceId)) }
            & (Get-Provider 'Mailbox.Type').Set $target @{ type = 'Shared' } $null (New-Context $ids.AliceId) | Out-Null
            foreach ($name in $names) {
                (Get-Canonical (& (Get-Provider $name).Get $target (New-Context $ids.AliceId))) | Should -BeExactly $before[$name] -Because "$name runs after Mailbox.Type in an offboard plan"
            }
        }
    }

    Describe 'Mailbox.Type' {
        BeforeAll { $script:provider = Get-Provider 'Mailbox.Type' }

        It 'Get reports identity, UPN and Regular for a user mailbox, asking Get-EXOMailbox only for RecipientTypeDetails' {
            $current = & $provider.Get $aliceTarget (New-Context)
            @($current.PSObject.Properties.Name) | Should -Be @('identity', 'userPrincipalName', 'type')
            $current.identity | Should -Be $ids.AliceId
            $current.userPrincipalName | Should -Be 'alice@example.com'
            $current.type | Should -Be 'Regular'
            $call = @(Get-Calls 'Get-EXOMailbox')[0]
            $call.Parameters['ExternalDirectoryObjectId'] | Should -Be $ids.AliceId
            $call.Parameters.ContainsKey('Identity') | Should -BeFalse -Because 'an Entra id is never passed as -Identity'
            @($call.Parameters['Properties']) | Should -Be @('RecipientTypeDetails')
        }

        It 'Get reports Shared for a shared mailbox and any other type raw' {
            (& $provider.Get (New-MailboxTarget $ids.SharedId 'reception@example.com') (New-Context)).type | Should -Be 'Shared'
            $alice.RecipientTypeDetails = 'EquipmentMailbox'
            (& $provider.Get $aliceTarget (New-Context)).type | Should -Be 'EquipmentMailbox'
        }

        It 'Test is true only when the type matches' {
            $regular = [pscustomobject]@{ identity = $ids.AliceId; userPrincipalName = 'alice@example.com'; type = 'Regular' }
            (& $provider.Test $regular @{ type = 'Regular' }) | Should -BeTrue
            (& $provider.Test $regular @{ type = 'regular' }) | Should -BeTrue
            (& $provider.Test $regular @{ type = 'Shared' }) | Should -BeFalse
            (& $provider.Test $null @{ type = 'Shared' }) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ type = 'RoomMailbox' }) @{ type = 'Shared' }) | Should -BeFalse
        }

        It 'Test refuses a Desired that is not Shared or Regular, or has an unknown key' {
            { & $provider.Test $null @{ type = 'Room' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Test $null @{} } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Test $null @{ type = 'Shared'; tpye = 'Shared' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        }

        It 'Set converts Regular -> Shared with Set-Mailbox -Type, then Get and Test agree' {
            $current = & $provider.Get $aliceTarget (New-Context)
            $observed = & $provider.Set $aliceTarget @{ type = 'Shared' } $current (New-Context)
            $observed.type | Should -Be 'Shared'
            $alice.RecipientTypeDetails | Should -Be 'SharedMailbox'
            $writes = @(Get-Writes)
            $writes.Count | Should -Be 1
            $writes[0].Command | Should -Be 'Set-Mailbox'
            $writes[0].Parameters['Identity'] | Should -Be 'alice@example.com'
            $writes[0].Parameters['Type'] | Should -Be 'Shared'
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) @{ type = 'Shared' }) | Should -BeTrue
        }

        It 'a second Set is harmless and Test stays true; Shared -> Regular works the same way' {
            & $provider.Set $aliceTarget @{ type = 'Shared' } $null (New-Context) | Out-Null
            { & $provider.Set $aliceTarget @{ type = 'Shared' } $null (New-Context) } | Should -Not -Throw
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) @{ type = 'Shared' }) | Should -BeTrue
            $back = & $provider.Set $aliceTarget @{ type = 'Regular' } $null (New-Context)
            (& $provider.Test $back @{ type = 'Regular' }) | Should -BeTrue
        }

        It 'Set never converts a room, equipment or unknown mailbox: Tenure.Provider.Unsupported and no write' {
            $alice.RecipientTypeDetails = 'RoomMailbox'
            { & $provider.Set $aliceTarget @{ type = 'Shared' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.Unsupported'
            { & $provider.Set $aliceTarget @{ type = 'Shared' } ([pscustomobject]@{ type = $null }) (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.Unsupported'
            @(Get-Writes).Count | Should -Be 0
            $alice.RecipientTypeDetails | Should -Be 'RoomMailbox'
        }

        It 'Describe shows the change as "Regular -> Shared"' {
            $current = & $provider.Get $aliceTarget (New-Context)
            (& $provider.Describe $aliceTarget $current @{ type = 'Shared' } 'Update') | Should -Be 'Update mailbox type of alice@example.com: Regular -> Shared'
            (& $provider.Describe $aliceTarget $null @{ type = 'Shared' } 'Create') | Should -Match '\? -> Shared$'
        }
    }

    Describe 'Mailbox.Forwarding' {
        BeforeAll { $script:provider = Get-Provider 'Mailbox.Forwarding' }

        It 'Get reports the SMTP forward lowercased without the smtp: prefix, the internal forward, and the keep-a-copy flag' {
            $alice.ForwardingSmtpAddress = 'smtp:Bob@Example.COM'
            $alice.DeliverToMailboxAndForward = $true
            $current = & $provider.Get $aliceTarget (New-Context)
            @($current.PSObject.Properties.Name) | Should -Be @('forwardingSmtpAddress', 'forwardingAddress', 'deliverToMailboxAndForward')
            $current.forwardingSmtpAddress | Should -BeExactly 'bob@example.com'
            $current.forwardingAddress | Should -BeNullOrEmpty
            $current.deliverToMailboxAndForward | Should -BeTrue
            @(@(Get-Calls 'Get-EXOMailbox')[0].Parameters['Properties']) | Should -Be @('ForwardingAddress', 'ForwardingSmtpAddress', 'DeliverToMailboxAndForward')
        }

        It 'Get reports no forwarding as $null, not an empty string' {
            $current = & $provider.Get $aliceTarget (New-Context)
            $null -eq $current.forwardingSmtpAddress | Should -BeTrue
            $null -eq $current.forwardingAddress | Should -BeTrue
            $current.deliverToMailboxAndForward | Should -BeFalse
        }

        It 'Test compares the address case-insensitively (null equals null) and the flag exactly' {
            $on = [pscustomobject]@{ forwardingSmtpAddress = 'bob@example.com'; forwardingAddress = $null; deliverToMailboxAndForward = $true }
            $off = [pscustomobject]@{ forwardingSmtpAddress = $null; forwardingAddress = $null; deliverToMailboxAndForward = $false }
            (& $provider.Test $on @{ forwardingSmtpAddress = 'BOB@example.com'; deliverToMailboxAndForward = $true }) | Should -BeTrue
            (& $provider.Test $on @{ forwardingSmtpAddress = 'smtp:bob@example.com'; deliverToMailboxAndForward = $true }) | Should -BeTrue
            (& $provider.Test $on @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $false }) | Should -BeFalse
            (& $provider.Test $on @{ forwardingSmtpAddress = 'carol@example.com'; deliverToMailboxAndForward = $true }) | Should -BeFalse
            (& $provider.Test $on @{ forwardingSmtpAddress = $null }) | Should -BeFalse
            (& $provider.Test $off @{ forwardingSmtpAddress = $null; deliverToMailboxAndForward = $false }) | Should -BeTrue
            (& $provider.Test $off @{ forwardingSmtpAddress = '' }) | Should -BeTrue
            (& $provider.Test $off @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $false }) | Should -BeFalse
            (& $provider.Test $null @{ forwardingSmtpAddress = $null }) | Should -BeFalse
        }

        It 'Test is never satisfied while the internal ForwardingAddress is set (it overrides the SMTP forward)' {
            $current = [pscustomobject]@{ forwardingSmtpAddress = 'bob@example.com'; forwardingAddress = 'carol'; deliverToMailboxAndForward = $true }
            (& $provider.Test $current @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $true }) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ forwardingSmtpAddress = $null; forwardingAddress = 'carol'; deliverToMailboxAndForward = $false }) @{ forwardingSmtpAddress = $null }) | Should -BeFalse
        }

        It 'with no forwarding the keep-a-copy flag must be off (it is what Set writes)' {
            $inert = [pscustomobject]@{ forwardingSmtpAddress = $null; forwardingAddress = $null; deliverToMailboxAndForward = $true }
            (& $provider.Test $inert @{ forwardingSmtpAddress = $null; deliverToMailboxAndForward = $true }) | Should -BeFalse
        }

        It 'Set forwards to an address, stored by Exchange as smtp:, clears ForwardingAddress, and Test is true after' {
            $alice.ForwardingAddress = 'carol'
            $desired = @{ forwardingSmtpAddress = 'Bob@Example.com'; deliverToMailboxAndForward = $true }
            $observed = & $provider.Set $aliceTarget $desired $null (New-Context)
            $alice.ForwardingSmtpAddress | Should -BeExactly 'smtp:bob@example.com'
            $alice.ForwardingAddress | Should -BeNullOrEmpty
            $alice.DeliverToMailboxAndForward | Should -BeTrue
            $observed.forwardingSmtpAddress | Should -Be 'bob@example.com'
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) $desired) | Should -BeTrue
            $write = @(Get-Writes)[0]
            $write.Command | Should -Be 'Set-Mailbox'
            $write.Parameters['ForwardingSmtpAddress'] | Should -Be 'bob@example.com'
            $write.Parameters.ContainsKey('ForwardingAddress') | Should -BeTrue
            $null -eq $write.Parameters['ForwardingAddress'] | Should -BeTrue
            $write.Parameters['DeliverToMailboxAndForward'] | Should -BeTrue
        }

        It 'Set with no address clears both forwarding fields and the flag, even when Desired asks to keep a copy' {
            $alice.ForwardingSmtpAddress = 'smtp:bob@example.com'
            $alice.ForwardingAddress = 'carol'
            $alice.DeliverToMailboxAndForward = $true
            $desired = @{ forwardingSmtpAddress = $null; deliverToMailboxAndForward = $true }
            & $provider.Set $aliceTarget $desired $null (New-Context) | Out-Null
            $alice.ForwardingSmtpAddress | Should -BeNullOrEmpty
            $alice.ForwardingAddress | Should -BeNullOrEmpty
            $alice.DeliverToMailboxAndForward | Should -BeFalse
            $write = @(Get-Writes)[0]
            $write.Parameters.ContainsKey('ForwardingSmtpAddress') | Should -BeTrue
            $null -eq $write.Parameters['ForwardingSmtpAddress'] | Should -BeTrue
            $write.Parameters['DeliverToMailboxAndForward'] | Should -BeFalse
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) $desired) | Should -BeTrue
        }

        It 'a second Set is harmless and Test stays true' {
            $desired = @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $false }
            & $provider.Set $aliceTarget $desired $null (New-Context) | Out-Null
            $again = & $provider.Set $aliceTarget $desired $null (New-Context)
            (& $provider.Test $again $desired) | Should -BeTrue
        }

        It 'refuses an address that is not one SMTP address, a non-boolean flag, and unknown keys, before writing' {
            foreach ($bad in 'not-an-address', 'a@example.org;c@example.net', 'a@example.org, c@example.net', 'none', 'manager') {
                { & $provider.Set $aliceTarget @{ forwardingSmtpAddress = $bad } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired' -Because $bad
            }
            { & $provider.Set $aliceTarget @{ forwardingSmtpAddress = @('a@example.org', 'c@example.net') } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $aliceTarget @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = 'false' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $aliceTarget @{ forwardSmtpAddress = 'bob@example.com' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            @(Get-Writes).Count | Should -Be 0
        }

        It 'Describe says where mail goes, whether a copy is kept, and when an internal forward is cleared' {
            (& $provider.Describe $aliceTarget $null @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $true } 'Update') | Should -Be 'Update forwarding on alice@example.com: forward to bob@example.com and keep a copy in the mailbox'
            (& $provider.Describe $aliceTarget $null @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $false } 'Update') | Should -Match 'without keeping a copy'
            (& $provider.Describe $aliceTarget $null @{ forwardingSmtpAddress = $null } 'Update') | Should -Be 'Update forwarding on alice@example.com: turn forwarding off'
            (& $provider.Describe $aliceTarget ([pscustomobject]@{ forwardingAddress = 'carol' }) @{ forwardingSmtpAddress = $null } 'Update') | Should -Match 'clears ForwardingAddress carol'
        }
    }

    Describe 'Mailbox.AutoReply' {
        BeforeAll {
            $script:provider = Get-Provider 'Mailbox.AutoReply'
            $script:message = 'Alice has left Example Corp. Please contact Bob Manager (bob@example.com).'
        }

        It 'Get reports the four fields with the HTML Exchange adds stripped off' {
            $alice.AutoReply = @{ AutoReplyState = 'Enabled'; InternalMessage = 'Gone &amp; done.'; ExternalMessage = '<html><body><p>Gone.</p><p>Bye.</p></body></html>'; ExternalAudience = 'Known' }
            $current = & $provider.Get $aliceTarget (New-Context)
            @($current.PSObject.Properties.Name) | Should -Be @('autoReplyState', 'internalMessage', 'externalMessage', 'externalAudience')
            $current.autoReplyState | Should -Be 'Enabled'
            $current.internalMessage | Should -BeExactly 'Gone & done.'
            $current.externalMessage | Should -BeExactly 'Gone. Bye.'
            $current.externalAudience | Should -Be 'Known'
        }

        It 'Get reports an empty message as $null' {
            $current = & $provider.Get $aliceTarget (New-Context)
            $current.autoReplyState | Should -Be 'Disabled'
            $null -eq $current.internalMessage | Should -BeTrue
        }

        It 'Test compares state, audience and the plain text of both messages, ignoring HTML and whitespace' {
            $current = [pscustomobject]@{ autoReplyState = 'Enabled'; internalMessage = 'Gone. Ask Bob.'; externalMessage = 'Gone. Ask Bob.'; externalAudience = 'All' }
            (& $provider.Test $current @{ autoReplyState = 'Enabled'; internalMessage = "Gone.`nAsk   Bob." }) | Should -BeTrue
            (& $provider.Test $current @{ autoReplyState = 'Enabled'; internalMessage = '<div>Gone.</div><div>Ask Bob.</div>' }) | Should -BeTrue
            (& $provider.Test $current @{ autoReplyState = 'Enabled'; internalMessage = 'Gone. Ask Carol.' }) | Should -BeFalse
            (& $provider.Test $current @{ autoReplyState = 'Enabled'; internalMessage = 'Gone. Ask Bob.'; externalAudience = 'Known' }) | Should -BeFalse
            (& $provider.Test $current @{ autoReplyState = 'Enabled'; internalMessage = 'Gone. Ask Bob.'; externalMessage = 'Other.' }) | Should -BeFalse
            (& $provider.Test $current @{ autoReplyState = 'Disabled' }) | Should -BeFalse
            (& $provider.Test $null @{ autoReplyState = 'Disabled' }) | Should -BeFalse
        }

        It 'a disabled auto-reply is satisfied whatever messages are stored' {
            $current = [pscustomobject]@{ autoReplyState = 'Disabled'; internalMessage = 'Old.'; externalMessage = $null; externalAudience = 'None' }
            (& $provider.Test $current @{ autoReplyState = 'Disabled' }) | Should -BeTrue
            (& $provider.Test ([pscustomobject]@{ autoReplyState = 'Scheduled'; internalMessage = 'Old.'; externalMessage = $null; externalAudience = 'All' }) @{ autoReplyState = 'Disabled' }) | Should -BeFalse
        }

        It 'Set turns the auto-reply on with both messages and the audience (external defaults to internal, audience to All)' {
            $desired = @{ autoReplyState = 'Enabled'; internalMessage = $message }
            $observed = & $provider.Set $aliceTarget $desired $null (New-Context)
            $write = @(Get-Writes)[0]
            $write.Command | Should -Be 'Set-MailboxAutoReplyConfiguration'
            $write.Parameters['Identity'] | Should -Be 'alice@example.com'
            $write.Parameters['AutoReplyState'] | Should -Be 'Enabled'
            $write.Parameters['InternalMessage'] | Should -Be $message
            $write.Parameters['ExternalMessage'] | Should -Be $message
            $write.Parameters['ExternalAudience'] | Should -Be 'All'
            $observed.internalMessage | Should -Be $message
            (& $provider.Test $observed $desired) | Should -BeTrue
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) $desired) | Should -BeTrue
        }

        It 'a multi-line message survives the HTML round trip (Exchange turns line breaks into br tags)' {
            $desired = @{ autoReplyState = 'Enabled'; internalMessage = "Alice has left.`r`nPlease contact Bob."; externalMessage = 'Alice has left.'; externalAudience = 'Known' }
            $observed = & $provider.Set $aliceTarget $desired $null (New-Context)
            $alice.AutoReply.ExternalAudience | Should -Be 'Known'
            (& $provider.Test $observed $desired) | Should -BeTrue
        }

        It 'Set to Disabled changes only the state, and Test is true after' {
            & $provider.Set $aliceTarget @{ autoReplyState = 'Enabled'; internalMessage = 'Gone.' } $null (New-Context) | Out-Null
            $observed = & $provider.Set $aliceTarget @{ autoReplyState = 'disabled' } $null (New-Context)
            $write = @(Get-Writes)[-1]
            @($write.Parameters.Keys | Sort-Object) | Should -Be @('AutoReplyState', 'Identity')
            $write.Parameters['AutoReplyState'] | Should -BeExactly 'Disabled'
            (& $provider.Test $observed @{ autoReplyState = 'Disabled' }) | Should -BeTrue
        }

        It 'a second Set is harmless and Test stays true' {
            $desired = @{ autoReplyState = 'Enabled'; internalMessage = $message; externalAudience = 'None' }
            & $provider.Set $aliceTarget $desired $null (New-Context) | Out-Null
            $again = & $provider.Set $aliceTarget $desired $null (New-Context)
            (& $provider.Test $again $desired) | Should -BeTrue
        }

        It 'refuses an enabled auto-reply without a message, an unknown state or audience, and a non-text message' {
            { & $provider.Test $null @{ autoReplyState = 'Enabled' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Test $null @{ autoReplyState = 'Enabled'; internalMessage = '<p> </p>' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Test $null @{ autoReplyState = 'On'; internalMessage = 'x' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Test $null @{ autoReplyState = 'Scheduled'; internalMessage = 'x' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Test $null @{ autoReplyState = 'Enabled'; internalMessage = 'x'; externalAudience = 'Everyone' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Test $null @{ autoReplyState = 'Enabled'; internalMessage = 42 } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $aliceTarget @{ autoReplyState = 'Enabled' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            @(Get-Writes).Count | Should -Be 0
        }

        It 'Describe quotes at most 60 characters of a message, cut with "..."' {
            $long = (1..40 | ForEach-Object { 'word{0:D2}' -f $_ }) -join ' '
            $text = & $provider.Describe $aliceTarget $null @{ autoReplyState = 'Enabled'; internalMessage = $long; externalMessage = "$long external" } 'Update'
            $text | Should -BeLike 'Update auto-reply on alice@example.com: turn on, external audience All, message "*'
            $quoted = [regex]::Matches($text, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value }
            @($quoted).Count | Should -Be 2
            foreach ($snippet in $quoted) {
                $snippet.Length | Should -BeLessOrEqual 60
                $snippet | Should -Match '\.\.\.$'
            }
            for ($start = 0; $start -le $long.Length - 61; $start++) {
                $text.Contains($long.Substring($start, 61)) | Should -BeFalse
            }
            (& $provider.Describe $aliceTarget $null @{ autoReplyState = 'Enabled'; internalMessage = 'Short.' } 'Update') | Should -Be 'Update auto-reply on alice@example.com: turn on, external audience All, message "Short."'
            (& $provider.Describe $aliceTarget $null @{ autoReplyState = 'Disabled' } 'Update') | Should -Be 'Update auto-reply on alice@example.com: turn off'
        }
    }

    Describe 'Mailbox.Delegate' {
        BeforeAll {
            $script:provider = Get-Provider 'Mailbox.Delegate'
            $script:grant = @{ user = 'bob@example.com'; accessRights = 'FullAccess'; present = $true }
            $script:revoke = @{ user = 'bob@example.com'; accessRights = 'FullAccess'; present = $false }
        }
        BeforeEach { $script:target = New-MailboxTarget $ids.AliceId 'alice@example.com' 'bob@example.com' }

        It 'Get reports the grantee from Target.Grantee, the explicit rights (sorted) and whether FullAccess is present' {
            $current = & $provider.Get $target (New-Context)
            @($current.PSObject.Properties.Name) | Should -Be @('user', 'accessRights', 'present')
            $current.user | Should -Be 'bob@example.com'
            @($current.accessRights).Count | Should -Be 0
            $current.present | Should -BeFalse
            $call = @(Get-Calls 'Get-EXOMailboxPermission')[0]
            $call.Parameters['Identity'] | Should -Be 'alice@example.com'
            $call.Parameters['User'] | Should -Be 'bob@example.com'
            $shared = & $provider.Get (New-MailboxTarget $ids.SharedId 'reception@example.com' 'Bob@Example.com') (New-Context)
            $shared.present | Should -BeTrue
            @($shared.accessRights) | Should -Be @('FullAccess')
        }

        It 'Get ignores inherited and deny entries (they are not ours to change)' {
            $alice.Permissions.Add(@{ User = 'bob@example.com'; AccessRights = [string[]]@('FullAccess'); IsInherited = $true; Deny = $false; InheritanceType = 'All'; AutoMapping = $false })
            $alice.Permissions.Add(@{ User = 'bob@example.com'; AccessRights = [string[]]@('FullAccess'); IsInherited = $false; Deny = $true; InheritanceType = 'All'; AutoMapping = $false })
            (& $provider.Get $target (New-Context)).present | Should -BeFalse
            $alice.Permissions.Add(@{ User = 'bob@example.com'; AccessRights = [string[]]@('ReadPermission', 'FullAccess'); IsInherited = $false; Deny = $false; InheritanceType = 'All'; AutoMapping = $false })
            $current = & $provider.Get $target (New-Context)
            $current.present | Should -BeTrue
            @($current.accessRights) | Should -Be @('FullAccess', 'ReadPermission')
        }

        It 'Get needs Target.Grantee: Tenure.Step.InvalidTarget otherwise' {
            { & $provider.Get $aliceTarget (New-Context) } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
        }

        It 'Test compares present for the same user, and is false for a snapshot of someone else' {
            $present = [pscustomobject]@{ user = 'bob@example.com'; accessRights = @('FullAccess'); present = $true }
            $absent = [pscustomobject]@{ user = 'bob@example.com'; accessRights = @(); present = $false }
            (& $provider.Test $present $grant) | Should -BeTrue
            (& $provider.Test $present $revoke) | Should -BeFalse
            (& $provider.Test $absent $revoke) | Should -BeTrue
            (& $provider.Test $absent $grant) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ user = 'carol@example.com'; accessRights = @('FullAccess'); present = $true }) $grant) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ user = 'BOB@example.com'; accessRights = @('FullAccess'); present = $true }) $grant) | Should -BeTrue
            (& $provider.Test $null $revoke) | Should -BeFalse
        }

        It 'Set grants FullAccess with automapping off, inheritance All and no prompt, and Test is true after' {
            $observed = & $provider.Set $target $grant $null (New-Context)
            $write = @(Get-Writes)[0]
            $write.Command | Should -Be 'Add-MailboxPermission'
            $write.Parameters['Identity'] | Should -Be 'alice@example.com'
            $write.Parameters['User'] | Should -Be 'bob@example.com'
            $write.Parameters['AccessRights'] | Should -Be 'FullAccess'
            $write.Parameters['InheritanceType'] | Should -Be 'All'
            $write.Parameters['AutoMapping'] | Should -BeFalse
            $write.Parameters['Confirm'] | Should -BeFalse
            ($alice.Permissions | Where-Object { $_.User -eq 'bob@example.com' }).AutoMapping | Should -BeFalse
            (& $provider.Test $observed $grant) | Should -BeTrue
            (& $provider.Test (& $provider.Get $target (New-Context)) $grant) | Should -BeTrue
        }

        It 'a second grant is harmless (Exchange only warns) and Test stays true' {
            & $provider.Set $target $grant $null (New-Context) | Out-Null
            $again = & $provider.Set $target $grant $null (New-Context)
            $w.Warnings[-1] | Should -Match 'already present'
            (& $provider.Test $again $grant) | Should -BeTrue
        }

        It 'Set removes FullAccess without a prompt, a second removal is harmless, and Test is true after' {
            $shared = New-MailboxTarget $ids.SharedId 'reception@example.com' 'bob@example.com'
            $observed = & $provider.Set $shared $revoke $null (New-Context)
            $write = @(Get-Writes)[0]
            $write.Command | Should -Be 'Remove-MailboxPermission'
            $write.Parameters['Confirm'] | Should -BeFalse
            $write.Parameters['AccessRights'] | Should -Be 'FullAccess'
            $write.Parameters.ContainsKey('AutoMapping') | Should -BeFalse
            (& $provider.Test $observed $revoke) | Should -BeTrue
            $again = & $provider.Set $shared $revoke $null (New-Context)
            (& $provider.Test $again $revoke) | Should -BeTrue
        }

        It 'treats an "already present" failure on add and an "isn''t present" failure on remove as the goal state' {
            $shared = New-MailboxTarget $ids.SharedId 'reception@example.com' 'bob@example.com'
            Add-FakeExchangeFault -World $w -Command 'Add-MailboxPermission' -Message 'The appropriate access control entry is already present on the object "reception" for account "bob@example.com".'
            (& $provider.Test (& $provider.Set $shared $grant $null (New-Context)) $grant) | Should -BeTrue
            Add-FakeExchangeFault -World $w -Command 'Remove-MailboxPermission' -Message "Can't remove the access control entry on the object `"alice`" for account `"bob@example.com`" because the ACE isn't present."
            (& $provider.Test (& $provider.Set $target $revoke $null (New-Context)) $revoke) | Should -BeTrue
        }

        It 'lets any other failure through' {
            Add-FakeExchangeFault -World $w -Command 'Add-MailboxPermission' -Message 'Access is denied.'
            { & $provider.Set $target $grant $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed'
            Add-FakeExchangeFault -World $w -Command 'Remove-MailboxPermission' -Message 'Access is denied.'
            { & $provider.Set $target $revoke $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed'
        }

        It 'refuses before writing when Desired.user is not Target.Grantee, present is missing or not a boolean, or the right is not FullAccess' {
            { & $provider.Set $target @{ user = 'carol@example.com'; present = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $target @{ user = 'bob@example.com' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $target @{ user = 'bob@example.com'; present = 'false' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $target @{ user = 'bob@example.com'; present = $true; accessRights = 'SendAs' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $target @{ user = 'bob@example.com'; present = $true; accessRights = @('FullAccess', 'ChangeOwner') } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $target @{ user = ''; present = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $aliceTarget $grant $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
            @(Get-Writes).Count | Should -Be 0
        }

        It 'accessRights may be omitted (FullAccess is the only right this provider manages)' {
            $desired = @{ user = 'bob@example.com'; present = $true }
            (& $provider.Test (& $provider.Set $target $desired $null (New-Context)) $desired) | Should -BeTrue
        }

        It 'Describe names the grantee, the right and automapping' {
            (& $provider.Describe $target $null $grant 'Update') | Should -Be 'Update mailbox access on alice@example.com: grant FullAccess to bob@example.com (automapping off)'
            (& $provider.Describe $target $null $revoke 'Remove') | Should -Be 'Remove mailbox access on alice@example.com: remove FullAccess from bob@example.com'
        }
    }

    Describe 'Mailbox.Hidden' {
        BeforeAll { $script:provider = Get-Provider 'Mailbox.Hidden' }

        It 'Get reports identity, UPN and the address-list flag' {
            $current = & $provider.Get $aliceTarget (New-Context)
            @($current.PSObject.Properties.Name) | Should -Be @('identity', 'userPrincipalName', 'hiddenFromAddressLists')
            $current.hiddenFromAddressLists | Should -BeFalse
            @(@(Get-Calls 'Get-EXOMailbox')[0].Parameters['Properties']) | Should -Be @('HiddenFromAddressListsEnabled')
        }

        It 'Test compares the flag' {
            (& $provider.Test ([pscustomobject]@{ hiddenFromAddressLists = $true }) @{ hiddenFromAddressLists = $true }) | Should -BeTrue
            (& $provider.Test ([pscustomobject]@{ hiddenFromAddressLists = $false }) @{ hiddenFromAddressLists = $true }) | Should -BeFalse
            (& $provider.Test $null @{ hiddenFromAddressLists = $false }) | Should -BeFalse
        }

        It 'Set hides and shows again, a second Set is harmless, and Test is true after each' {
            $hide = @{ hiddenFromAddressLists = $true }
            $observed = & $provider.Set $aliceTarget $hide $null (New-Context)
            $alice.HiddenFromAddressListsEnabled | Should -BeTrue
            @(Get-Writes)[0].Parameters['HiddenFromAddressListsEnabled'] | Should -BeTrue
            (& $provider.Test $observed $hide) | Should -BeTrue
            (& $provider.Test (& $provider.Set $aliceTarget $hide $null (New-Context)) $hide) | Should -BeTrue
            $show = @{ hiddenFromAddressLists = $false }
            (& $provider.Test (& $provider.Set $aliceTarget $show $null (New-Context)) $show) | Should -BeTrue
            $alice.HiddenFromAddressListsEnabled | Should -BeFalse
        }

        It 'refuses a missing or non-boolean flag before writing' {
            { & $provider.Set $aliceTarget @{} $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $aliceTarget @{ hiddenFromAddressLists = 'false' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $aliceTarget @{ hiddenFromAddressLists = 0 } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            @(Get-Writes).Count | Should -Be 0
        }

        It 'Describe says hide or show' {
            (& $provider.Describe $aliceTarget $null @{ hiddenFromAddressLists = $true } 'Update') | Should -Be 'Update address list visibility of alice@example.com: hide from address lists'
            (& $provider.Describe $aliceTarget $null @{ hiddenFromAddressLists = $false } 'Update') | Should -Be 'Update address list visibility of alice@example.com: show in address lists'
        }
    }

    Describe 'Calendar.CancelMeetings' {
        BeforeAll { $script:provider = Get-Provider 'Calendar.CancelMeetings' }

        It 'Get names the mailbox only (identity and UPN), so the conversion to shared cannot look like drift' {
            $current = & $provider.Get $aliceTarget (New-Context)
            @($current.PSObject.Properties.Name) | Should -Be @('identity', 'userPrincipalName')
            $current.identity | Should -Be $ids.AliceId
        }

        It 'Test is always false (an Invoke step is idempotent by its status)' {
            (& $provider.Test ([pscustomobject]@{ identity = $ids.AliceId }) @{ queryWindowInDays = 120 }) | Should -BeFalse
            (& $provider.Test $null $null) | Should -BeFalse
        }

        It 'Set cancels organized meetings for 120 days by default, without a prompt, and reports what it did' {
            $current = & $provider.Get $aliceTarget (New-Context)
            $result = & $provider.Set $aliceTarget @{} $current (New-Context)
            $write = @(Get-Writes)[0]
            $write.Command | Should -Be 'Remove-CalendarEvents'
            $write.Parameters['Identity'] | Should -Be 'alice@example.com'
            $write.Parameters['CancelOrganizedMeetings'] | Should -BeTrue
            $write.Parameters['QueryWindowInDays'] | Should -Be 120
            $write.Parameters['Confirm'] | Should -BeFalse
            $alice.CalendarEventsCancelled | Should -BeTrue
            $alice.CancelQueryWindowInDays | Should -Be 120
            @($result.PSObject.Properties.Name) | Should -Be @('identity', 'cancelledOrganizedMeetings', 'queryWindowInDays')
            $result.identity | Should -Be $ids.AliceId
            $result.cancelledOrganizedMeetings | Should -BeTrue
            $result.queryWindowInDays | Should -Be 120
            @(Get-Calls 'Get-EXOMailbox').Count | Should -Be 1 -Because 'there is no read-back after an irreversible call'
        }

        It 'Set honors the window from 1 to 1825 days and refuses anything else before calling Exchange' {
            (& $provider.Set $aliceTarget @{ queryWindowInDays = 1825 } $null (New-Context)).queryWindowInDays | Should -Be 1825
            (& $provider.Set $aliceTarget @{ queryWindowInDays = [long]30 } $null (New-Context)).queryWindowInDays | Should -Be 30
            $count = @(Get-Writes).Count
            foreach ($bad in 0, -1, 1826, 1.5, '120', $true) {
                { & $provider.Set $aliceTarget @{ queryWindowInDays = $bad } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired' -Because "$bad"
            }
            { & $provider.Set $aliceTarget @{ days = 10 } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            @(Get-Writes).Count | Should -Be $count
        }

        It 'Describe says what is canceled, for how long, and that it is irreversible' {
            (& $provider.Describe $aliceTarget $null @{ queryWindowInDays = 120 } 'Invoke') | Should -Be 'Cancel all meetings organized by alice@example.com for the next 120 days, irreversible'
            (& $provider.Describe $aliceTarget $null $null 'Invoke') | Should -Be 'Cancel all meetings organized by alice@example.com for the next 120 days, irreversible'
            (& $provider.Describe $aliceTarget $null @{ queryWindowInDays = 1 } 'Invoke') | Should -Match 'next 1 day, irreversible$'
        }
    }

    Describe 'DistributionGroup.Member' {
        BeforeAll {
            $script:provider = Get-Provider 'DistributionGroup.Member'
            function New-GroupTarget([string]$Id, [string]$Name, [string]$Mail) { @{ Kind = 'group'; Id = $Id; Name = $Name; Mail = $Mail } }
        }
        BeforeEach { $script:legal = New-GroupTarget $ids.LegalDlGroupId 'Legal DL' 'legal@example.com' }

        It 'Get reports the group, the subject and whether the subject is a member (matched on Entra id)' {
            $current = & $provider.Get $legal (New-Context $ids.AliceId)
            @($current.PSObject.Properties.Name) | Should -Be @('groupId', 'displayName', 'userId', 'member')
            $current.groupId | Should -Be $ids.LegalDlGroupId
            $current.displayName | Should -Be 'Legal DL'
            $current.userId | Should -Be $ids.AliceId
            $current.member | Should -BeTrue
            (& $provider.Get $legal (New-Context $ids.BobId)).member | Should -BeFalse
            (& $provider.Get $legal (New-Context $ids.AliceId.ToUpperInvariant())).member | Should -BeTrue
        }

        It 'Get asks for every member (ResultSize Unlimited)' {
            & $provider.Get $legal (New-Context $ids.AliceId) | Out-Null
            @(Get-Calls 'Get-DistributionGroupMember')[0].Parameters['ResultSize'] | Should -Be 'Unlimited'
            @(Get-Calls 'Get-DistributionGroup')[0].Parameters['Identity'] | Should -Be 'legal@example.com'
            @(Get-Calls 'Get-DistributionGroupMember')[0].Parameters['Identity'] | Should -Be 'legal@example.com'
        }

        It 'without a subject it reads member = $false and does not list members' {
            $current = & $provider.Get $legal (New-Context)
            $current.member | Should -BeFalse
            $null -eq $current.userId | Should -BeTrue
            @(Get-Calls 'Get-DistributionGroupMember').Count | Should -Be 0
            (& $provider.Get $legal $null).member | Should -BeFalse
        }

        It 'Test compares membership for the same user, and is false for a snapshot of someone else' {
            $member = [pscustomobject]@{ groupId = $ids.LegalDlGroupId; displayName = 'Legal DL'; userId = $ids.AliceId; member = $true }
            (& $provider.Test $member @{ userId = $ids.AliceId; member = $true }) | Should -BeTrue
            (& $provider.Test $member @{ userId = $ids.AliceId; member = $false }) | Should -BeFalse
            (& $provider.Test $member @{ userId = $ids.BobId; member = $true }) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ userId = $null; member = $false }) @{ userId = $ids.AliceId; member = $false }) | Should -BeFalse
            (& $provider.Test $null @{ userId = $ids.AliceId; member = $false }) | Should -BeFalse
        }

        It 'Set removes the user with the manager bypass and no prompt, and Test is true after' {
            $desired = @{ userId = $ids.AliceId; member = $false }
            $observed = & $provider.Set $legal $desired $null (New-Context $ids.AliceId)
            $write = @(Get-Writes)[0]
            $write.Command | Should -Be 'Remove-DistributionGroupMember'
            $write.Parameters['Identity'] | Should -Be 'legal@example.com'
            $write.Parameters['Member'] | Should -Be 'alice@example.com'
            $write.Parameters['BypassSecurityGroupManagerCheck'] | Should -BeTrue
            $write.Parameters['Confirm'] | Should -BeFalse
            @($w.DistributionGroups['Legal DL'].Members).Count | Should -Be 0
            (& $provider.Test $observed $desired) | Should -BeTrue
            (& $provider.Test (& $provider.Get $legal (New-Context $ids.AliceId)) $desired) | Should -BeTrue
        }

        It 'a second removal is harmless ("isn''t a member" is the goal state)' {
            $desired = @{ userId = $ids.AliceId; member = $false }
            & $provider.Set $legal $desired $null (New-Context $ids.AliceId) | Out-Null
            $again = & $provider.Set $legal $desired $null (New-Context $ids.AliceId)
            (& $provider.Test $again $desired) | Should -BeTrue
        }

        It 'Set adds a user, and a second add is harmless ("already a member" is the goal state)' {
            $desired = @{ userId = $ids.BobId; member = $true }
            $observed = & $provider.Set $legal $desired $null (New-Context $ids.BobId)
            @(Get-Writes)[0].Command | Should -Be 'Add-DistributionGroupMember'
            (& $provider.Test $observed $desired) | Should -BeTrue
            $again = & $provider.Set $legal $desired $null (New-Context $ids.BobId)
            (& $provider.Test $again $desired) | Should -BeTrue
        }

        It 'Set reads back the user it changed, whatever the plan subject is' {
            $observed = & $provider.Set $legal @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.AliceId)
            $observed.userId | Should -Be $ids.BobId
            $observed.member | Should -BeTrue
        }

        It 'lets any other failure through' {
            Add-FakeExchangeFault -World $w -Command 'Remove-DistributionGroupMember' -Message "You don't have sufficient permissions."
            { & $provider.Set $legal @{ userId = $ids.AliceId; member = $false } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed'
            @($w.DistributionGroups['Legal DL'].Members).Count | Should -Be 1
        }

        It 'names the group by Target.Mail and refuses an address that belongs to another group, or no address at all' {
            $misdirected = New-GroupTarget $ids.LegalDlGroupId 'Legal DL' 'finance-security@example.com'
            { & $provider.Get $misdirected (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidResult'
            { & $provider.Set $misdirected @{ userId = $ids.AliceId; member = $false } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidResult'
            { & $provider.Get @{ Kind = 'group'; Id = $ids.LegalDlGroupId; Name = 'Legal DL' } (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
            @(Get-Writes).Count | Should -Be 0
            @($w.DistributionGroups['Finance Security'].Members).Count | Should -Be 2
        }

        It 'adds a member by the address of their mailbox, read by Entra id' {
            & $provider.Set $legal @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.BobId) | Out-Null
            @(Get-Calls 'Get-EXOMailbox')[0].Parameters['ExternalDirectoryObjectId'] | Should -Be $ids.BobId
            $write = @(Get-Writes)[0]
            $write.Parameters['Identity'] | Should -BeExactly 'legal@example.com'
            $write.Parameters['Member'] | Should -BeExactly 'bob@example.com'
        }

        It 'refuses a missing user, a missing or non-boolean member flag, and unknown keys before writing' {
            { & $provider.Set $legal @{ member = $false } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $legal @{ userId = $ids.AliceId } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $legal @{ userId = $ids.AliceId; member = 'false' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set $legal @{ userId = $ids.AliceId; member = $false; groupId = 'x' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            @(Get-Writes).Count | Should -Be 0
        }

        It 'works on a mail-enabled security group as well' {
            $finance = New-GroupTarget $ids.FinanceSecurityGroupId 'Finance Security' 'finance-security@example.com'
            $desired = @{ userId = $ids.AliceId; member = $false }
            (& $provider.Test (& $provider.Set $finance $desired $null (New-Context $ids.AliceId)) $desired) | Should -BeTrue
            @($w.DistributionGroups['Finance Security'].Members).Count | Should -Be 1
        }

        It 'Describe says into or out of which group' {
            (& $provider.Describe $legal $null @{ userId = $ids.AliceId; member = $false } 'Remove') | Should -Be "Remove user $($ids.AliceId) out of distribution group Legal DL"
            (& $provider.Describe $legal $null @{ userId = $ids.BobId; member = $true } 'Create') | Should -Be "Create user $($ids.BobId) into distribution group Legal DL"
        }
    }

    Describe 'Check.MailboxSharedEligibility' {
        BeforeAll {
            $script:provider = Get-Provider 'Check.MailboxSharedEligibility'
            $script:license = 'a shared mailbox in this state still needs an Exchange Online license'
            function New-Snapshot([object]$Over = $false, [bool]$Archive = $false, [string[]]$Holds = @(), [long]$Limit = 50GB) {
                [pscustomobject]@{ sizeLimitBytes = $Limit; overSizeLimit = $Over; archiveEnabled = $Archive; holds = [string[]]$Holds }
            }
        }

        It 'Get reports only the facts the verdict depends on, from Get-EXOMailbox and Get-EXOMailboxStatistics' {
            $current = & $provider.Get $aliceTarget (New-Context)
            @($current.PSObject.Properties.Name) | Should -Be @('sizeLimitBytes', 'overSizeLimit', 'archiveEnabled', 'holds')
            $current.sizeLimitBytes | Should -Be ([long]50GB)
            $current.overSizeLimit | Should -BeExactly $false
            $current.archiveEnabled | Should -BeFalse
            , $current.holds | Should -BeOfType [string[]]
            @($current.holds).Count | Should -Be 0
            @(@(Get-Calls 'Get-EXOMailbox')[0].Parameters['Properties']) | Should -Be @('ArchiveStatus', 'LitigationHoldEnabled', 'InPlaceHolds', 'RetentionHoldEnabled', 'RecipientTypeDetails')
            @(Get-Calls 'Get-EXOMailboxStatistics')[0].Parameters['ExternalDirectoryObjectId'] | Should -Be $ids.AliceId
        }

        It 'gives the same snapshot when the mailbox grows but stays under the limit (no drift between plan and apply)' {
            $first = Invoke-Helper { param($o) Get-TenureCanonicalJson -InputObject $o } @(, (& $provider.Get $aliceTarget (New-Context)))
            Set-FakeExchangeMailboxSize -World $w -Identity 'alice@example.com' -Bytes (12GB + 48213)
            $second = Invoke-Helper { param($o) Get-TenureCanonicalJson -InputObject $o } @(, (& $provider.Get $aliceTarget (New-Context)))
            $second | Should -BeExactly $first
            Set-FakeExchangeMailboxSize -World $w -Identity 'alice@example.com' -Bytes ([long]50GB)
            (& $provider.Get $aliceTarget (New-Context)).overSizeLimit | Should -BeTrue -Because 'crossing the limit is a real change'
        }

        It 'a 12 GB mailbox with no archive and no holds passes' {
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) @{}) | Should -BeTrue
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) $null) | Should -BeTrue
        }

        It 'the 61.2 GB variant with an archive and a litigation hold fails, and Describe lists every reason and the license' {
            Set-FakeExchangeMailboxSize -World $w -Identity 'alice@example.com'
            $alice.ArchiveStatus = 'Active'
            $alice.LitigationHoldEnabled = $true
            $current = & $provider.Get $aliceTarget (New-Context)
            $current.overSizeLimit | Should -BeTrue
            $current.archiveEnabled | Should -BeTrue
            @($current.holds) | Should -Be @('litigation')
            (& $provider.Test $current @{}) | Should -BeFalse
            $text = & $provider.Describe $aliceTarget $current @{ maxSizeBytes = 50GB } 'Check'
            $text | Should -BeLike '*mailbox is 50 GB or more; archive enabled; litigation hold; *'
            $text | Should -BeLike "*$license"
        }

        It 'fails at exactly 50 GB and passes one byte under (SPEC 5.1: warn when size >= 50 GB)' {
            (& $provider.Test (New-Snapshot -Over $true) @{}) | Should -BeFalse
            (& $provider.Test (New-Snapshot -Over $false) @{}) | Should -BeTrue
            Set-FakeExchangeMailboxSize -World $w -Identity 'alice@example.com' -Bytes ([long]50GB)
            $current = & $provider.Get $aliceTarget (New-Context)
            $current.overSizeLimit | Should -BeTrue
            (& $provider.Test $current @{}) | Should -BeFalse
            (& $provider.Describe $aliceTarget $current @{} 'Check') | Should -Match 'mailbox is 50 GB or more'
            Set-FakeExchangeMailboxSize -World $w -Identity 'alice@example.com' -Bytes ([long]50GB - 1)
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) @{}) | Should -BeTrue
        }

        It 'counts in-place holds but not exclusions, and reports a retention hold' {
            $alice.InPlaceHolds = [string[]]@('UniH7d6a4b3c-0000-4000-8000-000000000001', '-mbx0000aaaa000040008000000000000001:2', 'mbx0000bbbb000040008000000000000002:1')
            $current = & $provider.Get $aliceTarget (New-Context)
            @($current.holds) | Should -Be @('inPlace')
            (& $provider.Test $current @{}) | Should -BeFalse
            (& $provider.Describe $aliceTarget $current @{} 'Check') | Should -Match 'in-place hold'
            $alice.InPlaceHolds = [string[]]@('-mbx0000aaaa000040008000000000000001:2')
            (& $provider.Test (& $provider.Get $aliceTarget (New-Context)) @{}) | Should -BeTrue
            $alice.RetentionHoldEnabled = $true
            $held = & $provider.Get $aliceTarget (New-Context)
            (& $provider.Test $held @{}) | Should -BeFalse
            (& $provider.Describe $aliceTarget $held @{} 'Check') | Should -Match 'retention hold'
        }

        It 'allowArchive and allowHolds relax the check, and a snapshot taken against another limit fails closed' {
            (& $provider.Test (New-Snapshot -Archive $true) @{ allowArchive = $true }) | Should -BeTrue
            (& $provider.Test (New-Snapshot -Holds @('litigation', 'inPlace', 'retention')) @{ allowHolds = $true }) | Should -BeTrue
            (& $provider.Test (New-Snapshot) @{ maxSizeBytes = [long]10GB }) | Should -BeFalse
            (& $provider.Describe $aliceTarget (New-Snapshot) @{ maxSizeBytes = [long]10GB } 'Check') | Should -Match 'another limit'
            (& $provider.Describe $aliceTarget (New-Snapshot -Archive $true) @{ allowArchive = $true } 'Check') | Should -Match 'archive enabled \(allowed\)'
        }

        It 'Target.MaxSizeBytes sets the limit the snapshot compares with' {
            $small = @{ Kind = 'mailbox'; Id = $ids.AliceId; Name = 'alice@example.com'; MaxSizeBytes = [long]10GB }
            $current = & $provider.Get $small (New-Context)
            $current.sizeLimitBytes | Should -Be ([long]10GB)
            $current.overSizeLimit | Should -BeTrue
            (& $provider.Test $current @{ maxSizeBytes = [long]10GB }) | Should -BeFalse
            { & $provider.Get @{ Kind = 'mailbox'; Id = $ids.AliceId; Name = 'alice@example.com'; MaxSizeBytes = 'big' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Step.InvalidTarget'
        }

        It 'a mailbox with no statistics has an unknown size and fails closed' {
            $alice.NeverLoggedOn = $true
            $current = & $provider.Get $aliceTarget (New-Context)
            $null -eq $current.overSizeLimit | Should -BeTrue
            (& $provider.Test $current @{}) | Should -BeFalse
            (& $provider.Describe $aliceTarget $current @{} 'Check') | Should -BeLike "*mailbox size unknown (limit 50 GB); $license"
        }

        It 'a snapshot without the holds list fails closed' {
            (& $provider.Test ([pscustomobject]@{ sizeLimitBytes = [long]50GB; overSizeLimit = $false; archiveEnabled = $false }) @{}) | Should -BeFalse
        }

        It 'Describe for a passing mailbox says so, and for a missing snapshot says the license may still be needed' {
            (& $provider.Describe $aliceTarget (& $provider.Get $aliceTarget (New-Context)) @{} 'NoOp') | Should -Be 'NoOp shared mailbox eligibility of alice@example.com: under 50 GB, no archive, no holds; can become a shared mailbox without a license'
            (& $provider.Describe $aliceTarget $null @{} 'Check') | Should -Match 'no mailbox data'
        }

        It 'refuses a maxSizeBytes that is not a positive whole number, non-boolean allow flags, and unknown keys' {
            foreach ($bad in '50GB', 0, -1, 1.5, $true) {
                { & $provider.Test (New-Snapshot) @{ maxSizeBytes = $bad } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired' -Because "$bad"
            }
            { & $provider.Test (New-Snapshot) @{ allowArchive = 'yes' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Test (New-Snapshot) @{ maxSize = 1 } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            (& $provider.Test (New-Snapshot) @{ maxSizeBytes = [double]53687091200 }) | Should -BeTrue
        }
    }

    Describe 'Exchange parsing helpers' {
        It 'ConvertFrom-TenureExchangeByteSize reads only the "(N bytes)" part, digits only, any separators' {
            $cases = @(
                @{ In = '61.2 GB (65,712,345,678 bytes)'; Out = 65712345678 }
                @{ In = '50 GB (53,687,091,200 bytes)'; Out = 53687091200 }
                @{ In = '50 GB (53.687.091.200 bytes)'; Out = 53687091200 }
                @{ In = "50 GB (53$([char]0x00A0)687$([char]0x00A0)091$([char]0x00A0)200 bytes)"; Out = 53687091200 }
                @{ In = '1.5 KB (1,536 bytes)'; Out = 1536 }
                @{ In = '0 B (0 bytes)'; Out = 0 }
                @{ In = '3 GB (3,221,225,472 Bytes)'; Out = 3221225472 }
                @{ In = [long]12345; Out = 12345 }
            )
            foreach ($case in $cases) {
                (Invoke-Helper { param($v) ConvertFrom-TenureExchangeByteSize -Value $v } @(, $case.In)) | Should -Be $case.Out -Because "$($case.In)"
            }
            foreach ($bad in 'Unlimited', '61.2 GB', '', '(bytes)', '(99999999999999999999 bytes)', -5) {
                $null -eq (Invoke-Helper { param($v) ConvertFrom-TenureExchangeByteSize -Value $v } @(, $bad)) | Should -BeTrue -Because "'$bad' has no usable byte count"
            }
            $null -eq (Invoke-Helper { ConvertFrom-TenureExchangeByteSize -Value $null }) | Should -BeTrue
        }

        It 'ConvertTo-TenureExchangePlainText strips tags to spaces, decodes entities and collapses whitespace' {
            Invoke-Helper { ConvertTo-TenureExchangePlainText -Value "<html>`n<body>`n<div>Gone &amp; done.<br>`nAsk&nbsp;Bob.</div>`n</body>`n</html>`n" } | Should -BeExactly 'Gone & done. Ask Bob.'
            Invoke-Helper { ConvertTo-TenureExchangePlainText -Value '<style>p { color: red }</style><p>Hi</p><!-- note -->' } | Should -BeExactly 'Hi'
            $null -eq (Invoke-Helper { ConvertTo-TenureExchangePlainText -Value '<html><body></body></html>' }) | Should -BeTrue
        }

        It 'ConvertTo-TenureExchangeSmtp strips smtp: in any case, trims and lowercases' {
            Invoke-Helper { ConvertTo-TenureExchangeSmtp -Value ' SMTP:Bob@Example.COM ' } | Should -BeExactly 'bob@example.com'
            $null -eq (Invoke-Helper { ConvertTo-TenureExchangeSmtp -Value 'smtp:' }) | Should -BeTrue
            $null -eq (Invoke-Helper { ConvertTo-TenureExchangeSmtp -Value '   ' }) | Should -BeTrue
        }

        It 'Format-TenureExchangeSnippet keeps one line and cuts at the limit with "..."' {
            Invoke-Helper { Format-TenureExchangeSnippet -Text "a`r`nb`tc" } | Should -BeExactly 'a b c'
            $cut = Invoke-Helper { Format-TenureExchangeSnippet -Text ('x' * 100) -MaxLength 60 }
            $cut.Length | Should -Be 60
            $cut | Should -Match '\.\.\.$'
        }

        It 'ConvertTo-TenureExchangeBool parses and never casts' {
            Invoke-Helper { ConvertTo-TenureExchangeBool -Value 'False' -Name 'x' } | Should -BeFalse
            Invoke-Helper { ConvertTo-TenureExchangeBool -Value 'true' -Name 'x' } | Should -BeTrue
            Invoke-Helper { ConvertTo-TenureExchangeBool -Value $null -Name 'x' } | Should -BeFalse
            { Invoke-Helper { ConvertTo-TenureExchangeBool -Value 'maybe' -Name 'x' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidResult'
            { Invoke-Helper { ConvertTo-TenureExchangeBool -Value 1 -Name 'x' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidResult'
        }
    }

    Describe 'Describe stays one line and leaks nothing it was not asked to show' {
        BeforeAll {
            $script:secret = 'Pa55-seeded-literal-9q'
            $script:names = 'Mailbox.Type', 'Mailbox.Forwarding', 'Mailbox.AutoReply', 'Mailbox.Delegate', 'Mailbox.Hidden', 'Calendar.CancelMeetings', 'DistributionGroup.Member', 'Check.MailboxSharedEligibility'
            $script:validDesired = @{
                'Mailbox.Type'                   = @{ type = 'Shared' }
                'Mailbox.Forwarding'             = @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $true }
                'Mailbox.AutoReply'              = @{ autoReplyState = 'Enabled'; internalMessage = 'Alice has left.' }
                'Mailbox.Delegate'               = @{ user = 'bob@example.com'; present = $true }
                'Mailbox.Hidden'                 = @{ hiddenFromAddressLists = $true }
                'Calendar.CancelMeetings'        = @{ queryWindowInDays = 120 }
                'DistributionGroup.Member'       = @{ userId = '10000000-0000-4000-8000-000000000001'; member = $false }
                'Check.MailboxSharedEligibility' = @{}
            }
        }

        It 'for 200 random Current/Desired pairs with password-like fields, Describe never throws, is one line, and never shows the secret' {
            $random = [System.Random]::new(20261008)
            $keys = 'password', 'Password', 'passwordProfile', 'temporaryAccessPass', 'secret', 'token', 'clientSecret'
            $target = @{ Kind = 'mailbox'; Id = '10000000-0000-4000-8000-000000000001'; Name = 'alice@example.com'; Grantee = 'bob@example.com' }
            for ($i = 0; $i -lt 200; $i++) {
                $name = $names[$random.Next($names.Count)]
                $provider = Get-Provider $name
                $desired = @{}
                if ($random.Next(2) -eq 0) { foreach ($k in $validDesired[$name].Keys) { $desired[$k] = $validDesired[$name][$k] } }
                $desired[$keys[$random.Next($keys.Count)]] = $secret
                $current = @{ identity = 'x'; type = 'Regular'; member = $true; present = $false; totalItemSizeBytes = [long]$random.Next(); archiveEnabled = ($random.Next(2) -eq 0) }
                $current[$keys[$random.Next($keys.Count)]] = $secret
                $currentObject = if ($random.Next(3) -eq 0) { $null } else { [pscustomobject]$current }
                $text = $null
                { $script:text = & $provider.Describe $target $currentObject $desired 'Update' } | Should -Not -Throw -Because "$name iteration $i"
                $text = $script:text
                $text | Should -BeOfType [string]
                $text.Contains($secret) | Should -BeFalse -Because "$name must not echo a password-like field"
                $text | Should -Not -Match "[`r`n]"
            }
        }

        It 'with valid Desired every provider describes the step without echoing unrelated Current fields' {
            $target = @{ Kind = 'mailbox'; Id = '10000000-0000-4000-8000-000000000001'; Name = 'alice@example.com'; Grantee = 'bob@example.com' }
            foreach ($name in $names) {
                $current = [pscustomobject]@{ identity = 'x'; passwordProfile = @{ password = $secret }; password = $secret }
                $text = & (Get-Provider $name).Describe $target $current $validDesired[$name] 'Update'
                $text.Contains($secret) | Should -BeFalse -Because $name
                $text | Should -Not -BeNullOrEmpty
            }
        }
    }
}
