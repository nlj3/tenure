# Exchange failures, a missing connection, mailboxes of an unexpected
# type, and a property test of the shared-mailbox eligibility check. The real providers
# and the real apply engine run against FakeExchange; every audit path is under TestDrive.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'PlanFixtures.ps1')
    . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeExchange.ps1')
    Import-TenureForTest
    # Plans here name made-up users and run without FakeGraph: the protection preflight compares names only.
    Disable-TestIdentityLookup

    $script:SavedConfirmPreference = $global:ConfirmPreference
    $global:ConfirmPreference = 'None'
    $script:SavedAuditEnv = $env:TENURE_AUDIT_PATH

    function Get-Provider([string]$Name) { Get-TenureProvider -Name $Name }
    function New-Context([string]$SubjectId) {
        $context = @{ Secrets = @{}; StepId = 'S01'; Mode = 'Apply' }
        if ($SubjectId) { $context.Subject = @{ Id = $SubjectId; UserPrincipalName = $null; DisplayName = $null } }
        $context
    }
    function Get-Canonical($Object) { Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $Object) }
    function Get-Writes { @($global:FakeExchangeWorld.Calls | Where-Object { $_.Command -notlike 'Get-*' }) }
    # A step for a real provider, snapshotted through its own Get (as a plan builder would).
    function New-ExchangeStep([string]$Id, [string]$Provider, [hashtable]$Target, [object]$After, [string]$SubjectId) {
        $before = & (Get-Provider $Provider).Get $Target (New-Context $SubjectId)
        $action = switch ((Get-Provider $Provider).Kind) { 'Invoke' { 'Invoke' } 'Check' { 'Check' } default { 'Update' } }
        New-TestStep -Id $Id -Provider $Provider -Target $Target -Before $before -After $After -Action $action
    }
}

AfterAll {
    $global:ConfirmPreference = $script:SavedConfirmPreference
    $env:TENURE_AUDIT_PATH = $script:SavedAuditEnv
    Remove-Variable -Name FakeExchangeWorld -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Exchange faults against FakeExchange' {
    BeforeAll {
        $global:FakeExchangeWorld = New-FakeExchangeWorld
        Mock -ModuleName Tenure Invoke-TenureExchange {
            & (Get-Module -Name Tenure) { Assert-TenureConnection -Backend Exchange }
            Invoke-FakeExchangeCommand -World $global:FakeExchangeWorld -Command $Command -Parameters $Parameters
        }
    }

    BeforeEach {
        Set-TenureTestSession
        Reset-FakeExchangeWorld
        $script:w = $global:FakeExchangeWorld
        $script:ids = $script:w.Ids
        $script:alice = $script:w.Mailboxes['alice@example.com']
        $script:aliceTarget = @{ Kind = 'mailbox'; Id = $script:ids.AliceId; Name = 'alice@example.com' }
        $script:audit = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $env:TENURE_AUDIT_PATH = Join-Path $TestDrive 'env-sentinel.jsonl'
        # Every Set below: provider, target, desired, the cmdlet it writes with, and a reader of the state it would change.
        $script:setCases = @(
            @{ Name = 'Mailbox.Type'; Target = $aliceTarget; Desired = @{ type = 'Shared' }; Command = 'Set-Mailbox'; Subject = $null
                Read = { $global:FakeExchangeWorld.Mailboxes['alice@example.com'].RecipientTypeDetails } }
            @{ Name = 'Mailbox.Forwarding'; Target = $aliceTarget; Desired = @{ forwardingSmtpAddress = 'bob@example.com'; deliverToMailboxAndForward = $true }; Command = 'Set-Mailbox'; Subject = $null
                Read = { $m = $global:FakeExchangeWorld.Mailboxes['alice@example.com']; "$($m.ForwardingSmtpAddress)|$($m.ForwardingAddress)|$($m.DeliverToMailboxAndForward)" } }
            @{ Name = 'Mailbox.AutoReply'; Target = $aliceTarget; Desired = @{ autoReplyState = 'Enabled'; internalMessage = 'Alice has left.' }; Command = 'Set-MailboxAutoReplyConfiguration'; Subject = $null
                Read = { $a = $global:FakeExchangeWorld.Mailboxes['alice@example.com'].AutoReply; "$($a.AutoReplyState)|$($a.InternalMessage)|$($a.ExternalMessage)|$($a.ExternalAudience)" } }
            @{ Name = 'Mailbox.Delegate'; Target = @{ Kind = 'mailbox'; Id = $ids.AliceId; Name = 'alice@example.com'; Grantee = 'bob@example.com' }; Desired = @{ user = 'bob@example.com'; present = $true }; Command = 'Add-MailboxPermission'; Subject = $null
                Read = { @($global:FakeExchangeWorld.Mailboxes['alice@example.com'].Permissions | ForEach-Object { "$($_.User)=$(@($_.AccessRights) -join '+')" }) -join ';' } }
            @{ Name = 'Mailbox.Delegate'; Target = @{ Kind = 'mailbox'; Id = $ids.SharedId; Name = 'reception@example.com'; Grantee = 'bob@example.com' }; Desired = @{ user = 'bob@example.com'; present = $false }; Command = 'Remove-MailboxPermission'; Subject = $null
                Read = { @($global:FakeExchangeWorld.Mailboxes['reception@example.com'].Permissions | ForEach-Object { "$($_.User)=$(@($_.AccessRights) -join '+')" }) -join ';' } }
            @{ Name = 'Mailbox.Hidden'; Target = $aliceTarget; Desired = @{ hiddenFromAddressLists = $true }; Command = 'Set-Mailbox'; Subject = $null
                Read = { $global:FakeExchangeWorld.Mailboxes['alice@example.com'].HiddenFromAddressListsEnabled } }
            @{ Name = 'Calendar.CancelMeetings'; Target = $aliceTarget; Desired = @{ queryWindowInDays = 120 }; Command = 'Remove-CalendarEvents'; Subject = $null
                Read = { $m = $global:FakeExchangeWorld.Mailboxes['alice@example.com']; "$($m.CalendarEventsCancelled)|$($m.CancelQueryWindowInDays)" } }
            @{ Name = 'DistributionGroup.Member'; Target = @{ Kind = 'group'; Id = $ids.LegalDlGroupId; Name = 'Legal DL'; Mail = 'legal@example.com' }; Desired = @{ userId = $ids.AliceId; member = $false }; Command = 'Remove-DistributionGroupMember'; Subject = $ids.AliceId
                Read = { @($global:FakeExchangeWorld.DistributionGroups['Legal DL'].Members | ForEach-Object { $_.ExternalDirectoryObjectId }) -join ';' } }
            @{ Name = 'DistributionGroup.Member'; Target = @{ Kind = 'group'; Id = $ids.LegalDlGroupId; Name = 'Legal DL'; Mail = 'legal@example.com' }; Desired = @{ userId = $ids.BobId; member = $true }; Command = 'Add-DistributionGroupMember'; Subject = $ids.BobId
                Read = { @($global:FakeExchangeWorld.DistributionGroups['Legal DL'].Members | ForEach-Object { $_.ExternalDirectoryObjectId }) -join ';' } }
        )
    }

    Context 'a Set whose cmdlet fails' {
        It 'leaves the state unchanged and surfaces Tenure.Exchange.Failed with the cmdlet message, for every provider' {
            foreach ($case in $setCases) {
                Reset-FakeExchangeWorld
                $before = & $case.Read
                Add-FakeExchangeFault -World $global:FakeExchangeWorld -Command $case.Command -Message 'The server is unavailable (injected).'
                $failure = { & (Get-Provider $case.Name).Set $case.Target $case.Desired $null (New-Context $case.Subject) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed' -PassThru -Because "$($case.Name) via $($case.Command)"
                $failure.Exception.Message | Should -Match 'injected'
                (& $case.Read) | Should -Be $before -Because "$($case.Name) must not change anything when $($case.Command) fails"
                $global:FakeExchangeWorld.Faults.Count | Should -Be 0 -Because "the fault was meant for $($case.Command), which $($case.Name) must call"
            }
        }

        It 'a failure that only mentions "already", "member" or "present" in another sense is never taken for the goal state' {
            $delegate = Get-Provider 'Mailbox.Delegate'
            $target = @{ Kind = 'mailbox'; Id = $ids.SharedId; Name = 'reception@example.com'; Grantee = 'bob@example.com' }
            Add-FakeExchangeFault -World $w -Command 'Remove-MailboxPermission' -Message 'Another operation is already in progress on this mailbox.'
            { & $delegate.Set $target @{ user = 'bob@example.com'; present = $false } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed'
            $group = Get-Provider 'DistributionGroup.Member'
            $legal = @{ Kind = 'group'; Id = $ids.LegalDlGroupId; Name = 'Legal DL'; Mail = 'legal@example.com' }
            Add-FakeExchangeFault -World $w -Command 'Add-DistributionGroupMember' -Message "The recipient isn't a member of an allowed sender list."
            { & $group.Set $legal @{ userId = $ids.BobId; member = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed'
            Add-FakeExchangeFault -World $w -Command 'Remove-DistributionGroupMember' -Message 'The recipient is already a member of a moderation queue.'
            { & $group.Set $legal @{ userId = $ids.AliceId; member = $false } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed'
            @($w.DistributionGroups['Legal DL'].Members).Count | Should -Be 1
        }

        It 'a goal-state error id other than Tenure.Exchange.Failed is never swallowed' {
            Add-FakeExchangeFault -World $w -Command 'Add-DistributionGroupMember' -Id 'Tenure.Exchange.NotConnected' -Message 'is already a member'
            { & (Get-Provider 'DistributionGroup.Member').Set @{ Kind = 'group'; Id = $ids.LegalDlGroupId; Name = 'Legal DL'; Mail = 'legal@example.com' } @{ userId = $ids.BobId; member = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
        }

        It 'through the apply engine: the step is Failed with the Exchange message, later steps stay Pending, the audit chain is valid' {
            $plan = New-TestPlan -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice Example' } -Steps @(
                (New-ExchangeStep 'S01' 'Mailbox.Type' $aliceTarget @{ type = 'Shared' })
                (New-ExchangeStep 'S02' 'Mailbox.AutoReply' $aliceTarget @{ autoReplyState = 'Enabled'; internalMessage = 'Alice has left.' })
                (New-ExchangeStep 'S03' 'Mailbox.Hidden' $aliceTarget @{ hiddenFromAddressLists = $true })
            )
            Add-FakeExchangeFault -World $w -Command 'Set-MailboxAutoReplyConfiguration' -Message 'Mailbox is locked (injected).'
            $result = Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false
            Get-TestStatus $plan | Should -Be 'Applied,Failed,Pending'
            $plan.Status | Should -Be 'PartiallyApplied'
            $plan.Steps[1].Result.Error | Should -BeLike "Tenure.Exchange.Failed: Exchange cmdlet 'Set-MailboxAutoReplyConfiguration' failed: Mailbox is locked (injected)."
            $result.Summary.Failed | Should -Be 1
            $alice.RecipientTypeDetails | Should -Be 'SharedMailbox'
            $alice.AutoReply.AutoReplyState | Should -Be 'Disabled'
            $alice.HiddenFromAddressListsEnabled | Should -BeFalse
            (Test-TenureAudit -Path $audit).Valid | Should -BeTrue
        }

        It 'through the apply engine: a goal-state error that was not true is caught by the post-condition, not reported as Applied' {
            $target = @{ Kind = 'mailbox'; Id = $ids.AliceId; Name = 'alice@example.com'; Grantee = 'bob@example.com' }
            $plan = New-TestPlan -Steps @(New-ExchangeStep 'S01' 'Mailbox.Delegate' $target @{ user = 'bob@example.com'; present = $true })
            Add-FakeExchangeFault -World $w -Command 'Add-MailboxPermission' -Message 'The appropriate access control entry is already present on the object (but it is not).'
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false | Out-Null
            $plan.Steps[0].Status | Should -Be 'Failed'
            $plan.Steps[0].Result.Error | Should -BeLike 'Tenure.Apply.PostConditionFailed*'
        }

        It 'through the apply engine: canceling meetings is refused without -AllowDestructive when confirmation is off, and never reaches Exchange' {
            $plan = New-TestPlan -Steps @(New-ExchangeStep 'S01' 'Calendar.CancelMeetings' $aliceTarget @{ queryWindowInDays = 120 })
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false | Out-Null
            $plan.Steps[0].Status | Should -Be 'Refused'
            @(Get-FakeExchangeCall -World $w -Command 'Remove-CalendarEvents').Count | Should -Be 0
            $alice.CalendarEventsCancelled | Should -BeFalse
            $plan2 = New-TestPlan -Steps @(New-ExchangeStep 'S01' 'Calendar.CancelMeetings' $aliceTarget @{ queryWindowInDays = 120 })
            Invoke-TenurePlan -Plan $plan2 -AuditPath $audit -Confirm:$false -AllowDestructive | Out-Null
            $plan2.Steps[0].Status | Should -Be 'Applied'
            $alice.CalendarEventsCancelled | Should -BeTrue
        }

        It 'a failure reading mailbox statistics surfaces; it never reads as an eligible mailbox' {
            Add-FakeExchangeFault -World $w -Command 'Get-EXOMailboxStatistics' -Message 'Statistics are unavailable (injected).'
            { & (Get-Provider 'Check.MailboxSharedEligibility').Get $aliceTarget (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.Failed'
        }
    }

    Context 'Exchange not connected' {
        It '<_> Get and Set throw Tenure.Exchange.NotConnected before any call reaches Exchange' -ForEach @('Mailbox.Type', 'Mailbox.Forwarding', 'Mailbox.AutoReply', 'Mailbox.Delegate', 'Mailbox.Hidden', 'Calendar.CancelMeetings', 'DistributionGroup.Member', 'Check.MailboxSharedEligibility') {
            Set-TenureTestSession -Exchange $false
            $name = $_
            $match = @($setCases | Where-Object { $_.Name -eq $name })
            $target = if ($match.Count -gt 0) { $match[0].Target } else { $aliceTarget }
            $desired = if ($match.Count -gt 0) { $match[0].Desired } else { @{} }
            $provider = Get-Provider $name
            { & $provider.Get $target (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
            if ($provider.Set) {
                { & $provider.Set $target $desired $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
            }
            $w.Calls.Count | Should -Be 0
        }

        It 'the apply engine refuses the whole plan before step 1' {
            $plan = New-TestPlan -Steps @(New-ExchangeStep 'S01' 'Mailbox.Hidden' $aliceTarget @{ hiddenFromAddressLists = $true })
            $w.Calls.Clear()
            Set-TenureTestSession -Exchange $false
            { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
            $w.Calls.Count | Should -Be 0
            $alice.HiddenFromAddressListsEnabled | Should -BeFalse
        }
    }

    Context 'a mailbox of an unexpected type' {
        It 'Mailbox.Type reports <_> raw instead of crashing or guessing' -ForEach @('RoomMailbox', 'EquipmentMailbox', 'DiscoveryMailbox', 'LinkedMailbox', 'SchedulingMailbox', 'GroupMailbox') {
            $alice.RecipientTypeDetails = $_
            (& (Get-Provider 'Mailbox.Type').Get $aliceTarget (New-Context)).type | Should -BeExactly $_
            (& (Get-Provider 'Mailbox.Type').Test (& (Get-Provider 'Mailbox.Type').Get $aliceTarget (New-Context)) @{ type = 'Shared' }) | Should -BeFalse
            (& (Get-Provider 'Mailbox.Type').Test (& (Get-Provider 'Mailbox.Type').Get $aliceTarget (New-Context)) @{ type = 'Regular' }) | Should -BeFalse
        }

        It 'an empty or missing RecipientTypeDetails reads as type $null' {
            $alice.RecipientTypeDetails = ''
            $null -eq (& (Get-Provider 'Mailbox.Type').Get $aliceTarget (New-Context)).type | Should -BeTrue
            $alice.RecipientTypeDetails = $null
            $null -eq (& (Get-Provider 'Mailbox.Type').Get $aliceTarget (New-Context)).type | Should -BeTrue
        }

        It 'the other mailbox providers read such a mailbox without crashing' {
            $alice.RecipientTypeDetails = 'RoomMailbox'
            foreach ($name in 'Mailbox.Forwarding', 'Mailbox.AutoReply', 'Mailbox.Hidden', 'Calendar.CancelMeetings', 'Check.MailboxSharedEligibility') {
                { & (Get-Provider $name).Get $aliceTarget (New-Context) } | Should -Not -Throw -Because $name
            }
        }

        It 'the apply engine never converts it: the step fails with Tenure.Provider.Unsupported and no Set-Mailbox is sent' {
            $alice.RecipientTypeDetails = 'RoomMailbox'
            $plan = New-TestPlan -Steps @(New-ExchangeStep 'S01' 'Mailbox.Type' $aliceTarget @{ type = 'Shared' })
            Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false | Out-Null
            $plan.Steps[0].Status | Should -Be 'Failed'
            $plan.Steps[0].Result.Error | Should -BeLike 'Tenure.Provider.Unsupported:*RoomMailbox*'
            @(Get-FakeExchangeCall -World $w -Command 'Set-Mailbox').Count | Should -Be 0
            $alice.RecipientTypeDetails | Should -Be 'RoomMailbox'
        }

        It 'a mailbox whose boolean comes back as text is parsed, never cast ("False" stays false)' {
            $alice.HiddenFromAddressListsEnabled = 'False'
            (& (Get-Provider 'Mailbox.Hidden').Get $aliceTarget (New-Context)).hiddenFromAddressLists | Should -BeFalse
            $alice.LitigationHoldEnabled = 'True'
            @((& (Get-Provider 'Check.MailboxSharedEligibility').Get $aliceTarget (New-Context)).holds) | Should -Contain 'litigation'
            $alice.HiddenFromAddressListsEnabled = 'sometimes'
            { & (Get-Provider 'Mailbox.Hidden').Get $aliceTarget (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidResult'
        }
    }

    Context 'shared-mailbox eligibility property' {
        It 'for 200 random mailboxes, Get then Test agrees with an independent reference predicate' {
            $random = [System.Random]::new(6061)
            $holdPool = @('UniH00000000-0000-4000-8000-000000000001', '-mbx00000000000040008000000000000001:2', 'mbx00000000000040008000000000000002:1', '-mbx00000000000040008000000000000003:1', 'cld00000000000040008000000000000004')
            $provider = Get-Provider 'Check.MailboxSharedEligibility'
            $disagreements = [System.Collections.Generic.List[string]]::new()
            $edges = @(([long]50GB - 1), [long]50GB, ([long]50GB + 1), [long]0, [long]1, [long]10GB, ([long]10GB - 1), [long]100GB)
            for ($i = 0; $i -lt 200; $i++) {
                Reset-FakeExchangeWorld
                $mailbox = $global:FakeExchangeWorld.Mailboxes['alice@example.com']
                $size = if ($random.Next(2) -eq 0) { $edges[$random.Next($edges.Count)] } else { [long]($random.NextDouble() * 120GB) }
                $mailbox.TotalItemSizeBytes = $size
                $mailbox.ArchiveStatus = @('None', 'Active')[$random.Next(2)]
                $mailbox.LitigationHoldEnabled = ($random.Next(4) -eq 0)
                $mailbox.RetentionHoldEnabled = ($random.Next(5) -eq 0)
                $mailbox.InPlaceHolds = [string[]]@($holdPool | Where-Object { $random.Next(4) -eq 0 })
                $desired = @{}
                if ($random.Next(3) -eq 0) { $desired.allowArchive = ($random.Next(2) -eq 0) }
                if ($random.Next(3) -eq 0) { $desired.allowHolds = ($random.Next(2) -eq 0) }
                if ($random.Next(3) -eq 0) { $desired.maxSizeBytes = @([long]10GB, [long]50GB, [long]100GB)[$random.Next(3)] }

                # Reference, from the world rather than from the provider's snapshot:
                # under the limit, and no archive unless allowed, and no hold of any kind unless allowed.
                $limit = if ($desired.ContainsKey('maxSizeBytes')) { $desired.maxSizeBytes } else { [long]53687091200 }
                $archiveOk = ($desired.ContainsKey('allowArchive') -and $desired.allowArchive) -or ($mailbox.ArchiveStatus -eq 'None')
                $realHolds = @($mailbox.InPlaceHolds | Where-Object { $_[0] -ne '-' }).Count
                $holdsOk = ($desired.ContainsKey('allowHolds') -and $desired.allowHolds) -or (-not $mailbox.LitigationHoldEnabled -and -not $mailbox.RetentionHoldEnabled -and $realHolds -eq 0)
                $expected = ($size -lt $limit) -and $archiveOk -and $holdsOk

                # The snapshot compares the size with the limit the target carries; the plan builder gives target and desired the same one.
                $target = $aliceTarget.Clone()
                $target['MaxSizeBytes'] = $limit
                $actual = & $provider.Test (& $provider.Get $target (New-Context)) $desired
                $actual | Should -BeOfType [bool]
                if ($actual -ne $expected) {
                    $disagreements.Add("size=$size archive=$($mailbox.ArchiveStatus) lit=$($mailbox.LitigationHoldEnabled) ret=$($mailbox.RetentionHoldEnabled) holds=$($mailbox.InPlaceHolds -join ',') desired=$(($desired.Keys | Sort-Object | ForEach-Object { "$_=$($desired[$_])" }) -join ',') expected=$expected actual=$actual")
                }
                $text = & $provider.Describe $target (& $provider.Get $target (New-Context)) $desired 'Check'
                if (-not $expected) { $text | Should -BeLike '*a shared mailbox in this state still needs an Exchange Online license' }
            }
            $disagreements -join "`n" | Should -BeNullOrEmpty
        }
    }
}

Describe 'The real Exchange seam when Exchange is not connected' {
    BeforeAll {
        Mock -ModuleName Tenure Get-Command { throw 'test: the seam must not resolve a cmdlet while Exchange is not connected' }
    }
    BeforeEach { Set-TenureTestSession -Exchange $false }

    It '<_> Get stops at Tenure.Exchange.NotConnected without resolving any cmdlet' -ForEach @('Mailbox.Type', 'Mailbox.Forwarding', 'Mailbox.AutoReply', 'Mailbox.Hidden', 'Calendar.CancelMeetings', 'Check.MailboxSharedEligibility') {
        $target = @{ Kind = 'mailbox'; Id = '10000000-0000-4000-8000-000000000001'; Name = 'alice@example.com'; Grantee = 'bob@example.com' }
        { & (Get-Provider $_).Get $target (New-Context) } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
        Should -Invoke -ModuleName Tenure -CommandName Get-Command -Times 0 -Exactly
    }
}
