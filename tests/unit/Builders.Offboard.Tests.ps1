# New-TenureOffboardPlan, the two subject checks, and the Resolve helpers it uses,
# against FakeGraph and FakeExchange. alice (manager bob) is the subject unless a test says otherwise;
# carol is the signed-in account of the fakes, but the test session signs in as admin@example.com.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeExchange.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    $global:FakeExchangeWorld = New-FakeExchangeWorld
    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
    Mock -ModuleName Tenure Invoke-TenureExchange {
        & (Get-Module -Name Tenure) { Assert-TenureConnection -Backend Exchange }
        Invoke-FakeExchangeCommand -World $global:FakeExchangeWorld -Command $Command -Parameters $Parameters
    }

    $script:ExamplePolicyPath = Join-Path $script:TenureSourceRoot 'Policies' 'example.policy.json'
    $script:GlobalAdminTemplate = '62e90394-69f5-4237-9190-012177145e10'

    # The example policy with edits applied to its raw hashtable (offboard settings live under defaults.offboard).
    function New-TestPolicy([scriptblock]$Edit) {
        $raw = Get-Content -LiteralPath $script:ExamplePolicyPath -Raw | ConvertFrom-Json -AsHashtable
        if ($Edit) { & $Edit $raw }
        Get-TenurePolicy -InputObject $raw
    }
    # The example policy protects breakglass@example.com, an account the fakes do not have: every plan built from it
    # warns that the entry protects no one. Counts of the builder's own warnings leave that one out.
    function Get-BuilderWarning($Plan) { @($Plan.Warnings | Where-Object { $_ -notlike "The policy's protectedUsers entry 'breakglass@example.com' matches no user*" }) }
    function Get-Step($Plan, [string]$Key) { @($Plan.Steps | Where-Object { $_.Key -ceq $Key })[0] }
    function Get-Keys($Plan) { @($Plan.Steps | ForEach-Object { $_.Key }) }
    function Get-Writes { @($global:FakeGraphWorld.Calls | Where-Object { $_.Method -in 'POST', 'PATCH', 'PUT', 'DELETE' }) }
    function Get-ExchangeWrites { @($global:FakeExchangeWorld.Calls | Where-Object { $_.Command -notlike 'Get-*' }) }
    function Get-User([string]$Key) { $global:FakeGraphWorld.Users | Where-Object { $_['id'] -eq $Key -or $_['userPrincipalName'] -eq $Key } | Select-Object -First 1 }
    function Get-FakeGroup([string]$Id) { $global:FakeGraphWorld.Groups | Where-Object { $_['id'] -eq $Id } | Select-Object -First 1 }
    # Makes the fake's Global Administrator role carry the real template id, and puts the given users in it.
    function Set-GlobalAdmin([string[]]$UserId) {
        $role = $global:FakeGraphWorld.DirectoryRoles[0]
        $role['roleTemplateId'] = $script:GlobalAdminTemplate
        $role['members'] = [string[]]$UserId
    }
    function Remove-FakeMailbox([string]$UserId, [string]$Upn) {
        $null = $global:FakeExchangeWorld.Mailboxes.Remove($UserId)
        $null = $global:FakeExchangeWorld.Mailboxes.Remove($Upn)
    }
    # Gives a user MCOEV as their only license: none of their licenses then includes an Exchange Online service plan.
    function Set-NoExchangeLicense([string]$UserId) {
        $user = Get-User $UserId
        $user['assignedLicenses'] = [System.Collections.Generic.List[hashtable]]::new()
        $user['assignedLicenses'].Add(@{ skuId = $script:ids.SkuVoiceId; disabledPlans = @() })
        $user['licenseAssignmentStates'] = [System.Collections.Generic.List[hashtable]]::new()
        $user['licenseAssignmentStates'].Add(@{ skuId = $script:ids.SkuVoiceId; assignedByGroup = $null; state = 'Active'; error = 'None' })
    }
    function Get-LicenseDetailReads { @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method GET -UriLike '*licenseDetails*') }
    function Get-TestHashOf($Value) { Invoke-InTenure { param($v) Get-TenureHash -InputObject $v } @(, $Value) }
    function Edit-Offboard([hashtable]$Settings) {
        $edit = { param($raw) foreach ($key in $Settings.Keys) { $raw['defaults']['offboard'][$key] = $Settings[$key] } }.GetNewClosure()
        New-TestPolicy -Edit $edit
    }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeExchangeWorld -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Resolve helpers for the builders' {
    BeforeEach {
        Reset-FakeGraphWorld
        Set-TenureTestSession
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
    }

    It 'Get-TenureUserMembership splits memberOf into groups with flags and roles, across pages, in display-name order' {
        $membership = Invoke-InTenure { param($id) Get-TenureUserMembership -UserId $id } @($ids.AliceId)
        @($membership.Groups | ForEach-Object { $_.DisplayName }) | Should -Be @('All Staff', 'Everyone Dynamic', 'Legal DL', 'Sales')
        @($membership.Roles).Count | Should -Be 0
        $byName = @{}
        foreach ($group in $membership.Groups) { $byName[$group.DisplayName] = $group }
        $byName['Sales'].Id | Should -BeExactly $ids.SalesGroupId
        $byName['Sales'].IsUnified | Should -BeTrue
        $byName['Sales'].IsExchangeManaged | Should -BeFalse
        $byName['Sales'].Mail | Should -BeExactly 'sales@example.com'
        $byName['All Staff'].SecurityEnabled | Should -BeTrue
        $byName['All Staff'].IsExchangeManaged | Should -BeFalse
        $byName['Everyone Dynamic'].IsDynamic | Should -BeTrue
        $byName['Legal DL'].IsExchangeManaged | Should -BeTrue
        $byName['Legal DL'].MailEnabled | Should -BeTrue
        $byName['Legal DL'].IsUnified | Should -BeFalse
        @($byName['Everyone Dynamic'].GroupTypes) | Should -Be @('DynamicMembership')
        (Get-FakeGraphCall -World $w -Method GET -UriLike '*memberOf*').Count | Should -BeGreaterThan 1 -Because 'the fake pages in twos'
    }

    It 'Get-TenureUserMembership lists directory roles, and the group list is empty for a user with no groups' {
        $role = $w.DirectoryRoles[0]
        $role['members'] = [string[]]@($ids.CarolId)
        ($w.Groups | ForEach-Object { $_['members'] = [string[]]@(@($_['members']) | Where-Object { $_ -ne $ids.CarolId }) })
        $membership = Invoke-InTenure { param($id) Get-TenureUserMembership -UserId $id } @($ids.CarolId)
        @($membership.Groups).Count | Should -Be 0
        @($membership.Roles).Count | Should -Be 1
        $membership.Roles[0].Id | Should -BeExactly $ids.GlobalAdminRoleId
        $membership.Roles[0].DisplayName | Should -BeExactly 'Global Administrator'
        $membership.Roles[0].RoleTemplateId | Should -BeExactly '41000000-0000-4000-8000-000000000001'
    }

    It 'Get-TenureUserMembership fails for an unknown user' {
        { Invoke-InTenure { Get-TenureUserMembership -UserId 'ffffffff-ffff-4fff-8fff-ffffffffffff' } } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
    }

    It 'Get-TenureUserManagedDevice lists the devices with lower-case ownership, ordered by name' {
        $devices = @(Invoke-InTenure { param($id) Get-TenureUserManagedDevice -UserId $id } @($ids.AliceId))
        $devices.Count | Should -Be 3
        @($devices | ForEach-Object { $_.DeviceName }) | Should -Be @('ALICE-LAPTOP', 'ALICE-PHONE', 'ALICE-TABLET')
        @($devices | ForEach-Object { $_.Ownership }) | Should -Be @('company', 'personal', 'unknown')
        $devices[0].Id | Should -BeExactly $ids.CompanyDeviceId
        $devices[0].OperatingSystem | Should -BeExactly 'Windows'
        @(Invoke-InTenure { param($id) Get-TenureUserManagedDevice -UserId $id } @($ids.BobId)).Count | Should -Be 0
    }

    It 'Get-TenureUserManagedDevice calls anything but company or personal unknown, whatever the case' {
        $w.ManagedDevices[2]['ownerType'] = ' COMPANY '
        $w.ManagedDevices[1]['ownerType'] = 'Corporate'
        $w.ManagedDevices[0]['ownerType'] = $null
        $devices = @(Invoke-InTenure { param($id) Get-TenureUserManagedDevice -UserId $id } @($ids.AliceId))
        @($devices | ForEach-Object { $_.Ownership }) | Should -Be @('unknown', 'unknown', 'company')
    }

    It 'Get-TenureGroupOwner lists owners with their user principal names' {
        $owners = @(Invoke-InTenure { param($id) Get-TenureGroupOwner -GroupId $id } @($ids.SalesGroupId))
        $owners.Count | Should -Be 1
        $owners[0].Id | Should -BeExactly $ids.BobId
        $owners[0].UserPrincipalName | Should -BeExactly 'bob@example.com'
        @(Invoke-InTenure { param($id) Get-TenureGroupOwner -GroupId $id } @($ids.AllStaffGroupId)).Count | Should -Be 0
        { Invoke-InTenure { Get-TenureGroupOwner -GroupId '20000000-0000-4000-8000-0000000000ee' } } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
    }

    It 'Get-TenureUserExchangePlan lists the Exchange Online service plans of direct and group-inherited licenses' {
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.AliceId) | ForEach-Object { "$($_.SkuPartNumber)/$($_.ServicePlanName)" }) | Should -Be @('SPE_E3/EXCHANGE_S_ENTERPRISE')
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.BobId) | ForEach-Object { "$($_.SkuPartNumber)/$($_.ServicePlanName)" }) | Should -Be @('SPE_E3/EXCHANGE_S_ENTERPRISE') -Because 'bob holds SPE_E3 through All Staff'
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.CarolId)).Count | Should -Be 0 -Because 'carol holds no license'
    }

    It 'Get-TenureUserExchangePlan finds nothing for a user whose only license has no Exchange Online plan, and counts a license whose plans are not reported' {
        $alice = $w.Users | Where-Object { $_['id'] -eq $ids.AliceId }
        $alice['assignedLicenses'] = [System.Collections.Generic.List[hashtable]]::new()
        $alice['assignedLicenses'].Add(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() })
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.AliceId)).Count | Should -Be 0
        ($w.SubscribedSkus | Where-Object { $_['skuId'] -eq $ids.SkuVoiceId })['servicePlans'] = @()
        $unknown = @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.AliceId))
        $unknown.Count | Should -Be 1 -Because 'a license whose plans Graph does not report might carry a mailbox'
        $unknown[0].SkuPartNumber | Should -BeExactly 'MCOEV'
        $unknown[0].ServicePlanName | Should -BeExactly '(service plans not reported)'
    }

    It 'Get-TenureUserExchangePlan counts only plans that grant a mailbox: EXCHANGE_S_ but not FOUNDATION, and not Disabled' {
        $alice = $w.Users | Where-Object { $_['id'] -eq $ids.AliceId }
        $voice = $w.SubscribedSkus | Where-Object { $_['skuId'] -eq $ids.SkuVoiceId }
        $alice['assignedLicenses'] = [System.Collections.Generic.List[hashtable]]::new()
        $alice['assignedLicenses'].Add(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() })

        # A license whose only Exchange plan is EXCHANGE_S_FOUNDATION grants no mailbox.
        $voice['servicePlans'] = @(@{ servicePlanId = '31000000-0000-4000-8000-000000000009'; servicePlanName = 'EXCHANGE_S_FOUNDATION'; appliesTo = 'User' }, @{ servicePlanId = '31000000-0000-4000-8000-000000000005'; servicePlanName = 'MCOEV'; appliesTo = 'User' })
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.AliceId)).Count | Should -Be 0 -Because 'EXCHANGE_S_FOUNDATION comes with many licenses and no mailbox'

        # Other EXCHANGE names that are not EXCHANGE_S_ do not count either.
        $voice['servicePlans'] = @(@{ servicePlanId = '31000000-0000-4000-8000-00000000000a'; servicePlanName = 'EXCHANGE_ANALYTICS'; appliesTo = 'User' })
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.AliceId)).Count | Should -Be 0

        # A mailbox-granting plan that the assignment disables grants nothing.
        $alice['assignedLicenses'] = [System.Collections.Generic.List[hashtable]]::new()
        $alice['assignedLicenses'].Add(@{ skuId = $ids.SkuE3Id; disabledPlans = @('31000000-0000-4000-8000-000000000001') })
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.AliceId)).Count | Should -Be 0 -Because 'EXCHANGE_S_ENTERPRISE is Disabled in this assignment'

        # The same plan enabled grants a mailbox.
        $alice['assignedLicenses'][0]['disabledPlans'] = @()
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.AliceId) | ForEach-Object { "$($_.SkuPartNumber)/$($_.ServicePlanName)" }) | Should -Be @('SPE_E3/EXCHANGE_S_ENTERPRISE')
    }

    It 'Get-TenureUserExchangePlan fails closed on a service plan it cannot read' {
        $alice = $w.Users | Where-Object { $_['id'] -eq $ids.AliceId }
        $alice['assignedLicenses'] = [System.Collections.Generic.List[hashtable]]::new()
        $alice['assignedLicenses'].Add(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() })
        ($w.SubscribedSkus | Where-Object { $_['skuId'] -eq $ids.SkuVoiceId })['servicePlans'] = @(@{ servicePlanId = '31000000-0000-4000-8000-00000000000b'; servicePlanName = ''; appliesTo = 'User' })
        @(Invoke-InTenure { param($id) Get-TenureUserExchangePlan -UserId $id } @($ids.AliceId) | ForEach-Object { $_.ServicePlanName }) | Should -Be @('(service plan name not reported)')
    }

    It 'Get-TenureGroupLicense reads a group''s license assignments once per plan' {
        (Get-FakeGroup $ids.AllStaffGroupId)['assignedLicenses'] = @(@{ skuId = $ids.SkuE3Id.ToUpperInvariant(); disabledPlans = @() })
        $cache = @{}
        @(Invoke-InTenure { param($id, $c) Get-TenureGroupLicense -GroupId $id -Cache $c } @($ids.AllStaffGroupId, $cache)) | Should -Be @($ids.SkuE3Id)
        @(Invoke-InTenure { param($id, $c) Get-TenureGroupLicense -GroupId $id -Cache $c } @($ids.AllStaffGroupId, $cache)) | Should -Be @($ids.SkuE3Id)
        @(Get-FakeGraphCall -World $w -Method GET -UriLike "*groups/$($ids.AllStaffGroupId)?*assignedLicenses*").Count | Should -Be 1
        @(Invoke-InTenure { param($id) Get-TenureGroupLicense -GroupId $id } @($ids.SalesGroupId)).Count | Should -Be 0
    }

    It 'Get-TenureGroupLicense -Detailed keeps each assignment''s disabled service plans, from the same cache' {
        (Get-FakeGroup $ids.AllStaffGroupId)['assignedLicenses'] = @(@{ skuId = $ids.SkuE3Id.ToUpperInvariant(); disabledPlans = @('31000000-0000-4000-8000-000000000001') })
        $cache = @{}
        $detail = @(Invoke-InTenure { param($id, $c) Get-TenureGroupLicense -GroupId $id -Cache $c -Detailed } @($ids.AllStaffGroupId, $cache))
        $detail.Count | Should -Be 1
        $detail[0].SkuId | Should -BeExactly $ids.SkuE3Id
        @($detail[0].DisabledPlans) | Should -Be @('31000000-0000-4000-8000-000000000001')
        @(Invoke-InTenure { param($id, $c) Get-TenureGroupLicense -GroupId $id -Cache $c } @($ids.AllStaffGroupId, $cache)) | Should -Be @($ids.SkuE3Id)
        @(Get-FakeGraphCall -World $w -Method GET -UriLike "*groups/$($ids.AllStaffGroupId)?*assignedLicenses*").Count | Should -Be 1
    }

    It 'Get-TenureMailboxSku names the mailbox service plans and the free seats of every subscribed SKU' {
        $skus = @{}
        foreach ($sku in @(Invoke-InTenure { Get-TenureMailboxSku })) { $skus[$sku.SkuId] = $sku }
        @($skus[$ids.SkuE3Id].MailboxPlanIds) | Should -Be @('31000000-0000-4000-8000-000000000001')
        $skus[$ids.SkuE3Id].Available | Should -Be 7
        @($skus[$ids.SkuDeskId].MailboxPlanIds).Count | Should -Be 1
        $skus[$ids.SkuDeskId].Available | Should -Be 0
        $skus[$ids.SkuDeskId].Consumed | Should -Be 5
        @($skus[$ids.SkuVoiceId].MailboxPlanIds).Count | Should -Be 0 -Because 'MCOEV gives no mailbox'
    }

    It 'Expand-TenureAutoReplyTemplate fills known names in one pass and reports the rest' {
        $result = Invoke-InTenure { param($t, $v) Expand-TenureAutoReplyTemplate -Template $t -Value $v } @('{displayName} left {company}. Ask {managerDisplayName} ({managerMail}) or {displayName}.', @{ displayName = '{managerMail}'; managerDisplayName = 'Bob'; managerMail = 'bob@example.com' })
        $result.Text | Should -BeExactly '{managerMail} left {company}. Ask Bob (bob@example.com) or {managerMail}.'
        @($result.Unresolved) | Should -Be @('company')
        @($result.Used) | Should -Be @('displayName', 'managerDisplayName', 'managerMail')
        (Invoke-InTenure { Expand-TenureAutoReplyTemplate -Template '' -Value @{} }).Text | Should -BeExactly ''
    }
}

Describe 'Check.SubjectAllowed' {
    BeforeAll { $script:provider = Get-TenureProvider -Name 'Check.SubjectAllowed' }
    BeforeEach {
        Reset-FakeGraphWorld
        Set-TenureTestSession
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $script:target = @{ Kind = 'user'; Id = $ids.AliceId; Name = 'alice@example.com' }
    }

    It 'is a Low-risk Refuse check on Graph without a Set' {
        $provider.Kind | Should -BeExactly 'Check'
        $provider.Backend | Should -BeExactly 'Graph'
        $provider.Severity | Should -BeExactly 'Refuse'
        $provider.Risk | Should -BeExactly 'Low'
        $provider.Reversible | Should -BeTrue
        @($provider.Scopes) | Should -Be @('User.Read.All')
        $provider.Set | Should -BeNullOrEmpty
    }

    It 'stores who the subject is and the verdict, never the signed-in account or the protected list' {
        $policy = New-TestPolicy -Edit { param($raw) $raw['defaults']['protectedUsers'] = @('zed@example.com', 'Breakglass@example.com', 'breakglass@example.com') }
        $current = & $provider.Get $target @{ Policy = $policy; Session = [pscustomobject]@{ Account = 'admin@example.com' }; Subject = @{ Id = $ids.AliceId } }
        @($current.PSObject.Properties.Name) | Should -Be @('id', 'userPrincipalName', 'mail', 'refusal')
        $current.userPrincipalName | Should -BeExactly 'alice@example.com'
        $current.refusal | Should -BeNullOrEmpty
    }

    It 'gives the same snapshot to another administrator, and with the protected list read from the plan instead of the policy' {
        $policy = New-TestPolicy -Edit { param($raw) $raw['defaults']['protectedUsers'] = @('breakglass@example.com') }
        $one = & $provider.Get $target @{ Policy = $policy; Session = [pscustomobject]@{ Account = 'admin@example.com' } }
        $two = & $provider.Get $target @{ ProtectedUsers = [string[]]@('breakglass@example.com', 'zed@example.com'); Session = [pscustomobject]@{ Account = 'other.admin@example.com' } }
        (Get-TestHashOf $two) | Should -BeExactly (Get-TestHashOf $one) -Because 'who applies a plan, and protected entries for other users, are not drift'
    }

    It 'reads no protected list and no account when the context has neither, and passes' {
        $current = & $provider.Get $target @{}
        $current.refusal | Should -BeNullOrEmpty
        & $provider.Test $current $null | Should -BeTrue
    }

    It 'takes Context.ProtectedUsers over Context.Policy when both are given' {
        $policy = New-TestPolicy -Edit { param($raw) $raw['defaults']['protectedUsers'] = @() }
        $current = & $provider.Get $target @{ Policy = $policy; ProtectedUsers = [string[]]@('alice@example.com') }
        & $provider.Test $current $null | Should -BeFalse
    }

    It 'passes for any other user' {
        $current = & $provider.Get $target @{ ProtectedUsers = [string[]]@('breakglass@example.com'); Session = [pscustomobject]@{ Account = 'admin@example.com' } }
        & $provider.Test $current $null | Should -BeTrue
        & $provider.Describe $target $current $null 'NoOp' | Should -Match 'allowed'
    }

    It 'refuses the signed-in account, whatever the case' {
        $current = & $provider.Get $target @{ Session = [pscustomobject]@{ Account = 'ALICE@example.COM' } }
        & $provider.Test $current $null | Should -BeFalse
        & $provider.Describe $target $current $null 'Check' | Should -Match 'signed-in account'
    }

    It 'refuses a protected user, matching the UPN whatever the case' {
        $current = & $provider.Get $target @{ ProtectedUsers = [string[]]@('ALICE@example.com'); Session = [pscustomobject]@{ Account = 'admin@example.com' } }
        & $provider.Test $current $null | Should -BeFalse
        & $provider.Describe $target $current $null 'Check' | Should -Match 'protected by policy'
    }

    It 'reads the subject''s object id and mail address into the snapshot' {
        ($w.Users | Where-Object { $_['id'] -eq $ids.AliceId })['mail'] = 'alice.example@example.com'
        $current = & $provider.Get $target @{}
        $current.id | Should -BeExactly $ids.AliceId
        $current.userPrincipalName | Should -BeExactly 'alice@example.com'
        $current.mail | Should -BeExactly 'alice.example@example.com'
    }

    It 'refuses a protected user named by <Form>, whatever the case' -ForEach @(
        @{ Form = 'user principal name'; Entry = 'ALICE@example.com' }
        @{ Form = 'object id'; Entry = ' 10000000-0000-4000-8000-000000000001 ' }
        @{ Form = 'mail address'; Entry = 'Alice.Example@EXAMPLE.com' }
    ) {
        ($w.Users | Where-Object { $_['id'] -eq $ids.AliceId })['mail'] = 'alice.example@example.com'
        $protecting = New-TestPolicy -Edit ({ param($raw) $raw['defaults']['protectedUsers'] = @('breakglass@example.com', $Entry) }.GetNewClosure())
        $current = & $provider.Get $target @{ Policy = $protecting; Session = [pscustomobject]@{ Account = 'admin@example.com' } }
        & $provider.Test $current $null | Should -BeFalse
        & $provider.Describe $target $current $null 'Check' | Should -Match 'protected by policy'
    }

    It 'a near miss protects no one: <Label>' -ForEach @(
        @{ Label = 'the alias without its domain'; Entry = 'alice' }
        @{ Label = 'the same name in another domain'; Entry = 'alice@example.org' }
        @{ Label = 'an address that only ends like hers'; Entry = 'malice@example.com' }
        @{ Label = 'a mail address with one character changed'; Entry = 'alice.exampl@example.com' }
        @{ Label = 'an object id with one character changed'; Entry = '10000000-0000-4000-8000-000000000011' }
        @{ Label = 'the display name'; Entry = 'Alice Example' }
    ) {
        ($w.Users | Where-Object { $_['id'] -eq $ids.AliceId })['mail'] = 'alice.example@example.com'
        $nearMiss = New-TestPolicy -Edit ({ param($raw) $raw['defaults']['protectedUsers'] = @($Entry) }.GetNewClosure())
        $current = & $provider.Get $target @{ Policy = $nearMiss }
        & $provider.Test $current $null | Should -BeTrue
        & $provider.Describe $target $current $null 'NoOp' | Should -Match 'allowed'
    }

    It 'refuses the signed-in account when it is given as the subject''s mail address' {
        ($w.Users | Where-Object { $_['id'] -eq $ids.AliceId })['mail'] = 'alice.example@example.com'
        $current = & $provider.Get $target @{ Session = [pscustomobject]@{ Account = 'Alice.Example@example.com' } }
        & $provider.Test $current $null | Should -BeFalse
        & $provider.Describe $target $current $null 'Check' | Should -Match 'signed-in account'
    }

    It 'the apply engine refuses the plan before step 1 when the policy protects the subject by object id' {
        $protecting = New-TestPolicy -Edit { param($raw) $raw['defaults']['protectedUsers'] = @('10000000-0000-4000-8000-000000000001') }
        $session = Invoke-InTenure { $script:Session }
        $step = New-TenureStep -Provider 'Check.SubjectAllowed' -Target $target -Context @{ Policy = $protecting; Session = $session } -Key 'subject'
        $step.Action | Should -BeExactly 'Check' -Because 'the check already fails when the plan is built'
        $plan = New-TenurePlan -Operation Offboard -Subject @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice Example' } -Step $step -Policy $protecting
        $audit = Join-Path $TestDrive ('subject-{0}.jsonl' -f [guid]::NewGuid().ToString('N'))
        { Invoke-TenurePlan -Plan $plan -Policy $protecting -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
        { Invoke-TenurePlan -Plan $plan -AuditPath $audit -Confirm:$false } | Should -Throw -ErrorId 'Tenure.Plan.Refused' -Because 'without -Policy the list the plan recorded is used'
        Test-Path $audit | Should -BeFalse
        $plan.Steps[0].Status | Should -BeExactly 'Pending'
    }

    It 'never passes without a snapshot, without a user principal name, or with a refusal' {
        & $provider.Test $null $null | Should -BeFalse
        & $provider.Test ([pscustomobject]@{ userPrincipalName = ''; refusal = $null }) $null | Should -BeFalse
        & $provider.Test ([pscustomobject]@{ userPrincipalName = 'alice@example.com'; refusal = 'subject is the signed-in account' }) $null | Should -BeFalse
    }

    It 'reports a missing user as TargetNotFound' {
        { & $provider.Get @{ Kind = 'user'; Id = 'ffffffff-ffff-4fff-8fff-ffffffffffff'; Name = 'x' } @{} } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }
}

Describe 'Check.SubjectNotGlobalAdmin' {
    BeforeAll { $script:provider = Get-TenureProvider -Name 'Check.SubjectNotGlobalAdmin' }
    BeforeEach {
        Reset-FakeGraphWorld
        Set-TenureTestSession
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
    }

    It 'is a Low-risk Warn check on Graph without a Set' {
        $provider.Kind | Should -BeExactly 'Check'
        $provider.Severity | Should -BeExactly 'Warn'
        $provider.Risk | Should -BeExactly 'Low'
        @($provider.Scopes) | Should -Be @('RoleManagement.Read.Directory', 'User.Read.All')
        $provider.Set | Should -BeNullOrEmpty
    }

    It 'passes for a user with no role and for one with another role' {
        $alice = & $provider.Get @{ Kind = 'user'; Id = $ids.AliceId; Name = 'alice@example.com' } @{}
        $alice.isGlobalAdmin | Should -BeFalse
        @($alice.roles).Count | Should -Be 0
        & $provider.Test $alice $null | Should -BeTrue
        # The fake's role has a made-up template id, so it is not Global Administrator.
        $carol = & $provider.Get @{ Kind = 'user'; Id = $ids.CarolId; Name = 'carol@example.com' } @{}
        @($carol.roles) | Should -Be @('Global Administrator')
        $carol.isGlobalAdmin | Should -BeFalse
    }

    It 'warns for the Global Administrator role, matched by its template id' {
        Set-GlobalAdmin -UserId $ids.CarolId
        $target = @{ Kind = 'user'; Id = $ids.CarolId; Name = 'carol@example.com' }
        $carol = & $provider.Get $target @{}
        $carol.isGlobalAdmin | Should -BeTrue
        & $provider.Test $carol $null | Should -BeFalse
        & $provider.Describe $target $carol $null 'Check' | Should -Match 'holds Global Administrator'
        & $provider.Describe $target $carol $null 'Check' | Should -Match 'break-glass'
    }

    It 'lists the role names sorted' {
        $w.DirectoryRoles.Add(@{ id = '40000000-0000-4000-8000-000000000002'; displayName = 'Billing Administrator'; roleTemplateId = 'b0f54661-2d74-4c50-afa3-1ec803f12efe'; description = 'x'; members = [string[]]@($ids.AliceId) })
        $w.DirectoryRoles[0]['members'] = [string[]]@($ids.AliceId)
        $alice = & $provider.Get @{ Kind = 'user'; Id = $ids.AliceId; Name = 'alice@example.com' } @{}
        @($alice.roles) | Should -Be @('Billing Administrator', 'Global Administrator')
    }

    It 'fails closed on a missing snapshot and reports a missing user as TargetNotFound' {
        & $provider.Test $null $null | Should -BeFalse
        & $provider.Test ([pscustomobject]@{ roles = @(); isGlobalAdmin = 'false' }) $null | Should -BeFalse
        { & $provider.Get @{ Kind = 'user'; Id = 'ffffffff-ffff-4fff-8fff-ffffffffffff'; Name = 'x' } @{} } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }
}

Describe 'New-TenureOffboardPlan' {
    BeforeAll {
        $script:policy = Get-TenurePolicy -Path $script:ExamplePolicyPath
    }
    BeforeEach {
        Reset-FakeGraphWorld
        Reset-FakeExchangeWorld
        Set-TenureTestSession
        $script:w = $global:FakeGraphWorld
        $script:x = $global:FakeExchangeWorld
        $script:ids = $script:w.Ids
    }

    Context 'the full plan for alice with the example policy' {
        It 'follows SPEC 5.1 step by step, with the golden shape' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $plan.PSObject.TypeNames | Should -Contain 'Tenure.Plan'
            $plan.Operation | Should -BeExactly 'Offboard'

            # Fixture ids are replaced by the fixture names, so the golden file reads as a story.
            $names = @{}
            foreach ($pair in $ids.GetEnumerator()) { $names[([string]$pair.Value).ToLowerInvariant()] = ($pair.Key -replace 'Id$', '') }
            $rename = { param([string]$Text) foreach ($id in $names.Keys) { $Text = $Text -replace [regex]::Escape($id), $names[$id] }; $Text }
            $keyById = @{}
            foreach ($step in $plan.Steps) { $keyById[$step.Id] = $step.Key }
            $shape = @($plan.Steps | ForEach-Object {
                    [ordered]@{
                        provider   = $_.Provider
                        action     = $_.Action
                        targetKind = $_.Target.Kind
                        targetName = $_.Target.Name
                        key        = & $rename $_.Key
                        dependsOn  = @($_.DependsOn | ForEach-Object { & $rename $keyById[$_] })
                        risk       = $_.Risk
                    }
                })
            $golden = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'golden' 'offboard-plan-shape.json') -Raw | ConvertFrom-Json -AsHashtable
            $shape.Count | Should -Be $golden.Count
            (Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $shape)) | Should -BeExactly (Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $golden))
        }

        It 'numbers the steps S01 to S21 and gives every step a reason' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            @($plan.Steps | ForEach-Object { $_.Id }) | Should -Be @(1..21 | ForEach-Object { 'S{0:D2}' -f $_ })
            foreach ($step in $plan.Steps) {
                $step.Reason | Should -Not -BeNullOrEmpty -Because "step $($step.Key) needs a reason"
                $step.Status | Should -BeExactly 'Pending'
            }
        }

        It 'makes the license step depend on the mailbox conversion, and nothing else depends on anything' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $licenses = Get-Step $plan 'licenses'
            $mailboxType = Get-Step $plan 'mailboxType'
            @($licenses.DependsOn) | Should -Be @($mailboxType.Id)
            $mailboxType.Id | Should -BeLessThan $licenses.Id
            @($plan.Steps | Where-Object { $_.Key -cne 'licenses' -and @($_.DependsOn).Count -gt 0 }).Count | Should -Be 0
        }

        It 'plans the right state for every step' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $subject = $plan.Subject
            $subject.Id | Should -BeExactly $ids.AliceId
            $subject.UserPrincipalName | Should -BeExactly 'alice@example.com'
            $subject.DisplayName | Should -BeExactly 'Alice Example'
            (Get-Step $plan 'signin').After.accountEnabled | Should -BeFalse
            (Get-Step $plan 'password').After.discard | Should -BeTrue
            (Get-Step $plan 'eligibility').After.maxSizeBytes | Should -Be 53687091200
            (Get-Step $plan 'eligibility').After.allowArchive | Should -BeFalse
            (Get-Step $plan 'eligibility').After.allowHolds | Should -BeFalse
            (Get-Step $plan 'mailboxType').After.type | Should -BeExactly 'Shared'
            (Get-Step $plan 'forwarding').After.forwardingSmtpAddress | Should -BeExactly 'bob@example.com'
            (Get-Step $plan 'forwarding').After.deliverToMailboxAndForward | Should -BeTrue
            (Get-Step $plan 'hidden').After.hiddenFromAddressLists | Should -BeTrue
            (Get-Step $plan 'calendar').After.queryWindowInDays | Should -Be 120
            $delegate = Get-Step $plan 'delegate'
            $delegate.Target.Grantee | Should -BeExactly 'bob@example.com'
            $delegate.Target.Id | Should -BeExactly $ids.AliceId
            $delegate.After.user | Should -BeExactly 'bob@example.com'
            $delegate.After.accessRights | Should -BeExactly 'FullAccess'
            $delegate.After.present | Should -BeTrue
            $oneDrive = Get-Step $plan 'onedrive'
            $oneDrive.Target.Kind | Should -BeExactly 'drive'
            $oneDrive.Target.Id | Should -BeExactly $ids.AliceId
            $oneDrive.After.granteeEmail | Should -BeExactly 'bob@example.com'
            $oneDrive.After.role | Should -BeExactly 'write'
            $oneDrive.After.present | Should -BeTrue
            @((Get-Step $plan 'licenses').After.add).Count | Should -Be 0
            (Get-Step $plan 'licenses').After.remove | Should -Be @($ids.SkuE3Id) -Because 'the step removes exactly the licenses assigned directly when it was planned'
            (Get-Step $plan 'licenses').Before.skuIds | Should -Be @($ids.SkuE3Id)
            (Get-Step $plan 'licenses').Risk | Should -BeExactly 'High'
        }

        It 'removes every group but gives the dynamic one a NoOp and sends the distribution list through Exchange' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $groups = @($plan.Steps | Where-Object { $_.Key -like 'group:*' })
            @($groups | ForEach-Object { $_.Target.Name }) | Should -Be @('All Staff', 'Everyone Dynamic', 'Legal DL', 'Sales')
            foreach ($group in $groups) {
                $group.After.userId | Should -BeExactly $ids.AliceId
                $group.After.member | Should -BeFalse
                $group.Target.Kind | Should -BeExactly 'group'
            }
            $dynamic = Get-Step $plan "group:$($ids.DynamicGroupId)"
            $dynamic.Action | Should -BeExactly 'NoOp'
            $dynamic.Reason | Should -Match 'dynamic membership'
            $dynamic.Fingerprint | Should -Match '^[0-9a-f]{64}$' -Because 'a NoOp still carries its snapshot'
            $legal = Get-Step $plan "group:$($ids.LegalDlGroupId)"
            $legal.Provider | Should -BeExactly 'DistributionGroup.Member'
            $legal.Action | Should -BeExactly 'Update'
            (Get-Step $plan "group:$($ids.SalesGroupId)").Provider | Should -BeExactly 'Group.Member'
            (Get-Step $plan "group:$($ids.AllStaffGroupId)").Provider | Should -BeExactly 'Group.Member'
        }

        It 'plans one device step per device: wipe the company laptop, retire the phone and the tablet' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $wipe = Get-Step $plan "device:$($ids.CompanyDeviceId)"
            $wipe.Provider | Should -BeExactly 'Device.Wipe'
            $wipe.Risk | Should -BeExactly 'Destructive'
            $wipe.Target.Id | Should -BeExactly $ids.CompanyDeviceId
            $wipe.Target.Name | Should -BeExactly 'ALICE-LAPTOP (company)'
            $wipe.After.keepEnrollmentData | Should -BeFalse
            $wipe.After.keepUserData | Should -BeFalse
            (Get-Step $plan "device:$($ids.PersonalDeviceId)").Provider | Should -BeExactly 'Device.Retire'
            (Get-Step $plan "device:$($ids.UnknownDeviceId)").Provider | Should -BeExactly 'Device.Retire'
            (Get-Step $plan "device:$($ids.UnknownDeviceId)").Target.Name | Should -BeExactly 'ALICE-TABLET (unknown)'
        }

        It 'warns about the tablet of unknown ownership, the auto-reply placeholder it cannot fill, and nothing else' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            @($plan.Warnings | Where-Object { $_ -like '*ALICE-TABLET*' -and $_ -like '*unknown ownership*' -and $_ -like '*never wiped*' }).Count | Should -Be 1
            @($plan.Warnings | Where-Object { $_ -like '*{company}*' }).Count | Should -Be 1
            @(Get-BuilderWarning $plan).Count | Should -Be 2
        }

        It 'renders the auto-reply from the policy template for both audiences' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $reply = (Get-Step $plan 'autoreply').After
            $expected = 'Alice Example has left {company}. Please contact Bob Manager (bob@example.com).'
            $reply.autoReplyState | Should -BeExactly 'Enabled'
            $reply.internalMessage | Should -BeExactly $expected
            $reply.externalMessage | Should -BeExactly $expected
            $reply.externalAudience | Should -BeExactly 'All'
        }

        It 'records the request and the policy, and no secret' {
            $plan = New-TenureOffboardPlan -User 'ALICE@example.com' -Policy $script:ExamplePolicyPath -KeepGroup 'sales@example.com', 'All Staff' -SkipDevices -Devices retireAll
            $plan.Inputs.User | Should -BeExactly 'alice@example.com'
            $plan.Inputs.Policy | Should -BeExactly $script:ExamplePolicyPath
            $plan.Inputs.KeepGroup | Should -Be @('All Staff', 'sales@example.com')
            $plan.Inputs.SkipDevices | Should -BeTrue
            $plan.Inputs.Devices | Should -BeExactly 'retireAll'
            $plan.Inputs.ContainsKey('SkipMailbox') | Should -BeFalse
            $plan.PolicyHash | Should -BeExactly $policy.Hash
            $plan.Status | Should -BeExactly 'Planned'
        }

        It 'reads the tenant and never writes: no Graph write, only Get cmdlets on Exchange, within the call budget' {
            $null = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $w.Calls.Count | Should -BeGreaterThan 0
            Get-Writes | Should -BeNullOrEmpty
            Get-ExchangeWrites | Should -BeNullOrEmpty
            $x.Calls.Count | Should -BeLessOrEqual 10 -Because 'SPEC 7: 8 Exchange calls plus 2 for the distribution list'
        }

        It 'survives an export and an import unchanged' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $path = Join-Path $TestDrive 'offboard.json'
            Export-TenurePlan -Plan $plan -Path $path
            $imported = Import-TenurePlan -Path $path
            @($imported.Steps | ForEach-Object { $_.Key }) | Should -Be (Get-Keys $plan)
            @($imported.Steps | ForEach-Object { $_.Fingerprint }) | Should -Be @($plan.Steps | ForEach-Object { $_.Fingerprint })
            @($imported.Steps | ForEach-Object { $_.Action }) | Should -Be @($plan.Steps | ForEach-Object { $_.Action })
        }

        It 'can be applied with -WhatIf without a change on either backend' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $audit = Join-Path $TestDrive 'whatif-audit.jsonl'
            $before = $w.Calls.Count
            $result = Invoke-TenurePlan -Plan $plan -Policy $policy -WhatIf -AuditPath $audit
            $result | Should -Not -BeNullOrEmpty
            $result.Summary.Failed | Should -Be 0
            $result.Summary.Refused | Should -Be 0
            $result.Summary.Drifted | Should -Be 0
            $plan.Steps | ForEach-Object { $_.Status } | Sort-Object -Unique | Should -Be @('Pending')
            Get-Writes | Should -BeNullOrEmpty
            Get-ExchangeWrites | Should -BeNullOrEmpty
            Test-Path -LiteralPath $audit | Should -BeFalse -Because '-WhatIf writes nothing'
            $w.Calls.Count | Should -BeGreaterThan $before -Because 'the engine re-read the state'
        }
    }

    Context 'refusing the wrong subject' {
        It 'refuses the signed-in account with Tenure.Plan.Refused and reads nothing else' {
            Set-TenureTestSession -Account 'carol@example.com'
            { New-TenureOffboardPlan -User 'carol@example.com' -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            { New-TenureOffboardPlan -User 'carol@example.com' -Policy $policy } | Should -Throw '*signed-in account*'
            { New-TenureOffboardPlan -User $ids.CarolId -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            @($w.Calls | Where-Object { $_.Uri -like '*memberOf*' -or $_.Uri -like '*managedDevices*' }).Count | Should -Be 0
            $x.Calls.Count | Should -Be 0
        }

        It 'matches the signed-in account without regard to case' {
            Set-TenureTestSession -Account 'CAROL@Example.com'
            { New-TenureOffboardPlan -User 'carol@example.com' -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
        }

        It 'refuses a user in protectedUsers' {
            $protected = New-TestPolicy -Edit { param($raw) $raw['defaults']['protectedUsers'] = @('ALICE@example.com') }
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $protected } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $protected } | Should -Throw '*protected by policy*'
            { New-TenureOffboardPlan -User 'bob@example.com' -Policy $protected } | Should -Not -Throw
        }

        It 'refuses a user that protectedUsers names by <Form>, not only by user principal name' -ForEach @(
            @{ Form = 'object id'; Entry = '10000000-0000-4000-8000-000000000001' }
            @{ Form = 'mail address'; Entry = 'ALICE.EXAMPLE@example.com' }
        ) {
            (Get-User $ids.AliceId)['mail'] = 'alice.example@example.com'
            $protected = New-TestPolicy -Edit ({ param($raw) $raw['defaults']['protectedUsers'] = @($Entry) }.GetNewClosure())
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $protected } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $protected } | Should -Throw '*protected by policy*'
            { New-TenureOffboardPlan -User 'bob@example.com' -Policy $protected } | Should -Not -Throw
        }

        It 'does not refuse a user for a near miss in protectedUsers' {
            (Get-User $ids.AliceId)['mail'] = 'alice.example@example.com'
            $nearMiss = New-TestPolicy -Edit { param($raw) $raw['defaults']['protectedUsers'] = @('alice', 'alice@example.org', 'alice.exampl@example.com', '10000000-0000-4000-8000-000000000011') }
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $nearMiss } | Should -Not -Throw
        }

        It 'fails with Tenure.User.NotFound for a user who does not exist' {
            { New-TenureOffboardPlan -User 'nobody@example.com' -Policy $policy } | Should -Throw -ErrorId 'Tenure.User.NotFound'
        }
    }

    Context 'a Global Administrator' {
        It 'warns, still plans the role removal, and finds no mailbox for a user who has none' {
            Set-GlobalAdmin -UserId $ids.CarolId
            $plan = New-TenureOffboardPlan -User 'carol@example.com' -Policy $policy
            (Get-Step $plan 'ga').Action | Should -BeExactly 'Check'
            @($plan.Warnings | Where-Object { $_ -like '*holds Global Administrator*' -and $_ -like '*break-glass*' }).Count | Should -Be 1
            $role = Get-Step $plan "role:$($ids.GlobalAdminRoleId)"
            $role.Provider | Should -BeExactly 'DirectoryRole.Member'
            $role.Target.Kind | Should -BeExactly 'role'
            $role.Target.Id | Should -BeExactly $ids.GlobalAdminRoleId
            $role.Target.Name | Should -BeExactly 'Global Administrator'
            $role.After.userId | Should -BeExactly $ids.CarolId
            $role.After.member | Should -BeFalse
            $role.Risk | Should -BeExactly 'High'
            $role.Action | Should -BeExactly 'Remove' -Because 'DirectoryRole.Member only removes'
            Get-Keys $plan | Should -Be @(Get-Keys $plan | Where-Object { $true }) # order is checked below
            $keys = Get-Keys $plan
            $keys.IndexOf('sessions') | Should -BeLessThan $keys.IndexOf("role:$($ids.GlobalAdminRoleId)")
        }

        It 'places the role steps after sessions and before the mailbox steps' {
            Set-GlobalAdmin -UserId $ids.AliceId
            $keys = Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy)
            $keys[0..5] | Should -Be @('subject', 'ga', 'signin', 'password', 'sessions', "role:$($ids.GlobalAdminRoleId)")
            $keys[6] | Should -BeExactly 'eligibility'
        }

        It 'does not warn for the other roles' {
            $plan = New-TenureOffboardPlan -User 'carol@example.com' -Policy $policy
            (Get-Step $plan 'ga').Action | Should -BeExactly 'NoOp'
            @($plan.Warnings | Where-Object { $_ -like '*Global Administrator*' }).Count | Should -Be 0
            Get-Keys $plan | Should -Contain "role:$($ids.GlobalAdminRoleId)" -Because 'every active role is removed'
        }
    }

    Context 'the mailbox' {
        It 'plans the mailbox steps when Exchange finds the mailbox, without reading the license details' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            foreach ($key in 'eligibility', 'mailboxType', 'forwarding', 'autoreply', 'delegate', 'hidden', 'calendar') { Get-Keys $plan | Should -Contain $key }
            @($plan.Warnings | Where-Object { $_ -like '*no mailbox*' }).Count | Should -Be 0
            Get-LicenseDetailReads | Should -BeNullOrEmpty
        }

        It 'omits every mailbox step with one warning when the user has no mailbox and no license with Exchange Online' {
            Remove-FakeMailbox -UserId $ids.AliceId -Upn 'alice@example.com'
            Set-NoExchangeLicense -UserId $ids.AliceId
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            @(Get-LicenseDetailReads).Count | Should -BeGreaterThan 0 -Because 'not found alone is no proof; the licenses are the evidence'
            $keys = Get-Keys $plan
            foreach ($key in 'eligibility', 'mailboxType', 'forwarding', 'autoreply', 'delegate', 'hidden', 'calendar') { $keys | Should -Not -Contain $key }
            @($plan.Warnings | Where-Object { $_ -like '*no mailbox*' }).Count | Should -Be 1
            $keys | Should -Contain 'onedrive'
            $keys | Should -Contain 'licenses'
            @((Get-Step $plan 'licenses').DependsOn).Count | Should -Be 0
            @($plan.Warnings | Where-Object { $_ -like '*30 days*' }).Count | Should -Be 0 -Because 'there is no mailbox to lose'
            Get-Keys $plan | Should -Contain "group:$($ids.LegalDlGroupId)" -Because 'a distribution list needs no mailbox'
        }

        It 'plans a delegate alone when it is the only mailbox step, and notices a missing mailbox then too' {
            $only = Edit-Offboard @{ convertMailboxToShared = $false; forwardTo = 'none'; hideFromAddressLists = $false; cancelMeetings = $false; autoReply = @{ enabled = $false; message = 'x' } }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $only
            $keys = Get-Keys $plan
            $keys | Should -Contain 'delegate'
            foreach ($key in 'eligibility', 'mailboxType', 'forwarding', 'autoreply', 'hidden', 'calendar') { $keys | Should -Not -Contain $key }
            Remove-FakeMailbox -UserId $ids.AliceId -Upn 'alice@example.com'
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $only } | Should -Throw -ErrorId 'Tenure.Plan.MailboxUnknown' -Because 'alice still holds SPE_E3, which includes Exchange Online'
            Set-NoExchangeLicense -UserId $ids.AliceId
            $missing = New-TenureOffboardPlan -User 'alice@example.com' -Policy $only
            Get-Keys $missing | Should -Not -Contain 'delegate'
            @($missing.Warnings | Where-Object { $_ -like '*no mailbox*' }).Count | Should -Be 1
        }

        It 'refuses with Tenure.Plan.MailboxUnknown when Exchange finds no mailbox but a license includes Exchange Online' {
            Remove-FakeMailbox -UserId $ids.AliceId -Upn 'alice@example.com'
            $failure = { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.MailboxUnknown' -PassThru
            $failure.Exception.Message | Should -Match 'alice@example\.com'
            $failure.Exception.Message | Should -Match 'SPE_E3 \(EXCHANGE_S_ENTERPRISE\)'
            $failure.Exception.Message | Should -Match '-SkipMailbox'
            Get-ExchangeWrites | Should -BeNullOrEmpty
            # Once the operator has confirmed there is no mailbox, -SkipMailbox plans without the mailbox steps.
            $skipped = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -SkipMailbox
            Get-Keys $skipped | Should -Not -Contain 'mailboxType'
            Get-Keys $skipped | Should -Contain 'licenses'
        }

        It 'counts a group-inherited license with Exchange Online as a possible mailbox' {
            Remove-FakeMailbox -UserId $ids.BobId -Upn 'bob@example.com'
            { New-TenureOffboardPlan -User 'bob@example.com' -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.MailboxUnknown' -Because 'bob holds SPE_E3 through All Staff'
        }

        It 'refuses when the license details cannot be read, instead of guessing there is no mailbox' {
            Remove-FakeMailbox -UserId $ids.AliceId -Upn 'alice@example.com'
            Set-NoExchangeLicense -UserId $ids.AliceId
            Add-FakeGraphFault -World $w -Status 403 -Code 'Authorization_RequestDenied' -Method GET -UriLike '*licenseDetails*'
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }

        It 'stops on an Exchange failure that is not a genuine not-found (<Label>) instead of leaving the mailbox steps out' -ForEach @(
            @{ Label = 'a busy server'; Message = 'The server is busy. Try again later.' }
            @{ Label = 'something else that could not be found'; Message = "The domain controller couldn't be found." }
        ) {
            Set-NoExchangeLicense -UserId $ids.AliceId
            Add-FakeExchangeFault -World $x -Command 'Get-EXOMailbox' -Message $Message
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy } | Should -Throw -ErrorId 'Tenure.Exchange.Failed'
            Get-LicenseDetailReads | Should -BeNullOrEmpty -Because 'a failed read is never taken for a missing mailbox'
        }

        It 'fails with Tenure.Plan.Invalid when the user to grant the mailbox to does not exist in Exchange' {
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -GrantMailboxTo 'ghost@example.com' } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -GrantMailboxTo 'ghost@example.com' } | Should -Throw '*ghost@example.com*'
        }

        It 'throws Tenure.Exchange.NotConnected, naming -SkipMailbox, before reading anything' {
            Set-TenureTestSession -Exchange $false
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy } | Should -Throw -ErrorId 'Tenure.Exchange.NotConnected'
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy } | Should -Throw '*-SkipMailbox*'
            $w.Calls.Count | Should -Be 0
        }

        It 'works without Exchange under -SkipMailbox, skipping the distribution list with a warning' {
            Set-TenureTestSession -Exchange $false
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -SkipMailbox
            $keys = Get-Keys $plan
            foreach ($key in 'eligibility', 'mailboxType', 'forwarding', 'autoreply', 'delegate', 'hidden', 'calendar') { $keys | Should -Not -Contain $key }
            $keys | Should -Not -Contain "group:$($ids.LegalDlGroupId)"
            @($plan.Warnings | Where-Object { $_ -like '*Legal DL*' -and $_ -like '*Exchange*' }).Count | Should -Be 1
            @((Get-Step $plan 'licenses').DependsOn).Count | Should -Be 0
            @($plan.Warnings | Where-Object { $_ -like '*30 days*' }).Count | Should -Be 1 -Because 'licenses go without a shared-mailbox conversion'
            $x.Calls.Count | Should -Be 0
            $plan.Inputs.SkipMailbox | Should -BeTrue
        }

        It 'keeps the distribution list under -SkipMailbox when Exchange is connected' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -SkipMailbox
            Get-Keys $plan | Should -Contain "group:$($ids.LegalDlGroupId)"
            @(Get-Keys $plan | Where-Object { $_ -in 'mailboxType', 'forwarding', 'delegate' }).Count | Should -Be 0
        }

        It 'warns when the mailbox is too big to become a shared mailbox without a license, and still plans the conversion' {
            Set-FakeExchangeMailboxSize -World $x -Identity 'alice@example.com' -Bytes 65712345678
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            (Get-Step $plan 'eligibility').Action | Should -BeExactly 'Check'
            @($plan.Warnings | Where-Object { $_ -like '*license*' -and $_ -like '*GB*' }).Count | Should -Be 1
            Get-Keys $plan | Should -Contain 'mailboxType'
        }
    }

    Context 'forwarding and grants' {
        It '-ForwardTo none leaves out the forwarding step' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -ForwardTo none
            Get-Keys $plan | Should -Not -Contain 'forwarding'
            Get-Keys $plan | Should -Contain 'delegate'
        }

        It '-ForwardTo with an address forwards there, and a parameter beats the policy' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -ForwardTo 'Mailroom@partner.example'
            (Get-Step $plan 'forwarding').After.forwardingSmtpAddress | Should -BeExactly 'Mailroom@partner.example'
            $off = Edit-Offboard @{ forwardTo = 'none' }
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off) | Should -Not -Contain 'forwarding'
            (Get-Step (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off -ForwardTo 'manager') 'forwarding').After.forwardingSmtpAddress | Should -BeExactly 'bob@example.com'
        }

        It 'follows deliverToMailboxAndForward from the policy' {
            $off = Edit-Offboard @{ deliverToMailboxAndForward = $false }
            (Get-Step (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off) 'forwarding').After.deliverToMailboxAndForward | Should -BeFalse
        }

        It 'refuses a forwarding value that is neither manager, none nor an address' {
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -ForwardTo 'not an address' } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -GrantOneDriveTo '' } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        }

        It 'uses an address given for the mailbox grant as it is, and grants OneDrive access separately' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -GrantMailboxTo 'reception@example.com' -GrantOneDriveTo 'Someone@partner.example'
            $delegate = Get-Step $plan 'delegate'
            $delegate.Target.Grantee | Should -BeExactly 'reception@example.com'
            $delegate.After.user | Should -BeExactly 'reception@example.com'
            (Get-Step $plan 'onedrive').After.granteeEmail | Should -BeExactly 'Someone@partner.example'
        }

        It '-GrantMailboxTo none and -GrantOneDriveTo none leave out both steps' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -GrantMailboxTo none -GrantOneDriveTo none
            Get-Keys $plan | Should -Not -Contain 'delegate'
            Get-Keys $plan | Should -Not -Contain 'onedrive'
            @(Get-BuilderWarning $plan).Count | Should -Be 2 -Because 'only the tablet and the {company} placeholder warn'
        }

        It 'leaves out forwarding, the mailbox grant and the OneDrive grant, each with a warning, when the user has no manager' {
            (Get-User $ids.AliceId)['managerId'] = $null
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            $keys = Get-Keys $plan
            foreach ($key in 'forwarding', 'delegate', 'onedrive') { $keys | Should -Not -Contain $key }
            foreach ($setting in 'forwardTo', 'grantMailboxTo', 'grantOneDriveTo') {
                @($plan.Warnings | Where-Object { $_ -like "*$setting*" -and $_ -like '*no manager*' }).Count | Should -Be 1 -Because $setting
            }
            $reply = (Get-Step $plan 'autoreply').After
            $reply.internalMessage | Should -BeExactly 'Alice Example has left {company}. Please contact  ().'
            @($plan.Warnings | Where-Object { $_ -like '*auto-reply*' -and $_ -like '*no manager*' }).Count | Should -Be 1
        }

        It 'falls back to the manager user principal name when the manager has no mail address' {
            (Get-User $ids.BobId)['mail'] = $null
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            (Get-Step $plan 'forwarding').After.forwardingSmtpAddress | Should -BeExactly 'bob@example.com'
            (Get-Step $plan 'autoreply').After.internalMessage | Should -Match '\(bob@example\.com\)'
        }
    }

    Context 'the auto-reply' {
        It '-AutoReplyMessage replaces the policy template and fills the placeholders' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -AutoReplyMessage '{displayName} is away; write to {managerMail} ({managerDisplayName}).'
            (Get-Step $plan 'autoreply').After.internalMessage | Should -BeExactly 'Alice Example is away; write to bob@example.com (Bob Manager).'
            @($plan.Warnings | Where-Object { $_ -like '*{company}*' }).Count | Should -Be 0
        }

        It 'plans no auto-reply when the policy turns it off, and -AutoReplyMessage turns it back on' {
            $off = Edit-Offboard @{ autoReply = @{ enabled = $false; message = 'x {displayName}' } }
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off) | Should -Not -Contain 'autoreply'
            $on = New-TenureOffboardPlan -User 'alice@example.com' -Policy $off -AutoReplyMessage 'Gone: {displayName}'
            (Get-Step $on 'autoreply').After.internalMessage | Should -BeExactly 'Gone: Alice Example'
        }

        It 'never expands a placeholder that came from a display name' {
            (Get-User $ids.AliceId)['displayName'] = 'Al {managerMail}'
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -AutoReplyMessage '{displayName} / {managerMail}'
            (Get-Step $plan 'autoreply').After.internalMessage | Should -BeExactly 'Al {managerMail} / bob@example.com'
        }
    }

    Context 'OneDrive' {
        It 'omits the step with a warning when the OneDrive was never provisioned' {
            $null = $w.Drives.Remove($ids.AliceId)
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            Get-Keys $plan | Should -Not -Contain 'onedrive'
            @($plan.Warnings | Where-Object { $_ -like '*OneDrive not provisioned*' }).Count | Should -Be 1
            Get-Keys $plan | Should -Contain 'calendar'
        }
    }

    Context 'groups' {
        It 'keeps the groups named in the policy and in -KeepGroup, by name, mail address or id' {
            $off = Edit-Offboard @{ keepGroups = @('All Staff') }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $off -KeepGroup 'sales@example.com', $ids.LegalDlGroupId
            (Get-Keys $plan | Where-Object { $_ -like 'group:*' }) | Should -Be @("group:$($ids.DynamicGroupId)")
            @(Get-BuilderWarning $plan).Count | Should -Be 2
        }

        It 'warns about a keep entry that matches no group, and ignores it' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -KeepGroup 'No Such Group'
            @($plan.Warnings | Where-Object { $_ -like '*No Such Group*' }).Count | Should -Be 1
            @($plan.Steps | Where-Object { $_.Key -like 'group:*' }).Count | Should -Be 4
        }

        It 'propagates an ambiguous keep entry' {
            $w.Groups.Add(@{ id = '20000000-0000-4000-8000-0000000000ff'; displayName = 'Sales'; mail = 'sales2@example.com'; mailNickname = 'sales2'; mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null; members = [string[]]@(); owners = [string[]]@() })
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -KeepGroup 'Sales' } | Should -Throw -ErrorId 'Tenure.Group.Ambiguous'
        }

        It 'plans no group steps when the policy does not remove groups' {
            $off = Edit-Offboard @{ removeFromGroups = $false }
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off) | Where-Object { $_ -like 'group:*' } | Should -BeNullOrEmpty
        }

        It 'warns, naming the group, when the user is its only owner' {
            (Get-FakeGroup $ids.SalesGroupId)['owners'] = [string[]]@($ids.AliceId)
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            @($plan.Warnings | Where-Object { $_ -like "*'Sales'*" -and $_ -like '*only owner*' }).Count | Should -Be 1
            Get-Keys $plan | Should -Contain "group:$($ids.SalesGroupId)" -Because 'the removal is still planned'
        }

        It 'does not warn when the user shares ownership, or owns a group that is kept' {
            (Get-FakeGroup $ids.SalesGroupId)['owners'] = [string[]]@($ids.AliceId, $ids.BobId)
            @((New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy).Warnings | Where-Object { $_ -like '*only owner*' }).Count | Should -Be 0
            (Get-FakeGroup $ids.SalesGroupId)['owners'] = [string[]]@($ids.AliceId)
            @((New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -KeepGroup 'Sales').Warnings | Where-Object { $_ -like '*only owner*' }).Count | Should -Be 0
        }
    }

    Context 'licenses' {
        It '-SkipLicenseRemoval and removeLicenses false both leave the step out' {
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -SkipLicenseRemoval) | Should -Not -Contain 'licenses'
            $off = Edit-Offboard @{ removeLicenses = $false }
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off) | Should -Not -Contain 'licenses'
        }

        It 'X1: a removal from a group that carries a license runs after the mailbox conversion and says the group carries a license' {
            # alice holds SPE_E3 (with Exchange Online) only through All Staff.
            $alice = Get-User $ids.AliceId
            $alice['licenseAssignmentStates'] = [System.Collections.Generic.List[hashtable]]::new()
            $alice['licenseAssignmentStates'].Add(@{ skuId = $ids.SkuE3Id; assignedByGroup = $ids.AllStaffGroupId; state = 'Active'; error = 'None' })
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none
            $mailboxType = Get-Step $plan 'mailboxType'
            $allStaff = Get-Step $plan "group:$($ids.AllStaffGroupId)"
            @($allStaff.DependsOn) | Should -Be @($mailboxType.Id)
            $allStaff.Reason | Should -Match "group 'All Staff'. The group carries a license \(SPE_E3\)"
            $allStaff.Reason | Should -Match 'after the mailbox is converted to shared'
            (Get-Step $plan "group:$($ids.SalesGroupId)").DependsOn | Should -BeNullOrEmpty -Because 'Sales carries no license'
            $licenses = Get-Step $plan 'licenses'
            $licenses.Reason | Should -Match 'not touched by this step'
            $licenses.Reason | Should -Match 'These go when this plan removes the user from the group: SPE_E3 via All Staff'
            $licenses.Reason | Should -Not -Match 'stay' -Because 'nothing the user inherits stays once the group removal runs'
        }

        It 'treats a group as license-carrying from its own assignedLicenses, even when the user''s license states do not name it' {
            (Get-FakeGroup $ids.SalesGroupId)['assignedLicenses'] = @(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() })
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none
            $sales = Get-Step $plan "group:$($ids.SalesGroupId)"
            @($sales.DependsOn) | Should -Be @((Get-Step $plan 'mailboxType').Id)
            $sales.Reason | Should -Match 'carries a license \(MCOEV\)'
        }

        It 'X1b: with license removal off, a group that carries a license is left out with a warning, and so is its license' {
            $alice = Get-User $ids.AliceId
            $alice['licenseAssignmentStates'] = [System.Collections.Generic.List[hashtable]]::new()
            $alice['licenseAssignmentStates'].Add(@{ skuId = $ids.SkuE3Id; assignedByGroup = $ids.AllStaffGroupId; state = 'Active'; error = 'None' })
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox -SkipLicenseRemoval
            Get-Keys $plan | Should -Not -Contain "group:$($ids.AllStaffGroupId)"
            Get-Keys $plan | Should -Not -Contain 'licenses'
            Get-Keys $plan | Should -Contain "group:$($ids.SalesGroupId)" -Because 'a group without a license is still removed'
            @($plan.Warnings | Where-Object { $_ -like "*'All Staff' carries a license (SPE_E3)*" -and $_ -like '*stays in the group*' }).Count | Should -Be 1
            $off = Edit-Offboard @{ removeLicenses = $false }
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off -Devices none) | Should -Not -Contain "group:$($ids.AllStaffGroupId)" -Because 'removeLicenses false is the same as -SkipLicenseRemoval'
        }

        It 'E: without the mailbox conversion, the license step and license-carrying group removals are Destructive, with a warning' {
            $alice = Get-User $ids.AliceId
            $alice['licenseAssignmentStates'].Add(@{ skuId = $ids.SkuVoiceId; assignedByGroup = $ids.AllStaffGroupId; state = 'Active'; error = 'None' })
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox
            (Get-Step $plan 'licenses').Risk | Should -BeExactly 'Destructive'
            (Get-Step $plan 'licenses').Reason | Should -Match 'deletes the mailbox after about 30 days'
            (Get-Step $plan "group:$($ids.AllStaffGroupId)").Risk | Should -BeExactly 'Destructive'
            (Get-Step $plan "group:$($ids.SalesGroupId)").Risk | Should -BeExactly 'Medium' -Because 'a group without a license deletes nothing'
            @($plan.Warnings | Where-Object { $_ -like '*does not convert the mailbox*' -and $_ -like '*Destructive*' }).Count | Should -Be 1
            $off = Edit-Offboard @{ convertMailboxToShared = $false }
            (Get-Step (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off -Devices none) 'licenses').Risk | Should -BeExactly 'Destructive'
        }

        It 'E: keeps the license step High when the conversion is planned, or when no license grants a mailbox' {
            (Get-Step (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none) 'licenses').Risk | Should -BeExactly 'High'
            Set-NoExchangeLicense $ids.AliceId
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none -SkipMailbox
            (Get-Step $plan 'licenses').Risk | Should -BeExactly 'High'
            @($plan.Warnings | Where-Object { $_ -like '*does not convert the mailbox*' }).Count | Should -Be 0
        }

        It 'is a NoOp that still names the inherited licenses for a user with none assigned directly' {
            $plan = New-TenureOffboardPlan -User 'bob@example.com' -Policy $policy
            $licenses = Get-Step $plan 'licenses'
            $licenses.Action | Should -BeExactly 'NoOp'
            $licenses.Reason | Should -Match 'nothing to remove'
            $licenses.Reason | Should -Match 'SPE_E3 via All Staff'
        }

        It 'does not depend on the mailbox conversion when the policy does not convert, and warns about the mailbox' {
            $off = Edit-Offboard @{ convertMailboxToShared = $false }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $off
            @((Get-Step $plan 'licenses').DependsOn).Count | Should -Be 0
            Get-Keys $plan | Should -Not -Contain 'mailboxType'
            Get-Keys $plan | Should -Not -Contain 'eligibility'
            @($plan.Warnings | Where-Object { $_ -like '*shared mailbox*' -and $_ -like '*30 days*' }).Count | Should -Be 1
        }
    }

    Context 'devices' {
        It '-Devices none and -SkipDevices plan no device steps' {
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices none) | Where-Object { $_ -like 'device:*' } | Should -BeNullOrEmpty
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -SkipDevices) | Where-Object { $_ -like 'device:*' } | Should -BeNullOrEmpty
            $off = Edit-Offboard @{ devices = 'none' }
            Get-Keys (New-TenureOffboardPlan -User 'alice@example.com' -Policy $off) | Where-Object { $_ -like 'device:*' } | Should -BeNullOrEmpty
            @($w.Calls | Where-Object { $_.Uri -like '*managedDevices*' }).Count | Should -Be 0 -Because 'devices are not even listed'
        }

        It '-Devices retireAll retires every device, the company laptop included, and warns about none' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -Devices retireAll
            @($plan.Steps | Where-Object { $_.Key -like 'device:*' } | ForEach-Object { $_.Provider }) | Should -Be @('Device.Retire', 'Device.Retire', 'Device.Retire')
            @($plan.Warnings | Where-Object { $_ -like '*ALICE-TABLET*' }).Count | Should -Be 0
        }

        It 'takes the mode from the policy and lets -Devices override it, whatever the case' {
            $retire = Edit-Offboard @{ devices = 'retireAll' }
            (Get-Step (New-TenureOffboardPlan -User 'alice@example.com' -Policy $retire) "device:$($ids.CompanyDeviceId)").Provider | Should -BeExactly 'Device.Retire'
            (Get-Step (New-TenureOffboardPlan -User 'alice@example.com' -Policy $retire -Devices WipeCorporateRetirePersonal) "device:$($ids.CompanyDeviceId)").Provider | Should -BeExactly 'Device.Wipe'
        }

        It 'retires, never wipes, a device of unknown ownership, and says so' {
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy
            (Get-Step $plan "device:$($ids.UnknownDeviceId)").Provider | Should -BeExactly 'Device.Retire'
            @($plan.Warnings | Where-Object { $_ -like '*unknown ownership*' }).Count | Should -Be 1
        }

        It 'plans nothing and warns about nothing for a user without devices' {
            $plan = New-TenureOffboardPlan -User 'bob@example.com' -Policy $policy
            Get-Keys $plan | Where-Object { $_ -like 'device:*' } | Should -BeNullOrEmpty
            @($plan.Warnings | Where-Object { $_ -like '*device*' }).Count | Should -Be 0
        }
    }

    Context 'policy switches and the leave date' {
        It 'leaves out every step its policy switch turns off' {
            $quiet = Edit-Offboard @{
                resetPassword = $false; revokeSessions = $false; removeDirectoryRoles = $false; convertMailboxToShared = $false
                hideFromAddressLists = $false; cancelMeetings = $false; removeFromGroups = $false; removeLicenses = $false
                forwardTo = 'none'; grantMailboxTo = 'none'; grantOneDriveTo = 'none'; devices = 'none'; autoReply = @{ enabled = $false; message = 'x' }
            }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $quiet
            Get-Keys $plan | Should -Be @('subject', 'ga', 'signin')
        }

        It 'sets the leave date last when the policy asks for it' {
            $off = Edit-Offboard @{ setEmployeeLeaveDate = $true }
            $plan = New-TenureOffboardPlan -User 'alice@example.com' -Policy $off
            (Get-Keys $plan)[-1] | Should -BeExactly 'leave'
            $leave = Get-Step $plan 'leave'
            $leave.Provider | Should -BeExactly 'User.LeaveDate'
            $leave.Action | Should -BeExactly 'Update'
            ([datetime]$leave.After.employeeLeaveDateTime).ToUniversalTime() | Should -BeGreaterThan ([datetime]::UtcNow.AddMinutes(-5))
            ([datetime]$leave.After.employeeLeaveDateTime).ToUniversalTime() | Should -BeLessOrEqual ([datetime]::UtcNow.AddMinutes(1))
        }

        It 'refuses a policy argument that is neither a path nor a policy' {
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy $null } | Should -Throw
            { New-TenureOffboardPlan -User 'alice@example.com' -Policy 42 } | Should -Throw -ErrorId 'Tenure.Policy.Invalid'
        }

        It 'accepts the policy as a path' {
            (New-TenureOffboardPlan -User 'alice@example.com' -Policy $script:ExamplePolicyPath).PolicyHash | Should -BeExactly $policy.Hash
        }
    }
}
