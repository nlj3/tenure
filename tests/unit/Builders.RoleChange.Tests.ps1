# New-TenureRoleChangePlan against FakeGraph and FakeExchange.
# alice (direct SPE_E3, EXCHANGESTANDARD through the unmanaged group Mail Users; member of Sales, All Staff,
# Everyone Dynamic, Legal DL; manager bob) changes role.

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

    function New-TestPolicy([hashtable]$Roles, [scriptblock]$Edit) {
        $raw = Get-Content -LiteralPath $script:ExamplePolicyPath -Raw | ConvertFrom-Json -AsHashtable
        if ($Roles) { $raw['roles'] = $Roles }
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
    function Add-FakeGroup([string]$Id, [string]$Name, [string[]]$Types = @(), [bool]$MailEnabled = $false, [string[]]$Members = @()) {
        $global:FakeGraphWorld.Groups.Add(@{
                id = $Id; displayName = $Name; mail = $(if ($MailEnabled) { ($Name -replace '\s', '').ToLowerInvariant() + '@example.com' } else { $null }); mailNickname = ($Name -replace '\s', '').ToLowerInvariant()
                mailEnabled = $MailEnabled; securityEnabled = (-not $MailEnabled); groupTypes = [string[]]$Types; membershipRule = $null
                members = [string[]]$Members; owners = [string[]]@()
            })
    }
    function Remove-FromFakeGroup([string]$GroupId, [string]$UserId) {
        $group = $global:FakeGraphWorld.Groups | Where-Object { $_['id'] -eq $GroupId } | Select-Object -First 1
        $group['members'] = [string[]]@(@($group['members']) | Where-Object { $_ -ne $UserId })
    }

    $script:SupportGroupId = '20000000-0000-4000-8000-000000000005'
    $script:MailUsersGroupId = '20000000-0000-4000-8000-000000000006'
    $script:StandardSkuId = '30000000-0000-4000-8000-000000000009'
    $script:BaseRoles = {
        @{
            sales   = @{ licenses = @('SPE_E3'); groups = @('sales@example.com', 'All Staff'); department = 'Sales' }
            support = @{ licenses = @('MCOEV'); groups = @('All Staff', 'Support'); department = 'Support'; jobTitle = 'Agent' }
        }
    }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeExchangeWorld -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'New-TenureRoleChangePlan' {
    BeforeEach {
        Reset-FakeGraphWorld
        Reset-FakeExchangeWorld
        Set-TenureTestSession
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        Add-FakeGroup -Id $script:SupportGroupId -Name 'Support' -Types 'Unified' -MailEnabled $true
        # bob's SPE_E3 comes through All Staff (his license states say so); the group carries it too.
        ($w.Groups | Where-Object { $_['id'] -eq $ids.AllStaffGroupId })['assignedLicenses'] = @(@{ skuId = $ids.SkuE3Id; disabledPlans = @() })
        # alice also holds EXCHANGESTANDARD (a SKU no role names) through Mail Users (a group no role names), so her
        # mailbox stays licensed whatever role she moves to. The tests of the mailbox rule take it away again.
        $w.SubscribedSkus.Add(@{ skuId = $script:StandardSkuId; skuPartNumber = 'EXCHANGESTANDARD'; prepaidUnits = @{ enabled = 5 }; consumedUnits = 1
                servicePlans = @(@{ servicePlanId = '31000000-0000-4000-8000-000000000009'; servicePlanName = 'EXCHANGE_S_STANDARD'; appliesTo = 'User' })
            })
        Add-FakeGroup -Id $script:MailUsersGroupId -Name 'Mail Users' -Members $ids.AliceId
        ($w.Groups | Where-Object { $_['id'] -eq $script:MailUsersGroupId })['assignedLicenses'] = @(@{ skuId = $script:StandardSkuId; disabledPlans = @() })
        $alice = $w.Users | Where-Object { $_['id'] -eq $ids.AliceId }
        $alice['assignedLicenses'].Add(@{ skuId = $script:StandardSkuId; disabledPlans = @() })
        $alice['licenseAssignmentStates'].Add(@{ skuId = $script:StandardSkuId; assignedByGroup = $script:MailUsersGroupId; state = 'Active'; error = 'None' })
        $script:policy = New-TestPolicy -Roles (& $script:BaseRoles)
    }

    Context 'moving from sales to support' {
        It 'plans the difference in the order licenses, adds, removes, attributes' {
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy
            $plan.PSObject.TypeNames | Should -Contain 'Tenure.Plan'
            $plan.Operation | Should -BeExactly 'RoleChange'
            Get-Keys $plan | Should -Be @('licenses', "group:$SupportGroupId", "group:$($ids.SalesGroupId)", 'attributes')
            @($plan.Steps | ForEach-Object { $_.Id }) | Should -Be @('S01', 'S02', 'S03', 'S04')
            @($plan.Steps | ForEach-Object { $_.Provider }) | Should -Be @('User.Licenses', 'Group.Member', 'Group.Member', 'User.Attributes')
            foreach ($step in $plan.Steps) {
                @($step.DependsOn).Count | Should -Be 0
                $step.Fingerprint | Should -Match '^[0-9a-f]{64}$' -Because 'every step of an existing user carries a snapshot'
                $step.Action | Should -BeExactly 'Update'
            }
            Get-Writes | Should -BeNullOrEmpty
            Get-ExchangeWrites | Should -BeNullOrEmpty
        }

        It 'replaces the managed license the new role does not list with the one it does' {
            $licenses = Get-Step (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy) 'licenses'
            $licenses.Before.skuIds | Should -Be @($ids.SkuE3Id)
            $licenses.After.add | Should -Be @($ids.SkuVoiceId)
            $licenses.After.remove | Should -Be @($ids.SkuE3Id)
            $licenses.Target.Id | Should -BeExactly $ids.AliceId
        }

        It 'adds the new group with the subject id and removes the managed group the role dropped' {
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy
            $add = Get-Step $plan "group:$SupportGroupId"
            $add.After.userId | Should -BeExactly $ids.AliceId
            $add.After.member | Should -BeTrue
            $add.Target.Kind | Should -BeExactly 'group'
            $add.Target.Name | Should -BeExactly 'Support'
            $remove = Get-Step $plan "group:$($ids.SalesGroupId)"
            $remove.After.userId | Should -BeExactly $ids.AliceId
            $remove.After.member | Should -BeFalse
            $remove.Target.Name | Should -BeExactly 'Sales'
        }

        It 'never touches a group the policy does not manage, or one that both roles share' {
            $global:FakeGraphWorld.Groups.Add(@{
                    id = '20000000-0000-4000-8000-0000000000aa'; displayName = 'Book Club'; mail = $null; mailNickname = 'bookclub'
                    mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
                    members = [string[]]@($ids.AliceId); owners = [string[]]@()
                })
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy
            Get-Keys $plan | Should -Not -Contain "group:20000000-0000-4000-8000-0000000000aa"
            Get-Keys $plan | Should -Not -Contain "group:$($ids.DynamicGroupId)"
            Get-Keys $plan | Should -Not -Contain "group:$($ids.LegalDlGroupId)"
            Get-Keys $plan | Should -Not -Contain "group:$($ids.AllStaffGroupId)" -Because 'the new role keeps it and alice is in it already'
        }

        It 'sets the department and job title of the new role' {
            $attributes = Get-Step (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy) 'attributes'
            $attributes.After.department | Should -BeExactly 'Support'
            $attributes.After.jobTitle | Should -BeExactly 'Agent'
            @($attributes.After.Keys).Count | Should -Be 2
        }

        It 'accepts the user as an object id and records the user principal name in the inputs' {
            $plan = New-TenureRoleChangePlan -User $ids.AliceId -Role support -Policy $policy
            $plan.Subject.Id | Should -BeExactly $ids.AliceId
            $plan.Subject.UserPrincipalName | Should -BeExactly 'alice@example.com'
            $plan.Subject.DisplayName | Should -BeExactly 'Alice Example'
            $plan.Inputs.User | Should -BeExactly 'alice@example.com'
            $plan.Inputs.Role | Should -BeExactly 'support'
            $plan.PolicyHash | Should -BeExactly $policy.Hash
        }
    }

    Context 'what is kept' {
        It 'keeps a group named by display name, mail address or id' -ForEach @(
            @{ Keep = 'Sales' }
            @{ Keep = 'sales@example.com' }
            @{ Keep = '20000000-0000-4000-8000-000000000001' }
        ) {
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -KeepGroup $Keep
            Get-Keys $plan | Should -Be @('licenses', "group:$SupportGroupId", 'attributes')
            @(Get-BuilderWarning $plan).Count | Should -Be 0
        }

        It 'warns about a keep entry that matches no group and still plans the rest' {
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -KeepGroup 'No Such Group'
            @($plan.Warnings | Where-Object { $_ -like "*No Such Group*" }).Count | Should -Be 1
            Get-Keys $plan | Should -Contain "group:$($ids.SalesGroupId)"
        }

        It 'does not remove a keep group from a dynamic or distribution list either' {
            $own = New-TestPolicy -Roles @{
                sales   = @{ licenses = @('SPE_E3'); groups = @('Sales', 'Everyone Dynamic', 'Legal DL') }
                support = @{ licenses = @('MCOEV'); groups = @('All Staff') }
            }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $own -KeepGroup 'Legal DL', 'Sales'
            Get-Keys $plan | Should -Be @('licenses', "group:$($ids.DynamicGroupId)")
        }

        It '-FromRole limits removal to the items of that role' {
            $own = New-TestPolicy -Roles @{
                sales   = @{ licenses = @('SPE_E3'); groups = @('sales@example.com', 'All Staff') }
                support = @{ licenses = @('MCOEV'); groups = @('All Staff', 'Support') }
                trial   = @{ licenses = @(); groups = @('Legal DL') }
            }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -FromRole trial -Policy $own
            Get-Keys $plan | Should -Be @('licenses', "group:$SupportGroupId", "group:$($ids.LegalDlGroupId)")
            (Get-Step $plan 'licenses').After.add | Should -Be @($ids.SkuVoiceId)
            @((Get-Step $plan 'licenses').After.remove).Count | Should -Be 0 -Because 'trial has no licenses, so SPE_E3 stays'
            $legal = Get-Step $plan "group:$($ids.LegalDlGroupId)"
            $legal.After.member | Should -BeFalse
            # Without -FromRole the managed set decides: Sales goes too, and so does Legal DL.
            $wide = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $own
            Get-Keys $wide | Should -Contain "group:$($ids.SalesGroupId)"
        }

        It '-FromRole removes that role''s licenses and leaves other managed ones alone' {
            $own = New-TestPolicy -Roles @{
                sales   = @{ licenses = @('SPE_E3'); groups = @('Sales') }
                support = @{ licenses = @('MCOEV'); groups = @('Support') }
                voice   = @{ licenses = @('MCOEV', 'EXCHANGEDESKLESS'); groups = @() }
            }
            # alice holds SPE_E3 only; moving to support from voice must not remove SPE_E3 (not voice's) and adds MCOEV.
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -FromRole voice -Policy $own
            (Get-Step $plan 'licenses').After.add | Should -Be @($ids.SkuVoiceId)
            @((Get-Step $plan 'licenses').After.remove).Count | Should -Be 0 -Because 'SPE_E3 is not a voice license, and alice does not hold the desk license'
            # From sales it does remove SPE_E3.
            $fromSales = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -FromRole sales -Policy $own
            (Get-Step $fromSales 'licenses').After.add | Should -Be @($ids.SkuVoiceId)
            (Get-Step $fromSales 'licenses').After.remove | Should -Be @($ids.SkuE3Id)
        }

        It 'keeps a direct license the policy does not manage' {
            $alice = $script:w.Users | Where-Object { $_['id'] -eq $ids.AliceId }
            $alice['assignedLicenses'].Add(@{ skuId = $ids.SkuDeskId; disabledPlans = @() })
            $alice['licenseAssignmentStates'].Add(@{ skuId = $ids.SkuDeskId; assignedByGroup = $null; state = 'Active'; error = 'None' })
            $licenses = Get-Step (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy) 'licenses'
            $licenses.Before.skuIds | Should -Be @($ids.SkuE3Id, $ids.SkuDeskId)
            $licenses.After.add | Should -Be @($ids.SkuVoiceId)
            $licenses.After.remove | Should -Be @($ids.SkuE3Id) -Because 'SPE_E3 is managed and the new role drops it; the desk license is not managed'
        }

        It 'leaves a license that comes from a group alone and says so' {
            $plan = New-TenureRoleChangePlan -User 'bob@example.com' -Role support -Policy $policy
            $licenses = Get-Step $plan 'licenses'
            $licenses.Before.skuIds.Count | Should -Be 0
            @($licenses.Before.PSObject.Properties.Name) | Should -Be @('skuIds') -Because 'the snapshot holds the direct licenses only'
            $licenses.After.add | Should -Be @($ids.SkuVoiceId)
            $licenses.After.remove | Should -Be @($ids.SkuE3Id) -Because 'bob holds SPE_E3 through a group; the provider keeps it and the reason says so'
            $licenses.Reason | Should -Match "group-inherited through 'All Staff'"
        }
    }

    Context 'nothing to change' {
        It 'makes every step a NoOp when the user already fits the role' {
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role sales -Policy $policy
            Get-Keys $plan | Should -Be @('licenses', 'attributes')
            foreach ($step in $plan.Steps) { $step.Action | Should -BeExactly 'NoOp' }
        }

        It 'plans a licenses step even for a role without licenses' {
            $own = New-TestPolicy -Roles @{ bare = @{ groups = @('All Staff') } }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role bare -Policy $own
            Get-Keys $plan | Should -Be @('licenses')
            (Get-Step $plan 'licenses').Action | Should -BeExactly 'NoOp' -Because 'nothing in the policy manages SPE_E3 here'
            @((Get-Step $plan 'licenses').After.add).Count | Should -Be 0
            @((Get-Step $plan 'licenses').After.remove).Count | Should -Be 0 -Because 'nothing in the policy manages SPE_E3 here, so it is not removed'
        }
    }

    Context 'attributes and manager' {
        It 'has no attributes step when neither the role nor a parameter gives a value' {
            $own = New-TestPolicy -Roles @{ bare = @{ groups = @('All Staff') } }
            Get-Keys (New-TenureRoleChangePlan -User 'alice@example.com' -Role bare -Policy $own) | Should -Not -Contain 'attributes'
        }

        It 'sets only the attribute that has a value, and lets parameters beat the role' {
            $own = New-TestPolicy -Roles @{ bare = @{ groups = @('All Staff') } }
            $titleOnly = Get-Step (New-TenureRoleChangePlan -User 'alice@example.com' -Role bare -Policy $own -JobTitle 'Lead') 'attributes'
            @($titleOnly.After.Keys) | Should -Be @('jobTitle')
            $titleOnly.After.jobTitle | Should -BeExactly 'Lead'
            $override = Get-Step (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Department 'Escalations' -JobTitle 'Lead') 'attributes'
            $override.After.department | Should -BeExactly 'Escalations'
            $override.After.jobTitle | Should -BeExactly 'Lead'
        }

        It 'has no manager step without a manager parameter or role manager' {
            Get-Keys (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy) | Should -Not -Contain 'manager'
        }

        It 'resolves the manager to an id: NoOp for the current manager, an Update for a new one' {
            $same = Get-Step (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager 'bob@example.com') 'manager'
            $same.Action | Should -BeExactly 'NoOp'
            $same.After.managerId | Should -BeExactly $ids.BobId
            $new = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager 'carol@example.com'
            (Get-Step $new 'manager').Action | Should -BeExactly 'Update'
            (Get-Step $new 'manager').After.managerId | Should -BeExactly $ids.CarolId
            (Get-Step $new 'manager').Before.managerId | Should -BeExactly $ids.BobId
            $new.Inputs.Manager | Should -BeExactly 'carol@example.com'
        }

        It 'takes the manager from the role, and puts the manager step last' {
            $own = New-TestPolicy -Roles @{
                sales   = @{ licenses = @('SPE_E3'); groups = @('Sales') }
                support = @{ licenses = @('MCOEV'); groups = @('Support'); manager = 'carol@example.com'; department = 'Support' }
            }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $own
            Get-Keys $plan | Should -Be @('licenses', "group:$SupportGroupId", "group:$($ids.SalesGroupId)", 'attributes', 'manager')
            (Get-Step $plan 'manager').After.managerId | Should -BeExactly $ids.CarolId
        }

        It 'refuses to make a user their own manager' {
            { New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager 'alice@example.com' } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        }
    }

    Context 'dynamic groups and distribution lists' {
        It 'turns the removal from a dynamic group into a NoOp that says why' {
            $own = New-TestPolicy -Roles @{
                sales   = @{ licenses = @('SPE_E3'); groups = @('Everyone Dynamic') }
                support = @{ licenses = @('MCOEV'); groups = @('All Staff') }
            }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $own
            $step = Get-Step $plan "group:$($ids.DynamicGroupId)"
            $step.Action | Should -BeExactly 'NoOp'
            $step.Provider | Should -BeExactly 'Group.Member'
            $step.Reason | Should -Match 'dynamic membership'
        }

        It 'skips an add to a dynamic group and warns' {
            Remove-FromFakeGroup -GroupId $ids.DynamicGroupId -UserId $ids.AliceId
            $own = New-TestPolicy -Roles @{ sales = @{ licenses = @('SPE_E3'); groups = @('Sales') }; dyn = @{ licenses = @('SPE_E3'); groups = @('Everyone Dynamic') } }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role dyn -Policy $own
            Get-Keys $plan | Should -Not -Contain "group:$($ids.DynamicGroupId)"
            @($plan.Warnings | Where-Object { $_ -like '*Everyone Dynamic*' -and $_ -like '*dynamic membership, cannot add*' }).Count | Should -Be 1
        }

        It 'routes a distribution list through Exchange, for adds and for removes' {
            $global:FakeExchangeWorld.DistributionGroups[$ids.LegalDlGroupId].Members.Clear()
            Remove-FromFakeGroup -GroupId $ids.LegalDlGroupId -UserId $ids.AliceId
            $own = New-TestPolicy -Roles @{
                sales   = @{ licenses = @('SPE_E3'); groups = @('Sales') }
                legal   = @{ licenses = @('SPE_E3'); groups = @('Legal DL') }
            }
            $toLegal = New-TenureRoleChangePlan -User 'alice@example.com' -Role legal -Policy $own
            $add = Get-Step $toLegal "group:$($ids.LegalDlGroupId)"
            $add.Provider | Should -BeExactly 'DistributionGroup.Member'
            $add.Action | Should -BeExactly 'Update'
            $add.After.userId | Should -BeExactly $ids.AliceId
            $add.Before.member | Should -BeFalse

            Reset-FakeGraphWorld
            Reset-FakeExchangeWorld
            $back = New-TenureRoleChangePlan -User 'alice@example.com' -Role sales -Policy $own
            $remove = Get-Step $back "group:$($ids.LegalDlGroupId)"
            $remove.Provider | Should -BeExactly 'DistributionGroup.Member'
            $remove.After.member | Should -BeFalse
            $remove.Before.member | Should -BeTrue
            Get-ExchangeWrites | Should -BeNullOrEmpty
        }

        It 'skips a distribution list and warns when Exchange is not connected' {
            Set-TenureTestSession -Exchange $false
            $own = New-TestPolicy -Roles @{
                sales = @{ licenses = @('SPE_E3'); groups = @('Sales') }
                legal = @{ licenses = @('SPE_E3'); groups = @('Legal DL') }
            }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role sales -Policy $own
            Get-Keys $plan | Should -Not -Contain "group:$($ids.LegalDlGroupId)"
            @($plan.Warnings | Where-Object { $_ -like '*Legal DL*' -and $_ -like '*Exchange*' }).Count | Should -Be 1
            $global:FakeExchangeWorld.Calls.Count | Should -Be 0
        }
    }

    Context 'warnings' {
        It 'warns, instead of failing, when a managed name matches nothing in the tenant' {
            $example = Get-TenurePolicy -Path $script:ExamplePolicyPath
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role sales -Policy $example
            @($plan.Warnings | Where-Object { $_ -like "*Warehouse Users*" }).Count | Should -Be 1
            Get-Keys $plan | Should -Be @('licenses', 'attributes')
        }

        It 'fails for a group of the new role that matches nothing' {
            $own = New-TestPolicy -Roles @{ r = @{ groups = @('No Such Group') } }
            { New-TenureRoleChangePlan -User 'alice@example.com' -Role r -Policy $own } | Should -Throw -ErrorId 'Tenure.Group.NotFound'
        }

        It 'propagates an ambiguous managed group name instead of guessing' {
            Add-FakeGroup -Id '20000000-0000-4000-8000-0000000000ff' -Name 'Sales'
            $own = New-TestPolicy -Roles @{ sales = @{ groups = @('Sales') }; support = @{ groups = @('All Staff') } }
            { New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $own } | Should -Throw -ErrorId 'Tenure.Group.Ambiguous'
        }

        It 'warns when a new license has no available units' {
            $own = New-TestPolicy -Roles @{ sales = @{ licenses = @('SPE_E3') }; desk = @{ licenses = @('EXCHANGEDESKLESS') } }
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role desk -Policy $own
            @($plan.Warnings | Where-Object { $_ -like '*EXCHANGEDESKLESS*' -and $_ -like '*no available*' }).Count | Should -Be 1
        }

        It 'does not warn about a license the user already holds' {
            @(Get-BuilderWarning (New-TenureRoleChangePlan -User 'alice@example.com' -Role sales -Policy $policy)).Count | Should -Be 0
        }

        It 'warns when licenses would be added to a user without a usage location' {
            ($script:w.Users | Where-Object { $_['id'] -eq $ids.AliceId })['usageLocation'] = $null
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy
            @($plan.Warnings | Where-Object { $_ -like '*usage location*' }).Count | Should -Be 1
        }
    }

    Context 'errors' {
        It 'fails with Tenure.Policy.RoleNotFound for an unknown role or from-role' {
            { New-TenureRoleChangePlan -User 'alice@example.com' -Role ghost -Policy $policy } | Should -Throw -ErrorId 'Tenure.Policy.RoleNotFound'
            { New-TenureRoleChangePlan -User 'alice@example.com' -Role support -FromRole ghost -Policy $policy } | Should -Throw -ErrorId 'Tenure.Policy.RoleNotFound'
        }

        It 'fails with Tenure.User.NotFound for an unknown user or manager' {
            { New-TenureRoleChangePlan -User 'nobody@example.com' -Role support -Policy $policy } | Should -Throw -ErrorId 'Tenure.User.NotFound'
            { New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager 'nobody@example.com' } | Should -Throw -ErrorId 'Tenure.User.NotFound'
        }

        It 'fails with Tenure.Sku.NotFound for a license of the new role that is not subscribed' {
            $own = New-TestPolicy -Roles @{ r = @{ licenses = @('NOT_A_SKU') } }
            { New-TenureRoleChangePlan -User 'alice@example.com' -Role r -Policy $own } | Should -Throw -ErrorId 'Tenure.Sku.NotFound'
        }
    }

    Context 'protected accounts' {
        BeforeEach {
            # alice's mail differs from her user principal name here, so each form of an entry is tested on its own.
            ($script:w.Users | Where-Object { $_['id'] -eq $script:ids.AliceId })['mail'] = 'alice.example@example.com'
        }

        It 'refuses a subject that protectedUsers names by <Form>, whatever the case, and reads nothing else' -ForEach @(
            @{ Form = 'user principal name'; Entry = 'Alice@Example.COM' }
            @{ Form = 'object id'; Entry = ' 10000000-0000-4000-8000-000000000001 ' }
            @{ Form = 'mail address'; Entry = 'ALICE.EXAMPLE@example.com' }
        ) {
            $protected = New-TestPolicy -Roles (& $script:BaseRoles) -Edit ({ param($raw) $raw['defaults']['protectedUsers'] = @($Entry) }.GetNewClosure())
            $failure = { New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $protected } | Should -Throw -ErrorId 'Tenure.Plan.Refused' -PassThru
            $failure.Exception.Message | Should -Match 'protected by policy'
            @($script:w.Calls | Where-Object { $_.Uri -like '*memberOf*' -or $_.Uri -like '*licenseAssignmentStates*' }).Count | Should -Be 0
            { New-TenureRoleChangePlan -User 'bob@example.com' -Role support -Policy $protected } | Should -Not -Throw -Because 'bob is not protected'
        }

        It 'a near miss protects no one: <Label>' -ForEach @(
            @{ Label = 'the alias without its domain'; Entry = 'alice' }
            @{ Label = 'the same name in another domain'; Entry = 'alice@example.org' }
            @{ Label = 'an address that only ends like hers'; Entry = 'malice@example.com' }
            @{ Label = 'an object id with one character changed'; Entry = '10000000-0000-4000-8000-000000000011' }
            @{ Label = 'the display name'; Entry = 'Alice Example' }
        ) {
            $nearMiss = New-TestPolicy -Roles (& $script:BaseRoles) -Edit ({ param($raw) $raw['defaults']['protectedUsers'] = @($Entry) }.GetNewClosure())
            { New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $nearMiss } | Should -Not -Throw
        }
    }

    Context 'the plan object' {
        It 'records the request without secrets, in a form that does not depend on how it was typed' {
            $file = Join-Path $TestDrive 'policy.json'
            $raw = Get-Content -LiteralPath $script:ExamplePolicyPath -Raw | ConvertFrom-Json -AsHashtable
            $raw['roles'] = & $script:BaseRoles
            $raw | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $file -Encoding utf8
            $plan = New-TenureRoleChangePlan -User 'ALICE@example.com' -Role support -Policy $file -KeepGroup 'sales@example.com', 'All Staff', 'all staff' -FromRole sales -Department 'Ops'
            $plan.Inputs.User | Should -BeExactly 'alice@example.com'
            $plan.Inputs.KeepGroup | Should -Be @('All Staff', 'sales@example.com')
            $plan.Inputs.FromRole | Should -BeExactly 'sales'
            $plan.Inputs.Department | Should -BeExactly 'Ops'
            $plan.Inputs.Policy | Should -BeExactly $file
            $plan.Status | Should -BeExactly 'Planned'
        }

        It 'survives an export and an import unchanged' {
            $plan = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager 'carol@example.com'
            $path = Join-Path $TestDrive 'rolechange.json'
            Export-TenurePlan -Plan $plan -Path $path
            $imported = Import-TenurePlan -Path $path
            @($imported.Steps | ForEach-Object { $_.Key }) | Should -Be (Get-Keys $plan)
            @($imported.Steps | ForEach-Object { $_.Fingerprint }) | Should -Be @($plan.Steps | ForEach-Object { $_.Fingerprint })
        }

        It 'reads and never writes, on either backend' {
            $null = New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager 'carol@example.com'
            $global:FakeGraphWorld.Calls.Count | Should -BeGreaterThan 0
            Get-Writes | Should -BeNullOrEmpty
            Get-ExchangeWrites | Should -BeNullOrEmpty
        }
    }
}
