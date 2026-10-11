# New-TenureOnboardPlan and Check.UserAbsent against FakeGraph and FakeExchange.
# The builder only plans: every test also proves nothing was written to either fake.

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

    # The example policy with its roles replaced (and, optionally, other keys changed) in memory.
    function New-TestPolicy([hashtable]$Roles, [scriptblock]$Edit) {
        $raw = Get-Content -LiteralPath $script:ExamplePolicyPath -Raw | ConvertFrom-Json -AsHashtable
        if ($Roles) { $raw['roles'] = $Roles }
        if ($Edit) { & $Edit $raw }
        Get-TenurePolicy -InputObject $raw
    }
    function Get-TestFingerprintOf($Target, $Before) { Invoke-InTenure { param($t, $b) Get-TenureStepFingerprint -Target $t -Before $b } @($Target, $Before) }
    # The example policy protects breakglass@example.com, an account the fakes do not have: every plan built from it
    # warns that the entry protects no one. Counts of the builder's own warnings leave that one out.
    function Get-BuilderWarning($Plan) { @($Plan.Warnings | Where-Object { $_ -notlike "The policy's protectedUsers entry 'breakglass@example.com' matches no user*" }) }
    function Get-Step($Plan, [string]$Key) { @($Plan.Steps | Where-Object { $_.Key -ceq $Key })[0] }
    function Get-Writes { @($global:FakeGraphWorld.Calls | Where-Object { $_.Method -in 'POST', 'PATCH', 'PUT', 'DELETE' }) }
    function Get-ExchangeWrites { @($global:FakeExchangeWorld.Calls | Where-Object { $_.Command -notlike 'Get-*' }) }
    function Get-Canonical($Object) { Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $Object) }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeExchangeWorld -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Check.UserAbsent' {
    BeforeAll { $script:provider = Get-TenureProvider -Name 'Check.UserAbsent' }
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
    }

    It 'is a Low-risk Refuse check on Graph without a Set' {
        $provider.Kind | Should -BeExactly 'Check'
        $provider.Backend | Should -BeExactly 'Graph'
        $provider.Severity | Should -BeExactly 'Refuse'
        $provider.Risk | Should -BeExactly 'Low'
        $provider.Reversible | Should -BeTrue
        @($provider.Scopes) | Should -Be @('User.Read.All', 'Directory.Read.All')
        $provider.Set | Should -BeNullOrEmpty
    }

    It 'counts nothing for a free name and passes' {
        $target = @{ Kind = 'user'; Id = 'new.hire@example.com'; Name = 'new.hire@example.com'; MailNickname = 'new.hire' }
        $current = & $provider.Get $target @{}
        $current.existing | Should -Be 0
        $current.deleted | Should -Be 0
        $current.userPrincipalName | Should -BeExactly 'new.hire@example.com'
        $current.mailNickname | Should -BeExactly 'new.hire'
        & $provider.Test $current @{ mailNickname = 'new.hire' } | Should -BeTrue
        & $provider.Describe $target $current @{ mailNickname = 'new.hire' } 'NoOp' | Should -Match 'free'
    }

    It 'finds an existing user by user principal name, whatever the case' {
        $current = & $provider.Get @{ Kind = 'user'; Id = 'ALICE@example.com'; Name = 'ALICE@example.com'; MailNickname = 'someone-else' } @{}
        $current.existing | Should -Be 1
        & $provider.Test $current @{} | Should -BeFalse
        & $provider.Describe @{ Kind = 'user'; Id = 'ALICE@example.com'; Name = 'ALICE@example.com' } $current @{} 'Check' | Should -Match 'already exists'
    }

    It 'finds a user that only shares the mail nickname' {
        $current = & $provider.Get @{ Kind = 'user'; Id = 'alice@other.example'; Name = 'alice@other.example'; MailNickname = 'alice' } @{}
        $current.existing | Should -Be 1
        & $provider.Test $current @{} | Should -BeFalse
    }

    It 'falls back to the local part of the UPN when the target carries no nickname' {
        $current = & $provider.Get @{ Kind = 'user'; Id = 'bob@elsewhere.example'; Name = 'bob@elsewhere.example' } @{}
        $current.mailNickname | Should -BeExactly 'bob'
        $current.existing | Should -Be 1
    }

    It 'counts a soft-deleted user and says to restore or purge it' {
        $target = @{ Kind = 'user'; Id = 'dave@example.com'; Name = 'dave@example.com'; MailNickname = 'dave2' }
        $current = & $provider.Get $target @{}
        $current.existing | Should -Be 0
        $current.deleted | Should -Be 1
        & $provider.Test $current @{} | Should -BeFalse
        & $provider.Describe $target $current @{} 'Check' | Should -Match 'restore or purge'
    }

    It 'doubles a single quote in the filter and encodes it' {
        $current = & $provider.Get @{ Kind = 'user'; Id = "o'brien@example.com"; Name = "o'brien@example.com"; MailNickname = "o'brien" } @{}
        $current.existing | Should -Be 0
        $call = @(Get-FakeGraphCall -World $script:w -Method GET -UriLike '*/users?*')[0]
        $call.Uri | Should -Match ([regex]::Escape([uri]::EscapeDataString("userPrincipalName eq 'o''brien@example.com'")))
    }

    It 'never passes without a snapshot or with malformed counts' {
        & $provider.Test $null @{} | Should -BeFalse
        & $provider.Test ([pscustomobject]@{ existing = '0'; deleted = '0' }) @{} | Should -BeFalse
        & $provider.Test ([pscustomobject]@{ existing = 0 }) @{} | Should -BeFalse
    }

    It 'only reads' {
        $null = & $provider.Get @{ Kind = 'user'; Id = 'x@example.com'; Name = 'x@example.com' } @{}
        Get-Writes | Should -BeNullOrEmpty
    }
}

Describe 'New-TenureOnboardPlan' {
    BeforeAll {
        $script:policy = Get-TenurePolicy -Path $script:ExamplePolicyPath
        $script:onboard = @{ UserPrincipalName = 'alex@example.com'; DisplayName = 'Alex Doe'; Role = 'sales' }
    }
    BeforeEach {
        Reset-FakeGraphWorld
        Reset-FakeExchangeWorld
        Set-TenureTestSession
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
    }

    Context 'the step list' {
        It 'is exactly the SPEC 5.2 list, in order, with the keys and dependencies the engine needs' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -Manager 'bob@example.com' -TemporaryAccessPass
            $plan | Should -BeOfType [pscustomobject]
            $plan.PSObject.TypeNames | Should -Contain 'Tenure.Plan'
            $plan.Operation | Should -BeExactly 'Onboard'
            @($plan.Steps | ForEach-Object { $_.Provider }) | Should -Be @(
                'Check.UserAbsent', 'User.Create', 'User.Manager', 'User.Licenses', 'Group.Member', 'Group.Member', 'User.TemporaryAccessPass')
            @($plan.Steps | ForEach-Object { $_.Key }) | Should -Be @(
                'absent', 'create', 'manager', 'licenses', "group:$($ids.AllStaffGroupId)", "group:$($ids.SalesGroupId)", 'tap')
            @($plan.Steps | ForEach-Object { $_.Id }) | Should -Be @('S01', 'S02', 'S03', 'S04', 'S05', 'S06', 'S07')
            @($plan.Steps[0].DependsOn).Count | Should -Be 0
            @($plan.Steps[1].DependsOn).Count | Should -Be 0
            foreach ($step in $plan.Steps[2..6]) { @($step.DependsOn) | Should -Be @('S02') -Because "step $($step.Key) needs the created user" }
            Get-Writes | Should -BeNullOrEmpty
            Get-ExchangeWrites | Should -BeNullOrEmpty
        }

        It 'gives the steps the actions the engine expects' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -Manager 'bob@example.com' -TemporaryAccessPass
            (Get-Step $plan 'absent').Action | Should -BeExactly 'NoOp'
            (Get-Step $plan 'absent').Kind | Should -BeExactly 'Check'
            (Get-Step $plan 'create').Action | Should -BeExactly 'Create'
            (Get-Step $plan 'create').Before | Should -BeNullOrEmpty
            (Get-Step $plan 'create').Fingerprint | Should -BeExactly (Get-TestFingerprintOf (Get-Step $plan 'create').Target $null) -Because 'the create binds its target as absent'
            foreach ($key in 'manager', 'licenses', "group:$($ids.SalesGroupId)") { (Get-Step $plan $key).Action | Should -BeExactly 'Update' }
            (Get-Step $plan 'tap').Action | Should -BeExactly 'Invoke'
        }

        It 'puts the placeholder in the target and, for groups, in the desired user' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -Manager 'bob@example.com' -TemporaryAccessPass
            foreach ($key in 'manager', 'licenses', 'tap') {
                $step = Get-Step $plan $key
                $step.Target.Kind | Should -BeExactly 'user' -Because $key
                $step.Target.Id | Should -BeExactly '{{subjectId}}' -Because $key
                $step.Before | Should -BeNullOrEmpty -Because 'no snapshot is taken for a user that does not exist'
                $step.Fingerprint | Should -BeExactly (Get-TestFingerprintOf $step.Target $null) -Because "$key binds the placeholder target"
            }
            foreach ($key in "group:$($ids.SalesGroupId)", "group:$($ids.AllStaffGroupId)") {
                # The group step binds the group, with the new user named by the placeholder: not a member yet.
                $groupStep = Get-Step $plan $key
                $groupStep.Before.userId | Should -BeExactly '{{subjectId}}' -Because $key
                $groupStep.Before.member | Should -BeExactly $false -Because $key
                $groupStep.Fingerprint | Should -BeExactly (Get-TestFingerprintOf $groupStep.Target $groupStep.Before) -Because $key
            }
            $group = Get-Step $plan "group:$($ids.SalesGroupId)"
            $group.Target.Kind | Should -BeExactly 'group'
            $group.Target.Id | Should -BeExactly $ids.SalesGroupId
            $group.Target.Name | Should -BeExactly 'Sales'
            $group.After.userId | Should -BeExactly '{{subjectId}}'
            $group.After.member | Should -BeTrue
            (Get-Step $plan 'manager').Target.Id | Should -BeExactly '{{subjectId}}'
            (Get-Step $plan 'manager').Target.Name | Should -BeExactly 'alex@example.com'
            (Get-Step $plan 'tap').After.lifetimeInMinutes | Should -Be 480
            (Get-Step $plan 'tap').After.isUsableOnce | Should -BeTrue
        }

        It 'creates the user from the role, with unset optional fields left out' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy
            $after = (Get-Step $plan 'create').After
            $after.userPrincipalName | Should -BeExactly 'alex@example.com'
            $after.displayName | Should -BeExactly 'Alex Doe'
            $after.mailNickname | Should -BeExactly 'alex'
            $after.usageLocation | Should -BeExactly 'US'
            $after.department | Should -BeExactly 'Sales'
            foreach ($absent in 'givenName', 'surname', 'jobTitle', 'officeLocation') { $after.ContainsKey($absent) | Should -BeFalse -Because $absent }
            (Get-Step $plan 'create').Target.Id | Should -BeExactly 'alex@example.com'
            (Get-Step $plan 'create').Target.Name | Should -BeExactly 'alex@example.com'
        }

        It 'carries every optional field it was given' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -GivenName 'Alex' -Surname 'Doe' -JobTitle 'Rep' -OfficeLocation 'Remote' -Department 'Field Sales' -UsageLocation 'ca'
            $after = (Get-Step $plan 'create').After
            $after.givenName | Should -BeExactly 'Alex'
            $after.surname | Should -BeExactly 'Doe'
            $after.jobTitle | Should -BeExactly 'Rep'
            $after.officeLocation | Should -BeExactly 'Remote'
            $after.department | Should -BeExactly 'Field Sales'
            $after.usageLocation | Should -BeExactly 'CA'
        }

        It 'has no manager step when none is given or defined, and no TAP step unless asked' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy
            @($plan.Steps | ForEach-Object { $_.Key }) | Should -Not -Contain 'manager'
            @($plan.Steps | ForEach-Object { $_.Key }) | Should -Not -Contain 'tap'
        }

        It 'has no license step when the role has no licenses and none are added' {
            $own = New-TestPolicy -Roles @{ plain = @{ groups = @('All Staff') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'alex@example.com' -DisplayName 'Alex Doe' -Role plain -Policy $own
            @($plan.Steps | ForEach-Object { $_.Key }) | Should -Be @('absent', 'create', "group:$($ids.AllStaffGroupId)")
        }
    }

    Context 'precedence' {
        It 'resolves the manager to an object id' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -Manager 'bob@example.com'
            (Get-Step $plan 'manager').After.managerId | Should -BeExactly $ids.BobId
            (Get-Step $plan 'manager').After.Keys.Count | Should -Be 1
        }

        It 'accepts a manager object id and records the manager UPN in the inputs' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -Manager $ids.BobId
            (Get-Step $plan 'manager').After.managerId | Should -BeExactly $ids.BobId
            $plan.Inputs.Manager | Should -BeExactly 'bob@example.com'
        }

        It 'uses the manager of the role when no parameter is given, and the parameter over it' {
            $own = New-TestPolicy -Roles @{ lead = @{ licenses = @('SPE_E3'); groups = @('All Staff'); manager = 'carol@example.com'; department = 'Ops'; jobTitle = 'Lead' } }
            $fromRole = New-TenureOnboardPlan -UserPrincipalName 'alex@example.com' -DisplayName 'Alex Doe' -Role lead -Policy $own
            (Get-Step $fromRole 'manager').After.managerId | Should -BeExactly $ids.CarolId
            (Get-Step $fromRole 'create').After.department | Should -BeExactly 'Ops'
            (Get-Step $fromRole 'create').After.jobTitle | Should -BeExactly 'Lead'
            $override = New-TenureOnboardPlan -UserPrincipalName 'alex@example.com' -DisplayName 'Alex Doe' -Role lead -Policy $own -Manager 'bob@example.com' -Department 'Sales' -JobTitle 'Rep'
            (Get-Step $override 'manager').After.managerId | Should -BeExactly $ids.BobId
            (Get-Step $override 'create').After.department | Should -BeExactly 'Sales'
            (Get-Step $override 'create').After.jobTitle | Should -BeExactly 'Rep'
        }

        It 'refuses a manager who is the new user' {
            $own = New-TestPolicy -Roles @{ lead = @{ groups = @('All Staff'); manager = 'bob@example.com' } }
            { New-TenureOnboardPlan -UserPrincipalName 'bob@example.com' -DisplayName 'Bob' -Role lead -Policy $own } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
        }

        It 'fails with Tenure.User.NotFound for an unknown manager' {
            { New-TenureOnboardPlan @onboard -Policy $policy -Manager 'nobody@example.com' } | Should -Throw -ErrorId 'Tenure.User.NotFound'
        }

        It 'takes the usage location from the parameter first, then from the policy defaults' {
            (Get-Step (New-TenureOnboardPlan @onboard -Policy $policy -UsageLocation 'DE') 'create').After.usageLocation | Should -BeExactly 'DE'
            $canada = New-TestPolicy -Edit { param($raw) $raw['defaults']['usageLocation'] = 'CA' }
            (Get-Step (New-TenureOnboardPlan @onboard -Policy $canada) 'create').After.usageLocation | Should -BeExactly 'CA'
            (Get-Step (New-TenureOnboardPlan @onboard -Policy $canada -UsageLocation 'FR') 'create').After.usageLocation | Should -BeExactly 'FR'
        }

        It 'refuses a plan with no usage location from anywhere' {
            $bare = New-TestPolicy
            $bare.Defaults['usageLocation'] = $null
            { New-TenureOnboardPlan @onboard -Policy $bare } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
            { New-TenureOnboardPlan @onboard -Policy $bare } | Should -Throw '*usage location*'
            (Get-Step (New-TenureOnboardPlan @onboard -Policy $bare -UsageLocation 'US') 'create').After.usageLocation | Should -BeExactly 'US'
        }

        It 'refuses a usage location that is not a two-letter code' {
            { New-TenureOnboardPlan @onboard -Policy $policy -UsageLocation 'USA' } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        }

        It 'defaults the mail nickname to the local part of the UPN and takes -MailNickname over it' {
            (Get-Step (New-TenureOnboardPlan @onboard -Policy $policy) 'create').After.mailNickname | Should -BeExactly 'alex'
            $custom = New-TenureOnboardPlan @onboard -Policy $policy -MailNickname 'alex.doe'
            (Get-Step $custom 'create').After.mailNickname | Should -BeExactly 'alex.doe'
            (Get-Step $custom 'absent').After.mailNickname | Should -BeExactly 'alex.doe'
            (Get-Step $custom 'absent').Before.mailNickname | Should -BeExactly 'alex.doe'
        }

        It 'refuses a mail nickname Entra ID would reject' -ForEach @(
            @{ Nickname = 'has space' }
            @{ Nickname = 'a@b' }
            @{ Nickname = ('x' * 65) }
            @{ Nickname = 'caf' + [char]0xE9 }
        ) {
            { New-TenureOnboardPlan @onboard -Policy $policy -MailNickname $Nickname } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        }

        It 'refuses a UPN that is not an address' {
            { New-TenureOnboardPlan -UserPrincipalName 'not-an-address' -DisplayName 'X' -Role sales -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.Invalid'
        }
    }

    Context 'roles, groups and licenses' {
        It 'fails with Tenure.Policy.RoleNotFound for a role the policy does not define' {
            { New-TenureOnboardPlan @onboard -Policy $policy -Role 'ghost' } | Should -Throw -ErrorId 'Tenure.Policy.RoleNotFound'
            { New-TenureOnboardPlan @onboard -Policy (New-TestPolicy -Roles @{}) } | Should -Throw -ErrorId 'Tenure.Policy.RoleNotFound'
        }

        It 'propagates an ambiguous group name instead of guessing' {
            $script:w.Groups.Add(@{
                    id = '20000000-0000-4000-8000-0000000000ff'; displayName = 'Sales'; mail = 'sales2@example.com'; mailNickname = 'sales2'
                    mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
                    members = [string[]]@(); owners = [string[]]@()
                })
            $own = New-TestPolicy -Roles @{ ambiguous = @{ groups = @('Sales') } }
            { New-TenureOnboardPlan -UserPrincipalName 'alex@example.com' -DisplayName 'Alex' -Role ambiguous -Policy $own } | Should -Throw -ErrorId 'Tenure.Group.Ambiguous'
            Get-Writes | Should -BeNullOrEmpty
        }

        It 'propagates an unknown group and an unknown SKU' {
            $badGroup = New-TestPolicy -Roles @{ r = @{ groups = @('No Such Group') } }
            { New-TenureOnboardPlan @onboard -Policy $badGroup -Role r } | Should -Throw -ErrorId 'Tenure.Group.NotFound'
            $badSku = New-TestPolicy -Roles @{ r = @{ licenses = @('NOT_A_SKU') } }
            { New-TenureOnboardPlan @onboard -Policy $badSku -Role r } | Should -Throw -ErrorId 'Tenure.Sku.NotFound'
            { New-TenureOnboardPlan @onboard -Policy $policy -AdditionalGroup 'No Such Group' } | Should -Throw -ErrorId 'Tenure.Group.NotFound'
            { New-TenureOnboardPlan @onboard -Policy $policy -AdditionalLicense 'NOT_A_SKU' } | Should -Throw -ErrorId 'Tenure.Sku.NotFound'
        }

        It 'sorts license ids in lower case and merges role and additional licenses without repeats' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -AdditionalLicense 'mcoev', 'SPE_E3'
            (Get-Step $plan 'licenses').After.add | Should -Be @($ids.SkuE3Id, $ids.SkuVoiceId)
            ((Get-Step $plan 'licenses').After.add | ForEach-Object { $_ -ceq $_.ToLowerInvariant() }) | Should -Not -Contain $false
            @((Get-Step $plan 'licenses').After.remove).Count | Should -Be 0 -Because 'a new user has no license to remove'
        }

        It 'merges additional groups with the role groups once, in display-name order' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -AdditionalGroup 'all staff', 'Legal DL'
            @($plan.Steps | Where-Object { $_.Key -like 'group:*' } | ForEach-Object { $_.Target.Name }) | Should -Be @('All Staff', 'Legal DL', 'Sales')
        }

        It 'orders the group steps by display name, whether the group was written as a name, a mail address or an id' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -AdditionalGroup $ids.SalesGroupId, 'Legal DL'
            @($plan.Steps | Where-Object { $_.Key -like 'group:*' } | ForEach-Object { $_.Target.Name }) | Should -Be @('All Staff', 'Legal DL', 'Sales')
            @($plan.Steps | Where-Object { $_.Key -like 'group:*' }).Count | Should -Be 3 -Because 'the id and the role mail address are the same group'
        }

        It 'warns, once per SKU, when a SKU has no available units' {
            $own = New-TestPolicy -Roles @{ desk = @{ licenses = @('EXCHANGEDESKLESS'); groups = @('All Staff') } }
            $plan = New-TenureOnboardPlan -UserPrincipalName 'alex@example.com' -DisplayName 'Alex' -Role desk -Policy $own
            @($plan.Warnings | Where-Object { $_ -like '*EXCHANGEDESKLESS*' -and $_ -like '*no available*' }).Count | Should -Be 1
            (Get-Step $plan 'licenses').After.add | Should -Be @($ids.SkuDeskId) -Because 'the license is still planned; the apply decides'
            @(Get-BuilderWarning (New-TenureOnboardPlan @onboard -Policy $policy)).Count | Should -Be 0
        }

        It 'does not warn for a SKU with units left' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -AdditionalLicense 'MCOEV'
            @($plan.Warnings | Where-Object { $_ -like '*no available*' }).Count | Should -Be 0
        }

        It 'skips a dynamic group with a warning instead of planning an add that cannot work' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -AdditionalGroup 'Everyone Dynamic'
            @($plan.Steps | ForEach-Object { $_.Key }) | Should -Not -Contain "group:$($ids.DynamicGroupId)"
            @($plan.Warnings | Where-Object { $_ -like "*Everyone Dynamic*" -and $_ -like '*dynamic membership, cannot add*' }).Count | Should -Be 1
        }

        It 'routes a distribution list to DistributionGroup.Member when Exchange is connected' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -AdditionalGroup 'Legal DL'
            $step = Get-Step $plan "group:$($ids.LegalDlGroupId)"
            $step.Provider | Should -BeExactly 'DistributionGroup.Member'
            $step.Target.Id | Should -BeExactly $ids.LegalDlGroupId
            $step.After.userId | Should -BeExactly '{{subjectId}}'
            $step.After.member | Should -BeTrue
            @($step.DependsOn) | Should -Be @('S02')
            ((Get-Step $plan "group:$($ids.SalesGroupId)").Provider) | Should -BeExactly 'Group.Member'
        }

        It 'skips a distribution list with a warning when Exchange is not connected' {
            Set-TenureTestSession -Exchange $false
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -AdditionalGroup 'Legal DL'
            @($plan.Steps | ForEach-Object { $_.Key }) | Should -Not -Contain "group:$($ids.LegalDlGroupId)"
            @($plan.Warnings | Where-Object { $_ -like '*Legal DL*' -and $_ -like '*Exchange*' }).Count | Should -Be 1
            @($plan.Steps | Where-Object { $_.Key -like 'group:*' }).Count | Should -Be 2
        }
    }

    Context 'the tenant domain' {
        It 'warns when the UPN domain is not the policy tenant domain, ignoring case' {
            $plan = New-TenureOnboardPlan -UserPrincipalName 'alex@other.example' -DisplayName 'Alex' -Role sales -Policy $policy
            @($plan.Warnings | Where-Object { $_ -like "*other.example*" -and $_ -like '*example.com*' }).Count | Should -Be 1
            @(Get-BuilderWarning (New-TenureOnboardPlan -UserPrincipalName 'alex@EXAMPLE.com' -DisplayName 'Alex' -Role sales -Policy $policy)).Count | Should -Be 0
        }

        It 'does not warn when the policy sets no domain' {
            $open = New-TestPolicy -Edit { param($raw) $raw.Remove('tenant') }
            $open.Tenant['domain'] | Should -BeNullOrEmpty
            @(Get-BuilderWarning (New-TenureOnboardPlan -UserPrincipalName 'alex@other.example' -DisplayName 'Alex' -Role sales -Policy $open)).Count | Should -Be 0
        }
    }

    Context 'refusing a name that is taken' {
        It 'refuses an existing user with Tenure.Plan.Refused and says why' {
            { New-TenureOnboardPlan -UserPrincipalName 'alice@example.com' -DisplayName 'Alice Two' -Role sales -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            { New-TenureOnboardPlan -UserPrincipalName 'alice@example.com' -DisplayName 'Alice Two' -Role sales -Policy $policy } | Should -Throw '*already exists*'
        }

        It 'refuses a soft-deleted user' {
            { New-TenureOnboardPlan -UserPrincipalName 'dave@example.com' -DisplayName 'Dave Again' -Role sales -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
            { New-TenureOnboardPlan -UserPrincipalName 'dave@example.com' -DisplayName 'Dave Again' -Role sales -Policy $policy } | Should -Throw '*restore or purge*'
        }

        It 'refuses a free UPN whose mail nickname is taken' {
            { New-TenureOnboardPlan -UserPrincipalName 'alice@other.example' -DisplayName 'Alice' -Role sales -Policy $policy } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
        }

        It 'checks the name before it looks up anything else' {
            { New-TenureOnboardPlan -UserPrincipalName 'alice@example.com' -DisplayName 'Alice' -Role sales -Policy $policy -Manager 'nobody@example.com' -AdditionalGroup 'No Such Group' } | Should -Throw -ErrorId 'Tenure.Plan.Refused'
        }
    }

    Context 'the plan object' {
        It 'records who it is for, the policy and the request, and no secret' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -Manager 'bob@example.com' -AdditionalGroup 'Legal DL', 'all staff' -TemporaryAccessPass
            $plan.Subject.Id | Should -BeNullOrEmpty
            $plan.Subject.UserPrincipalName | Should -BeExactly 'alex@example.com'
            $plan.Subject.DisplayName | Should -BeExactly 'Alex Doe'
            $plan.PolicyHash | Should -BeExactly $policy.Hash
            $plan.Status | Should -BeExactly 'Planned'
            $plan.Inputs.UserPrincipalName | Should -BeExactly 'alex@example.com'
            $plan.Inputs.Role | Should -BeExactly 'sales'
            $plan.Inputs.Policy | Should -BeExactly $script:ExamplePolicyPath
            $plan.Inputs.TemporaryAccessPass | Should -BeTrue
            $plan.Inputs.AdditionalGroup | Should -Be @('all staff', 'Legal DL')
            $plan.Inputs.ContainsKey('GivenName') | Should -BeFalse
            (Get-Canonical $plan) | Should -Not -Match 'passwordProfile|password"'
        }

        It 'records a policy that was not loaded from a file by hash' {
            $plan = New-TenureOnboardPlan @onboard -Policy (New-TestPolicy)
            $plan.Inputs.Policy | Should -Match '^sha256:[0-9a-f]{64}$'
        }

        It 'accepts the policy as a path' {
            $plan = New-TenureOnboardPlan @onboard -Policy $script:ExamplePolicyPath
            $plan.PolicyHash | Should -BeExactly $policy.Hash
        }

        It 'refuses a policy argument that is neither a path nor a policy' {
            { New-TenureOnboardPlan @onboard -Policy 42 } | Should -Throw -ErrorId 'Tenure.Policy.Invalid'
        }

        It 'survives an export and an import unchanged' {
            $plan = New-TenureOnboardPlan @onboard -Policy $policy -Manager 'bob@example.com' -TemporaryAccessPass
            $path = Join-Path $TestDrive 'onboard.json'
            Export-TenurePlan -Plan $plan -Path $path
            $imported = Import-TenurePlan -Path $path
            @($imported.Steps | ForEach-Object { $_.Key }) | Should -Be @($plan.Steps | ForEach-Object { $_.Key })
            (Get-Step $imported "group:$($ids.SalesGroupId)").After.userId | Should -BeExactly '{{subjectId}}'
        }

        It 'reads the tenant and writes nothing, to either backend' {
            $null = New-TenureOnboardPlan @onboard -Policy $policy -Manager 'bob@example.com' -TemporaryAccessPass -AdditionalGroup 'Legal DL'
            $global:FakeGraphWorld.Calls.Count | Should -BeGreaterThan 0
            Get-Writes | Should -BeNullOrEmpty
            Get-ExchangeWrites | Should -BeNullOrEmpty
            @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method GET -UriLike 'users/*/authentication/*').Count | Should -Be 0 -Because 'a placeholder step is never read from the tenant'
        }
    }
}
