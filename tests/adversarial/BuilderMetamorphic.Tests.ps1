# Plan builders, hostile angle:
#  1. CONTRIBUTING.md rule 4: builders compose steps and never call a seam themselves.
#  2. Metamorphic properties: reordering the lists a builder acts on, repeating entries, or changing the
#     case of the user's identity must not change the plan. The canonical form of a plan (keys sorted,
#     compressed) is compared once PlanId, CreatedAt and the Integrity value that seals them are blanked. A policy that was edited has another
#     PolicyHash (a hash of its text, arrays in file order), so the cases that edit the policy also
#     blank PolicyHash and Inputs.Policy, which records that hash.

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

    function New-TestPolicy([scriptblock]$Edit) {
        $raw = Get-Content -LiteralPath $script:ExamplePolicyPath -Raw | ConvertFrom-Json -AsHashtable
        if ($Edit) { & $Edit $raw }
        Get-TenurePolicy -InputObject $raw
    }
    # A deterministic permutation: the same seed always gives the same order.
    function Get-Shuffled([object[]]$Item, [int]$Seed) {
        $random = [System.Random]::new($Seed)
        $copy = [System.Collections.Generic.List[object]]::new($Item)
        for ($i = $copy.Count - 1; $i -gt 0; $i--) {
            $j = $random.Next($i + 1)
            $swap = $copy[$i]; $copy[$i] = $copy[$j]; $copy[$j] = $swap
        }
        , $copy.ToArray()
    }
    function Get-PlanForm($Plan, [switch]$IgnorePolicy) {
        $copy = Invoke-InTenure { param($p) Copy-TenureValue -InputObject $p } @(, $Plan)
        $copy.PlanId = $null
        $copy.CreatedAt = $null
        # Integrity seals PlanId and CreatedAt too, so it differs whenever they do.
        $copy.Integrity = $null
        if ($IgnorePolicy) {
            $copy.PolicyHash = $null
            $copy.Inputs['Policy'] = $null
        }
        Invoke-InTenure { param($p) Get-TenureCanonicalJson -InputObject $p } @(, $copy)
    }
    function Add-FakeGroup([string]$Id, [string]$Name, [string[]]$Types = @()) {
        $global:FakeGraphWorld.Groups.Add(@{
                id = $Id; displayName = $Name; mail = $null; mailNickname = ($Name -replace '\s', '').ToLowerInvariant()
                mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]$Types; membershipRule = $null
                members = [string[]]@(); owners = [string[]]@()
            })
    }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeExchangeWorld -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Plan builders and the seams (CONTRIBUTING.md rule 4)' {
    BeforeAll {
        $script:builderFiles = @(
            'Public/New-TenureOnboardPlan.ps1', 'Public/New-TenureRoleChangePlan.ps1', 'Public/New-TenureOffboardPlan.ps1', 'Private/Core/Builders.ps1'
        )
        function Find-SeamCall([string]$Text) {
            [regex]::Matches($Text, 'Invoke-TenureGraph|Invoke-TenureExchange') | ForEach-Object { $_.Value }
        }
    }

    It 'the scan sees a seam call' {
        @(Find-SeamCall 'x = Invoke-TenureGraph -Method GET').Count | Should -Be 1
        @(Find-SeamCall "Invoke-TenureExchange -Command 'x'").Count | Should -Be 1
        @(Find-SeamCall 'New-TenureStep -Provider x').Count | Should -Be 0
    }

    It '<_> does not mention Invoke-TenureGraph or Invoke-TenureExchange' -ForEach @(
        'Public/New-TenureOnboardPlan.ps1', 'Public/New-TenureRoleChangePlan.ps1', 'Public/New-TenureOffboardPlan.ps1', 'Private/Core/Builders.ps1'
    ) {
        $path = Join-Path $script:TenureSourceRoot $_
        Test-Path -LiteralPath $path | Should -BeTrue
        @(Find-SeamCall (Get-Content -LiteralPath $path -Raw)).Count | Should -Be 0
    }

    It 'the builder files are ASCII with LF line ends' {
        foreach ($file in $script:builderFiles + @('Private/Providers/Check.UserAbsent.ps1', 'Private/Providers/Check.SubjectAllowed.ps1', 'Private/Providers/Check.SubjectNotGlobalAdmin.ps1')) {
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path $script:TenureSourceRoot $file))
            @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0 -Because "$file must be ASCII"
            @($bytes | Where-Object { $_ -eq 13 }).Count | Should -Be 0 -Because "$file must use LF"
        }
    }
}

Describe 'Plan builders are insensitive to list order, repeats and the case of the identity' {
    BeforeEach {
        Reset-FakeGraphWorld
        Reset-FakeExchangeWorld
        Set-TenureTestSession
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        Add-FakeGroup -Id '20000000-0000-4000-8000-000000000005' -Name 'Support'
        Add-FakeGroup -Id '20000000-0000-4000-8000-000000000006' -Name 'Field Team'
    }

    Context 'offboard' {
        BeforeAll {
            $script:keep = @('All Staff', 'Sales', 'Legal DL', 'Everyone Dynamic')
        }

        It 'gives the same plan twice for the same request' {
            $policy = New-TestPolicy
            Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy) | Should -BeExactly (Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy))
        }

        It 'ignores the order, case and repeats of keepGroups in the policy (permutation <Seed>)' -ForEach @(1..8 | ForEach-Object { @{ Seed = $_ } }) {
            $reference = Get-PlanForm -IgnorePolicy (New-TenureOffboardPlan -User 'alice@example.com' -Policy (New-TestPolicy -Edit { param($raw) $raw['defaults']['offboard']['keepGroups'] = @('Sales', 'All Staff') }))
            $shuffled = Get-Shuffled -Item (@('sales@example.com', 'ALL STAFF', 'Sales', 'all staff')) -Seed $Seed
            $variant = New-TestPolicy -Edit { param($raw) $raw['defaults']['offboard']['keepGroups'] = $shuffled }.GetNewClosure()
            Get-PlanForm -IgnorePolicy (New-TenureOffboardPlan -User 'alice@example.com' -Policy $variant) | Should -BeExactly $reference
        }

        It 'ignores the order of -KeepGroup (permutation <Seed>)' -ForEach @(1..8 | ForEach-Object { @{ Seed = $_ } }) {
            $policy = New-TestPolicy
            $reference = Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -KeepGroup $script:keep)
            $shuffled = [string[]](Get-Shuffled -Item $script:keep -Seed $Seed)
            Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -KeepGroup $shuffled) | Should -BeExactly $reference
        }

        It 'ignores whether the policy or the parameter names a keep group' {
            $viaParameter = Get-PlanForm -IgnorePolicy (New-TenureOffboardPlan -User 'alice@example.com' -Policy (New-TestPolicy) -KeepGroup 'Sales', 'All Staff') 
            $viaPolicy = Get-PlanForm -IgnorePolicy (New-TenureOffboardPlan -User 'alice@example.com' -Policy (New-TestPolicy -Edit { param($raw) $raw['defaults']['offboard']['keepGroups'] = @('All Staff', 'Sales') }))
            # Inputs differ by design (the parameter is recorded); every step, warning and the subject must match.
            $a = $viaParameter | ConvertFrom-Json
            $b = $viaPolicy | ConvertFrom-Json
            ($a.Steps | ConvertTo-Json -Depth 30 -Compress) | Should -BeExactly ($b.Steps | ConvertTo-Json -Depth 30 -Compress)
            ($a.Warnings | ConvertTo-Json -Compress) | Should -BeExactly ($b.Warnings | ConvertTo-Json -Compress)
        }

        It 'ignores the case of the user principal name and whether an id is used' -ForEach @(
            @{ Identity = 'ALICE@EXAMPLE.COM' }
            @{ Identity = 'Alice@Example.Com' }
            @{ Identity = '10000000-0000-4000-8000-000000000001' }
        ) {
            $policy = New-TestPolicy
            $reference = Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy)
            Get-PlanForm (New-TenureOffboardPlan -User $Identity -Policy $policy) | Should -BeExactly $reference
        }

        It 'ignores the case of the recipient words' {
            $policy = New-TestPolicy
            $reference = Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -ForwardTo manager -GrantMailboxTo manager -GrantOneDriveTo none -Devices retireAll)
            $variant = Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -ForwardTo MANAGER -GrantMailboxTo Manager -GrantOneDriveTo None -Devices RETIREALL)
            ($variant | ConvertFrom-Json).Steps | ConvertTo-Json -Depth 30 -Compress | Should -BeExactly (($reference | ConvertFrom-Json).Steps | ConvertTo-Json -Depth 30 -Compress)
        }
    }

    Context 'role change' {
        BeforeAll {
            $script:roleSets = {
                param([string[]]$NewGroups, [string[]]$NewLicenses, [string[]]$OldGroups, [string[]]$OldLicenses)
                New-TestPolicy -Edit {
                    param($raw)
                    $raw['roles'] = @{
                        sales   = @{ licenses = $OldLicenses; groups = $OldGroups; department = 'Sales' }
                        support = @{ licenses = $NewLicenses; groups = $NewGroups; department = 'Support' }
                    }
                }.GetNewClosure()
            }
            $script:newGroups = @('All Staff', 'Support', 'Field Team')
            $script:newLicenses = @('MCOEV', 'SPE_E3')
            $script:oldGroups = @('sales@example.com', 'All Staff', 'Legal DL', 'Everyone Dynamic')
            $script:oldLicenses = @('SPE_E3', 'EXCHANGEDESKLESS')
        }

        It 'gives the same plan twice for the same request' {
            $policy = & $roleSets $newGroups $newLicenses $oldGroups $oldLicenses
            Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy) | Should -BeExactly (Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy))
        }

        It 'ignores the order of every role group and license list (permutation <Seed>)' -ForEach @(1..8 | ForEach-Object { @{ Seed = $_ } }) {
            $reference = Get-PlanForm -IgnorePolicy (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy (& $roleSets $newGroups $newLicenses $oldGroups $oldLicenses))
            $variantPolicy = & $roleSets (Get-Shuffled $newGroups $Seed) (Get-Shuffled $newLicenses ($Seed + 100)) (Get-Shuffled $oldGroups ($Seed + 200)) (Get-Shuffled $oldLicenses ($Seed + 300))
            Get-PlanForm -IgnorePolicy (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $variantPolicy) | Should -BeExactly $reference
        }

        It 'ignores repeats and case in a role list' {
            $reference = Get-PlanForm -IgnorePolicy (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy (& $roleSets $newGroups $newLicenses $oldGroups $oldLicenses))
            $noisy = & $roleSets ($newGroups + @('all staff', 'SUPPORT')) ($newLicenses + @('mcoev')) ($oldGroups + @('SALES@example.com')) ($oldLicenses + @('spe_e3'))
            Get-PlanForm -IgnorePolicy (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $noisy) | Should -BeExactly $reference
        }

        It 'ignores the order of -KeepGroup (permutation <Seed>)' -ForEach @(1..6 | ForEach-Object { @{ Seed = $_ } }) {
            $policy = & $roleSets $newGroups $newLicenses $oldGroups $oldLicenses
            $keep = @('Sales', 'Legal DL', 'Everyone Dynamic')
            $reference = Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -KeepGroup $keep)
            Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -KeepGroup ([string[]](Get-Shuffled $keep $Seed))) | Should -BeExactly $reference
        }

        It 'ignores the case of the user identity' -ForEach @(
            @{ Identity = 'ALICE@EXAMPLE.COM' }
            @{ Identity = '10000000-0000-4000-8000-000000000001' }
        ) {
            $policy = & $roleSets $newGroups $newLicenses $oldGroups $oldLicenses
            $reference = Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager 'bob@example.com')
            Get-PlanForm (New-TenureRoleChangePlan -User $Identity -Role support -Policy $policy -Manager 'BOB@example.com') | Should -BeExactly $reference
        }

        It 'ignores the case of the manager identity' {
            $policy = & $roleSets $newGroups $newLicenses $oldGroups $oldLicenses
            $reference = Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager 'carol@example.com')
            Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $policy -Manager $ids.CarolId) | Should -BeExactly $reference
        }
    }

    Context 'onboard' {
        BeforeAll {
            $script:onboardPolicy = {
                param([string[]]$Groups, [string[]]$Licenses)
                New-TestPolicy -Edit { param($raw) $raw['roles'] = @{ field = @{ licenses = $Licenses; groups = $Groups; department = 'Field' } } }.GetNewClosure()
            }
            $script:fieldGroups = @('All Staff', 'Support', 'Field Team', 'sales@example.com')
            $script:fieldLicenses = @('SPE_E3', 'MCOEV')
            $script:request = @{ UserPrincipalName = 'alex@example.com'; DisplayName = 'Alex Doe'; Role = 'field' }
        }

        It 'gives the same plan twice for the same request' {
            $policy = & $onboardPolicy $fieldGroups $fieldLicenses
            Get-PlanForm (New-TenureOnboardPlan @request -Policy $policy) | Should -BeExactly (Get-PlanForm (New-TenureOnboardPlan @request -Policy $policy))
        }

        It 'ignores the order of the role group and license lists (permutation <Seed>)' -ForEach @(1..8 | ForEach-Object { @{ Seed = $_ } }) {
            $reference = Get-PlanForm -IgnorePolicy (New-TenureOnboardPlan @request -Policy (& $onboardPolicy $fieldGroups $fieldLicenses))
            $variant = & $onboardPolicy (Get-Shuffled $fieldGroups $Seed) (Get-Shuffled $fieldLicenses ($Seed + 50))
            Get-PlanForm -IgnorePolicy (New-TenureOnboardPlan @request -Policy $variant) | Should -BeExactly $reference
        }

        It 'ignores the order of -AdditionalGroup and -AdditionalLicense (permutation <Seed>)' -ForEach @(1..8 | ForEach-Object { @{ Seed = $_ } }) {
            $policy = & $onboardPolicy @('All Staff') @('SPE_E3')
            $groups = @('Support', 'Field Team', 'Legal DL')
            $licenses = @('MCOEV', 'EXCHANGEDESKLESS')
            $reference = Get-PlanForm (New-TenureOnboardPlan @request -Policy $policy -AdditionalGroup $groups -AdditionalLicense $licenses)
            $variant = Get-PlanForm (New-TenureOnboardPlan @request -Policy $policy -AdditionalGroup ([string[]](Get-Shuffled $groups $Seed)) -AdditionalLicense ([string[]](Get-Shuffled $licenses ($Seed + 7))))
            $variant | Should -BeExactly $reference
        }

        It 'treats a group named in the role and again as an additional group as one group' {
            $policy = & $onboardPolicy @('All Staff', 'Support') @('SPE_E3')
            $once = Get-PlanForm (New-TenureOnboardPlan @request -Policy $policy)
            $twice = Get-PlanForm (New-TenureOnboardPlan @request -Policy $policy -AdditionalGroup 'support', 'ALL STAFF' -AdditionalLicense 'spe_e3')
            ($twice | ConvertFrom-Json).Steps | ConvertTo-Json -Depth 30 -Compress | Should -BeExactly (($once | ConvertFrom-Json).Steps | ConvertTo-Json -Depth 30 -Compress)
        }

        It 'ignores the case and form of the manager identity' -ForEach @(
            @{ Identity = 'BOB@example.com' }
            @{ Identity = '10000000-0000-4000-8000-000000000002' }
        ) {
            $policy = & $onboardPolicy $fieldGroups $fieldLicenses
            $reference = Get-PlanForm (New-TenureOnboardPlan @request -Policy $policy -Manager 'bob@example.com')
            Get-PlanForm (New-TenureOnboardPlan @request -Policy $policy -Manager $Identity) | Should -BeExactly $reference
        }
    }
}

Describe 'The metamorphic checks can fail' {
    BeforeEach {
        Reset-FakeGraphWorld
        Reset-FakeExchangeWorld
        Set-TenureTestSession
        Add-FakeGroup -Id '20000000-0000-4000-8000-000000000005' -Name 'Support'
    }

    It 'the shuffle really reorders a list' {
        $list = @('a', 'b', 'c', 'd', 'e')
        $orders = 1..8 | ForEach-Object { (Get-Shuffled $list $_) -join ',' }
        @($orders | Select-Object -Unique).Count | Should -BeGreaterThan 1
        @($orders | Where-Object { $_ -cne ($list -join ',') }).Count | Should -BeGreaterThan 0
        $shuffled = Get-Shuffled $list 3
        ($shuffled | Sort-Object) -join ',' | Should -BeExactly ($list -join ',')
    }

    It 'the plan form changes when the request really changes' {
        $policy = New-TestPolicy
        $plain = Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy)
        $kept = Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy $policy -KeepGroup 'Sales')
        $kept | Should -Not -BeExactly $plain
        (Get-PlanForm (New-TenureOffboardPlan -User 'bob@example.com' -Policy $policy)) | Should -Not -BeExactly $plain
        $roles = New-TestPolicy -Edit { param($raw) $raw['roles'] = @{ sales = @{ licenses = @('SPE_E3'); groups = @('Sales') }; support = @{ licenses = @('MCOEV'); groups = @('Support') } } }
        # support has no license with Exchange Online, so moving alice there takes her mailbox license away.
        $toSupport = Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role support -Policy $roles -AllowMailboxLoss)
        $toSales = Get-PlanForm (New-TenureRoleChangePlan -User 'alice@example.com' -Role sales -Policy $roles)
        $toSupport | Should -Not -BeExactly $toSales
    }

    It 'the plan form carries the steps, so an equal form means equal steps' {
        $form = Get-PlanForm (New-TenureOffboardPlan -User 'alice@example.com' -Policy (New-TestPolicy)) | ConvertFrom-Json
        @($form.Steps).Count | Should -Be 21
        $form.PlanId | Should -BeNullOrEmpty
        $form.CreatedAt | Should -BeNullOrEmpty
        $form.Operation | Should -BeExactly 'Offboard'
        @($form.Steps | Where-Object { $_.Key -like 'group:*' }).Count | Should -Be 4
    }
}
