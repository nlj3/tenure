BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }

    function Resolve-User([string]$Identity) { Invoke-InTenure { param($i) Resolve-TenureUser -Identity $i } @($Identity) }
    function Resolve-Group([string]$Identity) { Invoke-InTenure { param($i) Resolve-TenureGroup -Identity $i } @($Identity) }
    function Resolve-Sku([string]$PartNumber) { Invoke-InTenure { param($p) Resolve-TenureSku -PartNumber $p } @($PartNumber) }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Resolve-TenureUser' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
    }

    It 'resolves by UPN and returns every documented key' {
        $user = Resolve-User 'alice@example.com'
        $user | Should -BeOfType [hashtable]
        $user.Keys | Sort-Object | Should -Be @('AccountEnabled', 'Department', 'DisplayName', 'GivenName', 'Id', 'JobTitle', 'Mail', 'MailNickname', 'Manager', 'OfficeLocation', 'Surname', 'UsageLocation', 'UserPrincipalName')
        $user.Id | Should -Be $ids.AliceId
        $user.UserPrincipalName | Should -Be 'alice@example.com'
        $user.DisplayName | Should -Be 'Alice Example'
        $user.MailNickname | Should -Be 'alice'
        $user.Mail | Should -Be 'alice@example.com'
        $user.AccountEnabled | Should -BeTrue
        $user.UsageLocation | Should -Be 'US'
        $user.Department | Should -Be 'Sales'
        $user.JobTitle | Should -Be 'Account Executive'
        $user.GivenName | Should -Be 'Alice'
        $user.Surname | Should -Be 'Example'
    }

    It 'resolves by object id' {
        (Resolve-User $ids.BobId).UserPrincipalName | Should -Be 'bob@example.com'
    }

    It 'includes the manager as @{ Id; UserPrincipalName; DisplayName; Mail }' {
        $manager = (Resolve-User 'alice@example.com').Manager
        $manager.Keys | Sort-Object | Should -Be @('DisplayName', 'Id', 'Mail', 'UserPrincipalName')
        $manager.Id | Should -Be $ids.BobId
        $manager.UserPrincipalName | Should -Be 'bob@example.com'
        $manager.DisplayName | Should -Be 'Bob Manager'
        $manager.Mail | Should -Be 'bob@example.com'
    }

    It 'asks for the manager by the resolved object id, not the identity that was typed' {
        Resolve-User 'alice@example.com' | Out-Null
        @(Get-FakeGraphCall -World $w -Method GET -UriLike "*users/$($ids.AliceId)/manager*").Count | Should -Be 1
    }

    It 'Manager is $null when the user has none (Graph 404 on manager is not an error)' {
        $bob = Resolve-User 'bob@example.com'
        $bob.Manager | Should -BeNullOrEmpty
        $bob.ContainsKey('Manager') | Should -BeTrue
    }

    It 'throws Tenure.User.NotFound with the identity in the message' {
        $failure = { Resolve-User 'nobody@example.com' } | Should -Throw -ErrorId 'Tenure.User.NotFound' -PassThru
        $failure.Exception.Message | Should -Match 'nobody@example.com'
        $failure.Exception.Data['Identity'] | Should -Be 'nobody@example.com'
    }

    It 'a soft-deleted user is not found' {
        { Resolve-User 'dave@example.com' } | Should -Throw -ErrorId 'Tenure.User.NotFound'
    }

    It 'lets other Graph failures through untouched (403 stays Forbidden)' {
        Add-FakeGraphFault -World $w -Status 403
        { Resolve-User 'alice@example.com' } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
    }

    It 'a failure on the manager lookup other than 404 is not swallowed' {
        $w.Faults.Enqueue(@{ Status = 200; Body = @{ id = $ids.AliceId; userPrincipalName = 'alice@example.com' } })
        Add-FakeGraphFault -World $w -Status 403
        { Resolve-User 'alice@example.com' } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
    }

    It 'escapes the identity so it cannot add path segments or query options' {
        { Resolve-User 'alice@example.com/memberOf' } | Should -Throw -ErrorId 'Tenure.User.NotFound'
        @(Get-FakeGraphCall -World $w -Method GET -UriLike '*memberOf*').Count | Should -Be 1
        $w.Calls[-1].Uri | Should -Match 'users/alice%40example\.com%2FmemberOf\?'
        { Resolve-User 'x?$select=id' } | Should -Throw -ErrorId 'Tenure.User.NotFound'
    }

    It 'rejects an empty identity' {
        { Resolve-User '' } | Should -Throw
    }
}

Describe 'Resolve-TenureGroup' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
    }

    It 'resolves by display name and returns every documented key' {
        $group = Resolve-Group 'Sales'
        $group.Keys | Sort-Object | Should -Be @('DisplayName', 'GroupTypes', 'Id', 'IsAssignableToRole', 'IsDynamic', 'IsExchangeManaged', 'IsUnified', 'Mail', 'MailEnabled', 'MembershipRule', 'SecurityEnabled')
        $group.Id | Should -Be $ids.SalesGroupId
        $group.DisplayName | Should -Be 'Sales'
        $group.Mail | Should -Be 'sales@example.com'
        $group.GroupTypes | Should -Be @('Unified')
        $group.MailEnabled | Should -BeTrue
        $group.SecurityEnabled | Should -BeFalse
    }

    It 'resolves by mail address, case-insensitively' {
        (Resolve-Group 'SALES@example.com').Id | Should -Be $ids.SalesGroupId
        (Resolve-Group 'legal@example.com').Id | Should -Be $ids.LegalDlGroupId
    }

    It 'resolves by object id with a single GET groups/{id}' {
        $group = Resolve-Group $ids.AllStaffGroupId
        $group.DisplayName | Should -Be 'All Staff'
        $w.Calls.Count | Should -Be 1
        $w.Calls[0].Uri | Should -Match "/groups/$($ids.AllStaffGroupId)\?"
    }

    It 'a plain security group is not dynamic, not unified and not Exchange-managed' {
        $group = Resolve-Group 'All Staff'
        $group.IsDynamic | Should -BeFalse
        $group.IsUnified | Should -BeFalse
        $group.IsExchangeManaged | Should -BeFalse
        $group.GroupTypes.Count | Should -Be 0
        $group.Mail | Should -BeNullOrEmpty
    }

    It 'a Microsoft 365 (Unified) group is unified, mail-enabled and NOT Exchange-managed' {
        $group = Resolve-Group 'Sales'
        $group.IsUnified | Should -BeTrue
        $group.MailEnabled | Should -BeTrue
        $group.IsExchangeManaged | Should -BeFalse
    }

    It 'a dynamic group reports IsDynamic and its rule' {
        $group = Resolve-Group 'Everyone Dynamic'
        $group.IsDynamic | Should -BeTrue
        $group.IsUnified | Should -BeFalse
        $group.MembershipRule | Should -Be '(user.accountEnabled -eq true)'
        $group.IsExchangeManaged | Should -BeFalse
    }

    It 'a mail-enabled security group (not Unified) is Exchange-managed' {
        $group = Resolve-Group 'Legal DL'
        $group.MailEnabled | Should -BeTrue
        $group.SecurityEnabled | Should -BeTrue
        $group.IsUnified | Should -BeFalse
        $group.IsExchangeManaged | Should -BeTrue
    }

    It 'a distribution list (mail-enabled, not security, not Unified) is Exchange-managed' {
        ($w.Groups | Where-Object id -eq $ids.LegalDlGroupId).securityEnabled = $false
        (Resolve-Group 'Legal DL').IsExchangeManaged | Should -BeTrue
    }

    It 'throws Tenure.Group.NotFound for an unknown name, mail or id' -ForEach @(
        @{ Identity = 'No Such Group' }, @{ Identity = 'nobody@example.com' }, @{ Identity = '99999999-9999-4999-8999-999999999999' }
    ) {
        $failure = { Resolve-Group $Identity } | Should -Throw -ErrorId 'Tenure.Group.NotFound' -PassThru
        $failure.Exception.Message | Should -Match ([regex]::Escape($Identity))
    }

    It 'throws Tenure.Group.Ambiguous, listing every id and display name, when two groups match' {
        $w.Groups.Add(@{
                id = '20000000-0000-4000-8000-0000000000aa'; displayName = 'Sales'; mail = $null; mailNickname = 'sales2'
                mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
                members = [string[]]@(); owners = [string[]]@()
            })
        $failure = { Resolve-Group 'Sales' } | Should -Throw -ErrorId 'Tenure.Group.Ambiguous' -PassThru
        $failure.Exception.Message | Should -Match $ids.SalesGroupId
        $failure.Exception.Message | Should -Match '20000000-0000-4000-8000-0000000000aa'
        $failure.Exception.Message | Should -Match 'Sales'
        $failure.Exception.Data['Count'] | Should -Be 2
    }

    It 'is ambiguous when a display name equals another group''s mail address' {
        $w.Groups.Add(@{
                id = '20000000-0000-4000-8000-0000000000bb'; displayName = 'sales@example.com'; mail = $null; mailNickname = 'odd'
                mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
                members = [string[]]@(); owners = [string[]]@()
            })
        { Resolve-Group 'sales@example.com' } | Should -Throw -ErrorId 'Tenure.Group.Ambiguous'
    }

    It 'sees every page when deciding on ambiguity (the match on page 2 still counts)' {
        $w.PageSize = 1
        $w.Groups.Insert(0, @{
                id = '20000000-0000-4000-8000-0000000000cc'; displayName = 'Other'; mail = $null; mailNickname = 'other'
                mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
                members = [string[]]@(); owners = [string[]]@()
            })
        $w.Groups.Add(@{
                id = '20000000-0000-4000-8000-0000000000dd'; displayName = 'Legal DL'; mail = $null; mailNickname = 'legal2'
                mailEnabled = $false; securityEnabled = $true; groupTypes = [string[]]@(); membershipRule = $null
                members = [string[]]@(); owners = [string[]]@()
            })
        { Resolve-Group 'Legal DL' } | Should -Throw -ErrorId 'Tenure.Group.Ambiguous'
    }

    It 'doubles single quotes in the filter and URL-encodes the expression' {
        { Resolve-Group "Bob's Group & Friends" } | Should -Throw -ErrorId 'Tenure.Group.NotFound'
        $uri = $w.Calls[-1].Uri
        $uri | Should -Match '%27%27s'
        $uri | Should -Match '%26'
        $uri | Should -Not -Match ' '
    }

    It 'treats a 32-hex-digit group name as a name, not an id' {
        { Resolve-Group '10000000000040008000000000000001' } | Should -Throw -ErrorId 'Tenure.Group.NotFound'
        $w.Calls[-1].Uri | Should -Match 'groups\?'
    }

    It 'lets other Graph failures through untouched' {
        Add-FakeGraphFault -World $w -Status 403
        { Resolve-Group 'Sales' } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
    }
}

Describe 'Resolve-TenureSku and Get-TenureSubscribedSku' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
    }

    It 'maps a part number to @{ SkuId; SkuPartNumber; Available }' {
        $sku = Resolve-Sku 'SPE_E3'
        $sku.Keys | Sort-Object | Should -Be @('Available', 'SkuId', 'SkuPartNumber')
        $sku.SkuId | Should -Be $ids.SkuE3Id
        $sku.SkuPartNumber | Should -Be 'SPE_E3'
    }

    It 'matches the part number case-insensitively and returns the tenant''s spelling' {
        $sku = Resolve-Sku 'spe_e3'
        $sku.SkuId | Should -Be $ids.SkuE3Id
        $sku.SkuPartNumber | Should -Be 'SPE_E3'
    }

    It 'computes Available as enabled minus consumed' {
        (Resolve-Sku 'SPE_E3').Available | Should -Be 7
        (Resolve-Sku 'MCOEV').Available | Should -Be 2
    }

    It 'reports Available 0 when every unit is consumed' {
        (Resolve-Sku 'EXCHANGEDESKLESS').Available | Should -Be 0
    }

    It 'never reports a negative Available for an over-assigned SKU' {
        ($w.SubscribedSkus | Where-Object skuPartNumber -eq 'MCOEV').consumedUnits = 5
        (Resolve-Sku 'MCOEV').Available | Should -Be 0
    }

    It 'throws Tenure.Sku.NotFound listing the tenant''s part numbers' {
        $failure = { Resolve-Sku 'NOPE_E5' } | Should -Throw -ErrorId 'Tenure.Sku.NotFound' -PassThru
        $failure.Exception.Message | Should -Match 'NOPE_E5'
        $failure.Exception.Message | Should -Match 'EXCHANGEDESKLESS'
        $failure.Exception.Message | Should -Match 'MCOEV'
        $failure.Exception.Message | Should -Match 'SPE_E3'
    }

    It 'finds a SKU that is only on the second page' {
        $w.PageSize = 1
        (Resolve-Sku 'MCOEV').SkuId | Should -Be $ids.SkuVoiceId
        @(Get-FakeGraphCall -World $w -Method GET -UriLike '*subscribedSkus*').Count | Should -Be 3
    }

    It 'Get-TenureSubscribedSku lists every SKU with the same three keys' {
        $skus = @(Invoke-InTenure { Get-TenureSubscribedSku })
        $skus.Count | Should -Be 3
        @($skus.SkuPartNumber | Sort-Object) | Should -Be @('EXCHANGEDESKLESS', 'MCOEV', 'SPE_E3')
        ($skus | Where-Object SkuPartNumber -eq 'SPE_E3').SkuId | Should -Be $ids.SkuE3Id
        ($skus | Where-Object SkuPartNumber -eq 'SPE_E3').Available | Should -Be 7
        $skus | ForEach-Object { $_.Keys | Sort-Object | Should -Be @('Available', 'SkuId', 'SkuPartNumber') }
    }

    It 'Get-TenureSubscribedSku maps ids back to names for a builder' {
        $byId = @{}
        foreach ($sku in @(Invoke-InTenure { Get-TenureSubscribedSku })) { $byId[$sku.SkuId] = $sku.SkuPartNumber }
        $byId[$ids.SkuDeskId] | Should -Be 'EXCHANGEDESKLESS'
    }

    It 'a tenant with no SKUs yields an empty list and a clean NotFound' {
        $w.SubscribedSkus.Clear()
        @(Invoke-InTenure { Get-TenureSubscribedSku }).Count | Should -Be 0
        { Resolve-Sku 'SPE_E3' } | Should -Throw -ErrorId 'Tenure.Sku.NotFound'
    }
}

Describe 'Resolver helpers' {
    It 'ConvertTo-TenureUriSegment escapes separators and query characters' {
        Invoke-InTenure { ConvertTo-TenureUriSegment -Value 'a/b?c#d e@f' } | Should -Be 'a%2Fb%3Fc%23d%20e%40f'
    }

    It 'ConvertTo-TenureODataString doubles single quotes' {
        Invoke-InTenure { ConvertTo-TenureODataString -Value "O'Brien's" } | Should -Be "O''Brien''s"
    }

    It 'Get-TenureGraphProperty reads hashtables and objects, case-insensitively, and defaults when absent' {
        Invoke-InTenure { Get-TenureGraphProperty -InputObject @{ Id = 'x' } -Name 'id' } | Should -Be 'x'
        Invoke-InTenure { Get-TenureGraphProperty -InputObject ([pscustomobject]@{ userId = 'u' }) -Name 'USERID' } | Should -Be 'u'
        Invoke-InTenure { Get-TenureGraphProperty -InputObject ([pscustomobject]@{ a = 1 }) -Name 'missing' -Default 'd' } | Should -Be 'd'
        Invoke-InTenure { Get-TenureGraphProperty -InputObject $null -Name 'x' } | Should -BeNullOrEmpty
    }

    It 'ConvertTo-TenureTable accepts hashtables, objects and $null' {
        (Invoke-InTenure { ConvertTo-TenureTable -InputObject ([pscustomobject]@{ A = 1; b = 2 }) })['a'] | Should -Be 1
        (Invoke-InTenure { ConvertTo-TenureTable -InputObject @{ k = 'v' } }).k | Should -Be 'v'
        (Invoke-InTenure { ConvertTo-TenureTable -InputObject $null }).Count | Should -Be 0
    }

    It 'Get-TenureTargetId returns the id and reports a missing or placeholder id as Tenure.Provider.TargetNotFound' {
        Invoke-InTenure { Get-TenureTargetId -Target @{ Id = 'abc' } -Provider 'X.Y' } | Should -Be 'abc'
        { Invoke-InTenure { Get-TenureTargetId -Target @{ Id = $null } -Provider 'X.Y' } } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        { Invoke-InTenure { Get-TenureTargetId -Target @{ Kind = 'user' } -Provider 'X.Y' } } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        { Invoke-InTenure { Get-TenureTargetId -Target @{ Id = '{{subjectId}}' } -Provider 'X.Y' } } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }
}
