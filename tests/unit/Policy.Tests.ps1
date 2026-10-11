BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest

    $script:OffboardKeys = @(
        'resetPassword', 'revokeSessions', 'removeDirectoryRoles', 'convertMailboxToShared', 'hideFromAddressLists',
        'forwardTo', 'deliverToMailboxAndForward', 'autoReply', 'grantMailboxTo', 'grantOneDriveTo', 'cancelMeetings',
        'removeFromGroups', 'keepGroups', 'removeLicenses', 'devices', 'setEmployeeLeaveDate'
    )

    $script:ExamplePath = Join-Path $script:TenureSourceRoot 'Policies' 'example.policy.json'
    $script:SchemaPath = Join-Path $script:TenureSourceRoot 'Policies' 'tenure.policy.schema.json'

    function Get-ExampleTable {
        Get-Content -LiteralPath $script:ExamplePath -Raw | ConvertFrom-Json -AsHashtable
    }

    function Write-PolicyFile {
        param([Parameter(Mandatory)][object]$Content, [string]$Name = 'policy.json')
        $path = Join-Path $TestDrive $Name
        $text = if ($Content -is [string]) { $Content } else { ConvertTo-Json -InputObject $Content -Depth 20 }
        [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))
        $path
    }

    function Set-Nested {
        param([hashtable]$Table, [string[]]$Segments, $Value)
        $cursor = $Table
        for ($i = 0; $i -lt $Segments.Count - 1; $i++) { $cursor = $cursor[$Segments[$i]] }
        $cursor[$Segments[-1]] = $Value
    }

    function Remove-Nested {
        param([hashtable]$Table, [string[]]$Segments)
        $cursor = $Table
        for ($i = 0; $i -lt $Segments.Count - 1; $i++) { $cursor = $cursor[$Segments[$i]] }
        $cursor.Remove($Segments[-1])
    }

    # Helper variable names are prefixed so they cannot shadow variables the test scriptblocks read
    # (scriptblocks passed in resolve $path, $table, $value ... through dynamic scope).
    function Get-ThrownError {
        param([scriptblock]$HelperBlock)
        try { & $HelperBlock | Out-Null } catch { return $_ }
        $null
    }

    function Assert-PolicyInvalid {
        param([scriptblock]$HelperBlock, [string]$HelperExpectedPath)
        $helperThrown = Get-ThrownError $HelperBlock
        $helperThrown | Should -Not -BeNullOrEmpty -Because 'the call should have thrown'
        $helperThrown.FullyQualifiedErrorId | Should -Be 'Tenure.Policy.Invalid'
        $helperThrown.Exception.Data['Path'] | Should -Be $HelperExpectedPath
        $helperThrown.Exception.Message.StartsWith($HelperExpectedPath + ':') | Should -BeTrue -Because "message starts with the JSON path: $($helperThrown.Exception.Message)"
    }
}

Describe 'Get-TenurePolicy: example policy' {
    BeforeAll { $script:policy = Get-TenurePolicy -Path $script:ExamplePath }

    It 'loads clean and is a Tenure.Policy' {
        $script:policy.PSObject.TypeNames[0] | Should -Be 'Tenure.Policy'
        $script:policy.Version | Should -Be 1
        $script:policy.Version | Should -BeOfType [int]
    }

    It 'carries the tenant, roles and the path it came from' {
        $script:policy.Tenant | Should -BeOfType [hashtable]
        $script:policy.Tenant['domain'] | Should -Be 'example.com'
        $script:policy.Roles | Should -BeOfType [hashtable]
        @($script:policy.Roles.Keys | Sort-Object) | Should -Be @('sales', 'warehouse')
        $script:policy.Path | Should -Be $script:ExamplePath
    }

    It 'shapes every role with all five keys, null when absent' {
        $sales = $script:policy.Roles['sales']
        $sales | Should -BeOfType [hashtable]
        @($sales.Keys | Sort-Object) | Should -Be @('Department', 'Groups', 'JobTitle', 'Licenses', 'Manager')
        $sales['Licenses'] | Should -Be @('SPE_E3')
        $sales['Licenses'] | Should -BeOfType [string]
        , $sales['Licenses'] | Should -BeOfType [string[]]
        , $sales['Groups'] | Should -BeOfType [string[]]
        $sales['Groups'] | Should -Be @('sales@example.com', 'All Staff')
        $sales['Department'] | Should -Be 'Sales'
        $sales['JobTitle'] | Should -BeNullOrEmpty
        $sales['Manager'] | Should -BeNullOrEmpty
        $warehouse = $script:policy.Roles['warehouse']
        $warehouse['JobTitle'] | Should -Be 'Warehouse Associate'
        $warehouse['Department'] | Should -Be 'Operations'
    }

    It 'computes a sorted managed set across roles' {
        , $script:policy.ManagedSet.Licenses | Should -BeOfType [string[]]
        , $script:policy.ManagedSet.Groups | Should -BeOfType [string[]]
        $script:policy.ManagedSet.Licenses | Should -Be @('EXCHANGEDESKLESS', 'SPE_E3')
        $script:policy.ManagedSet.Groups | Should -Be @('All Staff', 'sales@example.com', 'Warehouse Users')
    }

    It 'has a 64 character lowercase hex hash' {
        $script:policy.Hash | Should -Match '^[0-9a-f]{64}$'
    }

    It 'applies the SPEC 2.1 defaults and values from the file' {
        $d = $script:policy.Defaults
        $d['usageLocation'] | Should -Be 'US'
        $d['passwordLength'] | Should -Be 20
        $d['protectedUsers'] | Should -Be @('breakglass@example.com')
        $d['offboard']['forwardTo'] | Should -Be 'manager'
        $d['offboard']['devices'] | Should -Be 'wipeCorporateRetirePersonal'
        $d['offboard']['autoReply']['enabled'] | Should -BeTrue
    }

    It 'does not leak _comment keys into the loaded policy' {
        $script:policy.Defaults.ContainsKey('_comment') | Should -BeFalse
        $script:policy.Tenant.ContainsKey('_comment') | Should -BeFalse
    }
}

Describe 'Get-TenurePolicy: defaults' {
    It 'fills every SPEC 2.1 default when the file only says version 1' {
        $path = Write-PolicyFile '{ "version": 1 }'
        $policy = Get-TenurePolicy -Path $path
        @($policy.Defaults.Keys | Sort-Object) | Should -Be @('offboard', 'passwordLength', 'protectedUsers', 'usageLocation')
        $policy.Defaults['usageLocation'] | Should -Be 'US'
        $policy.Defaults['passwordLength'] | Should -Be 20
        @($policy.Defaults['protectedUsers']).Count | Should -Be 0
        , $policy.Defaults['protectedUsers'] | Should -BeOfType [string[]]
        $policy.Tenant.ContainsKey('domain') | Should -BeTrue
        $policy.Tenant['domain'] | Should -BeNullOrEmpty
        $policy.Roles.Count | Should -Be 0
        @($policy.ManagedSet.Licenses).Count | Should -Be 0
        @($policy.ManagedSet.Groups).Count | Should -Be 0
        , $policy.ManagedSet.Licenses | Should -BeOfType [string[]]
        $policy.Path | Should -Be $path
    }

    It 'has every offboard key with its default' {
        $offboard = (Get-TenurePolicy -InputObject @{ version = 1 }).Defaults['offboard']
        @($offboard.Keys | Sort-Object) | Should -Be @($script:OffboardKeys | Sort-Object)
        foreach ($key in 'resetPassword', 'revokeSessions', 'removeDirectoryRoles', 'convertMailboxToShared', 'hideFromAddressLists', 'deliverToMailboxAndForward', 'cancelMeetings', 'removeFromGroups', 'removeLicenses') {
            $offboard[$key] | Should -BeTrue -Because $key
        }
        $offboard['setEmployeeLeaveDate'] | Should -BeFalse
        $offboard['forwardTo'] | Should -Be 'manager'
        $offboard['grantMailboxTo'] | Should -Be 'manager'
        $offboard['grantOneDriveTo'] | Should -Be 'manager'
        $offboard['devices'] | Should -Be 'wipeCorporateRetirePersonal'
        @($offboard['keepGroups']).Count | Should -Be 0
        $offboard['autoReply']['enabled'] | Should -BeTrue
        $offboard['autoReply']['message'] | Should -Be '{displayName} has left {company}. Please contact {managerDisplayName} ({managerMail}).'
    }

    It 'keeps unspecified siblings when a file overrides part of offboard and autoReply' {
        $table = @{ version = 1; defaults = @{ offboard = @{ forwardTo = 'none'; autoReply = @{ enabled = $false } } } }
        $offboard = (Get-TenurePolicy -InputObject $table).Defaults['offboard']
        $offboard['forwardTo'] | Should -Be 'none'
        $offboard['autoReply']['enabled'] | Should -BeFalse
        $offboard['autoReply']['message'] | Should -Match 'has left'
        $offboard['grantMailboxTo'] | Should -Be 'manager'
    }

    It 'returns fresh defaults each call (no shared mutable state)' {
        $first = Get-TenurePolicy -InputObject @{ version = 1 }
        $first.Defaults['offboard']['forwardTo'] = 'changed'
        $second = Get-TenurePolicy -InputObject @{ version = 1 }
        $second.Defaults['offboard']['forwardTo'] | Should -Be 'manager'
    }

    It 'fills missing role keys with empty arrays and nulls' {
        $policy = Get-TenurePolicy -InputObject @{ version = 1; roles = @{ bare = @{} } }
        $role = $policy.Roles['bare']
        @($role['Licenses']).Count | Should -Be 0
        @($role['Groups']).Count | Should -Be 0
        , $role['Licenses'] | Should -BeOfType [string[]]
        $role['Department'] | Should -BeNullOrEmpty
        $role['JobTitle'] | Should -BeNullOrEmpty
        $role['Manager'] | Should -BeNullOrEmpty
    }
}

Describe 'Get-TenurePolicy: InputObject' {
    It 'accepts a hashtable and a PSCustomObject with the same content and hashes them the same' {
        $table = Get-ExampleTable
        $object = Get-Content -LiteralPath $script:ExamplePath -Raw | ConvertFrom-Json
        $fromTable = Get-TenurePolicy -InputObject $table
        $fromObject = Get-TenurePolicy -InputObject $object
        $fromTable.Hash | Should -Be $fromObject.Hash
        $fromTable.Path | Should -BeNullOrEmpty
        $fromTable.Roles.Count | Should -Be 2
        $fromObject.Defaults['offboard']['devices'] | Should -Be 'wipeCorporateRetirePersonal'
    }

    It 'gives the same hash as loading the same content from a file' {
        $fromFile = Get-TenurePolicy -Path $script:ExamplePath
        $fromTable = Get-TenurePolicy -InputObject (Get-ExampleTable)
        $fromTable.Hash | Should -Be $fromFile.Hash
    }

    It 'does not modify the object it was given' {
        $table = Get-ExampleTable
        $before = ConvertTo-Json -InputObject $table -Depth 20
        $null = Get-TenurePolicy -InputObject $table
        ConvertTo-Json -InputObject $table -Depth 20 | Should -Be $before
    }

    It 'rejects a non-object with Tenure.Policy.Invalid at the root' {
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject 'text' } '$'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject 42 } '$'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @(1, 2) } '$'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject $null } '$'
    }

    It 'rejects values that are not JSON (secrets, dates) instead of hashing them' {
        $secret = ConvertTo-SecureString -String 'not-a-real-secret' -AsPlainText -Force
        $thrown = Get-ThrownError { Get-TenurePolicy -InputObject @{ version = 1; _comment = $secret } }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Policy.Invalid'
        $thrown.Exception.Data['Path'] | Should -Be '$._comment'
    }

    It 'refuses to be given both a path and an object' {
        { Get-TenurePolicy -Path $script:ExamplePath -InputObject @{ version = 1 } } | Should -Throw
    }
}

Describe 'Get-TenurePolicy: managed set' {
    It 'is the union across roles, de-duplicated case-insensitively and sorted' {
        $table = @{
            version = 1
            roles   = @{
                sales   = @{ licenses = @('SPE_E3', 'spe_e5'); groups = @('Sales Team', 'All Staff') }
                support = @{ licenses = @('SPE_E3', 'F1'); groups = @('all staff', 'Support', 'sales team') }
                empty   = @{}
            }
        }
        $managed = (Get-TenurePolicy -InputObject $table).ManagedSet
        $managed.Licenses | Should -Be @('F1', 'SPE_E3', 'spe_e5')
        $managed.Groups | Should -Be @('All Staff', 'Sales Team', 'Support')
        , $managed.Licenses | Should -BeOfType [string[]]
        , $managed.Groups | Should -BeOfType [string[]]
    }

    It 'does not depend on role order' {
        $a = @{ version = 1; roles = [ordered]@{ one = @{ groups = @('B', 'a') }; two = @{ groups = @('A', 'c') } } }
        $b = @{ version = 1; roles = [ordered]@{ two = @{ groups = @('A', 'c') }; one = @{ groups = @('B', 'a') } } }
        (Get-TenurePolicy -InputObject $a).ManagedSet.Groups | Should -Be (Get-TenurePolicy -InputObject $b).ManagedSet.Groups
    }

    It 'is empty (arrays, not null) when there are no roles' {
        $managed = (Get-TenurePolicy -InputObject @{ version = 1; roles = @{} }).ManagedSet
        @($managed.Licenses).Count | Should -Be 0
        @($managed.Groups).Count | Should -Be 0
    }
}

Describe 'Get-TenurePolicy: hash' {
    It 'is identical for two files with identical content' {
        $one = Write-PolicyFile -Content (Get-ExampleTable) -Name 'one.json'
        $two = Write-PolicyFile -Content (Get-ExampleTable) -Name 'two.json'
        (Get-TenurePolicy -Path $one).Hash | Should -Be (Get-TenurePolicy -Path $two).Hash
    }

    It 'does not depend on key order or whitespace' {
        $compact = Write-PolicyFile -Content '{"version":1,"roles":{"a":{"groups":["g"],"licenses":["l"]}}}' -Name 'compact.json'
        $spread = Write-PolicyFile -Content "{`n  `"roles`": { `"a`": { `"licenses`": [`"l`"], `"groups`": [`"g`"] } },`n  `"version`": 1`n}" -Name 'spread.json'
        (Get-TenurePolicy -Path $compact).Hash | Should -Be (Get-TenurePolicy -Path $spread).Hash
    }

    It 'is the hash of the raw object, taken before defaults are applied' {
        $policy = Get-TenurePolicy -InputObject @{ version = 1 }
        $policy.Hash | Should -Be (Invoke-InTenure { Get-TenureHash -InputObject @{ version = 1 } })
    }

    It 'changes when the content changes, including a _comment' {
        $base = Get-ExampleTable
        $changed = Get-ExampleTable
        $changed['_comment'] = 'different'
        (Get-TenurePolicy -InputObject $changed).Hash | Should -Not -Be (Get-TenurePolicy -InputObject $base).Hash
        $edited = Get-ExampleTable
        $edited['roles']['sales']['licenses'] = @('SPE_E5')
        (Get-TenurePolicy -InputObject $edited).Hash | Should -Not -Be (Get-TenurePolicy -InputObject $base).Hash
    }
}

Describe 'Get-TenurePolicy: validation' {
    It 'requires version to be exactly 1' {
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = 2 } } '$.version'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = 0 } } '$.version'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = '1' } } '$.version'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = $true } } '$.version'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = 1.5 } } '$.version'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = $null } } '$.version'
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ roles = @{} } } '$.version'
    }

    It 'accepts 1.0 as the integer 1 (JSON has one number type)' {
        (Get-TenurePolicy -InputObject @{ version = 1.0 }).Version | Should -Be 1
    }

    It 'rejects an unknown key at <Level> and names it in the path' -ForEach @(
        @{ Level = 'the top level'; Parent = @(); Path = '$.bogus' }
        @{ Level = 'tenant'; Parent = @('tenant'); Path = '$.tenant.bogus' }
        @{ Level = 'defaults'; Parent = @('defaults'); Path = '$.defaults.bogus' }
        @{ Level = 'defaults.offboard'; Parent = @('defaults', 'offboard'); Path = '$.defaults.offboard.bogus' }
        @{ Level = 'defaults.offboard.autoReply'; Parent = @('defaults', 'offboard', 'autoReply'); Path = '$.defaults.offboard.autoReply.bogus' }
        @{ Level = 'roles.sales'; Parent = @('roles', 'sales'); Path = '$.roles.sales.bogus' }
    ) {
        $table = Get-ExampleTable
        $cursor = $table
        foreach ($segment in $Parent) { $cursor = $cursor[$segment] }
        $cursor['bogus'] = 1
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject $table } $Path
    }

    It 'catches a typo in a real key (devcies for devices) from a file' {
        $table = Get-ExampleTable
        $table['defaults']['offboard'].Remove('devices')
        $table['defaults']['offboard']['devcies'] = 'none'
        $path = Write-PolicyFile $table
        Assert-PolicyInvalid { Get-TenurePolicy -Path $path } '$.defaults.offboard.devcies'
    }

    It 'treats key case as significant (Version is not version)' {
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = 1; Roles = @{} } } '$.Roles'
    }

    It 'lists the allowed keys in an unknown-key message' {
        $thrown = Get-ThrownError { Get-TenurePolicy -InputObject @{ version = 1; tenant = @{ domian = 'x' } } }
        $thrown.Exception.Message | Should -Match 'domain'
    }

    It 'allows keys starting with an underscore anywhere and ignores them' {
        $table = Get-ExampleTable
        foreach ($parent in @(@(), @('tenant'), @('defaults'), @('defaults', 'offboard'), @('defaults', 'offboard', 'autoReply'), @('roles'), @('roles', 'sales'))) {
            $cursor = $table
            foreach ($segment in $parent) { $cursor = $cursor[$segment] }
            $cursor['_note'] = 'anything', 5, @{ nested = $true }
        }
        $policy = Get-TenurePolicy -InputObject $table
        $policy.Roles.ContainsKey('_note') | Should -BeFalse
        $policy.Roles['sales'].ContainsKey('_note') | Should -BeFalse
        $policy.Defaults['offboard'].ContainsKey('_note') | Should -BeFalse
        $policy.Defaults['offboard']['autoReply'].ContainsKey('_note') | Should -BeFalse
    }

    It 'rejects <Name> with the right path' -ForEach @(
        @{ Name = 'a string tenant'; Segments = @('tenant'); Value = 'text'; Path = '$.tenant' }
        @{ Name = 'a numeric domain'; Segments = @('tenant', 'domain'); Value = 5; Path = '$.tenant.domain' }
        @{ Name = 'an array for defaults'; Segments = @('defaults'); Value = @(1); Path = '$.defaults' }
        @{ Name = 'a numeric usageLocation'; Segments = @('defaults', 'usageLocation'); Value = 1; Path = '$.defaults.usageLocation' }
        @{ Name = 'a string passwordLength'; Segments = @('defaults', 'passwordLength'); Value = '20'; Path = '$.defaults.passwordLength' }
        @{ Name = 'a fractional passwordLength'; Segments = @('defaults', 'passwordLength'); Value = 20.5; Path = '$.defaults.passwordLength' }
        @{ Name = 'a boolean passwordLength'; Segments = @('defaults', 'passwordLength'); Value = $true; Path = '$.defaults.passwordLength' }
        @{ Name = 'a passwordLength below 8'; Segments = @('defaults', 'passwordLength'); Value = 7; Path = '$.defaults.passwordLength' }
        @{ Name = 'a passwordLength above 256'; Segments = @('defaults', 'passwordLength'); Value = 257; Path = '$.defaults.passwordLength' }
        @{ Name = 'a string protectedUsers'; Segments = @('defaults', 'protectedUsers'); Value = 'a@example.com'; Path = '$.defaults.protectedUsers' }
        @{ Name = 'a number inside protectedUsers'; Segments = @('defaults', 'protectedUsers'); Value = @('a@example.com', 5); Path = '$.defaults.protectedUsers[1]' }
        @{ Name = 'a null inside keepGroups'; Segments = @('defaults', 'offboard', 'keepGroups'); Value = @('x', $null); Path = '$.defaults.offboard.keepGroups[1]' }
        @{ Name = 'a string for a bool'; Segments = @('defaults', 'offboard', 'resetPassword'); Value = 'yes'; Path = '$.defaults.offboard.resetPassword' }
        @{ Name = 'a number for a bool'; Segments = @('defaults', 'offboard', 'revokeSessions'); Value = 1; Path = '$.defaults.offboard.revokeSessions' }
        @{ Name = 'a string autoReply'; Segments = @('defaults', 'offboard', 'autoReply'); Value = 'off'; Path = '$.defaults.offboard.autoReply' }
        @{ Name = 'a string autoReply.enabled'; Segments = @('defaults', 'offboard', 'autoReply', 'enabled'); Value = 'true'; Path = '$.defaults.offboard.autoReply.enabled' }
        @{ Name = 'a numeric autoReply.message'; Segments = @('defaults', 'offboard', 'autoReply', 'message'); Value = 5; Path = '$.defaults.offboard.autoReply.message' }
        @{ Name = 'an array roles'; Segments = @('roles'); Value = @(); Path = '$.roles' }
        @{ Name = 'a string role'; Segments = @('roles', 'sales'); Value = 'x'; Path = '$.roles.sales' }
        @{ Name = 'a string licenses'; Segments = @('roles', 'sales', 'licenses'); Value = 'SPE_E3'; Path = '$.roles.sales.licenses' }
        @{ Name = 'a number inside groups'; Segments = @('roles', 'sales', 'groups'); Value = @(1); Path = '$.roles.sales.groups[0]' }
        @{ Name = 'a numeric department'; Segments = @('roles', 'sales', 'department'); Value = 5; Path = '$.roles.sales.department' }
        @{ Name = 'a null jobTitle'; Segments = @('roles', 'sales', 'jobTitle'); Value = $null; Path = '$.roles.sales.jobTitle' }
        @{ Name = 'a boolean manager'; Segments = @('roles', 'sales', 'manager'); Value = $true; Path = '$.roles.sales.manager' }
    ) {
        $table = Get-ExampleTable
        Set-Nested $table $Segments $Value
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject $table } $Path
    }

    It 'accepts a manager on a role' {
        $table = Get-ExampleTable
        $table['roles']['sales']['manager'] = 'lead@example.com'
        (Get-TenurePolicy -InputObject $table).Roles['sales']['Manager'] | Should -Be 'lead@example.com'
    }

    It 'accepts an empty roles object' {
        $policy = Get-TenurePolicy -InputObject @{ version = 1; roles = @{} }
        $policy.Roles.Count | Should -Be 0
    }

    It 'reports the first problem as the error and every problem in Data[Problems]' {
        $table = Get-ExampleTable
        $table['defaults']['passwordLength'] = 'long'
        $table['roles']['sales']['bogus'] = 1
        $thrown = Get-ThrownError { Get-TenurePolicy -InputObject $table }
        $thrown.Exception.Data['Problems'].Count | Should -Be 2
        $thrown.Exception.Message | Should -Be $thrown.Exception.Data['Problems'][0]
    }

    It 'is deterministic about which problem comes first for the same content' {
        $table = Get-ExampleTable
        $table['roles']['sales']['bogus'] = 1
        $table['defaults']['passwordLength'] = 'long'
        $one = (Get-ThrownError { Get-TenurePolicy -InputObject $table }).Exception.Message
        $two = (Get-ThrownError { Get-TenurePolicy -InputObject $table }).Exception.Message
        $one | Should -Be $two
    }

    Context 'role names' {
        It 'accepts letters, digits, underscore and hyphen' {
            $table = @{ version = 1; roles = @{ 'Sales-EU_2' = @{}; '9lives' = @{} } }
            @((Get-TenurePolicy -InputObject $table).Roles.Keys | Sort-Object) | Should -Be @('9lives', 'Sales-EU_2')
        }

        It 'rejects <Name>' -ForEach @(
            @{ Name = 'a space'; Role = 'sales team' }
            @{ Name = 'a dot'; Role = 'sales.eu' }
            @{ Name = 'an at sign'; Role = 'a@b' }
            @{ Name = 'a trailing newline'; Role = "sales`n" }
            @{ Name = 'non-ASCII letters'; Role = "caf$([char]0xE9)" }
        ) {
            $table = @{ version = 1; roles = @{ $Role = @{} } }
            $thrown = Get-ThrownError { Get-TenurePolicy -InputObject $table }
            $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Policy.Invalid'
            $thrown.Exception.Data['Path'] | Should -Be ('$.roles.' + $Role)
            $thrown.Exception.Message | Should -Match 'A-Za-z0-9'
        }

        It 'treats a role name starting with an underscore as a comment key, not a role' {
            $policy = Get-TenurePolicy -InputObject @{ version = 1; roles = @{ _note = 'free text'; real = @{} } }
            @($policy.Roles.Keys) | Should -Be @('real')
        }

        It 'rejects two role names that differ only by case' {
            $json = '{ "version": 1, "roles": { "Sales": {}, "sales": {} } }'
            $thrown = Get-ThrownError { Get-TenurePolicy -Path (Write-PolicyFile $json) }
            $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Policy.Invalid'
            $thrown.Exception.Data['Path'] | Should -Be '$.roles'
        }
    }

    Context 'forwardTo, grantMailboxTo and grantOneDriveTo: literal or address' {
        It '<Field> accepts <Value>' -ForEach @(
            foreach ($field in 'forwardTo', 'grantMailboxTo', 'grantOneDriveTo') {
                foreach ($value in 'manager', 'none', 'lead@example.com', 'first.last+tag@mail.example.com') {
                    @{ Field = $field; Value = $value }
                }
            }
        ) {
            $table = @{ version = 1; defaults = @{ offboard = @{ $Field = $Value } } }
            (Get-TenurePolicy -InputObject $table).Defaults['offboard'][$Field] | Should -Be $Value
        }

        It '<Field> rejects <Value>' -ForEach @(
            foreach ($field in 'forwardTo', 'grantMailboxTo', 'grantOneDriveTo') {
                foreach ($value in 'Manager', 'NONE', 'someone', 'a@b', '@example.com', 'a b@example.com', '', 'a@example.com ', "a@example.com`n") {
                    @{ Field = $field; Value = $value }
                }
            }
        ) {
            $table = @{ version = 1; defaults = @{ offboard = @{ $Field = $Value } } }
            Assert-PolicyInvalid { Get-TenurePolicy -InputObject $table } ('$.defaults.offboard.' + $Field)
        }

        It 'rejects a non-string forwardTo' {
            Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = 1; defaults = @{ offboard = @{ forwardTo = $false } } } } '$.defaults.offboard.forwardTo'
        }
    }

    Context 'devices' {
        It 'accepts each allowed value' -ForEach @(
            @{ Value = 'wipeCorporateRetirePersonal' }, @{ Value = 'retireAll' }, @{ Value = 'none' }
        ) {
            (Get-TenurePolicy -InputObject @{ version = 1; defaults = @{ offboard = @{ devices = $Value } } }).Defaults['offboard']['devices'] | Should -Be $Value
        }

        It 'rejects an unknown value or a wrong case' -ForEach @(
            @{ Value = 'wipeAll' }, @{ Value = 'RetireAll' }, @{ Value = '' }, @{ Value = 3 }
        ) {
            Assert-PolicyInvalid { Get-TenurePolicy -InputObject @{ version = 1; defaults = @{ offboard = @{ devices = $Value } } } } '$.defaults.offboard.devices'
        }
    }
}

Describe 'Get-TenurePolicy: passwordLength range' {
    It 'accepts <Value>' -ForEach @(
        @{ Value = 8 }, @{ Value = 9 }, @{ Value = 20 }, @{ Value = 255 }, @{ Value = 256 }, @{ Value = 8.0 }, @{ Value = [long]64 }
    ) {
        $policy = Get-TenurePolicy -InputObject @{ version = 1; defaults = @{ passwordLength = $Value } }
        [int]$policy.Defaults['passwordLength'] | Should -Be ([int]$Value)
    }

    It 'rejects <Value> with the path $.defaults.passwordLength' -ForEach @(
        @{ Value = 7 }, @{ Value = 0 }, @{ Value = -1 }, @{ Value = -20 }, @{ Value = 257 }, @{ Value = 1000 },
        @{ Value = [long]3000000000 }, @{ Value = [long]::MaxValue }, @{ Value = 7.0 }, @{ Value = 256.5 }
    ) {
        $table = @{ version = 1; defaults = @{ passwordLength = $Value } }
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject $table } '$.defaults.passwordLength'
    }

    It 'says the range in the message' {
        $thrown = Get-ThrownError { Get-TenurePolicy -InputObject @{ version = 1; defaults = @{ passwordLength = 7 } } }
        $thrown.Exception.Message | Should -Match '8 to 256'
        $thrown.Exception.Message | Should -Match 'got 7'
    }

    It 'falls back to 20 when passwordLength is not given' {
        (Get-TenurePolicy -InputObject @{ version = 1 }).Defaults['passwordLength'] | Should -Be 20
    }
}

Describe 'Get-TenurePolicy: empty strings in name lists' {
    It 'rejects <Bad> in <Where> with the element path' -ForEach @(
        foreach ($case in @(
                @{ Where = 'roles.sales.licenses'; Segments = @('roles', 'sales', 'licenses'); Good = 'SPE_E3' }
                @{ Where = 'roles.sales.groups'; Segments = @('roles', 'sales', 'groups'); Good = 'All Staff' }
                @{ Where = 'defaults.protectedUsers'; Segments = @('defaults', 'protectedUsers'); Good = 'breakglass@example.com' }
                @{ Where = 'defaults.offboard.keepGroups'; Segments = @('defaults', 'offboard', 'keepGroups'); Good = 'Executives' }
            )) {
            foreach ($bad in @('', ' ', "`t", "  `n ")) {
                @{ Where = $case.Where; Segments = $case.Segments; Good = $case.Good; Bad = $bad }
            }
        }
    ) {
        $table = Get-ExampleTable
        Set-Nested $table $Segments @($Good, $Bad)
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject $table } ('$.' + $Where + '[1]')
    }

    It 'names the first element when it is the empty one' {
        $table = Get-ExampleTable
        Set-Nested $table @('roles', 'sales', 'groups') @('', 'All Staff')
        Assert-PolicyInvalid { Get-TenurePolicy -InputObject $table } '$.roles.sales.groups[0]'
    }

    It 'reports every empty element in Test-TenurePolicy' {
        $table = Get-ExampleTable
        Set-Nested $table @('roles', 'sales', 'groups') @('', 'All Staff', ' ')
        $result = Test-TenurePolicy -Path (Write-PolicyFile $table)
        $result.Valid | Should -BeFalse
        @($result.Errors).Count | Should -Be 2
        $result.Errors[0].StartsWith('$.roles.sales.groups[0]:') | Should -BeTrue
        $result.Errors[1].StartsWith('$.roles.sales.groups[2]:') | Should -BeTrue
    }

    It 'keeps ordinary entries, including ones with inner spaces, out of trouble' {
        $table = @{ version = 1; roles = @{ r = @{ groups = @('All Staff', ' padded ', 'a'); licenses = @('SPE_E3') } } }
        $managed = (Get-TenurePolicy -InputObject $table).ManagedSet
        @($managed.Groups | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count | Should -Be 0
        @($managed.Groups).Count | Should -Be 3
    }
}

Describe 'Get-TenurePolicy: files' {
    It 'throws Tenure.Policy.NotFound for a missing file' {
        { Get-TenurePolicy -Path (Join-Path $TestDrive 'nope.json') } | Should -Throw -ErrorId 'Tenure.Policy.NotFound'
    }

    It 'throws Tenure.Policy.NotFound for a directory' {
        { Get-TenurePolicy -Path $TestDrive } | Should -Throw -ErrorId 'Tenure.Policy.NotFound'
    }

    It 'throws Tenure.Policy.Invalid at $ for malformed JSON: <Name>' -ForEach @(
        @{ Name = 'truncated'; Text = '{ "version": 1, ' }
        @{ Name = 'empty'; Text = '' }
        @{ Name = 'whitespace only'; Text = "  `n " }
        @{ Name = 'trailing comma'; Text = '{ "version": 1, }' }
        @{ Name = 'single quotes'; Text = "{ 'version': 1 }" }
        @{ Name = 'a comment'; Text = "{ // note`n `"version`": 1 }" }
        @{ Name = 'trailing garbage'; Text = '{ "version": 1 } x' }
        @{ Name = 'top-level array'; Text = '[1, 2]' }
        @{ Name = 'top-level string'; Text = '"version"' }
        @{ Name = 'top-level null'; Text = 'null' }
        @{ Name = 'a duplicate key'; Text = '{ "version": 1, "version": 1 }' }
    ) {
        $path = Write-PolicyFile -Content $Text -Name 'bad.json'
        Assert-PolicyInvalid { Get-TenurePolicy -Path $path } '$'
    }

    It 'reads a UTF-8 file with a byte order mark' {
        $path = Join-Path $TestDrive 'bom.json'
        [System.IO.File]::WriteAllText($path, '{ "version": 1, "tenant": { "domain": "example.com" } }', [System.Text.UTF8Encoding]::new($true))
        (Get-TenurePolicy -Path $path).Tenant['domain'] | Should -Be 'example.com'
    }

    It 'keeps string values that look like dates as strings' {
        $path = Write-PolicyFile '{ "version": 1, "roles": { "r": { "department": "2026-10-08T00:00:00Z" } } }'
        (Get-TenurePolicy -Path $path).Roles['r']['Department'] | Should -Be '2026-10-08T00:00:00Z'
    }

    It 'resolves a relative path against the current location' {
        $null = Write-PolicyFile -Content '{ "version": 1 }' -Name 'relative.json'
        Push-Location $TestDrive
        try { (Get-TenurePolicy -Path 'relative.json').Path | Should -Be (Join-Path (Get-Location).Path 'relative.json') } finally { Pop-Location }
    }
}

Describe 'Test-TenurePolicy' {
    It 'returns Valid true and no errors for the example policy' {
        $result = Test-TenurePolicy -Path $script:ExamplePath
        $result | Should -BeOfType [hashtable]
        $result.Valid | Should -BeTrue
        @($result.Errors).Count | Should -Be 0
    }

    It 'lists every problem when invalid, each starting with its JSON path' {
        $table = Get-ExampleTable
        $table['defaults']['passwordLength'] = 'long'
        $table['roles']['sales']['bogus'] = 1
        $result = Test-TenurePolicy -Path (Write-PolicyFile $table)
        $result.Valid | Should -BeFalse
        @($result.Errors).Count | Should -Be 2
        $result.Errors | Where-Object { $_.StartsWith('$.defaults.passwordLength:') } | Should -Not -BeNullOrEmpty
        $result.Errors | Where-Object { $_.StartsWith('$.roles.sales.bogus:') } | Should -Not -BeNullOrEmpty
        , $result.Errors | Should -BeOfType [string[]]
    }

    It 'reports a missing file as invalid with one error and does not throw' {
        $result = Test-TenurePolicy -Path (Join-Path $TestDrive 'missing.json')
        $result.Valid | Should -BeFalse
        @($result.Errors).Count | Should -Be 1
        $result.Errors[0] | Should -Match 'missing.json'
    }

    It 'reports malformed JSON without throwing' {
        $result = Test-TenurePolicy -Path (Write-PolicyFile '{ nope' -Name 'broken.json')
        $result.Valid | Should -BeFalse
        $result.Errors[0].StartsWith('$:') | Should -BeTrue
    }

    It 'does not throw for an empty path' {
        $result = Test-TenurePolicy -Path ''
        $result.Valid | Should -BeFalse
        @($result.Errors).Count | Should -Be 1
    }
}

Describe 'New-TenurePolicy' {
    It 'writes the example policy byte for byte' {
        $target = Join-Path $TestDrive 'new.policy.json'
        New-TenurePolicy -Path $target
        [System.IO.File]::ReadAllBytes($target) | Should -Be ([System.IO.File]::ReadAllBytes($script:ExamplePath))
    }

    It 'writes a file that loads clean' {
        $target = Join-Path $TestDrive 'loads.policy.json'
        New-TenurePolicy -Path $target
        (Get-TenurePolicy -Path $target).Roles.Count | Should -Be 2
    }

    It 'refuses to overwrite an existing file and leaves it untouched' {
        $target = Join-Path $TestDrive 'exists.policy.json'
        Set-Content -LiteralPath $target -Value 'precious'
        { New-TenurePolicy -Path $target } | Should -Throw -ErrorId 'Tenure.Policy.Exists'
        (Get-Content -LiteralPath $target -Raw).Trim() | Should -Be 'precious'
    }

    It 'overwrites with -Force' {
        $target = Join-Path $TestDrive 'force.policy.json'
        Set-Content -LiteralPath $target -Value 'old'
        New-TenurePolicy -Path $target -Force
        [System.IO.File]::ReadAllBytes($target) | Should -Be ([System.IO.File]::ReadAllBytes($script:ExamplePath))
    }

    It 'writes nothing with -WhatIf' {
        $target = Join-Path $TestDrive 'whatif.policy.json'
        New-TenurePolicy -Path $target -WhatIf
        Test-Path -LiteralPath $target | Should -BeFalse
    }

    It 'leaves an existing file alone with -Force -WhatIf' {
        $target = Join-Path $TestDrive 'whatif-force.policy.json'
        Set-Content -LiteralPath $target -Value 'keep'
        New-TenurePolicy -Path $target -Force -WhatIf
        (Get-Content -LiteralPath $target -Raw).Trim() | Should -Be 'keep'
    }

    It 'supports ShouldProcess with Medium impact' {
        $attribute = (Get-Command New-TenurePolicy).ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attribute.SupportsShouldProcess | Should -BeTrue
        $attribute.ConfirmImpact | Should -Be 'Medium'
    }
}

Describe 'Resolve-TenurePolicyArgument and Get-TenurePolicyRole (private)' {
    It 'loads a policy from a path string' {
        $policy = Invoke-InTenure { param($p) Resolve-TenurePolicyArgument -Policy $p } @($script:ExamplePath)
        $policy.PSObject.TypeNames[0] | Should -Be 'Tenure.Policy'
        $policy.Roles.Count | Should -Be 2
    }

    It 'returns a Tenure.Policy unchanged (same object)' {
        $policy = Get-TenurePolicy -Path $script:ExamplePath
        $same = Invoke-InTenure { param($p) Resolve-TenurePolicyArgument -Policy $p } @($policy)
        [object]::ReferenceEquals($same, $policy) | Should -BeTrue
    }

    It 'throws Tenure.Policy.Invalid for anything else' -ForEach @(
        @{ Value = 42 }, @{ Value = @{ version = 1 } }, @{ Value = $null }, @{ Value = [pscustomobject]@{ Version = 1 } }
    ) {
        { Invoke-InTenure { param($p) Resolve-TenurePolicyArgument -Policy $p } @($Value) } | Should -Throw -ErrorId 'Tenure.Policy.Invalid'
    }

    It 'propagates NotFound for a path that does not exist' {
        { Invoke-InTenure { param($p) Resolve-TenurePolicyArgument -Policy $p } @((Join-Path $TestDrive 'gone.json')) } | Should -Throw -ErrorId 'Tenure.Policy.NotFound'
    }

    It 'returns the role hashtable by name' {
        $policy = Get-TenurePolicy -Path $script:ExamplePath
        $role = Invoke-InTenure { param($p) Get-TenurePolicyRole -Policy $p -Name 'warehouse' } @($policy)
        $role['Department'] | Should -Be 'Operations'
        $role['Licenses'] | Should -Be @('EXCHANGEDESKLESS')
    }

    It 'throws RoleNotFound listing the available roles' {
        $policy = Get-TenurePolicy -Path $script:ExamplePath
        $thrown = Get-ThrownError { Invoke-InTenure { param($p) Get-TenurePolicyRole -Policy $p -Name 'finance' } @($policy) }
        $thrown.FullyQualifiedErrorId | Should -Be 'Tenure.Policy.RoleNotFound'
        $thrown.Exception.Message | Should -Match 'finance'
        $thrown.Exception.Message | Should -Match 'warehouse'
        $thrown.Exception.Message | Should -Match 'sales'
    }

    It 'throws RoleNotFound for any name when roles is empty' {
        $policy = Get-TenurePolicy -InputObject @{ version = 1; roles = @{} }
        { Invoke-InTenure { param($p) Get-TenurePolicyRole -Policy $p -Name 'sales' } @($policy) } | Should -Throw -ErrorId 'Tenure.Policy.RoleNotFound'
        { Invoke-InTenure { param($p) Get-TenurePolicyRole -Policy $p -Name '' } @($policy) } | Should -Throw -ErrorId 'Tenure.Policy.RoleNotFound'
    }
}

Describe 'Shipped policy files' {
    It 'example policy is ASCII, LF only, and explains name resolution in a _comment' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ExamplePath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
        @($bytes | Where-Object { $_ -eq 13 }).Count | Should -Be 0
        $table = Get-ExampleTable
        $table['_comment'] | Should -Match 'plan'
        $table['_comment'] | Should -Match 'resolved'
        (Get-Content -LiteralPath $script:ExamplePath -Raw) | Should -Match '^\{\s*"_comment"'
    }

    It 'example policy uses example.com only' {
        $text = Get-Content -LiteralPath $script:ExamplePath -Raw
        $domains = [regex]::Matches($text, '[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})') | ForEach-Object { $_.Groups[1].Value }
        @($domains | Where-Object { $_ -ne 'example.com' }).Count | Should -Be 0
        (Get-ExampleTable)['tenant']['domain'] | Should -Be 'example.com'
    }

    It 'the example policy contains the two SPEC 2.1 roles' {
        $policy = Get-TenurePolicy -Path $script:ExamplePath
        $policy.Roles['sales']['Licenses'] | Should -Be @('SPE_E3')
        $policy.Roles['warehouse']['Licenses'] | Should -Be @('EXCHANGEDESKLESS')
        $policy.Roles['warehouse']['Groups'] | Should -Be @('Warehouse Users')
        $policy.Roles['warehouse']['Department'] | Should -Be 'Operations'
        $policy.Roles['warehouse']['JobTitle'] | Should -Be 'Warehouse Associate'
    }

    Context 'JSON Schema file' {
        BeforeAll { $script:schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable }

        It 'is draft-07 with additionalProperties false and an underscore pattern at every object level' {
            $script:schema['$schema'] | Should -Be 'http://json-schema.org/draft-07/schema#'
            $objects = [System.Collections.Generic.List[hashtable]]::new()
            $walk = {
                param($node)
                if ($node -is [hashtable]) {
                    if ($node['type'] -eq 'object') { $objects.Add($node) }
                    foreach ($value in $node.Values) { & $walk $value }
                }
            }
            & $walk $script:schema
            $objects.Count | Should -BeGreaterOrEqual 7
            foreach ($object in $objects) {
                $object['additionalProperties'] | Should -BeFalse
                $object['patternProperties'].ContainsKey('^_') | Should -BeTrue
            }
        }

        It 'lists exactly the keys the loader accepts at each level' {
            $keys = Invoke-InTenure { Get-TenurePolicyKeySet }
            @($script:schema['properties'].Keys | Sort-Object) | Should -Be @($keys['Top'] | Sort-Object)
            @($script:schema['properties']['tenant']['properties'].Keys | Sort-Object) | Should -Be @($keys['Tenant'] | Sort-Object)
            @($script:schema['properties']['defaults']['properties'].Keys | Sort-Object) | Should -Be @($keys['Defaults'] | Sort-Object)
            @($script:schema['properties']['defaults']['properties']['offboard']['properties'].Keys | Sort-Object) | Should -Be @($keys['Offboard'] | Sort-Object)
            @($script:schema['properties']['defaults']['properties']['offboard']['properties']['autoReply']['properties'].Keys | Sort-Object) | Should -Be @($keys['AutoReply'] | Sort-Object)
            @($script:schema['definitions']['role']['properties'].Keys | Sort-Object) | Should -Be @($keys['Role'] | Sort-Object)
        }

        It 'agrees with the loader on the example policy and on broken variants' -Skip:($PSVersionTable.PSVersion.Major -lt 7 -or ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 4)) {
            $cases = [System.Collections.Generic.List[object]]::new()
            $cases.Add((Get-ExampleTable))
            foreach ($mutation in @(
                    { param($t) $t['version'] = 2 }
                    { param($t) $t['bogus'] = 1 }
                    { param($t) $t['defaults']['passwordLength'] = 'x' }
                    { param($t) $t['defaults']['passwordLength'] = 7 }
                    { param($t) $t['defaults']['passwordLength'] = 8 }
                    { param($t) $t['defaults']['passwordLength'] = 256 }
                    { param($t) $t['defaults']['passwordLength'] = 257 }
                    { param($t) $t['roles']['sales']['groups'] = @('All Staff', '') }
                    { param($t) $t['roles']['sales']['licenses'] = @(' ') }
                    { param($t) $t['defaults']['protectedUsers'] = @("`t") }
                    { param($t) $t['defaults']['offboard']['keepGroups'] = @('Execs', '  ') }
                    { param($t) $t['defaults']['offboard']['forwardTo'] = 'Manager' }
                    { param($t) $t['defaults']['offboard']['devices'] = 'wipeAll' }
                    { param($t) $t['roles']['bad name'] = @{} }
                    { param($t) $t['roles']['_comment'] = 'fine' }
                    { param($t) $t['roles']['sales']['licenses'] = 'SPE_E3' }
                    { param($t) $t['tenant']['_comment'] = 5 }
                    { param($t) $t.Remove('version') }
                )) {
                $copy = Get-ExampleTable
                & $mutation $copy
                $cases.Add($copy)
            }
            foreach ($case in $cases) {
                $json = ConvertTo-Json -InputObject $case -Depth 20
                $bySchema = Test-Json -Json $json -SchemaFile $script:SchemaPath -ErrorAction SilentlyContinue
                $byLoader = (Get-ThrownError { Get-TenurePolicy -InputObject $case }) -eq $null
                $bySchema | Should -Be $byLoader -Because $json
            }
        }
    }
}
