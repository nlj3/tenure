BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    $global:FakeGraphSleeps = [System.Collections.Generic.List[int]]::new()

    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
    Mock -ModuleName Tenure Start-Sleep { $global:FakeGraphSleeps.Add([int]$Seconds) }

    function Get-Canonical($Object) { Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $Object) }
    function New-Context([string]$SubjectId) {
        $context = @{ Secrets = @{}; StepId = 'S13'; Mode = 'Apply' }
        if ($SubjectId) { $context.Subject = @{ Id = $SubjectId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice Example' } }
        $context
    }
    function New-Target([string]$UserId, [string]$Upn = 'alice@example.com') { @{ Kind = 'drive'; Id = $UserId; Name = $Upn } }
    function Get-AlicePermissions { $global:FakeGraphWorld.Drives[$global:FakeGraphWorld.Ids.AliceId].permissions }
    function Add-Permission([string]$Id, [string[]]$Roles, [hashtable]$Shape) {
        $permission = @{ id = $Id; roles = $Roles }
        foreach ($key in $Shape.Keys) { $permission[$key] = $Shape[$key] }
        $global:FakeGraphWorld.Drives[$global:FakeGraphWorld.Ids.AliceId].permissions.Add($permission)
    }
    function Get-Writes([string]$Method) { @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method $Method -UriLike '*/drives/*') }
    # 200 responses for the next two requests (the drive, then its permissions), so a fault can hit the write that follows.
    function Add-DriveRead([object[]]$Permissions = @()) {
        $world = $global:FakeGraphWorld
        $world.Faults.Enqueue(@{ Status = 200; Body = @{ id = $world.Ids.AliceDriveId; driveType = 'business' } })
        $world.Faults.Enqueue(@{ Status = 200; Body = @{ value = @($Permissions) } })
    }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeGraphSleeps -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'OneDrive.Access' {
    BeforeAll {
        $script:provider = Get-TenureProvider -Name 'OneDrive.Access'
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    It 'is registered as a Medium-risk reversible State provider with Files.ReadWrite.All' {
        $provider.Kind | Should -BeExactly 'State'
        $provider.Backend | Should -BeExactly 'Graph'
        $provider.Risk | Should -BeExactly 'Medium'
        $provider.Reversible | Should -BeExactly $true
        @($provider.Scopes) | Should -Be @('Files.ReadWrite.All')
    }

    Context 'Get' {
        It 'reads the drive id, web URL and an empty grantee list for a drive nobody else can open' {
            $current = & $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId)
            $current | Should -BeOfType [pscustomobject]
            @($current.PSObject.Properties.Name | Sort-Object) | Should -Be @('driveId', 'grantees', 'webUrl')
            $current.driveId | Should -BeExactly $ids.AliceDriveId
            $current.webUrl | Should -BeExactly 'https://example-my.sharepoint.com/personal/alice_example_com/Documents'
            , $current.grantees | Should -BeOfType [object[]]
            @($current.grantees).Count | Should -Be 0
        }

        It 'asks for the drive with $select and then lists the root permissions' {
            & $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId) | Out-Null
            $w.Calls[0].Uri | Should -BeExactly "https://graph.microsoft.com/v1.0/users/$($ids.AliceId)/drive?`$select=id,driveType,webUrl"
            $w.Calls[1].Uri | Should -BeExactly 'https://graph.microsoft.com/v1.0/drives/b%21fake-drive-alice-0001/root/permissions'
        }

        It 'reads the grantee address from grantedToV2.user, grantedToV2.siteUser, grantedTo.user or invitation, lowercased' {
            Add-Permission 'p-v2' @('write') @{ grantedToV2 = @{ user = @{ email = 'Bob@Example.com'; displayName = 'Bob Manager' } } }
            Add-Permission 'p-site' @('read') @{ grantedToV2 = @{ siteUser = @{ email = 'erin@example.com'; loginName = 'i:0#.f|membership|erin@example.com' } } }
            Add-Permission 'p-v1' @('read') @{ grantedTo = @{ user = @{ email = 'CAROL@example.com' } } }
            Add-Permission 'p-invite' @('write') @{ invitation = @{ email = 'guest@example.com'; signInRequired = $true } }
            Add-Permission 'p-fallback' @('read') @{ grantedToV2 = @{ user = @{ displayName = 'No Address' } }; invitation = @{ email = 'frank@example.com' } }
            $current = & $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId)
            @($current.grantees | ForEach-Object { $_.email }) | Should -Be @('bob@example.com', 'carol@example.com', 'erin@example.com', 'frank@example.com', 'guest@example.com')
            ($current.grantees | Where-Object email -EQ 'bob@example.com').permissionId | Should -BeExactly 'p-v2'
            ($current.grantees | Where-Object email -EQ 'erin@example.com').permissionId | Should -BeExactly 'p-site'
            ($current.grantees | Where-Object email -EQ 'carol@example.com').permissionId | Should -BeExactly 'p-v1'
            ($current.grantees | Where-Object email -EQ 'guest@example.com').permissionId | Should -BeExactly 'p-invite'
            ($current.grantees | Where-Object email -EQ 'frank@example.com').permissionId | Should -BeExactly 'p-fallback'
            @($current.grantees[0].PSObject.Properties.Name | Sort-Object) | Should -Be @('email', 'permissionId', 'roles')
        }

        It 'skips permissions with no single address (sharing links) and tolerates missing roles' {
            Add-Permission 'p-link' @('read') @{ link = @{ type = 'view'; scope = 'organization' } }
            $w.Drives[$ids.AliceId].permissions.Add(@{ id = 'p-noroles'; grantedToV2 = @{ user = @{ email = 'bob@example.com' } } })
            $current = & $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId)
            @($current.grantees).Count | Should -Be 1
            $current.grantees[0].email | Should -BeExactly 'bob@example.com'
            @($current.grantees[0].roles).Count | Should -Be 0
        }

        It 'sorts roles and lowercases them' {
            Add-Permission 'p1' @('Write', 'read') @{ grantedToV2 = @{ user = @{ email = 'bob@example.com' } } }
            @((& $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId)).grantees[0].roles) | Should -Be @('read', 'write')
        }

        It 'follows paging on the permission list' {
            foreach ($n in 1..5) { Add-Permission "p$n" @('read') @{ grantedToV2 = @{ user = @{ email = "user$n@example.com" } } } }
            @((& $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId)).grantees).Count | Should -Be 5
            @(Get-FakeGraphCall -World $w -Method GET -UriLike '*root/permissions*').Count | Should -Be 3
        }

        It 'throws Tenure.Provider.TargetNotFound when the OneDrive was never provisioned, the user is unknown, or the target has no id' {
            { & $provider.Get (New-Target $ids.BobId 'bob@example.com') (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            { & $provider.Get (New-Target '99999999-9999-4999-8999-999999999999') (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            { & $provider.Get (New-Target $null) (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'a 403 stays Tenure.Graph.Forbidden' {
            Add-FakeGraphFault -World $w -Status 403 -Code 'accessDenied'
            { & $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }

        It 'fingerprint stability: the snapshot does not depend on the order Graph lists permissions in' {
            Add-Permission 'p-b' @('write') @{ grantedToV2 = @{ user = @{ email = 'bob@example.com' } } }
            Add-Permission 'p-a' @('read', 'write') @{ invitation = @{ email = 'bob@example.com' } }
            Add-Permission 'p-c' @('read') @{ grantedTo = @{ user = @{ email = 'carol@example.com' } } }
            $first = Get-Canonical (& $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId))
            $first | Should -BeExactly (Get-Canonical (& $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId)))
            $w.Drives[$ids.AliceId].permissions.Reverse()
            Get-Canonical (& $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId)) | Should -BeExactly $first
        }
    }

    Context 'Test' {
        BeforeAll {
            function New-Current([object[]]$Grantees) { [pscustomobject]@{ driveId = 'b!x'; webUrl = $null; grantees = $Grantees } }
            function New-Grantee([string]$Email, [string[]]$Roles) { [pscustomobject]@{ email = $Email; roles = $Roles; permissionId = "p-$Email" } }
        }

        It 'present $true needs the role, or a stronger one, on that address' {
            $current = New-Current @((New-Grantee 'bob@example.com' @('write')))
            (& $provider.Test $current @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true }) | Should -BeTrue
            (& $provider.Test $current @{ granteeEmail = 'bob@example.com'; role = 'read'; present = $true }) | Should -BeTrue
            (& $provider.Test (New-Current @((New-Grantee 'bob@example.com' @('read')))) @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true }) | Should -BeFalse
            (& $provider.Test (New-Current @((New-Grantee 'bob@example.com' @('owner')))) @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true }) | Should -BeTrue
            (& $provider.Test $current @{ granteeEmail = 'carol@example.com'; role = 'write'; present = $true }) | Should -BeFalse
        }

        It 'matches the address ignoring case and surrounding spaces' {
            $current = New-Current @((New-Grantee 'bob@example.com' @('write')))
            (& $provider.Test $current @{ granteeEmail = ' BOB@Example.COM '; role = 'write'; present = $true }) | Should -BeTrue
            (& $provider.Test $current @{ granteeEmail = 'BOB@EXAMPLE.COM'; present = $false }) | Should -BeFalse
        }

        It 'present $false means no grantee with that address at all, whatever its role' {
            $current = New-Current @((New-Grantee 'bob@example.com' @('read')), (New-Grantee 'carol@example.com' @('write')))
            (& $provider.Test $current @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $false }) | Should -BeFalse
            (& $provider.Test $current @{ granteeEmail = 'dave@example.com'; present = $false }) | Should -BeTrue
            (& $provider.Test (New-Current @()) @{ granteeEmail = 'bob@example.com'; present = $false }) | Should -BeTrue
        }

        It 'present defaults to $true' {
            (& $provider.Test (New-Current @((New-Grantee 'bob@example.com' @('write')))) @{ granteeEmail = 'bob@example.com'; role = 'write' }) | Should -BeTrue
            (& $provider.Test (New-Current @()) @{ granteeEmail = 'bob@example.com'; role = 'write' }) | Should -BeFalse
        }

        It 'is false for a missing current object, a missing address, a bad role or a non-boolean present' {
            $current = New-Current @((New-Grantee 'bob@example.com' @('write')))
            (& $provider.Test $null @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true }) | Should -BeFalse
            (& $provider.Test $current @{ role = 'write'; present = $true }) | Should -BeFalse
            (& $provider.Test $current @{ granteeEmail = 'bob@example.com'; role = 'owner'; present = $true }) | Should -BeFalse
            (& $provider.Test $current @{ granteeEmail = 'bob@example.com'; role = 'write'; present = 'true' }) | Should -BeFalse
        }

        It 'accepts an imported (PSCustomObject) Desired and Current' {
            $current = '{"driveId":"b!x","webUrl":null,"grantees":[{"email":"bob@example.com","roles":["write"],"permissionId":"p1"}]}' | ConvertFrom-Json
            (& $provider.Test $current ([pscustomobject]@{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true })) | Should -BeTrue
        }
    }

    Context 'Set: grant' {
        It 'invites with no email and sign-in required, then Get and Test agree' {
            $desired = @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true }
            $observed = & $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId)
            (& $provider.Test $observed $desired) | Should -BeTrue
            (& $provider.Test (& $provider.Get (New-Target $ids.AliceId) (New-Context $ids.AliceId)) $desired) | Should -BeTrue

            $posts = @(Get-Writes POST)
            $posts.Count | Should -Be 1
            $posts[0].Uri | Should -BeExactly 'https://graph.microsoft.com/v1.0/drives/b%21fake-drive-alice-0001/root/invite'
            $body = $posts[0].Body | ConvertFrom-Json -AsHashtable
            @($body.Keys | Sort-Object) | Should -Be @('recipients', 'requireSignIn', 'roles', 'sendInvitation')
            $body.sendInvitation | Should -BeExactly $false
            $body.requireSignIn | Should -BeExactly $true
            @($body.roles) | Should -Be @('write')
            @($body.recipients).Count | Should -Be 1
            $body.recipients[0].email | Should -BeExactly 'bob@example.com'
            @(Get-AlicePermissions).Count | Should -Be 1
        }

        It 'grants read when asked for read' {
            $observed = & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'carol@example.com'; role = 'read'; present = $true } $null (New-Context $ids.AliceId)
            @($observed.grantees[0].roles) | Should -Be @('read')
            @((@(Get-Writes POST)[0].Body | ConvertFrom-Json).roles) | Should -Be @('read')
        }

        It 'a second Set is harmless: no second invite, Test stays true' {
            $desired = @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true }
            & $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId) | Out-Null
            $again = & $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId)
            (& $provider.Test $again $desired) | Should -BeTrue
            @(Get-Writes POST).Count | Should -Be 1
            @(Get-AlicePermissions).Count | Should -Be 1
        }

        It 'an existing grant under a different case is already satisfied and sends nothing' {
            Add-Permission 'p-bob' @('write') @{ grantedToV2 = @{ user = @{ email = 'Bob@Example.com' } } }
            $observed = & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'BOB@example.com'; role = 'write'; present = $true } $null (New-Context $ids.AliceId)
            (& $provider.Test $observed @{ granteeEmail = 'BOB@example.com'; role = 'write'; present = $true }) | Should -BeTrue
            @(Get-Writes POST).Count | Should -Be 0
        }

        It 'treats Graph''s "already exists" 400 as success' {
            Add-Permission 'p-bob' @('write') @{ grantedToV2 = @{ user = @{ email = 'bob@example.com' } } }
            # Graph's first read does not show the grant yet (replication lag), so Set invites and is told it exists.
            Add-DriveRead
            Add-FakeGraphFault -World $w -Status 400 -Code 'invalidRequest' -Message 'The permission already exists for this recipient.'
            $desired = @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true }
            $observed = & $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId)
            (& $provider.Test $observed $desired) | Should -BeTrue
        }

        It 'a different 400 is not swallowed' {
            Add-DriveRead
            Add-FakeGraphFault -World $w -Status 400 -Code 'invalidRequest' -Message 'Recipient address is not valid.'
            { & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
        }

        It 'a 429 with Retry-After on the invite then success is transparent and grants once' {
            Add-DriveRead
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('2') }
            $desired = @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true }
            (& $provider.Test (& $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId)) $desired) | Should -BeTrue
            @($global:FakeGraphSleeps) | Should -Be @(2)
            @(Get-AlicePermissions).Count | Should -Be 1
        }

        It 'a 403 on the invite surfaces as Tenure.Graph.Forbidden and grants nothing' {
            Add-DriveRead
            Add-FakeGraphFault -World $w -Status 403 -Code 'accessDenied' -Message 'Access denied.'
            { & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
            @(Get-AlicePermissions).Count | Should -Be 0
        }

        It 'a user with no OneDrive is TargetNotFound and nothing is sent' {
            { & $provider.Set (New-Target $ids.BobId 'bob@example.com') @{ granteeEmail = 'alice@example.com'; role = 'write'; present = $true } $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            @(Get-Writes POST).Count | Should -Be 0
        }
    }

    Context 'Set: remove' {
        It 'deletes every permission held by that address (any case, any shape), leaves the rest, and Test is true' {
            Add-Permission 'p-bob-1' @('write') @{ grantedToV2 = @{ user = @{ email = 'Bob@Example.com' } } }
            Add-Permission 'p-bob-2' @('read') @{ invitation = @{ email = 'bob@example.com' } }
            Add-Permission 'p-carol' @('write') @{ grantedToV2 = @{ user = @{ email = 'carol@example.com' } } }
            $desired = @{ granteeEmail = 'BOB@example.com'; present = $false }
            $observed = & $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId)
            (& $provider.Test $observed $desired) | Should -BeTrue
            $deletes = @(Get-Writes DELETE)
            $deletes.Count | Should -Be 2
            @($deletes | ForEach-Object { ($_.Uri -split '/')[-1] } | Sort-Object) | Should -Be @('p-bob-1', 'p-bob-2')
            $deletes[0].Uri | Should -BeLike 'https://graph.microsoft.com/v1.0/drives/b%21fake-drive-alice-0001/root/permissions/p-bob-*'
            @(Get-AlicePermissions | ForEach-Object { $_['id'] }) | Should -Be @('p-carol')
        }

        It 'removing an address that has no access sends nothing and is satisfied' {
            Add-Permission 'p-carol' @('write') @{ grantedToV2 = @{ user = @{ email = 'carol@example.com' } } }
            $desired = @{ granteeEmail = 'bob@example.com'; present = $false }
            (& $provider.Test (& $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId)) $desired) | Should -BeTrue
            @(Get-Writes DELETE).Count | Should -Be 0
            @(Get-AlicePermissions).Count | Should -Be 1
        }

        It 'a permission already gone (404 on DELETE) is the goal state' {
            $gone = @{ id = 'p-gone'; roles = @('write'); grantedToV2 = @{ user = @{ email = 'bob@example.com' } } }
            Add-DriveRead -Permissions @($gone)
            $desired = @{ granteeEmail = 'bob@example.com'; present = $false }
            $observed = & $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId)
            (& $provider.Test $observed $desired) | Should -BeTrue
            @(Get-Writes DELETE).Count | Should -Be 1
        }

        It 'a 403 on DELETE is not mistaken for "already gone"' {
            Add-Permission 'p-bob' @('write') @{ grantedToV2 = @{ user = @{ email = 'bob@example.com' } } }
            Add-DriveRead -Permissions @(@{ id = 'p-bob'; roles = @('write'); grantedToV2 = @{ user = @{ email = 'bob@example.com' } } })
            Add-FakeGraphFault -World $w -Status 403 -Code 'accessDenied'
            { & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'bob@example.com'; present = $false } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
            @(Get-AlicePermissions).Count | Should -Be 1
        }

        It 'refuses to remove an owner permission and deletes nothing, not even that address''s other permissions' {
            Add-Permission 'p-alice-write' @('write') @{ grantedToV2 = @{ user = @{ email = 'alice@example.com' } } }
            Add-Permission 'p-alice-owner' @('owner') @{ grantedToV2 = @{ siteUser = @{ email = 'alice@example.com' } } }
            { & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'alice@example.com'; present = $false } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-Writes DELETE).Count | Should -Be 0
            @(Get-AlicePermissions).Count | Should -Be 2
        }

        It 'does not need a role to remove' {
            Add-Permission 'p-bob' @('read') @{ grantedToV2 = @{ user = @{ email = 'bob@example.com' } } }
            (& $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'bob@example.com'; present = $false } $null (New-Context $ids.AliceId)).grantees | Should -BeNullOrEmpty
        }

        It 'grant then remove returns to the start (Reversible)' {
            $target = New-Target $ids.AliceId
            $before = Get-Canonical (& $provider.Get $target (New-Context $ids.AliceId))
            & $provider.Set $target @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true } $null (New-Context $ids.AliceId) | Out-Null
            & $provider.Set $target @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $false } $null (New-Context $ids.AliceId) | Out-Null
            Get-Canonical (& $provider.Get $target (New-Context $ids.AliceId)) | Should -BeExactly $before
        }
    }

    Context 'Set: refusals (nothing is sent)' {
        It 'refuses to change a OneDrive that is not the plan subject''s own' {
            $failure = { & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true } $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition' -PassThru
            $failure.Exception.Message | Should -Match $ids.BobId
            $w.Calls.Count | Should -Be 0
            @(Get-AlicePermissions).Count | Should -Be 0
        }

        It 'refuses without a plan subject id (<case>)' -ForEach @(
            @{ case = 'no Subject'; ctx = @{ Secrets = @{} } }
            @{ case = 'empty Id'; ctx = @{ Subject = @{ Id = '' } } }
            @{ case = 'null Context'; ctx = $null }
        ) {
            { & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true } $null $ctx } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            $w.Calls.Count | Should -Be 0
        }

        It 'matches the subject id ignoring case' {
            & $provider.Set (New-Target $ids.AliceId) @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true } $null (New-Context $ids.AliceId.ToUpperInvariant()) | Out-Null
            @(Get-AlicePermissions).Count | Should -Be 1
        }

        It 'refuses a bad Desired (<case>) with InvalidDesired' -ForEach @(
            @{ case = 'no address'; desired = @{ role = 'write'; present = $true } }
            @{ case = 'not an address'; desired = @{ granteeEmail = 'bob'; role = 'write'; present = $true } }
            @{ case = 'owner role'; desired = @{ granteeEmail = 'bob@example.com'; role = 'owner'; present = $true } }
            @{ case = 'no role on a grant'; desired = @{ granteeEmail = 'bob@example.com'; present = $true } }
            @{ case = 'string present'; desired = @{ granteeEmail = 'bob@example.com'; role = 'write'; present = 'false' } }
            @{ case = 'misspelt present'; desired = @{ granteeEmail = 'bob@example.com'; role = 'write'; presnt = $false } }
        ) {
            { & $provider.Set (New-Target $ids.AliceId) $desired $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            $w.Calls.Count | Should -Be 0
        }
    }

    Context 'Describe' {
        It 'says who gets which access to whose OneDrive, and that no invitation email is sent' {
            $line = & $provider.Describe (New-Target $ids.AliceId 'alice@example.com') $null @{ granteeEmail = 'bob@example.com'; role = 'write'; present = $true } 'Create'
            $line | Should -BeExactly "grant bob@example.com write access to alice@example.com's OneDrive (no invitation email)"
            $line | Should -Match 'no invitation email'
        }

        It 'describes a removal' {
            (& $provider.Describe (New-Target $ids.AliceId 'alice@example.com') $null @{ granteeEmail = 'bob@example.com'; present = $false } 'Remove') | Should -BeExactly "remove bob@example.com's access to alice@example.com's OneDrive"
        }

        It 'copes with an incomplete Desired' {
            (& $provider.Describe (New-Target $ids.AliceId 'alice@example.com') $null $null 'Create') | Should -BeExactly "grant (no grantee) (no role) access to alice@example.com's OneDrive (no invitation email)"
        }
    }
}
