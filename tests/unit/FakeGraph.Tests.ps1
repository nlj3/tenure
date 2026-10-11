BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    $global:FakeGraphSleeps = [System.Collections.Generic.List[int]]::new()
    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
    Mock -ModuleName Tenure Start-Sleep { $global:FakeGraphSleeps.Add([int]$Seconds) }

    # Raw fake call (status + body, no seam error mapping).
    function Send([string]$Method, [string]$Uri, $Body = $null) {
        Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
    }
    # Through the real seam, so Tenure.Graph.* mapping and -All paging are exercised.
    function Invoke-Graph { Invoke-InTenure { param($p) Invoke-TenureGraph @p } @(, $args[0]) }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeGraphSleeps -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'FakeGraph world' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    It 'seeds the four users, with carol as the signed-in account and dave soft-deleted' {
        @($w.Users.userPrincipalName) | Should -Be @('alice@example.com', 'bob@example.com', 'carol@example.com')
        @($w.DeletedUsers.userPrincipalName) | Should -Be @('dave@example.com')
        $w.Me | Should -Be $ids.CarolId
        $w.PageSize | Should -Be 2
    }

    It 'seeds fixed GUID ids that are unique' {
        $guids = @($ids.Keys | Where-Object { $_ -ne 'AliceDriveId' } | ForEach-Object { $ids[$_] })
        $guids | ForEach-Object { { [guid]$_ } | Should -Not -Throw }
        @($guids | Select-Object -Unique).Count | Should -Be $guids.Count
    }

    It 'seeds alice with bob as manager, a direct SPE_E3 license and three devices' {
        $alice = $w.Users | Where-Object id -eq $ids.AliceId
        $alice.managerId | Should -Be $ids.BobId
        @($alice.assignedLicenses.skuId) | Should -Be @($ids.SkuE3Id)
        $alice.licenseAssignmentStates[0].assignedByGroup | Should -BeNullOrEmpty
        @($w.ManagedDevices | Where-Object userId -eq $ids.AliceId | ForEach-Object ownerType | Sort-Object) | Should -Be @('company', 'personal', 'unknown')
        $w.Drives[$ids.AliceId].id | Should -Be $ids.AliceDriveId
    }

    It 'seeds bob with SPE_E3 assigned by the All Staff group' {
        $bob = $w.Users | Where-Object id -eq $ids.BobId
        $bob.licenseAssignmentStates[0].assignedByGroup | Should -Be $ids.AllStaffGroupId
    }

    It 'seeds the four group shapes' {
        $sales = $w.Groups | Where-Object id -eq $ids.SalesGroupId
        $sales.groupTypes | Should -Contain 'Unified'
        $sales.mail | Should -Be 'sales@example.com'
        $dynamic = $w.Groups | Where-Object id -eq $ids.DynamicGroupId
        $dynamic.groupTypes | Should -Contain 'DynamicMembership'
        $dynamic.membershipRule | Should -Not -BeNullOrEmpty
        $legal = $w.Groups | Where-Object id -eq $ids.LegalDlGroupId
        $legal.mailEnabled | Should -BeTrue
        $legal.securityEnabled | Should -BeTrue
        $legal.groupTypes | Should -Not -Contain 'Unified'
        ($w.Groups | Where-Object id -eq $ids.AllStaffGroupId).securityEnabled | Should -BeTrue
    }

    It 'seeds the three SKUs with the agreed unit counts' {
        $e3 = $w.SubscribedSkus | Where-Object skuPartNumber -eq 'SPE_E3'
        ($e3.prepaidUnits.enabled - $e3.consumedUnits) | Should -Be 7
        $desk = $w.SubscribedSkus | Where-Object skuPartNumber -eq 'EXCHANGEDESKLESS'
        ($desk.prepaidUnits.enabled - $desk.consumedUnits) | Should -Be 0
        $voice = $w.SubscribedSkus | Where-Object skuPartNumber -eq 'MCOEV'
        ($voice.prepaidUnits.enabled - $voice.consumedUnits) | Should -Be 2
    }

    It 'seeds carol into the Global Administrator role' {
        $role = $w.DirectoryRoles | Where-Object displayName -eq 'Global Administrator'
        $role.members | Should -Contain $ids.CarolId
    }

    It 'Reset-FakeGraphWorld gives a clean world with no calls' {
        Send GET 'me' | Out-Null
        $w.Calls.Count | Should -Be 1
        Reset-FakeGraphWorld
        $global:FakeGraphWorld.Calls.Count | Should -Be 0
    }
}

Describe 'FakeGraph request routing' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    Context 'response shape' {
        It 'returns Status, Headers and a PSCustomObject Body round-tripped through JSON' {
            $r = Send GET 'users/alice@example.com'
            $r.Status | Should -Be 200
            $r.Headers | Should -BeOfType [hashtable]
            $r.Headers['request-id'] | Should -Not -BeNullOrEmpty
            $r.Body | Should -BeOfType [pscustomobject]
            $r.Body.userPrincipalName | Should -Be 'alice@example.com'
            $r.Body.assignedLicenses[0] | Should -BeOfType [pscustomobject]
        }

        It 'records every call, with the absolute URI the seam sent' {
            Invoke-Graph @{ Method = 'GET'; Uri = 'users/alice@example.com' } | Out-Null
            $w.Calls.Count | Should -Be 1
            $w.Calls[0].Method | Should -Be 'GET'
            $w.Calls[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/users/alice@example.com'
        }

        It 'serves 204 as a null body' {
            $r = Send PATCH "users/$($ids.AliceId)" @{ department = 'Ops' }
            $r.Status | Should -Be 204
            $r.Body | Should -BeNullOrEmpty
        }

        It 'answers an unknown route with a Graph-style 404' {
            $r = Send GET 'nothing/here'
            $r.Status | Should -Be 404
            $r.Body.error.code | Should -Be 'Request_ResourceNotFound'
            $r.Body.error.message | Should -Not -BeNullOrEmpty
        }

        It 'maps the unknown route to Tenure.Graph.NotFound through the seam' {
            { Invoke-Graph @{ Method = 'GET'; Uri = 'nothing/here' } } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
        }

        It 'accepts /beta/ and absolute URIs' {
            (Send GET 'https://graph.microsoft.com/beta/users/alice@example.com').Status | Should -Be 200
            (Send GET '/beta/users/alice@example.com').Status | Should -Be 200
            (Send GET '/users/alice@example.com').Status | Should -Be 200
        }

        It 'decodes URL-escaped path segments' {
            (Send GET 'users/alice%40example.com').Body.id | Should -Be $ids.AliceId
        }
    }

    Context 'users' {
        It 'GET users/{id} works by object id and by UPN, case-insensitively' {
            (Send GET "users/$($ids.AliceId)").Body.userPrincipalName | Should -Be 'alice@example.com'
            (Send GET 'users/ALICE@example.com').Body.id | Should -Be $ids.AliceId
        }

        It 'GET of an unknown user is 404 with the key in the message' {
            $r = Send GET 'users/nobody@example.com'
            $r.Status | Should -Be 404
            $r.Body.error.message | Should -Match 'nobody@example.com'
        }

        It 'hides internal fields (managerId) from responses' {
            (Send GET 'users/alice@example.com').Body.PSObject.Properties.Name | Should -Not -Contain 'managerId'
        }

        It 'a soft-deleted user is not addressable under users/' {
            (Send GET 'users/dave@example.com').Status | Should -Be 404
        }

        It 'GET me returns the signed-in account' {
            (Send GET 'me').Body.userPrincipalName | Should -Be 'carol@example.com'
        }

        It 'GET directory/deletedItems/microsoft.graph.user filters soft-deleted users' {
            $r = Send GET 'directory/deletedItems/microsoft.graph.user?$filter=userPrincipalName eq ''dave@example.com'''
            @($r.Body.value).Count | Should -Be 1
            $r.Body.value[0].id | Should -Be $ids.DaveId
            $r.Body.value[0].deletedDateTime | Should -Not -BeNullOrEmpty
            @((Send GET 'directory/deletedItems/microsoft.graph.user?$filter=userPrincipalName eq ''alice@example.com''').Body.value).Count | Should -Be 0
        }

        It 'PATCH applies keys, canonicalizes their case and 400s on unknown properties' {
            (Send PATCH 'users/alice@example.com' @{ Department = 'Ops'; employeeType = 'Contractor' }).Status | Should -Be 204
            $alice = (Send GET 'users/alice@example.com').Body
            $alice.department | Should -Be 'Ops'
            $alice.employeeType | Should -Be 'Contractor'
            $r = Send PATCH 'users/alice@example.com' @{ favoriteColor = 'blue' }
            $r.Status | Should -Be 400
            $r.Body.error.code | Should -Be 'Request_BadRequest'
        }

        It 'PATCH validates accountEnabled and usageLocation shapes' {
            (Send PATCH 'users/alice@example.com' @{ accountEnabled = 'no' }).Status | Should -Be 400
            (Send PATCH 'users/alice@example.com' @{ usageLocation = 'USA' }).Status | Should -Be 400
            (Send PATCH 'users/alice@example.com' @{ accountEnabled = $false }).Status | Should -Be 204
            (Send GET 'users/alice@example.com?$select=accountEnabled').Body.accountEnabled | Should -BeFalse
        }

        It 'PATCH never stores a passwordProfile and checks its complexity' {
            (Send PATCH 'users/alice@example.com' @{ passwordProfile = @{ password = 'short'; forceChangePasswordNextSignIn = $true } }).Status | Should -Be 400
            (Send PATCH 'users/alice@example.com' @{ passwordProfile = @{ password = 'Str0ng!Passw0rd'; forceChangePasswordNextSignIn = $true } }).Status | Should -Be 204
            ($w.Users | Where-Object id -eq $ids.AliceId).Keys | Should -Not -Contain 'passwordProfile'
            ($w.Users | ConvertTo-Json -Depth 10) | Should -Not -Match 'Str0ng!Passw0rd'
        }
    }

    Context 'POST users' {
        BeforeEach {
            $script:newUser = @{
                userPrincipalName = 'erin@example.com'; mailNickname = 'erin'; displayName = 'Erin Example'; accountEnabled = $true
                passwordProfile   = @{ forceChangePasswordNextSignIn = $true; password = 'Zk7#mQ4!vRt9wXp2' }
            }
        }

        It 'creates the user, assigns a new guid and answers 201 with the user' {
            $r = Send POST 'users' $newUser
            $r.Status | Should -Be 201
            { [guid]$r.Body.id } | Should -Not -Throw
            $r.Body.userPrincipalName | Should -Be 'erin@example.com'
            (Send GET 'users/erin@example.com').Body.id | Should -Be $r.Body.id
        }

        It 'never stores the password, in the world or in the call log' {
            Send POST 'users' $newUser | Out-Null
            $stored = $w.Users | Where-Object userPrincipalName -eq 'erin@example.com'
            $stored.Keys | Should -Not -Contain 'passwordProfile'
            ($w.Users | ConvertTo-Json -Depth 10) | Should -Not -Match 'Zk7#mQ4!vRt9wXp2'
            ($w.Calls | ConvertTo-Json -Depth 10) | Should -Not -Match 'Zk7#mQ4!vRt9wXp2'
            ($w | ConvertTo-Json -Depth 10) | Should -Not -Match 'Zk7#mQ4!vRt9wXp2'
        }

        It 'logs a SHA-256 digest of the password instead, so a test can still match it' {
            Send POST 'users' $newUser | Out-Null
            $expected = Get-FakeGraphSha256 -Text 'Zk7#mQ4!vRt9wXp2'
            $w.Calls[-1].Body | Should -Match "redacted:sha256:$expected"
            @($w.SecretDigests | Where-Object { $_.Kind -eq 'password' -and $_.Sha256 -eq $expected }).Count | Should -Be 1
        }

        It 'leaves a new user without mail, licenses or manager' {
            Send POST 'users' $newUser | Out-Null
            $stored = $w.Users | Where-Object userPrincipalName -eq 'erin@example.com'
            $stored.mail | Should -BeNullOrEmpty
            @($stored.assignedLicenses).Count | Should -Be 0
            $stored.managerId | Should -BeNullOrEmpty
        }

        It 'requires userPrincipalName, mailNickname, displayName, accountEnabled and passwordProfile.password' -ForEach @(
            @{ Missing = 'userPrincipalName' }, @{ Missing = 'mailNickname' }, @{ Missing = 'displayName' }, @{ Missing = 'accountEnabled' }
        ) {
            $body = $newUser.Clone()
            $body.Remove($Missing)
            $r = Send POST 'users' $body
            $r.Status | Should -Be 400
            $r.Body.error.message | Should -Match $Missing
        }

        It 'requires a password' {
            $body = $newUser.Clone()
            $body.Remove('passwordProfile')
            (Send POST 'users' $body).Status | Should -Be 400
        }

        It 'rejects a weak password' {
            $newUser.passwordProfile.password = 'password'
            (Send POST 'users' $newUser).Status | Should -Be 400
            @($w.Users).Count | Should -Be 3
        }

        It 'rejects a duplicate UPN or mail nickname, including a soft-deleted one' {
            $newUser.userPrincipalName = 'dave@example.com'
            (Send POST 'users' $newUser).Status | Should -Be 400
            $newUser.userPrincipalName = 'erin@example.com'
            $newUser.mailNickname = 'alice'
            (Send POST 'users' $newUser).Status | Should -Be 400
        }

        It 'rejects unknown properties' {
            $newUser.favoriteColor = 'blue'
            (Send POST 'users' $newUser).Status | Should -Be 400
        }
    }

    Context '$select, $filter and $top' {
        It '$select projects the listed properties, always keeps id and returns null for unset ones' {
            $body = (Send GET 'users/alice@example.com?$select=department,companyName').Body
            $body.PSObject.Properties.Name | Should -Be @('id', 'department', 'companyName')
            $body.department | Should -Be 'Sales'
            $body.companyName | Should -BeNullOrEmpty
        }

        It '$select matches property names case-insensitively and returns the canonical name' {
            (Send GET 'users/alice@example.com?$select=USERPRINCIPALNAME').Body.userPrincipalName | Should -Be 'alice@example.com'
        }

        It '$select with an unknown property is a 400' {
            $r = Send GET 'users/alice@example.com?$select=nope'
            $r.Status | Should -Be 400
            $r.Body.error.message | Should -Match 'nope'
        }

        It 'an unsupported query option is a 400, which catches a $select swallowed by string interpolation' {
            $r = Send GET 'users/alice@example.com?=id'
            $r.Status | Should -Be 400
            (Send GET 'users?$expand=manager').Status | Should -Be 400
        }

        It '$filter supports eq on UPN, mail, displayName, mailNickname and id' {
            foreach ($clause in "userPrincipalName eq 'alice@example.com'", "mail eq 'alice@example.com'", "displayName eq 'Alice Example'", "mailNickname eq 'alice'", "id eq '$($ids.AliceId)'") {
                $r = Send GET ('users?$filter=' + $clause)
                @($r.Body.value.id) | Should -Be @($ids.AliceId) -Because $clause
            }
        }

        It '$filter eq is case-insensitive and understands doubled single quotes' {
            @((Send GET 'users?$filter=userPrincipalName eq ''ALICE@EXAMPLE.COM''').Body.value).Count | Should -Be 1
            @((Send GET 'groups?$filter=displayName eq ''Bob''''s Group''').Body.value).Count | Should -Be 0
        }

        It '$filter joins clauses with or / and, parentheses and not' {
            $or = Send GET 'users?$filter=userPrincipalName eq ''alice@example.com'' or userPrincipalName eq ''carol@example.com''&$top=10'
            @($or.Body.value.userPrincipalName | Sort-Object) | Should -Be @('alice@example.com', 'carol@example.com')
            $and = Send GET 'users?$filter=department eq ''Sales'' and jobTitle eq ''Sales Manager''&$top=10'
            @($and.Body.value.userPrincipalName) | Should -Be @('bob@example.com')
            $grouped = Send GET 'users?$filter=accountEnabled eq true and (department eq ''IT'' or jobTitle eq ''Account Executive'')&$top=10'
            @($grouped.Body.value.userPrincipalName | Sort-Object) | Should -Be @('alice@example.com', 'carol@example.com')
            $not = Send GET 'users?$filter=not (department eq ''Sales'')&$top=10'
            @($not.Body.value.userPrincipalName) | Should -Be @('carol@example.com')
        }

        It '$filter supports startswith and ne' {
            $starts = Send GET 'users?$filter=startswith(displayName,''Bob'')'
            @($starts.Body.value.userPrincipalName) | Should -Be @('bob@example.com')
            $ne = Send GET 'users?$filter=department ne ''Sales''&$top=10'
            @($ne.Body.value.userPrincipalName) | Should -Be @('carol@example.com')
        }

        It '$filter on groups finds by mail or display name' {
            $r = Send GET 'groups?$filter=mail eq ''sales@example.com'' or displayName eq ''sales@example.com'''
            @($r.Body.value.id) | Should -Be @($ids.SalesGroupId)
            @((Send GET 'groups?$filter=displayName eq ''All Staff''').Body.value.id) | Should -Be @($ids.AllStaffGroupId)
        }

        It 'a malformed or unsupported $filter is a 400' {
            (Send GET 'users?$filter=userPrincipalName eq').Status | Should -Be 400
            (Send GET 'users?$filter=favoriteColor eq ''blue''').Status | Should -Be 400
            (Send GET 'users?$filter=department gt ''A''').Status | Should -Be 400
            (Send GET 'users?$filter=department eq ''Sales').Status | Should -Be 400
        }

        It '$top limits the page size to at most the world page size' {
            @((Send GET 'users?$top=1').Body.value).Count | Should -Be 1
            @((Send GET 'users?$top=50').Body.value).Count | Should -Be 2
            (Send GET 'users?$top=0').Status | Should -Be 400
        }
    }

    Context 'paging' {
        It 'returns the first page and an absolute nextLink whose skiptoken is the next offset' {
            $r = Send GET "groups/$($ids.AllStaffGroupId)/members"
            @($r.Body.value).Count | Should -Be 2
            $r.Body.'@odata.nextLink' | Should -Be "https://graph.microsoft.com/v1.0/groups/$($ids.AllStaffGroupId)/members?`$skiptoken=2"
        }

        It 'honors the skiptoken on the next call and the last page has no nextLink' {
            $r = Send GET "groups/$($ids.AllStaffGroupId)/members?`$skiptoken=2"
            @($r.Body.value.id) | Should -Be @($ids.CarolId)
            $r.Body.PSObject.Properties.Name | Should -Not -Contain '@odata.nextLink'
        }

        It 'keeps $select and $filter in the nextLink' {
            $r = Send GET 'users?$filter=accountEnabled eq true&$select=userPrincipalName&$top=1'
            $link = $r.Body.'@odata.nextLink'
            $link | Should -Match '^https://graph\.microsoft\.com/v1\.0/users\?'
            $link | Should -Match 'skiptoken=1'
            $next = Send GET $link
            @($next.Body.value.userPrincipalName) | Should -Be @('bob@example.com')
            $next.Body.value[0].PSObject.Properties.Name | Should -Be @('id', 'userPrincipalName')
        }

        It 'pages the beta prefix as beta' {
            (Send GET 'beta/subscribedSkus').Body.'@odata.nextLink' | Should -Match '^https://graph\.microsoft\.com/beta/subscribedSkus\?'
        }

        It 'the seam''s -All reassembles every page' {
            $members = @(Invoke-Graph @{ Method = 'GET'; Uri = "groups/$($ids.AllStaffGroupId)/members"; All = $true })
            $members.Count | Should -Be 3
            @($members.id | Sort-Object) | Should -Be @($ids.AliceId, $ids.BobId, $ids.CarolId)
            @(Get-FakeGraphCall -World $w -Method GET -UriLike '*/members*').Count | Should -Be 2
        }

        It 'the seam''s -All reassembles a filtered, selected, small-page query' {
            $users = @(Invoke-Graph @{ Method = 'GET'; Uri = 'users?$filter=accountEnabled eq true&$select=userPrincipalName&$top=1'; All = $true })
            $users.Count | Should -Be 3
            @($users.userPrincipalName | Sort-Object) | Should -Be @('alice@example.com', 'bob@example.com', 'carol@example.com')
        }

        It 'an invalid skiptoken is a 400' {
            (Send GET 'users?$skiptoken=abc').Status | Should -Be 400
        }

        It 'an empty collection is value = []' {
            $r = Send GET 'users?$filter=userPrincipalName eq ''nobody@example.com'''
            @($r.Body.value).Count | Should -Be 0
            $r.Body.PSObject.Properties.Name | Should -Contain 'value'
        }
    }

    Context 'faults' {
        It 'serves a queued fault ahead of the real response, once' {
            Add-FakeGraphFault -World $w -Status 403 -Code 'Authorization_RequestDenied' -Message 'Insufficient privileges'
            $first = Send GET 'users/alice@example.com'
            $first.Status | Should -Be 403
            $first.Body.error.code | Should -Be 'Authorization_RequestDenied'
            (Send GET 'users/alice@example.com').Status | Should -Be 200
        }

        It 'faults are recorded as calls and served in queue order' {
            Add-FakeGraphFault -World $w -Status 500
            Add-FakeGraphFault -World $w -Status 404
            (Send GET 'me').Status | Should -Be 500
            (Send GET 'me').Status | Should -Be 404
            (Send GET 'me').Status | Should -Be 200
            $w.Calls.Count | Should -Be 3
        }

        It 'a 429 with Retry-After then success is transparent through the seam' {
            Add-FakeGraphFault -World $w -Status 429 -Code 'TooManyRequests' -Headers @{ 'Retry-After' = @('3') }
            (Invoke-Graph @{ Method = 'GET'; Uri = 'users/alice@example.com' }).id | Should -Be $ids.AliceId
            @($global:FakeGraphSleeps) | Should -Be @(3)
            $w.Calls.Count | Should -Be 2
        }

        It 'a 403 surfaces as Tenure.Graph.Forbidden through the seam' {
            Add-FakeGraphFault -World $w -Status 403
            { Invoke-Graph @{ Method = 'GET'; Uri = 'me' } } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }

        It 'queued faults can be written by hand as hashtables, without Headers' {
            $w.Faults.Enqueue(@{ Status = 503; Body = @{ error = @{ code = 'serviceNotAvailable'; message = 'down' } } })
            $r = Send GET 'me'
            $r.Status | Should -Be 503
            $r.Headers['request-id'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'managers' {
        It 'GET manager returns the manager and honors $select' {
            $r = Send GET 'users/alice@example.com/manager?$select=id,userPrincipalName'
            $r.Status | Should -Be 200
            $r.Body.id | Should -Be $ids.BobId
            $r.Body.userPrincipalName | Should -Be 'bob@example.com'
            $r.Body.'@odata.type' | Should -Be '#microsoft.graph.user'
        }

        It 'GET manager is a Graph 404 when the user has none' {
            $r = Send GET 'users/bob@example.com/manager'
            $r.Status | Should -Be 404
            $r.Body.error.code | Should -Be 'Request_ResourceNotFound'
            { Invoke-Graph @{ Method = 'GET'; Uri = 'users/bob@example.com/manager' } } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
        }

        It 'PUT manager/$ref sets the manager from an @odata.id ending in /users/{id}' {
            $r = Send PUT 'users/carol@example.com/manager/$ref' @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($ids.BobId)" }
            $r.Status | Should -Be 204
            (Send GET 'users/carol@example.com/manager?$select=id').Body.id | Should -Be $ids.BobId
        }

        It 'PUT manager/$ref rejects an unknown manager, a missing reference and a cycle' {
            (Send PUT 'users/carol@example.com/manager/$ref' @{ '@odata.id' = 'https://graph.microsoft.com/v1.0/users/00000000-0000-0000-0000-000000000000' }).Status | Should -Be 404
            (Send PUT 'users/carol@example.com/manager/$ref' @{}).Status | Should -Be 400
            (Send PUT 'users/bob@example.com/manager/$ref' @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($ids.AliceId)" }).Status | Should -Be 400
        }

        It 'DELETE manager/$ref clears the manager and answers 204' {
            (Send DELETE 'users/alice@example.com/manager/$ref').Status | Should -Be 204
            (Send GET 'users/alice@example.com/manager').Status | Should -Be 404
        }
    }

    Context 'membership and directory roles' {
        BeforeEach { $w.PageSize = 50 }

        It 'memberOf lists groups and directory roles with their @odata.type' {
            $carol = Send GET 'users/carol@example.com/memberOf?$top=10'
            $types = @($carol.Body.value | ForEach-Object { $_.'@odata.type' })
            $types | Should -Contain '#microsoft.graph.directoryRole'
            $types | Should -Contain '#microsoft.graph.group'
            ($carol.Body.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }).displayName | Should -Be 'Global Administrator'
        }

        It 'alice is in Sales, All Staff, Everyone Dynamic and Legal DL' {
            $r = Send GET 'users/alice@example.com/memberOf?$top=10&$select=id,displayName'
            @($r.Body.value.displayName | Sort-Object) | Should -Be @('All Staff', 'Everyone Dynamic', 'Legal DL', 'Sales')
        }

        It 'transitiveMemberOf matches memberOf' {
            $a = (Send GET 'users/alice@example.com/memberOf?$top=10&$select=id').Body.value.id
            $b = (Send GET 'users/alice@example.com/transitiveMemberOf?$top=10&$select=id').Body.value.id
            @($b | Sort-Object) | Should -Be @($a | Sort-Object)
        }

        It 'GET groups/{id} returns the group by id only' {
            (Send GET "groups/$($ids.SalesGroupId)").Body.displayName | Should -Be 'Sales'
            (Send GET 'groups/Sales').Status | Should -Be 404
        }

        It 'GET members returns users with @odata.type and GET members/{uid} is 404 for a non-member' {
            $members = Send GET "groups/$($ids.SalesGroupId)/members"
            $members.Body.value[0].'@odata.type' | Should -Be '#microsoft.graph.user'
            (Send GET "groups/$($ids.SalesGroupId)/members/$($ids.AliceId)?`$select=id").Body.id | Should -Be $ids.AliceId
            (Send GET "groups/$($ids.SalesGroupId)/members/$($ids.BobId)?`$select=id").Status | Should -Be 404
        }

        It 'GET owners lists the owners' {
            @((Send GET "groups/$($ids.SalesGroupId)/owners").Body.value.id) | Should -Be @($ids.BobId)
        }

        It 'POST members/$ref adds a member (204) and a second add is the Graph 400 "already exist"' {
            $reference = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($ids.BobId)" }
            (Send POST "groups/$($ids.SalesGroupId)/members/`$ref" $reference).Status | Should -Be 204
            (Send GET "groups/$($ids.SalesGroupId)/members/$($ids.BobId)").Status | Should -Be 200
            $again = Send POST "groups/$($ids.SalesGroupId)/members/`$ref" $reference
            $again.Status | Should -Be 400
            $again.Body.error.code | Should -Be 'Request_BadRequest'
            $again.Body.error.message | Should -Match 'already exist'
        }

        It 'POST and DELETE members are a 400 on a dynamic group and on an Exchange-managed group' {
            $reference = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($ids.CarolId)" }
            (Send POST "groups/$($ids.DynamicGroupId)/members/`$ref" $reference).Status | Should -Be 400
            (Send POST "groups/$($ids.LegalDlGroupId)/members/`$ref" $reference).Status | Should -Be 400
            (Send DELETE "groups/$($ids.DynamicGroupId)/members/$($ids.AliceId)/`$ref").Status | Should -Be 400
            (Send DELETE "groups/$($ids.LegalDlGroupId)/members/$($ids.AliceId)/`$ref").Status | Should -Be 400
        }

        It 'POST members/$ref to an unknown user is 404' {
            (Send POST "groups/$($ids.SalesGroupId)/members/`$ref" @{ '@odata.id' = 'https://graph.microsoft.com/v1.0/directoryObjects/00000000-0000-0000-0000-000000000000' }).Status | Should -Be 404
        }

        It 'DELETE members/{uid}/$ref removes a member (204) and is 404 when not a member' {
            (Send DELETE "groups/$($ids.SalesGroupId)/members/$($ids.AliceId)/`$ref").Status | Should -Be 204
            (Send GET "groups/$($ids.SalesGroupId)/members/$($ids.AliceId)").Status | Should -Be 404
            (Send DELETE "groups/$($ids.SalesGroupId)/members/$($ids.AliceId)/`$ref").Status | Should -Be 404
        }

        It 'GET directoryRoles, role members and DELETE of a role member' {
            $roles = Send GET 'directoryRoles'
            @($roles.Body.value.displayName) | Should -Be @('Global Administrator')
            @((Send GET "directoryRoles/$($ids.GlobalAdminRoleId)/members").Body.value.id) | Should -Be @($ids.CarolId)
            (Send DELETE "directoryRoles/$($ids.GlobalAdminRoleId)/members/$($ids.CarolId)/`$ref").Status | Should -Be 204
            @((Send GET "directoryRoles/$($ids.GlobalAdminRoleId)/members").Body.value).Count | Should -Be 0
            (Send DELETE "directoryRoles/$($ids.GlobalAdminRoleId)/members/$($ids.CarolId)/`$ref").Status | Should -Be 404
        }
    }

    Context 'licenses' {
        It 'GET subscribedSkus returns the three SKUs' {
            $skus = @(Invoke-Graph @{ Method = 'GET'; Uri = 'subscribedSkus'; All = $true })
            @($skus.skuPartNumber | Sort-Object) | Should -Be @('EXCHANGEDESKLESS', 'MCOEV', 'SPE_E3')
            ($skus | Where-Object skuPartNumber -eq 'SPE_E3').prepaidUnits.enabled | Should -Be 10
            ($skus | Where-Object skuPartNumber -eq 'SPE_E3').consumedUnits | Should -Be 3
        }

        It 'GET licenseDetails maps assigned SKUs to part numbers' {
            $r = Send GET 'users/alice@example.com/licenseDetails'
            $r.Body.value[0].skuPartNumber | Should -Be 'SPE_E3'
            $r.Body.value[0].skuId | Should -Be $ids.SkuE3Id
        }

        It 'assignLicense adds a SKU and records a direct state' {
            $r = Send POST 'users/carol@example.com/assignLicense' @{ addLicenses = @(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() }); removeLicenses = @() }
            $r.Status | Should -Be 200
            $r.Body.id | Should -Be $ids.CarolId
            $carol = $w.Users | Where-Object id -eq $ids.CarolId
            @($carol.assignedLicenses.skuId) | Should -Be @($ids.SkuVoiceId)
            @($carol.licenseAssignmentStates | Where-Object { -not $_.assignedByGroup }).Count | Should -Be 1
        }

        It 'assignLicense removes a directly assigned SKU' {
            $r = Send POST 'users/alice@example.com/assignLicense' @{ addLicenses = @(); removeLicenses = @($ids.SkuE3Id) }
            $r.Status | Should -Be 200
            $alice = $w.Users | Where-Object id -eq $ids.AliceId
            @($alice.assignedLicenses).Count | Should -Be 0
            @($alice.licenseAssignmentStates).Count | Should -Be 0
        }

        It 'removing a group-assigned SKU is a 400 Request_BadRequest that mentions the group' {
            $r = Send POST 'users/bob@example.com/assignLicense' @{ addLicenses = @(); removeLicenses = @($ids.SkuE3Id) }
            $r.Status | Should -Be 400
            $r.Body.error.code | Should -Be 'Request_BadRequest'
            $r.Body.error.message | Should -Match 'group'
            @(($w.Users | Where-Object id -eq $ids.BobId).assignedLicenses).Count | Should -Be 1
        }

        It 'a direct assignment on top of a group one is kept as a second state, and removing it leaves the group one' {
            Send POST 'users/bob@example.com/assignLicense' @{ addLicenses = @(@{ skuId = $ids.SkuE3Id; disabledPlans = @() }); removeLicenses = @() } | Out-Null
            $bob = $w.Users | Where-Object id -eq $ids.BobId
            @($bob.assignedLicenses).Count | Should -Be 1
            @($bob.licenseAssignmentStates).Count | Should -Be 2
            (Send POST 'users/bob@example.com/assignLicense' @{ addLicenses = @(); removeLicenses = @($ids.SkuE3Id) }).Status | Should -Be 200
            @($bob.assignedLicenses).Count | Should -Be 1
            @($bob.licenseAssignmentStates.assignedByGroup) | Should -Be @($ids.AllStaffGroupId)
        }

        It 'validation failures change nothing (all-or-nothing)' {
            $r = Send POST 'users/alice@example.com/assignLicense' @{
                addLicenses    = @(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() })
                removeLicenses = @('00000000-0000-0000-0000-000000000000')
            }
            $r.Status | Should -Be 400
            @(($w.Users | Where-Object id -eq $ids.AliceId).assignedLicenses.skuId) | Should -Be @($ids.SkuE3Id)
        }

        It 'adding a license needs a usage location and a known SKU' {
            $w.Users | Where-Object id -eq $ids.CarolId | ForEach-Object { $_.usageLocation = $null }
            $noLocation = Send POST 'users/carol@example.com/assignLicense' @{ addLicenses = @(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() }); removeLicenses = @() }
            $noLocation.Status | Should -Be 400
            $noLocation.Body.error.message | Should -Match 'usage location'
            $unknown = Send POST 'users/alice@example.com/assignLicense' @{ addLicenses = @(@{ skuId = '00000000-0000-0000-0000-000000000000'; disabledPlans = @() }); removeLicenses = @() }
            $unknown.Status | Should -Be 400
        }

        It 'assignLicense needs both addLicenses and removeLicenses' {
            (Send POST 'users/alice@example.com/assignLicense' @{ addLicenses = @() }).Status | Should -Be 400
        }

        It 'leaves SubscribedSkus consumed counts alone' {
            Send POST 'users/carol@example.com/assignLicense' @{ addLicenses = @(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() }); removeLicenses = @() } | Out-Null
            ($w.SubscribedSkus | Where-Object skuPartNumber -eq 'MCOEV').consumedUnits | Should -Be 0
        }
    }

    Context 'sessions, devices and OneDrive' {
        BeforeEach { $w.PageSize = 50 }

        It 'revokeSignInSessions answers 200 with value = true and records the user' {
            $r = Send POST 'users/alice@example.com/revokeSignInSessions'
            $r.Status | Should -Be 200
            $r.Body.value | Should -BeTrue
            @($w.SignInSessionsRevoked) | Should -Be @($ids.AliceId)
        }

        It 'managedDevices lists alice''s three devices with real Graph property names' {
            $r = Send GET 'users/alice@example.com/managedDevices?$top=10'
            @($r.Body.value.managedDeviceOwnerType | Sort-Object) | Should -Be @('company', 'personal', 'unknown')
            $company = $r.Body.value | Where-Object managedDeviceOwnerType -eq 'company'
            $company.id | Should -Be $ids.CompanyDeviceId
            $company.userPrincipalName | Should -Be 'alice@example.com'
            $company.managementState | Should -Be 'managed'
        }

        It 'a user without devices has an empty list' {
            @((Send GET 'users/bob@example.com/managedDevices').Body.value).Count | Should -Be 0
        }

        It 'wipe and retire answer 204 and set the flags' {
            (Send POST "deviceManagement/managedDevices/$($ids.CompanyDeviceId)/wipe" @{}).Status | Should -Be 204
            (Send POST "deviceManagement/managedDevices/$($ids.PersonalDeviceId)/retire").Status | Should -Be 204
            ($w.ManagedDevices | Where-Object id -eq $ids.CompanyDeviceId).wiped | Should -BeTrue
            ($w.ManagedDevices | Where-Object id -eq $ids.PersonalDeviceId).retired | Should -BeTrue
            ($w.ManagedDevices | Where-Object id -eq $ids.UnknownDeviceId).wiped | Should -BeFalse
            (Send GET 'users/alice@example.com/managedDevices?$top=10').Body.value |
                Where-Object id -eq $ids.CompanyDeviceId | ForEach-Object managementState | Should -Be 'wipePending'
            (Send POST 'deviceManagement/managedDevices/00000000-0000-0000-0000-000000000000/wipe').Status | Should -Be 404
        }

        It 'GET drive is 404 when the user has none and returns the drive otherwise' {
            (Send GET 'users/bob@example.com/drive').Status | Should -Be 404
            $drive = Send GET 'users/alice@example.com/drive'
            $drive.Body.id | Should -Be $ids.AliceDriveId
            $drive.Body.driveType | Should -Be 'business'
        }

        It 'invite appends a permission, via the user path and via the drive id' {
            $invite = @{ recipients = @(@{ email = 'bob@example.com' }); roles = @('write'); requireSignIn = $true; sendInvitation = $false }
            $first = Send POST 'users/alice@example.com/drive/root/invite' $invite
            $first.Status | Should -Be 200
            @($first.Body.value).Count | Should -Be 1
            @($first.Body.value[0].roles) | Should -Be @('write')
            $first.Body.value[0].invitation.email | Should -Be 'bob@example.com'
            # A second recipient: inviting bob again would now be the "already exists" 400.
            $invite.recipients = @(@{ email = 'carol@example.com' })
            (Send POST "drives/$($ids.AliceDriveId)/root/invite" $invite).Status | Should -Be 200
            @((Send GET "drives/$($ids.AliceDriveId)/root/permissions").Body.value).Count | Should -Be 2
            @($w.Drives[$ids.AliceId].permissions).Count | Should -Be 2
        }

        It 'the call log keeps sendInvitation = false for the test to read' {
            Send POST 'users/alice@example.com/drive/root/invite' @{ recipients = @(@{ email = 'bob@example.com' }); roles = @('write'); requireSignIn = $true; sendInvitation = $false } | Out-Null
            ($w.Calls[-1].Body | ConvertFrom-Json).sendInvitation | Should -BeFalse
        }

        It 'GET deviceManagement/managedDevices/{id} returns one device with lastSyncDateTime and complianceState, honors $select, and is 404 when unknown' {
            $r = Send GET "deviceManagement/managedDevices/$($ids.CompanyDeviceId)"
            $r.Status | Should -Be 200
            $r.Body.id | Should -Be $ids.CompanyDeviceId
            $r.Body.userPrincipalName | Should -Be 'alice@example.com'
            $r.Body.lastSyncDateTime | Should -Be '2026-10-07T08:30:00Z'
            $r.Body.complianceState | Should -Be 'compliant'
            $selected = Send GET "deviceManagement/managedDevices/$($ids.UnknownDeviceId)?`$select=id,deviceName,lastSyncDateTime,complianceState"
            @($selected.Body.PSObject.Properties.Name) | Should -Be @('id', 'deviceName', 'lastSyncDateTime', 'complianceState')
            $selected.Body.complianceState | Should -Be 'noncompliant'
            (Send GET "deviceManagement/managedDevices/$($ids.CompanyDeviceId)?`$select=id,serialNumber").Status | Should -Be 400
            $missing = Send GET 'deviceManagement/managedDevices/59999999-9999-4999-8999-999999999999'
            $missing.Status | Should -Be 404
            $missing.Body.error.code | Should -Be 'ResourceNotFound'
        }

        It 'the single-device read shows a pending wipe, and the wipe route keeps the body it received' {
            Send POST "deviceManagement/managedDevices/$($ids.CompanyDeviceId)/wipe" @{ keepEnrollmentData = $false; keepUserData = $true } | Out-Null
            $device = $w.ManagedDevices | Where-Object id -eq $ids.CompanyDeviceId
            $device.wipeRequest.keepUserData | Should -BeTrue
            $device.wipeRequest.keepEnrollmentData | Should -BeFalse
            $read = (Send GET "deviceManagement/managedDevices/$($ids.CompanyDeviceId)").Body
            $read.managementState | Should -Be 'wipePending'
            $read.PSObject.Properties.Name | Should -Not -Contain 'wipeRequest'
            Send POST "deviceManagement/managedDevices/$($ids.PersonalDeviceId)/wipe" | Out-Null
            ($w.ManagedDevices | Where-Object id -eq $ids.PersonalDeviceId).wipeRequest.Count | Should -Be 0 -Because 'a bodiless wipe is stored as an empty request'
        }

        It 'GET users/{id}/drive returns webUrl and honors $select' {
            $drive = Send GET 'users/alice@example.com/drive?$select=id,driveType,webUrl'
            @($drive.Body.PSObject.Properties.Name) | Should -Be @('id', 'driveType', 'webUrl')
            $drive.Body.webUrl | Should -Be 'https://example-my.sharepoint.com/personal/alice_example_com/Documents'
            (Send GET 'users/alice@example.com/drive?$select=id,bogus').Status | Should -Be 400
        }

        It 'invite to a recipient that already holds the role is a 400 "already exists" and adds nothing; a new role is still granted' {
            $invite = @{ recipients = @(@{ email = 'bob@example.com' }); roles = @('read'); requireSignIn = $true; sendInvitation = $false }
            (Send POST 'users/alice@example.com/drive/root/invite' $invite).Status | Should -Be 200
            $again = Send POST "drives/$($ids.AliceDriveId)/root/invite" @{ recipients = @(@{ email = 'BOB@example.com' }); roles = @('read'); requireSignIn = $true; sendInvitation = $false }
            $again.Status | Should -Be 400
            $again.Body.error.message | Should -Match 'already exists'
            @($w.Drives[$ids.AliceId].permissions).Count | Should -Be 1
            (Send POST 'users/alice@example.com/drive/root/invite' @{ recipients = @(@{ email = 'bob@example.com' }); roles = @('write') }).Status | Should -Be 200
            @($w.Drives[$ids.AliceId].permissions).Count | Should -Be 2
        }

        It 'invite sees a grant stored in any shape (grantedTo, grantedToV2 user or siteUser, invitation)' {
            $w.Drives[$ids.AliceId].permissions.Add(@{ id = 'p-site'; roles = @('write'); grantedToV2 = @{ siteUser = @{ email = 'erin@example.com' } } })
            $w.Drives[$ids.AliceId].permissions.Add(@{ id = 'p-v1'; roles = @('write'); grantedTo = @{ user = @{ email = 'carol@example.com' } } })
            (Send POST 'users/alice@example.com/drive/root/invite' @{ recipients = @(@{ email = 'erin@example.com' }); roles = @('write') }).Status | Should -Be 400
            (Send POST 'users/alice@example.com/drive/root/invite' @{ recipients = @(@{ email = 'carol@example.com' }); roles = @('write') }).Status | Should -Be 400
            @($w.Drives[$ids.AliceId].permissions).Count | Should -Be 2
        }

        It 'DELETE drives/{id}/root/permissions/{id} removes one permission and is 404 for an unknown permission or drive' {
            $invite = @{ recipients = @(@{ email = 'bob@example.com' }, @{ email = 'carol@example.com' }); roles = @('write') }
            $granted = (Send POST 'users/alice@example.com/drive/root/invite' $invite).Body.value
            $bob = ($granted | Where-Object { $_.invitation.email -eq 'bob@example.com' }).id
            (Send DELETE "drives/$($ids.AliceDriveId)/root/permissions/$bob").Status | Should -Be 204
            @($w.Drives[$ids.AliceId].permissions | ForEach-Object { $_.invitation.email }) | Should -Be @('carol@example.com')
            $gone = Send DELETE "drives/$($ids.AliceDriveId)/root/permissions/$bob"
            $gone.Status | Should -Be 404
            $gone.Body.error.code | Should -Be 'itemNotFound'
            (Send DELETE 'drives/b!no-such-drive/root/permissions/x').Status | Should -Be 404
        }

        It 'invite needs recipients and roles, and a drive that exists' {
            (Send POST 'users/alice@example.com/drive/root/invite' @{ roles = @('write') }).Status | Should -Be 400
            (Send POST 'users/bob@example.com/drive/root/invite' @{ recipients = @(@{ email = 'x@example.com' }); roles = @('write') }).Status | Should -Be 404
            (Send GET 'drives/nope/root/permissions').Status | Should -Be 404
        }
    }

    Context 'Temporary Access Pass' {
        It 'POST creates a method and returns the pass once; the pass is never stored' {
            $r = Send POST 'users/alice@example.com/authentication/temporaryAccessPassMethods' @{ lifetimeInMinutes = 480; isUsableOnce = $true }
            $r.Status | Should -Be 201
            $r.Body.temporaryAccessPass | Should -Match '^TAP-'
            $r.Body.lifetimeInMinutes | Should -Be 480
            $r.Body.isUsableOnce | Should -BeTrue
            $r.Body.startDateTime | Should -Not -BeNullOrEmpty
            $r.Body.methodUsabilityReason | Should -Be 'EnabledByPolicy'
            ($w.TapMethods | ConvertTo-Json -Depth 10) | Should -Not -Match $r.Body.temporaryAccessPass
            $expected = Get-FakeGraphSha256 -Text $r.Body.temporaryAccessPass
            @($w.SecretDigests | Where-Object { $_.Kind -eq 'tap' -and $_.Sha256 -eq $expected }).Count | Should -Be 1
        }

        It 'GET lists the methods without the pass value' {
            Send POST 'users/alice@example.com/authentication/temporaryAccessPassMethods' @{ lifetimeInMinutes = 60 } | Out-Null
            $r = Send GET 'users/alice@example.com/authentication/temporaryAccessPassMethods'
            @($r.Body.value).Count | Should -Be 1
            $r.Body.value[0].temporaryAccessPass | Should -BeNullOrEmpty
            $r.Body.value[0].isUsable | Should -BeTrue
        }

        It 'a user with no methods has an empty list, and a lifetime outside 10..43200 is a 400' {
            @((Send GET 'users/alice@example.com/authentication/temporaryAccessPassMethods').Body.value).Count | Should -Be 0
            (Send POST 'users/alice@example.com/authentication/temporaryAccessPassMethods' @{ lifetimeInMinutes = 5 }).Status | Should -Be 400
        }

        It 'an expired method reads as not usable' {
            Send POST 'users/alice@example.com/authentication/temporaryAccessPassMethods' @{ lifetimeInMinutes = 10; startDateTime = '2020-01-01T00:00:00Z' } | Out-Null
            $method = (Send GET 'users/alice@example.com/authentication/temporaryAccessPassMethods').Body.value[0]
            $method.isUsable | Should -BeFalse
            $method.methodUsabilityReason | Should -Be 'Expired'
        }
    }
}
