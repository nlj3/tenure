BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    $global:FakeGraphSleeps = [System.Collections.Generic.List[int]]::new()
    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
    Mock -ModuleName Tenure Start-Sleep { $global:FakeGraphSleeps.Add([int]$Seconds) }

    function Get-Canonical($Object) { Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $Object) }
    # Context as the engine builds it: the plan's subject is the user being changed.
    function New-Context([string]$SubjectId) {
        $context = @{ Secrets = @{}; StepId = 'S05'; Mode = 'Apply' }
        if ($SubjectId) { $context.Subject = @{ Id = $SubjectId; UserPrincipalName = $null; DisplayName = $null } }
        $context
    }
    function New-Target([string]$GroupId, [string]$Name) { @{ Kind = 'group'; Id = $GroupId; Name = $Name } }
    function Get-GroupWrites { @($global:FakeGraphWorld.Calls | Where-Object { $_.Method -in 'POST', 'DELETE' }) }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeGraphSleeps -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Group.Member' {
    BeforeAll {
        $script:provider = Get-TenureProvider -Name 'Group.Member'
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    It 'is registered as a Medium-risk reversible State provider on the Graph backend' {
        $provider.Kind | Should -Be 'State'
        $provider.Backend | Should -Be 'Graph'
        $provider.Risk | Should -Be 'Medium'
        $provider.Reversible | Should -BeTrue
        @($provider.Scopes) | Should -Be @('GroupMember.ReadWrite.All', 'Group.Read.All')
    }

    Context 'Get' {
        It 'reports membership of the subject, plus the group flags' {
            $current = & $provider.Get (New-Target $ids.SalesGroupId 'Sales') (New-Context $ids.AliceId)
            $current | Should -BeOfType [pscustomobject]
            @($current.PSObject.Properties.Name | Sort-Object) | Should -Be @('isAssignableToRole', 'isDynamic', 'isExchangeManaged', 'member', 'userId')
            $current.userId | Should -Be $ids.AliceId
            $current.member | Should -BeTrue
            $current.isDynamic | Should -BeFalse
            $current.isExchangeManaged | Should -BeFalse
        }

        It 'a user outside the group reads as member = $false (the 404 on members/{uid} is not an error)' {
            $current = & $provider.Get (New-Target $ids.SalesGroupId 'Sales') (New-Context $ids.BobId)
            $current.member | Should -BeFalse
            $current.userId | Should -Be $ids.BobId
        }

        It 'flags a dynamic group and an Exchange-managed group' {
            $dynamic = & $provider.Get (New-Target $ids.DynamicGroupId 'Everyone Dynamic') (New-Context $ids.AliceId)
            $dynamic.isDynamic | Should -BeTrue
            $dynamic.isExchangeManaged | Should -BeFalse
            $dynamic.member | Should -BeTrue
            $legal = & $provider.Get (New-Target $ids.LegalDlGroupId 'Legal DL') (New-Context $ids.AliceId)
            $legal.isExchangeManaged | Should -BeTrue
            $legal.isDynamic | Should -BeFalse
            $allStaff = & $provider.Get (New-Target $ids.AllStaffGroupId 'All Staff') (New-Context $ids.AliceId)
            $allStaff.isDynamic | Should -BeFalse
            $allStaff.isExchangeManaged | Should -BeFalse
        }

        It 'without a subject id (an onboard plan before the user exists) it reads member = $false and asks Graph only about the group' {
            $current = & $provider.Get (New-Target $ids.SalesGroupId 'Sales') (New-Context)
            $current.member | Should -BeFalse
            $current.userId | Should -BeNullOrEmpty
            $w.Calls.Count | Should -Be 1
            $w.Calls[0].Uri | Should -Match "/groups/$($ids.SalesGroupId)\?"
        }

        It 'copes with a Context that has no Subject at all, or no Context' {
            (& $provider.Get (New-Target $ids.SalesGroupId 'Sales') @{ Secrets = @{} }).member | Should -BeFalse
            (& $provider.Get (New-Target $ids.SalesGroupId 'Sales') $null).member | Should -BeFalse
        }

        It 'asks for members/{uid} with $select=id' {
            & $provider.Get (New-Target $ids.SalesGroupId 'Sales') (New-Context $ids.AliceId) | Out-Null
            $w.Calls[-1].Uri | Should -Match "/groups/$($ids.SalesGroupId)/members/$($ids.AliceId)\?\`$select=id$"
        }

        It 'throws Tenure.Provider.TargetNotFound for an unknown group or a target without an id' {
            { & $provider.Get (New-Target '99999999-9999-4999-8999-999999999999' 'Ghost') (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            { & $provider.Get (New-Target $null 'Ghost') (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'lets other Graph failures through (403 stays Forbidden)' {
            Add-FakeGraphFault -World $w -Status 403
            { & $provider.Get (New-Target $ids.SalesGroupId 'Sales') (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }

        It 'fingerprint stability: two Gets canonicalize identically' {
            $target = New-Target $ids.SalesGroupId 'Sales'
            (Get-Canonical (& $provider.Get $target (New-Context $ids.AliceId))) | Should -BeExactly (Get-Canonical (& $provider.Get $target (New-Context $ids.AliceId)))
        }
    }

    Context 'Test' {
        It 'is true when member equals Desired.member, false otherwise' {
            $member = [pscustomobject]@{ userId = $ids.AliceId; member = $true; isDynamic = $false; isExchangeManaged = $false }
            $notMember = [pscustomobject]@{ userId = $ids.AliceId; member = $false; isDynamic = $false; isExchangeManaged = $false }
            (& $provider.Test $member @{ userId = $ids.AliceId; member = $true }) | Should -BeTrue
            (& $provider.Test $member @{ userId = $ids.AliceId; member = $false }) | Should -BeFalse
            (& $provider.Test $notMember @{ userId = $ids.AliceId; member = $false }) | Should -BeTrue
            (& $provider.Test $notMember @{ userId = $ids.AliceId; member = $true }) | Should -BeFalse
        }

        It 'is false for a missing current object' {
            (& $provider.Test $null @{ userId = $ids.AliceId; member = $true }) | Should -BeFalse
        }

        It 'is false when Desired names a different user than the one Get read' {
            $current = [pscustomobject]@{ userId = $ids.AliceId; member = $true; isDynamic = $false; isExchangeManaged = $false }
            (& $provider.Test $current @{ userId = $ids.BobId; member = $true }) | Should -BeFalse
        }

        It 'does not demand a userId on either side (plan time, before the user exists)' {
            $current = [pscustomobject]@{ userId = $null; member = $false; isDynamic = $false; isExchangeManaged = $false }
            (& $provider.Test $current @{ userId = '{{subjectId}}'; member = $false }) | Should -BeTrue
            (& $provider.Test $current @{ userId = '{{subjectId}}'; member = $true }) | Should -BeFalse
        }

        It 'accepts a PSCustomObject Desired and compares user ids ignoring case' {
            $current = [pscustomobject]@{ userId = $ids.AliceId.ToUpperInvariant(); member = $true; isDynamic = $false; isExchangeManaged = $false }
            (& $provider.Test $current ([pscustomobject]@{ userId = $ids.AliceId; member = $true })) | Should -BeTrue
        }
    }

    Context 'Set: add' {
        It 'adds a user, returns a fresh Get with member = $true and leaves Test true' {
            $desired = @{ userId = $ids.BobId; member = $true }
            $observed = & $provider.Set (New-Target $ids.SalesGroupId 'Sales') $desired $null (New-Context $ids.BobId)
            $observed.member | Should -BeTrue
            (& $provider.Test $observed $desired) | Should -BeTrue
            @(($w.Groups | Where-Object id -eq $ids.SalesGroupId).members) | Should -Contain $ids.BobId
        }

        It 'posts a directoryObjects reference for the user' {
            & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.BobId) | Out-Null
            $post = @(Get-GroupWrites | Where-Object { $_.Method -eq 'POST' })
            $post.Count | Should -Be 1
            $post[0].Uri | Should -Match "/groups/$($ids.SalesGroupId)/members/\`$ref$"
            ($post[0].Body | ConvertFrom-Json).'@odata.id' | Should -Be "https://graph.microsoft.com/v1.0/directoryObjects/$($ids.BobId)"
        }

        It 'treats Graph''s "already exist" 400 as success, so a second Set is harmless' {
            $desired = @{ userId = $ids.BobId; member = $true }
            & $provider.Set (New-Target $ids.SalesGroupId 'Sales') $desired $null (New-Context $ids.BobId) | Out-Null
            $again = & $provider.Set (New-Target $ids.SalesGroupId 'Sales') $desired $null (New-Context $ids.BobId)
            $again.member | Should -BeTrue
            @(($w.Groups | Where-Object id -eq $ids.SalesGroupId).members | Where-Object { $_ -eq $ids.BobId }).Count | Should -Be 1
            @(Get-GroupWrites).Count | Should -Be 2 -Because 'the second POST is sent and answered with the already-exist 400'
        }

        It 'adding someone who is already a member is success on the first try too' {
            (& $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.AliceId; member = $true } $null (New-Context $ids.AliceId)).member | Should -BeTrue
        }

        It 'reads back the user it changed even when the plan subject is someone else' {
            $observed = & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.AliceId)
            $observed.userId | Should -Be $ids.BobId
            $observed.member | Should -BeTrue
        }

        It 'reads back correctly with no Context.Subject at all' {
            $observed = & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.BobId; member = $true } $null (New-Context)
            $observed.member | Should -BeTrue
        }

        It 'accepts a PSCustomObject Desired' {
            (& $provider.Set (New-Target $ids.SalesGroupId 'Sales') ([pscustomobject]@{ userId = $ids.BobId; member = $true }) $null (New-Context $ids.BobId)).member | Should -BeTrue
        }

        It 'adds to a plain security group as well as to a Microsoft 365 group' {
            (& $provider.Set (New-Target $ids.AllStaffGroupId 'All Staff') @{ userId = $ids.CarolId; member = $true } $null (New-Context $ids.CarolId)).member | Should -BeTrue
        }

        It 'an unknown user surfaces as Tenure.Graph.NotFound (only the remove path forgives a 404)' {
            { & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = '99999999-9999-4999-8999-999999999999'; member = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
        }
    }

    Context 'Set: remove' {
        It 'removes a member, returns a fresh Get with member = $false and leaves Test true' {
            $desired = @{ userId = $ids.AliceId; member = $false }
            $observed = & $provider.Set (New-Target $ids.SalesGroupId 'Sales') $desired $null (New-Context $ids.AliceId)
            $observed.member | Should -BeFalse
            (& $provider.Test $observed $desired) | Should -BeTrue
            @(($w.Groups | Where-Object id -eq $ids.SalesGroupId).members) | Should -Not -Contain $ids.AliceId
        }

        It 'sends DELETE members/{uid}/$ref' {
            & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.AliceId; member = $false } $null (New-Context $ids.AliceId) | Out-Null
            $delete = @(Get-GroupWrites | Where-Object { $_.Method -eq 'DELETE' })
            $delete.Count | Should -Be 1
            $delete[0].Uri | Should -Match "/groups/$($ids.SalesGroupId)/members/$($ids.AliceId)/\`$ref$"
        }

        It 'treats Tenure.Graph.NotFound as success: removing a non-member is idempotent' {
            $desired = @{ userId = $ids.BobId; member = $false }
            $observed = & $provider.Set (New-Target $ids.SalesGroupId 'Sales') $desired $null (New-Context $ids.BobId)
            $observed.member | Should -BeFalse
            (& $provider.Test $observed $desired) | Should -BeTrue
        }

        It 'removing twice is harmless and leaves everyone else in place' {
            $desired = @{ userId = $ids.AliceId; member = $false }
            & $provider.Set (New-Target $ids.AllStaffGroupId 'All Staff') $desired $null (New-Context $ids.AliceId) | Out-Null
            (& $provider.Set (New-Target $ids.AllStaffGroupId 'All Staff') $desired $null (New-Context $ids.AliceId)).member | Should -BeFalse
            @(($w.Groups | Where-Object id -eq $ids.AllStaffGroupId).members | Sort-Object) | Should -Be @($ids.BobId, $ids.CarolId)
        }

        It 'add then remove returns to the start' {
            $target = New-Target $ids.SalesGroupId 'Sales'
            $before = Get-Canonical (& $provider.Get $target (New-Context $ids.BobId))
            & $provider.Set $target @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.BobId) | Out-Null
            & $provider.Set $target @{ userId = $ids.BobId; member = $false } $null (New-Context $ids.BobId) | Out-Null
            Get-Canonical (& $provider.Get $target (New-Context $ids.BobId)) | Should -BeExactly $before
        }
    }

    Context 'Set: groups Graph cannot change' {
        It 'throws Tenure.Provider.Unsupported for a dynamic group, saying why, and writes nothing' {
            $failure = { & $provider.Set (New-Target $ids.DynamicGroupId 'Everyone Dynamic') @{ userId = $ids.AliceId; member = $false } $null (New-Context $ids.AliceId) } |
                Should -Throw -ErrorId 'Tenure.Provider.Unsupported' -PassThru
            $failure.Exception.Message | Should -Match 'dynamic'
            $failure.Exception.Message | Should -Match 'Everyone Dynamic'
            @(Get-GroupWrites).Count | Should -Be 0
            @(($w.Groups | Where-Object id -eq $ids.DynamicGroupId).members) | Should -Contain $ids.AliceId
        }

        It 'throws Tenure.Provider.Unsupported for an Exchange-managed group, pointing at Exchange, and writes nothing' {
            $failure = { & $provider.Set (New-Target $ids.LegalDlGroupId 'Legal DL') @{ userId = $ids.AliceId; member = $false } $null (New-Context $ids.AliceId) } |
                Should -Throw -ErrorId 'Tenure.Provider.Unsupported' -PassThru
            $failure.Exception.Message | Should -Match 'Exchange'
            @(Get-GroupWrites).Count | Should -Be 0
            @(($w.Groups | Where-Object id -eq $ids.LegalDlGroupId).members) | Should -Contain $ids.AliceId
        }

        It 'refuses an add to those groups the same way' {
            { & $provider.Set (New-Target $ids.DynamicGroupId 'Everyone Dynamic') @{ userId = $ids.AliceId; member = $true } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Unsupported'
            { & $provider.Set (New-Target $ids.LegalDlGroupId 'Legal DL') @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Provider.Unsupported'
        }
    }

    Context 'Set: bad input' {
        It 'throws TargetNotFound for an unknown group and writes nothing' {
            { & $provider.Set (New-Target '99999999-9999-4999-8999-999999999999' 'Ghost') @{ userId = $ids.AliceId; member = $true } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            @(Get-GroupWrites).Count | Should -Be 0
        }

        It 'throws InvalidDesired without a userId and sends nothing' {
            { & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ member = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            $w.Calls.Count | Should -Be 0
        }

        It 'a target without an id is TargetNotFound' {
            { & $provider.Set (New-Target $null 'x') @{ userId = $ids.AliceId; member = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }
    }

    Context 'fault injection' {
        It 'a 429 with Retry-After then success is transparent on the add' {
            # The group lookup runs first; fail the POST that follows it.
            $w.Faults.Enqueue(@{ Status = 200; Body = @{ id = $ids.SalesGroupId; displayName = 'Sales'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false } })
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('2') }
            $observed = & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.BobId)
            $observed.member | Should -BeTrue
            @($global:FakeGraphSleeps) | Should -Be @(2)
            @(($w.Groups | Where-Object id -eq $ids.SalesGroupId).members | Where-Object { $_ -eq $ids.BobId }).Count | Should -Be 1
        }

        It 'a 429 with Retry-After then success is transparent on the remove' {
            $w.Faults.Enqueue(@{ Status = 200; Body = @{ id = $ids.SalesGroupId; displayName = 'Sales'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false } })
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('1') }
            (& $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.AliceId; member = $false } $null (New-Context $ids.AliceId)).member | Should -BeFalse
            @($global:FakeGraphSleeps) | Should -Be @(1)
        }

        It 'a 403 on the write surfaces as Tenure.Graph.Forbidden and changes nothing' {
            $w.Faults.Enqueue(@{ Status = 200; Body = @{ id = $ids.SalesGroupId; displayName = 'Sales'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false } })
            Add-FakeGraphFault -World $w -Status 403 -Code 'Authorization_RequestDenied' -Message 'Insufficient privileges to complete the operation.'
            { & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
            @(($w.Groups | Where-Object id -eq $ids.SalesGroupId).members) | Should -Not -Contain $ids.BobId
        }

        It 'a 400 that is not "already exist" is not swallowed' {
            $w.Faults.Enqueue(@{ Status = 200; Body = @{ id = $ids.SalesGroupId; displayName = 'Sales'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false } })
            Add-FakeGraphFault -World $w -Status 400 -Code 'Request_BadRequest' -Message 'Something else is wrong with the request.'
            { & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
        }

        It 'a 403 on the remove is not mistaken for "not a member"' {
            $w.Faults.Enqueue(@{ Status = 200; Body = @{ id = $ids.SalesGroupId; displayName = 'Sales'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false } })
            Add-FakeGraphFault -World $w -Status 403
            { & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.AliceId; member = $false } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }
    }

    Context 'Describe' {
        It 'says who is added to or removed from which group, on one line' {
            $target = New-Target $ids.SalesGroupId 'Sales'
            (& $provider.Describe $target $null @{ userId = $ids.AliceId; member = $true } 'Create') | Should -Be "Create user $($ids.AliceId) in group Sales"
            (& $provider.Describe $target $null @{ userId = $ids.AliceId; member = $false } 'Remove') | Should -Be "Remove user $($ids.AliceId) out of group Sales"
        }

        It 'never includes a password-like field, even if Desired carries one' {
            $line = & $provider.Describe (New-Target $ids.SalesGroupId 'Sales') $null @{ userId = $ids.AliceId; member = $true; password = 'Zk7#mQ4!vRt9wXp2' } 'Create'
            $line | Should -Not -Match 'Zk7'
            $line | Should -Not -Match 'password'
        }
    }
}

# ---- Regression tests for Group.Member ---------------------------------------------------------
# Each test below was written to fail against the code before its fix; the fix followed.

Describe 'Group.Member with dynamic groups, misrouted steps and a strict Desired' {
    BeforeAll {
        $script:provider = Get-TenureProvider -Name 'Group.Member'
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    It 'a remove step on a dynamic group is planned as NoOp (SPEC 5.1 step 14, SPEC 2.3), so apply never reaches Set' {
        $step = New-TenureStep -Provider 'Group.Member' -Target (New-Target $ids.DynamicGroupId 'Everyone Dynamic') -Desired @{ userId = $ids.AliceId; member = $false } -Context (New-Context $ids.AliceId) -Reason 'dynamic membership'
        $step.Action | Should -Be 'NoOp'
        $step.Reason | Should -Be 'dynamic membership'
        @(Get-GroupWrites).Count | Should -Be 0
    }

    It 'Test is true for a dynamic group whatever Desired.member says: the rule decides membership' {
        $dynamic = & $provider.Get (New-Target $ids.DynamicGroupId 'Everyone Dynamic') (New-Context $ids.AliceId)
        (& $provider.Test $dynamic @{ userId = $ids.AliceId; member = $false }) | Should -BeTrue
        (& $provider.Test $dynamic @{ userId = $ids.AliceId; member = $true }) | Should -BeTrue
    }

    It 'Describe says when membership is rule-based' {
        $dynamic = & $provider.Get (New-Target $ids.DynamicGroupId 'Everyone Dynamic') (New-Context $ids.AliceId)
        (& $provider.Describe (New-Target $ids.DynamicGroupId 'Everyone Dynamic') $dynamic @{ userId = $ids.AliceId; member = $false } 'NoOp') |
            Should -Be "NoOp user $($ids.AliceId) out of group Everyone Dynamic (dynamic membership: the group's rule decides)"
    }

    It 'an Exchange-managed group is still not "satisfied" by Test: a misrouted step must fail loudly' {
        $legal = & $provider.Get (New-Target $ids.LegalDlGroupId 'Legal DL') (New-Context $ids.AliceId)
        (& $provider.Test $legal @{ userId = $ids.AliceId; member = $false }) | Should -BeFalse
    }

    It 'refuses a non-boolean member instead of reading the string "false" as $true (no accidental add)' -ForEach @(
        @{ Member = 'false' }, @{ Member = 'False' }, @{ Member = 0 }, @{ Member = 'no' }
    ) {
        { & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.BobId; member = $Member } $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        { & $provider.Test ([pscustomobject]@{ userId = $ids.BobId; member = $false; isDynamic = $false; isExchangeManaged = $false }) @{ userId = $ids.BobId; member = $Member } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        @(Get-GroupWrites).Count | Should -Be 0
        @(($w.Groups | Where-Object id -eq $ids.SalesGroupId).members) | Should -Not -Contain $ids.BobId
    }

    It 'refuses a Desired without member instead of defaulting to a removal' {
        { & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.AliceId } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        @(($w.Groups | Where-Object id -eq $ids.SalesGroupId).members) | Should -Contain $ids.AliceId
        @(Get-GroupWrites).Count | Should -Be 0
    }

    It 'only a 400 "already exist" counts as already a member; a 500 that says the same is an error' {
        Add-FakeGraphFault -World $w -Status 500 -Code 'UnknownError' -Message 'One or more added object references already exist for the following modified properties: members.' -Method POST -Count 4
        { & $provider.Set (New-Target $ids.SalesGroupId 'Sales') @{ userId = $ids.BobId; member = $true } $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
    }
}
