# Fault injection on every provider Set.
# Each fault is aimed at the provider's write request with Add-FakeGraphFault -Method/-UriLike,
# so the reads around it run normally. For every provider:
#   - a 429 with Retry-After, then success, is transparent (the seam sleeps for Retry-After);
#   - a 403 surfaces as Tenure.Graph.Forbidden, mentions scope, and changes nothing;
#   - a 503 three times, then 200, succeeds (2, 4, 8 s back-off);
#   - a 404 on the write is Tenure.Graph.NotFound, except where the contract maps it to success,
#     and then the read-back reports what Graph really holds (so the engine's post-condition decides);
#   - a Set that hands out a secret never leaves one in Context.Secrets when the request fails, except
#     User.Create: its POST may have landed before the failure, so it keeps the password unless the
#     account already existed before the POST.

BeforeDiscovery {
    $script:FaultCaseNames = @(
        'User.SignIn', 'User.Password (returned)', 'User.Password (discarded)', 'User.Sessions', 'DirectoryRole.Member (remove)',
        'User.LeaveDate', 'User.TemporaryAccessPass', 'User.Create', 'User.Attributes',
        'User.Manager (set)', 'User.Manager (clear)', 'User.Licenses', 'Group.Member (add)', 'Group.Member (remove)'
    )
    $script:FaultCases = @($script:FaultCaseNames | ForEach-Object { @{ CaseName = $_ } })
}

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    $global:FakeGraphSleeps = [System.Collections.Generic.List[int]]::new()
    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
    Mock -ModuleName Tenure Start-Sleep { $global:FakeGraphSleeps.Add([int]$Seconds) }

    function Get-PlainText([System.Security.SecureString]$Secure) { [System.Net.NetworkCredential]::new('', $Secure).Password }
    function Get-UserRecord([string]$Id) { $global:FakeGraphWorld.Users | Where-Object { $_.id -eq $Id } }

    # One fault case per provider and direction. Built at run time (not discovery) so the closures see the fresh world.
    function New-FaultCase([string]$Name) {
        $w = $global:FakeGraphWorld
        $ids = $w.Ids
        $alice = @{ Kind = 'user'; Id = $ids.AliceId; Name = 'alice@example.com' }
        $role = @{ Kind = 'role'; Id = $ids.GlobalAdminRoleId; Name = 'Global Administrator' }
        $sales = @{ Kind = 'group'; Id = $ids.SalesGroupId; Name = 'Sales' }
        $roleMembers = { @(($w.DirectoryRoles | Where-Object { $_.id -eq $ids.GlobalAdminRoleId }).members) }.GetNewClosure()
        $salesMembers = { @(($w.Groups | Where-Object { $_.id -eq $ids.SalesGroupId }).members) }.GetNewClosure()
        # Closures run in their own dynamic module and cannot see this file's functions; capture what they need.
        $userRecord = { param($id) $w.Users | Where-Object { $_.id -eq $id } }.GetNewClosure()
        $passwordFor = { param($userId) @($w.SecretDigests | Where-Object { $_.Kind -eq 'password' -and $_.UserId -eq $userId }).Count -gt 0 }.GetNewClosure()
        $spec = switch ($Name) {
            'User.SignIn' {
                @{ Target = $alice; Desired = @{ accountEnabled = $false }; Subject = $ids.AliceId; Method = 'PATCH'; UriLike = "*/users/$($ids.AliceId)"
                    Changed = { (& $userRecord $ids.AliceId).accountEnabled -eq $false }.GetNewClosure() }
            }
            'User.Password (returned)' {
                @{ Provider = 'User.Password'; Target = $alice; Desired = @{ discard = $false }; Subject = $ids.AliceId; Method = 'PATCH'; UriLike = "*/users/$($ids.AliceId)"; Secret = 'password'
                    Changed = { & $passwordFor $ids.AliceId }.GetNewClosure() }
            }
            'User.Password (discarded)' {
                @{ Provider = 'User.Password'; Target = $alice; Desired = @{ discard = $true }; Subject = $ids.AliceId; Method = 'PATCH'; UriLike = "*/users/$($ids.AliceId)"
                    Changed = { & $passwordFor $ids.AliceId }.GetNewClosure() }
            }
            'User.Sessions' {
                @{ Target = $alice; Desired = $null; Subject = $ids.AliceId; Method = 'POST'; UriLike = '*/revokeSignInSessions'
                    Changed = { @($w.SignInSessionsRevoked) -contains $ids.AliceId }.GetNewClosure() }
            }
            'DirectoryRole.Member (remove)' {
                @{ Provider = 'DirectoryRole.Member'; Target = $role; Desired = @{ userId = $ids.CarolId; member = $false }; Subject = $ids.CarolId; Method = 'DELETE'; UriLike = '*/directoryRoles/*/members/*'; NotFoundIsSuccess = $true
                    Changed = { (& $roleMembers) -notcontains $ids.CarolId }.GetNewClosure() }
            }
            'User.LeaveDate' {
                @{ Target = $alice; Desired = @{ employeeLeaveDateTime = '2026-10-31T17:00:00Z' }; Subject = $ids.AliceId; Method = 'PATCH'; UriLike = "*/users/$($ids.AliceId)"
                    Changed = { (& $userRecord $ids.AliceId)['employeeLeaveDateTime'] -eq '2026-10-31T17:00:00Z' }.GetNewClosure() }
            }
            'User.TemporaryAccessPass' {
                @{ Target = $alice; Desired = @{}; Subject = $ids.AliceId; Method = 'POST'; UriLike = '*/temporaryAccessPassMethods'; Secret = 'tap'
                    Changed = { @($w.TapMethods[$ids.AliceId]).Where({ $null -ne $_ }).Count -gt 0 }.GetNewClosure() }
            }
            'User.Create' {
                @{ Target = @{ Kind = 'user'; Id = 'erin@example.com'; Name = 'Erin Example' }; Desired = @{ userPrincipalName = 'erin@example.com'; displayName = 'Erin Example'; mailNickname = 'erin'; usageLocation = 'US' }
                    Subject = $null; Method = 'POST'; UriLike = '*/v1.0/users'; Secret = 'password'; KeepsSecretOnFailure = $true
                    Changed = { @($w.Users | Where-Object { $_.userPrincipalName -eq 'erin@example.com' }).Count -eq 1 }.GetNewClosure() }
            }
            'User.Attributes' {
                @{ Target = $alice; Desired = @{ department = 'Operations' }; Subject = $ids.AliceId; Method = 'PATCH'; UriLike = "*/users/$($ids.AliceId)"
                    Changed = { (& $userRecord $ids.AliceId).department -eq 'Operations' }.GetNewClosure() }
            }
            'User.Manager (set)' {
                @{ Provider = 'User.Manager'; Target = $alice; Desired = @{ managerId = $ids.CarolId }; Subject = $ids.AliceId; Method = 'PUT'; UriLike = '*/manager/$ref'
                    Changed = { (& $userRecord $ids.AliceId).managerId -eq $ids.CarolId }.GetNewClosure() }
            }
            'User.Manager (clear)' {
                @{ Provider = 'User.Manager'; Target = $alice; Desired = @{ managerId = $null }; Subject = $ids.AliceId; Method = 'DELETE'; UriLike = '*/manager/$ref'; NotFoundIsSuccess = $true
                    Changed = { $null -eq (& $userRecord $ids.AliceId).managerId }.GetNewClosure() }
            }
            'User.Licenses' {
                @{ Target = $alice; Desired = @{ add = @(); remove = @($ids.SkuE3Id) }; Subject = $ids.AliceId; Method = 'POST'; UriLike = '*/assignLicense'
                    Changed = { @((& $userRecord $ids.AliceId).assignedLicenses).Count -eq 0 }.GetNewClosure() }
            }
            'Group.Member (add)' {
                @{ Provider = 'Group.Member'; Target = $sales; Desired = @{ userId = $ids.BobId; member = $true }; Subject = $ids.BobId; Method = 'POST'; UriLike = '*/groups/*/members/$ref'
                    Changed = { (& $salesMembers) -contains $ids.BobId }.GetNewClosure() }
            }
            'Group.Member (remove)' {
                @{ Provider = 'Group.Member'; Target = $sales; Desired = @{ userId = $ids.AliceId; member = $false }; Subject = $ids.AliceId; Method = 'DELETE'; UriLike = '*/groups/*/members/*'; NotFoundIsSuccess = $true
                    Changed = { (& $salesMembers) -notcontains $ids.AliceId }.GetNewClosure() }
            }
            default { throw "Unknown fault case '$Name'." }
        }
        if (-not $spec.ContainsKey('Provider')) { $spec.Provider = $Name }
        if (-not $spec.ContainsKey('NotFoundIsSuccess')) { $spec.NotFoundIsSuccess = $false }
        if (-not $spec.ContainsKey('Secret')) { $spec.Secret = $null }
        if (-not $spec.ContainsKey('KeepsSecretOnFailure')) { $spec.KeepsSecretOnFailure = $false }
        $spec.SecretsAfterFailure = if ($spec.KeepsSecretOnFailure) { 1 } else { 0 }
        $spec.Definition = Get-TenureProvider -Name $spec.Provider
        $spec
    }

    function New-FaultContext([hashtable]$Case) {
        @{ Secrets = @{}; StepId = 'S07'; Mode = 'Apply'; Subject = @{ Id = $Case.Subject; UserPrincipalName = $null; DisplayName = $null } }
    }

    function Invoke-FaultSet([hashtable]$Case, [hashtable]$Context) {
        & $Case.Definition.Set $Case.Target $Case.Desired $null $Context
    }

    # After a successful Set: the change is in the world, State providers satisfy Test, and a secret is the one Graph saw.
    function Assert-Succeeded([hashtable]$Case, [object]$Observed, [hashtable]$Context) {
        (& $Case.Changed) | Should -BeTrue -Because "$($Case.Provider) should have made its change"
        if ($Case.Definition.Kind -eq 'State') {
            (& $Case.Definition.Test $Observed $Case.Desired) | Should -BeTrue -Because 'Set must leave Test true'
        }
        if ($Case.Secret) {
            $Context.Secrets.Keys | Should -Be @('S07')
            $hash = Get-FakeGraphSha256 -Text (Get-PlainText $Context.Secrets['S07'])
            @($global:FakeGraphWorld.SecretDigests | Where-Object { $_.Kind -eq $Case.Secret -and $_.Sha256 -eq $hash }).Count | Should -Be 1
        } else {
            $Context.Secrets.Count | Should -Be 0
        }
    }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeGraphSleeps -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Provider Set under Graph faults' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $global:FakeGraphSleeps.Clear()
    }

    It 'covers every user, group and directory role provider that has a Set' -TestCases @(@{ Names = $FaultCaseNames }) {
        $expected = @('DirectoryRole.Member', 'Group.Member', 'User.Attributes', 'User.Create', 'User.LeaveDate', 'User.Licenses', 'User.Manager', 'User.Password', 'User.Sessions', 'User.SignIn', 'User.TemporaryAccessPass')
        $covered = @($Names | ForEach-Object { (New-FaultCase $_).Provider } | Sort-Object -Unique)
        $covered | Should -Be $expected
        foreach ($name in $expected) { (Get-TenureProvider -Name $name).Set | Should -BeOfType [scriptblock] }
    }

    Context '<CaseName>' -ForEach $FaultCases {
        BeforeEach {
            $script:case = New-FaultCase $CaseName
            $script:context = New-FaultContext $script:case
        }

        It 'a 429 with Retry-After on the write, then success, is transparent' {
            Add-FakeGraphFault -World $w -Status 429 -Code 'TooManyRequests' -Headers @{ 'Retry-After' = @('3') } -Method $case.Method -UriLike $case.UriLike
            $observed = Invoke-FaultSet $case $context
            @($global:FakeGraphSleeps) | Should -Be @(3)
            $w.Faults.Count | Should -Be 0 -Because 'the fault was aimed at a request the provider really makes'
            Assert-Succeeded $case $observed $context
        }

        It 'a 403 on the write is Tenure.Graph.Forbidden, mentions scope, changes nothing and hands back no secret' {
            Add-FakeGraphFault -World $w -Status 403 -Code 'Authorization_RequestDenied' -Message 'Insufficient privileges to complete the operation.' -Method $case.Method -UriLike $case.UriLike
            $failure = { Invoke-FaultSet $case $context } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden' -PassThru
            $failure.Exception.Message | Should -Match 'scope'
            $w.Faults.Count | Should -Be 0
            (& $case.Changed) | Should -BeFalse
            $context.Secrets.Count | Should -Be $case.SecretsAfterFailure
        }

        It 'a 503 three times on the write, then 200, succeeds after 2, 4 and 8 s' {
            Add-FakeGraphFault -World $w -Status 503 -Code 'ServiceUnavailable' -Count 3 -Method $case.Method -UriLike $case.UriLike
            $observed = Invoke-FaultSet $case $context
            @($global:FakeGraphSleeps) | Should -Be @(2, 4, 8)
            $w.Faults.Count | Should -Be 0
            Assert-Succeeded $case $observed $context
        }

        It 'a 404 on the write is Tenure.Graph.NotFound, or a forgiven 404 whose read-back tells the truth' {
            Add-FakeGraphFault -World $w -Status 404 -Code 'Request_ResourceNotFound' -Method $case.Method -UriLike $case.UriLike
            if ($case.NotFoundIsSuccess) {
                $observed = Invoke-FaultSet $case $context
                $w.Faults.Count | Should -Be 0
                # The injected 404 stood in for the real write, so nothing changed; the forgiven 404 must not hide that.
                (& $case.Changed) | Should -BeFalse
                (& $case.Definition.Test $observed $case.Desired) | Should -BeFalse -Because 'the read-back reports what Graph holds, so the engine post-condition fails the step'
                # And when Graph is already in the goal state, the same 404 is plain success.
                Invoke-FaultSet $case (New-FaultContext $case) | Out-Null
                Add-FakeGraphFault -World $w -Status 404 -Code 'Request_ResourceNotFound' -Method $case.Method -UriLike $case.UriLike
                $again = Invoke-FaultSet $case (New-FaultContext $case)
                (& $case.Definition.Test $again $case.Desired) | Should -BeTrue
            } else {
                { Invoke-FaultSet $case $context } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
                $w.Faults.Count | Should -Be 0
                (& $case.Changed) | Should -BeFalse
            }
            $context.Secrets.Count | Should -Be $case.SecretsAfterFailure
        }

        It 'a write that fails for good (<Status> x<Count>) leaves no secret behind (User.Create keeps it)' -ForEach @(
            @{ Status = 503; Count = 4; ErrorId = 'Tenure.Graph.Failed' }
            @{ Status = 429; Count = 4; ErrorId = 'Tenure.Graph.Throttled' }
            @{ Status = 400; Count = 1; ErrorId = 'Tenure.Graph.Failed' }
        ) {
            Add-FakeGraphFault -World $w -Status $Status -Count $Count -Method $case.Method -UriLike $case.UriLike
            { Invoke-FaultSet $case $context } | Should -Throw -ErrorId $ErrorId
            $context.Secrets.Count | Should -Be $case.SecretsAfterFailure
            (& $case.Changed) | Should -BeFalse
        }
    }
}
