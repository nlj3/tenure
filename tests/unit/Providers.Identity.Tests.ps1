BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    $global:FakeGraphSleeps = [System.Collections.Generic.List[int]]::new()
    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
    Mock -ModuleName Tenure Start-Sleep { $global:FakeGraphSleeps.Add([int]$Seconds) }

    function Get-Provider([string]$Name) { Get-TenureProvider -Name $Name }
    function Get-PlainText([System.Security.SecureString]$Secure) { [System.Net.NetworkCredential]::new('', $Secure).Password }
    function Get-Canonical($Object) { Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $Object) }
    function New-Context([string]$SubjectId, [hashtable]$Extra = @{}) {
        $context = @{ Secrets = @{}; StepId = 'S03'; Mode = 'Apply'; Subject = @{ Id = $null; UserPrincipalName = $null; DisplayName = $null } }
        if ($SubjectId) { $context.Subject = @{ Id = $SubjectId; UserPrincipalName = $null; DisplayName = $null } }
        foreach ($key in $Extra.Keys) { $context[$key] = $Extra[$key] }
        $context
    }
    function Get-UserRecord([string]$Id) { $global:FakeGraphWorld.Users | Where-Object { $_.id -eq $Id } }
    function Get-Writes { @($global:FakeGraphWorld.Calls | Where-Object { $_.Method -in 'POST', 'PATCH', 'PUT', 'DELETE' }) }
    # True when exactly one secret of this kind that FakeGraph saw or issued has this SecureString's digest.
    function Test-DigestRecorded([System.Security.SecureString]$Secure, [string]$Kind) {
        $hash = Get-FakeGraphSha256 -Text (Get-PlainText $Secure)
        @($global:FakeGraphWorld.SecretDigests | Where-Object { $_.Kind -eq $Kind -and $_.Sha256 -eq $hash }).Count -eq 1
    }
    # Runs a scriptblock with -Verbose on and returns @{ Output; Verbose (text) }.
    function Invoke-WithVerbose([scriptblock]$Script) {
        $global:VerbosePreference = 'Continue'
        try { $all = @(& { & $Script } 4>&1) } finally { $global:VerbosePreference = 'SilentlyContinue' }
        @{
            Output  = @($all | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] })
            Verbose = (@($all | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object { $_.Message }) -join "`n")
        }
    }
    function Assert-Absent([string]$Text, [string]$Secret, [string]$Where) {
        $Text.Contains($Secret) | Should -BeFalse -Because "the secret must not appear in $Where"
    }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeGraphSleeps -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Identity provider registration' {
    It 'registers <Name> with the agreed kind, risk, reversibility and scopes' -ForEach @(
        @{ Name = 'User.SignIn'; Kind = 'State'; Risk = 'High'; Reversible = $true; Scopes = @('User.EnableDisableAccount.All', 'User.Read.All') }
        @{ Name = 'User.Password'; Kind = 'Invoke'; Risk = 'High'; Reversible = $false; Scopes = @('User-PasswordProfile.ReadWrite.All', 'User.Read.All') }
        @{ Name = 'User.Sessions'; Kind = 'Invoke'; Risk = 'Medium'; Reversible = $false; Scopes = @('User.RevokeSessions.All', 'User.Read.All') }
        @{ Name = 'DirectoryRole.Member'; Kind = 'State'; Risk = 'High'; Reversible = $true; Scopes = @('RoleManagement.ReadWrite.Directory') }
        @{ Name = 'User.LeaveDate'; Kind = 'State'; Risk = 'Low'; Reversible = $true; Scopes = @('User-LifeCycleInfo.ReadWrite.All', 'User.Read.All') }
        @{ Name = 'User.TemporaryAccessPass'; Kind = 'Invoke'; Risk = 'High'; Reversible = $true; Scopes = @('UserAuthenticationMethod.ReadWrite.All') }
    ) {
        $provider = Get-Provider $Name
        $provider.Kind | Should -Be $Kind
        $provider.Backend | Should -Be 'Graph'
        $provider.Risk | Should -Be $Risk
        $provider.Reversible | Should -Be $Reversible
        @($provider.Scopes) | Should -Be $Scopes
        $provider.Set | Should -BeOfType [scriptblock]
    }
}

Describe 'FakeGraph routes and fault filters the identity providers rely on' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $w.PageSize = 50
    }

    It 'GET directoryRoles/{id} honors $select and is 404 for an unknown role' {
        $r = Invoke-FakeGraphRequest -World $w -Method GET -Uri "directoryRoles/$($ids.GlobalAdminRoleId)?`$select=id,displayName,roleTemplateId"
        $r.Status | Should -Be 200
        $r.Body.displayName | Should -Be 'Global Administrator'
        @($r.Body.PSObject.Properties.Name) | Should -Be @('id', 'displayName', 'roleTemplateId')
        (Invoke-FakeGraphRequest -World $w -Method GET -Uri 'directoryRoles/99999999-9999-4999-8999-999999999999').Status | Should -Be 404
    }

    It 'GET directoryRoles/{id}/members/{uid} is 200 for a member and 404 otherwise' {
        (Invoke-FakeGraphRequest -World $w -Method GET -Uri "directoryRoles/$($ids.GlobalAdminRoleId)/members/$($ids.CarolId)?`$select=id").Body.id | Should -Be $ids.CarolId
        (Invoke-FakeGraphRequest -World $w -Method GET -Uri "directoryRoles/$($ids.GlobalAdminRoleId)/members/$($ids.AliceId)").Status | Should -Be 404
    }

    It 'POST directoryRoles/{id}/members/$ref adds a member, then answers 400 "already exist"' {
        $reference = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($ids.AliceId)" }
        (Invoke-FakeGraphRequest -World $w -Method POST -Uri "directoryRoles/$($ids.GlobalAdminRoleId)/members/`$ref" -Body $reference).Status | Should -Be 204
        @(($w.DirectoryRoles | Where-Object id -eq $ids.GlobalAdminRoleId).members) | Should -Contain $ids.AliceId
        $again = Invoke-FakeGraphRequest -World $w -Method POST -Uri "directoryRoles/$($ids.GlobalAdminRoleId)/members/`$ref" -Body $reference
        $again.Status | Should -Be 400
        $again.Body.error.message | Should -Match 'already exist'
        (Invoke-FakeGraphRequest -World $w -Method POST -Uri "directoryRoles/$($ids.GlobalAdminRoleId)/members/`$ref" -Body @{ '@odata.id' = 'https://graph.microsoft.com/v1.0/directoryObjects/99999999-9999-4999-8999-999999999999' }).Status | Should -Be 404
    }

    It 'seeds lastPasswordChangeDateTime and signInSessionsValidFromDateTime, both readable with $select and both read-only' {
        $r = Invoke-FakeGraphRequest -World $w -Method GET -Uri 'users/alice@example.com?$select=lastPasswordChangeDateTime,signInSessionsValidFromDateTime'
        $r.Body.lastPasswordChangeDateTime | Should -Be '2026-01-15T09:00:00Z'
        $r.Body.signInSessionsValidFromDateTime | Should -Be '2026-01-15T09:00:00Z'
        (Invoke-FakeGraphRequest -World $w -Method PATCH -Uri 'users/alice@example.com' -Body @{ lastPasswordChangeDateTime = '2026-02-01T00:00:00Z' }).Status | Should -Be 400
        (Invoke-FakeGraphRequest -World $w -Method PATCH -Uri 'users/alice@example.com' -Body @{ signInSessionsValidFromDateTime = '2026-02-01T00:00:00Z' }).Status | Should -Be 400
    }

    It 'a password PATCH moves lastPasswordChangeDateTime; revokeSignInSessions moves signInSessionsValidFromDateTime' {
        (Invoke-FakeGraphRequest -World $w -Method PATCH -Uri 'users/alice@example.com' -Body @{ passwordProfile = @{ password = 'Kq7#vRt9!wXp2mZ4'; forceChangePasswordNextSignIn = $true } }).Status | Should -Be 204
        (Get-UserRecord $ids.AliceId).lastPasswordChangeDateTime | Should -Not -Be '2026-01-15T09:00:00Z'
        (Get-UserRecord $ids.AliceId).lastPasswordChangeDateTime | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        (Invoke-FakeGraphRequest -World $w -Method POST -Uri 'users/alice@example.com/revokeSignInSessions').Status | Should -Be 200
        (Get-UserRecord $ids.AliceId).signInSessionsValidFromDateTime | Should -Not -Be '2026-01-15T09:00:00Z'
    }

    It 'stores employeeLeaveDateTime the way Graph returns it, and rejects a value that is not a date' {
        (Invoke-FakeGraphRequest -World $w -Method PATCH -Uri 'users/alice@example.com' -Body @{ employeeLeaveDateTime = '2026-10-31T19:30:15.25+02:00' }).Status | Should -Be 204
        (Get-UserRecord $ids.AliceId).employeeLeaveDateTime | Should -Be '2026-10-31T17:30:15Z'
        (Invoke-FakeGraphRequest -World $w -Method PATCH -Uri 'users/alice@example.com' -Body @{ employeeLeaveDateTime = 'next tuesday' }).Status | Should -Be 400
        (Invoke-FakeGraphRequest -World $w -Method PATCH -Uri 'users/alice@example.com' -Body @{ employeeLeaveDateTime = $null }).Status | Should -Be 204
        (Get-UserRecord $ids.AliceId).employeeLeaveDateTime | Should -BeNullOrEmpty
    }

    It 'a fault filtered by -Method / -UriLike waits for a matching request and lets the others through' {
        Add-FakeGraphFault -World $w -Status 503 -Method PATCH -UriLike '*/users/*'
        (Invoke-FakeGraphRequest -World $w -Method GET -Uri 'users/alice@example.com').Status | Should -Be 200
        (Invoke-FakeGraphRequest -World $w -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/users/alice@example.com' -Body @{ department = 'X' }).Status | Should -Be 503
        $w.Faults.Count | Should -Be 0
        (Invoke-FakeGraphRequest -World $w -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/users/alice@example.com' -Body @{ department = 'X' }).Status | Should -Be 204
    }

    It 'unfiltered faults are still served first in, first out, ahead of filtered ones that do not match' {
        Add-FakeGraphFault -World $w -Status 500 -Method DELETE
        Add-FakeGraphFault -World $w -Status 429
        Add-FakeGraphFault -World $w -Status 403
        (Invoke-FakeGraphRequest -World $w -Method GET -Uri 'users/alice@example.com').Status | Should -Be 429
        (Invoke-FakeGraphRequest -World $w -Method GET -Uri 'users/alice@example.com').Status | Should -Be 403
        (Invoke-FakeGraphRequest -World $w -Method GET -Uri 'users/alice@example.com').Status | Should -Be 200
        (Invoke-FakeGraphRequest -World $w -Method DELETE -Uri "users/$($ids.AliceId)/manager/`$ref").Status | Should -Be 500
    }
}

Describe 'ConvertTo-TenureUtcDateString' {
    It 'normalizes <Label> to a UTC o string' -ForEach @(
        @{ Label = 'a Z string'; Value = '2026-10-31T17:00:00Z'; Expected = '2026-10-31T17:00:00.0000000Z' }
        @{ Label = 'an offset string'; Value = '2026-10-31T19:00:00+02:00'; Expected = '2026-10-31T17:00:00.0000000Z' }
        @{ Label = 'a string without an offset (read as UTC)'; Value = '2026-10-31T17:00:00'; Expected = '2026-10-31T17:00:00.0000000Z' }
        @{ Label = 'a UTC [datetime]'; Value = [datetime]::new(2026, 10, 31, 17, 0, 0, [System.DateTimeKind]::Utc); Expected = '2026-10-31T17:00:00.0000000Z' }
        @{ Label = 'an Unspecified [datetime] (read as UTC)'; Value = [datetime]::new(2026, 10, 31, 17, 0, 0, [System.DateTimeKind]::Unspecified); Expected = '2026-10-31T17:00:00.0000000Z' }
        @{ Label = 'a [DateTimeOffset]'; Value = [datetimeoffset]::new(2026, 10, 31, 12, 0, 0, [timespan]::FromHours(-5)); Expected = '2026-10-31T17:00:00.0000000Z' }
    ) {
        Invoke-InTenure { param($v) ConvertTo-TenureUtcDateString -Value $v } @(, $Value) | Should -BeExactly $Expected
    }

    It 'converts a Local [datetime] to UTC' {
        $local = [datetime]::new(2026, 10, 31, 17, 0, 0, [System.DateTimeKind]::Local)
        Invoke-InTenure { param($v) ConvertTo-TenureUtcDateString -Value $v } @(, $local) | Should -BeExactly ($local.ToUniversalTime().ToString('o'))
    }

    It 'returns $null for $null and empty, truncates to seconds on request, and refuses junk with InvalidDesired' {
        Invoke-InTenure { ConvertTo-TenureUtcDateString -Value $null } | Should -BeNullOrEmpty
        Invoke-InTenure { ConvertTo-TenureUtcDateString -Value '  ' } | Should -BeNullOrEmpty
        Invoke-InTenure { ConvertTo-TenureUtcDateString -Value '2026-10-31T17:00:00.987Z' -TruncateToSeconds } | Should -BeExactly '2026-10-31T17:00:00.0000000Z'
        { Invoke-InTenure { ConvertTo-TenureUtcDateString -Value 'soon' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        { Invoke-InTenure { ConvertTo-TenureUtcDateString -Value 42 } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
    }
}

Describe 'User.SignIn' {
    BeforeAll {
        $script:provider = Get-Provider 'User.SignIn'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'alice@example.com' } }
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    Context 'Get' {
        It 'returns id, userPrincipalName and accountEnabled only' {
            $current = & $provider.Get (& $aliceTarget) (New-Context)
            $current | Should -BeOfType [pscustomobject]
            @($current.PSObject.Properties.Name) | Should -Be @('id', 'userPrincipalName', 'accountEnabled')
            $current.id | Should -Be $ids.AliceId
            $current.accountEnabled | Should -BeTrue
            $w.Calls[-1].Uri | Should -Match "users/$($ids.AliceId)\?\`$select=id,userPrincipalName,accountEnabled$"
        }

        It 'throws Tenure.Provider.TargetNotFound for a missing user or a target without an id (and sends nothing for the latter)' {
            { & $provider.Get @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            $count = $w.Calls.Count
            { & $provider.Get @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            $w.Calls.Count | Should -Be $count
        }

        It 'escapes the identity as one path segment' {
            { & $provider.Get @{ Kind = 'user'; Id = 'a/../b?c@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            $w.Calls[-1].Uri | Should -Match 'users/a%2F\.\.%2Fb%3Fc%40example\.com\?'
        }

        It 'fingerprint stability' {
            (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context)))
        }
    }

    Context 'Test' {
        It 'compares accountEnabled exactly' {
            $enabled = [pscustomobject]@{ id = 'x'; userPrincipalName = 'x'; accountEnabled = $true }
            (& $provider.Test $enabled @{ accountEnabled = $true }) | Should -BeTrue
            (& $provider.Test $enabled @{ accountEnabled = $false }) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ accountEnabled = $false }) ([pscustomobject]@{ accountEnabled = $false })) | Should -BeTrue
        }

        It 'is false for a missing current object or a current value that is not a boolean' {
            (& $provider.Test $null @{ accountEnabled = $false }) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ accountEnabled = $null }) @{ accountEnabled = $false }) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ accountEnabled = 'false' }) @{ accountEnabled = $false }) | Should -BeFalse
        }

        It 'refuses a Desired that is not exactly @{ accountEnabled = a boolean }' -ForEach @(
            @{ Desired = @{ accountEnabled = 'false' } }, @{ Desired = @{ accountEnabled = 0 } }, @{ Desired = @{} }, @{ Desired = $null }
            @{ Desired = @{ accountEnabled = $false; department = 'x' } }, @{ Desired = @{ enabled = $false } }
        ) {
            { & $provider.Test ([pscustomobject]@{ accountEnabled = $true }) $Desired } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        }
    }

    Context 'Set' {
        It 'disables sign-in with a PATCH of accountEnabled only, returns a fresh Get and leaves Test true' {
            $desired = @{ accountEnabled = $false }
            $observed = & $provider.Set (& $aliceTarget) $desired $null (New-Context)
            $observed.accountEnabled | Should -BeFalse
            (& $provider.Test $observed $desired) | Should -BeTrue
            (& $provider.Test (& $provider.Get (& $aliceTarget) (New-Context)) $desired) | Should -BeTrue
            (Get-UserRecord $ids.AliceId).accountEnabled | Should -BeFalse
            $patch = @(Get-FakeGraphCall -World $w -Method PATCH)
            $patch.Count | Should -Be 1
            $patch[0].Uri | Should -Match "users/$($ids.AliceId)$"
            $patch[0].Body | Should -BeExactly '{"accountEnabled":false}'
        }

        It 'is reversible: enabling again restores the account' {
            & $provider.Set (& $aliceTarget) @{ accountEnabled = $false } $null (New-Context) | Out-Null
            (& $provider.Set (& $aliceTarget) @{ accountEnabled = $true } $null (New-Context)).accountEnabled | Should -BeTrue
        }

        It 'is idempotent: a second Set is harmless and the state is unchanged' {
            $first = & $provider.Set (& $aliceTarget) @{ accountEnabled = $false } $null (New-Context)
            $second = & $provider.Set (& $aliceTarget) @{ accountEnabled = $false } $first (New-Context)
            (Get-Canonical $second) | Should -BeExactly (Get-Canonical $first)
        }

        It 'refuses a string "false" and sends nothing: it must never read as $true and enable the account' {
            (Get-UserRecord $ids.AliceId).accountEnabled = $false
            { & $provider.Set (& $aliceTarget) @{ accountEnabled = 'false' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            @(Get-Writes).Count | Should -Be 0
            (Get-UserRecord $ids.AliceId).accountEnabled | Should -BeFalse
        }

        It 'accepts a PSCustomObject Desired (as after a plan import)' {
            (& $provider.Set (& $aliceTarget) ([pscustomobject]@{ accountEnabled = $false }) $null (New-Context)).accountEnabled | Should -BeFalse
        }

        It 'a missing user surfaces as Tenure.Graph.NotFound on the write' {
            { & $provider.Set @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } @{ accountEnabled = $false } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
        }
    }

    Context 'Describe' {
        It 'shows the change as "enabled: true -> false" on one line' {
            $current = & $provider.Get (& $aliceTarget) (New-Context)
            (& $provider.Describe (& $aliceTarget) $current @{ accountEnabled = $false } 'Update') | Should -Be 'Update sign-in of alice@example.com (enabled: true -> false)'
            (& $provider.Describe (& $aliceTarget) $null @{ accountEnabled = $true } 'Update') | Should -Be 'Update sign-in of alice@example.com (enabled: unknown -> true)'
        }
    }
}

Describe 'User.Password' {
    BeforeAll {
        $script:provider = Get-Provider 'User.Password'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'alice@example.com' } }
        $script:patchBody = { @(Get-FakeGraphCall -World $script:w -Method PATCH)[-1].Body | ConvertFrom-Json }
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    Context 'Get and Test' {
        It 'returns id, userPrincipalName and lastPasswordChangeDateTime as a UTC o string, and nothing secret' {
            $current = & $provider.Get (& $aliceTarget) (New-Context)
            @($current.PSObject.Properties.Name) | Should -Be @('id', 'userPrincipalName', 'lastPasswordChangeDateTime')
            $current.lastPasswordChangeDateTime | Should -BeExactly '2026-01-15T09:00:00.0000000Z'
            ($current | ConvertTo-Json) | Should -Not -Match 'password"'
        }

        It 'throws TargetNotFound for a missing user and is stable across two reads' {
            { & $provider.Get @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context)))
        }

        It 'Test is always false (an Invoke provider; SPEC 2.2)' {
            (& $provider.Test (& $provider.Get (& $aliceTarget) (New-Context)) @{}) | Should -BeFalse
            (& $provider.Test $null $null) | Should -BeFalse
        }
    }

    Context 'Set with discard (the default, used for offboarding)' {
        It 'resets the password, keeps nothing in Context.Secrets and says it was discarded' {
            $context = New-Context
            $observed = & $provider.Set (& $aliceTarget) $null $null $context
            $context.Secrets.Count | Should -Be 0
            $observed.discarded | Should -BeTrue
            @($observed.PSObject.Properties.Name) | Should -Be @('id', 'userPrincipalName', 'lastPasswordChangeDateTime', 'discarded')
            $observed.lastPasswordChangeDateTime | Should -Not -Be '2026-01-15T09:00:00.0000000Z' -Because 'the reset moved it'
            @($w.SecretDigests | Where-Object { $_.Kind -eq 'password' -and $_.UserId -eq $ids.AliceId }).Count | Should -Be 1 -Because 'Graph received a new password'
        }

        It 'works with no Context at all: nothing needs to be handed back' {
            (& $provider.Set (& $aliceTarget) @{ discard = $true } $null $null).discarded | Should -BeTrue
        }

        It 'sends forceChangePasswordNextSignIn = true and a password the call log only knows as a digest' {
            & $provider.Set (& $aliceTarget) @{} $null (New-Context) | Out-Null
            $body = & $patchBody
            @($body.PSObject.Properties.Name) | Should -Be @('passwordProfile')
            $body.passwordProfile.forceChangePasswordNextSignIn | Should -BeTrue
            $digest = @($w.SecretDigests | Where-Object Kind -eq 'password')[-1].Sha256
            $body.passwordProfile.password | Should -BeExactly "redacted:sha256:$digest"
        }

        It 'generates a fresh password each time: a second Set is harmless and resets again' {
            & $provider.Set (& $aliceTarget) @{} $null (New-Context) | Out-Null
            & $provider.Set (& $aliceTarget) @{} $null (New-Context) | Out-Null
            $digests = @($w.SecretDigests | Where-Object Kind -eq 'password')
            $digests.Count | Should -Be 2
            $digests[0].Sha256 | Should -Not -Be $digests[1].Sha256
        }
    }

    Context 'Set with discard = $false' {
        It 'puts the new password in Context.Secrets[StepId] as a SecureString that is exactly what Graph received' {
            $context = New-Context
            $observed = & $provider.Set (& $aliceTarget) @{ discard = $false } $null $context
            $observed.discarded | Should -BeFalse
            $context.Secrets.Keys | Should -Be @('S03')
            $context.Secrets['S03'] | Should -BeOfType [System.Security.SecureString]
            (Get-PlainText $context.Secrets['S03']).Length | Should -Be 20
            Test-DigestRecorded $context.Secrets['S03'] 'password' | Should -BeTrue
        }

        It 'falls back to the target id as the secret key without a StepId' {
            $context = New-Context
            $context.Remove('StepId')
            & $provider.Set (& $aliceTarget) @{ discard = $false } $null $context | Out-Null
            $context.Secrets.Keys | Should -Be @($ids.AliceId)
        }

        It 'uses policy defaults.passwordLength, clamped to 12..128' -ForEach @(@{ Configured = 32; Expected = 32 }, @{ Configured = 4; Expected = 12 }, @{ Configured = 999; Expected = 128 }) {
            $context = New-Context -Extra @{ Policy = [pscustomobject]@{ Defaults = @{ passwordLength = $Configured } } }
            & $provider.Set (& $aliceTarget) @{ discard = $false } $null $context | Out-Null
            (Get-PlainText $context.Secrets['S03']).Length | Should -Be $Expected
        }

        It 'honors forceChangePasswordNextSignIn = $false' {
            & $provider.Set (& $aliceTarget) @{ discard = $false; forceChangePasswordNextSignIn = $false } $null (New-Context) | Out-Null
            (& $patchBody).passwordProfile.forceChangePasswordNextSignIn | Should -BeFalse
        }

        It 'refuses without Context.Secrets, before generating or sending anything' {
            { & $provider.Set (& $aliceTarget) @{ discard = $false } $null @{ StepId = 'S03' } } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            { & $provider.Set (& $aliceTarget) @{ discard = $false } $null $null } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            $w.Calls.Count | Should -Be 0
        }

        It 'never leaks the password into the world, the call log, the verbose stream, the return value or Describe' {
            $context = New-Context
            $run = Invoke-WithVerbose { & $provider.Set (& $aliceTarget) @{ discard = $false } $null $context }
            $plain = Get-PlainText $context.Secrets['S03']
            $run.Verbose | Should -Match 'PATCH' -Because 'the verbose stream was captured'
            Assert-Absent $run.Verbose $plain 'the verbose stream'
            Assert-Absent ($run.Output | ConvertTo-Json -Depth 10) $plain 'the return value'
            Assert-Absent (Get-Canonical $run.Output[0]) $plain 'the canonical return value'
            Assert-Absent ($w.Calls | ConvertTo-Json -Depth 10) $plain 'the call log'
            Assert-Absent ($w.Users | ConvertTo-Json -Depth 10) $plain 'the stored users'
            Assert-Absent (& $provider.Describe (& $aliceTarget) $null @{ discard = $false } 'Invoke') $plain 'Describe'
        }

        It 'a failed reset leaves nothing in Context.Secrets' {
            Add-FakeGraphFault -World $w -Status 400 -Code 'Request_BadRequest' -Message 'The specified password does not comply with password complexity requirements.' -Method PATCH
            $context = New-Context
            $failure = { & $provider.Set (& $aliceTarget) @{ discard = $false } $null $context } | Should -Throw -ErrorId 'Tenure.Graph.Failed' -PassThru
            $context.Secrets.Count | Should -Be 0
            $failure.Exception.Message | Should -Not -Match 'redacted|sha256'
        }
    }

    Context 'Desired validation' {
        It 'refuses <Label> and sends nothing' -ForEach @(
            @{ Label = 'a string discard'; Desired = @{ discard = 'false' } }
            @{ Label = 'a number for forceChangePasswordNextSignIn'; Desired = @{ forceChangePasswordNextSignIn = 0 } }
            @{ Label = 'a password key'; Desired = @{ password = 'Zk7#mQ4!vRt9wXp2' } }
            @{ Label = 'an unknown key'; Desired = @{ length = 30 } }
        ) {
            $failure = { & $provider.Set (& $aliceTarget) $Desired $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired' -PassThru
            $failure.Exception.Message | Should -Not -Match 'Zk7'
            $w.Calls.Count | Should -Be 0
        }

        It 'treats $null values as the defaults (discard, force change)' {
            $context = New-Context
            (& $provider.Set (& $aliceTarget) @{ discard = $null; forceChangePasswordNextSignIn = $null } $null $context).discarded | Should -BeTrue
            $context.Secrets.Count | Should -Be 0
            (& $patchBody).passwordProfile.forceChangePasswordNextSignIn | Should -BeTrue
        }
    }

    Context 'Describe' {
        It 'says whether the password is discarded or returned' {
            (& $provider.Describe (& $aliceTarget) $null $null 'Invoke') | Should -Be 'Invoke password of alice@example.com: reset to a random password (discarded)'
            (& $provider.Describe (& $aliceTarget) $null @{ discard = $false } 'Invoke') | Should -Be 'Invoke password of alice@example.com: reset to a random password (returned on the apply result), change required at next sign-in'
            (& $provider.Describe (& $aliceTarget) $null @{ discard = $false; forceChangePasswordNextSignIn = $false } 'Invoke') | Should -Be 'Invoke password of alice@example.com: reset to a random password (returned on the apply result)'
        }
    }
}

Describe 'User.Sessions' {
    BeforeAll {
        $script:provider = Get-Provider 'User.Sessions'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'alice@example.com' } }
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    It 'Get returns id and userPrincipalName only, so a revoke never moves its own snapshot, and is stable' {
        $current = & $provider.Get (& $aliceTarget) (New-Context)
        @($current.PSObject.Properties.Name) | Should -Be @('id', 'userPrincipalName')
        (Get-Canonical $current) | Should -BeExactly (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context)))
        & $provider.Set (& $aliceTarget) $null $null (New-Context) | Out-Null
        (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context))) | Should -BeExactly (Get-Canonical $current) -Because 'signInSessionsValidFromDateTime moved, and is not in the snapshot'
        { & $provider.Get @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }

    It 'Set POSTs revokeSignInSessions with no body, and Graph moves signInSessionsValidFromDateTime' {
        $observed = & $provider.Set (& $aliceTarget) $null $null (New-Context)
        $observed.id | Should -Be $ids.AliceId
        (Get-UserRecord $ids.AliceId).signInSessionsValidFromDateTime | Should -Not -Be '2026-01-15T09:00:00Z'
        @($w.SignInSessionsRevoked) | Should -Be @($ids.AliceId)
        $post = @(Get-FakeGraphCall -World $w -Method POST)
        $post.Count | Should -Be 1
        $post[0].Uri | Should -Match "users/$($ids.AliceId)/revokeSignInSessions$"
        $post[0].Body | Should -BeNullOrEmpty
    }

    It 'ignores Desired and is harmless to run twice' {
        & $provider.Set (& $aliceTarget) @{} $null (New-Context) | Out-Null
        & $provider.Set (& $aliceTarget) @{ anything = 1 } $null (New-Context) | Out-Null
        @($w.SignInSessionsRevoked).Count | Should -Be 2
    }

    It 'Test is always false (an Invoke provider)' {
        (& $provider.Test (& $provider.Get (& $aliceTarget) (New-Context)) $null) | Should -BeFalse
    }

    It 'an explicit value = false from Graph is a failure, never reported as revoked' {
        $w.Faults.Enqueue(@{ Status = 200; Body = @{ value = $false }; Method = 'POST' })
        { & $provider.Set (& $aliceTarget) $null $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.UnexpectedResponse'
    }

    It 'a missing user surfaces as Tenure.Graph.NotFound on the POST' {
        { & $provider.Set @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } $null $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
    }

    It 'Describe names what is and is not revoked' {
        (& $provider.Describe (& $aliceTarget) $null $null 'Invoke') | Should -Be 'Invoke sessions of alice@example.com: revoke all sign-in sessions (refresh tokens; access tokens expire within an hour)'
    }
}

Describe 'DirectoryRole.Member' {
    BeforeAll {
        $script:provider = Get-Provider 'DirectoryRole.Member'
        $script:roleTarget = { @{ Kind = 'role'; Id = $script:ids.GlobalAdminRoleId; Name = 'Global Administrator' } }
        $script:roleMembers = { @(($script:w.DirectoryRoles | Where-Object id -eq $script:ids.GlobalAdminRoleId).members) }
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    Context 'Get' {
        It 'reports the role and whether the subject is a direct member' {
            $carol = & $provider.Get (& $roleTarget) (New-Context $ids.CarolId)
            $carol | Should -BeOfType [pscustomobject]
            @($carol.PSObject.Properties.Name) | Should -Be @('roleId', 'displayName', 'roleTemplateId', 'userId', 'member')
            $carol.roleId | Should -Be $ids.GlobalAdminRoleId
            $carol.displayName | Should -Be 'Global Administrator'
            $carol.roleTemplateId | Should -Be '41000000-0000-4000-8000-000000000001'
            $carol.userId | Should -Be $ids.CarolId
            $carol.member | Should -BeTrue
            (& $provider.Get (& $roleTarget) (New-Context $ids.AliceId)).member | Should -BeFalse
        }

        It 'pages through the member list' {
            $w.PageSize = 1
            ($w.DirectoryRoles | Where-Object id -eq $ids.GlobalAdminRoleId).members = [string[]]@($ids.AliceId, $ids.BobId, $ids.CarolId)
            (& $provider.Get (& $roleTarget) (New-Context $ids.CarolId)).member | Should -BeTrue
            @(Get-FakeGraphCall -World $w -Method GET -UriLike '*members*').Count | Should -Be 3
        }

        It 'without a subject it reads member = $false and userId = $null, and asks Graph only about the role' {
            $current = & $provider.Get (& $roleTarget) (New-Context)
            $current.member | Should -BeFalse
            $current.userId | Should -BeNullOrEmpty
            $w.Calls.Count | Should -Be 1
            (& $provider.Get (& $roleTarget) $null).member | Should -BeFalse
        }

        It 'throws Tenure.Provider.TargetNotFound for a role that is not activated, or a target without an id' {
            { & $provider.Get @{ Kind = 'role'; Id = '99999999-9999-4999-8999-999999999999'; Name = 'Ghost' } (New-Context $ids.CarolId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            { & $provider.Get @{ Kind = 'role'; Id = $null; Name = 'Ghost' } (New-Context $ids.CarolId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'a full (possibly truncated) page that lacks the user is confirmed with a direct lookup' {
            $filler = @(1..1000 | ForEach-Object { @{ id = ('70000000-0000-4000-8000-{0:D12}' -f $_) } })
            $w.Faults.Enqueue(@{ Status = 200; Body = @{ value = $filler }; Method = 'GET'; UriLike = '*/members[?]*' })
            (& $provider.Get (& $roleTarget) (New-Context $ids.CarolId)).member | Should -BeTrue -Because 'carol is a member; the list just did not show her'
            @(Get-FakeGraphCall -World $w -Method GET -UriLike "*/members/$($ids.CarolId)*").Count | Should -Be 1
            $w.Faults.Enqueue(@{ Status = 200; Body = @{ value = $filler }; Method = 'GET'; UriLike = '*/members[?]*' })
            (& $provider.Get (& $roleTarget) (New-Context $ids.AliceId)).member | Should -BeFalse
        }

        It 'a direct-lookup failure other than 404 is an error, not a "no"' {
            $filler = @(1..1000 | ForEach-Object { @{ id = ('70000000-0000-4000-8000-{0:D12}' -f $_) } })
            $w.Faults.Enqueue(@{ Status = 200; Body = @{ value = $filler }; Method = 'GET'; UriLike = '*/members[?]*' })
            Add-FakeGraphFault -World $w -Status 403 -Method GET -UriLike "*/members/$($ids.AliceId)*"
            { & $provider.Get (& $roleTarget) (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }

        It 'a short list does not trigger the direct lookup' {
            & $provider.Get (& $roleTarget) (New-Context $ids.AliceId) | Out-Null
            @(Get-FakeGraphCall -World $w -Method GET -UriLike "*/members/*").Count | Should -Be 0
        }

        It 'fingerprint stability' {
            (Get-Canonical (& $provider.Get (& $roleTarget) (New-Context $ids.CarolId))) | Should -BeExactly (Get-Canonical (& $provider.Get (& $roleTarget) (New-Context $ids.CarolId)))
        }
    }

    Context 'Test' {
        It 'is true only when member matches for the same user (ids compared ignoring case)' {
            $current = [pscustomobject]@{ roleId = 'r'; displayName = 'R'; roleTemplateId = 't'; userId = $ids.CarolId; member = $true }
            (& $provider.Test $current @{ userId = $ids.CarolId; member = $true }) | Should -BeTrue
            (& $provider.Test $current @{ userId = $ids.CarolId.ToUpperInvariant(); member = $true }) | Should -BeTrue
            (& $provider.Test $current @{ userId = $ids.CarolId; member = $false }) | Should -BeFalse
        }

        It 'is never satisfied by a read about nobody or about someone else' {
            $nobody = [pscustomobject]@{ roleId = 'r'; displayName = 'R'; roleTemplateId = 't'; userId = $null; member = $false }
            (& $provider.Test $nobody @{ userId = $ids.CarolId; member = $false }) | Should -BeFalse
            $other = [pscustomobject]@{ roleId = 'r'; displayName = 'R'; roleTemplateId = 't'; userId = $ids.AliceId; member = $false }
            (& $provider.Test $other @{ userId = $ids.CarolId; member = $false }) | Should -BeFalse
            (& $provider.Test $null @{ userId = $ids.CarolId; member = $false }) | Should -BeFalse
        }

        It 'refuses <Label>' -ForEach @(
            @{ Label = 'a string member'; Desired = @{ userId = '10000000-0000-4000-8000-000000000003'; member = 'false' } }
            @{ Label = 'a missing member'; Desired = @{ userId = '10000000-0000-4000-8000-000000000003' } }
            @{ Label = 'a missing userId'; Desired = @{ member = $false } }
            @{ Label = 'the {{subjectId}} placeholder'; Desired = @{ userId = '{{subjectId}}'; member = $false } }
            @{ Label = 'an unknown key'; Desired = @{ userId = '10000000-0000-4000-8000-000000000003'; member = $false; roleId = 'x' } }
            @{ Label = 'no Desired'; Desired = $null }
        ) {
            { & $provider.Test ([pscustomobject]@{ userId = $ids.CarolId; member = $true }) $Desired } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set (& $roleTarget) $Desired $null (New-Context $ids.CarolId) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            $w.Calls.Count | Should -Be 0
        }
    }

    Context 'Set: remove' {
        It 'removes the user with DELETE members/{uid}/$ref, returns a fresh Get and leaves Test true' {
            $desired = @{ userId = $ids.CarolId; member = $false }
            $observed = & $provider.Set (& $roleTarget) $desired $null (New-Context $ids.CarolId)
            $observed.member | Should -BeFalse
            $observed.userId | Should -Be $ids.CarolId
            (& $provider.Test $observed $desired) | Should -BeTrue
            (& $provider.Test (& $provider.Get (& $roleTarget) (New-Context $ids.CarolId)) $desired) | Should -BeTrue
            & $roleMembers | Should -Not -Contain $ids.CarolId
            $delete = @(Get-FakeGraphCall -World $w -Method DELETE)
            $delete.Count | Should -Be 1
            $delete[0].Uri | Should -Match "directoryRoles/$($ids.GlobalAdminRoleId)/members/$($ids.CarolId)/\`$ref$"
        }

        It 'removing a non-member is idempotent: the 404 on the DELETE is the goal state' {
            $desired = @{ userId = $ids.AliceId; member = $false }
            $observed = & $provider.Set (& $roleTarget) $desired $null (New-Context $ids.AliceId)
            $observed.member | Should -BeFalse
            (& $provider.Test $observed $desired) | Should -BeTrue
            & $roleMembers | Should -Be @($ids.CarolId)
        }

        It 'removing twice is harmless' {
            $desired = @{ userId = $ids.CarolId; member = $false }
            & $provider.Set (& $roleTarget) $desired $null (New-Context $ids.CarolId) | Out-Null
            (& $provider.Set (& $roleTarget) $desired $null (New-Context $ids.CarolId)).member | Should -BeFalse
        }

        It 'reads back the user it changed even when the plan subject is someone else' {
            $observed = & $provider.Set (& $roleTarget) @{ userId = $ids.CarolId; member = $false } $null (New-Context $ids.AliceId)
            $observed.userId | Should -Be $ids.CarolId
            $observed.member | Should -BeFalse
        }

        It 'a role that is not activated is TargetNotFound and nothing is written' {
            { & $provider.Set @{ Kind = 'role'; Id = '99999999-9999-4999-8999-999999999999'; Name = 'Ghost' } @{ userId = $ids.CarolId; member = $false } $null (New-Context $ids.CarolId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            @(Get-Writes).Count | Should -Be 0
        }

        It 'a 403 on the DELETE is not mistaken for "not a member"' {
            Add-FakeGraphFault -World $w -Status 403 -Method DELETE
            { & $provider.Set (& $roleTarget) @{ userId = $ids.CarolId; member = $false } $null (New-Context $ids.CarolId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
            & $roleMembers | Should -Contain $ids.CarolId
        }
    }

    Context 'Set: an add is refused' {
        It 'refuses to add a user to a directory role, before any request: Tenure removes directory roles and never grants them' {
            $failure = { & $provider.Set (& $roleTarget) @{ userId = $ids.AliceId; member = $true } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Unsupported' -PassThru
            $failure.Exception.Message | Should -Match 'Tenure removes directory roles and never grants them'
            $failure.Exception.Data['UserId'] | Should -Be $ids.AliceId
            & $roleMembers | Should -Not -Contain $ids.AliceId
            @(Get-FakeGraphCall -World $w).Count | Should -Be 0 -Because 'nothing is read or written'
        }

        It 'refuses an add for a user who already holds the role too, and for an unknown user' {
            { & $provider.Set (& $roleTarget) @{ userId = $ids.CarolId; member = $true } $null (New-Context $ids.CarolId) } | Should -Throw -ErrorId 'Tenure.Provider.Unsupported'
            { & $provider.Set (& $roleTarget) @{ userId = '99999999-9999-4999-8999-999999999999'; member = $true } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.Unsupported'
            @(Get-Writes).Count | Should -Be 0
            & $roleMembers | Should -Be @($ids.CarolId)
        }

        It 'declares only Remove and NoOp, so no step of it can be labelled an add' {
            @($provider.Actions) | Should -Be @('Remove', 'NoOp')
            { New-TenureStep -Provider 'DirectoryRole.Member' -Target (& $roleTarget) -Desired @{ userId = $ids.AliceId; member = $true } -Context @{ Subject = @{ Id = $ids.AliceId } } -Action Update } | Should -Throw -ErrorId 'Tenure.Step.Invalid'
        }
    }

    Context 'Describe' {
        It 'says who goes out of which role, and that an add is refused' {
            (& $provider.Describe (& $roleTarget) $null @{ userId = $ids.CarolId; member = $false } 'Remove') | Should -Be "Remove user $($ids.CarolId) out of directory role Global Administrator"
            (& $provider.Describe (& $roleTarget) $null @{ userId = $ids.AliceId; member = $true } 'Remove') | Should -Be "Remove user $($ids.AliceId) into directory role Global Administrator (refused: Tenure removes directory roles and never grants them)"
        }
    }
}

Describe 'User.LeaveDate' {
    BeforeAll {
        $script:provider = Get-Provider 'User.LeaveDate'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'alice@example.com' } }
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    It 'Get returns id and employeeLeaveDateTime ($null when unset); missing user is TargetNotFound' {
        $current = & $provider.Get (& $aliceTarget) (New-Context)
        @($current.PSObject.Properties.Name) | Should -Be @('id', 'employeeLeaveDateTime')
        $current.employeeLeaveDateTime | Should -BeNullOrEmpty
        $w.Calls[-1].Uri | Should -Match '\?\$select=id,employeeLeaveDateTime$'
        { & $provider.Get @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }

    It 'sets the date from <Label>, returns it as a UTC o string and leaves Test true' -ForEach @(
        @{ Label = 'a UTC [datetime]'; Value = [datetime]::new(2026, 10, 31, 17, 0, 0, [System.DateTimeKind]::Utc) }
        @{ Label = 'a Z string'; Value = '2026-10-31T17:00:00Z' }
        @{ Label = 'an offset string'; Value = '2026-10-31T12:00:00-05:00' }
        @{ Label = 'a string with fractional seconds'; Value = '2026-10-31T17:00:00.6543210Z' }
    ) {
        $desired = @{ employeeLeaveDateTime = $Value }
        $observed = & $provider.Set (& $aliceTarget) $desired $null (New-Context)
        $observed.employeeLeaveDateTime | Should -BeExactly '2026-10-31T17:00:00.0000000Z'
        (& $provider.Test $observed $desired) | Should -BeTrue
        (& $provider.Test (& $provider.Get (& $aliceTarget) (New-Context)) $desired) | Should -BeTrue
        (@(Get-FakeGraphCall -World $w -Method PATCH)[-1].Body | ConvertFrom-Json -DateKind String).employeeLeaveDateTime | Should -BeExactly '2026-10-31T17:00:00Z'
    }

    It 'Test compares at whole seconds and is false for a different second or a missing value' {
        $current = [pscustomobject]@{ id = 'x'; employeeLeaveDateTime = '2026-10-31T17:00:00.0000000Z' }
        (& $provider.Test $current @{ employeeLeaveDateTime = '2026-10-31T17:00:00.999Z' }) | Should -BeTrue
        (& $provider.Test $current @{ employeeLeaveDateTime = '2026-10-31T17:00:01Z' }) | Should -BeFalse
        (& $provider.Test $current @{ employeeLeaveDateTime = $null }) | Should -BeFalse
        (& $provider.Test ([pscustomobject]@{ id = 'x'; employeeLeaveDateTime = $null }) @{ employeeLeaveDateTime = $null }) | Should -BeTrue
        (& $provider.Test $null @{ employeeLeaveDateTime = $null }) | Should -BeFalse
        # The live side is truncated too: a stored value with a fraction still matches its second.
        (& $provider.Test ([pscustomobject]@{ id = 'x'; employeeLeaveDateTime = '2026-10-31T17:00:00.5000000Z' }) @{ employeeLeaveDateTime = '2026-10-31T17:00:00Z' }) | Should -BeTrue
    }

    It 'clears the date with $null, and a second Set is harmless' {
        & $provider.Set (& $aliceTarget) @{ employeeLeaveDateTime = '2026-10-31T17:00:00Z' } $null (New-Context) | Out-Null
        $first = & $provider.Set (& $aliceTarget) @{ employeeLeaveDateTime = $null } $null (New-Context)
        $first.employeeLeaveDateTime | Should -BeNullOrEmpty
        $second = & $provider.Set (& $aliceTarget) @{ employeeLeaveDateTime = $null } $first (New-Context)
        (Get-Canonical $second) | Should -BeExactly (Get-Canonical $first)
    }

    It 'refuses <Label> and sends nothing' -ForEach @(
        @{ Label = 'a date it cannot read'; Desired = @{ employeeLeaveDateTime = 'end of the month' } }
        @{ Label = 'a number'; Desired = @{ employeeLeaveDateTime = 20261031 } }
        @{ Label = 'a missing key (a typo must not clear the date)'; Desired = @{ employeeLeaveDate = '2026-10-31T17:00:00Z' } }
        @{ Label = 'no Desired'; Desired = $null }
        @{ Label = 'an extra key'; Desired = @{ employeeLeaveDateTime = '2026-10-31T17:00:00Z'; department = 'x' } }
    ) {
        { & $provider.Set (& $aliceTarget) $Desired $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        @(Get-Writes).Count | Should -Be 0
    }

    It 'Describe names the date, or none' {
        (& $provider.Describe (& $aliceTarget) $null @{ employeeLeaveDateTime = '2026-10-31T17:00:00Z' } 'Update') | Should -Be 'Update leave date of alice@example.com to 2026-10-31T17:00:00.0000000Z'
        (& $provider.Describe (& $aliceTarget) $null @{ employeeLeaveDateTime = $null } 'Update') | Should -Be 'Update leave date of alice@example.com to none'
    }

    It 'fingerprint stability once a date is set' {
        & $provider.Set (& $aliceTarget) @{ employeeLeaveDateTime = '2026-10-31T17:00:00Z' } $null (New-Context) | Out-Null
        (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context)))
    }
}

Describe 'User.TemporaryAccessPass Set' {
    BeforeAll {
        $script:provider = Get-Provider 'User.TemporaryAccessPass'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'alice@example.com' } }
        $script:postBody = { @(Get-FakeGraphCall -World $script:w -Method POST)[-1].Body | ConvertFrom-Json }
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    It 'stores exactly the pass Graph issued, as a SecureString in Context.Secrets[StepId], and the literal appears nowhere else' {
        $context = New-Context
        $run = Invoke-WithVerbose { & $provider.Set (& $aliceTarget) @{} $null $context }
        $context.Secrets.Keys | Should -Be @('S03')
        $context.Secrets['S03'] | Should -BeOfType [System.Security.SecureString]
        Test-DigestRecorded $context.Secrets['S03'] 'tap' | Should -BeTrue
        @($w.SecretDigests | Where-Object Kind -eq 'tap').Count | Should -Be 1
        $pass = Get-PlainText $context.Secrets['S03']
        $pass | Should -Match '^TAP-'

        $run.Output.Count | Should -Be 1
        $run.Verbose | Should -Match 'temporaryAccessPassMethods' -Because 'the verbose stream was captured'
        Assert-Absent $run.Verbose $pass 'the verbose stream'
        Assert-Absent ($run.Output[0] | ConvertTo-Json -Depth 10) $pass 'the returned object'
        Assert-Absent (Get-Canonical $run.Output[0]) $pass 'the canonical returned object'
        Assert-Absent ($w.Calls | ConvertTo-Json -Depth 10) $pass 'World.Calls'
        Assert-Absent ($w.TapMethods | ConvertTo-Json -Depth 10) $pass 'the stored methods'
        Assert-Absent (& $provider.Describe (& $aliceTarget) $null @{} 'Invoke') $pass 'Describe'
        Assert-Absent (& $provider.Describe (& $aliceTarget) (& $provider.Get (& $aliceTarget) (New-Context)) @{} 'Invoke') $pass 'Describe with a current state'
        Assert-Absent (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context))) $pass 'a later Get'
    }

    It 'returns the method without the pass: id, startDateTime (UTC o), lifetimeInMinutes, isUsableOnce, methodUsabilityReason' {
        $observed = & $provider.Set (& $aliceTarget) $null $null (New-Context)
        @($observed.PSObject.Properties.Name) | Should -Be @('id', 'startDateTime', 'lifetimeInMinutes', 'isUsableOnce', 'methodUsabilityReason')
        { [guid]$observed.id } | Should -Not -Throw
        $observed.startDateTime | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$'
        $observed.lifetimeInMinutes | Should -Be 480
        $observed.isUsableOnce | Should -BeTrue
        $observed.methodUsabilityReason | Should -Be 'EnabledByPolicy'
    }

    It 'sends lifetimeInMinutes 480 and isUsableOnce true by default, and no startDateTime' {
        & $provider.Set (& $aliceTarget) @{} $null (New-Context) | Out-Null
        $body = & $postBody
        @($body.PSObject.Properties.Name | Sort-Object) | Should -Be @('isUsableOnce', 'lifetimeInMinutes')
        $body.lifetimeInMinutes | Should -Be 480
        $body.isUsableOnce | Should -BeTrue
    }

    It 'honors a custom lifetime and a multi-use pass' {
        $observed = & $provider.Set (& $aliceTarget) @{ lifetimeInMinutes = 60; isUsableOnce = $false } $null (New-Context)
        $observed.lifetimeInMinutes | Should -Be 60
        $observed.isUsableOnce | Should -BeFalse
        (& $postBody).lifetimeInMinutes | Should -Be 60
    }

    It 'falls back to the target id as the secret key without a StepId' {
        $context = New-Context
        $context.Remove('StepId')
        & $provider.Set (& $aliceTarget) @{} $null $context | Out-Null
        $context.Secrets.Keys | Should -Be @($ids.AliceId)
    }

    It 'refuses without Context.Secrets, before sending anything' {
        { & $provider.Set (& $aliceTarget) @{} $null @{ StepId = 'S03' } } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
        { & $provider.Set (& $aliceTarget) @{} $null $null } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
        $w.Calls.Count | Should -Be 0
    }

    It 'refuses <Label> and sends nothing' -ForEach @(
        @{ Label = 'a lifetime below 10'; Desired = @{ lifetimeInMinutes = 5 } }
        @{ Label = 'a lifetime above 43200'; Desired = @{ lifetimeInMinutes = 43201 } }
        @{ Label = 'a fractional lifetime'; Desired = @{ lifetimeInMinutes = 60.5 } }
        @{ Label = 'a string lifetime'; Desired = @{ lifetimeInMinutes = '60' } }
        @{ Label = 'a string isUsableOnce'; Desired = @{ isUsableOnce = 'false' } }
        @{ Label = 'a startDateTime'; Desired = @{ startDateTime = '2026-11-01T09:00:00Z' } }
    ) {
        $context = New-Context
        { & $provider.Set (& $aliceTarget) $Desired $null $context } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        $w.Calls.Count | Should -Be 0
        $context.Secrets.Count | Should -Be 0
    }

    It 'a response without a pass is a failure and hands back nothing' {
        $w.Faults.Enqueue(@{ Status = 201; Body = @{ id = '60000000-0000-4000-8000-000000000001'; lifetimeInMinutes = 480; isUsableOnce = $true; temporaryAccessPass = $null }; Method = 'POST' })
        $context = New-Context
        { & $provider.Set (& $aliceTarget) @{} $null $context } | Should -Throw -ErrorId 'Tenure.Provider.UnexpectedResponse'
        $context.Secrets.Count | Should -Be 0
    }

    It 'a failed POST hands back nothing' {
        Add-FakeGraphFault -World $w -Status 400 -Code 'Request_BadRequest' -Message 'Temporary Access Pass is disabled by policy.' -Method POST
        $context = New-Context
        { & $provider.Set (& $aliceTarget) @{} $null $context } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
        $context.Secrets.Count | Should -Be 0
    }

    It 'a second Set issues a new pass (harmless) and Get then reports a usable method' {
        $first = New-Context
        $second = New-Context
        & $provider.Set (& $aliceTarget) @{} $null $first | Out-Null
        & $provider.Set (& $aliceTarget) @{} $null $second | Out-Null
        (Get-PlainText $first.Secrets['S03']) | Should -Not -Be (Get-PlainText $second.Secrets['S03'])
        (& $provider.Get (& $aliceTarget) (New-Context)).hasUsable | Should -BeTrue
    }

    It 'a missing user surfaces as Tenure.Graph.NotFound and hands back nothing' {
        $context = New-Context
        { & $provider.Set @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } @{} $null $context } | Should -Throw -ErrorId 'Tenure.Graph.NotFound'
        $context.Secrets.Count | Should -Be 0
    }
}

Describe 'Identity providers through the apply engine' {
    BeforeAll {
        $script:SavedConfirm = $global:ConfirmPreference
        $global:ConfirmPreference = 'None'
        # A plan records the policy it was built from; the engine refuses one that records none.
        $script:ExamplePolicy = Get-TenurePolicy -Path (Join-Path $script:TenureSourceRoot 'Policies' 'example.policy.json')
    }

    AfterAll { $global:ConfirmPreference = $script:SavedConfirm }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
        # Make alice a Global Administrator so the offboard removes a role.
        ($w.DirectoryRoles | Where-Object id -eq $ids.GlobalAdminRoleId).members = [string[]]@($ids.CarolId, $ids.AliceId)
        $script:subject = @{ Id = $ids.AliceId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice Example' }
        $script:userTarget = @{ Kind = 'user'; Id = $ids.AliceId; Name = 'alice@example.com' }
        $script:audit = Join-Path $TestDrive ("audit-{0}.jsonl" -f [guid]::NewGuid().ToString('N'))
        $script:out = Join-Path $TestDrive ("plan-{0}.json" -f [guid]::NewGuid().ToString('N'))
    }

    It 'an offboard core (disable, discarded reset, revoke, role removal, leave date) applies, verifies and leaves no secret anywhere' {
        $context = @{ Subject = $subject }
        $steps = @(
            New-TenureStep -Provider 'User.SignIn' -Target $userTarget -Desired @{ accountEnabled = $false } -Key 'disable' -Context $context
            New-TenureStep -Provider 'User.Password' -Target $userTarget -Desired @{ discard = $true } -Key 'reset' -DependsOn 'disable' -Context $context
            New-TenureStep -Provider 'User.Sessions' -Target $userTarget -Key 'revoke' -DependsOn 'disable', 'reset' -Context $context
            New-TenureStep -Provider 'DirectoryRole.Member' -Target @{ Kind = 'role'; Id = $ids.GlobalAdminRoleId; Name = 'Global Administrator' } -Desired @{ userId = $ids.AliceId; member = $false } -Key 'role' -Context $context
            New-TenureStep -Provider 'User.LeaveDate' -Target $userTarget -Desired @{ employeeLeaveDateTime = '2026-10-31T17:00:00Z' } -Key 'leave' -Context $context
        )
        @($steps.Action) | Should -Be @('Update', 'Invoke', 'Invoke', 'Remove', 'Update') -Because 'DirectoryRole.Member only removes, so its step is a Remove'
        $plan = New-TenurePlan -Operation 'Offboard' -Subject $subject -Step $steps -Policy $script:ExamplePolicy
        $result = Invoke-TenurePlan -Plan $plan -AuditPath $audit -OutFile $out -Confirm:$false

        @($result.Plan.Steps.Status) | Should -Be @('Applied', 'Applied', 'Applied', 'Applied', 'Applied')
        $result.Plan.Status | Should -Be 'Applied'
        $result.Secrets.Count | Should -Be 0 -Because 'an offboarding reset is discarded'
        (Get-UserRecord $ids.AliceId).accountEnabled | Should -BeFalse
        @($w.SignInSessionsRevoked) | Should -Be @($ids.AliceId)
        @(($w.DirectoryRoles | Where-Object id -eq $ids.GlobalAdminRoleId).members) | Should -Be @($ids.CarolId)
        (Get-UserRecord $ids.AliceId).employeeLeaveDateTime | Should -Be '2026-10-31T17:00:00Z'
        @($w.SecretDigests | Where-Object { $_.Kind -eq 'password' -and $_.UserId -eq $ids.AliceId }).Count | Should -Be 1
        (Test-TenureAudit -Path $audit).Valid | Should -BeTrue
        $auditText = [System.IO.File]::ReadAllText($audit)
        $auditText | Should -Not -Match 'passwordProfile|redacted:sha256'
    }

    It 'a returned password and a pass reach ApplyResult.Secrets only, never the plan, the plan file or the audit log' {
        $context = @{ Subject = $subject }
        $steps = @(
            New-TenureStep -Provider 'User.Password' -Target $userTarget -Desired @{ discard = $false } -Key 'reset' -Context $context
            New-TenureStep -Provider 'User.TemporaryAccessPass' -Target $userTarget -Desired @{ lifetimeInMinutes = 60 } -Key 'tap' -Context $context
        )
        $plan = New-TenurePlan -Operation 'Custom' -Subject $subject -Step $steps -Policy $script:ExamplePolicy
        $result = Invoke-TenurePlan -Plan $plan -AuditPath $audit -OutFile $out -Confirm:$false -Verbose 4>$null

        @($result.Plan.Steps.Status) | Should -Be @('Applied', 'Applied')
        @($result.Secrets.Keys | Sort-Object) | Should -Be @('S01', 'S02')
        Test-DigestRecorded $result.Secrets['S01'] 'password' | Should -BeTrue
        Test-DigestRecorded $result.Secrets['S02'] 'tap' | Should -BeTrue
        foreach ($secret in $result.Secrets.Values) {
            $plain = Get-PlainText $secret
            Assert-Absent ([System.IO.File]::ReadAllText($audit)) $plain 'the audit log'
            Assert-Absent ([System.IO.File]::ReadAllText($out)) $plain 'the plan file'
            Assert-Absent (Get-Canonical $result.Plan) $plain 'the canonical plan'
            Assert-Absent ($w.Calls | ConvertTo-Json -Depth 10) $plain 'World.Calls'
        }
    }
}
