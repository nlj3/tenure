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
    # Everything Graph says about a user's licenses (the provider's snapshot keeps only the direct SKUs).
    function Get-LicenseState([string]$UserId) { Invoke-InTenure { param($id) Get-TenureUserLicenseState -UserId $id } @($UserId) }
    function New-Context([hashtable]$Extra = @{}) {
        $context = @{ Secrets = @{}; StepId = 'S02'; Mode = 'Apply'; Subject = @{ Id = $null; UserPrincipalName = $null; DisplayName = $null } }
        foreach ($key in $Extra.Keys) { $context[$key] = $Extra[$key] }
        $context
    }
    function Get-Posts { param([string]$Like) @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method POST -UriLike $Like) }
    # The password Graph received, as its digest; compare with a SecureString under test.
    function Test-DigestRecorded([System.Security.SecureString]$Secure, [string]$Kind) {
        $hash = Get-FakeGraphSha256 -Text (Get-PlainText $Secure)
        @($global:FakeGraphWorld.SecretDigests | Where-Object { $_.Kind -eq $Kind -and $_.Sha256 -eq $hash }).Count -eq 1
    }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeGraphSleeps -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'provider registration' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    It 'registers the six user providers with the agreed metadata' -ForEach @(
        @{ Name = 'User.Create'; Kind = 'State'; Risk = 'High'; Scopes = @('User.ReadWrite.All') }
        @{ Name = 'User.Attributes'; Kind = 'State'; Risk = 'Low'; Scopes = @('User.ReadWrite.All') }
        @{ Name = 'User.Manager'; Kind = 'State'; Risk = 'Low'; Scopes = @('User.ReadWrite.All') }
        @{ Name = 'User.Licenses'; Kind = 'State'; Risk = 'Medium'; Scopes = @('User.ReadWrite.All', 'Organization.Read.All') }
        @{ Name = 'User.TemporaryAccessPass'; Kind = 'Invoke'; Risk = 'High'; Scopes = @('UserAuthenticationMethod.ReadWrite.All') }
    ) {
        $provider = Get-Provider $Name
        $provider.Kind | Should -Be $Kind
        $provider.Backend | Should -Be 'Graph'
        $provider.Risk | Should -Be $Risk
        $provider.Reversible | Should -BeTrue
        @($provider.Scopes) | Should -Be $Scopes
    }
}

Describe 'User.Create' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    BeforeAll {
        $script:provider = Get-Provider 'User.Create'
        $script:desired = {
            @{
                userPrincipalName = 'erin@example.com'; displayName = 'Erin Example'; mailNickname = 'erin'
                givenName = 'Erin'; surname = 'Example'; usageLocation = 'US'; department = 'Sales'; jobTitle = 'Rep'; officeLocation = 'Remote'
            }
        }
        $script:target = @{ Kind = 'user'; Id = 'erin@example.com'; Name = 'Erin Example' }
    }

    Context 'Get' {
        It 'throws Tenure.Provider.TargetNotFound for a user that does not exist yet' {
            { & $provider.Get $target (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'returns a plain object with the profile fields and no secret-like members' {
            $current = & $provider.Get @{ Kind = 'user'; Id = 'alice@example.com'; Name = 'Alice' } (New-Context)
            $current | Should -BeOfType [pscustomobject]
            $current.id | Should -Be $ids.AliceId
            $current.userPrincipalName | Should -Be 'alice@example.com'
            $current.displayName | Should -Be 'Alice Example'
            $current.department | Should -Be 'Sales'
            $current.accountEnabled | Should -BeTrue
            @($current.PSObject.Properties.Name | Sort-Object) | Should -Be @('accountEnabled', 'createdDateTime', 'department', 'displayName', 'givenName', 'id', 'jobTitle', 'mailNickname', 'officeLocation', 'surname', 'usageLocation', 'userPrincipalName')
            ($current | ConvertTo-Json -Depth 5) | Should -Not -Match 'password'
        }

        It 'reads a UPN with characters that need escaping without altering the route' {
            { & $provider.Get @{ Kind = 'user'; Id = 'a/b?c@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            $w.Calls[-1].Uri | Should -Match 'users/a%2Fb%3Fc%40example\.com\?'
        }

        It 'reports a target without an id as TargetNotFound and makes no request' {
            { & $provider.Get @{ Kind = 'user'; Id = $null; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            $w.Calls.Count | Should -Be 0
        }

        It 'fingerprint stability: two Gets of an inline target canonicalize identically' {
            $target = @{ Kind = 'user'; Id = 'alice@example.com'; Name = 'Alice' }
            (Get-Canonical (& $provider.Get $target (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get $target (New-Context)))
        }
    }

    Context 'Test' {
        It 'is false when the user does not exist' {
            (& $provider.Test $null (& $desired)) | Should -BeFalse
        }

        It 'is true when the UPN matches, ignoring case' {
            $current = [pscustomobject]@{ userPrincipalName = 'ERIN@Example.com' }
            (& $provider.Test $current (& $desired)) | Should -BeTrue
        }

        It 'is false when the UPN differs, and when Desired has no UPN' {
            (& $provider.Test ([pscustomobject]@{ userPrincipalName = 'other@example.com' }) (& $desired)) | Should -BeFalse
            (& $provider.Test ([pscustomobject]@{ userPrincipalName = 'erin@example.com' }) @{}) | Should -BeFalse
        }

        It 'accepts a PSCustomObject Desired (as after a plan import)' {
            (& $provider.Test ([pscustomobject]@{ userPrincipalName = 'erin@example.com' }) ([pscustomobject](& $desired))) | Should -BeTrue
        }
    }

    Context 'Set' {
        It 'creates the user, returns the fresh state with its id, and leaves Test true' {
            $context = New-Context
            $observed = & $provider.Set $target (& $desired) $null $context
            { [guid]$observed.id } | Should -Not -Throw
            $observed.userPrincipalName | Should -Be 'erin@example.com'
            $observed.givenName | Should -Be 'Erin'
            $observed.usageLocation | Should -Be 'US'
            $observed.accountEnabled | Should -BeTrue
            (& $provider.Test $observed (& $desired)) | Should -BeTrue
            @($w.Users | Where-Object userPrincipalName -eq 'erin@example.com').Count | Should -Be 1
        }

        It 'sends accountEnabled, forceChangePasswordNextSignIn and the desired fields, and omits null ones' {
            $desired = & $desired
            $desired.givenName = $null
            $desired.Remove('officeLocation')
            & $provider.Set $target $desired $null (New-Context) | Out-Null
            $body = (Get-Posts '*/users').Where({ $_.Uri -like '*/users' })[-1].Body | ConvertFrom-Json
            $body.accountEnabled | Should -BeTrue
            $body.passwordProfile.forceChangePasswordNextSignIn | Should -BeTrue
            $body.userPrincipalName | Should -Be 'erin@example.com'
            $body.PSObject.Properties.Name | Should -Not -Contain 'givenName'
            $body.PSObject.Properties.Name | Should -Not -Contain 'officeLocation'
            $body.department | Should -Be 'Sales'
        }

        It 'puts the generated password in Context.Secrets[StepId] as a SecureString that is exactly what Graph received' {
            $context = New-Context
            & $provider.Set $target (& $desired) $null $context | Out-Null
            $context.Secrets.Keys | Should -Be @('S02')
            $context.Secrets['S02'] | Should -BeOfType [System.Security.SecureString]
            (Get-PlainText $context.Secrets['S02']).Length | Should -Be 20
            Test-DigestRecorded $context.Secrets['S02'] 'password' | Should -BeTrue
        }

        It 'falls back to the UPN as the secret key when there is no StepId' {
            $context = New-Context
            $context.Remove('StepId')
            & $provider.Set $target (& $desired) $null $context | Out-Null
            $context.Secrets.Keys | Should -Be @('erin@example.com')
        }

        It 'uses policy defaults.passwordLength, clamped to 12..128, and 20 when the policy is silent' -ForEach @(
            @{ Configured = 32; Expected = 32 }, @{ Configured = 8; Expected = 12 }, @{ Configured = 500; Expected = 128 }
        ) {
            $policy = [pscustomobject]@{ defaults = [pscustomobject]@{ passwordLength = $Configured } }
            $context = New-Context @{ Policy = $policy }
            & $provider.Set $target (& $desired) $null $context | Out-Null
            (Get-PlainText $context.Secrets['S02']).Length | Should -Be $Expected
        }

        It 'reads passwordLength from a hashtable policy too' {
            $context = New-Context @{ Policy = @{ Defaults = @{ passwordLength = 24 } } }
            & $provider.Set $target (& $desired) $null $context | Out-Null
            (Get-PlainText $context.Secrets['S02']).Length | Should -Be 24
        }

        It 'never stores the password in the world or logs it in the call bodies' {
            $context = New-Context
            & $provider.Set $target (& $desired) $null $context | Out-Null
            $plain = Get-PlainText $context.Secrets['S02']
            ($w.Users | ConvertTo-Json -Depth 10) | Should -Not -Match ([regex]::Escape($plain))
            ($w.Calls | ConvertTo-Json -Depth 10) | Should -Not -Match ([regex]::Escape($plain))
        }

        It 'does not leak the password into the verbose stream, the return value or an error message' {
            $context = New-Context
            $global:VerbosePreference = 'Continue'
            try { $output = & { & $provider.Set $target (& $desired) $null $context } 4>&1 } finally { $global:VerbosePreference = 'SilentlyContinue' }
            $plain = Get-PlainText $context.Secrets['S02']
            @($output | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] }).Count | Should -BeGreaterThan 0
            ($output | Out-String) | Should -Not -Match ([regex]::Escape($plain))
            ($output | ForEach-Object { $_.ToString() }) -join "`n" | Should -Not -Match ([regex]::Escape($plain))

            $failure = { & $provider.Set $target (& $desired) $null (New-Context) } | Should -Throw -PassThru
            $failure.Exception.Message | Should -Not -Match 'password'
        }

        It 'a second Set for an existing user fails cleanly and leaves no secret behind' {
            & $provider.Set $target (& $desired) $null (New-Context) | Out-Null
            $context = New-Context
            { & $provider.Set $target (& $desired) $null $context } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
            $context.Secrets.Count | Should -Be 0
            @($w.Users | Where-Object userPrincipalName -eq 'erin@example.com').Count | Should -Be 1
        }

        It 'refuses without Context.Secrets and sends nothing' {
            { & $provider.Set $target (& $desired) $null @{ StepId = 'S02' } } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            { & $provider.Set $target (& $desired) $null $null } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            $w.Calls.Count | Should -Be 0
        }

        It 'refuses a Desired without UPN, display name or mail nickname and sends nothing' -ForEach @(
            @{ Missing = 'userPrincipalName' }, @{ Missing = 'displayName' }, @{ Missing = 'mailNickname' }
        ) {
            $desired = & $desired
            $desired.Remove($Missing)
            $context = New-Context
            { & $provider.Set $target $desired $null $context } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            $w.Calls.Count | Should -Be 0
            $context.Secrets.Count | Should -Be 0
        }

        It 'accepts a PSCustomObject Desired' {
            $observed = & $provider.Set $target ([pscustomobject](& $desired)) $null (New-Context)
            $observed.userPrincipalName | Should -Be 'erin@example.com'
        }

        It 'a 429 with Retry-After then success is transparent, and creates the user once' {
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('2') }
            $context = New-Context
            $observed = & $provider.Set $target (& $desired) $null $context
            $observed.userPrincipalName | Should -Be 'erin@example.com'
            @($global:FakeGraphSleeps) | Should -Be @(2)
            @($w.Users | Where-Object userPrincipalName -eq 'erin@example.com').Count | Should -Be 1
            $context.Secrets.Count | Should -Be 1
        }

        It 'a 403 surfaces as Tenure.Graph.Forbidden and no secret is handed back' {
            Add-FakeGraphFault -World $w -Status 403 -Code 'Authorization_RequestDenied' -Message 'Insufficient privileges'
            $context = New-Context
            { & $provider.Set $target (& $desired) $null $context } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
            $context.Secrets.Count | Should -Be 0
            @($w.Users | Where-Object userPrincipalName -eq 'erin@example.com').Count | Should -Be 0
        }

        It 'a duplicate mail nickname is a Graph failure, not a half-created user' {
            $desired = & $desired
            $desired.mailNickname = 'alice'
            $context = New-Context
            { & $provider.Set $target $desired $null $context } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
            @($w.Users | Where-Object userPrincipalName -eq 'erin@example.com').Count | Should -Be 0
            # A failed create keeps its password unless the UPN already belonged to someone before the POST.
            $context.Secrets.Count | Should -Be 1
        }
    }

    Context 'Describe' {
        It 'is one line naming the UPN and display name' {
            $line = & $provider.Describe $target $null (& $desired) 'Create'
            $line | Should -Be 'Create user erin@example.com (Erin Example)'
            $line | Should -Not -Match "`n"
        }

        It 'never includes a password-like field, even if Desired carries one' {
            $desired = & $desired
            $desired.passwordProfile = @{ password = 'Zk7#mQ4!vRt9wXp2'; forceChangePasswordNextSignIn = $true }
            $desired.password = 'Zk7#mQ4!vRt9wXp2'
            $line = & $provider.Describe $target $null $desired 'Create'
            $line | Should -Not -Match 'Zk7'
            $line | Should -Not -Match 'password'
        }
    }
}

Describe 'User.Attributes' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    BeforeAll {
        $script:provider = Get-Provider 'User.Attributes'
        $script:target = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'Alice Example' } }
    }

    Context 'Get' {
        It 'returns id plus every allowed attribute, null for the unset ones' {
            $current = & $provider.Get (& $target) (New-Context)
            @($current.PSObject.Properties.Name | Sort-Object) | Should -Be @('companyName', 'department', 'displayName', 'employeeId', 'employeeType', 'givenName', 'id', 'jobTitle', 'officeLocation', 'surname', 'usageLocation')
            $current.department | Should -Be 'Sales'
            $current.jobTitle | Should -Be 'Account Executive'
            $current.companyName | Should -BeNullOrEmpty
        }

        It 'throws Tenure.Provider.TargetNotFound for a missing user or a missing id' {
            { & $provider.Get @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            { & $provider.Get @{ Kind = 'user'; Id = $null; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'fingerprint stability: two Gets of the shared fixture target canonicalize identically' {
            (Get-Canonical (& $provider.Get (& $target) (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get (& $target) (New-Context)))
        }
    }

    Context 'Test' {
        It 'is true when every Desired key matches, and ignores keys not in Desired' {
            $current = & $provider.Get (& $target) (New-Context)
            (& $provider.Test $current @{ department = 'Sales' }) | Should -BeTrue
            (& $provider.Test $current @{ department = 'Sales'; jobTitle = 'Account Executive' }) | Should -BeTrue
        }

        It 'is false when any key differs, and the comparison is case-sensitive' {
            $current = & $provider.Get (& $target) (New-Context)
            (& $provider.Test $current @{ department = 'Sales'; jobTitle = 'Director' }) | Should -BeFalse
            (& $provider.Test $current @{ department = 'sales' }) | Should -BeFalse
        }

        It 'is null-safe: null equals null, null differs from a value' {
            $current = & $provider.Get (& $target) (New-Context)
            (& $provider.Test $current @{ companyName = $null }) | Should -BeTrue
            (& $provider.Test $current @{ companyName = 'Contoso' }) | Should -BeFalse
            (& $provider.Test $current @{ department = $null }) | Should -BeFalse
        }

        It 'is false for a missing current object and throws InvalidDesired for an unknown key' {
            (& $provider.Test $null @{ department = 'Sales' }) | Should -BeFalse
            { & $provider.Test $null @{ managerId = 'x' } } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        }
    }

    Context 'Set' {
        It 'patches only the Desired keys, returns a fresh Get and leaves Test true' {
            $desired = @{ department = 'Operations'; jobTitle = 'Coordinator' }
            $observed = & $provider.Set (& $target) $desired $null (New-Context)
            $observed.department | Should -Be 'Operations'
            $observed.jobTitle | Should -Be 'Coordinator'
            $observed.officeLocation | Should -Be 'Remote'
            (& $provider.Test $observed $desired) | Should -BeTrue
            $patch = Get-FakeGraphCall -World $w -Method PATCH
            @(($patch.Body | ConvertFrom-Json).PSObject.Properties.Name | Sort-Object) | Should -Be @('department', 'jobTitle')
        }

        It 'is idempotent: a second Set changes nothing and Test stays true' {
            $desired = @{ department = 'Operations' }
            $first = & $provider.Set (& $target) $desired $null (New-Context)
            $second = & $provider.Set (& $target) $desired $first (New-Context)
            (Get-Canonical $second) | Should -BeExactly (Get-Canonical $first)
            (& $provider.Test $second $desired) | Should -BeTrue
        }

        It 'can set the attributes that Graph returns as null on a fresh user (companyName, employeeId, employeeType)' {
            $desired = @{ companyName = 'Example Co'; employeeId = 'E-1001'; employeeType = 'Employee' }
            $observed = & $provider.Set (& $target) $desired $null (New-Context)
            $observed.companyName | Should -Be 'Example Co'
            $observed.employeeId | Should -Be 'E-1001'
            (& $provider.Test $observed $desired) | Should -BeTrue
        }

        It 'clears an attribute when Desired is null' {
            $observed = & $provider.Set (& $target) @{ officeLocation = $null } $null (New-Context)
            $observed.officeLocation | Should -BeNullOrEmpty
            (& $provider.Test $observed @{ officeLocation = $null }) | Should -BeTrue
        }

        It 'accepts keys in any case and a PSCustomObject Desired' {
            $observed = & $provider.Set (& $target) ([pscustomobject]@{ Department = 'Legal' }) $null (New-Context)
            $observed.department | Should -Be 'Legal'
        }

        It 'throws Tenure.Provider.InvalidDesired for an unknown key and sends nothing' {
            { & $provider.Set (& $target) @{ department = 'Sales'; managerId = 'x' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            { & $provider.Set (& $target) @{ accountEnabled = $false } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            @(Get-FakeGraphCall -World $w -Method PATCH).Count | Should -Be 0
        }

        It 'a 429 with Retry-After then success is transparent' {
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('1') }
            (& $provider.Set (& $target) @{ department = 'Ops' } $null (New-Context)).department | Should -Be 'Ops'
            @($global:FakeGraphSleeps) | Should -Be @(1)
        }

        It 'a 403 surfaces as Tenure.Graph.Forbidden' {
            Add-FakeGraphFault -World $w -Status 403
            { & $provider.Set (& $target) @{ department = 'Ops' } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }
    }

    Context 'Describe' {
        It 'lists the desired attributes on one line, sorted' {
            $line = & $provider.Describe (& $target) $null @{ jobTitle = 'Coordinator'; department = 'Operations' } 'Update'
            $line | Should -Be 'Update attributes of Alice Example: department=Operations, jobTitle=Coordinator'
        }
    }
}

Describe 'User.Manager' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    BeforeAll {
        $script:provider = Get-Provider 'User.Manager'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'Alice Example' } }
        $script:bobTarget = { @{ Kind = 'user'; Id = $script:ids.BobId; Name = 'Bob Manager' } }
    }

    Context 'Get and Test' {
        It 'returns the manager id' {
            (& $provider.Get (& $aliceTarget) (New-Context)).managerId | Should -Be $ids.BobId
        }

        It 'returns managerId $null when the user has no manager (Graph 404)' {
            $current = & $provider.Get (& $bobTarget) (New-Context)
            $current | Should -BeOfType [pscustomobject]
            $current.managerId | Should -BeNullOrEmpty
            $current.PSObject.Properties.Name | Should -Contain 'managerId'
        }

        It 'reports a target without an id as TargetNotFound' {
            { & $provider.Get @{ Kind = 'user'; Id = $null; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'Test is true for the same manager (any case) and for none-on-none, false otherwise' {
            $current = & $provider.Get (& $aliceTarget) (New-Context)
            (& $provider.Test $current @{ managerId = $ids.BobId }) | Should -BeTrue
            (& $provider.Test $current @{ managerId = $ids.BobId.ToUpperInvariant() }) | Should -BeTrue
            (& $provider.Test $current @{ managerId = $ids.CarolId }) | Should -BeFalse
            (& $provider.Test $current @{ managerId = $null }) | Should -BeFalse
            $none = & $provider.Get (& $bobTarget) (New-Context)
            (& $provider.Test $none @{ managerId = $null }) | Should -BeTrue
            (& $provider.Test $none @{ managerId = $ids.AliceId }) | Should -BeFalse
            (& $provider.Test $null @{ managerId = $null }) | Should -BeFalse
        }

        It 'fingerprint stability' {
            (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context)))
        }
    }

    Context 'Set' {
        It 'sets a manager with PUT manager/$ref, returns a fresh Get and leaves Test true' {
            $desired = @{ managerId = $ids.CarolId }
            $observed = & $provider.Set (& $aliceTarget) $desired $null (New-Context)
            $observed.managerId | Should -Be $ids.CarolId
            (& $provider.Test $observed $desired) | Should -BeTrue
            $put = @(Get-FakeGraphCall -World $w -Method PUT)
            $put.Count | Should -Be 1
            $put[0].Uri | Should -Match "users/$($ids.AliceId)/manager/\`$ref$"
            ($put[0].Body | ConvertFrom-Json).'@odata.id' | Should -Be "https://graph.microsoft.com/v1.0/users/$($ids.CarolId)"
        }

        It 'sets a manager for a user who had none' {
            $observed = & $provider.Set (& $bobTarget) @{ managerId = $ids.CarolId } $null (New-Context)
            $observed.managerId | Should -Be $ids.CarolId
        }

        It 'is idempotent: setting the same manager twice is harmless' {
            $desired = @{ managerId = $ids.CarolId }
            & $provider.Set (& $aliceTarget) $desired $null (New-Context) | Out-Null
            $again = & $provider.Set (& $aliceTarget) $desired $null (New-Context)
            $again.managerId | Should -Be $ids.CarolId
        }

        It 'clears the manager with DELETE manager/$ref when Desired.managerId is $null' {
            $desired = @{ managerId = $null }
            $observed = & $provider.Set (& $aliceTarget) $desired $null (New-Context)
            $observed.managerId | Should -BeNullOrEmpty
            (& $provider.Test $observed $desired) | Should -BeTrue
            @(Get-FakeGraphCall -World $w -Method DELETE).Count | Should -Be 1
        }

        It 'clearing twice is harmless, and a 404 on the DELETE counts as success' {
            & $provider.Set (& $aliceTarget) @{ managerId = $null } $null (New-Context) | Out-Null
            (& $provider.Set (& $aliceTarget) @{ managerId = $null } $null (New-Context)).managerId | Should -BeNullOrEmpty
            Add-FakeGraphFault -World $w -Status 404 -Code 'Request_ResourceNotFound'
            (& $provider.Set (& $aliceTarget) @{ managerId = $null } $null (New-Context)).managerId | Should -BeNullOrEmpty
        }

        It 'a circular reference surfaces as Tenure.Graph.Failed and changes nothing' {
            { & $provider.Set (& $bobTarget) @{ managerId = $ids.AliceId } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
            (& $provider.Get (& $bobTarget) (New-Context)).managerId | Should -BeNullOrEmpty
        }

        It 'a 429 with Retry-After then success is transparent; a 403 is Tenure.Graph.Forbidden' {
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('1') }
            (& $provider.Set (& $aliceTarget) @{ managerId = $ids.CarolId } $null (New-Context)).managerId | Should -Be $ids.CarolId
            @($global:FakeGraphSleeps) | Should -Be @(1)
            Add-FakeGraphFault -World $w -Status 403
            { & $provider.Set (& $aliceTarget) @{ managerId = $ids.BobId } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }
    }

    Context 'Describe' {
        It 'says what the manager becomes' {
            (& $provider.Describe (& $aliceTarget) $null @{ managerId = $ids.CarolId } 'Update') | Should -Be "Update manager of Alice Example to $($ids.CarolId)"
            (& $provider.Describe (& $aliceTarget) $null @{ managerId = $null } 'Remove') | Should -Be 'Remove manager of Alice Example to none'
        }
    }
}

Describe 'User.Licenses' {
    # Desired is a delta, @{ add = <sku ids>; remove = <sku ids> }, so a plan can never remove more than it showed.
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    BeforeAll {
        $script:provider = Get-Provider 'User.Licenses'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'Alice Example' } }
        $script:bobTarget = { @{ Kind = 'user'; Id = $script:ids.BobId; Name = 'Bob Manager' } }
        $script:carolTarget = { @{ Kind = 'user'; Id = $script:ids.CarolId; Name = 'Carol Admin' } }
        $script:postBody = { (@(Get-FakeGraphCall -World $script:w -Method POST -UriLike '*assignLicense')[-1].Body) | ConvertFrom-Json }
        $script:assignCount = { @(Get-FakeGraphCall -World $script:w -Method POST -UriLike '*assignLicense').Count }
    }

    Context 'Get' {
        It 'snapshots only the SKUs assigned directly; the full license state reports inherited ones and the usage location' {
            $alice = & $provider.Get (& $aliceTarget) (New-Context)
            $alice | Should -BeOfType [pscustomobject]
            @($alice.PSObject.Properties.Name) | Should -Be @('skuIds') -Because 'a group removal earlier in the same plan moves the inherited licenses, which must not read as drift'
            @($alice.skuIds) | Should -Be @($ids.SkuE3Id)
            $aliceState = Get-LicenseState $ids.AliceId
            @($aliceState.inheritedSkuIds).Count | Should -Be 0
            $aliceState.usageLocation | Should -Be 'US'
            @((& $provider.Get (& $bobTarget) (New-Context)).skuIds).Count | Should -Be 0
            @((Get-LicenseState $ids.BobId).inheritedSkuIds) | Should -Be @($ids.SkuE3Id)
            @((& $provider.Get (& $carolTarget) (New-Context)).skuIds).Count | Should -Be 0
            @((Get-LicenseState $ids.CarolId).inheritedSkuIds).Count | Should -Be 0
        }

        It 'a SKU that is both direct and group-assigned appears in both lists of the license state' {
            & $provider.Set (& $bobTarget) @{ add = @($ids.SkuE3Id); remove = @() } $null (New-Context) | Out-Null
            @((& $provider.Get (& $bobTarget) (New-Context)).skuIds) | Should -Be @($ids.SkuE3Id)
            @((Get-LicenseState $ids.BobId).inheritedSkuIds) | Should -Be @($ids.SkuE3Id)
        }

        It 'a group removal that takes an inherited license does not change the snapshot' {
            $before = & $provider.Get (& $bobTarget) (New-Context)
            Invoke-FakeGraphRequest -World $w -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$($ids.AllStaffGroupId)/members/$($ids.BobId)/`$ref" | Out-Null
            @((Get-LicenseState $ids.BobId).inheritedSkuIds).Count | Should -Be 0 -Because 'leaving the group took the license (FakeGraph models it)'
            (Get-Canonical (& $provider.Get (& $bobTarget) (New-Context))) | Should -BeExactly (Get-Canonical $before)
        }

        It 'returns lower-case ids sorted ordinally, so the order is stable' {
            & $provider.Set (& $aliceTarget) @{ add = @($ids.SkuVoiceId, $ids.SkuDeskId); remove = @() } $null (New-Context) | Out-Null
            $alice = & $provider.Get (& $aliceTarget) (New-Context)
            @($alice.skuIds) | Should -Be @($ids.SkuE3Id, $ids.SkuDeskId, $ids.SkuVoiceId)
        }

        It 'throws TargetNotFound for a missing user or id' {
            { & $provider.Get @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            { & $provider.Get @{ Kind = 'user'; Id = ''; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'fingerprint stability' {
            foreach ($t in (& $aliceTarget), (& $bobTarget)) {
                (Get-Canonical (& $provider.Get $t (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get $t (New-Context)))
            }
        }
    }

    Context 'Test' {
        It 'is true when every add is a direct assignment and no remove is, ignoring case' {
            $current = [pscustomobject]@{ skuIds = @($ids.SkuE3Id, $ids.SkuVoiceId); inheritedSkuIds = @(); inheritedFrom = @(); usageLocation = 'US' }
            (& $provider.Test $current @{ add = @($ids.SkuVoiceId.ToUpperInvariant(), $ids.SkuE3Id); remove = @($ids.SkuDeskId) }) | Should -BeTrue
            (& $provider.Test $current @{ add = @($ids.SkuDeskId); remove = @() }) | Should -BeFalse
            (& $provider.Test $current @{ add = @(); remove = @($ids.SkuE3Id) }) | Should -BeFalse
            (& $provider.Test $current @{ add = @(); remove = @() }) | Should -BeTrue -Because 'an empty delta asks for nothing'
        }

        It 'ignores direct SKUs the delta does not mention' {
            $current = [pscustomobject]@{ skuIds = @($ids.SkuE3Id, $ids.SkuVoiceId); inheritedSkuIds = @(); inheritedFrom = @(); usageLocation = 'US' }
            (& $provider.Test $current @{ add = @($ids.SkuE3Id); remove = @() }) | Should -BeTrue
        }

        It 'a remove that is only group-inherited is satisfied; inherited does not satisfy an add' {
            $bob = [pscustomobject]@{ skuIds = @(); inheritedSkuIds = @($ids.SkuE3Id); inheritedFrom = @(); usageLocation = 'US' }
            (& $provider.Test $bob @{ add = @(); remove = @($ids.SkuE3Id) }) | Should -BeTrue
            (& $provider.Test $bob @{ add = @($ids.SkuE3Id); remove = @() }) | Should -BeFalse -Because 'inherited does not satisfy a direct request'
            (& $provider.Test $null @{ add = @(); remove = @() }) | Should -BeFalse
        }

        It 'accepts an imported (PSCustomObject, object[]) Desired' {
            $current = [pscustomobject]@{ skuIds = @($ids.SkuE3Id); inheritedSkuIds = @(); inheritedFrom = @(); usageLocation = 'US' }
            $imported = ('{"add":["' + $ids.SkuE3Id + '"],"remove":[]}') | ConvertFrom-Json
            (& $provider.Test $current $imported) | Should -BeTrue
        }
    }

    Context 'Set: add path' {
        It 'adds a SKU, returns a fresh Get and leaves Test true' {
            $desired = @{ add = @($ids.SkuVoiceId); remove = @() }
            $observed = & $provider.Set (& $carolTarget) $desired $null (New-Context)
            @($observed.skuIds) | Should -Be @($ids.SkuVoiceId)
            (& $provider.Test $observed $desired) | Should -BeTrue
        }

        It 'always sends both addLicenses and removeLicenses, even when one side is empty' {
            & $provider.Set (& $carolTarget) @{ add = @($ids.SkuVoiceId); remove = @() } $null (New-Context) | Out-Null
            $body = & $postBody
            @($body.addLicenses).Count | Should -Be 1
            $body.addLicenses[0].skuId | Should -Be $ids.SkuVoiceId
            @($body.addLicenses[0].disabledPlans).Count | Should -Be 0
            $body.PSObject.Properties.Name | Should -Contain 'removeLicenses'
            @($body.removeLicenses).Count | Should -Be 0
        }

        It 'is idempotent: a second Set sends nothing and changes nothing' {
            $desired = @{ add = @($ids.SkuVoiceId); remove = @() }
            $first = & $provider.Set (& $carolTarget) $desired $null (New-Context)
            $callsBefore = $w.Calls.Count
            $second = & $provider.Set (& $carolTarget) $desired $first (New-Context)
            & $assignCount | Should -Be 1
            $w.Calls.Count | Should -BeGreaterThan $callsBefore
            (Get-Canonical $second) | Should -BeExactly (Get-Canonical $first)
        }

        It 'does not re-add a SKU the user already has directly' {
            & $provider.Set (& $aliceTarget) @{ add = @($ids.SkuE3Id); remove = @() } $null (New-Context) | Out-Null
            & $assignCount | Should -Be 0
        }

        It 'adds and removes in one request with exactly the delta' {
            $desired = @{ add = @($ids.SkuVoiceId); remove = @($ids.SkuE3Id) }
            $observed = & $provider.Set (& $aliceTarget) $desired $null (New-Context)
            @($observed.skuIds) | Should -Be @($ids.SkuVoiceId)
            $body = & $postBody
            @($body.addLicenses.skuId) | Should -Be @($ids.SkuVoiceId)
            @($body.removeLicenses) | Should -Be @($ids.SkuE3Id)
            & $assignCount | Should -Be 1
        }

        It 'works from the fresh state, not the Current it was handed' {
            $stale = [pscustomobject]@{ skuIds = @(); inheritedSkuIds = @(); inheritedFrom = @(); usageLocation = 'US' }
            $observed = & $provider.Set (& $aliceTarget) @{ add = @($ids.SkuE3Id); remove = @() } $stale (New-Context)
            @($observed.skuIds) | Should -Be @($ids.SkuE3Id)
            & $assignCount | Should -Be 0
        }

        It 'sends SKU ids in lower case' {
            & $provider.Set (& $carolTarget) @{ add = @($ids.SkuVoiceId.ToUpperInvariant()); remove = @() } $null (New-Context) | Out-Null
            (& $postBody).addLicenses[0].skuId | Should -BeExactly $ids.SkuVoiceId
        }

        It 'refuses to add when the user has no usage location (Tenure.Provider.Precondition) and sends nothing' {
            ($w.Users | Where-Object id -eq $ids.CarolId).usageLocation = $null
            { & $provider.Set (& $carolTarget) @{ add = @($ids.SkuVoiceId); remove = @() } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            & $assignCount | Should -Be 0
        }

        It 'a user created without a usage location hits the same precondition' {
            $context = New-Context
            $create = Get-Provider 'User.Create'
            $created = & $create.Set @{ Kind = 'user'; Id = 'frank@example.com'; Name = 'Frank' } @{ userPrincipalName = 'frank@example.com'; displayName = 'Frank'; mailNickname = 'frank' } $null $context
            { & $provider.Set @{ Kind = 'user'; Id = $created.id; Name = 'Frank' } @{ add = @($ids.SkuE3Id); remove = @() } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
        }

        It 'removing without adding does not need a usage location' {
            ($w.Users | Where-Object id -eq $ids.AliceId).usageLocation = $null
            $observed = & $provider.Set (& $aliceTarget) @{ add = @(); remove = @($ids.SkuE3Id) } $null (New-Context)
            @($observed.skuIds).Count | Should -Be 0
        }

        It 'a SKU Graph does not know surfaces as Tenure.Graph.Failed' {
            { & $provider.Set (& $carolTarget) @{ add = @('00000000-0000-0000-0000-000000000000'); remove = @() } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
        }
    }

    Context 'Set: remove path and inherited licenses' {
        It 'removes a listed direct SKU' {
            $desired = @{ add = @(); remove = @($ids.SkuE3Id) }
            $observed = & $provider.Set (& $aliceTarget) $desired $null (New-Context)
            @($observed.skuIds).Count | Should -Be 0
            (& $provider.Test $observed $desired) | Should -BeTrue
            @((& $postBody).removeLicenses) | Should -Be @($ids.SkuE3Id)
        }

        It 'never touches a group-inherited SKU: a remove of it sends nothing for bob' {
            $observed = & $provider.Set (& $bobTarget) @{ add = @(); remove = @($ids.SkuE3Id) } $null (New-Context)
            & $assignCount | Should -Be 0
            @($observed.skuIds).Count | Should -Be 0
            @((Get-LicenseState $ids.BobId).inheritedSkuIds) | Should -Be @($ids.SkuE3Id)
            @(($w.Users | Where-Object id -eq $ids.BobId).licenseAssignmentStates | Where-Object assignedByGroup).Count | Should -Be 1
        }

        It 'adding a SKU on top of an inherited one and removing it again leaves the inherited one in place' {
            $added = & $provider.Set (& $bobTarget) @{ add = @($ids.SkuE3Id); remove = @() } $null (New-Context)
            @($added.skuIds) | Should -Be @($ids.SkuE3Id)
            @((Get-LicenseState $ids.BobId).inheritedSkuIds) | Should -Be @($ids.SkuE3Id)
            $removed = & $provider.Set (& $bobTarget) @{ add = @(); remove = @($ids.SkuE3Id) } $null (New-Context)
            @($removed.skuIds).Count | Should -Be 0
            @((Get-LicenseState $ids.BobId).inheritedSkuIds) | Should -Be @($ids.SkuE3Id)
            @(($w.Users | Where-Object id -eq $ids.BobId).assignedLicenses).Count | Should -Be 1
        }

        It 'removing twice is harmless' {
            & $provider.Set (& $aliceTarget) @{ add = @(); remove = @($ids.SkuE3Id) } $null (New-Context) | Out-Null
            (& $provider.Set (& $aliceTarget) @{ add = @(); remove = @($ids.SkuE3Id) } $null (New-Context)).skuIds.Count | Should -Be 0
            & $assignCount | Should -Be 1
        }
    }

    Context 'faults' {
        It 'a 429 with Retry-After then success is transparent' {
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('4') }
            $observed = & $provider.Set (& $aliceTarget) @{ add = @(); remove = @($ids.SkuE3Id) } $null (New-Context)
            @($observed.skuIds).Count | Should -Be 0
            @($global:FakeGraphSleeps) | Should -Be @(4)
        }

        It 'a 403 on the write surfaces as Tenure.Graph.Forbidden and changes nothing' {
            Add-FakeGraphFault -World $w -Status 403 -Method POST -UriLike '*assignLicense'
            { & $provider.Set (& $carolTarget) @{ add = @($ids.SkuVoiceId); remove = @() } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
            @(($w.Users | Where-Object id -eq $ids.CarolId).assignedLicenses).Count | Should -Be 0
        }
    }

    Context 'Describe' {
        It 'names the SKU ids being added and removed' {
            $current = [pscustomobject]@{ skuIds = @($ids.SkuE3Id); inheritedSkuIds = @(); inheritedFrom = @(); usageLocation = 'US' }
            $line = & $provider.Describe (& $aliceTarget) $current @{ add = @($ids.SkuVoiceId); remove = @($ids.SkuE3Id) } 'Update'
            $line | Should -Be "Update licenses of Alice Example: +$($ids.SkuVoiceId) -$($ids.SkuE3Id)"
        }

        It 'says so when nothing changes, and lists the requested delta when there is no Current' {
            $current = [pscustomobject]@{ skuIds = @($ids.SkuE3Id); inheritedSkuIds = @(); inheritedFrom = @(); usageLocation = 'US' }
            (& $provider.Describe (& $aliceTarget) $current @{ add = @($ids.SkuE3Id); remove = @() } 'Update') | Should -Be 'Update licenses of Alice Example: no change'
            (& $provider.Describe (& $aliceTarget) $null @{ add = @($ids.SkuE3Id); remove = @($ids.SkuVoiceId) } 'Create') | Should -Be "Create licenses of Alice Example: +$($ids.SkuE3Id) -$($ids.SkuVoiceId)"
        }
    }
}

Describe 'User.TemporaryAccessPass' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    BeforeAll {
        $script:provider = Get-Provider 'User.TemporaryAccessPass'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'Alice Example' } }
    }

    It 'Get reports no methods for a user with none' {
        $current = & $provider.Get (& $aliceTarget) (New-Context)
        $current.existingCount | Should -Be 0
        $current.hasUsable | Should -BeFalse
    }

    It 'Get counts existing methods and flags a usable one, and never carries a pass value' {
        Invoke-FakeGraphRequest -World $w -Method POST -Uri "users/$($ids.AliceId)/authentication/temporaryAccessPassMethods" -Body @{ lifetimeInMinutes = 60 } | Out-Null
        $current = & $provider.Get (& $aliceTarget) (New-Context)
        $current.existingCount | Should -Be 1
        $current.hasUsable | Should -BeTrue
        ($current | ConvertTo-Json -Depth 5) | Should -Not -Match 'TAP-'
        @($current.PSObject.Properties.Name | Sort-Object) | Should -Be @('existingCount', 'hasUsable')
    }

    It 'Get counts an expired method but does not call it usable' {
        Invoke-FakeGraphRequest -World $w -Method POST -Uri "users/$($ids.AliceId)/authentication/temporaryAccessPassMethods" -Body @{ lifetimeInMinutes = 10; startDateTime = '2020-01-01T00:00:00Z' } | Out-Null
        $current = & $provider.Get (& $aliceTarget) (New-Context)
        $current.existingCount | Should -Be 1
        $current.hasUsable | Should -BeFalse
    }

    It 'Get pages through every method' {
        $w.PageSize = 1
        1..3 | ForEach-Object { Invoke-FakeGraphRequest -World $w -Method POST -Uri "users/$($ids.AliceId)/authentication/temporaryAccessPassMethods" -Body @{ lifetimeInMinutes = 60 } | Out-Null }
        (& $provider.Get (& $aliceTarget) (New-Context)).existingCount | Should -Be 3
    }

    It 'Get throws TargetNotFound for a missing user or id' {
        { & $provider.Get @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        { & $provider.Get @{ Kind = 'user'; Id = $null; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }

    It 'Get fingerprint stability' {
        (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get (& $aliceTarget) (New-Context)))
    }

    It 'Test is always false (Invoke providers are never satisfied)' {
        (& $provider.Test ([pscustomobject]@{ existingCount = 1; hasUsable = $true }) @{ lifetimeInMinutes = 480; isUsableOnce = $true }) | Should -BeFalse
        (& $provider.Test $null @{}) | Should -BeFalse
    }

    It 'Get surfaces a 403 as Tenure.Graph.Forbidden' {
        Add-FakeGraphFault -World $w -Status 403
        { & $provider.Get (& $aliceTarget) (New-Context) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
    }

    It 'Describe applies the defaults (480 minutes, usable once) and carries no pass value' {
        (& $provider.Describe (& $aliceTarget) $null @{} 'Invoke') | Should -Be 'Invoke Temporary Access Pass for Alice Example (lifetime 480 minutes, usable once: True)'
        (& $provider.Describe (& $aliceTarget) $null @{ lifetimeInMinutes = 60; isUsableOnce = $false } 'Invoke') | Should -Be 'Invoke Temporary Access Pass for Alice Example (lifetime 60 minutes, usable once: False)'
    }

    # Set issues the pass; the full coverage of Set is in Providers.Identity.Tests.ps1.
    It 'Set issues a pass into Context.Secrets[StepId] and returns the method without it' {
        $context = New-Context
        $observed = & $provider.Set (& $aliceTarget) @{} $null $context
        $context.Secrets.Keys | Should -Be @('S02')
        $context.Secrets['S02'] | Should -BeOfType [System.Security.SecureString]
        Test-DigestRecorded $context.Secrets['S02'] 'tap' | Should -BeTrue
        $observed.PSObject.Properties.Name | Should -Not -Contain 'temporaryAccessPass'
        (& $provider.Get (& $aliceTarget) (New-Context)).hasUsable | Should -BeTrue
    }
}

# ---- Regression tests for the user providers ---------------------------------------------------
# Each test below was written to fail against the code before its fix; the fix followed.

Describe 'User.Licenses delta contract and inherited licenses' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    BeforeAll {
        $script:provider = Get-Provider 'User.Licenses'
        $script:aliceTarget = { @{ Kind = 'user'; Id = $script:ids.AliceId; Name = 'Alice Example' } }
        $script:bobTarget = { @{ Kind = 'user'; Id = $script:ids.BobId; Name = 'Bob Manager' } }
        $script:assignCount = { @(Get-FakeGraphCall -World $script:w -Method POST -UriLike '*assignLicense').Count }
    }

    It 'refuses <Label> and sends nothing' -ForEach @(
        @{ Label = 'the old absolute shape (skuIds)'; Desired = @{ skuIds = @() } }
        @{ Label = 'an empty Desired'; Desired = @{} }
        @{ Label = 'no Desired'; Desired = $null }
        @{ Label = 'a missing remove'; Desired = @{ add = @() } }
        @{ Label = 'a missing add'; Desired = @{ remove = @('30000000-0000-4000-8000-000000000001') } }
        @{ Label = 'an extra key'; Desired = @{ add = @(); remove = @(); keep = @() } }
        @{ Label = 'a $null list'; Desired = @{ add = @(); remove = $null } }
        @{ Label = 'a bare string instead of an array'; Desired = @{ add = @(); remove = '30000000-0000-4000-8000-000000000001' } }
        @{ Label = 'a part number instead of a SKU id'; Desired = @{ add = @(); remove = @('SPE_E3') } }
        @{ Label = 'the same id in add and remove'; Desired = @{ add = @('30000000-0000-4000-8000-000000000001'); remove = @('30000000-0000-4000-8000-000000000001') } }
    ) {
        { & $provider.Set (& $aliceTarget) $Desired $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        { & $provider.Test ([pscustomobject]@{ skuIds = @(); inheritedSkuIds = @(); inheritedFrom = @(); usageLocation = 'US' }) $Desired } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
        $w.Calls.Count | Should -Be 0 -Because 'Desired is checked before anything is read or written'
        @(($w.Users | Where-Object id -eq $ids.AliceId).assignedLicenses.skuId) | Should -Be @($ids.SkuE3Id)
    }

    It 'an empty delta is valid and sends nothing' {
        $observed = & $provider.Set (& $aliceTarget) @{ add = @(); remove = @() } $null (New-Context)
        @($observed.skuIds) | Should -Be @($ids.SkuE3Id)
        & $assignCount | Should -Be 0
    }

    It 'a license assigned after planning is never removed: Set touches only the ids the plan listed' {
        # Planned: remove E3. Meanwhile someone assigns MCOEV directly. Even with -Force the step may only remove E3.
        Invoke-FakeGraphRequest -World $w -Method POST -Uri "users/$($ids.AliceId)/assignLicense" -Body @{ addLicenses = @(@{ skuId = $ids.SkuVoiceId; disabledPlans = @() }); removeLicenses = @() } | Out-Null
        $observed = & $provider.Set (& $aliceTarget) @{ add = @(); remove = @($ids.SkuE3Id) } $null (New-Context)
        @($observed.skuIds) | Should -Be @($ids.SkuVoiceId)
        $body = @(Get-FakeGraphCall -World $w -Method POST -UriLike '*assignLicense')[-1].Body | ConvertFrom-Json
        @($body.removeLicenses) | Should -Be @($ids.SkuE3Id)
        @($body.addLicenses).Count | Should -Be 0
    }

    It 'the license state names the group each inherited SKU comes from, so a plan can say why it is kept' {
        $bob = Get-LicenseState $ids.BobId
        @($bob.inheritedFrom).Count | Should -Be 1
        $bob.inheritedFrom[0].skuId | Should -Be $ids.SkuE3Id
        $bob.inheritedFrom[0].groupId | Should -Be $ids.AllStaffGroupId
        @((Get-LicenseState $ids.AliceId).inheritedFrom).Count | Should -Be 0
    }

    It 'Describe names a remove of a license not assigned directly as left alone' {
        $bob = & $provider.Get (& $bobTarget) (New-Context)
        $line = & $provider.Describe (& $bobTarget) $bob @{ add = @(); remove = @($ids.SkuE3Id) } 'Update'
        $line | Should -Be "Update licenses of Bob Manager: no change; not assigned directly, left alone: $($ids.SkuE3Id)"
        $line | Should -Not -Match "`n"
    }

    It 'Describe does not mention inherited SKUs the delta does not ask to remove' {
        $bob = & $provider.Get (& $bobTarget) (New-Context)
        (& $provider.Describe (& $bobTarget) $bob @{ add = @($ids.SkuVoiceId); remove = @() } 'Update') | Should -Be "Update licenses of Bob Manager: +$($ids.SkuVoiceId)"
    }

    It 'inheritedFrom keeps a stable order, and the snapshot is stable' {
        (Get-Canonical (& $provider.Get (& $bobTarget) (New-Context))) | Should -BeExactly (Get-Canonical (& $provider.Get (& $bobTarget) (New-Context)))
        (Get-Canonical (Get-LicenseState $ids.BobId)) | Should -BeExactly (Get-Canonical (Get-LicenseState $ids.BobId))
    }
}

Describe 'User.Manager on a user that does not exist' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    BeforeAll { $script:provider = Get-Provider 'User.Manager' }

    It 'Get on a user that does not exist throws TargetNotFound (SPEC 2.2), not managerId = $null' {
        { & $provider.Get @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }

    It 'clearing the manager of a user that does not exist fails instead of reporting success' {
        { & $provider.Set @{ Kind = 'user'; Id = 'nobody@example.com'; Name = 'x' } @{ managerId = $null } $null (New-Context) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
    }

    It 'a user without a manager still reads as managerId = $null' {
        (& $provider.Get @{ Kind = 'user'; Id = $ids.BobId; Name = 'Bob' } (New-Context)).managerId | Should -BeNullOrEmpty
    }
}

Describe 'User.Create read-back while the new user is not readable yet' {
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    BeforeAll {
        $script:provider = Get-Provider 'User.Create'
        $script:target = @{ Kind = 'user'; Id = 'erin@example.com'; Name = 'Erin Example' }
        $script:desired = { @{ userPrincipalName = 'erin@example.com'; displayName = 'Erin Example'; mailNickname = 'erin'; usageLocation = 'US' } }
    }

    It 'a replication-lag 404 on the read-back after a successful create is retried, not reported as a failure' {
        # The first 404 answers the pre-create lookup (the user really is absent); the next two hit the read-back.
        Add-FakeGraphFault -World $w -Status 404 -Code 'Request_ResourceNotFound' -Method GET -Count 3
        $context = New-Context
        $observed = & $provider.Set $target (& $desired) $null $context
        $observed.userPrincipalName | Should -Be 'erin@example.com'
        $context.Secrets.Count | Should -Be 1
        @($global:FakeGraphSleeps) | Should -Be @(2, 4)
        @(Get-FakeGraphCall -World $w -Method POST -UriLike '*/users').Count | Should -Be 1 -Because 'the create itself is never repeated'
    }

    It 'when the new user never becomes readable, Set fails but keeps the password for the user that now exists' {
        Add-FakeGraphFault -World $w -Status 404 -Code 'Request_ResourceNotFound' -Method GET -Count 10
        $context = New-Context
        $failure = { & $provider.Set $target (& $desired) $null $context } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound' -PassThru
        $failure.Exception.Message | Should -Match 'created'
        $context.Secrets.Count | Should -Be 1
        Test-DigestRecorded $context.Secrets['S02'] 'password' | Should -BeTrue
        @($w.Users | Where-Object userPrincipalName -eq 'erin@example.com').Count | Should -Be 1
        @($global:FakeGraphSleeps) | Should -Be @(2, 4, 8)
    }
}

Describe 'User.Create when the create lands but the POST reports failure' {
    # The seam retries a POST after 429/5xx. If the first attempt created the user and only the answer was
    # lost, the retry fails (5xx again, or 400 "already exists"), and the password must not be thrown away.
    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
        $global:CreateAttempts = 0
    }

    AfterAll { Remove-Variable -Name CreateAttempts -Scope Global -ErrorAction SilentlyContinue }

    BeforeAll {
        $script:provider = Get-Provider 'User.Create'
        $script:target = @{ Kind = 'user'; Id = 'erin@example.com'; Name = 'Erin Example' }
        $script:desired = { @{ userPrincipalName = 'erin@example.com'; displayName = 'Erin Example'; mailNickname = 'erin'; usageLocation = 'US' } }
        $script:erinCount = { @($script:w.Users | Where-Object userPrincipalName -eq 'erin@example.com').Count }
        # True when the SecureString is a password Graph actually received (the fake records one digest per accepted attempt).
        $script:graphSawPassword = { param($secure) $hash = Get-FakeGraphSha256 -Text (Get-PlainText $secure); @($script:w.SecretDigests | Where-Object { $_.Kind -eq 'password' -and $_.Sha256 -eq $hash }).Count -ge 1 }
    }

    It 'the first attempt created the user but answered 503, the retry got "already exists": the password is kept and the user returned' {
        Mock -ModuleName Tenure Invoke-TenureGraphRaw {
            $response = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
            if ($Method -eq 'POST' -and $Uri -like '*/v1.0/users') {
                $global:CreateAttempts++
                if ($global:CreateAttempts -eq 1) { return @{ Status = 503; Headers = $response.Headers; Body = (ConvertTo-FakeGraphBody -Value @{ error = @{ code = 'ServiceUnavailable'; message = 'Try again later.' } }) } }
            }
            $response
        }
        $context = New-Context
        $global:VerbosePreference = 'Continue'
        try { $output = @(& { & $provider.Set $target (& $desired) $null $context } 4>&1) } finally { $global:VerbosePreference = 'SilentlyContinue' }
        $observed = @($output | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] })
        $observed.Count | Should -Be 1
        $observed[0].userPrincipalName | Should -Be 'erin@example.com'
        (& $provider.Test $observed[0] (& $desired)) | Should -BeTrue
        $global:CreateAttempts | Should -Be 2
        & $erinCount | Should -Be 1
        $context.Secrets.Keys | Should -Be @('S02')
        & $graphSawPassword $context.Secrets['S02'] | Should -BeTrue
        (@($output | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] }).Message -join "`n") | Should -Match 'now exists'
    }

    It 'the first attempt created the user and every attempt answered 503: the password is still kept' {
        Mock -ModuleName Tenure Invoke-TenureGraphRaw {
            if ($Method -eq 'POST' -and $Uri -like '*/v1.0/users') {
                $global:CreateAttempts++
                $failed = @{ Status = 503; Headers = @{}; Body = (ConvertTo-FakeGraphBody -Value @{ error = @{ code = 'ServiceUnavailable'; message = 'Try again later.' } }) }
                if ($global:CreateAttempts -eq 1) { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body | Out-Null }
                return $failed
            }
            Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
        }
        $context = New-Context
        $observed = & $provider.Set $target (& $desired) $null $context
        $observed.userPrincipalName | Should -Be 'erin@example.com'
        $global:CreateAttempts | Should -Be 4
        $context.Secrets.Count | Should -Be 1
        & $graphSawPassword $context.Secrets['S02'] | Should -BeTrue
    }

    It 'a POST that failed for a user who was already there before it still hands back nothing (even if a lagging read missed them)' {
        # alice exists; the first read of her answers 404 (replication lag), the POST is a duplicate.
        Add-FakeGraphFault -World $w -Status 404 -Code 'Request_ResourceNotFound' -Method GET -Count 1
        $context = New-Context
        { & $provider.Set @{ Kind = 'user'; Id = 'alice@example.com'; Name = 'Alice' } @{ userPrincipalName = 'alice@example.com'; displayName = 'Alice Again'; mailNickname = 'alice2' } $null $context } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
        $context.Secrets.Count | Should -Be 0
    }

    It 'when the user cannot be looked up after a failed POST, the password is kept and the error stands' {
        Mock -ModuleName Tenure Invoke-TenureGraphRaw {
            $failed = @{ Status = 503; Headers = @{}; Body = (ConvertTo-FakeGraphBody -Value @{ error = @{ code = 'ServiceUnavailable'; message = 'Try again later.' } }) }
            if ($Method -eq 'POST') { $global:CreateAttempts++; return $failed }
            if ($global:CreateAttempts -gt 0) { return $failed }
            Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
        }
        $context = New-Context
        { & $provider.Set $target (& $desired) $null $context } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
        $context.Secrets.Count | Should -Be 1 -Because 'the create may have landed; discarding would lose the only copy'
    }

    It 'a failed POST whose user cannot be found afterwards keeps the password and the error stands (the read may lag)' {
        Add-FakeGraphFault -World $w -Status 503 -Count 4 -Method POST
        $context = New-Context
        { & $provider.Set $target (& $desired) $null $context } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
        $context.Secrets.Count | Should -Be 1 -Because 'a kept password for an absent user costs nothing; a discarded one for a user that exists loses a live credential'
        & $erinCount | Should -Be 0
    }

    It 'a failed POST whose user turns up afterwards without a createdDateTime is treated as this create''s' {
        Mock -ModuleName Tenure Invoke-TenureGraphRaw {
            $response = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
            if ($Method -eq 'POST' -and $Uri -like '*/v1.0/users') {
                $global:CreateAttempts++
                foreach ($user in $global:FakeGraphWorld.Users) { if ($user.userPrincipalName -eq 'erin@example.com') { $user.Remove('createdDateTime') } }
                return @{ Status = 503; Headers = $response.Headers; Body = (ConvertTo-FakeGraphBody -Value @{ error = @{ code = 'ServiceUnavailable'; message = 'Try again later.' } }) }
            }
            $response
        }
        $context = New-Context
        (& $provider.Set $target (& $desired) $null $context).userPrincipalName | Should -Be 'erin@example.com'
        $context.Secrets.Count | Should -Be 1
    }
}
