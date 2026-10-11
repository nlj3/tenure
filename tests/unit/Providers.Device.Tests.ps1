BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1'); . (Join-Path $PSScriptRoot '..' 'helpers' 'FakeGraph.ps1')
    Import-TenureForTest; Set-TenureTestSession
    $global:FakeGraphWorld = New-FakeGraphWorld
    $global:FakeGraphSleeps = [System.Collections.Generic.List[int]]::new()

    Mock -ModuleName Tenure Invoke-TenureGraphRaw { Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body }
    Mock -ModuleName Tenure Start-Sleep { $global:FakeGraphSleeps.Add([int]$Seconds) }

    function Get-Canonical($Object) { Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @(, $Object) }
    # Context as the engine builds it: the plan's subject is the user being offboarded.
    function New-Context([string]$SubjectId) {
        $context = @{ Secrets = @{}; StepId = 'S16'; Mode = 'Apply' }
        if ($SubjectId) { $context.Subject = @{ Id = $SubjectId; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice Example' } }
        $context
    }
    function New-Target([string]$DeviceId, [string]$Name = 'device') { @{ Kind = 'device'; Id = $DeviceId; Name = $Name } }
    function Find-Device([string]$Id) { $global:FakeGraphWorld.ManagedDevices | Where-Object { $_['id'] -eq $Id } | Select-Object -First 1 }
    function Get-DevicePosts([string]$Like = '*') { @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method POST -UriLike "*deviceManagement/managedDevices/$Like") }
    # A 200 response for the next request, carrying the device as Graph would show it (for faults on a later request).
    function Add-DeviceRead([string]$Id) {
        $device = Find-Device $Id
        $global:FakeGraphWorld.Faults.Enqueue(@{ Status = 200; Body = (ConvertTo-FakeGraphWire -World $global:FakeGraphWorld -Kind 'device' -Object $device) })
    }
    function Split-Warning([object[]]$Output) {
        @{
            Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            Result   = @($Output | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
        }
    }
}

AfterAll {
    Remove-Variable -Name FakeGraphWorld, FakeGraphSleeps, DeviceTestAnsweredId -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Device provider registration' {
    It 'Device.Wipe is a Destructive, irreversible Invoke provider with the privileged-operations scope' {
        $provider = Get-TenureProvider -Name 'Device.Wipe'
        $provider.Kind | Should -BeExactly 'Invoke'
        $provider.Backend | Should -BeExactly 'Graph'
        $provider.Risk | Should -BeExactly 'Destructive'
        $provider.Reversible | Should -BeExactly $false
        @($provider.Scopes) | Should -Be @('DeviceManagementManagedDevices.PrivilegedOperations.All', 'DeviceManagementManagedDevices.Read.All')
    }

    It 'Device.Retire is a High-risk, irreversible Invoke provider with the same scopes' {
        $provider = Get-TenureProvider -Name 'Device.Retire'
        $provider.Kind | Should -BeExactly 'Invoke'
        $provider.Backend | Should -BeExactly 'Graph'
        $provider.Risk | Should -BeExactly 'High'
        $provider.Reversible | Should -BeExactly $false
        @($provider.Scopes) | Should -Be @('DeviceManagementManagedDevices.PrivilegedOperations.All', 'DeviceManagementManagedDevices.Read.All')
    }
}

Describe 'Device.Wipe' {
    BeforeAll {
        $script:provider = Get-TenureProvider -Name 'Device.Wipe'
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    Context 'Get' {
        It 'reads <name> as ownership <ownership>' -ForEach @(
            @{ key = 'CompanyDeviceId'; name = 'ALICE-LAPTOP'; ownership = 'company'; os = 'Windows' }
            @{ key = 'PersonalDeviceId'; name = 'ALICE-PHONE'; ownership = 'personal'; os = 'iOS' }
            @{ key = 'UnknownDeviceId'; name = 'ALICE-TABLET'; ownership = 'unknown'; os = 'Android' }
        ) {
            $current = & $provider.Get (New-Target $ids[$key] $name) (New-Context $ids.AliceId)
            $current | Should -BeOfType [pscustomobject]
            @($current.PSObject.Properties.Name | Sort-Object) | Should -Be @('deviceName', 'id', 'operatingSystem', 'ownership', 'userId')
            $current.id | Should -BeExactly $ids[$key]
            $current.deviceName | Should -BeExactly $name
            $current.ownership | Should -BeExactly $ownership
            $current.operatingSystem | Should -BeExactly $os
            $current.userId | Should -BeExactly $ids.AliceId
        }

        It 'asks for exactly the documented $select on the managed device' {
            & $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId) | Out-Null
            $w.Calls.Count | Should -Be 1
            $w.Calls[0].Method | Should -BeExactly 'GET'
            $w.Calls[0].Uri | Should -BeExactly "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($ids.CompanyDeviceId)?`$select=id,deviceName,managedDeviceOwnerType,operatingSystem,userId"
        }

        It 'lowercases the owner type and reads anything that is not company or personal as unknown' -ForEach @(
            @{ raw = 'Company'; expected = 'company' }
            @{ raw = 'PERSONAL'; expected = 'personal' }
            @{ raw = 'unknownFutureValue'; expected = 'unknown' }
            @{ raw = ''; expected = 'unknown' }
            @{ raw = $null; expected = 'unknown' }
        ) {
            (Find-Device $ids.CompanyDeviceId)['ownerType'] = $raw
            (& $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId)).ownership | Should -BeExactly $expected
        }

        It 'gives the same snapshot after the device syncs or its management state moves on its own' {
            $before = Get-Canonical (& $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId))
            (Find-Device $ids.CompanyDeviceId)['lastSyncDateTime'] = '2026-10-11T16:30:00Z'
            (Find-Device $ids.CompanyDeviceId)['complianceState'] = 'noncompliant'
            Get-Canonical (& $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId)) | Should -BeExactly $before -Because 'a field that moves on its own would make every plan drift'
            (Find-Device $ids.CompanyDeviceId)['userId'] = $ids.BobId
            Get-Canonical (& $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId)) | Should -Not -Be $before -Because 'a new primary user is a real change'
        }

        It 'throws Tenure.Provider.TargetNotFound for an unknown device or a target without an id' {
            { & $provider.Get (New-Target '59999999-9999-4999-8999-999999999999') (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            { & $provider.Get (New-Target $null) (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'a 403 stays Tenure.Graph.Forbidden' {
            Add-FakeGraphFault -World $w -Status 403 -Code 'Forbidden' -Message 'Application is not authorized to perform this operation.'
            { & $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
        }

        It 'a 429 with Retry-After then success is transparent' {
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('2') }
            (& $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId)).ownership | Should -BeExactly 'company'
            @($global:FakeGraphSleeps) | Should -Be @(2)
        }

        It 'fingerprint stability: two Gets canonicalize identically, and Device.Retire reads the same object' {
            $target = New-Target $ids.PersonalDeviceId
            $first = Get-Canonical (& $provider.Get $target (New-Context $ids.AliceId))
            $first | Should -BeExactly (Get-Canonical (& $provider.Get $target (New-Context $ids.AliceId)))
            $first | Should -BeExactly (Get-Canonical (& (Get-TenureProvider -Name 'Device.Retire').Get $target (New-Context $ids.AliceId)))
        }
    }

    Context 'Test' {
        It 'is always $false (an Invoke step is idempotent by status, not by state)' {
            $current = & $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId)
            (& $provider.Test $current @{ keepEnrollmentData = $false; keepUserData = $false }) | Should -BeExactly $false
            (& $provider.Test $null $null) | Should -BeExactly $false
        }
    }

    Context 'Set' {
        It 'wipes the subject''s company device with exactly one POST, the default body, and returns a fresh Get' {
            $observed = & $provider.Set (New-Target $ids.CompanyDeviceId 'ALICE-LAPTOP (company)') @{ keepEnrollmentData = $false; keepUserData = $false } $null (New-Context $ids.AliceId)
            $posts = @(Get-DevicePosts)
            $posts.Count | Should -Be 1
            $posts[0].Uri | Should -BeExactly "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($ids.CompanyDeviceId)/wipe"
            $body = $posts[0].Body | ConvertFrom-Json -AsHashtable
            @($body.Keys | Sort-Object) | Should -Be @('keepEnrollmentData', 'keepUserData')
            $body.keepEnrollmentData | Should -BeExactly $false
            $body.keepUserData | Should -BeExactly $false
            (Find-Device $ids.CompanyDeviceId)['wiped'] | Should -BeTrue
            $observed.id | Should -BeExactly $ids.CompanyDeviceId
            $observed.ownership | Should -BeExactly 'company'
        }

        It 'leaves every other device alone' {
            & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.AliceId) | Out-Null
            (Find-Device $ids.PersonalDeviceId)['wiped'] | Should -BeFalse
            (Find-Device $ids.UnknownDeviceId)['wiped'] | Should -BeFalse
            @($w.ManagedDevices | Where-Object { $_['retired'] }).Count | Should -Be 0
        }

        It 'treats a missing Desired as the defaults (full wipe, nothing kept)' {
            & $provider.Set (New-Target $ids.CompanyDeviceId) $null $null (New-Context $ids.AliceId) | Out-Null
            $body = @(Get-DevicePosts)[0].Body | ConvertFrom-Json -AsHashtable
            $body.keepEnrollmentData | Should -BeExactly $false
            $body.keepUserData | Should -BeExactly $false
        }

        It 'passes keepUserData and keepEnrollmentData through, from a hashtable or an imported PSCustomObject' {
            & $provider.Set (New-Target $ids.CompanyDeviceId) ([pscustomobject]@{ KeepUserData = $true; keepEnrollmentData = $true }) $null (New-Context $ids.AliceId) | Out-Null
            $body = @(Get-DevicePosts)[0].Body | ConvertFrom-Json -AsHashtable
            $body.keepUserData | Should -BeExactly $true
            $body.keepEnrollmentData | Should -BeExactly $true
        }

        It 'refuses a non-boolean option (the string ''false'' would read as $true) and sends nothing' {
            { & $provider.Set (New-Target $ids.CompanyDeviceId) @{ keepUserData = 'false' } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            $w.Calls.Count | Should -Be 0
        }

        It 'refuses an unknown option, so a typo cannot silently become a full wipe, and sends nothing' {
            { & $provider.Set (New-Target $ids.CompanyDeviceId) @{ keepUsrData = $true } $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.InvalidDesired'
            $w.Calls.Count | Should -Be 0
        }

        It 'matches the subject id ignoring case' {
            & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.AliceId.ToUpperInvariant()) | Out-Null
            (Find-Device $ids.CompanyDeviceId)['wiped'] | Should -BeTrue
        }
    }

    Context 'Set: refusals (nothing is ever POSTed)' {
        It 'refuses a device whose primary user is not the plan subject' {
            $failure = { & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition' -PassThru
            $failure.Exception.Message | Should -Match 'ALICE-LAPTOP'
            $failure.Exception.Message | Should -Match $ids.BobId
            @(Get-DevicePosts).Count | Should -Be 0
            (Find-Device $ids.CompanyDeviceId)['wiped'] | Should -BeFalse
        }

        It 'refuses another user''s company device even when offboarding someone else' {
            $bobDeviceId = '50000000-0000-4000-8000-000000000009'
            $w.ManagedDevices.Add(@{ id = $bobDeviceId; deviceName = 'BOB-LAPTOP'; userId = $ids.BobId; ownerType = 'company'; operatingSystem = 'Windows'; wiped = $false; retired = $false })
            { & $provider.Set (New-Target $bobDeviceId 'BOB-LAPTOP (company)') @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-DevicePosts).Count | Should -Be 0
            (Find-Device $bobDeviceId)['wiped'] | Should -BeFalse
        }

        It 'refuses a device with no primary user' {
            (Find-Device $ids.CompanyDeviceId)['userId'] = $null
            { & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-DevicePosts).Count | Should -Be 0
        }

        It 'refuses when the context carries no subject id (<case>) and makes no Graph call at all' -ForEach @(
            @{ case = 'no Subject'; ctx = @{ Secrets = @{}; StepId = 'S16'; Mode = 'Apply' } }
            @{ case = 'Subject without Id'; ctx = @{ Secrets = @{}; Subject = @{ UserPrincipalName = 'alice@example.com' } } }
            @{ case = 'empty Id'; ctx = @{ Subject = @{ Id = '' } } }
            @{ case = 'unsubstituted placeholder'; ctx = @{ Subject = @{ Id = '{{subjectId}}' } } }
            @{ case = 'null Context'; ctx = $null }
        ) {
            { & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null $ctx } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            $w.Calls.Count | Should -Be 0
            (Find-Device $ids.CompanyDeviceId)['wiped'] | Should -BeFalse
        }

        It 'refuses to wipe a <ownership> device even for the subject (wipe is company-only)' -ForEach @(
            @{ key = 'PersonalDeviceId'; ownership = 'personal' }
            @{ key = 'UnknownDeviceId'; ownership = 'unknown' }
        ) {
            $failure = { & $provider.Set (New-Target $ids[$key]) @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition' -PassThru
            $failure.Exception.Message | Should -Match $ownership
            @(Get-DevicePosts).Count | Should -Be 0
            (Find-Device $ids[$key])['wiped'] | Should -BeFalse
        }

        It 'reads ownership and owner fresh and ignores a stale Current that claims otherwise' {
            $stale = [pscustomobject]@{ id = $ids.PersonalDeviceId; deviceName = 'ALICE-PHONE'; ownership = 'company'; operatingSystem = 'iOS'; userId = $ids.AliceId }
            { & $provider.Set (New-Target $ids.PersonalDeviceId) @{} $stale (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-DevicePosts).Count | Should -Be 0
        }

        It 'refuses a device whose ownership changed to personal after planning (the -Force case)' {
            $planned = & $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId)
            $planned.ownership | Should -BeExactly 'company'
            (Find-Device $ids.CompanyDeviceId)['ownerType'] = 'personal'
            { & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $planned (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-DevicePosts).Count | Should -Be 0
        }

        It 'throws TargetNotFound for an unknown device and sends no POST' {
            { & $provider.Set (New-Target '59999999-9999-4999-8999-999999999999') @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
            @(Get-DevicePosts).Count | Should -Be 0
        }

        It 'refuses when Graph answers for a different device id (<case>) and sends no POST' -ForEach @(
            @{ case = 'another id'; answered = '50000000-0000-4000-8000-000000000002' }
            @{ case = 'no id'; answered = $null }
        ) {
            $global:DeviceTestAnsweredId = $answered
            Mock -ModuleName Tenure Invoke-TenureGraphRaw {
                $response = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
                if ($Method -eq 'GET' -and $response.Status -eq 200) { $response.Body.id = $global:DeviceTestAnsweredId }
                $response
            }
            { & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-DevicePosts).Count | Should -Be 0
            Remove-Variable -Name DeviceTestAnsweredId -Scope Global
        }
    }

    Context 'Set: fault injection' {
        It 'a 429 with Retry-After on the wipe POST then success is transparent and wipes once' {
            Add-DeviceRead $ids.CompanyDeviceId
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('1') }
            $observed = & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.AliceId)
            $observed.id | Should -BeExactly $ids.CompanyDeviceId
            @($global:FakeGraphSleeps) | Should -Be @(1)
            @(Get-DevicePosts '*/wipe').Count | Should -Be 2 -Because 'the throttled POST is retried once by the seam'
            (Find-Device $ids.CompanyDeviceId)['wiped'] | Should -BeTrue
        }

        It 'a 403 on the wipe POST surfaces as Tenure.Graph.Forbidden and wipes nothing' {
            Add-DeviceRead $ids.CompanyDeviceId
            Add-FakeGraphFault -World $w -Status 403 -Code 'Forbidden' -Message 'Application is not authorized to perform this operation.'
            { & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
            (Find-Device $ids.CompanyDeviceId)['wiped'] | Should -BeFalse
        }

        It 'a 404 on the wipe POST (device gone meanwhile) is TargetNotFound' {
            Add-DeviceRead $ids.CompanyDeviceId
            Add-FakeGraphFault -World $w -Status 404 -Code 'ResourceNotFound' -Message 'Not found.'
            { & $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'once Graph accepted the wipe, a failed read-back is a warning and the step reports wipeIssued, not a failure' {
            # The device record disappears as soon as the wipe is sent.
            Mock -ModuleName Tenure Invoke-TenureGraphRaw {
                $sent = @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method POST -UriLike '*/wipe').Count -gt 0
                if ($sent -and $Method -eq 'GET') {
                    return @{ Status = 404; Headers = @{}; Body = [pscustomobject]@{ error = [pscustomobject]@{ code = 'ResourceNotFound'; message = 'Gone.' } } }
                }
                Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
            }
            $split = Split-Warning @(& $provider.Set (New-Target $ids.CompanyDeviceId) @{} $null (New-Context $ids.AliceId) 3>&1)
            $split.Warnings.Count | Should -Be 1
            $split.Warnings[0].Message | Should -Match 'accepted the wipe of ALICE-LAPTOP'
            $split.Result.Count | Should -Be 1
            $split.Result[0].commandIssued | Should -BeExactly 'wipeIssued'
            $split.Result[0].ownership | Should -BeExactly 'company'
            @(Get-DevicePosts '*/wipe').Count | Should -Be 1
            (Find-Device $ids.CompanyDeviceId)['wiped'] | Should -BeTrue
        }
    }

    Context 'Describe' {
        It 'names the device, its ownership and OS, and says irreversible' {
            $current = & $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId)
            $line = & $provider.Describe (New-Target $ids.CompanyDeviceId 'ALICE-LAPTOP (company)') $current @{ keepEnrollmentData = $false; keepUserData = $false } 'Invoke'
            $line | Should -BeExactly 'wipe ALICE-LAPTOP (company, Windows), irreversible'
        }

        It 'says what a partial wipe keeps' {
            $current = & $provider.Get (New-Target $ids.CompanyDeviceId) (New-Context $ids.AliceId)
            (& $provider.Describe (New-Target $ids.CompanyDeviceId) $current @{ keepUserData = $true } 'Invoke') | Should -BeExactly 'wipe ALICE-LAPTOP (company, Windows), irreversible; keeps user data'
        }

        It 'copes with no snapshot at all' {
            (& $provider.Describe (New-Target $ids.CompanyDeviceId 'ALICE-LAPTOP (company)') $null $null 'Invoke') | Should -BeExactly 'wipe ALICE-LAPTOP (company) (unknown, unknown OS), irreversible'
        }
    }
}

Describe 'Device.Retire' {
    BeforeAll {
        $script:provider = Get-TenureProvider -Name 'Device.Retire'
    }

    BeforeEach {
        Reset-FakeGraphWorld
        $script:w = $global:FakeGraphWorld
        $script:ids = $script:w.Ids
        $global:FakeGraphSleeps.Clear()
    }

    Context 'Get' {
        It 'reads <key> with the same shape as Device.Wipe' -ForEach @(
            @{ key = 'CompanyDeviceId'; ownership = 'company' }
            @{ key = 'PersonalDeviceId'; ownership = 'personal' }
            @{ key = 'UnknownDeviceId'; ownership = 'unknown' }
        ) {
            $current = & $provider.Get (New-Target $ids[$key]) (New-Context $ids.AliceId)
            @($current.PSObject.Properties.Name | Sort-Object) | Should -Be @('deviceName', 'id', 'operatingSystem', 'ownership', 'userId')
            $current.ownership | Should -BeExactly $ownership
            $current.userId | Should -BeExactly $ids.AliceId
        }

        It 'throws Tenure.Provider.TargetNotFound for an unknown device' {
            { & $provider.Get (New-Target '59999999-9999-4999-8999-999999999999') (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.TargetNotFound'
        }

        It 'Test is always $false' {
            (& $provider.Test (& $provider.Get (New-Target $ids.PersonalDeviceId) (New-Context $ids.AliceId)) @{}) | Should -BeExactly $false
        }
    }

    Context 'Set' {
        It 'retires the subject''s <key> with exactly one bodiless POST and returns a fresh Get' -ForEach @(
            @{ key = 'PersonalDeviceId' }
            @{ key = 'UnknownDeviceId' }
            @{ key = 'CompanyDeviceId' }
        ) {
            $observed = & $provider.Set (New-Target $ids[$key]) @{} $null (New-Context $ids.AliceId)
            $posts = @(Get-DevicePosts)
            $posts.Count | Should -Be 1
            $posts[0].Uri | Should -BeExactly "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($ids[$key])/retire"
            $posts[0].Body | Should -BeNullOrEmpty
            (Find-Device $ids[$key])['retired'] | Should -BeTrue
            (Find-Device $ids[$key])['wiped'] | Should -BeFalse
            $observed.id | Should -BeExactly $ids[$key]
            @(Get-DevicePosts '*/wipe').Count | Should -Be 0
        }

        It 'refuses a device whose primary user is not the plan subject, and sends no POST' {
            { & $provider.Set (New-Target $ids.PersonalDeviceId) @{} $null (New-Context $ids.BobId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-DevicePosts).Count | Should -Be 0
            (Find-Device $ids.PersonalDeviceId)['retired'] | Should -BeFalse
        }

        It 'refuses a device with no primary user' {
            (Find-Device $ids.PersonalDeviceId)['userId'] = $null
            { & $provider.Set (New-Target $ids.PersonalDeviceId) @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-DevicePosts).Count | Should -Be 0
        }

        It 'refuses without a subject id and makes no Graph call' {
            { & $provider.Set (New-Target $ids.PersonalDeviceId) @{} $null @{ Secrets = @{} } } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            { & $provider.Set (New-Target $ids.PersonalDeviceId) @{} $null $null } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            $w.Calls.Count | Should -Be 0
        }

        It 'refuses when Graph answers for a different device id, and sends no POST' {
            Mock -ModuleName Tenure Invoke-TenureGraphRaw {
                $response = Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
                if ($Method -eq 'GET' -and $response.Status -eq 200) { $response.Body.id = $global:FakeGraphWorld.Ids.CompanyDeviceId }
                $response
            }
            { & $provider.Set (New-Target $ids.PersonalDeviceId) @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Provider.Precondition'
            @(Get-DevicePosts).Count | Should -Be 0
        }

        It 'a 429 with Retry-After then success is transparent' {
            Add-DeviceRead $ids.PersonalDeviceId
            Add-FakeGraphFault -World $w -Status 429 -Headers @{ 'Retry-After' = @('2') }
            (& $provider.Set (New-Target $ids.PersonalDeviceId) @{} $null (New-Context $ids.AliceId)).id | Should -BeExactly $ids.PersonalDeviceId
            @($global:FakeGraphSleeps) | Should -Be @(2)
            (Find-Device $ids.PersonalDeviceId)['retired'] | Should -BeTrue
        }

        It 'a 403 on the retire POST surfaces as Tenure.Graph.Forbidden and retires nothing' {
            Add-DeviceRead $ids.PersonalDeviceId
            Add-FakeGraphFault -World $w -Status 403
            { & $provider.Set (New-Target $ids.PersonalDeviceId) @{} $null (New-Context $ids.AliceId) } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden'
            (Find-Device $ids.PersonalDeviceId)['retired'] | Should -BeFalse
        }

        It 'once Graph accepted the retire, a failed read-back is a warning and the step reports retireIssued' {
            Mock -ModuleName Tenure Invoke-TenureGraphRaw {
                $sent = @(Get-FakeGraphCall -World $global:FakeGraphWorld -Method POST -UriLike '*/retire').Count -gt 0
                if ($sent -and $Method -eq 'GET') {
                    return @{ Status = 503; Headers = @{}; Body = [pscustomobject]@{ error = [pscustomobject]@{ code = 'ServiceUnavailable'; message = 'Try later.' } } }
                }
                Invoke-FakeGraphRequest -World $global:FakeGraphWorld -Method $Method -Uri $Uri -Body $Body
            }
            $split = Split-Warning @(& $provider.Set (New-Target $ids.PersonalDeviceId) @{} $null (New-Context $ids.AliceId) 3>&1)
            $split.Warnings.Count | Should -Be 1
            $split.Result[0].commandIssued | Should -BeExactly 'retireIssued'
            (Find-Device $ids.PersonalDeviceId)['retired'] | Should -BeTrue
        }
    }

    Context 'Describe' {
        It 'says what a retire removes and keeps' {
            $current = & $provider.Get (New-Target $ids.PersonalDeviceId) (New-Context $ids.AliceId)
            (& $provider.Describe (New-Target $ids.PersonalDeviceId 'ALICE-PHONE (personal)') $current $null 'Invoke') | Should -BeExactly 'retire ALICE-PHONE (personal, iOS): removes company data and management, keeps personal data'
        }

        It 'copes with no snapshot' {
            (& $provider.Describe (New-Target $ids.PersonalDeviceId 'ALICE-PHONE (personal)') $null $null 'Invoke') | Should -BeExactly 'retire ALICE-PHONE (personal) (unknown, unknown OS): removes company data and management, keeps personal data'
        }
    }
}
