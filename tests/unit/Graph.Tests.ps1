BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest
    $global:TenureGraphResponses = [System.Collections.Generic.Queue[hashtable]]::new()
    $global:TenureGraphCalls = [System.Collections.Generic.List[hashtable]]::new()
    $global:TenureSleeps = [System.Collections.Generic.List[int]]::new()

    Mock -ModuleName Tenure Invoke-TenureGraphRaw {
        $global:TenureGraphCalls.Add(@{ Method = $Method; Uri = $Uri; Body = $Body; Headers = $Headers })
        if ($global:TenureGraphResponses.Count -eq 0) { throw 'FakeGraph: no queued response' }
        $global:TenureGraphResponses.Dequeue()
    }
    Mock -ModuleName Tenure Start-Sleep { $global:TenureSleeps.Add([int]$Seconds) }

    function Enqueue([int]$Status, $Body, [hashtable]$Headers = @{}) {
        $global:TenureGraphResponses.Enqueue(@{ Status = $Status; Headers = $Headers; Body = $Body })
    }
    function Invoke-Graph { Invoke-InTenure { param($p) Invoke-TenureGraph @p } @(, $args[0]) }
}

AfterAll {
    Remove-Variable -Name TenureGraphResponses, TenureGraphCalls, TenureSleeps -Scope Global -ErrorAction SilentlyContinue
    Clear-TenureTestSession
}

Describe 'Invoke-TenureGraph' {
    BeforeEach {
        $global:TenureGraphResponses.Clear()
        $global:TenureGraphCalls.Clear()
        $global:TenureSleeps.Clear()
        Set-TenureTestSession
    }

    It 'refuses when not connected and never calls the SDK' {
        Clear-TenureTestSession
        { Invoke-Graph @{ Method = 'GET'; Uri = 'users' } } | Should -Throw -ErrorId 'Tenure.Graph.NotConnected'
        $global:TenureGraphCalls.Count | Should -Be 0
    }

    It 'prefixes relative URIs with v1.0 and leaves beta and absolute URIs alone' {
        Enqueue 200 ([pscustomobject]@{ id = '1' })
        Enqueue 200 ([pscustomobject]@{ id = '2' })
        Enqueue 200 ([pscustomobject]@{ id = '3' })
        Invoke-Graph @{ Method = 'GET'; Uri = '/users/x' } | Out-Null
        Invoke-Graph @{ Method = 'GET'; Uri = 'beta/users/x' } | Out-Null
        Invoke-Graph @{ Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/me' } | Out-Null
        $global:TenureGraphCalls[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/users/x'
        $global:TenureGraphCalls[1].Uri | Should -Be 'https://graph.microsoft.com/beta/users/x'
        $global:TenureGraphCalls[2].Uri | Should -Be 'https://graph.microsoft.com/v1.0/me'
    }

    It 'returns the body on 2xx' {
        Enqueue 200 ([pscustomobject]@{ id = 'abc'; accountEnabled = $true })
        (Invoke-Graph @{ Method = 'GET'; Uri = 'users/abc' }).accountEnabled | Should -BeTrue
    }

    It 'serializes a hashtable body as compact JSON' {
        Enqueue 204 $null
        Invoke-Graph @{ Method = 'PATCH'; Uri = 'users/abc'; Body = @{ accountEnabled = $false } } | Out-Null
        $global:TenureGraphCalls[0].Body | Should -Be '{"accountEnabled":false}'
    }

    It 'maps 404 to Tenure.Graph.NotFound with structured data' {
        Enqueue 404 ([pscustomobject]@{ error = [pscustomobject]@{ code = 'Request_ResourceNotFound'; message = 'gone' } }) @{ 'request-id' = @('req-1') }
        $error = { Invoke-Graph @{ Method = 'GET'; Uri = 'users/nope' } } | Should -Throw -ErrorId 'Tenure.Graph.NotFound' -PassThru
        $error.Exception.Data['StatusCode'] | Should -Be 404
        $error.Exception.Data['Code'] | Should -Be 'Request_ResourceNotFound'
        $error.Exception.Data['RequestId'] | Should -Be 'req-1'
    }

    It 'maps 403 to Tenure.Graph.Forbidden and points at scopes' {
        Enqueue 403 ([pscustomobject]@{ error = [pscustomobject]@{ code = 'Authorization_RequestDenied'; message = 'Insufficient privileges' } })
        $error = { Invoke-Graph @{ Method = 'DELETE'; Uri = 'groups/g/members/u/$ref' } } | Should -Throw -ErrorId 'Tenure.Graph.Forbidden' -PassThru
        $error.Exception.Message | Should -Match 'scope'
    }

    It 'maps 401 to Tenure.Graph.NotConnected' {
        Enqueue 401 ([pscustomobject]@{ error = [pscustomobject]@{ code = 'InvalidAuthenticationToken'; message = 'expired' } })
        { Invoke-Graph @{ Method = 'GET'; Uri = 'me' } } | Should -Throw -ErrorId 'Tenure.Graph.NotConnected'
    }

    It 'treats a 200 with an error body as Tenure.Graph.Failed' {
        Enqueue 200 ([pscustomobject]@{ error = [pscustomobject]@{ code = 'Weird'; message = 'lying 200' } })
        { Invoke-Graph @{ Method = 'GET'; Uri = 'me' } } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
    }

    It 'retries a 429 honoring Retry-After, then succeeds' {
        Enqueue 429 ([pscustomobject]@{ error = [pscustomobject]@{ code = 'TooManyRequests'; message = 'slow down' } }) @{ 'Retry-After' = @('7') }
        Enqueue 200 ([pscustomobject]@{ id = 'ok' })
        (Invoke-Graph @{ Method = 'GET'; Uri = 'me' }).id | Should -Be 'ok'
        $global:TenureSleeps | Should -Be @(7)
        $global:TenureGraphCalls.Count | Should -Be 2
    }

    It 'waits at most 60 s however long Retry-After asks for, so a call has a latest time to land' {
        Enqueue 429 ([pscustomobject]@{ error = [pscustomobject]@{ code = 'TooManyRequests'; message = 'slow down' } }) @{ 'Retry-After' = @('3600') }
        Enqueue 200 ([pscustomobject]@{ id = 'ok' })
        (Invoke-Graph @{ Method = 'GET'; Uri = 'me' }).id | Should -Be 'ok'
        $global:TenureSleeps | Should -Be @(60)
        # Four attempts of at most 5 minutes each, and three waits of at most 60 s.
        (Invoke-InTenure { Get-TenureGraphLongestCall }) | Should -Be ([timespan]::FromMinutes(23))
    }

    It 'backs off exponentially without Retry-After and gives up with Tenure.Graph.Throttled' {
        1..4 | ForEach-Object { Enqueue 429 ([pscustomobject]@{ error = [pscustomobject]@{ code = 'TooManyRequests'; message = 'x' } }) }
        { Invoke-Graph @{ Method = 'GET'; Uri = 'me' } } | Should -Throw -ErrorId 'Tenure.Graph.Throttled'
        $global:TenureSleeps | Should -Be @(2, 4, 8)
        $global:TenureGraphCalls.Count | Should -Be 4
    }

    It 'retries 5xx and surfaces Tenure.Graph.Failed when they persist' {
        Enqueue 503 $null
        Enqueue 200 ([pscustomobject]@{ id = 'recovered' })
        (Invoke-Graph @{ Method = 'GET'; Uri = 'me' }).id | Should -Be 'recovered'
        $global:TenureGraphCalls.Clear(); $global:TenureSleeps.Clear()
        Enqueue 502 $null
        { Invoke-Graph @{ Method = 'GET'; Uri = 'me'; MaxRetry = 0 } } | Should -Throw -ErrorId 'Tenure.Graph.Failed'
        $global:TenureSleeps.Count | Should -Be 0
    }

    It 'follows @odata.nextLink with -All and concatenates value arrays' {
        Enqueue 200 ([pscustomobject]@{ value = @([pscustomobject]@{ id = 'a' }, [pscustomobject]@{ id = 'b' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=1' })
        Enqueue 200 ([pscustomobject]@{ value = @([pscustomobject]@{ id = 'c' }) })
        $items = @(Invoke-Graph @{ Method = 'GET'; Uri = 'users'; All = $true })
        $items.id | Should -Be @('a', 'b', 'c')
        $global:TenureGraphCalls[1].Uri | Should -Be 'https://graph.microsoft.com/v1.0/users?$skiptoken=1'
    }

    It 'returns an empty array from -All when value is empty' {
        Enqueue 200 ([pscustomobject]@{ value = @() })
        $items = @(Invoke-Graph @{ Method = 'GET'; Uri = 'users'; All = $true })
        $items.Count | Should -Be 0
    }

    It 'does not resend the body on paged follow-up requests' {
        Enqueue 200 ([pscustomobject]@{ value = @(1); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/x?skip=1' })
        Enqueue 200 ([pscustomobject]@{ value = @(2) })
        Invoke-Graph @{ Method = 'POST'; Uri = 'x'; Body = @{ q = 1 }; All = $true } | Out-Null
        $global:TenureGraphCalls[0].Body | Should -Not -BeNullOrEmpty
        $global:TenureGraphCalls[1].Body | Should -BeNullOrEmpty
    }
}
