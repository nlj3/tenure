function Invoke-TenureGraphRaw {
    <#
    .SYNOPSIS
        The only place in the module that calls Invoke-MgGraphRequest.
    .DESCRIPTION
        Returns a hashtable with Status (int), Headers (dictionary) and Body (object).
        Never throws on HTTP status; Invoke-TenureGraph maps statuses to errors.
        Unit tests mock this function; it is exercised only by integration tests.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [AllowNull()][string]$Body,
        [hashtable]$Headers
    )

    $statusCode = 0
    $responseHeaders = @{}
    $parameters = @{
        Method                  = $Method
        Uri                     = $Uri
        OutputType              = 'PSObject'
        SkipHttpErrorCheck      = $true
        StatusCodeVariable      = 'statusCode'
        ResponseHeadersVariable = 'responseHeaders'
        ErrorAction             = 'Stop'
    }
    if ($Headers) { $parameters.Headers = $Headers }
    if ($null -ne $Body -and $Body.Length -gt 0) {
        $parameters.Body = $Body
        $parameters.ContentType = 'application/json'
    }
    $response = Invoke-MgGraphRequest @parameters
    @{ Status = [int]$statusCode; Headers = $responseHeaders; Body = $response }
}

function Invoke-TenureGraph {
    <#
    .SYNOPSIS
        Graph seam: relative or absolute URI, JSON body, retries on 429/5xx, paging with -All.
        With -All the items are emitted one by one; always wrap the call in @(...).
    .DESCRIPTION
        Error ids: Tenure.Graph.NotConnected (no session or 401), Tenure.Graph.NotFound (404),
        Tenure.Graph.Forbidden (403), Tenure.Graph.Throttled (429 after retries),
        Tenure.Graph.Failed (anything else, including 2xx with an error body).
        Exception.Data carries StatusCode, Code, Message, RequestId, Method, Uri.
    .EXAMPLE
        Invoke-TenureGraph -Method GET -Uri 'users/alice@example.com?$select=id,accountEnabled'
    .EXAMPLE
        @(Invoke-TenureGraph -Method GET -Uri 'users/{id}/memberOf' -All)
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [AllowNull()]
        [object]$Body,

        [switch]$All,

        [hashtable]$Headers,

        [ValidateRange(0, 10)]
        [int]$MaxRetry = 3
    )

    Assert-TenureConnection -Backend Graph

    $target = if ($Uri -match '^https?://') {
        $Uri
    } elseif ($Uri -match '^/?beta/') {
        'https://graph.microsoft.com/' + $Uri.TrimStart('/')
    } else {
        'https://graph.microsoft.com/v1.0/' + $Uri.TrimStart('/')
    }

    $bodyJson = $null
    if ($null -ne $Body) {
        $bodyJson = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 32 -Compress }
    }

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $target
    while ($next) {
        $attempt = 0
        $raw = $null
        while ($true) {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $raw = Invoke-TenureGraphRaw -Method $Method -Uri $next -Body $bodyJson -Headers $Headers
            Write-Verbose ("Graph {0} {1} -> {2} ({3} ms)" -f $Method, $next, $raw.Status, $stopwatch.ElapsedMilliseconds)
            $retryable = ($raw.Status -eq 429) -or ($raw.Status -ge 500 -and $raw.Status -le 599)
            if (-not $retryable -or $attempt -ge $MaxRetry) { break }
            $attempt++
            $delay = [math]::Pow(2, $attempt)
            $retryAfter = $null
            if ($raw.Headers -and $raw.Headers.Contains('Retry-After')) { $retryAfter = @($raw.Headers['Retry-After'])[0] }
            if ($retryAfter -and [int]::TryParse([string]$retryAfter, [ref]$delay)) { $delay = [math]::Max(1, $delay) }
            Write-Verbose ("Graph {0} {1}: status {2}, retry {3}/{4} after {5} s" -f $Method, $next, $raw.Status, $attempt, $MaxRetry, $delay)
            Start-Sleep -Seconds $delay
        }

        $body = $raw.Body
        $errorInfo = $null
        if ($null -ne $body -and $body.PSObject.Properties['error'] -and $null -ne $body.error) { $errorInfo = $body.error }
        if ($raw.Status -ge 400 -or $null -ne $errorInfo) {
            $code = if ($errorInfo -and $errorInfo.PSObject.Properties['code']) { [string]$errorInfo.code } else { '' }
            $message = if ($errorInfo -and $errorInfo.PSObject.Properties['message']) { [string]$errorInfo.message } else { '' }
            $requestId = ''
            if ($raw.Headers -and $raw.Headers.Contains('request-id')) { $requestId = [string]@($raw.Headers['request-id'])[0] }
            $data = @{ StatusCode = $raw.Status; Code = $code; Message = $message; RequestId = $requestId; Method = $Method; Uri = $next }
            $summary = "Graph $Method $next returned $($raw.Status)" + $(if ($code) { " ($code)" } else { '' }) + $(if ($message) { ": $message" } else { '.' })
            switch ($raw.Status) {
                401 { throw (New-TenureError -Id 'Tenure.Graph.NotConnected' -Message "$summary Run Connect-Tenure again." -Category AuthenticationError -Data $data) }
                403 { throw (New-TenureError -Id 'Tenure.Graph.Forbidden' -Message "$summary The signed-in identity lacks a required scope or role; compare with the provider's Scopes in Get-TenureProvider." -Category PermissionDenied -Data $data) }
                404 { throw (New-TenureError -Id 'Tenure.Graph.NotFound' -Message $summary -Category ObjectNotFound -Data $data) }
                429 { throw (New-TenureError -Id 'Tenure.Graph.Throttled' -Message "$summary Gave up after $MaxRetry retries." -Category LimitsExceeded -Data $data) }
                default { throw (New-TenureError -Id 'Tenure.Graph.Failed' -Message $summary -Category NotSpecified -Data $data) }
            }
        }

        if (-not $All) { return $body }

        if ($null -ne $body -and $body.PSObject.Properties['value']) {
            foreach ($item in @($body.value)) { $items.Add($item) }
        } elseif ($null -ne $body) {
            $items.Add($body)
        }
        $next = $null
        if ($null -ne $body -and $body.PSObject.Properties['@odata.nextLink']) { $next = [string]$body.'@odata.nextLink' }
        $bodyJson = $null
    }
    # Emitted unrolled: callers wrap in @(...) (the PowerShell idiom). Zero items -> nothing.
    return $items.ToArray()
}
