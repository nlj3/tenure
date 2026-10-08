function Register-TenureProvider {
    <#
    .SYNOPSIS
        Validates a provider definition and stores it in the module registry.
    .DESCRIPTION
        See docs/SPEC.md section 2.2 for the contract. Providers are registered at module
        load by files in Private/Providers. Tests register fakes with -Force and
        remove them with Unregister-TenureProvider.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Provider')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [hashtable]$Definition,

        [switch]$Force
    )

    $problems = [System.Collections.Generic.List[string]]::new()
    $get = { param($key) if ($Definition.ContainsKey($key)) { $Definition[$key] } else { $null } }

    $name = & $get 'Name'
    if (-not ($name -is [string]) -or $name -cnotmatch '^[A-Z][A-Za-z]+\.[A-Z][A-Za-z]+$') {
        $problems.Add("Name must match 'Area.Resource' (got '$name').")
    }
    $kind = & $get 'Kind'
    if ($kind -notin 'State', 'Invoke', 'Check') { $problems.Add("Kind must be State, Invoke or Check (got '$kind').") }
    $backend = & $get 'Backend'
    if ($backend -notin 'Graph', 'Exchange') { $problems.Add("Backend must be Graph or Exchange (got '$backend').") }
    $risk = & $get 'Risk'
    if ($risk -notin 'Low', 'Medium', 'High', 'Destructive') { $problems.Add("Risk must be Low, Medium, High or Destructive (got '$risk').") }
    $reversible = & $get 'Reversible'
    if (-not ($reversible -is [bool])) { $problems.Add('Reversible must be a [bool].') }
    $scopes = & $get 'Scopes'
    if ($null -eq $scopes) { $scopes = @() }
    if (@($scopes | Where-Object { -not ($_ -is [string]) }).Count -gt 0) { $problems.Add('Scopes must be strings.') }

    foreach ($required in 'Get', 'Test', 'Describe') {
        if (-not ((& $get $required) -is [scriptblock])) { $problems.Add("$required must be a scriptblock.") }
    }
    $set = & $get 'Set'
    if ($kind -in 'State', 'Invoke' -and -not ($set -is [scriptblock])) { $problems.Add("Set must be a scriptblock for Kind '$kind'.") }
    if ($kind -eq 'Check' -and $null -ne $set) { $problems.Add('Check providers must not define Set.') }
    $severity = & $get 'Severity'
    if ($kind -eq 'Check' -and $severity -notin 'Warn', 'Refuse') { $problems.Add("Check providers need Severity Warn or Refuse (got '$severity').") }
    if ($kind -ne 'Check' -and $null -ne $severity) { $problems.Add('Severity is only valid for Check providers.') }

    $allowedKeys = 'Name', 'Kind', 'Backend', 'Scopes', 'Risk', 'Reversible', 'Get', 'Test', 'Set', 'Describe', 'Severity', 'Description'
    foreach ($key in $Definition.Keys) {
        if ($key -notin $allowedKeys) { $problems.Add("Unknown key '$key'.") }
    }

    if ($problems.Count -gt 0) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDefinition' -Message ("Provider definition '$name' is invalid: " + ($problems -join ' ')) -Category InvalidArgument -Data @{ Problems = $problems.ToArray() })
    }
    if ($script:Providers.Contains($name) -and -not $Force) {
        throw (New-TenureError -Id 'Tenure.Provider.Duplicate' -Message "Provider '$name' is already registered. Use -Force to replace it." -Category ResourceExists)
    }

    $provider = [pscustomobject]@{
        PSTypeName  = 'Tenure.Provider'
        Name        = $name
        Kind        = $kind
        Backend     = $backend
        Scopes      = @($scopes)
        Risk        = $risk
        Reversible  = $reversible
        Severity    = $severity
        Description = [string](& $get 'Description')
        Get         = & $get 'Get'
        Test        = & $get 'Test'
        Set         = $set
        Describe    = & $get 'Describe'
    }
    $script:Providers[$name] = $provider
    $provider
}

function Unregister-TenureProvider {
    <#
    .SYNOPSIS
        Removes a provider from the registry (test cleanup).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if ($script:Providers.Contains($Name)) { $script:Providers.Remove($Name) }
}

function Get-TenureProviderDefinition {
    <#
    .SYNOPSIS
        Returns a registered provider or throws Tenure.Provider.NotRegistered.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Provider')]
    param([Parameter(Mandatory)][string]$Name)

    if (-not $script:Providers.Contains($Name)) {
        throw (New-TenureError -Id 'Tenure.Provider.NotRegistered' -Message "No provider named '$Name' is registered. Run Get-TenureProvider to list them." -Category ObjectNotFound)
    }
    $script:Providers[$Name]
}
