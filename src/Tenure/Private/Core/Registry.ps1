# The kinds of object a step can act on (SPEC section 2.3). Each provider declares one of them as its TargetKind.
$script:TargetKinds = [string[]]@('user', 'group', 'device', 'mailbox', 'drive', 'role')

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
    # Repeatable: firing the Invoke twice does no harm, so a resumed run may fire it again when an earlier
    # attempt left no record of its outcome. Absent means $false.
    $repeatable = & $get 'Repeatable'
    if ($null -ne $repeatable -and -not ($repeatable -is [bool])) { $problems.Add('Repeatable must be a [bool].') }
    if ($kind -ne 'Invoke' -and $repeatable -eq $true) { $problems.Add('Repeatable is only valid for Invoke providers.') }
    # TargetKind: the one kind of object the provider acts on. The engine reads Target.Id as that kind, whatever a
    # plan's Target.Kind label says, and refuses a step whose label disagrees.
    $targetKind = & $get 'TargetKind'
    if ($targetKind -isnot [string] -or $script:TargetKinds -cnotcontains $targetKind) { $problems.Add(("TargetKind must be one of {0} (got '{1}')." -f ($script:TargetKinds -join ', '), $targetKind)) }
    # Actions: the step actions the provider allows. A plan step with any other Action is refused.
    $actions = @(& $get 'Actions')
    $actionChoices = switch ($kind) { 'Check' { @('Check', 'NoOp') } 'Invoke' { @('Invoke') } default { @('Create', 'Update', 'Remove', 'NoOp') } }
    if ($actions.Count -eq 0 -or @($actions | Where-Object { $_ -isnot [string] -or $actionChoices -cnotcontains $_ }).Count -gt 0) {
        $problems.Add(("Actions must list one or more of {0} for Kind '{1}'." -f ($actionChoices -join ', '), $kind))
    }
    # AffectedBy (Check only, required there, may be empty): providers whose steps change what the check reads. On
    # a later run, a check whose input this plan's own step changed is re-evaluated instead of drift-checked.
    $affectedBy = @(& $get 'AffectedBy' | Where-Object { $null -ne $_ })
    if ($kind -ne 'Check' -and $affectedBy.Count -gt 0) { $problems.Add('AffectedBy is only valid for Check providers.') }
    if ($kind -eq 'Check' -and -not $Definition.ContainsKey('AffectedBy')) { $problems.Add('Check providers must declare AffectedBy (an empty list when no provider changes what they read).') }
    if (@($affectedBy | Where-Object { $_ -isnot [string] -or $_ -cnotmatch '^[A-Z][A-Za-z]+\.[A-Z][A-Za-z]+$' }).Count -gt 0) { $problems.Add("AffectedBy must list provider names ('Area.Resource').") }

    $allowedKeys = 'Name', 'Kind', 'Backend', 'Scopes', 'Risk', 'Reversible', 'Repeatable', 'TargetKind', 'Actions', 'AffectedBy', 'Get', 'Test', 'Set', 'Describe', 'Severity', 'Description'
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
        Repeatable  = ($repeatable -eq $true)
        TargetKind  = $targetKind
        Actions     = [string[]]$actions
        AffectedBy  = [string[]]$affectedBy
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
