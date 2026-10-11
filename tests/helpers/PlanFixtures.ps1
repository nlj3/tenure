# Hand-built Tenure.Step / Tenure.Plan fixtures for the apply engine and audit tests.
# Dot-source after TestHelpers.ps1 and Import-TenureForTest:
#   . (Join-Path $PSScriptRoot '..' 'helpers' 'PlanFixtures.ps1')
#
# These deliberately do not call New-TenureStep / New-TenurePlan: the engine is tested
# against the shapes in docs/SPEC.md sections 2.3 and 2.4, not against the builders.

function Get-TestHash {
    <#
    .SYNOPSIS
        Get-TenureHash from inside the module (the same function the builders use).
    #>
    param([AllowNull()][object]$InputObject)
    Invoke-InTenure { param($o) Get-TenureHash -InputObject $o } @(, $InputObject)
}

function Get-TestFingerprint {
    <#
    .SYNOPSIS
        Get-TenureStepFingerprint from inside the module: the hash of the target identity and the Before snapshot.
    #>
    param([AllowNull()][object]$Target, [AllowNull()][object]$Before)
    Invoke-InTenure { param($t, $b) Get-TenureStepFingerprint -Target $t -Before $b } @($Target, $Before)
}

function Get-TestSnapshot {
    <#
    .SYNOPSIS
        A PSCustomObject copy of one fake-state entry, like a provider Get returns.
    #>
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][string]$Id)
    [pscustomobject]$State[$Id].Clone()
}

function New-TestSecureString {
    param([Parameter(Mandatory)][string]$Text)
    $secure = [securestring]::new()
    foreach ($character in $Text.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    $secure
}

function ConvertFrom-TestSecureString {
    param([Parameter(Mandatory)][securestring]$SecureString)
    [System.Net.NetworkCredential]::new('', $SecureString).Password
}

function Register-TestProvider {
    param([Parameter(Mandatory)][hashtable]$Definition)
    $null = Invoke-InTenure { param($d) Register-TenureProvider -Definition $d -Force } @($Definition)
}

function Unregister-TestProvider {
    param([Parameter(Mandatory)][string[]]$Name)
    foreach ($item in $Name) { Invoke-InTenure { param($n) Unregister-TenureProvider -Name $n } @($item) }
}

function New-RecordingProvider {
    <#
    .SYNOPSIS
        A fake State provider over $State whose Set records '<Name>:<Target.Id>' in $Log.
    .DESCRIPTION
        Wraps New-FakeProviderDefinition. Use -Overrides for Kind, Risk, Backend and so on.
        Kind 'Check' drops Set (Check providers must not define one) and defaults Severity
        to Refuse.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$State,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Log,
        [hashtable]$Overrides = @{}
    )
    $set = {
        param($Target, $Desired, $Current, $Context)
        $Log.Add("${Name}:$($Target.Id)")
        if (-not $State.ContainsKey($Target.Id)) { $State[$Target.Id] = @{} }
        foreach ($key in $Desired.Keys) { $State[$Target.Id][$key] = $Desired[$key] }
        [pscustomobject]$State[$Target.Id].Clone()
    }.GetNewClosure()
    $merged = @{ Set = $set }
    foreach ($key in $Overrides.Keys) { $merged[$key] = $Overrides[$key] }
    $definition = New-FakeProviderDefinition -Name $Name -State $State -Overrides $merged
    if ($definition['Kind'] -eq 'Check') {
        $definition.Remove('Set')
        if (-not $definition.ContainsKey('Severity')) { $definition['Severity'] = 'Refuse' }
    }
    $definition
}

function New-TestStep {
    <#
    .SYNOPSIS
        A Tenure.Step shaped as in SPEC section 2.3, plus Key.
    .DESCRIPTION
        Kind and Risk default to the registered provider's values (or State / Low).
        Target defaults to @{ Kind = 'user'; Id = 'u-<Id>'; Name = 'user <Id>' }.
        Fingerprint defaults to Get-TenureStepFingerprint(Target, Before), the function the
        builders and the engine use; with Before $null that binds the target as absent.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$Provider = 'Fake.State',
        [string]$Kind,
        [hashtable]$Target,
        [string]$Action = 'Update',
        [AllowNull()][object]$Before = $null,
        [AllowNull()][object]$After = @{},
        [AllowNull()][string]$Fingerprint,
        [string]$Risk,
        [bool]$Reversible = $true,
        [string]$Reason,
        [string[]]$DependsOn = @(),
        [string]$Status = 'Pending',
        [AllowNull()][object]$Result = $null
    )

    $registered = Invoke-InTenure { param($n) if ($script:Providers.Contains($n)) { $script:Providers[$n] } } @($Provider)
    if (-not $Kind) { $Kind = if ($registered) { $registered.Kind } else { 'State' } }
    if (-not $Risk) { $Risk = if ($registered) { $registered.Risk } else { 'Low' } }
    if (-not $Target) { $Target = @{ Kind = 'user'; Id = "u-$Id"; Name = "user $Id" } }
    if (-not $PSBoundParameters.ContainsKey('Fingerprint')) {
        $Fingerprint = Get-TestFingerprint -Target $Target -Before $Before
    }
    if (-not $Reason) { $Reason = "$Action $($Target.Name)" }

    [pscustomobject]@{
        PSTypeName  = 'Tenure.Step'
        Id          = $Id
        Key         = "key-$Id"
        Provider    = $Provider
        Kind        = $Kind
        Target      = $Target
        Action      = $Action
        Before      = $Before
        After       = $After
        Fingerprint = $Fingerprint
        Risk        = $Risk
        Reversible  = $Reversible
        Reason      = $Reason
        DependsOn   = [string[]]$DependsOn
        Status      = $Status
        Result      = $Result
    }
}

# The PolicyHash New-TestPlan records by default; New-TestPolicyObject carries the same hash.
$script:TestPolicyHash = ('7e57' * 16)

function New-TestPolicyObject {
    <#
    .SYNOPSIS
        A minimal policy stand-in whose Hash matches New-TestPlan's default PolicyHash, for passing -Policy to the engine.
    #>
    param([string[]]$ProtectedUsers = @())
    [pscustomobject]@{
        PSTypeName = 'Tenure.Policy'
        Hash       = $script:TestPolicyHash
        Defaults   = @{ protectedUsers = [string[]]$ProtectedUsers }
        ManagedSet = @{ Licenses = [string[]]@(); Groups = [string[]]@() }
    }
}

function New-TestPlan {
    <#
    .SYNOPSIS
        A Tenure.Plan shaped as in SPEC section 2.4, sealed with its Integrity value.
    .DESCRIPTION
        Change a step's Status or Result freely after this; anything else the plan says (a
        step's Target, After, Before, Risk, the subject, CreatedAt) changes the integrity
        value, so reseal with Update-TestPlanIntegrity when the change is part of the setup
        rather than the tampering under test.

        The plan records a policy unless the test says otherwise: PolicyHash defaults to
        $script:TestPolicyHash and PolicySnapshot to one with no protected users, so the engine,
        run without -Policy, has a recorded list to check. Pass -PolicyHash '' or
        -PolicySnapshot $null to build a plan that records none.
    #>
    param(
        [object[]]$Steps = @(),
        [string]$Operation = 'Custom',
        [hashtable]$Subject,
        [AllowNull()][object]$CreatedAt,
        [string]$Status = 'Planned',
        [AllowNull()][string]$PolicyHash = $null,
        [AllowNull()][hashtable]$PolicySnapshot = $null,
        [AllowNull()][string]$TenantId = '00000000-0000-0000-0000-00000000beef'
    )

    if (-not $PSBoundParameters.ContainsKey('Subject')) {
        $Subject = @{ Id = '11111111-2222-3333-4444-555555555555'; UserPrincipalName = 'alice@example.com'; DisplayName = 'Alice Example' }
    }
    if (-not $PSBoundParameters.ContainsKey('CreatedAt')) { $CreatedAt = [datetime]::UtcNow.ToString('o') }
    if (-not $PSBoundParameters.ContainsKey('PolicyHash')) { $PolicyHash = $script:TestPolicyHash }
    if (-not $PSBoundParameters.ContainsKey('PolicySnapshot')) { $PolicySnapshot = @{ ProtectedUsers = [string[]]@(); ManagedSet = @{ Licenses = [string[]]@(); Groups = [string[]]@() } } }
    if ([string]::IsNullOrEmpty($PolicyHash)) { $PolicyHash = $null }

    $plan = [pscustomobject]@{
        PSTypeName     = 'Tenure.Plan'
        SchemaVersion  = 2
        PlanId         = [guid]::NewGuid().ToString()
        CreatedAt      = $CreatedAt
        CreatedBy      = @{ Account = 'admin@example.com'; TenantId = $TenantId; AuthType = 'Test' }
        ModuleVersion  = (Get-Module -Name Tenure).Version.ToString()
        Operation      = $Operation
        Subject        = $Subject
        PolicyHash     = $PolicyHash
        PolicySnapshot = $PolicySnapshot
        Inputs         = @{}
        Steps          = @($Steps)
        Warnings       = @()
        Status         = $Status
        Integrity      = $null
    }
    Update-TestPlanIntegrity $plan
    $plan
}

function Update-TestPlanIntegrity {
    <#
    .SYNOPSIS
        Recomputes Plan.Integrity with the module's own function (for setup changes, never for the tampering a test checks).
    #>
    param([Parameter(Mandatory, Position = 0)][object]$Plan)
    try {
        $Plan.Integrity = Invoke-InTenure { param($p) Get-TenurePlanIntegrity -Plan $p } @($Plan)
    } catch {
        # A plan that cannot even be hashed (a SecureString in a step) is left unsealed: the engine's shape check
        # refuses it first, which is what such a test is about.
        $Plan.Integrity = $null
    }
}

function Disable-TestIdentityLookup {
    <#
    .SYNOPSIS
        Replaces the engine's account lookup (Get-TenureUserIdentity) inside the loaded module with one that finds nobody.
    .DESCRIPTION
        For test files whose plans name made-up users and run without FakeGraph. The
        subject-protection preflight then compares only the names the plan itself carries
        (subject id and user principal name). Tests of that preflight use FakeGraph instead.
        The replacement lasts until the module is imported again. Works outside Pester too.
    #>
    Invoke-InTenure { function script:Get-TenureUserIdentity { param([string]$Identity) $null } }
}

function Get-TestStatus {
    <#
    .SYNOPSIS
        The step statuses of a plan as one comma-separated string (easy to assert).
    #>
    param([Parameter(Mandatory)][object]$Plan)
    (@($Plan.Steps) | ForEach-Object { $_.Status }) -join ','
}

function New-TestCmdlet {
    <#
    .SYNOPSIS
        A stand-in for $PSCmdlet with scriptable ShouldProcess and ShouldContinue, for
        driving Invoke-TenurePlanCore through confirmation paths a test host cannot prompt.
    .DESCRIPTION
        Calls records every call as 'ShouldProcess:<target>' or 'ShouldContinue:<query>'.
        The rules receive the same arguments and return a bool or throw.
    #>
    param(
        [scriptblock]$ShouldProcess = { param($target, $action) $true },
        [scriptblock]$ShouldContinue = { param($query, $caption) $true }
    )
    $cmdlet = [pscustomobject]@{
        Calls        = [System.Collections.Generic.List[string]]::new()
        ProcessRule  = $ShouldProcess
        ContinueRule = $ShouldContinue
    }
    $cmdlet | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value {
        param($target, $action)
        $this.Calls.Add("ShouldProcess:$target")
        & $this.ProcessRule $target $action
    }
    $cmdlet | Add-Member -MemberType ScriptMethod -Name ShouldContinue -Value {
        param($query, $caption)
        $this.Calls.Add("ShouldContinue:$query")
        & $this.ContinueRule $query $caption
    }
    $cmdlet
}

function Invoke-TestCore {
    <#
    .SYNOPSIS
        Runs the private engine with a stand-in cmdlet (confirmation not suppressed by default).
    #>
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Cmdlet,
        [Parameter(Mandatory)][string]$AuditPath,
        [hashtable]$With = @{}
    )
    $parameters = @{ Plan = $Plan; Cmdlet = $Cmdlet; AuditPath = $AuditPath; ConfirmSuppressed = $false }
    foreach ($key in $With.Keys) { $parameters[$key] = $With[$key] }
    Invoke-InTenure { param($p) Invoke-TenurePlanCore @p } @(, $parameters)
}

function Write-TestAudit {
    <#
    .SYNOPSIS
        Appends a hand-made entry through the real writer (to stage audit history).
    #>
    param([Parameter(Mandatory)][hashtable]$Entry, [Parameter(Mandatory)][string]$Path)
    Invoke-InTenure { param($e, $p) Write-TenureAudit -Entry $e -Path $p } @($Entry, $Path)
}
