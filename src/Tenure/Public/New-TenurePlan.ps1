function New-TenurePlan {
    <#
    .SYNOPSIS
        Assembles steps into a plan: assigns step ids, resolves dependencies, stamps who and when.
    .DESCRIPTION
        Steps get the ids S01, S02, ... in the order given (S100 and up for long plans). Each
        step's DependsOn, which holds step keys while steps are being built, is rewritten to
        ids. A dependency must name an earlier step: an unknown key, a key of a later step
        and a duplicate key are all Tenure.Plan.Invalid, so the plan is always in execution
        order. The input steps are copied; the objects you pass are not modified.

        Inputs records the request parameters, and the steps hold the before and after
        state; neither may contain a SecureString or a PSCredential anywhere (Tenure.Plan.Invalid).
        CreatedBy comes from the current Tenure connection, or reads "(not connected)" when
        there is none; a plan built while not connected names no tenant and cannot be applied.
        PolicyHash is the hash of the policy the plan was built from, so a later
        policy edit is detectable, and PolicySnapshot records that policy's protected users and
        managed set, which Invoke-TenurePlan and Test-TenurePlan use when no -Policy is given.
        A plan built without -Policy records neither and cannot be applied or tested: build
        every plan you mean to apply with -Policy. While connected to Graph, each
        protectedUsers entry of the policy is looked up, and one that matches no user (by
        object id, user principal name or mail address) adds a warning that names it.

        Integrity seals the plan: a SHA-256 over everything it says and does except the
        statuses and results the apply engine writes. Import-TenurePlan, Test-TenurePlan and
        Invoke-TenurePlan recompute it and refuse a plan that was edited after it was built
        (Tenure.Plan.Tampered).
    .PARAMETER Operation
        Onboard, RoleChange, Offboard or Custom.
    .PARAMETER Subject
        Hashtable with Id (may be $null before an onboarded user exists), UserPrincipalName
        and DisplayName.
    .PARAMETER Step
        Tenure.Step objects from New-TenureStep, in execution order. May be empty.
    .PARAMETER Policy
        The Tenure.Policy (or a path to a policy file) the plan was built from.
    .PARAMETER Inputs
        The request parameters, for the record. No secrets. $null is an empty table.
    .PARAMETER Warning
        Warnings to show with the plan.
    .EXAMPLE
        $disable = New-TenureStep -Provider 'User.SignIn' -Target $target -Desired @{ accountEnabled = $false } -Key 'disable'
        $revoke = New-TenureStep -Provider 'User.Sessions' -Target $target -Key 'revoke' -DependsOn 'disable'
        New-TenurePlan -Operation Custom -Subject @{ Id = $user.Id; UserPrincipalName = $user.UserPrincipalName; DisplayName = $user.DisplayName } -Step $disable, $revoke

        Builds a two-step plan in which S02 depends on S01.
    .OUTPUTS
        Tenure.Plan
        Errors: Tenure.Plan.Invalid, Tenure.Policy.Invalid.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Plan')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object; changes no state.')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Onboard', 'RoleChange', 'Offboard', 'Custom')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [hashtable]$Subject,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Step,

        [AllowNull()]
        [object]$Policy,

        [hashtable]$Inputs = @{},

        [string[]]$Warning = @()
    )

    $fail = { param($message) throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message $message -Category InvalidArgument) }
    # -Inputs $null seals as an empty table, the value Import-TenurePlan reads back for a missing Inputs.
    if ($null -eq $Inputs) { $Inputs = @{} }

    foreach ($field in 'Id', 'UserPrincipalName', 'DisplayName') {
        if (-not $Subject.ContainsKey($field)) { & $fail "Subject must have an '$field' entry (Id may be `$null)." }
    }
    if ($null -ne $Subject['Id'] -and $Subject['Id'] -isnot [string]) { & $fail 'Subject.Id must be a string or $null.' }
    foreach ($field in 'UserPrincipalName', 'DisplayName') {
        if ($Subject[$field] -isnot [string] -or [string]::IsNullOrWhiteSpace($Subject[$field])) { & $fail "Subject.$field must be a non-empty string." }
    }

    try {
        $null = Get-TenureCanonicalJson -InputObject $Inputs
    } catch {
        if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Json.SecretRejected') {
            & $fail 'Inputs may not contain secrets (found a SecureString or PSCredential). Secrets are returned on the apply result only.'
        }
        throw
    }

    $policyHash = $null
    $policySnapshot = $null
    $planWarnings = [System.Collections.Generic.List[string]]::new()
    foreach ($text in @($Warning | Where-Object { $null -ne $_ })) { $planWarnings.Add([string]$text) }
    if ($PSBoundParameters.ContainsKey('Policy') -and $null -ne $Policy) {
        $policyObject = Resolve-TenurePolicyArgument -Policy $Policy
        $policyHash = $policyObject.Hash
        $policySnapshot = ConvertTo-TenurePolicySnapshot -Policy $policyObject
        # A protectedUsers entry with a typo protects no one, silently. Each entry is looked up now, while the plan
        # is built (connected to Graph), and one that matches no user is a plan warning that names it.
        if ($null -ne $script:Session -and $script:Session.PSObject.Properties['Graph'] -and [bool]$script:Session.Graph) {
            foreach ($entry in @($policySnapshot.ProtectedUsers)) {
                try {
                    if (-not (Test-TenureProtectedEntry -Entry $entry)) {
                        $planWarnings.Add("The policy's protectedUsers entry '$entry' matches no user in this tenant, so it protects no one. Check the policy.")
                    }
                } catch {
                    $why = Get-TenureErrorId -ErrorRecord $_
                    if (-not $why) { $why = $_.Exception.GetType().Name }
                    $planWarnings.Add("The policy's protectedUsers entry '$entry' could not be looked up ($why), so it is not known whether it matches a user.")
                }
            }
        }
    }

    # Pass 1: validate steps and keys; remember each key's position.
    $positionByKey = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    for ($i = 0; $i -lt $Step.Count; $i++) {
        $candidate = $Step[$i]
        if ($null -eq $candidate -or $candidate.PSObject.TypeNames -notcontains 'Tenure.Step') {
            & $fail ("-Step[$i] is not a Tenure.Step. Build steps with New-TenureStep.")
        }
        $key = Get-TenureProperty -InputObject $candidate -Name 'Key'
        if ($key -isnot [string] -or [string]::IsNullOrWhiteSpace($key)) { & $fail ("-Step[$i] has no Key. Build steps with New-TenureStep.") }
        try {
            $null = Get-TenureCanonicalJson -InputObject $candidate
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Json.SecretRejected') {
                & $fail ("Steps may not contain secrets: step '$key' (-Step[$i]) holds a SecureString or PSCredential. Secrets are returned on the apply result only.")
            }
            throw
        }
        if ($positionByKey.ContainsKey($key)) { & $fail ("Step key '$key' is used by more than one step (-Step[{0}] and -Step[$i]); keys must be unique." -f $positionByKey[$key]) }
        $positionByKey[$key] = $i
    }

    # Pass 2: assign ids, rewrite DependsOn from keys to ids, copy.
    $steps = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Step.Count; $i++) {
        $source = $Step[$i]
        $key = $source.Key
        $ids = [System.Collections.Generic.List[string]]::new()
        foreach ($dependency in @(Get-TenureProperty -InputObject $source -Name 'DependsOn')) {
            if ($null -eq $dependency) { continue }
            if (-not $positionByKey.ContainsKey([string]$dependency)) {
                & $fail ("Step '$key' depends on '$dependency', which is not the key of any step in this plan.")
            }
            $dependencyPosition = $positionByKey[[string]$dependency]
            if ($dependencyPosition -ge $i) {
                & $fail ("Step '$key' depends on '$dependency', which is not an earlier step. Steps run in the order given, so a dependency must come before the step that needs it.")
            }
            $dependencyId = 'S{0:D2}' -f ($dependencyPosition + 1)
            if (-not $ids.Contains($dependencyId)) { $ids.Add($dependencyId) }
        }
        $status = Get-TenureProperty -InputObject $source -Name 'Status'
        $steps.Add((ConvertTo-TenureStep -Field @{
                    Id          = 'S{0:D2}' -f ($i + 1)
                    Key         = $key
                    Provider    = Get-TenureProperty -InputObject $source -Name 'Provider'
                    Kind        = Get-TenureProperty -InputObject $source -Name 'Kind'
                    Target      = Copy-TenureValue -InputObject (Get-TenureProperty -InputObject $source -Name 'Target')
                    Action      = Get-TenureProperty -InputObject $source -Name 'Action'
                    Before      = Copy-TenureValue -InputObject (Get-TenureProperty -InputObject $source -Name 'Before')
                    After       = Copy-TenureValue -InputObject (Get-TenureProperty -InputObject $source -Name 'After')
                    Fingerprint = Get-TenureProperty -InputObject $source -Name 'Fingerprint'
                    Risk        = Get-TenureProperty -InputObject $source -Name 'Risk'
                    Reversible  = Get-TenureProperty -InputObject $source -Name 'Reversible'
                    Reason      = Get-TenureProperty -InputObject $source -Name 'Reason'
                    DependsOn   = $ids.ToArray()
                    Status      = if ($null -ne $status) { $status } else { 'Pending' }
                    Result      = Copy-TenureValue -InputObject (Get-TenureProperty -InputObject $source -Name 'Result')
                }))
    }

    $session = $script:Session
    $createdBy = if ($null -ne $session) {
        @{
            Account  = Get-TenureProperty -InputObject $session -Name 'Account'
            TenantId = Get-TenureProperty -InputObject $session -Name 'TenantId'
            AuthType = Get-TenureProperty -InputObject $session -Name 'AuthType'
        }
    } else {
        @{ Account = '(not connected)'; TenantId = $null; AuthType = $null }
    }

    $plan = [pscustomobject]@{
        PSTypeName     = 'Tenure.Plan'
        SchemaVersion  = $script:PlanSchemaVersion
        PlanId         = [guid]::NewGuid().ToString()
        CreatedAt      = [datetime]::UtcNow
        CreatedBy      = $createdBy
        ModuleVersion  = [string]$script:ModuleVersion
        Operation      = $Operation
        Subject        = @{ Id = $Subject['Id']; UserPrincipalName = $Subject['UserPrincipalName']; DisplayName = $Subject['DisplayName'] }
        PolicyHash     = $policyHash
        PolicySnapshot = $policySnapshot
        Inputs         = Copy-TenureValue -InputObject $Inputs
        Steps          = $steps.ToArray()
        Warnings       = [string[]]$planWarnings.ToArray()
        Status         = 'Planned'
        Integrity      = $null
    }
    # Sealed last: from here on, any edit to what the plan does shows up as Tenure.Plan.Tampered.
    $plan.Integrity = Get-TenurePlanIntegrity -Plan $plan
    $plan
}
