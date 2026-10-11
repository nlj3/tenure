# Apply engine (docs/SPEC.md section 5.4, ADR-0002). Invoke-TenurePlanCore runs a plan
# step by step; Test-TenurePlanCore compares a plan with live state without writing.
#
# The engine never knows what a provider does. It reads state through Get, compares
# with Test, writes through Set, and records every outcome in the plan and the audit
# log. The guards below exist so that a plan file cannot lower its own safety:
# the plan's Integrity value must match its content (Tenure.Plan.Tampered), the
# provider's Kind, Severity, TargetKind and Actions are authoritative (a step labelled
# otherwise is refused), the effective Risk is the higher of the step's and the
# provider's, every step carries a fingerprint (a step with no snapshot must be a
# Create, whose target must be absent, or act on the new subject), a Severity Refuse
# check fails closed, the plan must record the policy it was built from (or match the
# -Policy given) and name the connected tenant, and no step may change the signed-in
# account or a protected user, whatever steps the plan has.
#
# Crash safety. Before Set runs, the step is marked Result.Attempted (and the plan file
# is rewritten when one is configured); for Invoke, Create and Destructive steps an
# Attempting entry is also written to the audit log. On the next run the audit log
# decides whether an Invoke step already fired, may have fired, or did not. One that
# may have fired runs again under -Resume only when its provider is Repeatable;
# otherwise the run stops there until the operator names it in -AssumeFired.

$script:PlanStatuses = @('Planned', 'DryRun', 'Applied', 'PartiallyApplied', 'Failed')
$script:StepStatuses = @('Pending', 'Applied', 'Skipped', 'Failed', 'DryRun', 'Drifted', 'Refused', 'Declined')
$script:StepActions = @('Create', 'Update', 'Remove', 'Invoke', 'Check', 'NoOp')
$script:RiskOrder = @{ Low = 0; Medium = 1; High = 2; Destructive = 3 }
$script:PlaceholderTokenPattern = '^\{\{[A-Za-z0-9_]+\}\}$'
$script:SubjectIdPlaceholder = '{{subjectId}}'
$script:FutureSkew = [timespan]::FromMinutes(5)
$script:MinSecretLength = 6
$script:CreateReadBackDelays = @(2, 4, 8)
# A target a resumed Create finds may be adopted only if it was created no earlier than the step's Attempting
# entry, less this margin for the clock difference between this machine and the service.
$script:AdoptClockSkew = [timespan]::FromMinutes(5)
$script:LastApplyResult = $null

function Get-TenureApplyMember {
    <#
    .SYNOPSIS
        Reads a key from a dictionary or a property from an object; $null when absent.
        Safe under strict mode.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    $null
}

function ConvertTo-TenureTargetTable {
    <#
    .SYNOPSIS
        Copies a step Target (dictionary or object) into a new hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Target)

    $table = @{}
    if ($null -eq $Target) { return $table }
    if ($Target -is [System.Collections.IDictionary]) {
        foreach ($key in $Target.Keys) { $table[[string]$key] = $Target[$key] }
        return $table
    }
    foreach ($property in $Target.PSObject.Properties) { $table[$property.Name] = $property.Value }
    $table
}

function Test-TenureSubjectPlaceholder {
    <#
    .SYNOPSIS
        True when a value is exactly the {{subjectId}} placeholder (trimmed, any case).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][object]$Value)

    ($Value -is [string]) -and [string]::Equals($Value.Trim(), $script:SubjectIdPlaceholder, [System.StringComparison]::OrdinalIgnoreCase)
}

function Resolve-TenurePlaceholderValue {
    <#
    .SYNOPSIS
        Returns a copy of a value with every string leaf that is exactly {{subjectId}}
        (trimmed, any case) replaced by the subject id, and whether any placeholder token
        is left unresolved.
    .DESCRIPTION
        Only whole values are placeholders: a string that merely contains the text is left
        alone. Dictionaries, objects and arrays on the way to a replaced value are copied,
        never changed in place. A leaf that is any other {{name}} token, or {{subjectId}}
        while the subject has no id, is reported as unresolved.
        Returns @{ Value; Changed; Unresolved } (a hashtable, so arrays are not unrolled).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()][object]$Value,
        [AllowNull()][object]$SubjectId,
        [int]$Depth = 0
    )

    if ($Depth -gt 64) {
        throw (New-TenureError -Id 'Tenure.Json.TooDeep' -Message 'Object nesting exceeds 64 levels.')
    }
    $known = ($SubjectId -is [string] -and $SubjectId.Length -gt 0)
    if ($null -eq $Value) { return @{ Value = $null; Changed = $false; Unresolved = $false } }
    if ($Value -is [string]) {
        if (Test-TenureSubjectPlaceholder -Value $Value) {
            if ($known) { return @{ Value = $SubjectId; Changed = $true; Unresolved = $false } }
            return @{ Value = $Value; Changed = $false; Unresolved = $true }
        }
        return @{ Value = $Value; Changed = $false; Unresolved = ($Value.Trim() -cmatch $script:PlaceholderTokenPattern) }
    }
    if ($Value -is [System.ValueType] -or $Value -is [securestring]) { return @{ Value = $Value; Changed = $false; Unresolved = $false } }

    $changed = $false
    $unresolved = $false
    if ($Value -is [System.Collections.IDictionary]) {
        # A hashtable clone keeps its key comparer; other dictionaries become ordered ones.
        $copy = if ($Value -is [hashtable]) { $Value.Clone() } else { [ordered]@{} }
        foreach ($key in @($Value.Keys)) {
            $inner = Resolve-TenurePlaceholderValue -Value $Value[$key] -SubjectId $SubjectId -Depth ($Depth + 1)
            $copy[$key] = $inner.Value
            if ($inner.Changed) { $changed = $true }
            if ($inner.Unresolved) { $unresolved = $true }
        }
        if ($changed) { return @{ Value = $copy; Changed = $true; Unresolved = $unresolved } }
        return @{ Value = $Value; Changed = $false; Unresolved = $unresolved }
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $inner = Resolve-TenurePlaceholderValue -Value $item -SubjectId $SubjectId -Depth ($Depth + 1)
            $items.Add($inner.Value)
            if ($inner.Changed) { $changed = $true }
            if ($inner.Unresolved) { $unresolved = $true }
        }
        if ($changed) { return @{ Value = $items.ToArray(); Changed = $true; Unresolved = $unresolved } }
        return @{ Value = $Value; Changed = $false; Unresolved = $unresolved }
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $inner = Resolve-TenurePlaceholderValue -Value $property.Value -SubjectId $SubjectId -Depth ($Depth + 1)
            $ordered[$property.Name] = $inner.Value
            if ($inner.Changed) { $changed = $true }
            if ($inner.Unresolved) { $unresolved = $true }
        }
        if ($changed) { return @{ Value = [pscustomobject]$ordered; Changed = $true; Unresolved = $unresolved } }
        return @{ Value = $Value; Changed = $false; Unresolved = $unresolved }
    }
    @{ Value = $Value; Changed = $false; Unresolved = $false }
}

function Resolve-TenureStepPlaceholder {
    <#
    .SYNOPSIS
        Resolves {{subjectId}} in a step's Target and After (fresh copies) and reports
        whether any placeholder is still unresolved.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object]$Step,
        [AllowNull()][object]$SubjectId
    )

    $target = Resolve-TenurePlaceholderValue -Value (ConvertTo-TenureTargetTable -Target $Step.Target) -SubjectId $SubjectId
    $after = Resolve-TenurePlaceholderValue -Value $Step.After -SubjectId $SubjectId
    @{
        Target        = $target.Value
        TargetChanged = $target.Changed
        After         = $after.Value
        AfterChanged  = $after.Changed
        Unresolved    = ($target.Unresolved -or $after.Unresolved)
    }
}

function Test-TenureStepDrift {
    <#
    .SYNOPSIS
        True when a step's live state no longer matches what its fingerprint bound at plan time.
    .DESCRIPTION
        -Target is the step's target with {{subjectId}} resolved; -Current is what Get returned
        ($null for a Create whose target was not found). Three cases:
        - The plan was built before its subject existed and the step's Target.Id is the
          placeholder with no snapshot: only the binding is checked (the stored fingerprint must
          be the placeholder target's, with Before null). There was no state to compare with.
        - The snapshot itself names the subject by the placeholder (a membership taken before the
          user existed, "not a member"): the snapshot must still match the fingerprint, and the
          live state is compared with the snapshot after the placeholder is filled in.
        - Otherwise the live state, hashed with the target, must equal the fingerprint. For a Create
          step that means the target is still absent.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][hashtable]$Target,
        [AllowNull()][object]$Current,
        [AllowNull()][object]$SubjectId
    )

    $stored = [string]$Step.Fingerprint
    $planned = ConvertTo-TenureTargetTable -Target $Step.Target
    $before = $Step.Before
    if ($null -eq $before -and (Test-TenureSubjectPlaceholder -Value (Get-TenureApplyMember -InputObject $planned -Name 'Id'))) {
        return ((Get-TenureStepFingerprint -Target $planned -Before $null) -cne $stored)
    }
    if ($null -ne $before -and (Resolve-TenurePlaceholderValue -Value $before -SubjectId $null).Unresolved) {
        if ((Get-TenureStepFingerprint -Target $planned -Before $before) -cne $stored) { return $true }
        $filled = Resolve-TenurePlaceholderValue -Value $before -SubjectId $SubjectId
        if ($filled.Unresolved) { return $true }
        return ((Get-TenureStepFingerprint -Target $Target -Before $filled.Value) -cne (Get-TenureStepFingerprint -Target $Target -Before $Current))
    }
    ((Get-TenureStepFingerprint -Target $Target -Before $Current) -cne $stored)
}

function Get-TenureStepReadContext {
    <#
    .SYNOPSIS
        The context a step's provider reads with: for a membership step, Subject.Id is the user the step acts on.
    .DESCRIPTION
        Group and role providers (TargetKind group or role) read the membership of Context.Subject.Id,
        because Get has no Desired. A step's own user is After.userId, which is the subject in a
        builder's plan but may be anyone in a Custom plan. So for those providers, when After.userId
        is a non-empty string, the returned context is a copy whose Subject is a copy of the plan
        subject with Id set to that user. Every other step reads with the context as given. Used for
        the snapshot (New-TenureStep), the read before Set, the read back after Set, and Test-TenurePlan.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object]$Provider,
        [Parameter(Mandatory)][hashtable]$Context,
        [AllowNull()][object]$After
    )

    if ([string]$Provider.TargetKind -cnotin 'group', 'role') { return $Context }
    $userId = Get-TenureApplyMember -InputObject $After -Name 'userId'
    if ($userId -isnot [string] -or [string]::IsNullOrWhiteSpace($userId)) { return $Context }
    $subject = @{}
    $current = if ($Context.ContainsKey('Subject')) { $Context['Subject'] } else { $null }
    if ($current -is [System.Collections.IDictionary]) {
        foreach ($key in @($current.Keys)) { $subject[[string]$key] = $current[$key] }
    } elseif ($null -ne $current) {
        foreach ($property in $current.PSObject.Properties) { $subject[$property.Name] = $property.Value }
    }
    $subject['Id'] = $userId
    $copy = $Context.Clone()
    $copy['Subject'] = $subject
    $copy
}

function Get-TenureEngineDescription {
    <#
    .SYNOPSIS
        The provider's own one-line description of what a step will do now, for prompts.
    .DESCRIPTION
        Calls the registered provider's Describe with the resolved target, the live state and
        the desired state, so a confirmation never rests on the Reason text a plan file carries.
        A Describe that fails gives "<Action> <Provider>".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Provider,
        [Parameter(Mandatory)][hashtable]$Target,
        [AllowNull()][object]$Current,
        [AllowNull()][object]$After,
        [Parameter(Mandatory)][string]$Action,
        [AllowNull()][hashtable]$Secrets
    )

    $text = $null
    try {
        $text = [string](Invoke-TenureProviderBlock -Block $Provider.Describe -ArgumentList @($Target, $Current, $After, $Action))
    } catch {
        $text = $null
    }
    if ([string]::IsNullOrWhiteSpace($text)) { $text = "$Action $($Provider.Name)" }
    Hide-TenureSecretText -Text $text -Secrets $Secrets
}

function Get-TenurePlanProtectedUser {
    <#
    .SYNOPSIS
        The protectedUsers list a run checks: the -Policy given, or the list the plan recorded when it was built.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [AllowNull()][object]$Policy
    )

    $list = if ($null -ne $Policy) {
        @(Get-TenureApplyMember -InputObject (Get-TenureApplyMember -InputObject $Policy -Name 'Defaults') -Name 'protectedUsers')
    } else {
        @(Get-TenureApplyMember -InputObject (Get-TenureApplyMember -InputObject $Plan -Name 'PolicySnapshot') -Name 'ProtectedUsers')
    }
    [string[]]@($list | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
}

function Assert-TenurePlanPolicy {
    <#
    .SYNOPSIS
        Refuses a plan whose policy facts cannot be trusted for this run (Tenure.Plan.PolicyMissing, Tenure.Plan.PolicyMismatch).
    .DESCRIPTION
        Without -Policy the run checks the protected users the plan recorded, so a plan that
        records no PolicyHash or no PolicySnapshot is refused (PolicyMissing): there would be
        nothing to check against. With -Policy, the policy must carry a Hash and it must equal
        the plan's PolicyHash; anything else is PolicyMismatch, including a plan that records
        no policy and a -Policy object without a Hash, which would otherwise silently replace
        the recorded list.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [AllowNull()][object]$Policy
    )

    $planHash = [string](Get-TenureApplyMember -InputObject $Plan -Name 'PolicyHash')
    $snapshot = Get-TenureApplyMember -InputObject $Plan -Name 'PolicySnapshot'
    if ($null -eq $Policy) {
        if ($planHash.Length -eq 0 -or $null -eq $snapshot) {
            throw (New-TenureError -Id 'Tenure.Plan.PolicyMissing' -Message "Plan $($Plan.PlanId) records no policy (its PolicyHash or PolicySnapshot is missing), so there is no list of protected users to check it against. Pass the policy it was built from with -Policy, or build the plan again with -Policy." -Category InvalidOperation -Data @{ PlanId = $Plan.PlanId })
        }
        return
    }
    $givenHash = [string](Get-TenureApplyMember -InputObject $Policy -Name 'Hash')
    if ($givenHash.Length -eq 0) {
        throw (New-TenureError -Id 'Tenure.Plan.PolicyMismatch' -Message "The -Policy given has no Hash, so it cannot be matched to plan $($Plan.PlanId). Pass a policy file path or an object from Get-TenurePolicy." -Category InvalidArgument -Data @{ PlanId = $Plan.PlanId })
    }
    if ($planHash.Length -eq 0) {
        throw (New-TenureError -Id 'Tenure.Plan.PolicyMismatch' -Message "Plan $($Plan.PlanId) was built without a policy, so the -Policy given cannot be matched to it. Build the plan again with -Policy." -Category InvalidOperation -Data @{ PlanId = $Plan.PlanId })
    }
    if ($givenHash -cne $planHash) {
        throw (New-TenureError -Id 'Tenure.Plan.PolicyMismatch' -Message "Plan $($Plan.PlanId) was built from a different policy (plan PolicyHash differs from the -Policy given). Re-plan with this policy or omit -Policy." -Category InvalidOperation -Data @{ PlanId = $Plan.PlanId })
    }
}

function Assert-TenurePlanTenant {
    <#
    .SYNOPSIS
        Throws Tenure.Plan.WrongTenant when the plan was built in a different tenant from the one connected now.
    .DESCRIPTION
        A plan needs a session that names the tenant the plan names. A plan that names no tenant
        (built while not connected, or with CreatedBy.TenantId blanked) cannot be shown to belong
        to this tenant and is refused too.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param([Parameter(Mandatory)][object]$Plan)

    $planTenant = ([string](Get-TenureApplyMember -InputObject (Get-TenureApplyMember -InputObject $Plan -Name 'CreatedBy') -Name 'TenantId')).Trim()
    if ($planTenant.Length -eq 0) {
        throw (New-TenureError -Id 'Tenure.Plan.WrongTenant' -Message "Plan $($Plan.PlanId) names no tenant (CreatedBy.TenantId is blank), so it cannot be shown to belong to the tenant this session is connected to. Build the plan again while connected." -Category InvalidOperation -Data @{ PlanTenantId = ''; SessionTenantId = $(if ($null -ne $script:Session -and $script:Session.PSObject.Properties['TenantId']) { [string]$script:Session.TenantId } else { '' }) })
    }
    $sessionTenant = ''
    if ($null -ne $script:Session -and $script:Session.PSObject.Properties['TenantId']) { $sessionTenant = ([string]$script:Session.TenantId).Trim() }
    $left = [guid]::Empty
    $right = [guid]::Empty
    $same = if ([guid]::TryParse($planTenant, [ref]$left) -and [guid]::TryParse($sessionTenant, [ref]$right)) { $left -eq $right } else { [string]::Equals($planTenant, $sessionTenant, [System.StringComparison]::OrdinalIgnoreCase) }
    if (-not $same) {
        $shown = if ($sessionTenant) { $sessionTenant } else { 'an unknown tenant' }
        throw (New-TenureError -Id 'Tenure.Plan.WrongTenant' -Message "Plan $($Plan.PlanId) was built in tenant $planTenant, but this session is connected to $shown. Connect to the tenant the plan was built in, or build the plan again here." -Category InvalidOperation -Data @{ PlanTenantId = $planTenant; SessionTenantId = $sessionTenant })
    }
}

function Assert-TenurePlanProtection {
    <#
    .SYNOPSIS
        Refuses a plan, before any step runs, when it would change the signed-in account or a protected user.
    .DESCRIPTION
        Runs for every plan, whatever its steps (Custom plans included): it does not depend on a
        Check.SubjectAllowed step being present. The accounts a plan changes are its subject and,
        for every step that is not a Check, the user named by Target.Id when the step's provider
        acts on a user, mailbox or drive (its TargetKind, never the plan's Target.Kind label), and
        the user named by After.userId (a group or role membership; without one, the subject).
        {{subjectId}} stands for the subject. Each account is read once from Graph for its object
        id, user principal name and mail address; one that does not exist yet (an onboarding) is
        compared by the name the plan gives it. A match with the signed-in account or with a
        protectedUsers entry (-ProtectedUsers) throws Tenure.Plan.Refused naming the step.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][hashtable]$Providers,
        [AllowNull()][AllowEmptyCollection()][string[]]$ProtectedUsers
    )

    $subject = $Plan.Subject
    $subjectId = [string](Get-TenureApplyMember -InputObject $subject -Name 'Id')
    $subjectUpn = [string](Get-TenureApplyMember -InputObject $subject -Name 'UserPrincipalName')
    $subjectRef = if ($subjectId.Trim().Length -gt 0) { $subjectId.Trim() } else { $subjectUpn.Trim() }

    # Every account the plan changes, with the first step that changes it.
    $references = [ordered]@{}
    $add = {
        param([string]$value, [string]$where)
        if ([string]::IsNullOrWhiteSpace($value)) { return }
        $key = $value.Trim().ToLowerInvariant()
        if (-not $references.Contains($key)) { $references[$key] = @{ Value = $value.Trim(); Where = $where } }
    }
    & $add $subjectRef 'the plan subject'
    foreach ($step in @($Plan.Steps)) {
        $provider = $Providers[[string]$step.Provider]
        if ($null -ne $provider -and $provider.Kind -ceq 'Check') { continue }
        $where = "step $($step.Id) ($($step.Provider))"
        $target = ConvertTo-TenureTargetTable -Target $step.Target
        # An unregistered provider never reaches this check (the caller looks every provider up first); the label is
        # only the fallback for that case. A provider whose TargetKind is a user, mailbox or drive changes Target.Id.
        $actsOn = if ($null -ne $provider) { [string]$provider.TargetKind } else { [string](Get-TenureApplyMember -InputObject $target -Name 'Kind') }
        if ($actsOn -cin 'user', 'mailbox', 'drive') {
            $value = Get-TenureApplyMember -InputObject $target -Name 'Id'
            if (Test-TenureSubjectPlaceholder -Value $value) { $value = $subjectRef }
            if ($value -is [string]) { & $add $value $where }
        }
        $userId = Get-TenureApplyMember -InputObject $step.After -Name 'userId'
        if (Test-TenureSubjectPlaceholder -Value $userId) { $userId = $subjectRef }
        if ($userId -is [string]) { & $add $userId $where }
    }

    $account = ''
    if ($null -ne $script:Session -and $script:Session.PSObject.Properties['Account']) { $account = ([string]$script:Session.Account).Trim() }
    foreach ($key in $references.Keys) {
        $reference = $references[$key]
        $names = [System.Collections.Generic.List[string]]::new()
        $names.Add($reference.Value)
        if ([string]::Equals($reference.Value, $subjectRef, [System.StringComparison]::OrdinalIgnoreCase)) {
            foreach ($name in $subjectId, $subjectUpn) { if (-not [string]::IsNullOrWhiteSpace($name)) { $names.Add($name.Trim()) } }
        }
        $found = Get-TenureUserIdentity -Identity $reference.Value
        if ($null -ne $found) {
            foreach ($name in $found.Id, $found.UserPrincipalName, $found.Mail) { if (-not [string]::IsNullOrWhiteSpace([string]$name)) { $names.Add(([string]$name).Trim()) } }
        }
        $why = $null
        if ($account.Length -gt 0) {
            foreach ($name in $names) {
                if ([string]::Equals($name, $account, [System.StringComparison]::OrdinalIgnoreCase)) { $why = 'the signed-in account'; break }
            }
        }
        if (-not $why) {
            $entry = Find-TenureProtectedUser -Protected @($ProtectedUsers) -Identity $names.ToArray()
            if ($entry) { $why = "protected by policy (protectedUsers entry '$entry')" }
        }
        if ($why) {
            throw (New-TenureError -Id 'Tenure.Plan.Refused' -Message "Refusing to apply plan $($Plan.PlanId): $($reference.Where) changes $($reference.Value), which is $why. Nothing was changed." -Category InvalidOperation -Data @{ PlanId = $Plan.PlanId; Account = $reference.Value; Where = $reference.Where })
        }
    }
}

function Assert-TenureSubjectIdOrigin {
    <#
    .SYNOPSIS
        For a plan sealed without a subject id, checks that the id it carries now is one this plan's own create step produced.
    .DESCRIPTION
        The apply engine fills Subject.Id in after a create step. The integrity value cannot cover
        that id, so the audit log must: an Applied or Skipped entry of one of this plan's Create
        steps whose observed id is Subject.Id. Anything else is Tenure.Plan.Tampered.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [AllowNull()][hashtable]$History
    )

    $subjectId = [string](Get-TenureApplyMember -InputObject $Plan.Subject -Name 'Id')
    if ($null -ne $History) {
        foreach ($step in @($Plan.Steps)) {
            if ($step.Action -cne 'Create' -or -not $History.CreatedIds.ContainsKey([string]$step.Id)) { continue }
            if ([string]::Equals([string]$History.CreatedIds[[string]$step.Id], $subjectId, [System.StringComparison]::OrdinalIgnoreCase)) { return }
        }
    }
    throw (New-TenureError -Id 'Tenure.Plan.Tampered' -Message "Plan $($Plan.PlanId) was built without a subject id and now carries '$subjectId', but the audit log does not show one of this plan's create steps producing that id. Build the plan again, or run it with the audit log of its earlier runs (-AuditPath)." -Category SecurityError -Data @{ PlanId = $Plan.PlanId; SubjectId = $subjectId })
}

function Find-TenureCreatorStep {
    <#
    .SYNOPSIS
        For a Check step, the id of a later Create step of the same plan on the same target that the audit log shows was attempted, or $null.
    .DESCRIPTION
        A check that the target does not exist (Check.UserAbsent) is made false by the plan's own
        create step. On resume, that is not a reason to stop: the audit log, not the plan file,
        has to show that this plan's create step ran, in an attempt that did not end in a
        recorded failure.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Step,
        [AllowNull()][hashtable]$History
    )

    if ($null -eq $History) { return $null }
    $target = ConvertTo-TenureTargetTable -Target $Step.Target
    $kind = [string](Get-TenureApplyMember -InputObject $target -Name 'Kind')
    $id = [string](Get-TenureApplyMember -InputObject $target -Name 'Id')
    $after = $false
    foreach ($candidate in @($Plan.Steps)) {
        if ([object]::ReferenceEquals($candidate, $Step) -or $candidate.Id -ceq $Step.Id) { $after = $true; continue }
        if (-not $after -or $candidate.Action -cne 'Create') { continue }
        $other = ConvertTo-TenureTargetTable -Target $candidate.Target
        if ([string](Get-TenureApplyMember -InputObject $other -Name 'Kind') -cne $kind) { continue }
        if (-not [string]::Equals([string](Get-TenureApplyMember -InputObject $other -Name 'Id'), $id, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($History.Attempts.ContainsKey([string]$candidate.Id) -and @($History.Attempts[[string]$candidate.Id] | Where-Object { -not $_.Failed }).Count -gt 0) { return [string]$candidate.Id }
    }
    $null
}

function Find-TenureAdoptionWindow {
    <#
    .SYNOPSIS
        The attempt of a Create step during which a found target was created, or $null.
    .DESCRIPTION
        -Attempts is History.Attempts for the step (@{ At; End; Failed } per Attempting entry).
        An attempt qualifies when it did not end in a recorded failure and CreatedAt lies between
        its Attempting entry and its end, each widened by the clock margin $script:AdoptClockSkew.
        The end is the next entry for the step, or the run's PlanFinished, or a later PlanStarted,
        but never later than the Attempting entry plus the longest a Graph call can take
        (Get-TenureGraphLongestCall): a request cannot land after that, so an account created
        later is someone else's even when the run died without a later entry. A target that does
        not report when it was created never qualifies.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()][object]$Attempts,
        [AllowNull()][Nullable[datetime]]$CreatedAt
    )

    if ($null -eq $CreatedAt) { return $null }
    foreach ($attempt in @($Attempts | Where-Object { $null -ne $_ })) {
        if ($attempt.Failed) { continue }
        $from = ConvertFrom-TenureTimestamp -Value $attempt.At
        if ($null -eq $from -or $CreatedAt -lt ($from - $script:AdoptClockSkew)) { continue }
        $latest = $from + (Get-TenureGraphLongestCall)
        $until = ConvertFrom-TenureTimestamp -Value $attempt.End
        if ($null -eq $until -or $until -gt $latest) { $until = $latest }
        if ($CreatedAt -gt ($until + $script:AdoptClockSkew)) { continue }
        return $attempt
    }
    $null
}

function Find-TenureAffectingStep {
    <#
    .SYNOPSIS
        For a Check step, the id of a step of the same plan whose provider is in the check provider's AffectedBy and that changed state, or $null.
    .DESCRIPTION
        "Changed state" is the audit log's word for an earlier run (History.Changed: an Applied
        entry, or an attempt that did not end in a recorded failure) or this run's own Applied
        outcome. The plan file's statuses are not evidence.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][object]$Provider,
        [Parameter(Mandatory)][hashtable]$Run
    )

    $names = @($Provider.AffectedBy | Where-Object { $null -ne $_ })
    if ($names.Count -eq 0) { return $null }
    foreach ($candidate in @($Plan.Steps)) {
        $id = [string]$candidate.Id
        if ($id -ceq [string]$Step.Id -or $names -cnotcontains [string]$candidate.Provider) { continue }
        if ($null -ne $Run.History -and $Run.History.Changed.Contains($id)) { return $id }
        if ($Run.Outcomes.ContainsKey($id) -and $Run.Outcomes[$id] -ceq 'Applied') { return $id }
    }
    $null
}

function New-TenureStepContext {
    <#
    .SYNOPSIS
        The Context the engine hands a step's provider (SPEC section 2.2), with the plan subject.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds a hashtable; changes no state.')]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][hashtable]$Run
    )

    @{
        Policy         = $Run.Policy
        ProtectedUsers = $Run.ProtectedUsers
        Subject        = $Plan.Subject
        Session        = $script:Session
        Secrets        = $Run.Secrets
        StepId         = $Step.Id
        Mode           = $Run.Mode
    }
}

function Test-TenureDependencySatisfied {
    <#
    .SYNOPSIS
        True when a dependency step's desired state holds right now, read live through its provider (Get, then Test).
    .DESCRIPTION
        Used for a dependency this run did not apply or skip. An Invoke step never holds (its Test
        is always false), and neither does a Create (an object that matches it now is not proof
        that this plan created it); a step that still holds a placeholder, or whose read fails,
        does not hold either.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][hashtable]$Run
    )

    $provider = $Run.Providers[[string]$Step.Provider]
    if ($null -eq $provider -or $provider.Kind -ceq 'Invoke' -or $Step.Action -ceq 'Create') { return $false }
    $resolved = Resolve-TenureStepPlaceholder -Step $Step -SubjectId (Get-TenureApplyMember -InputObject $Plan.Subject -Name 'Id')
    if ($resolved.Unresolved) { return $false }
    $context = Get-TenureStepReadContext -Provider $provider -Context (New-TenureStepContext -Plan $Plan -Step $Step -Run $Run) -After $resolved.After
    try {
        $current = Invoke-TenureProviderBlock -Block $provider.Get -ArgumentList @($resolved.Target, $context)
        return [bool](Invoke-TenureProviderTest -Provider $provider -Current $current -Desired $resolved.After)
    } catch {
        Write-Verbose (Hide-TenureSecretText -Text "[$($Step.Id)] the dependency's live state could not be read: $(Format-TenureErrorText -ErrorRecord $_)" -Secrets $Run.Secrets)
        return $false
    } finally {
        Protect-TenureSecretTable -Secrets $Run.Secrets -Provider $provider.Name
    }
}

function Get-TenureTargetLabel {
    <#
    .SYNOPSIS
        "<Name> (<Id>)" for messages; never includes state.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][hashtable]$Target)

    $name = $null
    $id = $null
    if ($null -ne $Target) {
        if ($Target.ContainsKey('Name')) { $name = $Target['Name'] }
        if ($Target.ContainsKey('Id')) { $id = $Target['Id'] }
    }
    if ($name -and $id) { return "$name ($id)" }
    if ($name) { return [string]$name }
    if ($id) { return "($id)" }
    '(no target id)'
}

function Format-TenureErrorText {
    <#
    .SYNOPSIS
        Formats an ErrorRecord as 'id: message' for Result.Error and the audit log.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $id = Get-TenureErrorId -ErrorRecord $ErrorRecord
    if (-not $id) { $id = $ErrorRecord.Exception.GetType().FullName }
    "${id}: $($ErrorRecord.Exception.Message)"
}

function Invoke-TenureProviderBlock {
    <#
    .SYNOPSIS
        Invokes a provider scriptblock and returns its output. A non-terminating error
        written by the block is rethrown, so a half-failed Get or Set is never mistaken
        for success.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][scriptblock]$Block,
        [object[]]$ArgumentList = @()
    )

    $output = @(& $Block @ArgumentList 2>&1)
    $values = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $output) {
        if ($item -is [System.Management.Automation.ErrorRecord]) { throw $item }
        $values.Add($item)
    }
    if ($values.Count -eq 0) { return $null }
    if ($values.Count -eq 1) { return $values[0] }
    $values.ToArray()
}

function Invoke-TenureProviderTest {
    <#
    .SYNOPSIS
        Runs a provider Test. Anything other than a [bool] is a provider bug and throws
        Tenure.Provider.InvalidResult rather than being coerced.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$Provider,
        [AllowNull()][object]$Current,
        [AllowNull()][object]$Desired
    )

    $result = Invoke-TenureProviderBlock -Block $Provider.Test -ArgumentList @($Current, $Desired)
    if (-not ($result -is [bool])) {
        $type = if ($null -eq $result) { 'null' } else { $result.GetType().Name }
        throw (New-TenureError -Id 'Tenure.Provider.InvalidResult' -Message "Provider '$($Provider.Name)' Test returned $type; expected [bool]." -Category InvalidResult)
    }
    $result
}

function Get-TenureSecretPlainText {
    <#
    .SYNOPSIS
        Decodes the SecureString values of the run's secret table so outputs can be
        checked for leaks. The strings are never stored or written anywhere.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][hashtable]$Secrets)

    if ($null -eq $Secrets -or $Secrets.Count -eq 0) { return @() }
    $plain = [System.Collections.Generic.List[string]]::new()
    foreach ($value in @($Secrets.Values)) {
        if ($value -is [securestring]) {
            $text = [System.Net.NetworkCredential]::new('', $value).Password
            if ($null -ne $text -and $text.Length -ge $script:MinSecretLength) { $plain.Add($text) }
        }
    }
    $plain.ToArray()
}

function Hide-TenureSecretText {
    <#
    .SYNOPSIS
        Replaces any generated secret value inside a string with '[redacted]'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$Text,
        [AllowNull()][hashtable]$Secrets
    )

    if ($null -eq $Text) { return $null }
    $value = [string]$Text
    foreach ($plain in (Get-TenureSecretPlainText -Secrets $Secrets)) {
        $value = $value.Replace($plain, '[redacted]')
    }
    $value
}

function Test-TenureStateSafe {
    <#
    .SYNOPSIS
        Checks that a state object can be stored in the plan and the audit log: it must
        serialize to canonical JSON (no SecureString or credential, not absurdly deep)
        and must not contain any secret generated during this run.
    .OUTPUTS
        @{ Safe = [bool]; Error = 'id: message' or $null }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()][object]$State,
        [AllowNull()][hashtable]$Secrets
    )

    if ($null -eq $State) { return @{ Safe = $true; Error = $null } }
    try {
        $json = Get-TenureCanonicalJson -InputObject $State
    } catch {
        return @{ Safe = $false; Error = (Format-TenureErrorText -ErrorRecord $_) }
    }
    foreach ($plain in (Get-TenureSecretPlainText -Secrets $Secrets)) {
        if ($json.Contains($plain) -or $json.Contains((ConvertTo-Json -InputObject $plain -Compress).Trim('"'))) {
            return @{ Safe = $false; Error = 'Tenure.Json.SecretRejected: the state object contains a secret generated during this run.' }
        }
    }
    @{ Safe = $true; Error = $null }
}

function Protect-TenureSecretTable {
    <#
    .SYNOPSIS
        Enforces that the run's secret table holds SecureString values only. A plain
        string is converted (the value is kept for the caller); anything else is
        removed. Both cases warn without echoing the value. Runs after every provider
        Get and Set.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][hashtable]$Secrets,
        [string]$Provider
    )

    if ($null -eq $Secrets) { return }
    foreach ($key in @($Secrets.Keys)) {
        $value = $Secrets[$key]
        if ($value -is [securestring]) { continue }
        if ($value -is [string]) {
            $secure = [securestring]::new()
            foreach ($character in $value.ToCharArray()) { $secure.AppendChar($character) }
            $secure.MakeReadOnly()
            $Secrets[$key] = $secure
            Write-Warning "Provider '$Provider' stored a plain string in Context.Secrets['$key']; it was converted to SecureString. Providers must store SecureString only."
            continue
        }
        [void]$Secrets.Remove($key)
        Write-Warning "Provider '$Provider' stored a non-SecureString value in Context.Secrets['$key']; it was removed. Providers must store SecureString only."
    }
}

function Clear-TenureSecretError {
    <#
    .SYNOPSIS
        Removes from the global $Error list every record whose text contains a secret
        generated during this run (best effort; a provider error may echo a value).
    #>
    [CmdletBinding()]
    param([AllowNull()][hashtable]$Secrets)

    $plain = @(Get-TenureSecretPlainText -Secrets $Secrets)
    if ($plain.Count -eq 0) { return }
    $list = Get-Variable -Name Error -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $list) { return }
    for ($index = $list.Count - 1; $index -ge 0; $index--) {
        $item = $list[$index]
        $text = [string]$item
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $text += "`n" + $item.Exception.ToString()
            if ($item.ErrorDetails) { $text += "`n" + $item.ErrorDetails.Message }
        } elseif ($item -is [System.Exception]) {
            $text += "`n" + $item.ToString()
        }
        foreach ($secret in $plain) {
            if ($text.Contains($secret)) {
                $list.RemoveAt($index)
                break
            }
        }
    }
}

function Get-TenurePlanStatus {
    <#
    .SYNOPSIS
        Derives Plan.Status from the step statuses (pure function).
    .DESCRIPTION
        Any Failed, Drifted or Refused step: PartiallyApplied when at least one step is
        Applied, else Failed. A Declined step counts as Pending (nothing was done). Otherwise:
        Applied steps mixed with Pending or DryRun steps
        are PartiallyApplied; any Pending step (and nothing Applied) is Planned; DryRun
        and Skipped only (at least one DryRun) is DryRun; Applied and Skipped only
        (including an empty plan) is Applied, except that a plan with a step the operator
        assumed fired (-AssumeFired, Result.Assumed) is never Applied: it stays
        PartiallyApplied, because nothing shows that step did its work.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][object]$Plan)

    $summary = Get-TenurePlanSummary -Plan $Plan
    $bad = $summary.Failed + $summary.Drifted + $summary.Refused
    if ($bad -gt 0) {
        if ($summary.Applied -gt 0) { return 'PartiallyApplied' }
        return 'Failed'
    }
    $assumed = $false
    foreach ($step in @(Get-TenureApplyMember -InputObject $Plan -Name 'Steps')) {
        if ((Get-TenureApplyMember -InputObject (Get-TenureApplyMember -InputObject $step -Name 'Result') -Name 'Assumed') -eq $true) { $assumed = $true; break }
    }
    $notDone = $summary.Pending + $summary.Declined
    if ($summary.Applied -gt 0) {
        if (($notDone + $summary.DryRun) -gt 0 -or $assumed) { return 'PartiallyApplied' }
        return 'Applied'
    }
    if ($notDone -gt 0) { return 'Planned' }
    if ($summary.DryRun -gt 0) { return 'DryRun' }
    if ($assumed) { return 'PartiallyApplied' }
    'Applied'
}

function Get-TenurePlanSummary {
    <#
    .SYNOPSIS
        Counts steps per status. The counts always sum to the number of steps; a status
        outside the known set counts as Failed.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)][object]$Plan)

    $summary = [ordered]@{ Applied = 0; Skipped = 0; Failed = 0; DryRun = 0; Drifted = 0; Refused = 0; Pending = 0; Declined = 0 }
    foreach ($step in @(Get-TenureApplyMember -InputObject $Plan -Name 'Steps')) {
        if ($null -eq $step) { continue }
        $status = [string](Get-TenureApplyMember -InputObject $step -Name 'Status')
        $known = $false
        foreach ($name in $script:StepStatuses) {
            if ($status -ceq $name) {
                $summary[$name]++
                $known = $true
                break
            }
        }
        if (-not $known) { $summary.Failed++ }
    }
    $summary
}

function Get-TenureEffectiveRisk {
    <#
    .SYNOPSIS
        The higher of the step's Risk and the provider's Risk (a plan may raise, never lower).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][string]$StepRisk,
        [Parameter(Mandatory)][string]$ProviderRisk
    )

    $risk = $ProviderRisk
    if ($StepRisk -and $script:RiskOrder.ContainsKey($StepRisk) -and $script:RiskOrder[$StepRisk] -gt $script:RiskOrder[$ProviderRisk]) { $risk = $StepRisk }
    $risk
}

function Test-TenureSubjectReference {
    <#
    .SYNOPSIS
        True when a value names the plan's subject: the {{subjectId}} placeholder, the
        subject id (any case), or, on an Onboard plan whose subject has no id yet, the
        subject's user principal name.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][object]$Plan
    )

    if (Test-TenureSubjectPlaceholder -Value $Value) { return $true }
    if (-not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace($Value)) { return $false }
    $candidate = $Value.Trim()
    $subjectId = Get-TenureApplyMember -InputObject $Plan.Subject -Name 'Id'
    if ($subjectId -is [string] -and $subjectId.Trim().Length -gt 0 -and [string]::Equals($candidate, $subjectId.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ([string]$Plan.Operation -ceq 'Onboard') {
        $upn = Get-TenureApplyMember -InputObject $Plan.Subject -Name 'UserPrincipalName'
        if ($upn -is [string] -and $upn.Trim().Length -gt 0 -and [string]::Equals($candidate, $upn.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

function Assert-TenurePlanShape {
    <#
    .SYNOPSIS
        Validates the parts of a plan the engine relies on. Throws Tenure.Plan.Invalid
        (or Tenure.Plan.UnsupportedSchema) naming the first problem; never echoes state.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$Plan)

    $invalid = {
        param([string]$Message)
        throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message "Invalid plan: $Message" -Category InvalidData)
    }

    if ($null -eq $Plan -or -not ($Plan.PSObject.TypeNames -contains 'Tenure.Plan')) {
        & $invalid 'expected a Tenure.Plan object (build it with New-TenurePlan or read it with Import-TenurePlan).'
    }
    foreach ($name in 'PlanId', 'CreatedAt', 'Operation', 'Subject', 'Steps', 'Status') {
        if (-not $Plan.PSObject.Properties[$name]) { & $invalid "missing property '$name'." }
    }
    $schema = Get-TenureApplyMember -InputObject $Plan -Name 'SchemaVersion'
    if ([string]$schema -cne [string]$script:PlanSchemaVersion) {
        $advice = if ($schema -is [int] -and $schema -gt $script:PlanSchemaVersion) { 'Upgrade Tenure.' } else { 'Plans from earlier versions carry no integrity value; build the plan again.' }
        throw (New-TenureError -Id 'Tenure.Plan.UnsupportedSchema' -Message "Plan schemaVersion '$schema' is not supported by this module (supports $($script:PlanSchemaVersion)). $advice" -Category InvalidData)
    }
    if (-not ($Plan.PlanId -is [string]) -or [string]::IsNullOrWhiteSpace($Plan.PlanId)) { & $invalid 'PlanId must be a non-empty string.' }
    if (-not ($Plan.Status -is [string]) -or $Plan.Status -cnotin $script:PlanStatuses) { & $invalid "Status must be one of $($script:PlanStatuses -join ', ')." }
    if ($null -eq $Plan.Subject -or -not ($Plan.Subject -is [System.Collections.IDictionary] -or $Plan.Subject -is [System.Management.Automation.PSCustomObject])) {
        & $invalid 'Subject must be a hashtable or object.'
    }

    $seen = @{}
    $index = 0
    foreach ($step in @($Plan.Steps)) {
        $index++
        if ($null -eq $step -or -not ($step -is [System.Management.Automation.PSCustomObject])) { & $invalid "step #$index is not an object." }
        foreach ($name in 'Id', 'Provider', 'Target', 'Action', 'Before', 'After', 'Fingerprint', 'DependsOn', 'Status', 'Result') {
            if (-not $step.PSObject.Properties[$name]) { & $invalid "step #$index is missing '$name'." }
        }
        $id = $step.Id
        if (-not ($id -is [string]) -or $id -cnotmatch '^S[0-9]{2,3}$') { & $invalid "step #$index has an invalid Id." }
        if ($seen.ContainsKey($id)) { & $invalid "step id '$id' is not unique." }
        if (-not ($step.Provider -is [string]) -or [string]::IsNullOrWhiteSpace($step.Provider)) { & $invalid "step $id has no Provider." }
        if (-not ($step.Action -is [string]) -or $step.Action -cnotin $script:StepActions) { & $invalid "step $id Action must be one of $($script:StepActions -join ', ')." }
        if (-not ($step.Status -is [string]) -or $step.Status -cnotin $script:StepStatuses) { & $invalid "step $id Status must be one of $($script:StepStatuses -join ', ')." }
        if ($null -eq $step.Target -or -not ($step.Target -is [System.Collections.IDictionary] -or $step.Target -is [System.Management.Automation.PSCustomObject])) {
            & $invalid "step $id Target must be a hashtable."
        }
        if ($step.PSObject.Properties['Risk'] -and $null -ne $step.Risk -and -not ($step.Risk -is [string] -and $script:RiskOrder.ContainsKey($step.Risk))) {
            & $invalid "step $id Risk must be Low, Medium, High or Destructive."
        }
        # The provider decides what a step acts on and how. Target.Kind and Action are labels in the plan; a label
        # that disagrees with the provider would steer the protection check and the subject binding past the
        # account the provider really changes, so it is refused. An unregistered provider is refused later, by name.
        $provider = if ($script:Providers.Contains([string]$step.Provider)) { $script:Providers[[string]$step.Provider] } else { $null }
        $labelKind = [string](Get-TenureApplyMember -InputObject $step.Target -Name 'Kind')
        # Identifiers are strings, and mailboxes and drives are named by object id, in every plan (Custom too).
        $identifierProblem = Get-TenureStepIdentifierProblem -Target $step.Target -After $step.After -TargetKind $(if ($null -ne $provider) { $provider.TargetKind } else { $labelKind })
        if ($identifierProblem) { & $invalid "step $id ${identifierProblem}." }
        if ($null -ne $provider) {
            if ($labelKind -cne $provider.TargetKind) {
                & $invalid "step $id has Target.Kind '$labelKind', but provider '$($provider.Name)' acts on a $($provider.TargetKind). Build the step with New-TenureStep and the provider's own target kind."
            }
            if (@($provider.Actions) -cnotcontains [string]$step.Action) {
                & $invalid "step $id has Action '$($step.Action)', which provider '$($provider.Name)' does not allow (it allows $(@($provider.Actions) -join ', '))."
            }
        }
        # Every step binds its target. A step without a snapshot (Before $null) is either a Create, whose
        # fingerprint means "the target does not exist yet", or a step on the user an earlier step creates.
        $fingerprint = $step.Fingerprint
        if (-not ($fingerprint -is [string]) -or $fingerprint -cnotmatch '^[0-9a-f]{64}$') {
            & $invalid "step $id has no Fingerprint (a lowercase SHA-256 hex string). Every step binds its target so drift can be detected; build the plan again."
        }
        if ($null -eq $step.Before) {
            $targetId = Get-TenureApplyMember -InputObject $step.Target -Name 'Id'
            if ($step.Action -cne 'Create' -and -not (Test-TenureSubjectPlaceholder -Value $targetId)) {
                & $invalid "step $id has no Before snapshot. Only a Create step, or a step whose Target.Id is {{subjectId}}, may have none; any other step needs a snapshot so drift can be detected."
            }
        }
        foreach ($dependency in @($step.DependsOn)) {
            if ($null -eq $dependency) { continue }
            if (-not ($dependency -is [string]) -or -not $seen.ContainsKey($dependency)) {
                & $invalid "step $id depends on '$dependency', which is not an earlier step."
            }
        }
        foreach ($name in 'Target', 'Before', 'After') {
            try {
                $null = Get-TenureCanonicalJson -InputObject $step.$name
            } catch {
                & $invalid "step $id $name cannot be serialized ($(Get-TenureErrorId -ErrorRecord $_)). Plans must never carry secrets."
            }
        }

        # Subject binding: an Onboard, RoleChange or Offboard plan acts on its subject only,
        # so a plan file edited to point a step at someone else is refused (even with -Force).
        # What the step acts on is the provider's TargetKind, not the label.
        if ([string]$Plan.Operation -cne 'Custom') {
            $targetKind = if ($null -ne $provider) { $provider.TargetKind } else { $labelKind }
            if ($targetKind -cin 'user', 'mailbox', 'drive') {
                $targetId = Get-TenureApplyMember -InputObject $step.Target -Name 'Id'
                if (-not (Test-TenureSubjectReference -Value $targetId -Plan $Plan)) {
                    & $invalid "step $id acts on $targetKind '$targetId', which is not the plan's subject. An $($Plan.Operation) plan may only act on its subject; build a Custom plan for anything else."
                }
            }
            $after = $step.After
            $hasUserId = $false
            if ($after -is [System.Collections.IDictionary]) {
                $hasUserId = $after.Contains('userId')
            } elseif ($null -ne $after -and $after.PSObject.Properties['userId']) {
                $hasUserId = $true
            }
            if ($hasUserId) {
                $userId = Get-TenureApplyMember -InputObject $after -Name 'userId'
                if (-not (Test-TenureSubjectReference -Value $userId -Plan $Plan)) {
                    & $invalid "step $id names user '$userId' in After.userId, which is not the plan's subject. An $($Plan.Operation) plan may only act on its subject."
                }
            }
        }
        $seen[$id] = $true
    }
}

function Copy-TenurePlanForWhatIf {
    <#
    .SYNOPSIS
        Shallow copy of a plan with its own Subject, Steps and Targets, so a -WhatIf
        run can record simulated statuses without touching the caller's plan.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Plan')]
    param([Parameter(Mandatory)][object]$Plan)

    $copy = $Plan.PSObject.Copy()
    if ($Plan.Subject -is [hashtable]) {
        $copy.Subject = $Plan.Subject.Clone()
    } elseif ($Plan.Subject -is [System.Management.Automation.PSCustomObject]) {
        $copy.Subject = $Plan.Subject.PSObject.Copy()
    } else {
        $copy.Subject = ConvertTo-TenureTargetTable -Target $Plan.Subject
    }
    $copy.Steps = @(foreach ($step in @($Plan.Steps)) {
            $stepCopy = $step.PSObject.Copy()
            $stepCopy.Target = ConvertTo-TenureTargetTable -Target $step.Target
            $stepCopy
        })
    $copy
}

function Save-TenurePlanFile {
    <#
    .SYNOPSIS
        Writes a plan as JSON (the Export-TenurePlan format) atomically: a temporary file
        in the same folder, flushed to disk, then a rename over the target.
    .DESCRIPTION
        Canonical JSON runs first as the no-secrets guard. Throws
        Tenure.Apply.OutFileUnwritable when the file cannot be written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$Path
    )

    $null = Get-TenureCanonicalJson -InputObject $Plan
    $exportable = ConvertTo-TenureExportObject -InputObject $Plan
    $json = ConvertTo-Json -InputObject $exportable -Depth 20 -WarningAction SilentlyContinue -WarningVariable truncation
    if (@($truncation).Count -gt 0) {
        throw (New-TenureError -Id 'Tenure.Apply.OutFileUnwritable' -Message "The plan nests deeper than 20 levels and cannot be saved to '$Path' without losing data." -Category WriteError)
    }
    $text = ($json -replace "`r`n", "`n") + "`n"
    $temporary = '{0}.{1}.tmp' -f $Path, [guid]::NewGuid().ToString('N')
    try {
        Write-TenureTemporaryFile -Path $temporary -Text $text
        [System.IO.File]::Move($temporary, $Path, $true)
    } catch {
        $cause = Get-TenureAuditInnerException -ErrorRecord $_
        if ([System.IO.File]::Exists($temporary)) {
            try { [System.IO.File]::Delete($temporary) } catch { Write-Verbose "Could not remove '$temporary'." }
        }
        throw (New-TenureError -Id 'Tenure.Apply.OutFileUnwritable' -Message "Could not write the plan file '$Path': $($cause.Message)" -Category WriteError -Data @{ FilePath = $Path })
    }
}

function Save-TenurePlanProgress {
    <#
    .SYNOPSIS
        Rewrites the run's plan file (when one is configured) with the current statuses.
        A failure warns once and the run continues: the audit log remains the record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][hashtable]$Run
    )

    if ($Run.WhatIf -or [string]::IsNullOrEmpty($Run.PlanFile)) { return }
    $Plan.Status = Get-TenurePlanStatus -Plan $Plan
    try {
        Save-TenurePlanFile -Plan $Plan -Path $Run.PlanFile
    } catch {
        if (-not $Run.PersistWarned) {
            $Run.PersistWarned = $true
            Write-Warning "The plan file '$($Run.PlanFile)' could not be updated: $($_.Exception.Message) The run continues; the audit log records every outcome, and the returned plan carries the statuses."
        }
    }
}

function New-TenureStepOutcome {
    <#
    .SYNOPSIS
        The record Invoke-TenurePlanStep returns; the core loop commits it.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds a hashtable; changes no state.')]
    param()

    @{
        Status        = $null
        Observed      = $null
        Error         = $null
        Notes         = [System.Collections.Generic.List[string]]::new()
        Stop          = $false
        Target        = $null
        TargetChanged = $false
        After         = $null
        AfterChanged  = $false
        CreatedId     = $null
        Warning       = $null
        Simulated     = $false
        Uncertain     = $false
        Assumed       = $false
    }
}

function Test-TenureInvokeUncertain {
    <#
    .SYNOPSIS
        True when an Invoke step may have fired in an earlier run without its outcome
        being recorded: the audit log has an unfinished Attempting entry, the plan says
        the step was interrupted or uncertain, or Set was attempted and no outcome
        followed (a process killed mid-step).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][hashtable]$Run
    )

    if ($null -ne $Run.History -and $Run.History.Uncertain.Contains($Step.Id)) { return $true }
    $result = $Step.Result
    if ((Get-TenureApplyMember -InputObject $result -Name 'Uncertain') -eq $true) { return $true }
    $errorText = [string](Get-TenureApplyMember -InputObject $result -Name 'Error')
    if ($errorText.StartsWith('Tenure.Apply.Interrupted', [System.StringComparison]::Ordinal)) { return $true }
    if ($Step.Status -ceq 'Pending' -and (Get-TenureApplyMember -InputObject $result -Name 'Attempted') -eq $true) { return $true }
    $false
}

function Invoke-TenurePlanStep {
    <#
    .SYNOPSIS
        Runs one step's decision and applies the fail-closed rule for Refuse checks.
    .DESCRIPTION
        A Check with Severity Refuse is a safety precondition: any outcome other than
        "Test true" (a dependency that did not apply, a Get error, drift, a Test that
        throws or returns false) makes it Refused and stops the plan, regardless of
        -ContinueOnError and -Force.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Provider,
        [Parameter(Mandatory)][hashtable]$StepsById,
        [Parameter(Mandatory)][hashtable]$Run
    )

    $outcome = Invoke-TenurePlanStepDecision -Step $Step -Plan $Plan -Provider $Provider -StepsById $StepsById -Run $Run
    $refuseCheck = ($Provider.Kind -ceq 'Check' -and $Provider.Severity -cne 'Warn')
    if ($refuseCheck -and $outcome.Status -cin 'Failed', 'Drifted', 'Refused') {
        $outcome.Status = 'Refused'
        $outcome.Stop = $true
        $said = $false
        foreach ($note in $outcome.Notes) { if ($note.Contains('the plan stops here')) { $said = $true } }
        if (-not $said) { $outcome.Notes.Add('a Severity Refuse check fails closed: the plan stops here') }
    }
    $outcome
}

function Invoke-TenurePlanStepDecision {
    <#
    .SYNOPSIS
        Decides and performs one step (SPEC section 5.4) and returns an outcome record.
    .DESCRIPTION
        Does not commit the outcome to the plan. Before Set it calls
        Register-TenureSetAttempt (write-ahead audit entry for Invoke and Destructive
        steps, Result.Attempted, plan file rewrite) and sets $Run.SetStarted.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'ShouldProcess and ShouldContinue are evaluated against the public Invoke-TenurePlan cmdlet, passed in as $Run.Cmdlet.')]
    param(
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Provider,
        [Parameter(Mandatory)][hashtable]$StepsById,
        [Parameter(Mandatory)][hashtable]$Run
    )

    $outcome = New-TenureStepOutcome
    $continue = [bool]$Run.ContinueOnError
    $kind = $Provider.Kind
    $refuseCheck = ($kind -ceq 'Check' -and $Provider.Severity -cne 'Warn')
    $previous = $Step.Status
    # Only the audit log counts as evidence that Set was called in an earlier run: Result.Attempted in a plan
    # file can be edited, a hash-chained entry cannot be without breaking the chain.
    $attemptedBefore = ($null -ne $Run.History -and $Run.History.Attempted.Contains([string]$Step.Id))
    $repeatAttempt = $false

    # 1. Dependencies. Only this run's outcome counts: a status left in the plan by an earlier run may be stale
    #    (the change was undone since, and the step was declined now). A dependency this run did not apply or
    #    skip is met only when a live read shows its desired state holds right now.
    foreach ($dependency in @($Step.DependsOn)) {
        if ($null -eq $dependency) { continue }
        $depStatus = if ($Run.Outcomes.ContainsKey($dependency)) { $Run.Outcomes[$dependency] } else { $null }
        $met = ($depStatus -ceq 'Applied' -or $depStatus -ceq 'Skipped')
        if (-not $met -and $Run.DryRun -and $depStatus -ceq 'DryRun') { $met = $true }
        if (-not $met -and $Run.WhatIf -and $Run.Simulated.Contains($dependency)) { $met = $true }
        if (-not $met -and (Test-TenureDependencySatisfied -Step $StepsById[$dependency] -Plan $Plan -Run $Run)) {
            $met = $true
            $outcome.Notes.Add("dependency $dependency was not applied in this run, but its desired state holds now (read live)")
        }
        if (-not $met) {
            $outcome.Status = 'Refused'
            $outcome.Notes.Add("dependency $dependency not applied")
            $outcome.Stop = -not $continue
            return $outcome
        }
    }

    # 2. Invoke steps are idempotent by status and by the audit log. One that may have fired in an
    #    earlier run without its outcome being recorded runs again only under -Resume and only when its
    #    provider is Repeatable (a session revoke, a device retire or wipe, a meeting cancellation). Any
    #    other stops the run until the operator checks it and names it in -AssumeFired, which is recorded.
    #    The plan file's own Applied or Skipped is not enough: statuses are not sealed, and a status edited
    #    to Skipped would otherwise silence a revoke or a wipe. Without the audit log's record the step is
    #    in doubt, like one whose attempt was never confirmed.
    if ($kind -ceq 'Invoke') {
        if ($null -ne $Run.History -and $Run.History.Applied.Contains([string]$Step.Id)) {
            $outcome.Status = 'Skipped'
            $outcome.Notes.Add($(if ($previous -cin 'Applied', 'Skipped') { 'already applied in an earlier run (audit log)' } else { 'already fired per audit log' }))
            if ($Run.History.Assumed.Contains([string]$Step.Id)) {
                # The audit log shows the earlier run only assumed it fired (-AssumeFired); the mark carries over, so
                # a run from a plan file that never saw that run cannot end Applied either.
                $outcome.Assumed = $true
                $outcome.Notes.Add('assumed fired in that run (-AssumeFired), not seen to fire; the plan cannot end Applied')
            }
            return $outcome
        }
        $claimed = ($previous -ceq 'Applied' -or $previous -ceq 'Skipped')
        if ($claimed) { $outcome.Notes.Add("the plan file says this step ran in an earlier run, but the audit log '$($Run.AuditPath)' has no record of it") }
        $named = $Run.AssumeFired.Contains([string]$Step.Id)
        if ($claimed -or (Test-TenureInvokeUncertain -Step $Step -Run $Run)) {
            if ($named) {
                $outcome.Status = 'Skipped'
                $outcome.Assumed = $true
                $outcome.Notes.Add('assumed fired: Set may have run in an earlier run whose outcome was never recorded, and the operator named this step in -AssumeFired; Set was not called again. The plan cannot end Applied')
                return $outcome
            }
            if ($Run.Resume -and $Provider.Repeatable) {
                $outcome.Notes.Add('may have fired in an earlier run whose outcome was never recorded; the provider is Repeatable, so it runs again (-Resume)')
                $repeatAttempt = $true
            } else {
                $outcome.Status = 'Refused'
                $outcome.Uncertain = $true
                $outcome.Error = 'Tenure.Apply.Uncertain: Set may have run in an earlier run and its outcome was never recorded.'
                if ($Provider.Repeatable) {
                    $outcome.Notes.Add("may have fired in an earlier run; it is safe to repeat: pass -Resume to run it again, or -AssumeFired $($Step.Id) once you have checked that it fired")
                } else {
                    $outcome.Notes.Add("may have fired in an earlier run and is not safe to repeat; the run stops here. Check the target: if it fired, pass -AssumeFired $($Step.Id) to record that and continue; if it did not, build the plan again")
                }
                $outcome.Stop = $true
                return $outcome
            }
        } elseif ($named) {
            $outcome.Status = 'Refused'
            $outcome.Error = "Tenure.Apply.InvalidArgument: -AssumeFired names $($Step.Id), but nothing shows it was attempted in an earlier run."
            $outcome.Notes.Add("-AssumeFired names this step, but the audit log and the plan show no unconfirmed attempt; run again without $($Step.Id) in -AssumeFired")
            $outcome.Stop = $true
            return $outcome
        }
    }

    # 3. Placeholders, target and context.
    $subjectId = Get-TenureApplyMember -InputObject $Plan.Subject -Name 'Id'
    $resolved = Resolve-TenureStepPlaceholder -Step $Step -SubjectId $subjectId
    $target = $resolved.Target
    $after = $resolved.After
    $outcome.Target = $target
    $outcome.TargetChanged = $resolved.TargetChanged
    $outcome.After = $after
    $outcome.AfterChanged = $resolved.AfterChanged
    $Run.StepTarget = $target
    $Run.StepAfter = $after
    $label = Get-TenureTargetLabel -Target $target
    $description = "[$($Step.Id)] $($Step.Provider) on $label"
    $reason = [string](Get-TenureApplyMember -InputObject $Step -Name 'Reason')
    if ([string]::IsNullOrWhiteSpace($reason)) { $reason = "$($Step.Action) $($Step.Provider)" }

    if ($resolved.Unresolved) {
        $outcome.Notes.Add('the step still holds a placeholder: the subject has no id yet (the create step has not been applied)')
        if ($Run.DryRun) {
            $outcome.Status = 'DryRun'
            $outcome.Notes.Add('not checked in a dry run')
            return $outcome
        }
        if ($Run.WhatIf) {
            [void]$Run.Cmdlet.ShouldProcess($description, (Get-TenureEngineDescription -Provider $Provider -Target $target -Current $null -After $after -Action ([string]$Step.Action) -Secrets $Run.Secrets))
            $outcome.Status = 'Pending'
            $outcome.Simulated = $true
            return $outcome
        }
        $outcome.Status = 'Refused'
        $outcome.Stop = -not $continue
        return $outcome
    }

    $context = New-TenureStepContext -Plan $Plan -Step $Step -Run $Run
    # Reads (before and after Set) name the step's own user: for a membership step that is After.userId.
    $readContext = Get-TenureStepReadContext -Provider $Provider -Context $context -After $after

    # 4. Current state. Secrets a Get put in the table are protected and searched too.
    $current = $null
    try {
        $current = Invoke-TenureProviderBlock -Block $Provider.Get -ArgumentList @($target, $readContext)
    } catch {
        $errorId = Get-TenureErrorId -ErrorRecord $_
        if ($errorId -ceq 'Tenure.Provider.TargetNotFound' -and $Step.Action -ceq 'Create') {
            $current = $null
        } else {
            $outcome.Status = 'Failed'
            $outcome.Error = Format-TenureErrorText -ErrorRecord $_
            $outcome.Notes.Add('could not read current state')
            $outcome.Stop = -not $continue
            return $outcome
        }
    } finally {
        Protect-TenureSecretTable -Secrets $Run.Secrets -Provider $Provider.Name
    }
    $safety = Test-TenureStateSafe -State $current -Secrets $Run.Secrets
    if (-not $safety.Safe) {
        $outcome.Status = 'Failed'
        $outcome.Error = $safety.Error
        $outcome.Notes.Add('current state withheld: it cannot be stored safely')
        $outcome.Stop = -not $continue
        return $outcome
    }

    # Resume of a Create whose Set was called in an earlier run (the audit log has its Attempting
    # entry): the target now exists because we created it, so adopt it instead of creating it again.
    # A Create that was never attempted never adopts an account that happens to exist.
    if ($Step.Action -ceq 'Create' -and $attemptedBefore -and $null -ne $current) {
        # The target must have been created during one of this step's attempts: after its Attempting entry and
        # before the next entry for the step or the run's end, an attempt that did not end in a recorded failure.
        # Anything else is someone else's account that took the name, not the one this plan created.
        $createdAt = ConvertFrom-TenureTimestamp -Value (Get-TenureApplyMember -InputObject $current -Name 'createdDateTime')
        $window = Find-TenureAdoptionWindow -Attempts $Run.History.Attempts[[string]$Step.Id] -CreatedAt $createdAt
        if ($null -eq $window) {
            $shown = if ($null -ne $createdAt) { "was created at $($createdAt.ToString('o'))" } else { 'does not say when it was created' }
            $outcome.Status = 'Drifted'
            $outcome.Observed = $current
            $outcome.Notes.Add("the target exists but $shown, which is not during an attempt of this plan's create step that did not end in a recorded failure (audit log); it is not the account this plan created and is not adopted")
            $outcome.Stop = $true
            return $outcome
        }
        $outcome.Status = 'Skipped'
        $outcome.Observed = $current
        $outcome.Notes.Add('created by an earlier attempt (Set was called and the target now exists); its id is adopted')
        $foundId = Get-TenureApplyMember -InputObject $current -Name 'id'
        if ($foundId -is [string] -and $foundId.Length -gt 0) {
            $outcome.CreatedId = $foundId
        } else {
            $outcome.Notes.Add('the found target has no id to adopt')
        }
        $matchesDesired = $false
        try {
            $matchesDesired = Invoke-TenureProviderTest -Provider $Provider -Current $current -Desired $after
        } catch {
            $matchesDesired = $false
        }
        if (-not $matchesDesired) {
            $outcome.Notes.Add('it does not match the desired state; review it')
            $outcome.Warning = "${description}: created by an earlier attempt but it does not match the desired state; review it."
        }
        return $outcome
    }

    # A State step whose desired state already holds has nothing to do, so it is Skipped before any drift
    # verdict: an earlier step of this plan, in this run or an earlier one, may have moved the very state the
    # snapshot describes (a sign-in disable takes the user out of a dynamic group; a group removal takes its
    # licenses). A Create is the exception: its target must be absent, or adopted above.
    $tested = $false
    if ($kind -ceq 'State' -and $Step.Action -cne 'Create') {
        try {
            $satisfied = Invoke-TenureProviderTest -Provider $Provider -Current $current -Desired $after
        } catch {
            $outcome.Status = 'Failed'
            $outcome.Error = Format-TenureErrorText -ErrorRecord $_
            $outcome.Observed = $current
            $outcome.Stop = -not $continue
            return $outcome
        }
        if ($satisfied) {
            $outcome.Status = 'Skipped'
            $outcome.Observed = $current
            if ($previous -ceq 'Failed') {
                $outcome.Notes.Add('satisfied by an earlier run')
            } elseif ($previous -cin 'Applied', 'Skipped') {
                $outcome.Notes.Add("$($previous.ToLowerInvariant()) in an earlier run; still satisfied")
            } else {
                $outcome.Notes.Add('already satisfied')
            }
            return $outcome
        }
        $tested = $true
    }

    # Resume of a check that this plan's own create step made false (a user-absent check after the
    # user was created): it passed in an earlier run of this plan, and the audit log shows this
    # plan's create step on the same target ran, so it is not checked again.
    if ($kind -ceq 'Check' -and $null -ne $Run.History -and $Run.History.Applied.Contains([string]$Step.Id)) {
        $creator = Find-TenureCreatorStep -Plan $Plan -Step $Step -History $Run.History
        if ($creator) {
            $outcome.Status = 'Skipped'
            $outcome.Observed = $current
            $outcome.Notes.Add("passed in an earlier run of this plan; its target exists now because this plan's create step $creator ran (audit log)")
            return $outcome
        }
    }

    # A check whose input this plan's own step changed (the audit log of an earlier run, or this run, shows a
    # step of a provider in the check's AffectedBy applied) cannot be compared with its snapshot: the plan
    # itself moved it. It is evaluated against the live state instead: passing is Skipped, failing refuses.
    if ($kind -ceq 'Check') {
        $affecting = Find-TenureAffectingStep -Plan $Plan -Step $Step -Provider $Provider -Run $Run
        if ($affecting) {
            try {
                $passes = Invoke-TenureProviderTest -Provider $Provider -Current $current -Desired $after
            } catch {
                $passes = $false
            }
            $outcome.Observed = $current
            if ($passes) {
                $outcome.Status = 'Skipped'
                $outcome.Notes.Add("re-evaluated against the live state instead of the snapshot, because this plan's step $affecting changed what it checks; it passes")
                return $outcome
            }
            $outcome.Status = 'Refused'
            $outcome.Notes.Add("re-evaluated against the live state instead of the snapshot, because this plan's step $affecting changed what it checks; it does not pass, so the plan stops here")
            $outcome.Stop = $true
            return $outcome
        }
    }

    # Drift: the live state no longer matches the snapshot the plan was reviewed against.
    # The fingerprint binds the target as well as the state, so a plan file edited to point
    # a step at another object drifts even when that object looks the same, and a Create
    # whose target exists now drifts too. -Force overrides it, except for a Refuse check,
    # which fails closed, and a Create, whose target must be absent.
    if ($repeatAttempt) {
        # The earlier attempt may have changed the very state the fingerprint describes (a revoke moves the
        # session timestamp), so drift says nothing here; the provider's Set re-checks what it needs.
        $outcome.Notes.Add('drift check skipped for a Repeatable step run again')
    } elseif (Test-TenureStepDrift -Step $Step -Target $target -Current $current -SubjectId $subjectId) {
        if ($refuseCheck) {
            $outcome.Status = 'Drifted'
            $outcome.Observed = $current
            $outcome.Notes.Add('drift: the checked state changed since the plan was built; re-plan')
            return $outcome
        }
        if ($Step.Action -ceq 'Create') {
            $outcome.Status = 'Drifted'
            $outcome.Observed = $current
            $outcome.Notes.Add('drift: the target of this create exists now, but it was absent when the plan was built and this plan never attempted to create it; -Force does not override this')
            $outcome.Stop = -not $continue
            return $outcome
        }
        if (-not $Run.Force) {
            $outcome.Status = 'Drifted'
            $outcome.Observed = $current
            $outcome.Notes.Add('drift: the live state differs from the plan snapshot; re-plan or use -Force')
            $outcome.Stop = -not $continue
            return $outcome
        }
        $outcome.Notes.Add('drift overridden by -Force')
    }

    # 5. Satisfied state and checks. Check providers never Set. A State step was tested above.
    if (($kind -ceq 'State' -and -not $tested) -or $kind -ceq 'Check') {
        try {
            $satisfied = Invoke-TenureProviderTest -Provider $Provider -Current $current -Desired $after
        } catch {
            $outcome.Status = 'Failed'
            $outcome.Error = Format-TenureErrorText -ErrorRecord $_
            $outcome.Observed = $current
            $outcome.Stop = -not $continue
            return $outcome
        }
        if ($kind -ceq 'Check') {
            $outcome.Observed = $current
            if ($satisfied) {
                $outcome.Status = 'Skipped'
                $outcome.Notes.Add('check passed')
                return $outcome
            }
            if (-not $refuseCheck) {
                $outcome.Status = 'Skipped'
                $outcome.Notes.Add('check did not pass (Severity Warn); continuing')
                $outcome.Warning = "${description}: check did not pass (Severity Warn); continuing. $reason"
                return $outcome
            }
            $outcome.Status = 'Refused'
            $outcome.Notes.Add('check did not pass (Severity Refuse); the plan stops here')
            $outcome.Stop = $true
            return $outcome
        }
        if ($satisfied) {
            $outcome.Status = 'Skipped'
            $outcome.Observed = $current
            $outcome.Notes.Add('already satisfied')
            return $outcome
        }
    }

    # A NoOp step showed "no change" in the reviewed plan. It is no longer satisfied, so
    # applying it now would be a change nobody reviewed: refuse instead of calling Set.
    if ($Step.Action -ceq 'NoOp') {
        $outcome.Status = 'Refused'
        $outcome.Observed = $current
        $outcome.Notes.Add('no-op at plan time but no longer satisfied; re-plan to review the change')
        $outcome.Stop = -not $continue
        return $outcome
    }

    # 6. Dry run: report, never Set, never prompt.
    if ($Run.DryRun) {
        $outcome.Status = 'DryRun'
        $outcome.Observed = $current
        $outcome.Notes.Add('dry run: Set not called')
        return $outcome
    }

    # 7. Destructive steps need -AllowDestructive when confirmation is suppressed.
    $risk = Get-TenureEffectiveRisk -StepRisk ([string](Get-TenureApplyMember -InputObject $Step -Name 'Risk')) -ProviderRisk $Provider.Risk
    if ($risk -ceq 'Destructive' -and $Run.ConfirmSuppressed -and -not $Run.AllowDestructive) {
        $outcome.Status = 'Refused'
        $outcome.Observed = $current
        $outcome.Notes.Add('destructive step: confirmation is suppressed and -AllowDestructive was not given')
        $outcome.Stop = -not $continue
        return $outcome
    }

    # 8. ShouldProcess: -WhatIf leaves the step Pending; a declined prompt makes it Declined, which the plan file
    #    records so a status from an earlier run cannot stand in for it. Neither is audited. The prompts show
    #    the provider's own description of the change, worked out from the live state, not the Reason text the
    #    plan carries.
    $engineText = Get-TenureEngineDescription -Provider $Provider -Target $target -Current $current -After $after -Action ([string]$Step.Action) -Secrets $Run.Secrets
    if (-not $Run.Cmdlet.ShouldProcess($description, $engineText)) {
        if ($Run.WhatIf) {
            $outcome.Status = 'Pending'
            $outcome.Simulated = $true
            return $outcome
        }
        $outcome.Status = 'Declined'
        $outcome.Observed = $current
        $outcome.Notes.Add('declined at the confirmation prompt; nothing was changed')
        return $outcome
    }

    # A Destructive step without -AllowDestructive gets its own question, which has no
    # "Yes to All": an answer given at an earlier step never covers it.
    if ($risk -ceq 'Destructive' -and -not $Run.AllowDestructive) {
        $query = "$description is a Destructive step that may not be reversible. $($Provider.Name) will: $engineText. Run it?"
        $confirmed = $false
        try {
            $confirmed = [bool]$Run.Cmdlet.ShouldContinue($query, 'Confirm destructive step')
        } catch {
            $outcome.Status = 'Refused'
            $outcome.Observed = $current
            $outcome.Notes.Add('destructive step: this host cannot ask for confirmation; pass -AllowDestructive to run it')
            $outcome.Stop = -not $continue
            return $outcome
        }
        if (-not $confirmed) {
            $outcome.Status = 'Declined'
            $outcome.Observed = $current
            $outcome.Notes.Add('declined at the destructive-step question; nothing was changed')
            return $outcome
        }
    }

    # 9. Write-ahead, Set, then read back and verify.
    Register-TenureSetAttempt -Plan $Plan -Step $Step -Target $target -After $after -WriteAhead ($kind -ceq 'Invoke' -or $risk -ceq 'Destructive' -or $Step.Action -ceq 'Create') -Run $Run
    $Run.SetStarted = $true
    $setResult = $null
    try {
        $setResult = Invoke-TenureProviderBlock -Block $Provider.Set -ArgumentList @($target, $after, $current, $context)
    } catch {
        $outcome.Status = 'Failed'
        $outcome.Error = Format-TenureErrorText -ErrorRecord $_
        $outcome.Notes.Add('Set failed')
        $outcome.Stop = -not $continue
        return $outcome
    } finally {
        Protect-TenureSecretTable -Secrets $Run.Secrets -Provider $Provider.Name
    }

    # Read back. A just-created object may not be readable yet (directory replication), so
    # a Create retries a TargetNotFound read after 2, 4 and 8 seconds and then falls back
    # to the object Set returned, when that carries an id. Set itself is never retried.
    $observed = $null
    if ($kind -ceq 'Invoke') {
        $observed = $setResult
    } else {
        $delays = @()
        if ($Step.Action -ceq 'Create') { $delays = $script:CreateReadBackDelays }
        $attempt = 0
        while ($true) {
            try {
                $observed = Invoke-TenureProviderBlock -Block $Provider.Get -ArgumentList @($target, $readContext)
                break
            } catch {
                $readError = $_
                $notFound = ((Get-TenureErrorId -ErrorRecord $readError) -ceq 'Tenure.Provider.TargetNotFound')
                if ($notFound -and $attempt -lt $delays.Count) {
                    Write-Verbose "[$($Step.Id)] the created object is not readable yet; retrying in $($delays[$attempt]) s."
                    Start-Sleep -Seconds $delays[$attempt]
                    $attempt++
                    continue
                }
                $setId = Get-TenureApplyMember -InputObject $setResult -Name 'id'
                if ($notFound -and $Step.Action -ceq 'Create' -and $setId -is [string] -and $setId.Length -gt 0) {
                    $observed = $setResult
                    $outcome.Notes.Add("the created object could not be read back after $($delays.Count) retries; using the object Set returned")
                    break
                }
                $outcome.Status = 'Failed'
                $outcome.Error = Format-TenureErrorText -ErrorRecord $readError
                $outcome.Notes.Add('Set ran but the state could not be read back; Set was not retried')
                $outcome.Stop = -not $continue
                return $outcome
            } finally {
                Protect-TenureSecretTable -Secrets $Run.Secrets -Provider $Provider.Name
            }
        }
    }

    $observedId = Get-TenureApplyMember -InputObject $observed -Name 'id'
    $safety = Test-TenureStateSafe -State $observed -Secrets $Run.Secrets
    if (-not $safety.Safe) {
        $outcome.Status = 'Failed'
        $outcome.Error = $safety.Error
        $outcome.Notes.Add('Set ran; the observed state was withheld because it cannot be stored safely')
        $outcome.Stop = -not $continue
        return $outcome
    }
    $outcome.Observed = $observed

    if ($kind -ceq 'State') {
        try {
            $met = Invoke-TenureProviderTest -Provider $Provider -Current $observed -Desired $after
        } catch {
            $outcome.Status = 'Failed'
            $outcome.Error = Format-TenureErrorText -ErrorRecord $_
            $outcome.Notes.Add('Set ran; the post-condition could not be evaluated')
            $outcome.Stop = -not $continue
            return $outcome
        }
        if (-not $met) {
            $outcome.Status = 'Failed'
            $outcome.Error = 'Tenure.Apply.PostConditionFailed: post-condition not met: Test returned false after Set.'
            $outcome.Notes.Add('post-condition not met')
            $outcome.Stop = -not $continue
            return $outcome
        }
    }

    if ($Step.Action -ceq 'Create' -and $observedId -is [string] -and $observedId.Length -gt 0) {
        $outcome.CreatedId = $observedId
    }
    $outcome.Status = 'Applied'
    $outcome
}

function Write-TenureStepEntry {
    <#
    .SYNOPSIS
        Writes one step entry to the audit log. State fields that cannot be stored safely
        are written as null with a note (never with the secret). Updates $Run.AuditHead.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.AuditEntry')]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][hashtable]$Run,
        [Parameter(Mandatory)][string]$Outcome,
        [AllowNull()][object]$Target,
        [AllowNull()][object]$After,
        [AllowNull()][object]$Observed,
        [AllowNull()][string]$ErrorText,
        [AllowNull()][string]$Note,
        [AllowNull()][object]$DurationMs
    )

    $entry = @{
        PlanId     = $Plan.PlanId
        Operation  = $Plan.Operation
        StepId     = $Step.Id
        Provider   = $Step.Provider
        Target     = $Target
        Action     = $Step.Action
        Actor      = $Run.Actor
        Outcome    = $Outcome
        Before     = $Step.Before
        After      = $After
        Observed   = $Observed
        Error      = $(if ([string]::IsNullOrEmpty($ErrorText)) { $null } else { $ErrorText })
        Note       = $(if ([string]::IsNullOrEmpty($Note)) { $null } else { $Note })
        DurationMs = $DurationMs
        Mode       = $Run.Mode
    }
    $withheld = [System.Collections.Generic.List[string]]::new()
    foreach ($name in 'Target', 'Before', 'After', 'Observed') {
        $check = Test-TenureStateSafe -State $entry[$name] -Secrets $Run.Secrets
        if (-not $check.Safe) {
            $entry[$name] = $null
            $withheld.Add($name)
        }
    }
    if ($withheld.Count -gt 0) {
        $text = "$($withheld -join ', ') withheld from the audit log: cannot be stored safely"
        if ($entry.Note) { $entry.Note = "$($entry.Note); $text" } else { $entry.Note = $text }
    }
    $written = Write-TenureAudit -Entry $entry -Path $Run.AuditPath
    $Run.AuditHead = [ordered]@{ Seq = $written.Seq; Hash = $written.Hash }
    $written
}

function Write-TenureStepAudit {
    <#
    .SYNOPSIS
        Writes the audit entry for a step outcome already committed to the plan.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.AuditEntry')]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][hashtable]$Run,
        [AllowNull()][object]$Target,
        [AllowNull()][object]$After
    )

    # The audit entry names what the step acted on: the target and desired state with {{subjectId}} filled in.
    if ($null -eq $Target) { $Target = $Step.Target }
    if (-not $PSBoundParameters.ContainsKey('After')) { $After = $Step.After }
    $result = $Step.Result
    $fields = @{
        Plan       = $Plan
        Step       = $Step
        Run        = $Run
        Outcome    = $Step.Status
        Target     = $Target
        After      = $After
        Observed   = Get-TenureApplyMember -InputObject $result -Name 'Observed'
        ErrorText  = Get-TenureApplyMember -InputObject $result -Name 'Error'
        Note       = Get-TenureApplyMember -InputObject $result -Name 'Note'
        DurationMs = Get-TenureApplyMember -InputObject $result -Name 'DurationMs'
    }
    Write-TenureStepEntry @fields
}

function Register-TenureSetAttempt {
    <#
    .SYNOPSIS
        Records, before Set runs, that it is about to run: an Attempting audit entry for
        Invoke and Destructive steps, Result.Attempted on the step, and a plan file
        rewrite. An audit failure here throws, so Set never runs unrecorded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][hashtable]$Target,
        [AllowNull()][object]$After,
        [Parameter(Mandatory)][bool]$WriteAhead,
        [Parameter(Mandatory)][hashtable]$Run
    )

    if ($WriteAhead) {
        $null = Write-TenureStepEntry -Plan $Plan -Step $Step -Run $Run -Outcome 'Attempting' -Target $Target -After $After -Note 'Set is about to run'
    }
    $previousUncertain = ((Get-TenureApplyMember -InputObject $Step.Result -Name 'Uncertain') -eq $true)
    $Step.Result = [ordered]@{
        At         = [datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        DurationMs = $null
        Observed   = $null
        Error      = $null
        Note       = 'Set in progress'
        Attempted  = $true
        Uncertain  = $previousUncertain
        Assumed    = $false
    }
    Save-TenurePlanProgress -Plan $Plan -Run $Run
}

function Complete-TenurePlanStep {
    <#
    .SYNOPSIS
        Commits an outcome to the step (Status, Result, resolved Target and After) and to
        the plan Subject when a Create step produced or adopted the subject id.
    .DESCRIPTION
        Result.Attempted is sticky: true once Set has been called for the step in any run.
        Result.Uncertain is sticky until the step is Applied or Skipped. Result.Assumed is
        sticky: a step the operator assumed fired stays marked. The step's Target and After
        are never rewritten (the plan's integrity value covers them); {{subjectId}} is
        resolved again on every run from Subject.Id.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Step,
        [Parameter(Mandatory)][hashtable]$Outcome,
        [Parameter(Mandatory)][string]$At,
        [Parameter(Mandatory)][long]$DurationMs,
        [Parameter(Mandatory)][hashtable]$Run
    )

    $note = $null
    if ($Outcome.Notes.Count -gt 0) { $note = Hide-TenureSecretText -Text ($Outcome.Notes -join '; ') -Secrets $Run.Secrets }
    $errorText = Hide-TenureSecretText -Text $Outcome.Error -Secrets $Run.Secrets
    $previousAttempted = ((Get-TenureApplyMember -InputObject $Step.Result -Name 'Attempted') -eq $true)
    $previousUncertain = ((Get-TenureApplyMember -InputObject $Step.Result -Name 'Uncertain') -eq $true)
    $previousAssumed = ((Get-TenureApplyMember -InputObject $Step.Result -Name 'Assumed') -eq $true)

    $Step.Status = $Outcome.Status
    $Step.Result = [ordered]@{
        At         = $At
        DurationMs = $DurationMs
        Observed   = $Outcome.Observed
        Error      = $errorText
        Note       = $note
        Attempted  = ([bool]$Run.SetStarted -or $previousAttempted)
        Uncertain  = ([bool]$Outcome.Uncertain -or ($previousUncertain -and $Outcome.Status -cnotin 'Applied', 'Skipped'))
        Assumed    = ([bool]$Outcome.Assumed -or $previousAssumed)
    }

    if ($null -ne $Outcome.CreatedId) {
        $target = ConvertTo-TenureTargetTable -Target $Step.Target
        $kind = if ($target.ContainsKey('Kind')) { [string]$target['Kind'] } else { '' }
        $subjectId = Get-TenureApplyMember -InputObject $Plan.Subject -Name 'Id'
        if ($kind -ceq 'user' -and ($null -eq $subjectId -or [string]::IsNullOrEmpty([string]$subjectId))) {
            if ($Plan.Subject -is [System.Collections.IDictionary]) {
                $Plan.Subject['Id'] = $Outcome.CreatedId
            } elseif ($Plan.Subject.PSObject.Properties['Id']) {
                $Plan.Subject.Id = $Outcome.CreatedId
            } else {
                $Plan.Subject | Add-Member -MemberType NoteProperty -Name 'Id' -Value $Outcome.CreatedId
            }
            Write-Verbose "[$($Step.Id)] subject id is now $($Outcome.CreatedId)."
        }
    }
}

function New-TenureApplyResult {
    <#
    .SYNOPSIS
        Builds the Tenure.ApplyResult object (SPEC section 2.6).
    #>
    [CmdletBinding()]
    [OutputType('Tenure.ApplyResult')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an object; changes no state.')]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][hashtable]$Secrets,
        [Parameter(Mandatory)][string]$AuditPath,
        [AllowNull()][object]$AuditHead
    )

    [pscustomobject]@{
        PSTypeName = 'Tenure.ApplyResult'
        Plan       = $Plan
        Summary    = Get-TenurePlanSummary -Plan $Plan
        Secrets    = $Secrets
        AuditPath  = $AuditPath
        AuditHead  = $AuditHead
    }
}

function Write-TenurePlanFinished {
    <#
    .SYNOPSIS
        Writes the PlanFinished entry with the final status and summary; updates AuditHead.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.AuditEntry')]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][hashtable]$Run,
        [Parameter(Mandatory)][hashtable]$Target,
        [AllowNull()][string]$Note
    )

    $entry = @{
        PlanId    = $Plan.PlanId
        Operation = $Plan.Operation
        Target    = $Target
        Actor     = $Run.Actor
        Outcome   = 'PlanFinished'
        Observed  = [ordered]@{ Status = $Plan.Status; Summary = (Get-TenurePlanSummary -Plan $Plan) }
        Mode      = $Run.Mode
    }
    if ($Note) { $entry.Note = $Note }
    $written = Write-TenureAudit -Path $Run.AuditPath -Entry $entry
    $Run.AuditHead = [ordered]@{ Seq = $written.Seq; Hash = $written.Hash }
    $written
}

function Invoke-TenurePlanCore {
    <#
    .SYNOPSIS
        The apply engine behind Invoke-TenurePlan (SPEC section 5.4).
    .DESCRIPTION
        Mutates and returns the given plan (statuses, Result, resolved placeholders,
        Subject.Id, Status) except under -WhatIf, where it works on a copy and writes
        nothing. ShouldProcess is evaluated against -Cmdlet (the public cmdlet's $PSCmdlet).

        Preflight, before any step and any write: plan shape (including each step's
        Target.Kind and Action against its provider), the integrity value
        (Tenure.Plan.Tampered), Status not Applied, age within -MaxAge (unless
        -AllowStale), providers registered, backends connected, the plan names the
        connected tenant, -AssumeFired names Invoke steps, the policy (recorded, or matching
        -Policy), a subject id filled in after the plan was sealed was produced by this
        plan's create step (audit log), and no step changes the signed-in account or a
        protected user (Tenure.Plan.Refused). Then, under the audit lock, the plan's history
        is read and a run still open in the log is refused (Tenure.Plan.RunInProgress,
        unless -Resume), as is a plan the log shows finished Applied
        (Tenure.Plan.AlreadyApplied, unless -Force), before PlanStarted is written. With -PlanFile the plan file is rewritten before step 1, before each Set
        and after every outcome.

        Every way out of the loop runs the same finally: the result (with secrets) is
        kept for Get-TenureApplyResult, a PlanFinished entry is written if none was, and
        the plan file is saved. That includes Ctrl+C, which skips catch blocks. An error
        that escapes after the run started carries the ApplyResult in
        Exception.Data['ApplyResult'].
    #>
    [CmdletBinding()]
    [OutputType('Tenure.ApplyResult')]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Cmdlet,
        [switch]$DryRun,
        [switch]$Force,
        [switch]$AllowStale,
        [switch]$Resume,
        [switch]$ContinueOnError,
        [switch]$AllowDestructive,
        [timespan]$MaxAge = [timespan]::FromHours(24),
        [AllowNull()][AllowEmptyString()][string]$AuditPath,
        [AllowNull()][AllowEmptyString()][string]$PlanFile,
        [AllowNull()][object]$Policy,
        [AllowNull()][AllowEmptyCollection()][string[]]$AssumeFired = @(),
        [bool]$ConfirmSuppressed = $false,
        [bool]$WhatIfMode = $false
    )

    # Preflight. Nothing below may write to the tenant, the audit log or the plan file.
    Assert-TenurePlanShape -Plan $Plan
    $integrity = Assert-TenurePlanIntegrity -Plan $Plan
    if ($Plan.Status -ceq 'Applied') {
        throw (New-TenureError -Id 'Tenure.Plan.AlreadyApplied' -Message "Plan $($Plan.PlanId) is already Applied. Build a new plan to make further changes." -Category InvalidOperation)
    }
    if ($MaxAge -le [timespan]::Zero) {
        throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message 'MaxAge must be a positive time span.' -Category InvalidArgument)
    }
    $createdAt = ConvertFrom-TenureTimestamp -Value $Plan.CreatedAt
    if ($null -eq $createdAt) {
        throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message 'Invalid plan: CreatedAt is not a date.' -Category InvalidData)
    }
    $age = [datetime]::UtcNow - $createdAt
    if (-not $AllowStale) {
        if ($age -gt $MaxAge) {
            throw (New-TenureError -Id 'Tenure.Plan.Stale' -Message ("Plan {0} was created {1:N1} hours ago, more than -MaxAge ({2:N1} hours). Re-plan, or use -AllowStale after reviewing it." -f $Plan.PlanId, $age.TotalHours, $MaxAge.TotalHours) -Category InvalidOperation)
        }
        if ($age -lt (-$script:FutureSkew)) {
            throw (New-TenureError -Id 'Tenure.Plan.Stale' -Message "Plan $($Plan.PlanId) has a CreatedAt in the future. Re-plan, or use -AllowStale after reviewing it." -Category InvalidOperation)
        }
    }

    $providers = @{}
    foreach ($step in @($Plan.Steps)) {
        if (-not $providers.ContainsKey($step.Provider)) {
            $providers[$step.Provider] = Get-TenureProviderDefinition -Name $step.Provider
        }
        $provider = $providers[$step.Provider]
        $stepKind = Get-TenureApplyMember -InputObject $step -Name 'Kind'
        if ($null -ne $stepKind -and [string]$stepKind -cne $provider.Kind) {
            throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message "Invalid plan: step $($step.Id) has Kind '$stepKind' but provider '$($provider.Name)' is '$($provider.Kind)'. Re-plan with this module version." -Category InvalidData)
        }
    }
    # The subject-protection lookup reads Graph, whatever backends the steps use.
    foreach ($backend in @(@($providers.Values | ForEach-Object { $_.Backend }) + 'Graph' | Sort-Object -Unique)) {
        Assert-TenureConnection -Backend $backend
    }
    Assert-TenurePlanTenant -Plan $Plan

    $assumedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($assumedId in @($AssumeFired | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $named = @($Plan.Steps | Where-Object { $_.Id -ceq $assumedId.Trim() })
        if ($named.Count -eq 0 -or $providers[[string]$named[0].Provider].Kind -cne 'Invoke') {
            throw (New-TenureError -Id 'Tenure.Apply.InvalidArgument' -Message "-AssumeFired '$assumedId' does not name an Invoke step of plan $($Plan.PlanId). Name the step id (for example S05) of an Invoke step the run stopped at." -Category InvalidArgument -Data @{ StepId = $assumedId })
        }
        [void]$assumedIds.Add($assumedId.Trim())
    }

    $planPolicyHash = Get-TenureApplyMember -InputObject $Plan -Name 'PolicyHash'
    Assert-TenurePlanPolicy -Plan $Plan -Policy $Policy

    $auditFile = Resolve-TenureAuditPath -Path $AuditPath
    if (-not $integrity.SubjectIdBound) {
        # Read without the lock: the evidence is append-only, and this must be settled before PlanStarted.
        Assert-TenureSubjectIdOrigin -Plan $Plan -History (Get-TenureAuditHistory -Line @(Read-TenureAuditFile -Path $auditFile) -PlanId ([string]$Plan.PlanId) -Path $auditFile)
    }
    $protectedUsers = Get-TenurePlanProtectedUser -Plan $Plan -Policy $Policy
    Assert-TenurePlanProtection -Plan $Plan -Providers $providers -ProtectedUsers $protectedUsers
    $work = $Plan
    if ($WhatIfMode) { $work = Copy-TenurePlanForWhatIf -Plan $Plan }

    $actor = [ordered]@{ Account = $null; TenantId = $null }
    if ($null -ne $script:Session) {
        if ($script:Session.PSObject.Properties['Account']) { $actor.Account = $script:Session.Account }
        if ($script:Session.PSObject.Properties['TenantId']) { $actor.TenantId = $script:Session.TenantId }
    }

    $run = @{
        Cmdlet            = $Cmdlet
        Mode              = $(if ($DryRun) { 'DryRun' } else { 'Apply' })
        DryRun            = [bool]$DryRun
        Force             = [bool]$Force
        Resume            = [bool]$Resume
        ContinueOnError   = [bool]$ContinueOnError
        AllowDestructive  = [bool]$AllowDestructive
        ConfirmSuppressed = $ConfirmSuppressed
        WhatIf            = $WhatIfMode
        Policy            = $Policy
        ProtectedUsers    = $protectedUsers
        AssumeFired       = $assumedIds
        Providers         = $providers
        Outcomes          = @{}
        StepTarget        = $null
        StepAfter         = $null
        Secrets           = @{}
        Simulated         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        AuditPath         = $auditFile
        PlanFile          = $(if ($WhatIfMode) { $null } else { $PlanFile })
        Actor             = $actor
        History           = $null
        AuditHead         = $null
        SetStarted        = $false
        PersistWarned     = $false
        FinishAttempted   = $false
        Result            = $null
    }

    $stepsById = @{}
    foreach ($step in @($work.Steps)) { $stepsById[$step.Id] = $step }
    $planTarget = ConvertTo-TenureTargetTable -Target $work.Subject

    # Start the run: read this plan's history (under the audit lock when writing) and
    # refuse while an earlier run is still open.
    if ($WhatIfMode) {
        $run.History = Get-TenureAuditHistory -Line @(Read-TenureAuditFile -Path $auditFile) -PlanId ([string]$work.PlanId) -Path $auditFile
        Assert-TenureRunAllowed -History $run.History -PlanId ([string]$work.PlanId) -Path $auditFile -Resume:$Resume -Force:$Force
    } else {
        $options = [ordered]@{
            DryRun            = [bool]$DryRun
            Force             = [bool]$Force
            AllowStale        = [bool]$AllowStale
            Resume            = [bool]$Resume
            ContinueOnError   = [bool]$ContinueOnError
            AllowDestructive  = [bool]$AllowDestructive
            ConfirmSuppressed = $ConfirmSuppressed
            AssumeFired       = [string[]]@($assumedIds | Sort-Object)
            PolicyGiven       = ($null -ne $Policy)
        }
        # What was asked for and what the reviewer was warned about travel with the run, so the log alone
        # shows, for example, that a plan ran with -SkipMailbox.
        $start = Open-TenureAuditRun -Path $auditFile -PlanId ([string]$work.PlanId) -Resume:$Resume -Force:$Force -Entry @{
            PlanId    = $work.PlanId
            Operation = $work.Operation
            Target    = $planTarget
            Actor     = $actor
            Outcome   = 'PlanStarted'
            Observed  = [ordered]@{
                Status     = $work.Status
                Steps      = @($work.Steps).Count
                CreatedAt  = $createdAt.ToString('o')
                CreatedBy  = Get-TenureApplyMember -InputObject $work -Name 'CreatedBy'
                PolicyHash = $planPolicyHash
                Integrity  = Get-TenureApplyMember -InputObject $work -Name 'Integrity'
                Inputs     = Get-TenureApplyMember -InputObject $work -Name 'Inputs'
                Warnings   = [string[]]@(Get-TenureApplyMember -InputObject $work -Name 'Warnings' | Where-Object { $null -ne $_ })
                Options    = $options
            }
            Mode      = $run.Mode
        }
        $run.History = $start.History
        $run.AuditHead = [ordered]@{ Seq = $start.Entry.Seq; Hash = $start.Entry.Hash }
    }
    Write-Verbose ("Plan {0}: {1} step(s), mode {2}{3}; audit log {4}." -f $work.PlanId, @($work.Steps).Count, $run.Mode, $(if ($WhatIfMode) { ' (WhatIf)' } else { '' }), $auditFile)

    $completed = $false
    $result = $null
    try {
        try {
            # The plan file must be writable before anything changes.
            if ($run.PlanFile) { Save-TenurePlanFile -Plan $work -Path $run.PlanFile }

            foreach ($step in @($work.Steps)) {
                $provider = $providers[$step.Provider]
                $run.SetStarted = $false
                $run.StepTarget = $null
                $run.StepAfter = $null
                $committed = $false
                $at = [datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $outcome = Invoke-TenurePlanStep -Step $step -Plan $work -Provider $provider -StepsById $stepsById -Run $run
                    if ($outcome.Status -ceq 'Pending') {
                        $committed = $true
                        if ($outcome.Simulated) { [void]$run.Simulated.Add($step.Id) }
                        Write-Verbose "[$($step.Id)] $($step.Provider): Pending (not confirmed; nothing written)."
                        continue
                    }
                    Complete-TenurePlanStep -Plan $work -Step $step -Outcome $outcome -At $at -DurationMs $stopwatch.ElapsedMilliseconds -Run $run
                    $committed = $true
                    $run.Outcomes[[string]$step.Id] = [string]$step.Status
                    if ($outcome.Status -ceq 'Declined') {
                        # The operator said no. The plan file records it, so a status from an earlier run cannot stand
                        # in for this answer; like -WhatIf, a decline writes nothing to the audit log.
                        Write-Verbose "[$($step.Id)] $($step.Provider): Declined (nothing changed)."
                        Save-TenurePlanProgress -Plan $work -Run $run
                        continue
                    }
                    $labelTarget = if ($null -ne $outcome.Target) { $outcome.Target } else { ConvertTo-TenureTargetTable -Target $step.Target }
                    $message = "[$($step.Id)] $($step.Provider) on $(Get-TenureTargetLabel -Target $labelTarget): $($step.Status)"
                    if ($step.Result['Note']) { $message += ". $($step.Result['Note'])" }
                    if ($step.Result['Error']) { $message += ". $($step.Result['Error'])" }
                    Write-Verbose $message
                    if ($outcome.Warning) { Write-Warning (Hide-TenureSecretText -Text $outcome.Warning -Secrets $run.Secrets) }
                    if (-not $WhatIfMode) {
                        $auditTarget = if ($null -ne $outcome.Target) { $outcome.Target } else { $step.Target }
                        $auditAfter = if ($null -ne $outcome.Target) { $outcome.After } else { $step.After }
                        $null = Write-TenureStepAudit -Plan $work -Step $step -Run $run -Target $auditTarget -After $auditAfter
                    }
                    Save-TenurePlanProgress -Plan $work -Run $run
                    Clear-TenureSecretError -Secrets $run.Secrets
                    if ($outcome.Stop) {
                        Write-Verbose "[$($step.Id)] stopping: later steps stay Pending."
                        break
                    }
                } finally {
                    if (-not $committed -and $run.SetStarted) {
                        # Interrupted (for example Ctrl+C) after Set was called: the change
                        # may or may not have happened. Record that, best effort.
                        $step.Status = 'Failed'
                        $step.Result = [ordered]@{
                            At         = $at
                            DurationMs = $stopwatch.ElapsedMilliseconds
                            Observed   = $null
                            Error      = 'Tenure.Apply.Interrupted: the run stopped while Set was in progress; check the target before resuming.'
                            Note       = 'interrupted during Set'
                            Attempted  = $true
                            Uncertain  = $true
                            Assumed    = $false
                        }
                        if (-not $WhatIfMode) {
                            try {
                                $null = Write-TenureStepAudit -Plan $work -Step $step -Run $run -Target $run.StepTarget -After $run.StepAfter
                            } catch {
                                Write-Verbose "[$($step.Id)] could not record the interruption in the audit log."
                            }
                        }
                    }
                }
            }
        } catch {
            # Something escaped a step: an audit write failed, a prompt could not be shown,
            # or an engine bug. Statuses stay accurate and secrets are never lost.
            $caught = $_
            $work.Status = Get-TenurePlanStatus -Plan $work
            $run.Result = New-TenureApplyResult -Plan $work -Secrets $run.Secrets -AuditPath $auditFile -AuditHead $run.AuditHead
            $errorId = Get-TenureErrorId -ErrorRecord $caught
            if ($errorId -and $errorId.StartsWith('Tenure.Audit.', [System.StringComparison]::Ordinal)) {
                throw (New-TenureError -Id $errorId -Message "The audit log could not be written after the run started, so the run stopped. Step statuses in the plan are accurate; generated secrets are in Exception.Data['ApplyResult'].Secrets and Get-TenureApplyResult. Cause: $($caught.Exception.Message)" -Category WriteError -Data @{ ApplyResult = $run.Result; Path = $auditFile } -Inner $caught)
            }
            try {
                $caught.Exception.Data['ApplyResult'] = $run.Result
            } catch {
                Write-Verbose 'Could not attach the partial ApplyResult to the error.'
            }
            throw $caught
        }

        $work.Status = Get-TenurePlanStatus -Plan $work
        if (-not $WhatIfMode) {
            $run.FinishAttempted = $true
            try {
                $null = Write-TenurePlanFinished -Plan $work -Run $run -Target $planTarget
            } catch {
                $caught = $_
                $run.Result = New-TenureApplyResult -Plan $work -Secrets $run.Secrets -AuditPath $auditFile -AuditHead $run.AuditHead
                $errorId = Get-TenureErrorId -ErrorRecord $caught
                if (-not $errorId) { $errorId = 'Tenure.Audit.Unwritable' }
                throw (New-TenureError -Id $errorId -Message "The PlanFinished audit entry could not be written. Step statuses in the plan are accurate; generated secrets are in Exception.Data['ApplyResult'].Secrets and Get-TenureApplyResult. Cause: $($caught.Exception.Message)" -Category WriteError -Data @{ ApplyResult = $run.Result; Path = $auditFile } -Inner $caught)
            }
        }
        Save-TenurePlanProgress -Plan $work -Run $run
        Clear-TenureSecretError -Secrets $run.Secrets
        $result = New-TenureApplyResult -Plan $work -Secrets $run.Secrets -AuditPath $auditFile -AuditHead $run.AuditHead
        $run.Result = $result
        if (-not $WhatIfMode) { $script:LastApplyResult = $result }
        $completed = $true
    } finally {
        if (-not $completed) {
            # Abnormal end, including Ctrl+C (which runs finally blocks but not catch
            # blocks). The order matters: keep the secrets first, then close the run in
            # the audit log, then save the plan file.
            $work.Status = Get-TenurePlanStatus -Plan $work
            if ($null -eq $run.Result) { $run.Result = New-TenureApplyResult -Plan $work -Secrets $run.Secrets -AuditPath $auditFile -AuditHead $run.AuditHead }
            if (-not $WhatIfMode) {
                $script:LastApplyResult = $run.Result
                if (-not $run.FinishAttempted) {
                    $run.FinishAttempted = $true
                    try {
                        $null = Write-TenurePlanFinished -Plan $work -Run $run -Target $planTarget -Note 'the run did not complete normally (stopped or failed); see the step entries above'
                        $run.Result.AuditHead = $run.AuditHead
                    } catch {
                        Write-Verbose 'Could not write the PlanFinished entry after an abnormal end.'
                    }
                }
            }
            Save-TenurePlanProgress -Plan $work -Run $run
            try {
                Clear-TenureSecretError -Secrets $run.Secrets
            } catch {
                Write-Verbose 'Could not clean secrets out of $Error.'
            }
        }
    }

    $summary = $result.Summary
    Write-Information -MessageData ("Plan {0} {1}{2}: {3} applied, {4} skipped, {5} failed, {6} dry run, {7} drifted, {8} refused, {9} declined, {10} pending. Audit: {11}" -f $work.PlanId, $work.Status, $(if ($WhatIfMode) { ' (WhatIf, nothing written)' } else { '' }), $summary.Applied, $summary.Skipped, $summary.Failed, $summary.DryRun, $summary.Drifted, $summary.Refused, $summary.Declined, $summary.Pending, $auditFile) -Tags 'Tenure', 'Summary'
    $result
}

function Test-TenurePlanCore {
    <#
    .SYNOPSIS
        Read-only comparison of a plan with live state (the logic behind Test-TenurePlan).
    .DESCRIPTION
        Classifies each step the way Invoke-TenurePlan would treat it right now: Drifted
        (the live state differs from the plan's Fingerprint), Satisfied (nothing to do: Test
        is true), Unverified (an Invoke step that only the plan file calls done; this command
        does not read the audit log, which is what Invoke-TenurePlan believes) or Pending
        (the rest). A State step whose desired state holds is Satisfied before any drift
        verdict, as in Invoke-TenurePlan. A Check whose input a step of this plan changed (a
        step of a provider in its AffectedBy that the plan file calls Applied) is compared
        with the live state: Satisfied when it passes, Drifted when it does not.
        Calls Get and Test only: no Set, no ShouldProcess, no audit entry, no change to
        the plan. A step whose state cannot be read is Pending, with a warning.

        Before any step it refuses what Invoke-TenurePlan would refuse before step 1: a plan
        whose integrity value does not match (Tenure.Plan.Tampered), a plan from another
        tenant or naming none, a -Policy whose hash differs from the plan's or a plan with no
        recorded policy and no -Policy, and a plan that would change the signed-in account or
        a protected user (Tenure.Plan.Refused). The protected users come from -Policy, or from
        the list the plan recorded when no -Policy is given.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [AllowNull()][object]$Policy
    )

    Assert-TenurePlanShape -Plan $Plan
    $null = Assert-TenurePlanIntegrity -Plan $Plan
    $providers = @{}
    foreach ($step in @($Plan.Steps)) {
        if (-not $providers.ContainsKey($step.Provider)) { $providers[$step.Provider] = Get-TenureProviderDefinition -Name $step.Provider }
    }
    foreach ($backend in @(@($providers.Values | ForEach-Object { $_.Backend }) + 'Graph' | Sort-Object -Unique)) {
        Assert-TenureConnection -Backend $backend
    }
    Assert-TenurePlanTenant -Plan $Plan
    Assert-TenurePlanPolicy -Plan $Plan -Policy $Policy
    $protectedUsers = Get-TenurePlanProtectedUser -Plan $Plan -Policy $Policy
    Assert-TenurePlanProtection -Plan $Plan -Providers $providers -ProtectedUsers $protectedUsers

    $drifted = [System.Collections.Generic.List[object]]::new()
    $satisfied = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.List[object]]::new()
    $unverified = [System.Collections.Generic.List[object]]::new()
    $subjectId = Get-TenureApplyMember -InputObject $Plan.Subject -Name 'Id'

    foreach ($step in @($Plan.Steps)) {
        $provider = $providers[$step.Provider]
        $kind = $provider.Kind
        $previous = $step.Status
        # Only the file says so; Invoke-TenurePlan skips such a step only when the audit log agrees.
        if ($kind -ceq 'Invoke' -and ($previous -ceq 'Applied' -or $previous -ceq 'Skipped')) { $unverified.Add($step); continue }

        $resolved = Resolve-TenureStepPlaceholder -Step $step -SubjectId $subjectId
        if ($resolved.Unresolved) { $pending.Add($step); continue }
        $context = @{ Policy = $Policy; ProtectedUsers = $protectedUsers; Subject = $Plan.Subject; Session = $script:Session; Secrets = @{}; StepId = $step.Id; Mode = 'DryRun' }
        $context = Get-TenureStepReadContext -Provider $provider -Context $context -After $resolved.After

        try {
            $current = $null
            try {
                $current = Invoke-TenureProviderBlock -Block $provider.Get -ArgumentList @($resolved.Target, $context)
            } catch {
                if ((Get-TenureErrorId -ErrorRecord $_) -cne 'Tenure.Provider.TargetNotFound' -or $step.Action -cne 'Create') { throw }
            }
            if ($kind -ceq 'State' -and $step.Action -cne 'Create' -and (Invoke-TenureProviderTest -Provider $provider -Current $current -Desired $resolved.After)) {
                $satisfied.Add($step)
                continue
            }
            if ($kind -ceq 'Check' -and @($provider.AffectedBy).Count -gt 0) {
                $affecting = @($Plan.Steps | Where-Object { $_.Id -cne $step.Id -and @($provider.AffectedBy) -ccontains [string]$_.Provider -and $_.Status -ceq 'Applied' })
                if ($affecting.Count -gt 0) {
                    if (Invoke-TenureProviderTest -Provider $provider -Current $current -Desired $resolved.After) { $satisfied.Add($step) } else { $drifted.Add($step) }
                    continue
                }
            }
            if (Test-TenureStepDrift -Step $step -Target $resolved.Target -Current $current -SubjectId $subjectId) {
                $drifted.Add($step)
                continue
            }
            if (($kind -ceq 'State' -or $kind -ceq 'Check') -and (Invoke-TenureProviderTest -Provider $provider -Current $current -Desired $resolved.After)) {
                $satisfied.Add($step)
                continue
            }
            $pending.Add($step)
        } catch {
            Write-Warning "[$($step.Id)] $($step.Provider): could not compare with live state ($(Format-TenureErrorText -ErrorRecord $_)); counted as Pending."
            $pending.Add($step)
        }
    }

    [pscustomobject]@{
        PSTypeName = 'Tenure.PlanTestResult'
        Drifted    = $drifted.ToArray()
        Satisfied  = $satisfied.ToArray()
        Pending    = $pending.ToArray()
        Unverified = $unverified.ToArray()
    }
}
