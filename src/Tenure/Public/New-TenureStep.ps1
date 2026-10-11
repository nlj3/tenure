function New-TenureStep {
    <#
    .SYNOPSIS
        Builds one plan step: snapshots current state through a provider and decides the action.
    .DESCRIPTION
        Looks up the provider, validates the target, reads the current state with the
        provider's Get (the snapshot, stored as Before and fingerprinted), and asks the
        provider's Test whether the desired state already holds. The step's Fingerprint is
        a hash of the target's Kind and Id together with Before, so the apply engine can tell
        that the object, or its state, has changed. It is never empty: with no snapshot
        (Before $null) it binds the target as "absent" for a Create, or as the user created
        earlier in the plan for a {{subjectId}} target.
        The Action follows from that:

        State provider: NoOp when Test is true, otherwise Update (Create when there is no
        current state; Remove for a provider whose Actions allow Remove but not Update, such
        as DirectoryRole.Member). -Action replaces Update and Create but never overrides NoOp.
        Invoke provider: Invoke (or -Action when given). Test is not called.
        Check provider: NoOp when Test is true, otherwise Check.
        An -Action the provider's Actions do not list is Tenure.Step.Invalid, and so is a
        target that exists but does not match for a provider that can only create.

        Target.Kind must be the kind the provider acts on (its TargetKind, see
        Get-TenureProvider), or Tenure.Step.InvalidTarget: the apply engine reads the
        account a step changes from the provider, and refuses a plan whose labels disagree.
        For a membership provider (TargetKind group or role) the snapshot is the membership
        of the user in Desired.userId, the user the step changes, whatever subject -Context
        names.

        If Get throws Tenure.Provider.TargetNotFound the error is rethrown, unless
        -AllowMissing is set, in which case Before is $null and the step is a Create.
        Use -SkipSnapshot when the target cannot exist yet: a Create, or a step whose
        Target.Id is {{subjectId}} (a user created earlier in the plan). -Action is then
        required and neither Get nor Test is called; any other target is Tenure.Step.Invalid.

        Risk is the provider's Risk, raised (never lowered) by -Risk. Reason is -Reason, or
        the provider's Describe text. The step carries a Key chosen by the caller so
        -DependsOn can name other steps before ids exist; New-TenurePlan turns keys into ids.
    .PARAMETER Provider
        Registered provider name, for example 'User.SignIn'.
    .PARAMETER Target
        Hashtable with Kind (user, group, device, mailbox, drive or role), Id and Name. Id is a
        non-empty string; for a mailbox or drive provider it is the owner's Entra object id (an
        alias or address is Tenure.Step.InvalidTarget). Id may be the placeholder {{subjectId}}
        (any letter case), but only together with -SkipSnapshot and -Action: the provider's Get
        is never called with the placeholder.
    .PARAMETER Desired
        The desired state, stored as After. Must never contain a secret. A userId in it must be a
        non-empty string (Tenure.Step.Invalid otherwise).
    .PARAMETER Key
        Stable key other steps use in -DependsOn. Default: a new guid.
    .PARAMETER Reason
        Human-readable reason. Default: the provider's Describe output.
    .PARAMETER DependsOn
        Keys of the steps this one depends on.
    .PARAMETER Context
        Passed to the provider scriptblocks. Missing keys default to Policy, Subject and
        Session $null, Secrets @{} and Mode 'Plan'.
    .PARAMETER Risk
        Raises the provider's risk. A lower value is ignored.
    .PARAMETER AllowMissing
        Treat Tenure.Provider.TargetNotFound as "does not exist yet" (a Create).
    .PARAMETER SkipSnapshot
        Do not call Get or Test. Requires -Action, and only for a Create or a {{subjectId}} target.
    .PARAMETER Action
        Create, Update, Remove or Invoke. See the description for how it combines with Test.
    .EXAMPLE
        New-TenureStep -Provider 'User.SignIn' -Target @{ Kind = 'user'; Id = $user.Id; Name = $user.UserPrincipalName } -Desired @{ accountEnabled = $false } -Key 'disable'

        Snapshots the account and returns an Update step, or NoOp when it is already disabled.
    .EXAMPLE
        New-TenureStep -Provider 'User.Manager' -Target @{ Kind = 'user'; Id = '{{subjectId}}'; Name = 'New hire' } -Desired @{ managerId = $manager.Id } -SkipSnapshot -Action Update -DependsOn 'create'

        A step for a user that does not exist yet: the apply engine fills in the id once the create step has run.
    .OUTPUTS
        Tenure.Step
        Id is $null until New-TenurePlan assigns it. Errors: Tenure.Provider.NotRegistered,
        Tenure.Step.InvalidTarget, Tenure.Step.Invalid, and any error the provider's Get
        throws other than an allowed TargetNotFound.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Step')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Reads state through the provider Get and returns an in-memory object; changes no state.')]
    param(
        [Parameter(Mandatory)]
        [string]$Provider,

        [Parameter(Mandatory)]
        [hashtable]$Target,

        [AllowNull()]
        [object]$Desired,

        [string]$Key,

        [string]$Reason,

        [string[]]$DependsOn = @(),

        [hashtable]$Context,

        [ValidateSet('Low', 'Medium', 'High', 'Destructive')]
        [string]$Risk,

        [switch]$AllowMissing,

        [switch]$SkipSnapshot,

        [ValidateSet('Create', 'Update', 'Remove', 'Invoke')]
        [string]$Action
    )

    $definition = Get-TenureProviderDefinition -Name $Provider
    Assert-TenureStepTarget -Target $Target
    # The provider decides what kind of object it acts on; a target labelled otherwise would mislead the apply
    # engine's protection check, so it is refused here, and again by the engine.
    if ([string]$Target['Kind'] -cne $definition.TargetKind) {
        throw (New-TenureError -Id 'Tenure.Step.InvalidTarget' -Message "Provider '$($definition.Name)' acts on a $($definition.TargetKind), but the target's Kind is '$($Target['Kind'])'. Use Kind '$($definition.TargetKind)'." -Category InvalidArgument -Data @{ Provider = $definition.Name; Kind = [string]$Target['Kind'] })
    }
    # Identifiers are strings, and a mailbox or drive is named by its owner's object id (Get-TenureStepIdentifierProblem).
    $problem = Get-TenureStepIdentifierProblem -Target $Target -After $null -TargetKind $definition.TargetKind
    if ($problem) {
        throw (New-TenureError -Id 'Tenure.Step.InvalidTarget' -Message "Invalid step target for '$($definition.Name)': $problem." -Category InvalidArgument -Data @{ Provider = $definition.Name })
    }
    $problem = Get-TenureStepIdentifierProblem -Target $Target -After $Desired -TargetKind $definition.TargetKind
    if ($problem) {
        throw (New-TenureError -Id 'Tenure.Step.Invalid' -Message "Invalid step for '$($definition.Name)': $problem." -Category InvalidArgument -Data @{ Provider = $definition.Name })
    }
    if ($PSBoundParameters.ContainsKey('Action') -and @($definition.Actions) -cnotcontains $Action) {
        throw (New-TenureError -Id 'Tenure.Step.Invalid' -Message "Provider '$($definition.Name)' does not allow Action '$Action' (it allows $(@($definition.Actions) -join ', '))." -Category InvalidArgument)
    }

    # The placeholder stands for a user that does not exist yet; reading it from the tenant is meaningless.
    if (-not $SkipSnapshot -and ([string](Get-TenureProperty -InputObject $Target -Name 'Id')).Trim() -ieq '{{subjectId}}') {
        throw (New-TenureError -Id 'Tenure.Step.Invalid' -Message 'Target.Id is the placeholder {{subjectId}}, which stands for a user created earlier in the plan and cannot be read from the tenant. A step on that target needs -SkipSnapshot and -Action.' -Category InvalidArgument)
    }

    $hasAction = $PSBoundParameters.ContainsKey('Action')
    if ($PSBoundParameters.ContainsKey('Key')) {
        if ([string]::IsNullOrWhiteSpace($Key)) {
            throw (New-TenureError -Id 'Tenure.Step.Invalid' -Message '-Key must not be empty.' -Category InvalidArgument)
        }
    } else {
        $Key = [guid]::NewGuid().ToString()
    }
    if ($SkipSnapshot -and -not $hasAction) {
        throw (New-TenureError -Id 'Tenure.Step.Invalid' -Message '-SkipSnapshot requires -Action: without a snapshot the step cannot work out whether to create, update or remove.' -Category InvalidArgument)
    }
    # Without a snapshot there is no state to check for drift. That is only right for a target that must not
    # exist yet (a Create, whose fingerprint means "absent") or for the user an earlier step of the plan creates.
    if ($SkipSnapshot -and $Action -cne 'Create' -and ([string](Get-TenureProperty -InputObject $Target -Name 'Id')).Trim() -ine '{{subjectId}}') {
        throw (New-TenureError -Id 'Tenure.Step.Invalid' -Message '-SkipSnapshot is only for a Create step or a step whose Target.Id is {{subjectId}}; any other step needs a snapshot so the apply engine can detect drift.' -Category InvalidArgument)
    }

    $effectiveContext = @{ Policy = $null; Subject = $null; Session = $null; Secrets = @{}; Mode = 'Plan' }
    if ($PSBoundParameters.ContainsKey('Context') -and $null -ne $Context) {
        foreach ($contextKey in $Context.Keys) { $effectiveContext[$contextKey] = $Context[$contextKey] }
    }
    # A membership step (a group or role provider) is about the user in Desired.userId; its snapshot is that user's
    # membership, the same read the apply engine makes before and after Set.
    $effectiveContext = Get-TenureStepReadContext -Provider $definition -Context $effectiveContext -After $Desired

    # Snapshot: the provider Get is the only thing that reads tenant state.
    $before = $null
    if (-not $SkipSnapshot) {
        try {
            $before = & $definition.Get $Target $effectiveContext
        } catch {
            if ($AllowMissing -and (Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Provider.TargetNotFound') {
                $before = $null
            } else {
                throw
            }
        }
    }
    $fingerprint = Get-TenureStepFingerprint -Target $Target -Before $before

    # Action. NoOp is exactly "Test(Before, After) was true" (SPEC 2.3).
    $kind = $definition.Kind
    $resolvedAction = $null
    if ($SkipSnapshot) {
        $resolvedAction = if ($kind -eq 'Check') { 'Check' } else { $Action }
    } elseif ($kind -eq 'Invoke') {
        $resolvedAction = if ($hasAction) { $Action } else { 'Invoke' }
    } else {
        $satisfied = [bool](& $definition.Test $before $Desired)
        if ($satisfied) {
            $resolvedAction = 'NoOp'
        } elseif ($kind -eq 'Check') {
            $resolvedAction = 'Check'
        } elseif ($hasAction) {
            $resolvedAction = $Action
        } else {
            # The first action the provider allows: Create for a target that does not exist, otherwise Update,
            # or Remove for a provider that only takes things away (DirectoryRole.Member).
            $candidates = if ($null -eq $before) { @('Create') } else { @('Update', 'Remove') }
            $resolvedAction = @($candidates | Where-Object { @($definition.Actions) -ccontains $_ })[0]
            if ($null -eq $resolvedAction) {
                $state = if ($null -eq $before) { 'does not exist' } else { 'exists and does not match the desired state' }
                throw (New-TenureError -Id 'Tenure.Step.Invalid' -Message "The target of provider '$($definition.Name)' $state, and the provider allows only $(@($definition.Actions) -join ', ')." -Category InvalidArgument)
            }
        }
    }

    # Risk can be raised by the caller, never lowered.
    $rank = @{ Low = 0; Medium = 1; High = 2; Destructive = 3 }
    $effectiveRisk = $definition.Risk
    if ($PSBoundParameters.ContainsKey('Risk')) {
        if ($rank[$Risk] -gt $rank[$effectiveRisk]) {
            $effectiveRisk = $Risk
        } elseif ($rank[$Risk] -lt $rank[$effectiveRisk]) {
            Write-Verbose ("Ignoring -Risk {0} for {1}: the provider's own risk {2} is higher and risk is never lowered." -f $Risk, $Provider, $effectiveRisk)
        }
    }

    $text = if ($PSBoundParameters.ContainsKey('Reason') -and -not [string]::IsNullOrWhiteSpace($Reason)) {
        $Reason
    } else {
        [string](& $definition.Describe $Target $before $Desired $resolvedAction)
    }

    ConvertTo-TenureStep -Field @{
        Id          = $null
        Key         = $Key
        Provider    = $definition.Name
        Kind        = $kind
        Target      = Copy-TenureValue -InputObject $Target
        Action      = $resolvedAction
        Before      = $before
        After       = Copy-TenureValue -InputObject $Desired
        Fingerprint = $fingerprint
        Risk        = $effectiveRisk
        Reversible  = $definition.Reversible
        Reason      = $text
        DependsOn   = $DependsOn
        Status      = 'Pending'
        Result      = $null
    }
}
