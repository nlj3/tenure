function Invoke-TenurePlan {
    <#
    .SYNOPSIS
        Applies a Tenure plan step by step, with drift checks, confirmation, dependency
        order, crash-safe resume and a hash-chained audit log.
    .DESCRIPTION
        Runs the steps of a plan in order (docs/SPEC.md section 5.4). For each step the
        engine checks dependencies, re-reads the live state, refuses on drift (the state
        no longer matches the snapshot the plan was reviewed against), skips steps that
        are already satisfied, asks for confirmation (ConfirmImpact High), calls the
        provider's Set, reads the state back and verifies it.

        Before any step runs the plan is refused when its Integrity value does not match
        its content (Tenure.Plan.Tampered: something in the plan was edited after it was
        built), when a step's Target.Kind or Action is not one its provider declares
        (Tenure.Plan.Invalid), when its file says Applied, when the audit log shows a run of
        it that finished Applied (Tenure.Plan.AlreadyApplied, unless -Force), when it is
        older than -MaxAge, uses a provider that is not registered, needs a backend that is
        not connected, names no tenant or another tenant (Tenure.Plan.WrongTenant), records
        no policy and no -Policy is given (Tenure.Plan.PolicyMissing), or when the audit log
        shows an earlier run of the same plan that started and never finished (pass -Resume
        once you know no other shell is running it). It is also refused
        (Tenure.Plan.Refused) when its subject, or any user a step changes, is the signed-in
        account or a protected user. Which user a step changes comes from its provider
        (Target.Id for a provider that acts on a user, mailbox or drive; After.userId for a
        group or role membership), never from the plan's Target.Kind label, and the check
        does not depend on the plan having a Check.SubjectAllowed step; the protected users
        come from -Policy, or from the list the plan recorded when it was built. A
        PlanStarted entry is then written, with the plan's inputs, warnings and policy hash,
        so an unwritable audit path stops the run before step 1. Every step outcome except
        Pending and Declined is appended to the audit log, followed by a PlanFinished entry
        with the summary.

        A State step whose desired state already holds is Skipped before any drift check:
        an earlier step of the same plan may have moved the state its snapshot describes (a
        sign-in disable takes the user out of a dynamic group). A check whose input an
        earlier step of this plan changed (the audit log shows a step of a provider in the
        check's AffectedBy applied) is evaluated against the live state instead of its
        snapshot: passing it is Skipped, failing it stops the run. A dependency counts as
        met only when this run applied or skipped it, or when a live read shows its desired
        state holds now; a status an earlier run left in the plan is not enough. A step
        whose confirmation is declined is recorded Declined in the plan (not in the audit
        log). A membership step reads the user it changes (After.userId), before and after
        Set.

        The plan object you pass in is updated in place (step Status and Result,
        Subject.Id after a Create, and Plan.Status) and is also returned as Plan on the
        result. A string value in a step's Target or After that is exactly {{subjectId}}
        (any case, surrounding spaces ignored, at any depth) is replaced with the subject's
        id, in a copy, every time the step runs; the plan keeps the placeholder. A value
        that only contains that text is left alone, and a step that still holds a
        placeholder because the subject has no id yet is refused (reported as DryRun in a
        dry run).

        Crash safety. When -OutFile is given, or -Plan is a path (then -OutFile defaults
        to that path), the plan file is rewritten after every status change and just
        before every Set. Invoke, Create and Destructive steps get an Attempting audit
        entry before their Set runs. On a later run, an Invoke step that the audit log
        shows as fired is skipped. One that may have fired (Attempting with no outcome,
        interrupted, or marked done in the plan file with no record in the audit log) runs
        again under -Resume when its provider is Repeatable (session
        revoke, device retire and wipe, meeting cancellation); any other stops the run at
        that step until you check it and name it in -AssumeFired, which is recorded in the
        audit log, and a later run, even from a plan file that never saw that run, keeps the
        mark. A plan with an assumed step never ends Applied. A Create step whose
        Attempting entry is in the audit log adopts the account it finds instead of
        creating it again, but only when that attempt did not end in a refused request and
        the account was created during it (between the Attempting entry and the next entry
        for the step or the run's end); a user-absent check that passed in that earlier run
        is not checked again. If the run is stopped with Ctrl+C, the step in progress is recorded
        as interrupted, the run is closed in the audit log, the plan file is saved, and the
        result (with any generated secrets) is kept for Get-TenureApplyResult.

        Generated secrets (passwords, Temporary Access Passes) are returned only as
        SecureString values in the result's Secrets table, keyed by step id. They never
        appear in the plan, the plan file, the audit log, or the verbose stream, and
        error records that echo one are removed from $Error.

        Steps with Risk Destructive are refused when confirmation is suppressed
        (-Confirm:$false or $ConfirmPreference 'None') unless -AllowDestructive is given.
        Without -AllowDestructive, each Destructive step also gets its own yes/no question
        that "Yes to All" never covers; a host that cannot prompt refuses the step. The
        prompts show the provider's own description of the change, worked out from the
        live state, never only the Reason text in the plan. A Check with Severity Refuse
        fails closed: anything but a passing Test stops the plan, regardless of
        -ContinueOnError and -Force. A Create whose target exists now (and that this plan
        never attempted) is Drifted even with -Force.

        Passing -WhatIf to this command writes nothing: no Set, no audit entry, no plan
        file (provider Get calls still read the tenant). The given plan is not changed;
        the result carries a copy with the simulated statuses.

        The audit log must be on a local file system. Its lock is advisory and is not
        honored on network shares or cloud-synced folders (OneDrive, Dropbox, iCloud
        Drive, Google Drive); a warning is shown once per session for those.
    .PARAMETER Plan
        A Tenure.Plan object, or the path of a plan file written by Export-TenurePlan.
    .PARAMETER DryRun
        Evaluates every step against live state and records DryRun outcomes (audit Mode
        'DryRun') without calling Set or prompting.
    .PARAMETER Force
        Applies steps whose live state drifted from the plan snapshot (each such step
        notes 'drift overridden by -Force'), and applies a plan the audit log shows finished
        Applied once already. It does not override the plan age, a Refuse check, a Create
        whose target exists, the integrity check, a plan file that says Applied, or an
        earlier run that is still open.
    .PARAMETER AllowStale
        Applies a plan older than -MaxAge, or one whose CreatedAt is in the future.
    .PARAMETER Resume
        Continues after an earlier run of the same plan that never finished, and runs
        again an Invoke step that may have fired in that run when its provider is
        Repeatable. Any other such step stops the run; see -AssumeFired.
    .PARAMETER AssumeFired
        Step ids of Invoke steps that may have fired in an earlier run (the run stopped at
        them) and that you have checked did fire. Each is recorded as Skipped with
        Result.Assumed, noted in the audit log, and the plan can then never end Applied.
        Naming a step that is not in doubt refuses that step.
    .PARAMETER ContinueOnError
        Continues after a Failed, Drifted or Refused step instead of stopping. Steps that
        depend on a step that did not apply are still refused. A Refuse check stops the
        plan regardless.
    .PARAMETER AllowDestructive
        Allows Destructive steps to run without their own confirmation question, and when
        confirmation is suppressed.
    .PARAMETER MaxAge
        The oldest plan accepted without -AllowStale. Defaults to 24 hours.
    .PARAMETER AuditPath
        The audit log file. Defaults to $env:TENURE_AUDIT_PATH, then ~/.tenure/audit.jsonl.
        Must be on a local disk.
    .PARAMETER OutFile
        The plan file to keep up to date during the run. Defaults to -Plan when -Plan is a
        path.
    .PARAMETER Policy
        A Tenure.Policy object or policy file path passed to providers as Context.Policy.
        Refused (Tenure.Plan.PolicyMismatch) when it has no Hash, when its hash differs from
        the plan's PolicyHash, or when the plan records no policy. Optional: without it the
        protected users the plan recorded when it was built are checked, and a plan that
        records none is refused (Tenure.Plan.PolicyMissing). A different administrator from
        the one who built the plan may apply it; the audit log records who did.
    .EXAMPLE
        $plan = New-TenureOffboardPlan -User 'alex@example.com' -Policy ./tenure.policy.json
        Export-TenurePlan -Plan $plan -Path ./alex-offboard.json
        $result = Invoke-TenurePlan ./alex-offboard.json

        Applies a saved plan, prompting before each change and keeping the file up to date.
    .EXAMPLE
        Invoke-TenurePlan ./alex-offboard.json -DryRun -AuditPath ./audit.jsonl

        Checks every step against live state and records the dry run, changing nothing.
    .EXAMPLE
        $result = Invoke-TenurePlan $plan -Confirm:$false -AllowDestructive
        $result.Summary
        $result.Secrets['S02']   # SecureString

        Applies without prompting, including Destructive steps, and reads a generated secret.
    .EXAMPLE
        Invoke-TenurePlan ./alex-offboard.json -Resume

        Continues a run that was stopped with Ctrl+C. A Repeatable step that may have fired
        runs again; any other such step stops the run and names itself.
    .EXAMPLE
        Invoke-TenurePlan ./alex-offboard.json -Resume -AssumeFired S03

        Continues after checking that step S03 (for example a password reset) did fire in
        the interrupted run. The plan then ends PartiallyApplied, not Applied.
    .EXAMPLE
        Invoke-TenurePlan $plan -WhatIf

        Lists what would be changed. No Set is called and nothing is written.
    .OUTPUTS
        Tenure.ApplyResult with Plan, Summary (Applied, Skipped, Failed, DryRun, Drifted,
        Refused, Pending, Declined), Secrets (step id to SecureString), AuditPath and AuditHead
        (Seq and Hash of the last audit entry written, the external anchor for
        Test-TenureAudit).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Tenure.ApplyResult')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object]$Plan,

        [switch]$DryRun,

        [switch]$Force,

        [switch]$AllowStale,

        [switch]$Resume,

        [switch]$ContinueOnError,

        [switch]$AllowDestructive,

        [ValidateScript({ $_ -gt [timespan]::Zero })]
        [timespan]$MaxAge = [timespan]::FromHours(24),

        [string]$AuditPath,

        [string]$OutFile,

        [object]$Policy,

        [string[]]$AssumeFired = @()
    )

    process {
        $planObject = $Plan
        $planPath = $null
        if ($Plan -is [string]) {
            $planPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Plan)
            $planObject = Import-TenurePlan -Path $Plan
        }
        $policyObject = $Policy
        if ($Policy -is [string]) { $policyObject = Get-TenurePolicy -Path $Policy }

        # The same values ShouldProcess will use: -WhatIf / -Confirm set these locally,
        # otherwise they come from the module or global scope.
        $whatIf = [bool]$WhatIfPreference
        $confirmSuppressed = ([string]$ConfirmPreference -eq 'None')
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Confirm') -and -not [bool]$PSCmdlet.MyInvocation.BoundParameters['Confirm']) { $confirmSuppressed = $true }

        $outPath = $planPath
        if (-not [string]::IsNullOrWhiteSpace($OutFile)) { $outPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutFile) }
        if ($outPath) {
            $outDirectory = [System.IO.Path]::GetDirectoryName($outPath)
            if (-not [string]::IsNullOrEmpty($outDirectory) -and -not [System.IO.Directory]::Exists($outDirectory)) {
                throw (New-TenureError -Id 'Tenure.Apply.OutFileUnwritable' -Message "The directory for the plan file '$outPath' does not exist." -Category WriteError)
            }
            if ($whatIf) {
                # Prints the "What if" line only; the file is never written under -WhatIf.
                $null = $PSCmdlet.ShouldProcess($outPath, 'Keep the plan file up to date during the run')
            }
        }

        $core = @{
            Plan              = $planObject
            Cmdlet            = $PSCmdlet
            DryRun            = $DryRun
            Force             = $Force
            AllowStale        = $AllowStale
            Resume            = $Resume
            ContinueOnError   = $ContinueOnError
            AllowDestructive  = $AllowDestructive
            MaxAge            = $MaxAge
            AuditPath         = $AuditPath
            PlanFile          = $outPath
            Policy            = $policyObject
            AssumeFired       = $AssumeFired
            ConfirmSuppressed = $confirmSuppressed
            WhatIfMode        = $whatIf
        }
        Invoke-TenurePlanCore @core
    }
}
