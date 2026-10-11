function Test-TenurePlan {
    <#
    .SYNOPSIS
        Compares a plan with live state and reports which steps drifted, which are
        already satisfied and which would still change something. Read-only.
    .DESCRIPTION
        For every step, reads the current state through the step's provider and
        classifies the step the way Invoke-TenurePlan would treat it now:

        Drifted    - the live state no longer matches the plan's Before snapshot
                     (Fingerprint); Invoke-TenurePlan would refuse the step without -Force.
                     A check whose input an earlier step of the plan changed (by the plan
                     file's statuses) is compared with the live state instead, and is
                     Drifted when it does not pass.
        Satisfied  - nothing to do: Test is already true. A State step whose desired state
                     holds is Satisfied whatever its snapshot says, as Invoke-TenurePlan
                     skips it.
        Unverified - an Invoke step that the plan file calls Applied or Skipped. This
                     command does not read the audit log, so the file is its only evidence;
                     Invoke-TenurePlan skips the step only when the audit log agrees.
        Pending    - the step would still change something (or its state could not be
                     read; a warning says why).

        Calls only provider Get and Test. No Set, no confirmation prompt, no audit entry,
        and the plan object is not changed. The backends the plan needs, and Graph, must be
        connected.

        Like Invoke-TenurePlan, it first refuses a plan whose Integrity value does not match
        its content (Tenure.Plan.Tampered), a step whose Target.Kind or Action its provider
        does not declare (Tenure.Plan.Invalid), a plan that names no tenant or another one
        (Tenure.Plan.WrongTenant), a plan that records no policy when no -Policy is given
        (Tenure.Plan.PolicyMissing), and a plan that would change the signed-in account or a
        protected user (Tenure.Plan.Refused).
    .PARAMETER Plan
        A Tenure.Plan object, or the path of a plan file written by Export-TenurePlan.
    .PARAMETER Policy
        A Tenure.Policy object or policy file path. Refused (Tenure.Plan.PolicyMismatch) when
        it has no Hash, when its hash differs from the plan's PolicyHash, or when the plan
        records no policy. Without it, the protected users the plan recorded when it was
        built are used.
    .EXAMPLE
        $check = Test-TenurePlan $plan
        $check.Drifted | Select-Object Id, Provider, Reason

        Lists the steps whose targets changed since the plan was built.
    .EXAMPLE
        if ((Test-TenurePlan ./plan.json).Drifted.Count -gt 0) { 'Re-plan before applying.' }
    .OUTPUTS
        Tenure.PlanTestResult with Drifted, Satisfied, Pending and Unverified arrays of Tenure.Step.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.PlanTestResult')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [object]$Plan,

        [object]$Policy
    )

    process {
        $planObject = $Plan
        if ($Plan -is [string]) { $planObject = Import-TenurePlan -Path $Plan }
        $policyObject = $Policy
        if ($Policy -is [string]) { $policyObject = Get-TenurePolicy -Path $Policy }
        Test-TenurePlanCore -Plan $planObject -Policy $policyObject
    }
}
