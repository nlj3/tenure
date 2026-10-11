function New-TenureOnboardPlan {
    <#
    .SYNOPSIS
        Builds the plan that onboards a new user: account, manager, licenses, groups and an optional Temporary Access Pass.
    .DESCRIPTION
        Turns a role from the policy (its licenses, groups, department, job title and manager)
        plus the parameters you give into a plan, in the order of docs/SPEC.md section 5.2:

        1. absent: Check.UserAbsent refuses the plan when the user principal name or mail nickname
           is taken, including by a soft-deleted user.
        2. create: User.Create (the one-time password is generated when the plan is applied and
           returned on the apply result, never stored in the plan).
        3. manager: User.Manager, when a manager is known.
        4. licenses: User.Licenses with the role's SKUs plus -AdditionalLicense. A SKU with no
           available units is a plan warning.
        5. group:<id>: one Group.Member (or DistributionGroup.Member for a distribution list)
           add per group of the role plus -AdditionalGroup.
        6. tap: User.TemporaryAccessPass, when -TemporaryAccessPass is given.

        Steps 3 to 6 depend on step 2 and name the new user by the placeholder {{subjectId}},
        which the apply engine replaces with the id of the user the create step makes. The
        manager, license and pass steps target the placeholder; a group step targets the group,
        and its snapshot is taken now with the new user named by the placeholder ("not a
        member"), so the step binds the group like any other. Every step has a fingerprint, and
        the create step's fingerprint means "this user does not exist": if it exists when the
        plan is applied, and this plan did not create it, the create step drifts.

        Department, job title and manager come from the parameter first, then from the role.
        The usage location comes from -UsageLocation, then from the policy defaults; licenses
        need one, so a plan with neither is refused. Groups with dynamic membership cannot be
        added to by hand, and distribution lists need an Exchange connection; both are skipped
        with a warning. Group, SKU and manager names are looked up now, so a typo or an
        ambiguous group name stops the plan here (Tenure.Group.NotFound, Tenure.Group.Ambiguous,
        Tenure.Sku.NotFound, Tenure.User.NotFound).
    .PARAMETER UserPrincipalName
        The new user's user principal name, for example alex@example.com.
    .PARAMETER DisplayName
        The new user's display name.
    .PARAMETER GivenName
        First name.
    .PARAMETER Surname
        Last name.
    .PARAMETER Role
        A role name from the policy (Tenure.Policy.RoleNotFound when it is not defined).
    .PARAMETER Policy
        A Tenure.Policy from Get-TenurePolicy, or the path of a policy file.
    .PARAMETER Manager
        The manager's user principal name or object id. Overrides the role's manager.
    .PARAMETER Department
        Overrides the role's department.
    .PARAMETER JobTitle
        Overrides the role's job title.
    .PARAMETER OfficeLocation
        Office location.
    .PARAMETER UsageLocation
        Two-letter country code. Defaults to the policy's defaults.usageLocation.
    .PARAMETER AdditionalGroup
        Extra groups (display name, mail address or object id) on top of the role's.
    .PARAMETER AdditionalLicense
        Extra SKU part numbers on top of the role's.
    .PARAMETER TemporaryAccessPass
        Add a step that issues a Temporary Access Pass (480 minutes, usable once). The pass is
        returned on the apply result only.
    .PARAMETER MailNickname
        Defaults to the part of the user principal name before the @.
    .EXAMPLE
        $policy = Get-TenurePolicy -Path ./tenure.policy.json
        New-TenureOnboardPlan -UserPrincipalName alex@example.com -DisplayName 'Alex Doe' -Role sales -Policy $policy

        Builds the plan for a new salesperson; review it with Show-TenurePlan before applying.
    .EXAMPLE
        New-TenureOnboardPlan -UserPrincipalName kim@example.com -DisplayName 'Kim Lee' -Role warehouse -Policy ./tenure.policy.json -Manager bob@example.com -AdditionalGroup 'Night Shift' -TemporaryAccessPass

        Adds a group, sets the manager and issues a Temporary Access Pass for the first sign-in.
    .OUTPUTS
        Tenure.Plan
        Operation 'Onboard'; Subject.Id is $null until the create step is applied. Errors:
        Tenure.Plan.Invalid, Tenure.Plan.Refused (the user already exists), Tenure.Policy.RoleNotFound,
        Tenure.Group.NotFound, Tenure.Group.Ambiguous, Tenure.Sku.NotFound, Tenure.User.NotFound.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Plan')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Reads state through provider snapshots and returns an in-memory plan; changes no state.')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [string]$GivenName,

        [string]$Surname,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Role,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Policy,

        [string]$Manager,

        [string]$Department,

        [string]$JobTitle,

        [string]$OfficeLocation,

        [string]$UsageLocation,

        [string[]]$AdditionalGroup,

        [string[]]$AdditionalLicense,

        [switch]$TemporaryAccessPass,

        [string]$MailNickname
    )

    $invalid = { param($message) throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message $message -Category InvalidArgument) }

    $upn = $UserPrincipalName.Trim()
    if ($upn -cnotmatch '^[^@\s]+@[^@\s]+\.[^@\s]+\z') { & $invalid "UserPrincipalName must look like name@domain (got '$upn')." }
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { & $invalid 'DisplayName must not be empty.' }
    $nickname = if ($PSBoundParameters.ContainsKey('MailNickname')) { $MailNickname.Trim() } else { $upn.Split('@')[0] }
    # Entra ID: ASCII only, at most 64 characters, none of @ ( ) \ [ ] " ; : < > , or a space.
    if ($nickname -cnotmatch '^[\x21-\x7E]{1,64}\z' -or $nickname -cmatch '[@()\\\[\]";:<>,]') {
        & $invalid "MailNickname '$nickname' is not valid: use 1 to 64 printable ASCII characters without spaces and without @ ( ) \ [ ] `" ; : < > ,"
    }

    $policyObject = Resolve-TenurePolicyArgument -Policy $Policy
    $roleDefinition = Get-TenurePolicyRole -Policy $policyObject -Name $Role

    $location = if ($PSBoundParameters.ContainsKey('UsageLocation') -and -not [string]::IsNullOrWhiteSpace($UsageLocation)) { $UsageLocation.Trim() } else { [string]$policyObject.Defaults['usageLocation'] }
    if ([string]::IsNullOrWhiteSpace($location)) {
        & $invalid 'No usage location: pass -UsageLocation or set defaults.usageLocation in the policy. Licenses cannot be assigned without one.'
    }
    if ($location -cnotmatch '^[A-Za-z]{2}\z') { & $invalid "UsageLocation must be a two-letter country code (got '$location')." }
    $location = $location.ToUpperInvariant()

    $warnings = [System.Collections.Generic.List[string]]::new()
    $domain = $upn.Split('@')[1]
    $tenantDomain = [string]$policyObject.Tenant['domain']
    if (-not [string]::IsNullOrWhiteSpace($tenantDomain) -and $domain -ine $tenantDomain.Trim()) {
        $warnings.Add("The user principal name domain '$domain' differs from the policy's tenant domain '$($tenantDomain.Trim())'.")
    }

    $subject = @{ Id = $null; UserPrincipalName = $upn; DisplayName = $DisplayName.Trim() }
    $context = Get-TenureStepContext -Policy $policyObject -Subject $subject
    $steps = [System.Collections.Generic.List[object]]::new()

    # 1. Refuse before anything else is looked up when the name is taken.
    $absent = New-TenureStep -Provider 'Check.UserAbsent' -Target @{ Kind = 'user'; Id = $upn; Name = $upn; MailNickname = $nickname } -Desired @{ mailNickname = $nickname } -Context $context -Key 'absent'
    Assert-TenureStepAllowed -Step $absent -Operation 'Onboard'
    $steps.Add($absent)

    # Attribute precedence: parameter, then role, then nothing.
    $departmentValue = if ($PSBoundParameters.ContainsKey('Department') -and -not [string]::IsNullOrWhiteSpace($Department)) { $Department } else { $roleDefinition.Department }
    $jobTitleValue = if ($PSBoundParameters.ContainsKey('JobTitle') -and -not [string]::IsNullOrWhiteSpace($JobTitle)) { $JobTitle } else { $roleDefinition.JobTitle }
    $managerIdentity = if ($PSBoundParameters.ContainsKey('Manager') -and -not [string]::IsNullOrWhiteSpace($Manager)) { $Manager.Trim() } else { $roleDefinition.Manager }
    $managerUser = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$managerIdentity)) { $managerUser = Resolve-TenureUser -Identity ([string]$managerIdentity) }

    # Everything named in the request is resolved now: a typo stops the plan here.
    $groups = @(Resolve-TenureBuilderGroup -Identity (@($roleDefinition.Groups) + @($AdditionalGroup)) -Description 'group')
    $skus = @(Resolve-TenureBuilderSku -PartNumber (@($roleDefinition.Licenses) + @($AdditionalLicense)) -Description 'license')
    foreach ($sku in $skus) {
        if ($sku.Available -le 0) {
            $warnings.Add("License $($sku.SkuPartNumber) has no available units; assigning it will fail until more are bought or freed.")
        }
    }

    # 2. The account.
    $desired = @{ userPrincipalName = $upn; displayName = $subject.DisplayName; mailNickname = $nickname }
    foreach ($pair in @(
            @('givenName', $GivenName), @('surname', $Surname), @('usageLocation', $location),
            @('department', $departmentValue), @('jobTitle', $jobTitleValue), @('officeLocation', $OfficeLocation)
        )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$pair[1])) { $desired[$pair[0]] = ([string]$pair[1]).Trim() }
    }
    $steps.Add((New-TenureStep -Provider 'User.Create' -Target @{ Kind = 'user'; Id = $upn; Name = $upn } -Desired $desired -Context $context -Key 'create' -AllowMissing))

    $placeholder = @{ Kind = 'user'; Id = '{{subjectId}}'; Name = $upn }

    # 3. Manager.
    if ($null -ne $managerUser) {
        if ([string]$managerUser.UserPrincipalName -ieq $upn) { & $invalid 'A user cannot be their own manager.' }
        $steps.Add((New-TenureStep -Provider 'User.Manager' -Target $placeholder -Desired @{ managerId = [string]$managerUser.Id } -Context $context -Key 'manager' -DependsOn 'create' -SkipSnapshot -Action Update))
    }

    # 4. Licenses.
    if ($skus.Count -gt 0) {
        $skuIds = [string[]]@(ConvertTo-TenureSkuIdList -Id ($skus | ForEach-Object { $_.SkuId }))
        $steps.Add((New-TenureStep -Provider 'User.Licenses' -Target $placeholder -Desired @{ add = $skuIds; remove = [string[]]@() } -Context $context -Key 'licenses' -DependsOn 'create' -SkipSnapshot -Action Update))
    }

    # 5. Groups.
    foreach ($group in $groups) {
        $blocker = Get-TenureGroupStepBlocker -Group $group -Member $true
        if ($blocker) {
            $warnings.Add($blocker)
            continue
        }
        $steps.Add((New-TenureMembershipStep -Group $group -UserId '{{subjectId}}' -Member $true -Context $context -DependsOn 'create' -Placeholder))
    }

    # 6. Temporary Access Pass.
    if ($TemporaryAccessPass) {
        $steps.Add((New-TenureStep -Provider 'User.TemporaryAccessPass' -Target $placeholder -Desired @{ lifetimeInMinutes = 480; isUsableOnce = $true } -Context $context -Key 'tap' -DependsOn 'create' -SkipSnapshot -Action Invoke))
    }

    $replace = @{}
    if ($null -ne $managerUser -and $PSBoundParameters.ContainsKey('Manager')) { $replace['Manager'] = [string]$managerUser.UserPrincipalName }
    $inputs = Get-TenureBuilderInput -Bound $PSBoundParameters -Policy $policyObject -Replace $replace
    New-TenurePlan -Operation Onboard -Subject $subject -Step $steps.ToArray() -Policy $policyObject -Inputs $inputs -Warning $warnings.ToArray()
}
