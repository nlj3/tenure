# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

# Role template id of Global Administrator. It is the same in every tenant (a Microsoft constant, not tenant data).
$script:GlobalAdministratorRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'

$null = Register-TenureProvider -Definition @{
    Name        = 'Check.SubjectNotGlobalAdmin'
    Kind        = 'Check'
    Backend     = 'Graph'
    Scopes      = @('RoleManagement.Read.Directory', 'User.Read.All')
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Check', 'NoOp')
    AffectedBy  = @('DirectoryRole.Member')
    Severity    = 'Warn'
    Description = 'Warns when the subject holds the Global Administrator role as a direct, active member, so the operator can check that the tenant keeps a break-glass admin.'

    # Target: @{ Kind = 'user'; Id = <subject id>; Name = <subject UPN> }
    # Desired: not used.
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'Check.SubjectNotGlobalAdmin'
        try {
            $memberOf = @(Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '/memberOf?$select=id,displayName,roleTemplateId') -All)
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'Check.SubjectNotGlobalAdmin'; Identity = $id } -Inner $_)
            }
            throw
        }
        $names = [System.Collections.Generic.List[string]]::new()
        $isGlobalAdmin = $false
        foreach ($item in $memberOf) {
            if (([string](Get-TenureGraphProperty -InputObject $item -Name '@odata.type')) -ine '#microsoft.graph.directoryRole') { continue }
            $names.Add([string](Get-TenureGraphProperty -InputObject $item -Name 'displayName'))
            if (([string](Get-TenureGraphProperty -InputObject $item -Name 'roleTemplateId')) -ieq $script:GlobalAdministratorRoleTemplateId) { $isGlobalAdmin = $true }
        }
        $names.Sort([System.StringComparer]::OrdinalIgnoreCase)
        [pscustomobject]@{
            roles         = [string[]]$names.ToArray()
            isGlobalAdmin = $isGlobalAdmin
        }
    }

    Test        = {
        param($Current, $Desired)
        if ($null -eq $Current) { return $false }
        $flag = Get-TenureGraphProperty -InputObject $Current -Name 'isGlobalAdmin'
        return (($flag -is [bool]) -and (-not $flag))
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        $flag = Get-TenureGraphProperty -InputObject $Current -Name 'isGlobalAdmin'
        if ($flag -is [bool] -and $flag) {
            return "$name holds Global Administrator; removing the role is in this plan, check break-glass coverage"
        }
        if ($null -eq $Current) { return "Role membership of $name could not be read, so Global Administrator cannot be ruled out" }
        "$name does not hold Global Administrator"
    }
}
