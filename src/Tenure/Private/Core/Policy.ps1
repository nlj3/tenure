# Policy loader internals (docs/SPEC.md sections 2.1 and 5.5, ADR-0004).
# The public verbs are Get-TenurePolicy, Test-TenurePolicy and New-TenurePolicy.
# The JSON Schema in Policies/tenure.policy.schema.json is for editors; the rules live
# here and a test keeps the two in step.

function Get-TenurePolicySpec {
    <#
    .SYNOPSIS
        The policy shape: for every level, each allowed key and the kind of value it takes.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    @{
        Top       = @{ version = 'Version'; tenant = 'Object:Tenant'; defaults = 'Object:Defaults'; roles = 'Roles' }
        Tenant    = @{ domain = 'String' }
        Defaults  = @{ usageLocation = 'String'; passwordLength = 'PasswordLength'; protectedUsers = 'StringArray'; offboard = 'Object:Offboard' }
        Offboard  = @{
            resetPassword              = 'Boolean'
            revokeSessions             = 'Boolean'
            removeDirectoryRoles       = 'Boolean'
            convertMailboxToShared     = 'Boolean'
            hideFromAddressLists       = 'Boolean'
            forwardTo                  = 'Address'
            deliverToMailboxAndForward = 'Boolean'
            autoReply                  = 'Object:AutoReply'
            grantMailboxTo             = 'Address'
            grantOneDriveTo            = 'Address'
            cancelMeetings             = 'Boolean'
            removeFromGroups           = 'Boolean'
            keepGroups                 = 'StringArray'
            removeLicenses             = 'Boolean'
            devices                    = 'Devices'
            setEmployeeLeaveDate       = 'Boolean'
        }
        AutoReply = @{ enabled = 'Boolean'; message = 'String' }
        Role      = @{ licenses = 'StringArray'; groups = 'StringArray'; department = 'String'; jobTitle = 'String'; manager = 'String' }
    }
}

function Get-TenurePolicyKeySet {
    <#
    .SYNOPSIS
        Allowed keys per policy level (Top, Tenant, Defaults, Offboard, AutoReply, Role).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $spec = Get-TenurePolicySpec
    $keys = @{}
    foreach ($level in $spec.Keys) { $keys[$level] = [string[]]@($spec[$level].Keys) }
    $keys
}

function Get-TenurePolicyDefault {
    <#
    .SYNOPSIS
        Fresh copy of the SPEC 2.1 defaults (the values used when a key is missing).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    @{
        usageLocation  = 'US'
        passwordLength = 20
        protectedUsers = [string[]]@()
        offboard       = @{
            resetPassword              = $true
            revokeSessions             = $true
            removeDirectoryRoles       = $true
            convertMailboxToShared     = $true
            hideFromAddressLists       = $true
            forwardTo                  = 'manager'
            deliverToMailboxAndForward = $true
            autoReply                  = @{
                enabled = $true
                message = '{displayName} has left {company}. Please contact {managerDisplayName} ({managerMail}).'
            }
            grantMailboxTo             = 'manager'
            grantOneDriveTo            = 'manager'
            cancelMeetings             = $true
            removeFromGroups           = $true
            keepGroups                 = [string[]]@()
            removeLicenses             = $true
            devices                    = 'wipeCorporateRetirePersonal'
            setEmployeeLeaveDate       = $false
        }
    }
}

function ConvertTo-TenurePolicyRaw {
    <#
    .SYNOPSIS
        Deep-copies a hashtable or PSCustomObject into the plain value model the validator reads.
    .DESCRIPTION
        The result uses case-insensitive ordered dictionaries, object[] arrays and JSON scalars
        only. Anything that is not JSON-shaped (a SecureString, a date, a script block) throws
        Tenure.Policy.Invalid with the path of the offending value. The input is never modified.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Position = 0)][AllowNull()][object]$InputObject,
        [string]$Path = '$',
        [int]$Depth = 0
    )

    $fail = { param($message) throw (Get-TenureValidationError -Id 'Tenure.Policy.Invalid' -Path $Path -Message $message) }
    if ($Depth -gt 50) { & $fail 'nests deeper than 50 levels' }

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [bool]) { return $InputObject }
    if ($InputObject -is [byte] -or $InputObject -is [sbyte] -or $InputObject -is [int16] -or $InputObject -is [uint16] -or $InputObject -is [int]) { return [int]$InputObject }
    if ($InputObject -is [uint32] -or $InputObject -is [long]) { return [long]$InputObject }
    if ($InputObject -is [uint64]) {
        if ($InputObject -le [long]::MaxValue) { return [long]$InputObject }
        return [double]$InputObject
    }
    if ($InputObject -is [double] -or $InputObject -is [single] -or $InputObject -is [decimal]) {
        $number = [double]$InputObject
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { & $fail 'is not a finite number' }
        return $number
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $table = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $name = [string]$key
            $childPath = '{0}.{1}' -f $Path, $name
            if ($table.Contains($name)) { & $fail "duplicate key '$name'" }
            $table[$name] = ConvertTo-TenurePolicyRaw -InputObject $InputObject[$key] -Path $childPath -Depth ($Depth + 1)
        }
        return $table
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $table = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            if ($property.MemberType -ne 'NoteProperty') { continue }
            $table[$property.Name] = ConvertTo-TenurePolicyRaw -InputObject $property.Value -Path ('{0}.{1}' -f $Path, $property.Name) -Depth ($Depth + 1)
        }
        return $table
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        $index = 0
        foreach ($item in $InputObject) {
            $list.Add((ConvertTo-TenurePolicyRaw -InputObject $item -Path ('{0}[{1}]' -f $Path, $index) -Depth ($Depth + 1)))
            $index++
        }
        return , $list.ToArray()
    }
    & $fail ('holds a value of type {0}, which cannot appear in a policy' -f $InputObject.GetType().Name)
}

function Read-TenurePolicyFile {
    <#
    .SYNOPSIS
        Reads and parses a policy file into the plain value model.
    .DESCRIPTION
        Missing file or directory: Tenure.Policy.NotFound. Unreadable, non-UTF-8 or malformed
        JSON (including comments, trailing commas and duplicate keys): Tenure.Policy.Invalid
        with path '$'.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$FullPath)

    if ([string]::IsNullOrWhiteSpace($FullPath) -or -not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        throw (New-TenureError -Id 'Tenure.Policy.NotFound' -Message "Policy file '$FullPath' was not found." -Category ObjectNotFound -Data @{ FilePath = $FullPath })
    }
    $text = $null
    try {
        $text = [System.IO.File]::ReadAllText($FullPath, [System.Text.UTF8Encoding]::new($false, $true))
    } catch {
        # .NET exceptions arrive wrapped in a MethodInvocationException; look at the inner one.
        $cause = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
        if ($cause -is [System.Text.DecoderFallbackException]) {
            throw (Get-TenureValidationError -Id 'Tenure.Policy.Invalid' -Path '$' -Message 'the file is not valid UTF-8 text' -Data @{ FilePath = $FullPath })
        }
        throw (New-TenureError -Id 'Tenure.Policy.NotFound' -Message "Policy file '$FullPath' could not be read: $($cause.Message)" -Category ReadError -Data @{ FilePath = $FullPath })
    }
    try {
        ConvertFrom-TenureJsonText -Text $text -ErrorId 'Tenure.Policy.Invalid'
    } catch {
        # Add the file name to the structured data without changing the id or the message.
        if ($_.Exception.Data.Contains('TenureId')) { $_.Exception.Data['FilePath'] = $FullPath }
        throw
    }
}

function Add-TenurePolicyProblem {
    <#
    .SYNOPSIS
        Records one validation problem. The message starts with the JSON path.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Problems,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Message
    )

    $Problems.Add([pscustomobject]@{ Path = $Path; Message = ('{0}: {1}' -f $Path, $Message) })
}

function Test-TenurePolicyNode {
    <#
    .SYNOPSIS
        Checks one object of the policy against the spec for its level, recursing into children.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Node,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Problems
    )

    $spec = (Get-TenurePolicySpec)[$Level]
    $allowed = [string[]]@($spec.Keys)
    $keys = [string[]]@($Node.Keys | ForEach-Object { [string]$_ })
    [array]::Sort($keys, [System.StringComparer]::Ordinal)
    if ($Level -eq 'Top' -and $keys -ccontains 'version') {
        $keys = [string[]]@('version') + [string[]]@($keys | Where-Object { $_ -cne 'version' })
    }

    foreach ($key in $keys) {
        if ($key.StartsWith('_', [System.StringComparison]::Ordinal)) { continue }
        $childPath = '{0}.{1}' -f $Path, $key
        if ($allowed -cnotcontains $key) {
            $sortedAllowed = [string[]]@($allowed | Sort-Object)
            Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message ("unknown key '{0}' (allowed: {1})" -f $key, ($sortedAllowed -join ', '))
            continue
        }
        $value = $Node[$key]
        $kind = $spec[$key]
        $got = Get-TenureValueTypeName $value

        switch -Regex ($kind) {
            '^Object:(.+)$' {
                if ($value -isnot [System.Collections.IDictionary]) {
                    Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message "must be an object (got $got)"
                } else {
                    Test-TenurePolicyNode -Node $value -Path $childPath -Level $Matches[1] -Problems $Problems
                }
            }
            '^Version$' {
                $number = ConvertTo-TenureInteger $value
                if ($null -eq $number -or $number -ne 1) {
                    Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message "must be the integer 1 (got $got)"
                }
            }
            '^String$' {
                if ($value -isnot [string]) { Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message "must be a string (got $got)" }
            }
            '^Boolean$' {
                if ($value -isnot [bool]) { Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message "must be true or false (got $got)" }
            }
            '^PasswordLength$' {
                # Entra ID accepts passwords of 8 to 256 characters.
                $number = ConvertTo-TenureInteger $value
                if ($null -eq $number -or $number -lt 8 -or $number -gt 256) {
                    $shown = if ($null -ne $number) { [string]$number } else { $got }
                    Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message "must be an integer from 8 to 256 (got $shown)"
                }
            }
            '^StringArray$' {
                if ($value -is [string] -or $value -isnot [System.Collections.IEnumerable] -or $value -is [System.Collections.IDictionary]) {
                    Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message "must be an array of strings (got $got)"
                } else {
                    $index = 0
                    foreach ($item in $value) {
                        if ($item -isnot [string]) {
                            Add-TenurePolicyProblem -Problems $Problems -Path ('{0}[{1}]' -f $childPath, $index) -Message ('must be a string (got {0})' -f (Get-TenureValueTypeName $item))
                        } elseif ([string]::IsNullOrWhiteSpace($item)) {
                            # An empty name can never resolve to a license, group or user, and must not reach the managed set.
                            Add-TenurePolicyProblem -Problems $Problems -Path ('{0}[{1}]' -f $childPath, $index) -Message 'must not be empty or only whitespace'
                        }
                        $index++
                    }
                }
            }
            '^Address$' {
                if ($value -isnot [string]) {
                    Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message "must be a string (got $got)"
                } elseif ($value -cnotmatch '^(manager|none|[^@\s]+@[^@\s]+\.[^@\s]+)\z') {
                    Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message ("must be 'manager', 'none' or a mail address (got '{0}')" -f $value)
                }
            }
            '^Devices$' {
                $choices = [string[]]@('wipeCorporateRetirePersonal', 'retireAll', 'none')
                if ($value -isnot [string] -or $choices -cnotcontains $value) {
                    $shown = if ($value -is [string]) { "'$value'" } else { $got }
                    Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message ('must be one of {0} (got {1})' -f ($choices -join ', '), $shown)
                }
            }
            '^Roles$' {
                if ($value -isnot [System.Collections.IDictionary]) {
                    Add-TenurePolicyProblem -Problems $Problems -Path $childPath -Message "must be an object (got $got)"
                } else {
                    $roleNames = [string[]]@($value.Keys | ForEach-Object { [string]$_ })
                    [array]::Sort($roleNames, [System.StringComparer]::Ordinal)
                    foreach ($roleName in $roleNames) {
                        # Keys starting with an underscore are comments everywhere, including under roles.
                        if ($roleName.StartsWith('_', [System.StringComparison]::Ordinal)) { continue }
                        $rolePath = '{0}.{1}' -f $childPath, $roleName
                        if ($roleName -cnotmatch '^[A-Za-z0-9_-]+\z') {
                            Add-TenurePolicyProblem -Problems $Problems -Path $rolePath -Message 'role name must match ^[A-Za-z0-9_-]+$ (letters, digits, underscore, hyphen)'
                        }
                        $role = $value[$roleName]
                        if ($role -isnot [System.Collections.IDictionary]) {
                            Add-TenurePolicyProblem -Problems $Problems -Path $rolePath -Message ('must be an object (got {0})' -f (Get-TenureValueTypeName $role))
                        } else {
                            Test-TenurePolicyNode -Node $role -Path $rolePath -Level 'Role' -Problems $Problems
                        }
                    }
                }
            }
        }
    }
}

function Get-TenurePolicyProblem {
    <#
    .SYNOPSIS
        Validates a policy in the plain value model and emits every problem (Path, Message).
    .DESCRIPTION
        Emits nothing when the policy is valid. Wrap calls in @(...). Problems come in a
        stable order (version first, then keys in ordinal order, depth first) so the "first
        problem" is the same for the same content.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)][AllowNull()][object]$Raw)

    $problems = [System.Collections.Generic.List[object]]::new()
    if ($Raw -isnot [System.Collections.IDictionary]) {
        Add-TenurePolicyProblem -Problems $problems -Path '$' -Message ('the policy must be a JSON object (got {0})' -f (Get-TenureValueTypeName $Raw))
        return $problems.ToArray()
    }
    Test-TenurePolicyNode -Node $Raw -Path '$' -Level 'Top' -Problems $problems
    if (@($Raw.Keys) -cnotcontains 'version') {
        $problems.Insert(0, [pscustomobject]@{ Path = '$.version'; Message = '$.version: required property is missing (must be 1)' })
    }
    $problems.ToArray()
}

function Get-TenureManagedSet {
    <#
    .SYNOPSIS
        Union of every role's licenses and groups, de-duplicated case-insensitively and sorted.
    .DESCRIPTION
        Role changes only ever remove items in this set (SPEC 2.1). The first spelling seen
        wins, scanning roles in name order, so the result does not depend on role order.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable]$Roles)

    $names = [string[]]@($Roles.Keys)
    [array]::Sort($names, [System.StringComparer]::Ordinal)
    $result = @{}
    foreach ($field in 'Licenses', 'Groups') {
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $items = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $names) {
            foreach ($item in $Roles[$name][$field]) {
                if ($seen.Add($item)) { $items.Add($item) }
            }
        }
        $sorted = $items.ToArray()
        [array]::Sort($sorted, [System.StringComparer]::OrdinalIgnoreCase)
        $result[$field] = [string[]]$sorted
    }
    $result
}

function ConvertTo-TenurePolicy {
    <#
    .SYNOPSIS
        Builds the Tenure.Policy object from a validated raw policy, applying defaults.
    .DESCRIPTION
        Call only after Get-TenurePolicyProblem returned nothing. Hash is taken from the raw
        content, before defaults are applied and including any underscore keys.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Policy')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object; changes no state.')]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Raw,
        [AllowNull()][string]$Path
    )

    $defaults = Get-TenurePolicyDefault
    $offboardSpec = (Get-TenurePolicySpec)['Offboard']

    $tenant = @{ domain = $null }
    if ($Raw.Contains('tenant') -and $Raw['tenant'].Contains('domain')) { $tenant['domain'] = $Raw['tenant']['domain'] }

    if ($Raw.Contains('defaults')) {
        $rawDefaults = $Raw['defaults']
        if ($rawDefaults.Contains('usageLocation')) { $defaults['usageLocation'] = $rawDefaults['usageLocation'] }
        if ($rawDefaults.Contains('passwordLength')) { $defaults['passwordLength'] = ConvertTo-TenureInteger $rawDefaults['passwordLength'] }
        if ($rawDefaults.Contains('protectedUsers')) { $defaults['protectedUsers'] = [string[]]@($rawDefaults['protectedUsers']) }
        if ($rawDefaults.Contains('offboard')) {
            $rawOffboard = $rawDefaults['offboard']
            foreach ($key in $offboardSpec.Keys) {
                if (-not $rawOffboard.Contains($key)) { continue }
                if ($key -eq 'autoReply') {
                    foreach ($inner in 'enabled', 'message') {
                        if ($rawOffboard['autoReply'].Contains($inner)) { $defaults['offboard']['autoReply'][$inner] = $rawOffboard['autoReply'][$inner] }
                    }
                } elseif ($key -eq 'keepGroups') {
                    $defaults['offboard']['keepGroups'] = [string[]]@($rawOffboard['keepGroups'])
                } else {
                    $defaults['offboard'][$key] = $rawOffboard[$key]
                }
            }
        }
    }

    $roles = @{}
    if ($Raw.Contains('roles')) {
        foreach ($name in $Raw['roles'].Keys) {
            if ($name.StartsWith('_', [System.StringComparison]::Ordinal)) { continue }
            $rawRole = $Raw['roles'][$name]
            $roles[$name] = @{
                Licenses   = [string[]]@(if ($rawRole.Contains('licenses')) { $rawRole['licenses'] })
                Groups     = [string[]]@(if ($rawRole.Contains('groups')) { $rawRole['groups'] })
                Department = if ($rawRole.Contains('department')) { $rawRole['department'] } else { $null }
                JobTitle   = if ($rawRole.Contains('jobTitle')) { $rawRole['jobTitle'] } else { $null }
                Manager    = if ($rawRole.Contains('manager')) { $rawRole['manager'] } else { $null }
            }
        }
    }

    [pscustomobject]@{
        PSTypeName = 'Tenure.Policy'
        Version    = 1
        Tenant     = $tenant
        Defaults   = $defaults
        Roles      = $roles
        ManagedSet = Get-TenureManagedSet -Roles $roles
        Hash       = Get-TenureHash -InputObject $Raw
        Path       = $Path
    }
}

function Resolve-TenurePolicyArgument {
    <#
    .SYNOPSIS
        Turns a -Policy argument (a path or a loaded Tenure.Policy) into a Tenure.Policy.
    .DESCRIPTION
        Plan builders call this so users can pass either form. A string is loaded with
        Get-TenurePolicy -Path; a Tenure.Policy is returned as it is; anything else is
        Tenure.Policy.Invalid.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Policy')]
    param([Parameter(Mandatory)][AllowNull()][object]$Policy)

    if ($Policy -is [string]) { return Get-TenurePolicy -Path $Policy }
    if ($null -ne $Policy -and $Policy.PSObject.TypeNames -contains 'Tenure.Policy') { return $Policy }
    $got = if ($null -eq $Policy) { 'null' } else { $Policy.GetType().Name }
    throw (New-TenureError -Id 'Tenure.Policy.Invalid' -Message "The policy argument must be a path to a policy file or a Tenure.Policy object from Get-TenurePolicy (got $got)." -Category InvalidArgument)
}

function Get-TenurePolicyRole {
    <#
    .SYNOPSIS
        Returns one role from a policy, or throws Tenure.Policy.RoleNotFound listing the roles that exist.
    .DESCRIPTION
        The role is a hashtable with Licenses, Groups, Department, JobTitle and Manager.
        Role names are matched without regard to case; a policy cannot hold two roles that
        differ only by case.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Policy,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name
    )

    $resolved = Resolve-TenurePolicyArgument -Policy $Policy
    if ($Name -and $resolved.Roles.ContainsKey($Name)) { return $resolved.Roles[$Name] }

    $available = [string[]]@($resolved.Roles.Keys | Sort-Object)
    $listing = if ($available.Count -gt 0) { 'Available roles: ' + ($available -join ', ') + '.' } else { 'The policy defines no roles.' }
    throw (New-TenureError -Id 'Tenure.Policy.RoleNotFound' -Message ("Role '{0}' is not defined in the policy. {1}" -f $Name, $listing) -Category ObjectNotFound -Data @{ Role = $Name; Available = $available })
}

function Find-TenureProtectedUser {
    <#
    .SYNOPSIS
        Returns the defaults.protectedUsers entry that names a user, or $null when none does.
    .DESCRIPTION
        An entry protects the user when it equals one of -Identity (the user's object id, user
        principal name and mail address), ignoring case and surrounding white space. Only whole
        values match: an alias without its domain, another domain, or an id with one character
        changed protects no one, because a loose match could refuse a different user while the
        account the entry was written for stays unprotected. Blank entries and blank
        identities never match.
    .EXAMPLE
        Find-TenureProtectedUser -Protected $policy.Defaults['protectedUsers'] -Identity $user.Id, $user.UserPrincipalName, $user.Mail
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Protected,
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$Identity
    )

    foreach ($entry in @($Protected)) {
        if ($null -eq $entry) { continue }
        $text = ([string]$entry).Trim()
        if ($text.Length -eq 0) { continue }
        foreach ($value in @($Identity)) {
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            if ([string]::Equals($text, $value.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) { return $text }
        }
    }
    $null
}
