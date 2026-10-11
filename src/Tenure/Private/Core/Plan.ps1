# Shared helpers for the plan model (steps, plans, plan files) and the strict JSON reader
# that both the plan importer and the policy loader use. Public surface lives in Public/.

function Get-TenureValidationError {
    <#
    .SYNOPSIS
        Builds a validation ErrorRecord whose message starts with a JSON path.
    .DESCRIPTION
        Used by the policy loader and the plan importer. The path also goes in
        Exception.Data['Path'] so callers and tests do not have to parse the message.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data
    )

    $payload = @{ Path = $Path }
    if ($Data) { foreach ($key in $Data.Keys) { $payload[$key] = $Data[$key] } }
    New-TenureError -Id $Id -Message ('{0}: {1}' -f $Path, $Message) -Category InvalidData -Data $payload
}

function Get-TenureProperty {
    <#
    .SYNOPSIS
        Reads a property from an object without tripping strict mode when it is absent.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$InputObject,
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

function Get-TenureValueTypeName {
    <#
    .SYNOPSIS
        JSON-style type name of a value, for error messages.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()][object]$Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return 'string' }
    if ($Value -is [bool]) { return 'boolean' }
    if ($Value -is [int] -or $Value -is [long]) { return 'integer' }
    if ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { return 'number' }
    if ($Value -is [System.Collections.IDictionary]) { return 'object' }
    if ($Value -is [System.Collections.IEnumerable]) { return 'array' }
    $Value.GetType().Name
}

function ConvertTo-TenureUtcDateTime {
    <#
    .SYNOPSIS
        Parses a date-time string into a UTC [datetime], or returns $null when it is not one.
    .DESCRIPTION
        Strings with an offset are converted to UTC; strings without one are taken as UTC.
        Anything that is not a string is not a date here.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param([Parameter(Position = 0)][AllowNull()][object]$Value)

    if ($Value -isnot [string]) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $null }
    [datetime]::SpecifyKind($parsed, [System.DateTimeKind]::Utc)
}

function ConvertTo-TenureInteger {
    <#
    .SYNOPSIS
        Returns the value as [int] or [long] when it is a whole number, otherwise $null.
    .DESCRIPTION
        JSON has one number type, so 20 and 20.0 are the same integer. Booleans and
        strings are never integers.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Position = 0)][AllowNull()][object]$Value)

    if ($Value -is [int]) { return $Value }
    if ($Value -is [long]) {
        if ($Value -ge [int]::MinValue -and $Value -le [int]::MaxValue) { return [int]$Value }
        return $Value
    }
    if ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) {
        $number = [double]$Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { return $null }
        if ([math]::Floor($number) -ne $number) { return $null }
        if ([math]::Abs($number) -gt 9007199254740992) { return $null }
        if ([math]::Abs($number) -le [int]::MaxValue) { return [int]$number }
        return [long]$number
    }
    $null
}

function ConvertFrom-TenureJsonElement {
    <#
    .SYNOPSIS
        Converts a parsed JSON element into plain values without any type coercion.
    .DESCRIPTION
        Objects become case-insensitive ordered dictionaries (keys keep their spelling and
        order), arrays become object[], numbers become int, long or double, and strings stay
        strings (no date coercion, unlike ConvertFrom-Json). A key that appears twice, or
        twice with different case, is an error because one value would silently win.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][System.Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Path
    )

    switch ($Element.ValueKind) {
        'Object' {
            $table = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) {
                $name = $property.Name
                if ($table.Contains($name)) {
                    throw (Get-TenureValidationError -Id $ErrorId -Path $Path -Message "duplicate key '$name' (keys are compared without regard to case)")
                }
                $table[$name] = ConvertFrom-TenureJsonElement -Element $property.Value -ErrorId $ErrorId -Path ('{0}.{1}' -f $Path, $name)
            }
            return $table
        }
        'Array' {
            $list = [System.Collections.Generic.List[object]]::new()
            $index = 0
            foreach ($item in $Element.EnumerateArray()) {
                $list.Add((ConvertFrom-TenureJsonElement -Element $item -ErrorId $ErrorId -Path ('{0}[{1}]' -f $Path, $index)))
                $index++
            }
            return , $list.ToArray()
        }
        'String' { return $Element.GetString() }
        'Number' {
            $asInt = 0
            if ($Element.TryGetInt32([ref]$asInt)) { return $asInt }
            $asLong = [long]0
            if ($Element.TryGetInt64([ref]$asLong)) { return $asLong }
            return $Element.GetDouble()
        }
        'True' { return $true }
        'False' { return $false }
        default { return $null }
    }
}

function ConvertFrom-TenureJsonText {
    <#
    .SYNOPSIS
        Parses strict JSON text (no comments, no trailing commas) into plain values.
    .DESCRIPTION
        Malformed text throws -ErrorId with path '$'. See ConvertFrom-TenureJsonElement for
        the value model.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$ErrorId
    )

    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 64
    $document = $null
    try {
        $document = [System.Text.Json.JsonDocument]::Parse($Text, $options)
    } catch {
        $reason = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        if ($reason.Length -gt 200) { $reason = $reason.Substring(0, 200) }
        throw (Get-TenureValidationError -Id $ErrorId -Path '$' -Message "not valid JSON ($reason)")
    }
    try {
        ConvertFrom-TenureJsonElement -Element $document.RootElement -ErrorId $ErrorId -Path '$'
    } finally {
        $document.Dispose()
    }
}

function Copy-TenureValue {
    <#
    .SYNOPSIS
        Deep copy of hashtables, dictionaries, PSCustomObjects and arrays. Everything else is shared.
    .DESCRIPTION
        Plan objects must not share mutable state with the caller's inputs or with other
        plans (the apply engine fills in placeholders in place). Scalars, dates and other
        .NET objects are returned as they are.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Position = 0)][AllowNull()][object]$InputObject,
        [int]$Depth = 0
    )

    if ($Depth -gt 64) {
        throw (New-TenureError -Id 'Tenure.Json.TooDeep' -Message 'Object nesting exceeds 64 levels.')
    }
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [System.ValueType]) { return $InputObject }

    if ($InputObject -is [hashtable]) {
        # Hashtable.Clone keeps the comparer (case sensitivity) of the original.
        $copy = $InputObject.Clone()
        foreach ($key in @($copy.Keys)) {
            $copy[$key] = Copy-TenureValue -InputObject $InputObject[$key] -Depth ($Depth + 1)
        }
        return $copy
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        # OrderedDictionary (what [ordered] and the canonical JSON writer produce) has no Clone, and other
        # dictionaries do not either, so rebuild: same order, values copied, and the same key case rule.
        # Keys and Values enumerate in the same order; reading them in parallel avoids the integer-key
        # ambiguity of the OrderedDictionary indexer (an int is a position there).
        $keys = @($InputObject.Keys)
        $values = @($InputObject.Values)
        $lookup = if ($null -ne $InputObject.PSObject.Methods['ContainsKey']) { 'ContainsKey' } else { 'Contains' }

        # The comparer of an existing dictionary cannot be read, so observe it: a dictionary that does not find
        # a key under swapped case, or that holds two keys differing only by case, compares ordinally.
        $caseSensitive = $false
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $keys) {
            if ($key -isnot [string]) { continue }
            if (-not $seen.Add($key)) { $caseSensitive = $true }
            $swapped = -join @($key.ToCharArray() | ForEach-Object { if ([char]::IsUpper($_)) { [char]::ToLowerInvariant($_) } else { [char]::ToUpperInvariant($_) } })
            if ($swapped -cne $key -and -not $InputObject.$lookup($swapped)) { $caseSensitive = $true }
        }
        $comparer = if ($caseSensitive) { [System.StringComparer]::Ordinal } else { [System.StringComparer]::OrdinalIgnoreCase }
        $copy = [System.Collections.Specialized.OrderedDictionary]::new($comparer)
        for ($i = 0; $i -lt $keys.Count; $i++) {
            $copy.Add($keys[$i], (Copy-TenureValue -InputObject $values[$i] -Depth ($Depth + 1)))
        }
        return $copy
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) { $list.Add((Copy-TenureValue -InputObject $item -Depth ($Depth + 1))) }
        return , $list.ToArray()
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            if ($property.MemberType -ne 'NoteProperty') { continue }
            $ordered[$property.Name] = Copy-TenureValue -InputObject $property.Value -Depth ($Depth + 1)
        }
        $clone = [pscustomobject]$ordered
        # Keep a custom type name (for example a provider's own PSTypeName) on the copy.
        $typeNames = @($InputObject.PSObject.TypeNames)
        for ($i = $typeNames.Count - 1; $i -ge 0; $i--) {
            if ($typeNames[$i] -ne 'System.Management.Automation.PSCustomObject' -and $typeNames[$i] -ne 'System.Object') {
                $clone.PSObject.TypeNames.Insert(0, $typeNames[$i])
            }
        }
        return $clone
    }
    $InputObject
}

function ConvertTo-TenureHashtableTree {
    <#
    .SYNOPSIS
        Rebuilds a parsed JSON value with every object as a hashtable (deep).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Position = 0)][AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [System.ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $table = @{}
        foreach ($key in $InputObject.Keys) { $table[[string]$key] = ConvertTo-TenureHashtableTree -InputObject $InputObject[$key] }
        return $table
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) { $list.Add((ConvertTo-TenureHashtableTree -InputObject $item)) }
        return , $list.ToArray()
    }
    $InputObject
}

function ConvertTo-TenureObjectTree {
    <#
    .SYNOPSIS
        Rebuilds a parsed JSON value with every object as a PSCustomObject (deep, key order kept).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Position = 0)][AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [System.ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in $InputObject.Keys) { $ordered[[string]$key] = ConvertTo-TenureObjectTree -InputObject $InputObject[$key] }
        return [pscustomobject]$ordered
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) { $list.Add((ConvertTo-TenureObjectTree -InputObject $item)) }
        return , $list.ToArray()
    }
    $InputObject
}

$script:PlanSchemaVersion = 2

function Get-TenureStepFingerprint {
    <#
    .SYNOPSIS
        Fingerprint of a step: SHA-256 of the canonical JSON of its target identity and its Before snapshot.
    .DESCRIPTION
        Never empty. The hash covers the target Kind and Id as well as Before, so a plan file
        edited to point a step at a different object no longer matches what that object looks
        like now. A $null Before is hashed as null and means "absent": a Create step's target
        must not exist yet, and a step on the {{subjectId}} placeholder binds only its target.
        The target Name is display text and is not part of the fingerprint. Key order does not
        matter. The apply engine and Test-TenurePlan call this same function on the live state,
        so the two sides always agree.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Target,
        [Parameter(Mandatory)][AllowNull()][object]$Before
    )

    Get-TenureHash -InputObject @{
        Target = @{
            Kind = Get-TenureProperty -InputObject $Target -Name 'Kind'
            Id   = Get-TenureProperty -InputObject $Target -Name 'Id'
        }
        Before = $Before
    }
}

function ConvertTo-TenurePolicySnapshot {
    <#
    .SYNOPSIS
        The policy facts a plan records at build time: the protected users and the managed set.
    .DESCRIPTION
        Applying or testing a plan without -Policy uses these. Protected users are trimmed,
        de-duplicated and sorted ignoring case, so the record does not depend on the order of
        the policy file. Returns $null for no policy.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Policy)

    if ($null -eq $Policy) { return $null }
    $defaults = Get-TenureProperty -InputObject $Policy -Name 'Defaults'
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $protected = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @(Get-TenureProperty -InputObject $defaults -Name 'protectedUsers')) {
        if ($null -eq $entry -or [string]::IsNullOrWhiteSpace([string]$entry)) { continue }
        $text = ([string]$entry).Trim()
        if ($seen.Add($text)) { $protected.Add($text) }
    }
    $protected.Sort([System.StringComparer]::OrdinalIgnoreCase)
    $managed = Get-TenureProperty -InputObject $Policy -Name 'ManagedSet'
    @{
        ProtectedUsers = [string[]]$protected.ToArray()
        ManagedSet     = @{
            Licenses = [string[]]@(Get-TenureProperty -InputObject $managed -Name 'Licenses' | Where-Object { $null -ne $_ })
            Groups   = [string[]]@(Get-TenureProperty -InputObject $managed -Name 'Groups' | Where-Object { $null -ne $_ })
        }
    }
}

function Get-TenurePlanIntegrity {
    <#
    .SYNOPSIS
        The plan's integrity value: SHA-256 of the canonical JSON of what the plan says and does.
    .DESCRIPTION
        Covers SchemaVersion, PlanId, CreatedAt, CreatedBy, ModuleVersion, Operation, Subject,
        PolicyHash, PolicySnapshot, Inputs, Warnings and, for every step in order, Id, Key,
        Provider, Kind, Target, Action, Before, After, Fingerprint, Risk, Reversible, Reason and
        DependsOn. Left out are the fields the apply engine writes: Plan.Status, each step's
        Status and Result, and Subject.Id once a create step has filled it in. With
        -UnboundSubjectId the subject id is taken as $null, the value a plan built before its
        subject existed was sealed with.

        It is a plain hash, not a signature: it shows that a file was edited by hand or by a
        tool that did not recompute it, and someone who recomputes it can still forge a plan.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Plan,
        [switch]$UnboundSubjectId
    )

    $subject = Get-TenureProperty -InputObject $Plan -Name 'Subject'
    $createdAt = Get-TenureProperty -InputObject $Plan -Name 'CreatedAt'
    $timestamp = ConvertFrom-TenureTimestamp -Value $createdAt
    $createdBy = Get-TenureProperty -InputObject $Plan -Name 'CreatedBy'
    $steps = [System.Collections.Generic.List[object]]::new()
    foreach ($step in @(Get-TenureProperty -InputObject $Plan -Name 'Steps')) {
        if ($null -eq $step) { $steps.Add($null); continue }
        $sealed = [ordered]@{}
        foreach ($name in 'Id', 'Key', 'Provider', 'Kind', 'Target', 'Action', 'Before', 'After', 'Fingerprint', 'Risk', 'Reversible', 'Reason') {
            $sealed[$name] = Get-TenureProperty -InputObject $step -Name $name
        }
        $sealed['DependsOn'] = [string[]]@(Get-TenureProperty -InputObject $step -Name 'DependsOn' | Where-Object { $null -ne $_ })
        $steps.Add($sealed)
    }
    $body = [ordered]@{
        SchemaVersion  = Get-TenureProperty -InputObject $Plan -Name 'SchemaVersion'
        PlanId         = Get-TenureProperty -InputObject $Plan -Name 'PlanId'
        CreatedAt      = $(if ($null -ne $timestamp) { $timestamp.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) } else { $createdAt })
        CreatedBy      = [ordered]@{
            Account  = Get-TenureProperty -InputObject $createdBy -Name 'Account'
            TenantId = Get-TenureProperty -InputObject $createdBy -Name 'TenantId'
            AuthType = Get-TenureProperty -InputObject $createdBy -Name 'AuthType'
        }
        ModuleVersion  = Get-TenureProperty -InputObject $Plan -Name 'ModuleVersion'
        Operation      = Get-TenureProperty -InputObject $Plan -Name 'Operation'
        Subject        = [ordered]@{
            Id                = $(if ($UnboundSubjectId) { $null } else { Get-TenureProperty -InputObject $subject -Name 'Id' })
            UserPrincipalName = Get-TenureProperty -InputObject $subject -Name 'UserPrincipalName'
            DisplayName       = Get-TenureProperty -InputObject $subject -Name 'DisplayName'
        }
        PolicyHash     = Get-TenureProperty -InputObject $Plan -Name 'PolicyHash'
        PolicySnapshot = Get-TenureProperty -InputObject $Plan -Name 'PolicySnapshot'
        Inputs         = Get-TenureProperty -InputObject $Plan -Name 'Inputs'
        Warnings       = [string[]]@(Get-TenureProperty -InputObject $Plan -Name 'Warnings' | Where-Object { $null -ne $_ })
        Steps          = $steps.ToArray()
    }
    Get-TenureHash -InputObject $body
}

function Test-TenurePlanIntegrity {
    <#
    .SYNOPSIS
        Recomputes a plan's integrity value and compares it with Plan.Integrity.
    .DESCRIPTION
        Returns @{ Valid; SubjectIdBound }. SubjectIdBound is $false when the plan was sealed
        without a subject id and the id was filled in afterwards (the apply engine does that
        after a create step); the engine then needs the audit log to show this plan created
        that id. A missing or malformed Integrity is not valid.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][object]$Plan)

    $stored = Get-TenureProperty -InputObject $Plan -Name 'Integrity'
    if ($stored -isnot [string] -or $stored -cnotmatch '^[0-9a-f]{64}\z') { return @{ Valid = $false; SubjectIdBound = $true } }
    if ((Get-TenurePlanIntegrity -Plan $Plan) -ceq $stored) { return @{ Valid = $true; SubjectIdBound = $true } }
    $subjectId = Get-TenureProperty -InputObject (Get-TenureProperty -InputObject $Plan -Name 'Subject') -Name 'Id'
    if ($subjectId -is [string] -and $subjectId.Length -gt 0 -and (Get-TenurePlanIntegrity -Plan $Plan -UnboundSubjectId) -ceq $stored) {
        return @{ Valid = $true; SubjectIdBound = $false }
    }
    @{ Valid = $false; SubjectIdBound = $true }
}

function Assert-TenurePlanIntegrity {
    <#
    .SYNOPSIS
        Throws Tenure.Plan.Tampered unless the plan's Integrity matches its content; returns Test-TenurePlanIntegrity's answer.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][object]$Plan)

    $check = Test-TenurePlanIntegrity -Plan $Plan
    if (-not $check.Valid) {
        $planId = Get-TenureProperty -InputObject $Plan -Name 'PlanId'
        throw (New-TenureError -Id 'Tenure.Plan.Tampered' -Message "Plan $planId was changed after it was built: its Integrity value does not match its content. Steps, targets, desired states and the subject may not be added, removed, reordered or edited once a plan is built. Build the plan again (re-plan) and review it." -Category SecurityError -Data @{ PlanId = $planId })
    }
    $check
}

function Write-TenureTemporaryFile {
    <#
    .SYNOPSIS
        Writes UTF-8 text (no byte order mark) to a new file and flushes it to disk before returning.
    .DESCRIPTION
        The plan writers write a temporary file and then rename it over the target. Flushing
        first means the rename never publishes a file whose bytes are still only in the
        operating system's cache, so a crash or power cut leaves the old plan or the new one,
        never an empty or partial file.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function ConvertTo-TenureStep {
    <#
    .SYNOPSIS
        Builds the Tenure.Step object (SPEC 2.3 fields plus Key) from a hashtable of field values.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Step')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object; changes no state.')]
    param([Parameter(Mandatory)][hashtable]$Field)

    $dependsOn = [string[]]@($Field['DependsOn'] | Where-Object { $null -ne $_ })
    $status = if ($null -ne $Field['Status']) { [string]$Field['Status'] } else { 'Pending' }
    [pscustomobject]@{
        PSTypeName  = 'Tenure.Step'
        Id          = $Field['Id']
        Key         = $Field['Key']
        Provider    = $Field['Provider']
        Kind        = $Field['Kind']
        Target      = $Field['Target']
        Action      = $Field['Action']
        Before      = $Field['Before']
        After       = $Field['After']
        Fingerprint = if ($null -ne $Field['Fingerprint']) { [string]$Field['Fingerprint'] } else { '' }
        Risk        = $Field['Risk']
        Reversible  = $Field['Reversible']
        Reason      = $Field['Reason']
        DependsOn   = $dependsOn
        Status      = $status
        Result      = $Field['Result']
    }
}

function Assert-TenureStepTarget {
    <#
    .SYNOPSIS
        Throws Tenure.Step.InvalidTarget unless Target has a valid Kind, Id and Name.
    .DESCRIPTION
        Id may be the literal placeholder {{subjectId}}, which the apply engine replaces
        with the id of the user created earlier in the plan.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param([Parameter(Mandatory)][hashtable]$Target)

    $kinds = [string[]]@('user', 'group', 'device', 'mailbox', 'drive', 'role')
    $problems = [System.Collections.Generic.List[string]]::new()

    $kind = Get-TenureProperty -InputObject $Target -Name 'Kind'
    if ($kind -isnot [string] -or $kinds -cnotcontains $kind) {
        $problems.Add(("Target.Kind must be one of {0} (got '{1}')." -f ($kinds -join ', '), $kind))
    }
    foreach ($field in 'Id', 'Name') {
        $value = Get-TenureProperty -InputObject $Target -Name $field
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
            $problems.Add(("Target.{0} must be a non-empty string (got {1})." -f $field, (Get-TenureValueTypeName $value)))
        }
    }
    if ($problems.Count -gt 0) {
        throw (New-TenureError -Id 'Tenure.Step.InvalidTarget' -Message ('Invalid step target: ' + ($problems -join ' ')) -Category InvalidArgument -Data @{ Problems = $problems.ToArray() })
    }
}

function ConvertTo-TenureExportObject {
    <#
    .SYNOPSIS
        Rebuilds a plan graph so ConvertTo-Json writes it faithfully.
    .DESCRIPTION
        Dates become UTC round-trip strings (ConvertTo-Json drops trailing zero digits and
        keeps local offsets, which would change the canonical form and so the fingerprints),
        enums and guids become strings, hashtable keys are sorted for a stable file, and
        PSCustomObject property order is kept. SecureString and PSCredential are refused.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Position = 0)][AllowNull()][object]$InputObject,
        [int]$Depth = 0
    )

    if ($Depth -gt 64) {
        throw (New-TenureError -Id 'Tenure.Json.TooDeep' -Message 'Object nesting exceeds 64 levels.')
    }
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Security.SecureString] -or $InputObject -is [pscredential]) {
        throw (New-TenureError -Id 'Tenure.Json.SecretRejected' -Message 'Refusing to serialize a SecureString or credential.' -Category SecurityError)
    }
    if ($InputObject -is [string]) { return $InputObject }
    if ($InputObject -is [datetime]) { return $InputObject.ToUniversalTime().ToString('o') }
    if ($InputObject -is [datetimeoffset]) { return $InputObject.ToUniversalTime().ToString('o') }
    if ($InputObject -is [enum] -or $InputObject -is [guid]) { return $InputObject.ToString() }
    if ($InputObject -is [bool] -or $InputObject -is [System.ValueType]) { return $InputObject }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $keys = @($InputObject.Keys | ForEach-Object { [string]$_ })
        [array]::Sort($keys, [System.StringComparer]::Ordinal)
        $ordered = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
        foreach ($key in $keys) {
            $ordered[$key] = ConvertTo-TenureExportObject -InputObject $InputObject[$key] -Depth ($Depth + 1)
        }
        return $ordered
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) { $list.Add((ConvertTo-TenureExportObject -InputObject $item -Depth ($Depth + 1))) }
        return , $list.ToArray()
    }

    $ordered = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.MemberType -notin 'NoteProperty', 'Property', 'AliasProperty', 'ScriptProperty') { continue }
        $ordered[[string]$property.Name] = ConvertTo-TenureExportObject -InputObject $property.Value -Depth ($Depth + 1)
    }
    $ordered
}

function ConvertFrom-TenurePlanModel {
    <#
    .SYNOPSIS
        Validates a parsed plan file and rebuilds it as a Tenure.Plan with normalized types.
    .DESCRIPTION
        Throws Tenure.Plan.Invalid with the JSON path of the first problem. The schema
        version is checked by the caller before this runs. Property names of the plan and
        step records are matched without regard to case; keys inside Target, Before, After,
        Inputs and Result keep the spelling they have in the file.
    #>
    [CmdletBinding()]
    [OutputType('Tenure.Plan')]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Model)

    $fail = { param($path, $message) throw (Get-TenureValidationError -Id 'Tenure.Plan.Invalid' -Path $path -Message $message) }
    $operations = [string[]]@('Onboard', 'RoleChange', 'Offboard', 'Custom')
    $planStatuses = [string[]]@('Planned', 'DryRun', 'Applied', 'PartiallyApplied', 'Failed')
    $actions = [string[]]@('Create', 'Update', 'Remove', 'Invoke', 'Check', 'NoOp')
    $stepStatuses = [string[]]@('Pending', 'Applied', 'Skipped', 'Failed', 'DryRun', 'Drifted', 'Refused', 'Declined')
    $risks = [string[]]@('Low', 'Medium', 'High', 'Destructive')
    $providerKinds = [string[]]@('State', 'Invoke', 'Check')
    $targetKinds = [string[]]@('user', 'group', 'device', 'mailbox', 'drive', 'role')

    foreach ($name in 'PlanId', 'CreatedAt', 'CreatedBy', 'ModuleVersion', 'Operation', 'Subject', 'Steps', 'Status', 'Integrity') {
        if (-not $Model.Contains($name)) { & $fail ('$.' + $name) 'required property is missing' }
    }

    $planId = $Model['PlanId']
    $parsedGuid = [guid]::Empty
    if ($planId -isnot [string] -or -not [guid]::TryParse($planId, [ref]$parsedGuid)) { & $fail '$.PlanId' 'must be a guid string' }

    $createdAt = ConvertTo-TenureUtcDateTime -Value $Model['CreatedAt']
    if ($null -eq $createdAt) { & $fail '$.CreatedAt' 'must be an ISO 8601 date-time string' }

    $createdBySource = $Model['CreatedBy']
    if ($createdBySource -isnot [System.Collections.IDictionary]) { & $fail '$.CreatedBy' ('must be an object (got {0})' -f (Get-TenureValueTypeName $createdBySource)) }
    $createdBy = @{
        Account  = Get-TenureProperty -InputObject $createdBySource -Name 'Account'
        TenantId = Get-TenureProperty -InputObject $createdBySource -Name 'TenantId'
        AuthType = Get-TenureProperty -InputObject $createdBySource -Name 'AuthType'
    }

    if ($Model['ModuleVersion'] -isnot [string]) { & $fail '$.ModuleVersion' 'must be a string' }
    $operation = $Model['Operation']
    if ($operation -isnot [string] -or $operations -cnotcontains $operation) { & $fail '$.Operation' ('must be one of {0}' -f ($operations -join ', ')) }
    $planStatus = $Model['Status']
    if ($planStatus -isnot [string] -or $planStatuses -cnotcontains $planStatus) { & $fail '$.Status' ('must be one of {0}' -f ($planStatuses -join ', ')) }

    $subjectSource = $Model['Subject']
    if ($subjectSource -isnot [System.Collections.IDictionary]) { & $fail '$.Subject' ('must be an object (got {0})' -f (Get-TenureValueTypeName $subjectSource)) }
    foreach ($name in 'Id', 'UserPrincipalName', 'DisplayName') {
        if (-not $subjectSource.Contains($name)) { & $fail ('$.Subject.' + $name) 'required property is missing' }
    }
    $subjectId = $subjectSource['Id']
    if ($null -ne $subjectId -and $subjectId -isnot [string]) { & $fail '$.Subject.Id' 'must be a string or null' }
    foreach ($name in 'UserPrincipalName', 'DisplayName') {
        if ($subjectSource[$name] -isnot [string]) { & $fail ('$.Subject.' + $name) 'must be a string' }
    }
    $subject = @{ Id = $subjectId; UserPrincipalName = $subjectSource['UserPrincipalName']; DisplayName = $subjectSource['DisplayName'] }

    $policyHash = $null
    if ($Model.Contains('PolicyHash') -and $null -ne $Model['PolicyHash']) {
        if ($Model['PolicyHash'] -isnot [string]) { & $fail '$.PolicyHash' 'must be a string or null' }
        $policyHash = $Model['PolicyHash']
    }

    $policySnapshot = $null
    if ($Model.Contains('PolicySnapshot') -and $null -ne $Model['PolicySnapshot']) {
        $snapshotSource = $Model['PolicySnapshot']
        if ($snapshotSource -isnot [System.Collections.IDictionary]) { & $fail '$.PolicySnapshot' ('must be an object or null (got {0})' -f (Get-TenureValueTypeName $snapshotSource)) }
        $readList = {
            param($value, $path)
            if ($value -is [string] -or $value -isnot [System.Collections.IEnumerable] -or $value -is [System.Collections.IDictionary]) { & $fail $path 'must be an array of strings' }
            $items = [System.Collections.Generic.List[string]]::new()
            $position = 0
            foreach ($item in $value) {
                if ($item -isnot [string]) { & $fail ('{0}[{1}]' -f $path, $position) 'must be a string' }
                $items.Add($item)
                $position++
            }
            , [string[]]$items.ToArray()
        }
        $managedSource = $snapshotSource['ManagedSet']
        if ($managedSource -isnot [System.Collections.IDictionary]) { & $fail '$.PolicySnapshot.ManagedSet' 'must be an object' }
        $policySnapshot = @{
            ProtectedUsers = & $readList $snapshotSource['ProtectedUsers'] '$.PolicySnapshot.ProtectedUsers'
            ManagedSet     = @{
                Licenses = & $readList $managedSource['Licenses'] '$.PolicySnapshot.ManagedSet.Licenses'
                Groups   = & $readList $managedSource['Groups'] '$.PolicySnapshot.ManagedSet.Groups'
            }
        }
    }

    $integrity = $Model['Integrity']
    if ($integrity -isnot [string] -or $integrity -cnotmatch '^[0-9a-f]{64}\z') { & $fail '$.Integrity' 'must be a lowercase sha256 hex string' }

    $inputs = @{}
    if ($Model.Contains('Inputs') -and $null -ne $Model['Inputs']) {
        if ($Model['Inputs'] -isnot [System.Collections.IDictionary]) { & $fail '$.Inputs' ('must be an object (got {0})' -f (Get-TenureValueTypeName $Model['Inputs'])) }
        $inputs = ConvertTo-TenureHashtableTree -InputObject $Model['Inputs']
    }

    $warnings = [System.Collections.Generic.List[string]]::new()
    if ($Model.Contains('Warnings') -and $null -ne $Model['Warnings']) {
        $warningSource = $Model['Warnings']
        if ($warningSource -is [string] -or $warningSource -isnot [System.Collections.IEnumerable] -or $warningSource -is [System.Collections.IDictionary]) {
            & $fail '$.Warnings' 'must be an array of strings'
        }
        $index = 0
        foreach ($item in $warningSource) {
            if ($item -isnot [string]) { & $fail ('$.Warnings[{0}]' -f $index) 'must be a string' }
            $warnings.Add($item)
            $index++
        }
    }

    $stepSource = $Model['Steps']
    if ($stepSource -is [string] -or $stepSource -isnot [System.Collections.IEnumerable] -or $stepSource -is [System.Collections.IDictionary]) {
        & $fail '$.Steps' ('must be an array (got {0})' -f (Get-TenureValueTypeName $stepSource))
    }

    $steps = [System.Collections.Generic.List[object]]::new()
    $positionById = @{}
    $index = 0
    foreach ($raw in $stepSource) {
        $path = '$.Steps[{0}]' -f $index
        if ($raw -isnot [System.Collections.IDictionary]) { & $fail $path ('must be an object (got {0})' -f (Get-TenureValueTypeName $raw)) }
        foreach ($name in 'Id', 'Provider', 'Kind', 'Target', 'Action', 'Fingerprint', 'Risk', 'Reversible', 'Status') {
            if (-not $raw.Contains($name)) { & $fail ('{0}.{1}' -f $path, $name) 'required property is missing' }
        }

        $id = $raw['Id']
        if ($id -isnot [string] -or $id -cnotmatch '^S[0-9]{2,}\z') { & $fail ($path + '.Id') 'must look like S01' }
        if ($positionById.ContainsKey($id)) { & $fail ($path + '.Id') "duplicate step id '$id'" }

        $key = $null
        if ($raw.Contains('Key') -and $null -ne $raw['Key']) {
            if ($raw['Key'] -isnot [string]) { & $fail ($path + '.Key') 'must be a string or null' }
            $key = $raw['Key']
        }
        if ($raw['Provider'] -isnot [string] -or $raw['Provider'] -cnotmatch '^[A-Z][A-Za-z]+\.[A-Z][A-Za-z]+\z') { & $fail ($path + '.Provider') "must look like 'Area.Resource'" }
        if ($raw['Kind'] -isnot [string] -or $providerKinds -cnotcontains $raw['Kind']) { & $fail ($path + '.Kind') ('must be one of {0}' -f ($providerKinds -join ', ')) }
        if ($raw['Action'] -isnot [string] -or $actions -cnotcontains $raw['Action']) { & $fail ($path + '.Action') ('must be one of {0}' -f ($actions -join ', ')) }
        if ($raw['Risk'] -isnot [string] -or $risks -cnotcontains $raw['Risk']) { & $fail ($path + '.Risk') ('must be one of {0}' -f ($risks -join ', ')) }
        if ($raw['Reversible'] -isnot [bool]) { & $fail ($path + '.Reversible') 'must be true or false' }
        if ($raw['Status'] -isnot [string] -or $stepStatuses -cnotcontains $raw['Status']) { & $fail ($path + '.Status') ('must be one of {0}' -f ($stepStatuses -join ', ')) }
        $fingerprint = $raw['Fingerprint']
        if ($fingerprint -isnot [string] -or $fingerprint -cnotmatch '^[0-9a-f]{64}\z') { & $fail ($path + '.Fingerprint') 'must be a lowercase sha256 hex string (every step binds its target)' }

        $targetSource = $raw['Target']
        if ($targetSource -isnot [System.Collections.IDictionary]) { & $fail ($path + '.Target') ('must be an object (got {0})' -f (Get-TenureValueTypeName $targetSource)) }
        $targetKind = $targetSource['Kind']
        if ($targetKind -isnot [string] -or $targetKinds -cnotcontains $targetKind) { & $fail ($path + '.Target.Kind') ('must be one of {0}' -f ($targetKinds -join ', ')) }
        $targetId = $targetSource['Id']
        if ($null -ne $targetId -and $targetId -isnot [string]) { & $fail ($path + '.Target.Id') 'must be a string or null' }
        if ($targetSource['Name'] -isnot [string]) { & $fail ($path + '.Target.Name') 'must be a string' }

        $reason = ''
        if ($raw.Contains('Reason') -and $null -ne $raw['Reason']) {
            if ($raw['Reason'] -isnot [string]) { & $fail ($path + '.Reason') 'must be a string' }
            $reason = $raw['Reason']
        }

        $dependsOn = [System.Collections.Generic.List[string]]::new()
        if ($raw.Contains('DependsOn') -and $null -ne $raw['DependsOn']) {
            $dependencySource = $raw['DependsOn']
            if ($dependencySource -is [string] -or $dependencySource -isnot [System.Collections.IEnumerable] -or $dependencySource -is [System.Collections.IDictionary]) {
                & $fail ($path + '.DependsOn') 'must be an array of step ids'
            }
            $dependencyIndex = 0
            foreach ($dependency in $dependencySource) {
                $dependencyPath = '{0}.DependsOn[{1}]' -f $path, $dependencyIndex
                if ($dependency -isnot [string]) { & $fail $dependencyPath 'must be a step id string' }
                if (-not $positionById.ContainsKey($dependency)) {
                    & $fail $dependencyPath "'$dependency' is not the id of an earlier step"
                }
                $dependsOn.Add($dependency)
                $dependencyIndex++
            }
        }

        $result = $null
        if ($raw.Contains('Result') -and $null -ne $raw['Result']) {
            $resultSource = $raw['Result']
            if ($resultSource -isnot [System.Collections.IDictionary]) { & $fail ($path + '.Result') ('must be an object or null (got {0})' -f (Get-TenureValueTypeName $resultSource)) }
            $result = ConvertTo-TenureHashtableTree -InputObject $resultSource
            if ($resultSource.Contains('Observed')) { $result['Observed'] = ConvertTo-TenureObjectTree -InputObject $resultSource['Observed'] }
            if ($resultSource.Contains('At') -and $null -ne $resultSource['At']) {
                # Export writes dates as UTC 'o' strings; give a fresh plan's type back (a UTC [datetime]).
                $at = ConvertTo-TenureUtcDateTime -Value $resultSource['At']
                if ($null -eq $at) { & $fail ($path + '.Result.At') 'must be an ISO 8601 date-time string or null' }
                $result['At'] = $at
            }
        }

        $positionById[$id] = $index
        $steps.Add((ConvertTo-TenureStep -Field @{
                    Id          = $id
                    Key         = $key
                    Provider    = $raw['Provider']
                    Kind        = $raw['Kind']
                    Target      = ConvertTo-TenureHashtableTree -InputObject $targetSource
                    Action      = $raw['Action']
                    Before      = if ($raw.Contains('Before')) { ConvertTo-TenureObjectTree -InputObject $raw['Before'] } else { $null }
                    After       = if ($raw.Contains('After')) { ConvertTo-TenureHashtableTree -InputObject $raw['After'] } else { $null }
                    Fingerprint = $fingerprint
                    Risk        = $raw['Risk']
                    Reversible  = $raw['Reversible']
                    Reason      = $reason
                    DependsOn   = $dependsOn.ToArray()
                    Status      = $raw['Status']
                    Result      = $result
                }))
        $index++
    }

    [pscustomobject]@{
        PSTypeName     = 'Tenure.Plan'
        SchemaVersion  = $script:PlanSchemaVersion
        PlanId         = $planId
        CreatedAt      = $createdAt
        CreatedBy      = $createdBy
        ModuleVersion  = $Model['ModuleVersion']
        Operation      = $operation
        Subject        = $subject
        PolicyHash     = $policyHash
        PolicySnapshot = $policySnapshot
        Inputs         = $inputs
        Steps          = $steps.ToArray()
        Warnings       = $warnings.ToArray()
        Status         = $planStatus
        Integrity      = $integrity
    }
}
