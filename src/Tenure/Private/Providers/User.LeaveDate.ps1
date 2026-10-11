# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureUtcDateString {
    # A Graph or Desired date -> UTC ISO 8601 'o' string, or $null for $null / empty.
    # Graph dates reach providers as strings, [datetime] (any Kind) or [DateTimeOffset] depending on the JSON
    # reader, so every date a provider returns goes through here; that keeps fingerprints identical across
    # machines and time zones. A string without an offset, and a [datetime] of Kind Unspecified, are read as UTC.
    # Also used by User.Password, User.Sessions and User.TemporaryAccessPass.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$Value,
        # Drop sub-second precision (Graph stores whole seconds for some properties; Test compares at that grain).
        [switch]$TruncateToSeconds,
        [string]$Provider = 'provider',
        [string]$Key = 'date'
    )

    if ($null -eq $Value) { return $null }
    $utc = $null
    if ($Value -is [datetimeoffset]) {
        $utc = $Value.UtcDateTime
    } elseif ($Value -is [datetime]) {
        $utc = if ($Value.Kind -eq [System.DateTimeKind]::Local) { $Value.ToUniversalTime() } else { [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
    } elseif ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
        $parsed = [datetimeoffset]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
        if (-not [datetimeoffset]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$Provider cannot read '$Value' as a date for '$Key'; use an ISO 8601 date and time, for example 2026-10-31T17:00:00Z." -Category InvalidArgument -Data @{ Provider = $Provider; Key = $Key })
        }
        $utc = $parsed.UtcDateTime
    } else {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$Provider needs a date for '$Key' (a [datetime] or an ISO 8601 string), not a $($Value.GetType().Name)." -Category InvalidArgument -Data @{ Provider = $Provider; Key = $Key })
    }
    if ($TruncateToSeconds) { $utc = $utc.AddTicks(-($utc.Ticks % [timespan]::TicksPerSecond)) }
    $utc.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-TenureLeaveDateDesired {
    # Desired -> @{ employeeLeaveDateTime = <UTC 'o' string, whole seconds, or $null> }.
    # The key is required: a missing key (a typo) must not quietly clear the leave date.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $table = ConvertTo-TenureTable -InputObject $Desired
    foreach ($key in $table.Keys) {
        if ($key -ne 'employeeLeaveDateTime') {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "User.LeaveDate cannot set '$key'. Allowed: employeeLeaveDateTime." -Category InvalidArgument -Data @{ Provider = 'User.LeaveDate'; Key = [string]$key })
        }
    }
    if (-not $table.ContainsKey('employeeLeaveDateTime')) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message 'User.LeaveDate needs Desired.employeeLeaveDateTime (a UTC date and time, or $null to clear it).' -Category InvalidArgument -Data @{ Provider = 'User.LeaveDate'; Key = 'employeeLeaveDateTime' })
    }
    @{ employeeLeaveDateTime = ConvertTo-TenureUtcDateString -Value $table['employeeLeaveDateTime'] -TruncateToSeconds -Provider 'User.LeaveDate' -Key 'employeeLeaveDateTime' }
}

$null = Register-TenureProvider -Definition @{
    Name        = 'User.LeaveDate'
    Kind        = 'State'
    Backend     = 'Graph'
    # Graph documents both for writing employeeLeaveDateTime; the write also needs the Global Administrator role in delegated use.
    Scopes      = @('User-LifeCycleInfo.ReadWrite.All', 'User.Read.All')
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'user'
    Actions     = @('Update', 'NoOp')
    Description = 'Sets or clears a user''s employeeLeaveDateTime (UTC). Desired: @{ employeeLeaveDateTime = <UTC date or ISO string, or $null> }.'

    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'User.LeaveDate'
        try {
            $user = Invoke-TenureGraph -Method GET -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id) + '?$select=id,employeeLeaveDateTime')
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "User '$id' does not exist." -Category ObjectNotFound -Data @{ Provider = 'User.LeaveDate'; Identity = $id } -Inner $_)
            }
            throw
        }
        [pscustomobject]@{
            id                    = Get-TenureGraphProperty -InputObject $user -Name 'id'
            employeeLeaveDateTime = ConvertTo-TenureUtcDateString -Value (Get-TenureGraphProperty -InputObject $user -Name 'employeeLeaveDateTime') -Provider 'User.LeaveDate' -Key 'employeeLeaveDateTime'
        }
    }

    # Equal after normalizing both sides to UTC whole seconds; $null equals only $null.
    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureLeaveDateDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        $actual = ConvertTo-TenureUtcDateString -Value (Get-TenureGraphProperty -InputObject $Current -Name 'employeeLeaveDateTime') -TruncateToSeconds -Provider 'User.LeaveDate' -Key 'employeeLeaveDateTime'
        return [string]::Equals($actual, $wanted['employeeLeaveDateTime'], [System.StringComparison]::Ordinal)
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)
        $wanted = ConvertTo-TenureLeaveDateDesired -Desired $Desired
        $id = Get-TenureTargetId -Target $Target -Provider 'User.LeaveDate'
        $value = $null
        if ($null -ne $wanted['employeeLeaveDateTime']) {
            # Whole seconds with a Z suffix: the form Graph itself returns.
            $value = ([datetimeoffset]::Parse($wanted['employeeLeaveDateTime'], [System.Globalization.CultureInfo]::InvariantCulture)).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        }
        Invoke-TenureGraph -Method PATCH -Uri ('users/' + (ConvertTo-TenureUriSegment -Value $id)) -Body @{ employeeLeaveDateTime = $value } | Out-Null
        & (Get-TenureProviderDefinition -Name 'User.LeaveDate').Get $Target $Context
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $wanted = ConvertTo-TenureLeaveDateDesired -Desired $Desired
        $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
        $value = if ($null -eq $wanted['employeeLeaveDateTime']) { 'none' } else { $wanted['employeeLeaveDateTime'] }
        "$Action leave date of $name to $value"
    }
}
