<#
    Shared helpers for the Exchange Online providers: reading through the
    Exchange seam with the TargetNotFound mapping, naming a mailbox the way Exchange
    can be trusted to resolve it, and parsing what the Exchange cmdlets return (sizes,
    SMTP addresses, HTML auto-reply text, access rights).
    Only Invoke-TenureExchangeRead calls the seam. No cmdlet name appears in this file
    outside block comments: the seam scanner strips -Command literals only in provider
    files, so cmdlet names are always passed in by the provider.

    Identity contract. A mailbox target's Id is the Entra object id of its owner, but real
    Exchange is not trusted to resolve an Entra id given as -Identity: it may answer
    "couldn't be found" for a mailbox that exists. So the Get-EXO reads name the mailbox
    with -ExternalDirectoryObjectId, and every other cmdlet gets the mailbox's user
    principal name (for -Identity, -User and -Member) or a group's primary SMTP address.
#>

function Test-TenureExchangeError {
    <#
    .SYNOPSIS
        True when an ErrorRecord is a Tenure.Exchange.Failed whose message matches any of the -like patterns.
    .DESCRIPTION
        Providers use this to recognize the few cmdlet failures that mean "already in the
        goal state" (for example "already a member"). Only Tenure.Exchange.Failed counts:
        NotConnected and CommandUnavailable are never treated as success.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory)][string[]]$Like
    )

    if ((Get-TenureErrorId -ErrorRecord $ErrorRecord) -cne 'Tenure.Exchange.Failed') { return $false }
    $text = [string]$ErrorRecord.Exception.Message
    foreach ($pattern in $Like) {
        if ($text -like $pattern) { return $true }
    }
    return $false
}

function Test-TenureExchangeNotFound {
    <#
    .SYNOPSIS
        True when an Exchange failure says that one of the values in -Name "couldn't be found".
    .DESCRIPTION
        Exchange reports a missing object as a cmdlet failure such as "The operation couldn't
        be performed because object 'alice@example.com' couldn't be found on '...'." Only that
        counts as not found, and only when the message names, in quotes, a value this read
        asked for. A failure that says something else "couldn't be found" (a server, a domain
        controller, a session) is a failed read, not proof that the object is missing, and
        must never be taken for "this user has no mailbox". Only Tenure.Exchange.Failed counts.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [AllowEmptyCollection()][string[]]$Name = @()
    )

    if ((Get-TenureErrorId -ErrorRecord $ErrorRecord) -cne 'Tenure.Exchange.Failed') { return $false }
    $text = [string]$ErrorRecord.Exception.Message
    if ($text.IndexOf("couldn't be found", [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    foreach ($value in @($Name)) {
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($text.IndexOf("'" + $value.Trim() + "'", [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function Invoke-TenureExchangeRead {
    <#
    .SYNOPSIS
        Runs a read through the Exchange seam; "'<value>' couldn't be found" becomes Tenure.Provider.TargetNotFound.
    .DESCRIPTION
        Exchange reports a missing mailbox, recipient or group as a cmdlet failure whose
        message says the object "couldn't be found". A provider Get must report that as
        Tenure.Provider.TargetNotFound (SPEC section 2.2). The mapping is narrow: the message
        must name one of -NotFoundName (by default -Identity, the value the read was given),
        see Test-TenureExchangeNotFound. Every other error passes through unchanged.
        Without -Single the objects are emitted one by one: wrap the call in @(...).
        With -Single exactly one object is returned; none is TargetNotFound and more
        than one is Tenure.Provider.InvalidResult (never guess which object was meant).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][string]$Command,
        [hashtable]$Parameters = @{},
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$Identity,
        [string[]]$NotFoundName,
        [switch]$Single
    )

    if (-not $PSBoundParameters.ContainsKey('NotFoundName')) { $NotFoundName = @($Identity) }
    try {
        $result = @(Invoke-TenureExchange -Command $Command -Parameters $Parameters | Where-Object { $null -ne $_ })
    } catch {
        if (Test-TenureExchangeNotFound -ErrorRecord $_ -Name $NotFoundName) {
            throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "$Provider found no Exchange object for '$Identity': $($_.Exception.Message)" -Category ObjectNotFound -Data @{ Provider = $Provider; Identity = $Identity } -Inner $_)
        }
        throw
    }
    if (-not $Single) { return $result }
    if ($result.Count -eq 0) {
        throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "$Provider found no Exchange object for '$Identity'." -Category ObjectNotFound -Data @{ Provider = $Provider; Identity = $Identity })
    }
    if ($result.Count -gt 1) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidResult' -Message "$Provider expected one Exchange object for '$Identity' and got $($result.Count); refusing to guess." -Category InvalidResult -Data @{ Provider = $Provider; Identity = $Identity; Count = $result.Count })
    }
    $result[0]
}

function Test-TenureExchangeObjectId {
    <#
    .SYNOPSIS
        True when a value is shaped like an Entra object id (a GUID in its usual 8-4-4-4-12 form).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value.Trim() -cmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Get-TenureExchangeMailboxSelector {
    <#
    .SYNOPSIS
        The parameters that name a mailbox for a Get-EXO read: -ExternalDirectoryObjectId for an Entra object id, -Identity for anything else.
    .DESCRIPTION
        Returns a new hashtable; the caller adds the other parameters. Only the Get-EXO reads
        take -ExternalDirectoryObjectId; every other cmdlet needs the address from
        Resolve-TenureExchangeMailboxAddress.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$Id)

    $value = $Id.Trim()
    if (Test-TenureExchangeObjectId -Value $value) { return @{ ExternalDirectoryObjectId = $value } }
    @{ Identity = $value }
}

function Get-TenureExchangeAddressCache {
    <#
    .SYNOPSIS
        The plan-time table of mailbox addresses (Context.ExchangeAddresses), or $null when there is none.
    .DESCRIPTION
        While a plan builder runs (Context.Mode 'Plan'), the user principal name that a
        mailbox read by Entra id returned is kept here, keyed by the lower-case id, so the
        later steps of the same plan need not read it again (SPEC section 7 budgets the
        Exchange calls of an offboard plan). The apply engine builds a fresh context for
        every step without this table, so at apply time every address is read afresh.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Context)

    if ($Context -isnot [System.Collections.IDictionary]) { return $null }
    if ([string]$Context['Mode'] -cne 'Plan') { return $null }
    $cache = $Context['ExchangeAddresses']
    if ($cache -is [hashtable]) { return $cache }
    $null
}

function Get-TenureExchangeMailboxAddress {
    <#
    .SYNOPSIS
        The address to name a mailbox by: its user principal name, else its primary SMTP address, in lower case; $null when it has neither.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Mailbox)

    foreach ($name in 'UserPrincipalName', 'PrimarySmtpAddress') {
        $value = [string](Get-TenureGraphProperty -InputObject $Mailbox -Name $name)
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim().ToLowerInvariant() }
    }
    $null
}

function Read-TenureExchangeMailbox {
    <#
    .SYNOPSIS
        Reads the target's mailbox with a Get-EXO read named by the provider, by Entra object id.
    .DESCRIPTION
        Target.Id is the Entra object id of the mailbox owner and is passed as
        -ExternalDirectoryObjectId (a target id that is an address is passed as -Identity).
        A mailbox Exchange returns for another id is Tenure.Provider.InvalidResult: the
        provider never acts on an object it did not ask for. "Couldn't be found" naming the
        id is Tenure.Provider.TargetNotFound; any other failure passes through. While a plan
        is built the mailbox's address is kept for the later steps (Get-TenureExchangeAddressCache).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [AllowNull()][object]$Target,
        [AllowNull()][object]$Context,
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Property = @(),
        [Parameter(Mandatory)][string]$Provider
    )

    $id = (Get-TenureTargetId -Target $Target -Provider $Provider).Trim()
    $parameters = Get-TenureExchangeMailboxSelector -Id $id
    if ($Property.Count -gt 0) { $parameters['Properties'] = [string[]]$Property }
    $mailbox = Invoke-TenureExchangeRead -Command $Command -Parameters $parameters -Provider $Provider -Identity $id -Single
    if ($parameters.ContainsKey('ExternalDirectoryObjectId')) {
        $found = ([string](Get-TenureGraphProperty -InputObject $mailbox -Name 'ExternalDirectoryObjectId')).Trim()
        if (-not [string]::Equals($found, $id, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidResult' -Message "$Provider asked Exchange for the mailbox of '$id' and got one for '$(Format-TenureExchangeSnippet -Text $found -MaxLength 60)'; refusing to act on it." -Category InvalidResult -Data @{ Provider = $Provider; Identity = $id })
        }
        $cache = Get-TenureExchangeAddressCache -Context $Context
        $address = Get-TenureExchangeMailboxAddress -Mailbox $mailbox
        if ($null -ne $cache -and $address) { $cache[$id.ToLowerInvariant()] = $address }
    }
    $mailbox
}

function Resolve-TenureExchangeMailboxAddress {
    <#
    .SYNOPSIS
        The user principal name to pass as -Identity for the target's mailbox to a cmdlet that is not a Get-EXO read.
    .DESCRIPTION
        Taken from, in order: the Current snapshot when it names this mailbox (its identity
        equals Target.Id; the apply engine hands Set the state it has just read by Entra id),
        the plan-time table, or a read of the mailbox by its Entra id with -Command (the
        provider's Get-EXO read). A target id that is already an address is used as it is.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$Target,
        [AllowNull()][object]$Current,
        [AllowNull()][object]$Context,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$Provider
    )

    $id = (Get-TenureTargetId -Target $Target -Provider $Provider).Trim()
    if (-not (Test-TenureExchangeObjectId -Value $id)) { return $id }
    $known = ([string](Get-TenureGraphProperty -InputObject $Current -Name 'identity')).Trim()
    $knownAddress = ([string](Get-TenureGraphProperty -InputObject $Current -Name 'userPrincipalName')).Trim()
    if ($knownAddress -and [string]::Equals($known, $id, [System.StringComparison]::OrdinalIgnoreCase)) { return $knownAddress.ToLowerInvariant() }
    $cache = Get-TenureExchangeAddressCache -Context $Context
    if ($null -ne $cache -and $cache.ContainsKey($id.ToLowerInvariant())) { return [string]$cache[$id.ToLowerInvariant()] }
    $mailbox = Read-TenureExchangeMailbox -Target $Target -Context $Context -Command $Command -Provider $Provider
    $address = Get-TenureExchangeMailboxAddress -Mailbox $mailbox
    if (-not $address) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidResult' -Message "$Provider read the mailbox of '$id' but Exchange returned no user principal name or primary SMTP address to name it by." -Category InvalidResult -Data @{ Provider = $Provider; Identity = $id })
    }
    $address
}

function Get-TenureExchangeObjectId {
    <#
    .SYNOPSIS
        The stable id of an Exchange object for state snapshots: ExternalDirectoryObjectId (the Entra id), else Identity.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$InputObject)

    $id = [string](Get-TenureGraphProperty -InputObject $InputObject -Name 'ExternalDirectoryObjectId')
    if ([string]::IsNullOrWhiteSpace($id)) { $id = [string](Get-TenureGraphProperty -InputObject $InputObject -Name 'Identity') }
    if ([string]::IsNullOrWhiteSpace($id)) { return $null }
    $id.ToLowerInvariant()
}

function Get-TenureExchangeTargetLabel {
    <#
    .SYNOPSIS
        Target.Name, else Target.Id, for one-line descriptions.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Target)

    $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name')
    if (-not [string]::IsNullOrWhiteSpace($name)) { return (Format-TenureExchangeSnippet -Text $name -MaxLength 120) }
    $id = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Id')
    if (-not [string]::IsNullOrWhiteSpace($id)) { return (Format-TenureExchangeSnippet -Text $id -MaxLength 120) }
    '(unknown target)'
}

function ConvertTo-TenureExchangeBool {
    <#
    .SYNOPSIS
        Reads a boolean that Exchange returned. $null and '' are $false; 'True'/'False' strings are parsed.
    .DESCRIPTION
        A cast would turn the string 'False' into $true, so values are parsed, never cast.
        Anything that is not a boolean is Tenure.Provider.InvalidResult.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [string]) {
        if ($Value.Trim().Length -eq 0) { return $false }
        $parsed = $false
        if ([bool]::TryParse($Value.Trim(), [ref]$parsed)) { return $parsed }
    }
    throw (New-TenureError -Id 'Tenure.Provider.InvalidResult' -Message "Exchange returned '$Name' as $($Value.GetType().Name); expected a boolean." -Category InvalidResult -Data @{ Property = $Name })
}

function ConvertTo-TenureExchangeInteger {
    <#
    .SYNOPSIS
        Returns an integral number as [long], or $null for anything else (strings, fractions, booleans, $null).
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [short] -or $Value -is [byte] -or $Value -is [uint32] -or $Value -is [uint16] -or $Value -is [sbyte]) {
        return [long]$Value
    }
    if ($Value -is [uint64]) {
        if ($Value -le [uint64][long]::MaxValue) { return [long]$Value }
        return $null
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        $number = [decimal]0
        try { $number = [decimal]$Value } catch { return $null }
        if ($number -ne [decimal]::Truncate($number)) { return $null }
        if ($number -gt [decimal][long]::MaxValue -or $number -lt [decimal][long]::MinValue) { return $null }
        return [long]$number
    }
    $null
}

function ConvertFrom-TenureExchangeByteSize {
    <#
    .SYNOPSIS
        Parses an Exchange size such as "61.2 GB (65,712,345,678 bytes)" into a byte count ([long]).
    .DESCRIPTION
        Only the "(N bytes)" part is trusted: its digits are kept and every other character
        (thousands separators of any culture) is dropped. A plain integral number is taken
        as bytes. Anything else, including a missing value, returns $null so a caller can
        treat the size as unknown instead of as zero.
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    $number = ConvertTo-TenureExchangeInteger -Value $Value
    if ($null -ne $number) {
        if ($number -lt 0) { return $null }
        return $number
    }
    $match = [regex]::Match([string]$Value, '\(([^()]*?)\s*bytes\s*\)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) { return $null }
    $digits = [regex]::Replace($match.Groups[1].Value, '[^0-9]', '')
    if ($digits.Length -eq 0 -or $digits.Length -gt 18) { return $null }
    [long]$digits
}

function Format-TenureExchangeGigabyte {
    <#
    .SYNOPSIS
        Formats a byte count as gigabytes with at most one decimal (binary units, as Exchange counts them): 65712345678 -> '61.2 GB'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][long]$Bytes)

    ([double]$Bytes / 1GB).ToString('0.#', [System.Globalization.CultureInfo]::InvariantCulture) + ' GB'
}

function ConvertTo-TenureExchangeSmtp {
    <#
    .SYNOPSIS
        Normalizes an SMTP address: trims, strips an 'smtp:' prefix (any case) and lowercases. $null or blank gives $null.
    .DESCRIPTION
        Exchange returns ForwardingSmtpAddress as a proxy address ('smtp:user@example.com').
        Lowercasing is for comparison and stable snapshots; mail routing is case-insensitive.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim()
    if ($text.Length -ge 5 -and $text.Substring(0, 5) -ieq 'smtp:') { $text = $text.Substring(5).Trim() }
    if ($text.Length -eq 0) { return $null }
    $text.ToLowerInvariant()
}

function Test-TenureExchangeSmtp {
    <#
    .SYNOPSIS
        True when a normalized value is one plain SMTP address (local@domain.tld, no spaces, no list separators).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][string]$Address)

    if ([string]::IsNullOrEmpty($Address)) { return $false }
    return ($Address -cmatch '^[^@\s,;:<>"()\[\]\\]+@[^@\s,;:<>"()\[\]\\]+\.[^@\s,;:<>"()\[\]\\.]+$')
}

function ConvertTo-TenureExchangePlainText {
    <#
    .SYNOPSIS
        Turns an auto-reply message into plain text: tags become spaces, entities are decoded, whitespace runs collapse.
    .DESCRIPTION
        Exchange stores auto-reply messages as HTML and returns them wrapped in
        <html><body>...</body></html> even when plain text was set, so a byte comparison
        with what was set never matches. Tags become a space (not nothing) so that
        "<div>a</div><div>b</div>" reads "a b". Returns $null for empty text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    $text = [regex]::Replace($text, '(?is)<(script|style)\b.*?</\1\s*>', ' ')
    $text = [regex]::Replace($text, '(?s)<!--.*?-->', ' ')
    $text = [regex]::Replace($text, '<[^>]*>', ' ')
    $text = [System.Net.WebUtility]::HtmlDecode($text)
    $text = [regex]::Replace($text, '\s+', ' ').Trim()
    if ($text.Length -eq 0) { return $null }
    $text
}

function Get-TenureExchangeTextKey {
    <#
    .SYNOPSIS
        Comparison key for auto-reply text: the plain text with all whitespace removed ('' for empty).
    .DESCRIPTION
        Exchange re-flows the HTML it stores (line breaks become <br> or separate <div>
        elements), so whitespace is not a reliable signal. Two messages are the same when
        their plain text is the same apart from whitespace. Comparison is ordinal.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)

    $plain = ConvertTo-TenureExchangePlainText -Value $Value
    if ($null -eq $plain) { return '' }
    [regex]::Replace($plain, '\s+', '')
}

function Format-TenureExchangeSnippet {
    <#
    .SYNOPSIS
        One line of at most -MaxLength characters; longer text is cut and ends with '...'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$Text,
        [ValidateRange(4, 1000)][int]$MaxLength = 60
    )

    if ($null -eq $Text) { return '' }
    $line = [regex]::Replace([string]$Text, '\s+', ' ').Trim()
    if ($line.Length -le $MaxLength) { return $line }
    $line.Substring(0, $MaxLength - 3).TrimEnd() + '...'
}

function ConvertTo-TenureExchangeStringList {
    <#
    .SYNOPSIS
        Flattens a string, array or list into sorted, de-duplicated, non-empty strings. Emits them one by one: wrap in @(...).
    .DESCRIPTION
        Exchange returns AccessRights as an array or as "FullAccess, ReadPermission";
        -Split also splits on commas. Duplicates are dropped case-insensitively and the
        result is sorted ordinally so state snapshots are stable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$Value,
        [switch]$Split
    )

    if ($null -eq $Value) { return }
    # @() enumerates an array or list and wraps a single value (a string stays whole).
    $items = @($Value)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $items) {
        if ($null -eq $item) { continue }
        $parts = if ($Split) { ([string]$item).Split(',') } else { @([string]$item) }
        foreach ($part in $parts) {
            $text = $part.Trim()
            if ($text.Length -eq 0) { continue }
            if ($seen.Add($text)) { $list.Add($text) }
        }
    }
    $array = $list.ToArray()
    [array]::Sort($array, [System.StringComparer]::Ordinal)
    $array
}

function Assert-TenureExchangeDesiredKey {
    <#
    .SYNOPSIS
        Throws Tenure.Provider.InvalidDesired when Desired has a key outside -Allowed (case-insensitive). Typos must not pass silently.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [AllowNull()][object]$Desired,
        [Parameter(Mandatory)][string[]]$Allowed,
        [Parameter(Mandatory)][string]$Provider
    )

    if ($null -ne $Desired -and -not ($Desired -is [System.Collections.IDictionary] -or $Desired -is [System.Management.Automation.PSCustomObject])) {
        throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$Provider needs Desired as a hashtable or object (got $($Desired.GetType().Name))." -Category InvalidArgument -Data @{ Provider = $Provider })
    }
    $table = ConvertTo-TenureTable -InputObject $Desired
    foreach ($key in $table.Keys) {
        if (-not ($Allowed | Where-Object { $_ -ieq $key })) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$Provider does not understand Desired.$(Format-TenureExchangeSnippet -Text $key -MaxLength 40). Allowed: $($Allowed -join ', ')." -Category InvalidArgument -Data @{ Provider = $Provider; Key = (Format-TenureExchangeSnippet -Text $key -MaxLength 40) })
        }
    }
}

function Get-TenureExchangeDesiredBool {
    <#
    .SYNOPSIS
        Reads a boolean from Desired. Absent or $null gives -Default, or throws when -Required; a non-boolean always throws.
    .DESCRIPTION
        The value must be a real [bool]: the string 'false' would cast to $true, which for
        a grant or a membership is the opposite of what was asked. Errors are
        Tenure.Provider.InvalidDesired.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][object]$Desired,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Provider,
        [switch]$Required,
        [bool]$Default = $false
    )

    $value = Get-TenureGraphProperty -InputObject $Desired -Name $Name
    if ($null -eq $value) {
        if ($Required) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$Provider needs Desired.$Name (true or false)." -Category InvalidArgument -Data @{ Provider = $Provider; Key = $Name })
        }
        return $Default
    }
    if ($value -is [bool]) { return $value }
    throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$Provider needs Desired.$Name as true or false (got $($value.GetType().Name))." -Category InvalidArgument -Data @{ Provider = $Provider; Key = $Name })
}
