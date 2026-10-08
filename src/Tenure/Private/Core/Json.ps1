function ConvertTo-TenureCanonical {
    <#
    .SYNOPSIS
        Rebuilds an object graph with ordinal-sorted keys so JSON output is stable.
    .DESCRIPTION
        Dictionaries and PSCustomObjects become ordered dictionaries with keys sorted
        ordinally (case-sensitive). Arrays keep their order. Dates become UTC 'o'
        strings. SecureString is refused: nothing hashed or serialized may be a secret.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$InputObject,

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
    if ($InputObject -is [enum]) { return $InputObject.ToString() }
    if ($InputObject -is [guid]) { return $InputObject.ToString() }
    if ($InputObject -is [bool] -or $InputObject -is [System.ValueType]) { return $InputObject }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $keys = @($InputObject.Keys | ForEach-Object { [string]$_ })
        [array]::Sort($keys, [System.StringComparer]::Ordinal)
        $ordered = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
        foreach ($key in $keys) {
            $ordered[$key] = ConvertTo-TenureCanonical -InputObject $InputObject[$key] -Depth ($Depth + 1)
        }
        return $ordered
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) {
            $list.Add((ConvertTo-TenureCanonical -InputObject $item -Depth ($Depth + 1)))
        }
        return , $list.ToArray()
    }

    # PSCustomObject and other objects: project their properties.
    $properties = @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -in 'NoteProperty', 'Property', 'AliasProperty', 'ScriptProperty' })
    $names = @($properties | ForEach-Object { [string]$_.Name })
    [array]::Sort($names, [System.StringComparer]::Ordinal)
    $ordered = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
    foreach ($name in $names) {
        $value = ($properties | Where-Object Name -eq $name | Select-Object -First 1).Value
        $ordered[$name] = ConvertTo-TenureCanonical -InputObject $value -Depth ($Depth + 1)
    }
    return $ordered
}

function Get-TenureCanonicalJson {
    <#
    .SYNOPSIS
        Compressed JSON with ordinally sorted keys. Same object graph, same string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$InputObject
    )

    $canonical = ConvertTo-TenureCanonical -InputObject $InputObject
    if ($null -eq $canonical) { return 'null' }
    ConvertTo-Json -InputObject $canonical -Depth 64 -Compress
}

function Get-TenureHash {
    <#
    .SYNOPSIS
        Lowercase SHA-256 hex of a string, or of the canonical JSON of any other object.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [object]$InputObject
    )

    $text = if ($InputObject -is [string]) { $InputObject } else { Get-TenureCanonicalJson -InputObject $InputObject }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    [System.Convert]::ToHexString($hash).ToLowerInvariant()
}
