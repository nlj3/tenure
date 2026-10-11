function New-TenurePassword {
    <#
    .SYNOPSIS
        Generates a random password as a SecureString.
    .DESCRIPTION
        Characters come from System.Security.Cryptography.RandomNumberGenerator and are
        appended to the SecureString one at a time, so the password is never held as a
        string by this function. The result always contains at least one upper case
        letter, one lower case letter, one digit and one symbol from !@#$%^&*()-_=+[]{}:,.?
        and never contains the ambiguous characters 0 O o 1 l I |.
    .PARAMETER Length
        Number of characters, 12 to 128. Default 20.
    .EXAMPLE
        $password = New-TenurePassword -Length 24
    #>
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory SecureString; changes no state.')]
    param(
        [ValidateRange(12, 128)]
        [int]$Length = 20
    )

    $classes = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ'
        'abcdefghijkmnpqrstuvwxyz'
        '23456789'
        '!@#$%^&*()-_=+[]{}:,.?'
    )
    $pool = -join $classes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]
    $chars = [char[]]::new($Length)
    try {
        # One character from each class first, the rest from the whole pool, then shuffle (Fisher-Yates).
        for ($i = 0; $i -lt $Length; $i++) {
            $source = if ($i -lt $classes.Count) { $classes[$i] } else { $pool }
            $chars[$i] = $source[$rng::GetInt32($source.Length)]
        }
        for ($i = $Length - 1; $i -gt 0; $i--) {
            $j = $rng::GetInt32($i + 1)
            $swap = $chars[$i]
            $chars[$i] = $chars[$j]
            $chars[$j] = $swap
        }
        $secure = [System.Security.SecureString]::new()
        foreach ($char in $chars) { $secure.AppendChar($char) }
        $secure.MakeReadOnly()
        return $secure
    } finally {
        [array]::Clear($chars, 0, $chars.Length)
    }
}

function ConvertTo-TenureSecureString {
    <#
    .SYNOPSIS
        Wraps a plaintext value (for example a Temporary Access Pass returned by Graph) in a SecureString.
    .DESCRIPTION
        Uses AppendChar rather than ConvertTo-SecureString -AsPlainText. The caller still
        had to hold the plaintext to call this; do it on the line that receives the value
        and never store, log or return the plaintext.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory SecureString; changes no state.')]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PlainText)

    $secure = [System.Security.SecureString]::new()
    foreach ($char in $PlainText.ToCharArray()) { $secure.AppendChar($char) }
    $secure.MakeReadOnly()
    $secure
}

function ConvertFrom-TenureSecureString {
    <#
    .SYNOPSIS
        Returns the plaintext of a SecureString.
    .DESCRIPTION
        Only ever called on the line that builds a Graph request body. Never log the
        result, never store it in a variable that outlives the request, never put it in
        an error message.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.SecureString]$SecureString)

    [System.Net.NetworkCredential]::new('', $SecureString).Password
}
