BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest

    function New-Password([int]$Length = 0) {
        Invoke-InTenure { param($n) if ($n -gt 0) { New-TenurePassword -Length $n } else { New-TenurePassword } } @($Length)
    }
    function ConvertFrom-Secure($Secure) {
        Invoke-InTenure { param($s) ConvertFrom-TenureSecureString -SecureString $s } @(, $Secure)
    }
    # 200 generations of the default length, as plaintext, for the statistical checks.
    $script:Samples = @(Invoke-InTenure { 1..200 | ForEach-Object { ConvertFrom-TenureSecureString -SecureString (New-TenurePassword) } })
}

Describe 'New-TenurePassword' {
    It 'returns a read-only SecureString of the default length 20' {
        $secure = New-Password
        $secure | Should -BeOfType [System.Security.SecureString]
        $secure.IsReadOnly() | Should -BeTrue
        $secure.Length | Should -Be 20
    }

    It 'honors -Length across the allowed range' -ForEach @(@{ Length = 12 }, @{ Length = 13 }, @{ Length = 64 }, @{ Length = 128 }) {
        (New-Password $Length).Length | Should -Be $Length
    }

    It 'enforces Length 12..128' -ForEach @(@{ Length = 11 }, @{ Length = 0 }, @{ Length = -5 }, @{ Length = 129 }) {
        { Invoke-InTenure { param($n) New-TenurePassword -Length $n } @($Length) } | Should -Throw
    }

    It 'always contains an upper case letter, a lower case letter, a digit and a symbol (200 generations)' {
        $script:Samples.Count | Should -Be 200
        foreach ($password in $script:Samples) {
            $password | Should -CMatch '[A-Z]'
            $password | Should -CMatch '[a-z]'
            $password | Should -Match '[0-9]'
            $password | Should -CMatch '[!@#$%^&*()\-_=+\[\]{}:,.?]'
        }
    }

    It 'also holds the class guarantee at the minimum length (200 generations)' {
        $short = @(Invoke-InTenure { 1..200 | ForEach-Object { ConvertFrom-TenureSecureString -SecureString (New-TenurePassword -Length 12) } })
        foreach ($password in $short) {
            $password.Length | Should -Be 12
            $password | Should -CMatch '[A-Z]'
            $password | Should -CMatch '[a-z]'
            $password | Should -Match '[0-9]'
            $password | Should -CMatch '[!@#$%^&*()\-_=+\[\]{}:,.?]'
        }
    }

    It 'never uses the ambiguous characters 0 O o 1 l I |' {
        foreach ($password in $script:Samples) { $password | Should -Not -CMatch '[0OolI1|]' }
    }

    It 'only uses letters, digits and the agreed symbols' {
        foreach ($password in $script:Samples) { $password | Should -CMatch '^[A-Za-z0-9!@#$%^&*()\-_=+\[\]{}:,.?]+$' }
    }

    It 'two calls differ, and the 200 samples are all distinct' {
        (ConvertFrom-Secure (New-Password)) | Should -Not -Be (ConvertFrom-Secure (New-Password))
        @($script:Samples | Select-Object -Unique).Count | Should -Be 200
    }

    It 'draws from every character class position, not just a fixed prefix (shuffled)' {
        # If the guaranteed characters stayed in positions 0-3, the first four would always be upper, lower, digit, symbol.
        $fixedPrefix = @($script:Samples | Where-Object { $_[0] -cmatch '[A-Z]' -and $_[1] -cmatch '[a-z]' -and $_[2] -match '[0-9]' -and $_[3] -cmatch '[^A-Za-z0-9]' })
        $fixedPrefix.Count | Should -BeLessThan 20
    }
}

Describe 'ConvertFrom-TenureSecureString and ConvertTo-TenureSecureString' {
    It 'round-trips a generated password' {
        $secure = New-Password 24
        $plain = ConvertFrom-Secure $secure
        $plain.Length | Should -Be 24
        $again = Invoke-InTenure { param($p) ConvertTo-TenureSecureString -PlainText $p } @($plain)
        (ConvertFrom-Secure $again) | Should -BeExactly $plain
    }

    It 'ConvertTo-TenureSecureString returns a read-only SecureString and accepts an empty string' {
        $secure = Invoke-InTenure { param($p) ConvertTo-TenureSecureString -PlainText $p } @('TAP-abc123')
        $secure | Should -BeOfType [System.Security.SecureString]
        $secure.IsReadOnly() | Should -BeTrue
        (ConvertFrom-Secure $secure) | Should -BeExactly 'TAP-abc123'
        (Invoke-InTenure { ConvertTo-TenureSecureString -PlainText '' }).Length | Should -Be 0
    }

    It 'ConvertFrom-TenureSecureString refuses a non-SecureString' {
        { Invoke-InTenure { param($s) ConvertFrom-TenureSecureString -SecureString $s } @('plain text') } | Should -Throw
    }
}
