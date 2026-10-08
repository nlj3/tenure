BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')
    Import-TenureForTest
    function Get-Canonical($object) { Invoke-InTenure { param($o) Get-TenureCanonicalJson -InputObject $o } @($object) }
    function Get-Hash($object) { Invoke-InTenure { param($o) Get-TenureHash -InputObject $o } @($object) }
}

Describe 'Get-TenureCanonicalJson' {
    It 'is independent of key insertion order' {
        $a = [ordered]@{ zeta = 1; alpha = @{ y = 2; x = 1 }; mid = @(3, 2, 1) }
        $b = [ordered]@{ mid = @(3, 2, 1); alpha = [ordered]@{ x = 1; y = 2 }; zeta = 1 }
        Get-Canonical $a | Should -Be (Get-Canonical $b)
        Get-Canonical $a | Should -Be '{"alpha":{"x":1,"y":2},"mid":[3,2,1],"zeta":1}'
    }

    It 'treats PSCustomObject and hashtable with the same content as equal' {
        $object = [pscustomobject]@{ b = 'two'; a = 1 }
        $table = @{ a = 1; b = 'two' }
        Get-Canonical $object | Should -Be (Get-Canonical $table)
    }

    It 'sorts keys ordinally and case-sensitively' {
        # PowerShell hashtables are case-insensitive, so use an ordinal dictionary (Graph payloads can carry both).
        $dictionary = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        $dictionary['b'] = 1; $dictionary['B'] = 2; $dictionary['a'] = 3
        Get-Canonical $dictionary | Should -Be '{"B":2,"a":3,"b":1}'
    }

    It 'keeps array order' {
        Get-Canonical @{ items = @('c', 'a', 'b') } | Should -Be '{"items":["c","a","b"]}'
    }

    It 'renders null, empty arrays and nested nulls' {
        Get-Canonical $null | Should -Be 'null'
        Get-Canonical @{ list = @(); n = $null } | Should -Be '{"list":[],"n":null}'
    }

    It 'renders dates as UTC round-trip strings' {
        $date = [datetime]::new(2026, 10, 8, 12, 30, 0, [System.DateTimeKind]::Utc)
        Get-Canonical @{ at = $date } | Should -Be '{"at":"2026-10-08T12:30:00.0000000Z"}'
    }

    It 'renders guids and enums as strings' {
        $guid = [guid]'11111111-2222-3333-4444-555555555555'
        Get-Canonical @{ id = $guid; cat = [System.Management.Automation.ErrorCategory]::ObjectNotFound } |
            Should -Be '{"cat":"ObjectNotFound","id":"11111111-2222-3333-4444-555555555555"}'
    }

    It 'refuses SecureString anywhere in the graph' {
        $secret = ConvertTo-SecureString -String 'not-a-real-secret' -AsPlainText -Force
        { Get-Canonical @{ nested = @{ pw = $secret } } } | Should -Throw -ErrorId 'Tenure.Json.SecretRejected'
    }

    It 'refuses PSCredential anywhere in the graph' {
        $credential = [pscredential]::new('user', (ConvertTo-SecureString -String 'x' -AsPlainText -Force))
        { Get-Canonical @{ cred = $credential } } | Should -Throw -ErrorId 'Tenure.Json.SecretRejected'
    }

    It 'refuses absurd nesting' {
        $deep = @{}
        $cursor = $deep
        1..70 | ForEach-Object { $cursor['n'] = @{}; $cursor = $cursor['n'] }
        { Get-Canonical $deep } | Should -Throw -ErrorId 'Tenure.Json.TooDeep'
    }

    Context 'fuzz: random nested objects' {
        BeforeAll {
            $script:random = [System.Random]::new(20261008)
            function New-RandomValue([int]$depth) {
                switch ($script:random.Next(0, 7)) {
                    0 { $script:random.Next(-1000, 1000) }
                    1 { 'str' + $script:random.Next(0, 100) }
                    2 { [bool]($script:random.Next(0, 2)) }
                    3 { $null }
                    4 { if ($depth -lt 3) { New-RandomObject ($depth + 1) } else { 0 } }
                    5 { if ($depth -lt 3) { , @(1..$script:random.Next(0, 4) | ForEach-Object { New-RandomValue ($depth + 1) }) } else { 'leaf' } }
                    6 { [datetime]::new(2026, 1, 1).AddMinutes($script:random.Next(0, 100000)) }
                }
            }
            function New-RandomObject([int]$depth) {
                $table = [ordered]@{}
                $keys = @('alpha', 'Beta', 'gamma', 'delta', 'Z', 'a') | Sort-Object { $script:random.Next() } | Select-Object -First ($script:random.Next(1, 6))
                foreach ($key in $keys) { $table[$key] = New-RandomValue $depth }
                $table
            }
            function Get-Shuffled($object) {
                if ($object -is [System.Collections.IDictionary]) {
                    $shuffled = [ordered]@{}
                    foreach ($key in ($object.Keys | Sort-Object { $script:random.Next() })) { $shuffled[$key] = Get-Shuffled $object[$key] }
                    return $shuffled
                }
                if ($object -is [array]) { return , @($object | ForEach-Object { Get-Shuffled $_ }) }
                $object
            }
        }

        It 'produces the same canonical JSON for key-shuffled copies (50 cases)' {
            foreach ($i in 1..50) {
                $original = New-RandomObject 0
                $shuffled = Get-Shuffled $original
                Get-Canonical $shuffled | Should -Be (Get-Canonical $original) -Because "case $i"
            }
        }
    }
}

Describe 'Get-TenureHash' {
    It 'hashes strings as UTF-8 SHA-256 (known vector)' {
        Get-Hash 'abc' | Should -Be 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    }

    It 'hashes objects through canonical JSON' {
        Get-Hash @{ b = 1; a = 2 } | Should -Be (Get-Hash '{"a":2,"b":1}')
    }

    It 'is lowercase hex of length 64' {
        Get-Hash @{ x = 1 } | Should -Match '^[0-9a-f]{64}$'
    }

    It 'hashes null deterministically' {
        Get-Hash $null | Should -Be (Get-Hash 'null')
    }
}
