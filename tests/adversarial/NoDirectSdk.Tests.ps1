# CONTRIBUTING.md rule 1: every tenant call goes through the two seams. This suite greps
# the source for SDK commands outside the files allowed to contain them.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')

    $script:Allowed = @{
        'Private/Core/Graph.ps1'      = @('Invoke-MgGraphRequest')
        'Private/Core/Connection.ps1' = @('Connect-MgGraph', 'Disconnect-MgGraph', 'Get-MgContext', 'Connect-ExchangeOnline', 'Disconnect-ExchangeOnline', 'Get-ConnectionInformation')
        'Public/Connect-Tenure.ps1'   = @('Connect-MgGraph', 'Get-MgContext', 'Connect-ExchangeOnline', 'Get-ConnectionInformation')
        'Public/Disconnect-Tenure.ps1' = @('Disconnect-MgGraph', 'Disconnect-ExchangeOnline')
    }
    $script:Forbidden = [regex]'(?<![\w-])(Invoke-MgGraphRequest|Invoke-MgRestMethod|(?:Get|New|Set|Remove|Update|Add|Invoke|Connect|Disconnect)-Mg[A-Za-z]+|Get-EXO[A-Za-z]+|(?:Get|Set|New|Remove|Enable|Disable)-(?:Mailbox|CASMailbox|Mailbox[A-Za-z]+|DistributionGroup[A-Za-z]*|UnifiedGroup[A-Za-z]*|Recipient|User|CalendarEvents|RemoteMailbox)|Add-MailboxPermission|Remove-MailboxPermission|Add-RecipientPermission|Remove-CalendarEvents|Connect-ExchangeOnline|Disconnect-ExchangeOnline|Get-ConnectionInformation|Connect-IPPSSession|Connect-SPOService|Connect-PnPOnline|Connect-AzureAD|Connect-MsolService)(?![\w-])'

    function Get-SdkViolation([string]$RelativePath, [string]$Content) {
        $allowed = @()
        if ($script:Allowed.ContainsKey($RelativePath)) { $allowed = $script:Allowed[$RelativePath] }
        # Block comments (including comment-based help) may mention cmdlets freely; blank them line-preserving.
        $Content = [regex]::Replace($Content, '(?s)<#.*?#>', { param($m) ($m.Value -replace '[^\r\n]', ' ') })
        $lines = $Content -split "`r?`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -match '^\s*#') { continue }
            $line = $line -replace '#.*$', ''
            foreach ($match in $script:Forbidden.Matches($line)) {
                if ($match.Groups[1].Value -in $allowed) { continue }
                [pscustomobject]@{ File = $RelativePath; Line = $i + 1; Command = $match.Groups[1].Value }
            }
        }
    }
}

Describe 'No direct SDK calls outside the seams' {
    It 'the scanner itself catches a provider that calls Invoke-MgGraphRequest' {
        $violations = @(Get-SdkViolation 'Private/Providers/User.Bad.ps1' "function x {`n  `$r = Invoke-MgGraphRequest -Uri users`n}")
        $violations.Count | Should -Be 1
        $violations[0].Command | Should -Be 'Invoke-MgGraphRequest'
        $violations[0].Line | Should -Be 2
    }

    It 'the scanner catches Exchange cmdlets and Graph SDK cmdlets' {
        @(Get-SdkViolation 'Private/Providers/M.ps1' 'Set-Mailbox -Identity x -Type Shared').Count | Should -Be 1
        @(Get-SdkViolation 'Private/Providers/M.ps1' 'Get-MgUser -UserId x').Count | Should -Be 1
        @(Get-SdkViolation 'Private/Providers/M.ps1' 'Get-EXOMailbox -Identity x').Count | Should -Be 1
    }

    It 'the scanner ignores comments and the seam helpers' {
        @(Get-SdkViolation 'Private/Providers/M.ps1' '# Set-Mailbox is wrapped by Invoke-TenureExchange').Count | Should -Be 0
        @(Get-SdkViolation 'Private/Providers/M.ps1' "Invoke-TenureExchange -Command 'Set-Mailbox'").Count | Should -Be 1 -Because 'a string literal naming a cmdlet still counts; the scanner only skips comments'
    }

    It 'the scanner still allows a listed command in its allowed file' {
        @(Get-SdkViolation 'Private/Core/Graph.ps1' '$r = Invoke-MgGraphRequest @p').Count | Should -Be 0
        @(Get-SdkViolation 'Private/Core/Graph.ps1' '$r = Get-MgUser').Count | Should -Be 1
    }

    It 'finds no violations in src/' {
        $files = Get-ChildItem -Path $script:TenureSourceRoot -Recurse -Filter '*.ps1' -File
        $violations = foreach ($file in $files) {
            $relative = $file.FullName.Substring($script:TenureSourceRoot.Length + 1) -replace '\\', '/'
            $content = Get-Content -LiteralPath $file.FullName -Raw
            # Providers name Exchange cmdlets as strings for Invoke-TenureExchange -Command; strip single-quoted literals there.
            if ($relative -like 'Private/Providers/*' -or $relative -like 'Private/Core/Resolve*.ps1') {
                $content = $content -replace "-Command\s+'[^']+'", '-Command <literal>'
            }
            Get-SdkViolation $relative $content
        }
        $violations = @($violations)
        if ($violations.Count -gt 0) {
            $report = ($violations | ForEach-Object { "$($_.File):$($_.Line) $($_.Command)" }) -join "`n"
            throw "Direct SDK calls found outside the seams:`n$report"
        }
        $violations.Count | Should -Be 0
    }
}
