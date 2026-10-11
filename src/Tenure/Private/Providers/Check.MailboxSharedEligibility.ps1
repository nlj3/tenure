# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

function ConvertTo-TenureSharedEligibilityDesired {
    # Validates Check.MailboxSharedEligibility Desired. Returns @{ MaxSizeBytes = [long]; AllowArchive = [bool]; AllowHolds = [bool] }.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Desired)

    $provider = 'Check.MailboxSharedEligibility'
    Assert-TenureExchangeDesiredKey -Desired $Desired -Allowed @('maxSizeBytes', 'allowArchive', 'allowHolds') -Provider $provider
    $max = [long]50GB
    $raw = Get-TenureGraphProperty -InputObject $Desired -Name 'maxSizeBytes'
    if ($null -ne $raw) {
        $max = ConvertTo-TenureExchangeInteger -Value $raw
        if ($null -eq $max -or $max -le 0) {
            throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "$provider needs Desired.maxSizeBytes as a positive whole number of bytes (got '$(Format-TenureExchangeSnippet -Text $raw -MaxLength 40)')." -Category InvalidArgument -Data @{ Provider = $provider; Key = 'maxSizeBytes' })
        }
    }
    @{
        MaxSizeBytes = [long]$max
        AllowArchive = Get-TenureExchangeDesiredBool -Desired $Desired -Name 'allowArchive' -Provider $provider
        AllowHolds   = Get-TenureExchangeDesiredBool -Desired $Desired -Name 'allowHolds' -Provider $provider
    }
}

function Get-TenureSharedEligibilityLimit {
    # The size limit a snapshot compares with: Target.MaxSizeBytes, or 50 GB. Get has no Desired, so the limit
    # rides on the target (the way Mailbox.Delegate carries its grantee).
    [CmdletBinding()]
    [OutputType([long])]
    param([AllowNull()][object]$Target)

    $raw = Get-TenureGraphProperty -InputObject $Target -Name 'MaxSizeBytes'
    if ($null -eq $raw) { return [long]50GB }
    $limit = ConvertTo-TenureExchangeInteger -Value $raw
    if ($null -eq $limit -or $limit -le 0) {
        throw (New-TenureError -Id 'Tenure.Step.InvalidTarget' -Message "Check.MailboxSharedEligibility needs Target.MaxSizeBytes as a positive whole number of bytes (got '$(Format-TenureExchangeSnippet -Text $raw -MaxLength 40)')." -Category InvalidArgument -Data @{ Provider = 'Check.MailboxSharedEligibility' })
    }
    [long]$limit
}

function Get-TenureSharedEligibilityProblem {
    <#
    .SYNOPSIS
        Lists why a mailbox snapshot cannot become an unlicensed shared mailbox under the wanted limits. Empty means eligible.
    .DESCRIPTION
        Test and Describe both use this, so the reasons shown always agree with the verdict.
        An unknown size, or a snapshot that compared the size with another limit than the one
        wanted, counts as a problem: the check fails closed. Emits strings one by one; wrap in @(...).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Current,
        [Parameter(Mandatory)][hashtable]$Wanted
    )

    $limit = Format-TenureExchangeGigabyte -Bytes $Wanted.MaxSizeBytes
    $checked = ConvertTo-TenureExchangeInteger -Value (Get-TenureGraphProperty -InputObject $Current -Name 'sizeLimitBytes')
    $over = Get-TenureGraphProperty -InputObject $Current -Name 'overSizeLimit'
    if ($null -eq $checked -or $checked -ne $Wanted.MaxSizeBytes) {
        "mailbox size was compared with another limit than $limit"
    } elseif ($over -isnot [bool]) {
        "mailbox size unknown (limit $limit)"
    } elseif ($over) {
        "mailbox is $limit or more"
    }
    if (-not $Wanted.AllowArchive -and (ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $Current -Name 'archiveEnabled') -Name 'archiveEnabled')) {
        'archive enabled'
    }
    if (-not $Wanted.AllowHolds) {
        # Read directly: a function return would unroll an empty list into $null.
        $hasHolds = $false
        $holds = $null
        if ($Current -is [System.Collections.IDictionary]) {
            $hasHolds = $Current.Contains('holds')
            if ($hasHolds) { $holds = $Current['holds'] }
        } elseif ($Current.PSObject.Properties['holds']) {
            $hasHolds = $true
            $holds = $Current.PSObject.Properties['holds'].Value
        }
        if (-not $hasHolds -or $null -eq $holds -or $holds -is [string]) {
            'holds unknown'
        } else {
            foreach ($kind in @($holds)) {
                switch ([string]$kind) {
                    'litigation' { 'litigation hold' }
                    'inPlace' { 'in-place hold' }
                    'retention' { 'retention hold' }
                    default { "$kind hold" }
                }
            }
        }
    }
}

$null = Register-TenureProvider -Definition @{
    Name        = 'Check.MailboxSharedEligibility'
    Kind        = 'Check'
    Backend     = 'Exchange'
    Scopes      = @()
    Risk        = 'Low'
    Reversible  = $true
    TargetKind  = 'mailbox'
    Actions     = @('Check', 'NoOp')
    AffectedBy  = @('Mailbox.Type')
    Severity    = 'Warn'
    Description = 'Warns before a mailbox is converted to shared when it would still need a license: 50 GB or more, an archive, or a litigation, in-place or retention hold.'

    # Target: @{ Kind = 'mailbox'; Id = <Entra user id>; Name = <UPN>; MaxSizeBytes = 50GB (optional) }
    # Desired: @{ maxSizeBytes = 50GB; allowArchive = $false; allowHolds = $false }
    # Both reads name the mailbox by Entra id (-ExternalDirectoryObjectId), see ExchangeHelpers.ps1.
    # The snapshot holds only the facts the verdict depends on (over the limit or not, archive or not, which
    # kinds of hold), never the raw size: a mailbox grows with every message, and a snapshot that moved with
    # it would report drift between planning and applying for no reason.
    Get         = {
        param($Target, $Context)
        $id = (Get-TenureTargetId -Target $Target -Provider 'Check.MailboxSharedEligibility').Trim()
        $mailbox = Read-TenureExchangeMailbox -Target $Target -Context $Context -Command 'Get-EXOMailbox' -Property @('ArchiveStatus', 'LitigationHoldEnabled', 'InPlaceHolds', 'RetentionHoldEnabled', 'RecipientTypeDetails') -Provider 'Check.MailboxSharedEligibility'
        # A mailbox nobody has signed in to returns no statistics; its size is then unknown, not zero.
        $statistics = @(Invoke-TenureExchangeRead -Command 'Get-EXOMailboxStatistics' -Parameters (Get-TenureExchangeMailboxSelector -Id $id) -Provider 'Check.MailboxSharedEligibility' -Identity $id)
        $size = $null
        if ($statistics.Count -eq 1) { $size = ConvertFrom-TenureExchangeByteSize -Value (Get-TenureGraphProperty -InputObject $statistics[0] -Name 'TotalItemSize') }
        $archive = [string](Get-TenureGraphProperty -InputObject $mailbox -Name 'ArchiveStatus')
        # InPlaceHolds entries that start with '-' are exclusions from an organization-wide policy, not holds.
        $inPlace = @(ConvertTo-TenureExchangeStringList -Value (Get-TenureGraphProperty -InputObject $mailbox -Name 'InPlaceHolds') | Where-Object { -not $_.StartsWith('-', [System.StringComparison]::Ordinal) })
        $holds = [System.Collections.Generic.List[string]]::new()
        if ($inPlace.Count -gt 0) { $holds.Add('inPlace') }
        if (ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $mailbox -Name 'LitigationHoldEnabled') -Name 'LitigationHoldEnabled') { $holds.Add('litigation') }
        if (ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $mailbox -Name 'RetentionHoldEnabled') -Name 'RetentionHoldEnabled') { $holds.Add('retention') }
        $limit = Get-TenureSharedEligibilityLimit -Target $Target
        [pscustomobject]@{
            sizeLimitBytes = $limit
            overSizeLimit  = $(if ($null -eq $size -or $size -lt 0) { $null } else { $size -ge $limit })
            archiveEnabled = (-not [string]::IsNullOrWhiteSpace($archive) -and $archive.Trim() -ine 'None')
            holds          = [string[]]$holds.ToArray()
        }
    }

    Test        = {
        param($Current, $Desired)
        $wanted = ConvertTo-TenureSharedEligibilityDesired -Desired $Desired
        if ($null -eq $Current) { return $false }
        return (@(Get-TenureSharedEligibilityProblem -Current $Current -Wanted $wanted).Count -eq 0)
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $label = Get-TenureExchangeTargetLabel -Target $Target
        $license = 'a shared mailbox in this state still needs an Exchange Online license'
        try {
            $wanted = ConvertTo-TenureSharedEligibilityDesired -Desired $Desired
        } catch {
            return "$Action shared mailbox eligibility of ${label}: invalid desired state"
        }
        if ($null -eq $Current) {
            return "$Action shared mailbox eligibility of ${label}: no mailbox data; $license unless it is under $(Format-TenureExchangeGigabyte -Bytes $wanted.MaxSizeBytes) with no archive and no holds"
        }
        try {
            $problems = @(Get-TenureSharedEligibilityProblem -Current $Current -Wanted $wanted)
        } catch {
            return "$Action shared mailbox eligibility of ${label}: the mailbox snapshot could not be read; $license unless proven otherwise"
        }
        if ($problems.Count -gt 0) {
            return "$Action shared mailbox eligibility of ${label}: $($problems -join '; '); $license"
        }
        # Eligible. With allowArchive / allowHolds an archive or hold can be present, so say which.
        $facts = [System.Collections.Generic.List[string]]::new()
        $facts.Add("under $(Format-TenureExchangeGigabyte -Bytes $wanted.MaxSizeBytes)")
        $facts.Add($(if (ConvertTo-TenureExchangeBool -Value (Get-TenureGraphProperty -InputObject $Current -Name 'archiveEnabled') -Name 'archiveEnabled') { 'archive enabled (allowed)' } else { 'no archive' }))
        $facts.Add($(if (@(Get-TenureGraphProperty -InputObject $Current -Name 'holds' | Where-Object { $null -ne $_ }).Count -gt 0) { 'holds present (allowed)' } else { 'no holds' }))
        "$Action shared mailbox eligibility of ${label}: $($facts -join ', '); can become a shared mailbox without a license"
    }
}
