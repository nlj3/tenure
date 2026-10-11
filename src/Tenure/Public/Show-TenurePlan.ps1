function Show-TenurePlan {
    <#
    .SYNOPSIS
        Shows a plan as plain text: a header, one row per step, dependencies, warnings and a legend.
    .DESCRIPTION
        This is the view to read before you apply anything. It prints three header lines (plan
        id, operation and subject; who made the plan, when, with which module version and policy;
        the status and a count of steps by kind), then one row per step in execution order:

            ~ S01 User.SignIn  alice@example.com  enabled: true -> false

        The first column is a symbol: + create, ~ update, - remove, ! invoke, = no-op (already
        satisfied), ? check, and x for a step whose Risk is Destructive and whose action is
        anything but a no-op. A no-op never reaches the provider's Set, so it always shows = and
        is not counted or listed as destructive, even when its provider is rated Destructive.
        The symbol follows the plan's intent: a destructive step keeps its x after it is Applied
        or Skipped.
        Then come the step id, the provider, the target name and the reason. Ids and provider
        names are never shortened. A target name over 28 characters is not cut either; it pushes
        its row to the right. The reason wraps at -Width, and continuation lines sit under the
        Reason column.

        Once any step has left Pending, every row ends with its status in brackets, for example
        [Applied] or [Drifted]. A Failed, Drifted or Refused step also gets one extra line with
        the Error (or, when there is none, the Note) recorded in its Result.

        After the rows: a Depends line listing every dependency edge as "<step> -> <dependency>"
        (only when there are any), the plan warnings (only when there are any), a Destructive
        line naming the destructive steps and what they need (only when there are any), and
        always the legend. Before and After contents are never printed, and nothing is read from
        a Secrets table. The text is the same with color on or off; set the NO_COLOR environment
        variable to turn color off.
    .PARAMETER Plan
        The Tenure.Plan to show, from New-TenurePlan, one of the New-Tenure*Plan builders or
        Import-TenurePlan. Accepted from the pipeline.
    .PARAMETER PassThru
        Also write the lines to the success pipeline as strings. Without it the function only
        writes to the host and returns nothing.
    .PARAMETER Width
        Line width to wrap at. Defaults to the host window width when the host reports one,
        otherwise 120. Anything below 80 is raised to 80.
    .EXAMPLE
        Show-TenurePlan -Plan $plan

        Prints the plan to the console for review.
    .EXAMPLE
        Show-TenurePlan -Plan $plan -PassThru -Width 100 | Set-Content -Path ./offboard-review.txt -Encoding utf8

        Prints the plan and also saves the same text to a file, for example to attach to a change ticket.
    .OUTPUTS
        System.String[]
        With -PassThru, the lines of the view, one string per line. Without it, nothing.
        Errors: Tenure.Plan.Invalid when -Plan is not a Tenure.Plan or a step has an action the
        view has no symbol for.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$Plan,

        [switch]$PassThru,

        [int]$Width
    )

    process {
        $fail = { param($message) throw (New-TenureError -Id 'Tenure.Plan.Invalid' -Message $message -Category InvalidArgument) }
        if ($null -eq $Plan -or $Plan.PSObject.TypeNames -notcontains 'Tenure.Plan') {
            & $fail 'Show-TenurePlan needs a Tenure.Plan from New-TenurePlan or Import-TenurePlan.'
        }

        # Width: the caller's, else the host's, else 120; never below 80.
        $lineWidth = 120
        if ($PSBoundParameters.ContainsKey('Width')) {
            $lineWidth = $Width
        } else {
            try {
                $hostWidth = [int]$Host.UI.RawUI.WindowSize.Width
                if ($hostWidth -gt 0) { $lineWidth = $hostWidth }
            } catch {
                Write-Verbose "The host did not report a window width ($($_.Exception.Message)); using 120."
            }
        }
        if ($lineWidth -lt 80) { $lineWidth = 80 }

        # Free text goes through this so a stray line break or tab cannot break a row apart.
        $clean = {
            param($Value)
            if ($null -eq $Value) { return '' }
            ([regex]::Replace([string]$Value, '[\p{Cc}\s]+', ' ')).Trim()
        }

        # Greedy word wrap over tokens. A token is never split unless it is longer than a whole
        # line, so ids, provider names and dependency edges stay intact.
        $wrap = {
            param([string[]]$Token, [int]$FirstWidth, [int]$RestWidth)
            $wrapped = [System.Collections.Generic.List[string]]::new()
            $limit = $FirstWidth
            $current = ''
            foreach ($item in $Token) {
                $piece = $item
                if ($current.Length -gt 0) {
                    if (($current.Length + 1 + $piece.Length) -le $limit) {
                        $current = "$current $piece"
                        continue
                    }
                    $wrapped.Add($current)
                    $current = ''
                    $limit = $RestWidth
                }
                while ($piece.Length -gt $limit) {
                    $wrapped.Add($piece.Substring(0, $limit))
                    $piece = $piece.Substring($limit)
                    $limit = $RestWidth
                }
                $current = $piece
            }
            if ($current.Length -gt 0) { $wrapped.Add($current) }
            $wrapped.ToArray()
        }

        $entries = [System.Collections.Generic.List[object]]::new()
        $emit = {
            param([string]$Text, [string]$Color)
            $entries.Add([pscustomobject]@{ Text = $Text.TrimEnd(); Color = $Color })
        }

        # Header
        $planId = & $clean (Get-TenureProperty -InputObject $Plan -Name 'PlanId')
        $shortId = if ($planId.Length -gt 8) { $planId.Substring(0, 8) } else { $planId }
        $subject = Get-TenureProperty -InputObject $Plan -Name 'Subject'
        $upn = & $clean (Get-TenureProperty -InputObject $subject -Name 'UserPrincipalName')
        $displayName = & $clean (Get-TenureProperty -InputObject $subject -Name 'DisplayName')
        $headline = 'Plan {0}: {1}' -f $shortId, (& $clean (Get-TenureProperty -InputObject $Plan -Name 'Operation'))
        if ($upn) { $headline += " $upn" }
        if ($displayName) { $headline += " ($displayName)" }

        $createdAt = Get-TenureProperty -InputObject $Plan -Name 'CreatedAt'
        $moment = $null
        if ($createdAt -is [datetime]) {
            $moment = $createdAt
            if ($createdAt.Kind -eq [System.DateTimeKind]::Local) { $moment = $createdAt.ToUniversalTime() }
        } elseif ($createdAt -is [System.DateTimeOffset]) {
            $moment = $createdAt.UtcDateTime
        } elseif ($createdAt -is [string]) {
            $moment = ConvertTo-TenureUtcDateTime -Value $createdAt
        }
        $when = '(unknown time)'
        if ($null -ne $moment) { $when = $moment.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' }
        $account = & $clean (Get-TenureProperty -InputObject (Get-TenureProperty -InputObject $Plan -Name 'CreatedBy') -Name 'Account')
        if (-not $account) { $account = '(unknown)' }
        $moduleVersion = & $clean (Get-TenureProperty -InputObject $Plan -Name 'ModuleVersion')
        if (-not $moduleVersion) { $moduleVersion = '(unknown)' }
        $policyHash = & $clean (Get-TenureProperty -InputObject $Plan -Name 'PolicyHash')
        $policyText = 'no policy'
        if ($policyHash) { $policyText = 'policy ' + $policyHash.Substring(0, [Math]::Min(8, $policyHash.Length)) }
        $provenance = 'Created {0} by {1} with Tenure {2}, {3}' -f $when, $account, $moduleVersion, $policyText

        # Steps: validate, classify and collect the row fields.
        $symbolFor = @{ Create = '+'; Update = '~'; Remove = '-'; Invoke = '!'; NoOp = '='; Check = '?' }
        $colorFor = @{ '+' = 'Green'; '~' = 'Yellow'; '-' = 'Red'; '!' = 'Magenta'; 'x' = 'Red'; '=' = 'DarkGray'; '?' = 'Cyan' }
        $rows = [System.Collections.Generic.List[object]]::new()
        $edges = [System.Collections.Generic.List[string]]::new()
        $destructiveSteps = [System.Collections.Generic.List[string]]::new()
        $changes = 0
        $noops = 0
        $checks = 0
        $anyStarted = $false
        foreach ($step in @(Get-TenureProperty -InputObject $Plan -Name 'Steps' | Where-Object { $null -ne $_ })) {
            $id = & $clean (Get-TenureProperty -InputObject $step -Name 'Id')
            if (-not $id) { & $fail 'A step in the plan has no Id.' }
            $providerName = & $clean (Get-TenureProperty -InputObject $step -Name 'Provider')
            $action = & $clean (Get-TenureProperty -InputObject $step -Name 'Action')
            if (-not $symbolFor.ContainsKey($action)) { & $fail "Step $id has the action '$action', which this view has no symbol for." }

            # A destructive step is counted once, as destructive, whatever its action, except a NoOp:
            # the engine never calls Set for it, so flagging it would be a false alarm.
            $isDestructive = ((& $clean (Get-TenureProperty -InputObject $step -Name 'Risk')) -ieq 'Destructive') -and ($action -ine 'NoOp')
            $symbol = $symbolFor[$action]
            if ($isDestructive) {
                $symbol = 'x'
                $destructiveSteps.Add("$id $providerName")
            } elseif ($action -ieq 'NoOp') {
                $noops++
            } elseif ($action -ieq 'Check') {
                $checks++
            } else {
                $changes++
            }

            $status = & $clean (Get-TenureProperty -InputObject $step -Name 'Status')
            if (-not $status) { $status = 'Pending' }
            if ($status -ine 'Pending') { $anyStarted = $true }

            $extra = ''
            if ($status -in 'Failed', 'Drifted', 'Refused') {
                $result = Get-TenureProperty -InputObject $step -Name 'Result'
                $errorText = & $clean (Get-TenureProperty -InputObject $result -Name 'Error')
                $noteText = & $clean (Get-TenureProperty -InputObject $result -Name 'Note')
                if ($errorText) {
                    $extra = "Error: $errorText"
                } elseif ($noteText) {
                    $extra = "Note: $noteText"
                }
            }

            foreach ($dependency in @(Get-TenureProperty -InputObject $step -Name 'DependsOn')) {
                $dependencyId = & $clean $dependency
                if ($dependencyId) { $edges.Add("$id -> $dependencyId") }
            }

            $rows.Add([pscustomobject]@{
                    Symbol   = $symbol
                    Id       = $id
                    Provider = $providerName
                    Target   = & $clean (Get-TenureProperty -InputObject (Get-TenureProperty -InputObject $step -Name 'Target') -Name 'Name')
                    Reason   = & $clean (Get-TenureProperty -InputObject $step -Name 'Reason')
                    Status   = $status
                    Extra    = $extra
                })
        }

        # Summary line: counts by kind, singular and plural, zero counts left out.
        $planStatus = & $clean (Get-TenureProperty -InputObject $Plan -Name 'Status')
        if (-not $planStatus) { $planStatus = '(unknown)' }
        $summary = "Status $planStatus."
        if ($rows.Count -eq 0) {
            $summary += ' 0 steps.'
        } else {
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($changes -gt 0) { $parts.Add($(if ($changes -eq 1) { '1 change' } else { "$changes changes" })) }
            if ($noops -gt 0) { $parts.Add($(if ($noops -eq 1) { '1 no-op' } else { "$noops no-ops" })) }
            if ($checks -gt 0) { $parts.Add($(if ($checks -eq 1) { '1 check' } else { "$checks checks" })) }
            if ($destructiveSteps.Count -gt 0) { $parts.Add("$($destructiveSteps.Count) destructive") }
            $stepWord = if ($rows.Count -eq 1) { '1 step' } else { "$($rows.Count) steps" }
            $partsText = $parts -join ', '
            $summary += " ${stepWord}: ${partsText}."
        }

        & $emit $headline $null
        & $emit $provenance $null
        & $emit $summary $null
        & $emit '' $null

        # Rows. The Reason column starts after the widest id, provider and (capped) target.
        $idWidth = 0
        $providerWidth = 0
        $targetWidth = 0
        foreach ($row in $rows) {
            $idWidth = [Math]::Max($idWidth, $row.Id.Length)
            $providerWidth = [Math]::Max($providerWidth, $row.Provider.Length)
            $targetWidth = [Math]::Max($targetWidth, $row.Target.Length)
        }
        $targetWidth = [Math]::Min($targetWidth, 28)
        $reasonColumn = 2 + 1 + 1 + $idWidth + 1 + $providerWidth + 2 + $targetWidth + 2
        $continuationWidth = [Math]::Max($lineWidth - $reasonColumn, 20)
        $indent = ' ' * $reasonColumn
        foreach ($row in $rows) {
            $color = $colorFor[$row.Symbol]
            $prefix = '  {0} {1} {2}  {3}  ' -f $row.Symbol, $row.Id.PadRight($idWidth), $row.Provider.PadRight($providerWidth), $row.Target.PadRight($targetWidth)
            $tokens = [System.Collections.Generic.List[string]]::new()
            foreach ($word in ($row.Reason -split ' ')) { if ($word) { $tokens.Add($word) } }
            if ($anyStarted) { $tokens.Add("[$($row.Status)]") }
            $tokenArray = $tokens.ToArray()
            $firstWidth = [Math]::Max($lineWidth - $prefix.Length, 20)
            $reasonLines = @(& $wrap $tokenArray $firstWidth $continuationWidth)
            if ($reasonLines.Count -gt 0) {
                & $emit ($prefix + $reasonLines[0]) $color
                foreach ($line in $reasonLines | Select-Object -Skip 1) { & $emit ($indent + $line) $color }
            } else {
                & $emit $prefix $color
            }
            if ($row.Extra) {
                $extraColor = if ($row.Status -ieq 'Drifted') { 'Yellow' } else { 'Red' }
                foreach ($line in @(& $wrap ([string[]]@($row.Extra -split ' ' | Where-Object { $_ })) $continuationWidth $continuationWidth)) {
                    & $emit ($indent + $line) $extraColor
                }
            }
        }

        # Trailer: dependencies, warnings, destructive steps.
        if ($rows.Count -gt 0) { & $emit '' $null }

        if ($edges.Count -gt 0) {
            $edgeTokens = for ($i = 0; $i -lt $edges.Count; $i++) {
                if ($i -lt $edges.Count - 1) { $edges[$i] + ',' } else { $edges[$i] }
            }
            $edgeLines = @(& $wrap ([string[]]@($edgeTokens)) ($lineWidth - 9) ($lineWidth - 9))
            & $emit ('Depends: ' + $edgeLines[0]) $null
            foreach ($line in $edgeLines | Select-Object -Skip 1) { & $emit ((' ' * 9) + $line) $null }
        }

        $warnings = @(Get-TenureProperty -InputObject $Plan -Name 'Warnings' | Where-Object { $null -ne $_ } | ForEach-Object { & $clean $_ } | Where-Object { $_ })
        if ($warnings.Count -gt 0) {
            & $emit 'Warnings:' 'Yellow'
            foreach ($warning in $warnings) {
                $warningLines = @(& $wrap ([string[]]@($warning -split ' ')) ($lineWidth - 4) ($lineWidth - 4))
                & $emit ('  - ' + $warningLines[0]) 'Yellow'
                foreach ($line in $warningLines | Select-Object -Skip 1) { & $emit ('    ' + $line) 'Yellow' }
            }
        }

        if ($destructiveSteps.Count -gt 0) {
            $destructiveTokens = [System.Collections.Generic.List[string]]::new()
            for ($i = 0; $i -lt $destructiveSteps.Count; $i++) {
                $ending = if ($i -lt $destructiveSteps.Count - 1) { ',' } else { '.' }
                $destructiveTokens.Add($destructiveSteps[$i] + $ending)
            }
            foreach ($word in 'Needs an interactive -Confirm or -AllowDestructive.' -split ' ') { $destructiveTokens.Add($word) }
            $destructiveArray = $destructiveTokens.ToArray()
            $destructiveLines = @(& $wrap $destructiveArray ($lineWidth - 13) ($lineWidth - 13))
            & $emit ('Destructive: ' + $destructiveLines[0]) 'Red'
            foreach ($line in $destructiveLines | Select-Object -Skip 1) { & $emit ((' ' * 13) + $line) 'Red' }
        }

        & $emit 'Legend: + create  ~ update  - remove  ! invoke  x destructive  = no-op  ? check' 'DarkGray'

        # Host output first, then the pipeline copy. Color never changes the text.
        $useColor = [string]::IsNullOrEmpty($env:NO_COLOR)
        foreach ($entry in $entries) {
            if ($useColor -and $entry.Color) {
                Write-Host $entry.Text -ForegroundColor $entry.Color
            } else {
                Write-Host $entry.Text
            }
        }
        if ($PassThru) {
            foreach ($entry in $entries) { $entry.Text }
        }
    }
}
