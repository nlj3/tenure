# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

$null = Register-TenureProvider -Definition @{
    Name        = 'Device.Wipe'
    Kind        = 'Invoke'
    Backend     = 'Graph'
    Scopes      = @('DeviceManagementManagedDevices.PrivilegedOperations.All', 'DeviceManagementManagedDevices.Read.All')
    Risk        = 'Destructive'
    Reversible  = $false
    TargetKind  = 'device'
    Actions     = @('Invoke')
    Repeatable  = $true
    Description = 'Factory-resets one Intune managed device (Graph wipe). Irreversible. Set refuses unless the device''s primary user is the plan subject and Intune reports the device as company-owned.'

    # Target: @{ Kind = 'device'; Id = <Intune managed device id>; Name = '<deviceName> (<ownership>)' }
    # Desired: @{ keepEnrollmentData = $false; keepUserData = $false } (both default to $false; no other key is accepted).
    # Get is the same read as Device.Retire's (the two files are kept identical on purpose).
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'Device.Wipe'
        $select = '?$select=id,deviceName,managedDeviceOwnerType,operatingSystem,userId'
        try {
            $device = Invoke-TenureGraph -Method GET -Uri ('deviceManagement/managedDevices/' + (ConvertTo-TenureUriSegment -Value $id) + $select)
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "Managed device '$id' does not exist in Intune." -Category ObjectNotFound -Data @{ Provider = 'Device.Wipe'; Identity = $id } -Inner $_)
            }
            throw
        }
        $text = { param($value) if ($null -eq $value) { $null } else { [string]$value } }

        # Anything Graph does not call company or personal reads as 'unknown', and 'unknown' is never wiped.
        $ownerType = ([string](Get-TenureGraphProperty -InputObject $device -Name 'managedDeviceOwnerType')).Trim().ToLowerInvariant()
        $ownership = 'unknown'
        if ($ownerType -ceq 'company' -or $ownerType -ceq 'personal') { $ownership = $ownerType }

        # Only facts that change when someone changes the device: its name, owner type, OS and primary user.
        # lastSyncDateTime and managementState move on their own (every check-in, a health flag), and a
        # snapshot that held them would report drift between planning and applying for no reason.
        [pscustomobject]@{
            id              = & $text (Get-TenureGraphProperty -InputObject $device -Name 'id')
            deviceName      = & $text (Get-TenureGraphProperty -InputObject $device -Name 'deviceName')
            ownership       = $ownership
            operatingSystem = & $text (Get-TenureGraphProperty -InputObject $device -Name 'operatingSystem')
            userId          = & $text (Get-TenureGraphProperty -InputObject $device -Name 'userId')
        }
    }

    # Invoke providers are never "satisfied": idempotency comes from the step status.
    Test        = {
        param($Current, $Desired)
        return $false
    }

    Set         = {
        param($Target, $Desired, $Current, $Context)

        # 1. Desired: only the two documented switches, and only real booleans. A typo, or the
        #    string 'false' (which PowerShell reads as $true), must not change what kind of wipe goes out.
        $allowed = @('keepEnrollmentData', 'keepUserData')
        $body = @{ keepEnrollmentData = $false; keepUserData = $false }
        $options = ConvertTo-TenureTable -InputObject $Desired
        foreach ($key in @($options.Keys)) {
            $name = $allowed | Where-Object { $_ -ieq [string]$key } | Select-Object -First 1
            if (-not $name) {
                throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "Device.Wipe does not accept Desired.$key (allowed: keepEnrollmentData, keepUserData)." -Category InvalidArgument -Data @{ Provider = 'Device.Wipe'; Key = [string]$key })
            }
            $value = $options[$key]
            if ($null -eq $value) { continue }
            if ($value -isnot [bool]) {
                throw (New-TenureError -Id 'Tenure.Provider.InvalidDesired' -Message "Device.Wipe needs Desired.$name to be a boolean." -Category InvalidArgument -Data @{ Provider = 'Device.Wipe'; Key = $name })
            }
            $body[$name] = $value
        }

        # 2. The plan subject. Without one, nothing proves the device belongs to the user being offboarded.
        $subjectId = [string](Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Subject') -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($subjectId) -or $subjectId.StartsWith('{{', [System.StringComparison]::Ordinal)) {
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message 'Refusing to wipe: the context has no plan subject id, so the device cannot be checked against the user being offboarded.' -Data @{ Provider = 'Device.Wipe'; SubjectId = $subjectId })
        }

        # 3. Fresh read. Never trust the plan snapshot or the Current argument: the primary user and
        #    the ownership can change after planning, and -Force skips the drift check.
        $device = & (Get-TenureProviderDefinition -Name 'Device.Wipe').Get $Target $Context
        $targetId = Get-TenureTargetId -Target $Target -Provider 'Device.Wipe'
        $deviceId = [string]$device.id
        $deviceName = [string]$device.deviceName
        $ownerId = [string]$device.userId
        if ([string]::IsNullOrWhiteSpace($deviceId) -or -not [string]::Equals($deviceId, $targetId, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message "Refusing to wipe: Graph answered for device '$deviceId' when asked for '$targetId'." -Data @{ Provider = 'Device.Wipe'; DeviceId = $deviceId; TargetId = $targetId })
        }
        if ([string]::IsNullOrWhiteSpace($ownerId) -or -not [string]::Equals($ownerId, $subjectId, [System.StringComparison]::OrdinalIgnoreCase)) {
            $shownOwner = if ($ownerId) { $ownerId } else { 'nobody' }
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message "Refusing to wipe $deviceName ($deviceId): its primary user is $shownOwner, not the plan subject $subjectId." -Data @{ Provider = 'Device.Wipe'; DeviceId = $deviceId; DeviceUserId = $ownerId; SubjectId = $subjectId })
        }
        if ($device.ownership -cne 'company') {
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message "Refusing to wipe $deviceName ($deviceId): Intune reports its ownership as $($device.ownership), and only company-owned devices are wiped. Retire it instead." -Data @{ Provider = 'Device.Wipe'; DeviceId = $deviceId; Ownership = $device.ownership })
        }

        # 4. The irreversible call.
        try {
            Invoke-TenureGraph -Method POST -Uri ('deviceManagement/managedDevices/' + (ConvertTo-TenureUriSegment -Value $deviceId) + '/wipe') -Body $body | Out-Null
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "Managed device '$deviceId' disappeared before the wipe was sent; nothing was wiped." -Category ObjectNotFound -Data @{ Provider = 'Device.Wipe'; Identity = $deviceId } -Inner $_)
            }
            throw
        }

        # 5. Read back. Graph has accepted the wipe, so a failed read must not turn the step into
        #    Failed (the audit would then say the device was not wiped). Report the command as issued.
        try {
            & (Get-TenureProviderDefinition -Name 'Device.Wipe').Get $Target $Context
        } catch {
            Write-Warning "Device.Wipe: Graph accepted the wipe of $deviceName ($deviceId), but reading the device back failed: $($_.Exception.Message)"
            [pscustomobject]@{
                id              = $device.id
                deviceName      = $device.deviceName
                ownership       = $device.ownership
                operatingSystem = $device.operatingSystem
                userId          = $device.userId
                commandIssued   = 'wipeIssued'
            }
        }
    }

    Describe    = {
        param($Target, $Current, $Desired, $Action)
        $name = [string](Get-TenureGraphProperty -InputObject $Current -Name 'deviceName')
        if (-not $name) { $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Name') }
        if (-not $name) { $name = [string](Get-TenureGraphProperty -InputObject $Target -Name 'Id') }
        $ownership = [string](Get-TenureGraphProperty -InputObject $Current -Name 'ownership')
        if (-not $ownership) { $ownership = 'unknown' }
        $os = [string](Get-TenureGraphProperty -InputObject $Current -Name 'operatingSystem')
        if (-not $os) { $os = 'unknown OS' }

        $kept = @()
        $keepEnrollment = Get-TenureGraphProperty -InputObject $Desired -Name 'keepEnrollmentData'
        $keepUser = Get-TenureGraphProperty -InputObject $Desired -Name 'keepUserData'
        if ($keepEnrollment -is [bool] -and $keepEnrollment) { $kept += 'enrollment data' }
        if ($keepUser -is [bool] -and $keepUser) { $kept += 'user data' }
        $keeps = if ($kept.Count -gt 0) { '; keeps ' + ($kept -join ' and ') } else { '' }
        "wipe $name ($ownership, $os), irreversible$keeps"
    }
}
