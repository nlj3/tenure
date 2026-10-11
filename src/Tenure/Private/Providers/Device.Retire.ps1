# Provider scriptblocks have the fixed signatures in SPEC section 2.2, so a given Get/Test/Set/Describe
# often leaves a parameter unused. The analyzer only honors this suppression on a file's own param block.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Provider scriptblocks have a fixed signature (SPEC section 2.2).')]
param()

$null = Register-TenureProvider -Definition @{
    Name        = 'Device.Retire'
    Kind        = 'Invoke'
    Backend     = 'Graph'
    Scopes      = @('DeviceManagementManagedDevices.PrivilegedOperations.All', 'DeviceManagementManagedDevices.Read.All')
    Risk        = 'High'
    Reversible  = $false
    TargetKind  = 'device'
    Actions     = @('Invoke')
    Repeatable  = $true
    Description = 'Retires one Intune managed device (Graph retire): removes company data, apps and management, keeps personal data. Set refuses unless the device''s primary user is the plan subject.'

    # Target: @{ Kind = 'device'; Id = <Intune managed device id>; Name = '<deviceName> (<ownership>)' }
    # Desired: not used (retire takes no options).
    # Get is the same read as Device.Wipe's (the two files are kept identical on purpose).
    Get         = {
        param($Target, $Context)
        $id = Get-TenureTargetId -Target $Target -Provider 'Device.Retire'
        $select = '?$select=id,deviceName,managedDeviceOwnerType,operatingSystem,userId'
        try {
            $device = Invoke-TenureGraph -Method GET -Uri ('deviceManagement/managedDevices/' + (ConvertTo-TenureUriSegment -Value $id) + $select)
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "Managed device '$id' does not exist in Intune." -Category ObjectNotFound -Data @{ Provider = 'Device.Retire'; Identity = $id } -Inner $_)
            }
            throw
        }
        $text = { param($value) if ($null -eq $value) { $null } else { [string]$value } }

        # Anything Graph does not call company or personal reads as 'unknown'.
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

        # 1. The plan subject. Without one, nothing proves the device belongs to the user being offboarded.
        $subjectId = [string](Get-TenureGraphProperty -InputObject (Get-TenureGraphProperty -InputObject $Context -Name 'Subject') -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($subjectId) -or $subjectId.StartsWith('{{', [System.StringComparison]::Ordinal)) {
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message 'Refusing to retire: the context has no plan subject id, so the device cannot be checked against the user being offboarded.' -Data @{ Provider = 'Device.Retire'; SubjectId = $subjectId })
        }

        # 2. Fresh read. Never trust the plan snapshot or the Current argument: the primary user can
        #    change after planning, and -Force skips the drift check.
        $device = & (Get-TenureProviderDefinition -Name 'Device.Retire').Get $Target $Context
        $targetId = Get-TenureTargetId -Target $Target -Provider 'Device.Retire'
        $deviceId = [string]$device.id
        $deviceName = [string]$device.deviceName
        $ownerId = [string]$device.userId
        if ([string]::IsNullOrWhiteSpace($deviceId) -or -not [string]::Equals($deviceId, $targetId, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message "Refusing to retire: Graph answered for device '$deviceId' when asked for '$targetId'." -Data @{ Provider = 'Device.Retire'; DeviceId = $deviceId; TargetId = $targetId })
        }
        if ([string]::IsNullOrWhiteSpace($ownerId) -or -not [string]::Equals($ownerId, $subjectId, [System.StringComparison]::OrdinalIgnoreCase)) {
            $shownOwner = if ($ownerId) { $ownerId } else { 'nobody' }
            throw (New-TenureError -Id 'Tenure.Provider.Precondition' -Message "Refusing to retire $deviceName ($deviceId): its primary user is $shownOwner, not the plan subject $subjectId." -Data @{ Provider = 'Device.Retire'; DeviceId = $deviceId; DeviceUserId = $ownerId; SubjectId = $subjectId })
        }

        # 3. The irreversible call (retire takes no body).
        try {
            Invoke-TenureGraph -Method POST -Uri ('deviceManagement/managedDevices/' + (ConvertTo-TenureUriSegment -Value $deviceId) + '/retire') | Out-Null
        } catch {
            if ((Get-TenureErrorId -ErrorRecord $_) -eq 'Tenure.Graph.NotFound') {
                throw (New-TenureError -Id 'Tenure.Provider.TargetNotFound' -Message "Managed device '$deviceId' disappeared before the retire was sent; nothing was changed." -Category ObjectNotFound -Data @{ Provider = 'Device.Retire'; Identity = $deviceId } -Inner $_)
            }
            throw
        }

        # 4. Read back. Graph has accepted the retire, so a failed read must not turn the step into
        #    Failed (the audit would then say the device was not retired). Report the command as issued.
        try {
            & (Get-TenureProviderDefinition -Name 'Device.Retire').Get $Target $Context
        } catch {
            Write-Warning "Device.Retire: Graph accepted the retire of $deviceName ($deviceId), but reading the device back failed: $($_.Exception.Message)"
            [pscustomobject]@{
                id              = $device.id
                deviceName      = $device.deviceName
                ownership       = $device.ownership
                operatingSystem = $device.operatingSystem
                userId          = $device.userId
                commandIssued   = 'retireIssued'
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
        "retire $name ($ownership, $os): removes company data and management, keeps personal data"
    }
}
