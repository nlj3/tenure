function New-TenureError {
    <#
    .SYNOPSIS
        Builds an ErrorRecord with a stable Tenure error id.
    .DESCRIPTION
        Error ids are part of the module contract (tests assert on them). The id is
        stored as FullyQualifiedErrorId and in Exception.Data['TenureId']. Extra
        structured context goes in -Data and lands in Exception.Data.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an ErrorRecord object; changes no state.')]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^Tenure\.[A-Za-z]+\.[A-Za-z]+$')]
        [string]$Id,

        [Parameter(Mandatory)]
        [string]$Message,

        [System.Management.Automation.ErrorCategory]$Category = [System.Management.Automation.ErrorCategory]::InvalidOperation,

        [hashtable]$Data,

        [System.Management.Automation.ErrorRecord]$Inner,

        [object]$TargetObject
    )

    $exception = if ($Inner) {
        [System.Exception]::new($Message, $Inner.Exception)
    } else {
        [System.Exception]::new($Message)
    }
    if ($Data) {
        foreach ($key in $Data.Keys) { $exception.Data[$key] = $Data[$key] }
    }
    $exception.Data['TenureId'] = $Id
    [System.Management.Automation.ErrorRecord]::new($exception, $Id, $Category, $TargetObject)
}

function Get-TenureErrorId {
    <#
    .SYNOPSIS
        Returns the Tenure error id carried by an ErrorRecord, or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    if ($ErrorRecord.Exception.Data.Contains('TenureId')) { return [string]$ErrorRecord.Exception.Data['TenureId'] }
    if ($ErrorRecord.FullyQualifiedErrorId -like 'Tenure.*') { return $ErrorRecord.FullyQualifiedErrorId }
    return $null
}
