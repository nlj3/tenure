# Shared helpers for Tenure tests. Dot-source from BeforeAll:
#   . (Join-Path $PSScriptRoot '..' 'helpers' 'TestHelpers.ps1')

$script:TenureRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$script:TenureSourceRoot = Join-Path $script:TenureRepoRoot 'src' 'Tenure'
$script:TenureManifest = Join-Path $script:TenureSourceRoot 'Tenure.psd1'

function Import-TenureForTest {
    Import-Module $script:TenureManifest -Force -ErrorAction Stop
}

function Set-TenureTestSession {
    <#
    .SYNOPSIS
        Marks the module as connected (or not) without touching any SDK.
    #>
    param([bool]$Graph = $true, [bool]$Exchange = $true, [string]$Account = 'admin@example.com', [string]$TenantId = '00000000-0000-0000-0000-00000000beef')
    $module = Get-Module -Name Tenure
    & $module {
        param($g, $e, $a, $t)
        $script:Session = [pscustomobject]@{
            PSTypeName  = 'Tenure.Connection'
            Account     = $a
            TenantId    = $t
            AuthType    = 'Test'
            Graph       = $g
            Exchange    = $e
            Scopes      = @()
            ConnectedAt = [datetime]::UtcNow
        }
    } $Graph $Exchange $Account $TenantId
}

function Clear-TenureTestSession {
    $module = Get-Module -Name Tenure
    & $module { $script:Session = $null }
}

function New-FakeProviderDefinition {
    <#
    .SYNOPSIS
        A valid provider definition backed by an in-memory state hashtable.
    .DESCRIPTION
        $State is keyed by Target.Id and holds the "current" object. Set writes Desired
        into it. Use -Overrides to replace any key (for example Kind, Risk, Set).
    #>
    param(
        [string]$Name = 'Fake.State',
        [hashtable]$State = @{},
        [hashtable]$Overrides = @{}
    )
    $definition = @{
        Name       = $Name
        Kind       = 'State'
        Backend    = 'Graph'
        Scopes     = @('Fake.ReadWrite.All')
        Risk       = 'Low'
        Reversible = $true
        Get        = {
            param($Target, $Context)
            if (-not $State.ContainsKey($Target.Id)) {
                # Fakes run in test scope, so build the ErrorRecord directly (same id the module uses).
                throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new("No fake target '$($Target.Id)'."), 'Tenure.Provider.TargetNotFound', 'ObjectNotFound', $Target)
            }
            [pscustomobject]$State[$Target.Id]
        }.GetNewClosure()
        Test       = {
            param($Current, $Desired)
            if ($null -eq $Current) { return $false }
            foreach ($key in $Desired.Keys) {
                if (-not $Current.PSObject.Properties[$key] -or $Current.$key -ne $Desired[$key]) { return $false }
            }
            $true
        }
        Set        = {
            param($Target, $Desired, $Current, $Context)
            if (-not $State.ContainsKey($Target.Id)) { $State[$Target.Id] = @{} }
            foreach ($key in $Desired.Keys) { $State[$Target.Id][$key] = $Desired[$key] }
            [pscustomobject]$State[$Target.Id]
        }.GetNewClosure()
        Describe   = {
            param($Target, $Current, $Desired, $Action)
            "$Action $($Target.Name): " + (($Desired.Keys | Sort-Object | ForEach-Object { "$_=$($Desired[$_])" }) -join ', ')
        }
    }
    foreach ($key in $Overrides.Keys) { $definition[$key] = $Overrides[$key] }
    $definition
}

function Invoke-InTenure {
    <#
    .SYNOPSIS
        Runs a scriptblock inside the Tenure module scope (private functions visible).
    #>
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock, [object[]]$ArgumentList = @())
    $module = Get-Module -Name Tenure
    & $module $ScriptBlock @ArgumentList
}
