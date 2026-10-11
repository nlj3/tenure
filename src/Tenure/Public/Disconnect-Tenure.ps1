function Disconnect-Tenure {
    <#
    .SYNOPSIS
        Ends the Tenure session and signs out of Microsoft Graph and Exchange Online.
    .DESCRIPTION
        Clears the session that Connect-Tenure recorded, then disconnects Microsoft Graph
        and every Exchange Online connection in this PowerShell session. A failed or
        unnecessary disconnect is reported on the verbose stream only, so this is safe to
        call when nothing is connected. Returns nothing.
    .EXAMPLE
        Disconnect-Tenure

        Signs out of both backends. Plans and applies refuse to run until Connect-Tenure.
    .EXAMPLE
        Disconnect-Tenure -Verbose

        Shows which backend was disconnected and which had nothing to disconnect.
    .OUTPUTS
        None.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    Disconnect-TenureSession
}
