# Spike 0001: do the two seams load on macOS without a tenant?

**Date:** 2026-10-08  ·  **Timebox:** 10 minutes  ·  **Verdict:** GO

## Method
On macOS (Darwin 27, arm64, PowerShell 7.5.4), import the two dependency modules
and check which commands exist before any connection.

## Results
| Check | Result |
|---|---|
| `Import-Module Microsoft.Graph.Authentication` | 136 ms |
| `Import-Module ExchangeOnlineManagement` (3.9.2) | 427 ms |
| `Invoke-MgGraphRequest` present without connection | yes |
| `Get-MgContext` without connection | null |
| `Connect-ExchangeOnline` present | yes |
| `Set-Mailbox` present before connect | **no** |
| `Get-EXOMailbox` present before connect | yes |

## Consequences
- The Exchange seam must resolve the cmdlet at call time (`Get-Command` after
  connect), not at module load. Unit tests mock the seam, never `Set-Mailbox`.
- The Graph seam wraps `Invoke-MgGraphRequest`, which exists without a session, so
  the seam itself can be unit tested by mocking that one cmdlet.
- Both modules install from the Gallery in well under five minutes, so they can be
  `RequiredModules`.
