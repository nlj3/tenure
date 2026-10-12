# ADR-0001: all tenant access through two seams

Date: 2026-10-08
Status: accepted

## Context
The module must be unit-testable with no tenant, and must run on macOS, Linux and
Windows. The Microsoft.Graph SDK is 40 sub-modules; the Exchange module generates its
cmdlets at connect time.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Call `Get-MgUser`, `Set-Mailbox` etc. directly from providers | Familiar, typed | Needs 10+ Graph sub-modules installed; mocking dozens of cmdlets; Exchange cmdlets do not exist before connect |
| Two wrappers: `Invoke-TenureGraph` (REST via `Invoke-MgGraphRequest`) and `Invoke-TenureExchange` (`& (Get-Command $name) @params`) | One dependency each, two mocks cover everything, version-stable REST | Providers write raw Graph paths; less IntelliSense |
| Pure REST with our own token handling | Zero SDK | Reimplementing auth is RED work with no upside |

## Decision
Two seams. `Microsoft.Graph.Authentication` and `ExchangeOnlineManagement` are the only
required modules. A test fails the build if any file under `src/` outside the seams
references an SDK command.

## Consequences
- Easy: mocking, CI on three OSes, small install.
- Hard: providers must know Graph URLs and payloads, and each one has to be checked against the Graph documentation.
- Reversal cost: low per provider, high across the registry.

## Revisit when
The Graph SDK ships a slim "core + request" package smaller than the auth module, or a
provider needs a feature only the typed cmdlets expose.
