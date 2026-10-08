# ADR-0005: PowerShell 7.2+, two required modules, Pester 5

**Date:** 2026-10-08  ·  **Status:** accepted

## Context
The module must install and run on a technician's Mac, an Ubuntu CI runner and a
Windows admin box.

## Decision
- `PowerShellVersion = '7.2'`. Windows PowerShell 5.1 is unsupported (Exchange V3 REST
  and cross-platform paths).
- `RequiredModules`: `Microsoft.Graph.Authentication` (>= 2.25.0),
  `ExchangeOnlineManagement` (>= 3.4.0). Nothing else.
- Tests: Pester 5.x pinned (`-MaximumVersion 5.99`); PSScriptAnalyzer latest.
- No `InvokeBuild`, no `platyPS` at build time; `build.ps1` is a plain script.

## Consequences
- Easy: `Install-Module Tenure` pulls two modules, CI bootstraps in minutes.
- Hard: no SharePoint admin cmdlets (OneDrive handoff uses the Graph sharing API,
  site-collection-admin delegation is documented as a manual alternative).

## Revisit when
Pester 6 stabilises and the ecosystem moves, or Microsoft ships OneDrive admin
delegation in Graph v1.0.
