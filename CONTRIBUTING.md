# Contributing to Tenure

Tenure is a PowerShell 7 module that onboards, re-roles and offboards Microsoft 365
accounts the way Terraform changes infrastructure: build a plan from live state,
show it, then apply it step by step with drift checks and an append-only audit log.

Read `docs/SPEC.md` before writing code. It is the contract. Decisions and the
reasons behind them live in `docs/adr/`. The risk register is `docs/RISKS.md`.

## Verify gate

Run this before opening a pull request:

```
pwsh ./build.ps1 -Task CI        # analyzer + unit tests + manifest + build
pwsh ./build.ps1 -Task Test      # unit tests only (fast loop)
pwsh ./build.ps1 -Task Analyze   # PSScriptAnalyzer only
```

Unit tests need no tenant, no network and no credentials. If a test you wrote needs
any of those, it is an integration test: put it in `tests/integration/` with the
`Integration` tag. Integration tests only run with `-Task Integration` and the
`TENURE_INTEGRATION=1` environment variable, against a tenant you own.

## Rules

1. **Two seams, no exceptions.** Every call to Microsoft Graph goes through
   `Invoke-TenureGraph`. Every Exchange Online cmdlet goes through
   `Invoke-TenureExchange`. Nothing else in `src/` may call `Invoke-MgGraphRequest`,
   `Get-Mg*`, `Set-Mailbox`, or any other SDK command directly. A test enforces this.
2. **Secrets never land anywhere.** Generated passwords and Temporary Access Passes
   are returned as `SecureString` on the apply result only. They must not appear in
   plan objects, plan files, audit entries, verbose or debug output, error messages,
   or test fixtures. A test enforces this too.
3. **No tenant data in the repo.** No real tenant ids, domains, user names, object
   ids, SKU ids from a real tenant, or screenshots. Fixtures use `example.com` and
   made-up GUIDs.
4. **Providers are the only place tenant state is read or written.** Plan builders
   compose steps; they never call seams directly. The apply engine never knows what
   a provider does.
5. **Idempotent by construction.** Every provider `Set` must leave `Test` true, and
   applying a satisfied step must be a no-op (`Skipped`), not an error.
6. **PowerShell 7.2+, cross-platform.** No Windows-only APIs, no
   `Microsoft.Online.SharePoint.PowerShell`, no MSOnline or AzureAD modules. Paths
   use `Join-Path`. Line endings LF.
7. **Pester 5 only** (`-MaximumVersion 5.99`). `Should -Throw -ErrorId` for error
   contracts. Mock the seams, not the SDK, except in the seam tests themselves.
8. **Releases are cut by the maintainer.** Do not tag, publish, or create releases
   from a branch.

## Conventions

- Public functions: one per file in `src/Tenure/Public/`, `Verb-TenureNoun`,
  comment-based help with at least one example.
- Private functions: `src/Tenure/Private/Core/`. Providers:
  `src/Tenure/Private/Providers/<Area>.<Resource>.ps1`, one
  `Register-TenureProvider` call per file.
- Objects are `[pscustomobject]` with a `PSTypeName` (`Tenure.Plan`, `Tenure.Step`,
  `Tenure.AuditEntry`, `Tenure.Policy`, `Tenure.Provider`, `Tenure.ApplyResult`).
  No PowerShell classes; they do not cross module boundaries cleanly.
- Errors: `throw (New-TenureError -Id 'Tenure.<Area>.<Problem>' ...)`. Ids are part
  of the contract; tests assert on them.
- JSON out: `ConvertTo-Json -Depth 20`. Canonical JSON (sorted keys, compressed) for
  anything hashed.
- Dates: UTC ISO 8601 (`o` format).
- Prose in README and docs: plain and specific, no marketing voice.

## Analyzer notes

- Source files are ASCII only (the analyzer wants a BOM otherwise). Write
  "section 2.2", not a section sign.
- Object factories named `New-*` that change no state carry
  `[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = '...')]`.
  Anything that writes a file or touches the tenant supports `ShouldProcess` instead.
- Parameters of `build.ps1` are copied to `$script:` variables; nested functions read
  those.
- `Invoke-TenureGraph -All` emits items one by one. Always wrap it:
  `@(Invoke-TenureGraph ... -All)`. Never `return , $array` from a function whose
  callers use `@(...)`; it nests.
- Regex on identifiers uses `-cmatch` / `-cnotmatch`. `-match` is case-insensitive.
