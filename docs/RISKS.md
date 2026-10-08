# Risk register

| ID | Risk | Type | Likelihood | Impact | Mitigation | Trigger to act | Status |
|----|------|------|-----------|--------|------------|----------------|--------|
| R1 | Seam design leaks: a provider calls the SDK directly and the unit suite silently depends on a tenant | technical | med | severe | Adversarial test greps `src/` for SDK calls outside the two seams | any direct call found | open |
| R2 | Offboard order wrong: license removed before mailbox conversion, mailbox lost | product | med | fatal | `dependsOn` edge from license removal to mailbox conversion; plan refuses to reorder | tenant test shows mailbox soft-deleted | open |
| R3 | Secrets (temp password, TAP) land in plan file, audit log or verbose stream | security | med | severe | Secrets returned only as SecureString on the apply result; adversarial test scans every output for a seeded value | any hit | open |
| R4 | Stale or drifted plan applied: state changed between plan and apply | product | high | severe | Per-step fingerprint on `before`; apply refuses on mismatch unless `-Force`; 24h max plan age | drift test fails | open |
| R5 | Exchange V3 cmdlets unavailable on macOS/Linux | technical | low | severe | Spike 0001 showed the module loads; cmdlets are REST-backed after connect | real-tenant run fails on macOS | open |
| R6 | Group-based licensing and dynamic groups cannot be removed directly; provider throws instead of explaining | product | high | moderate | Providers detect `assignedByGroup` / dynamic membership and emit `Skipped` with reason | tenant test | open |
| R7 | Shared mailbox over 50 GB or on hold loses data after license removal | product | med | severe | `Mailbox.SharedEligibility` check step warns; `-SkipLicenseRemoval` documented | warning never fires | open |
| R8 | Device wipe hits a personal device | security | low | fatal | Default policy wipes corporate-owned only, retires personal; destructive steps need `-Confirm` or `-AllowDestructive` | ownership field missing in Graph response | open |
| R9 | Self-offboard or break-glass account offboarded | security | low | fatal | Refuse when subject is the signed-in account or in `protectedUsers`; warn on Global Administrator | test | open |
| R10 | Gallery publish from CI with a bad secret or wrong version | operational | med | moderate | Release workflow only on a published GitHub release; version from tag; dry-run job first | failed publish | open |
| R11 | Graph throttling (429) during a 30-step apply leaves a half-applied plan | operational | med | moderate | Seam retries with Retry-After up to 3 times; plan status `PartiallyApplied` + resume | tenant test | open |
| R12 | Pester 6 breaks the suite | technical | low | minor | Pin Pester 5.x in build script and CI | CI red after upgrade | open |

For each `fatal` risk there is a slice that retires it (R2 → S8, R8 → S7, R9 → S8).
