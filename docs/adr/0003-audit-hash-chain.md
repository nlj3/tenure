# ADR-0003: append-only JSONL audit log with a SHA-256 hash chain

Date: 2026-10-08
Status: accepted

## Context
The audit log answers "who changed what, when, from which plan". It is also the
3am debugging path. It has to be simple to write from any OS and hard to edit quietly.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Plain JSONL | Simple, greppable | Silent edits undetectable |
| JSONL with per-line hash chain (`hash = sha256(prevHash + canonicalJson(entry))`) | Tamper-evident, still greppable, zero deps | Not tamper-proof (a rewriter can recompute); verifier needed |
| Signed entries | Tamper-proof | Key management is a project of its own |

## Decision
JSONL with a hash chain. `Test-TenureAudit` walks the file and reports the first
broken link. Default path `~/.tenure/audit.jsonl`, overridable per call and by
`TENURE_AUDIT_PATH`. Secrets are never written; `before`/`after` are provider state
snapshots that exclude credential fields by construction.

## Consequences
- Easy: `Get-TenureAudit -PlanId` reconstructs a run; `Test-TenureAudit` for integrity.
- Hard: concurrent writers from two shells would race; one writer per file assumed
  (documented), with a lock file as a later option.

## Amendment 2026-10-08
- Line format fixed as: canonical JSON without `Hash`, then `,"Hash":"<hex>"` as the last member;
  the verifier re-hashes the stored text rather than re-serializing (ConvertFrom-Json would
  turn date-like strings into dates and `1.50` into `1.5`, producing false tamper reports).
- `Note` field added to every entry so Skipped, Drifted and Refused outcomes say why.
- Writer locks the file exclusively (FileShare.None) with a ~2 s retry; .NET append mode does
  not use O_APPEND on Unix, so a lock is the only real protection. Multi-writer is therefore
  supported on one host; the "one writer per file" caveat above is withdrawn.
- A torn or garbage last line makes the writer throw `Tenure.Audit.Corrupt` instead of chaining
  onto it. Readers skip blank lines, strip a BOM and accept CRLF.

## Revisit when
A consumer needs non-repudiation (then sign entries), or the audit directory must be
created with restricted permissions on every OS (needs .NET 7+ / PowerShell 7.3+).
