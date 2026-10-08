# ADR-0003: append-only JSONL audit log with a SHA-256 hash chain

**Date:** 2026-10-08  ·  **Status:** accepted

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

## Revisit when
A consumer needs non-repudiation (then sign entries) or multi-writer use.
