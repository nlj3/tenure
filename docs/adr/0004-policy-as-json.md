# ADR-0004: policy file is JSON with a published schema

Date: 2026-10-08
Status: accepted

## Context
Role templates (which licenses and groups a role gets) and offboarding defaults are
per-tenant configuration. They must stay out of the module and be easy for another
tool to generate.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| PSD1 | Native to PowerShell | No schema, awkward for non-PowerShell producers |
| JSON + JSON Schema | Editor validation, any producer, diffable | Comments not allowed (use `_comment` keys) |
| YAML | Comments | Extra dependency |

## Decision
JSON, validated on load by a small in-module validator (no dependency) and shipped
with `src/Tenure/Policies/tenure.policy.schema.json` for editors. Group and license references
are names resolved to ids at plan time; the plan carries the resolved ids.

## Consequences
- Easy: another tool can write a policy and call the same verbs.
- Hard: typos in group names surface at plan time, not load time (by design, since
  resolution needs a tenant).

## Revisit when
Policies need inheritance or per-department overrides.
