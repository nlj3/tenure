# ADR-0007: plan files carry an integrity value, not a signature

Date: 2026-10-11
Status: accepted

## Context
A plan is reviewed, saved with `Export-TenurePlan`, and applied later, possibly from another shell or by another
administrator. The fingerprints of ADR-0002 bind each step to the state of its target, but nothing bound the plan
to what was reviewed. A saved plan could be edited and then applied without `-Force`: a forwarding
address changed to an outside address (no drift, because the target and its state were the same), a group step
rewritten into a Global Administrator grant (Action `Create` with an empty fingerprint skipped the drift check),
a whole offboarding re-pointed at a protected account with the check steps removed, and a retire step turned into
a wipe of the same laptop (the retire and wipe snapshots are the same shape, so the fingerprint matched).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Nothing beyond fingerprints | No change | Every edit above applies |
| Plain SHA-256 over the plan's content, stored in the plan | No key to manage; any admin can apply any plan; catches hand edits and tools that do not recompute it | A forger who reimplements the formula can recompute it |
| HMAC with a key under `~/.tenure` | Edits without the key are caught | Only the machine and account that built the plan can apply it; key storage and rotation is a project; lost key strands every plan |
| Signature with a certificate | Real non-repudiation | Certificate distribution and trust; out of proportion for a 24-hour artifact |

## Decision
A plain SHA-256, `Plan.Integrity`, over the canonical JSON of everything the plan says and does: schema version,
plan id, creation time, creator and tenant, module version, operation, subject, policy hash, the recorded policy
facts, inputs, warnings, and every step's id, key, provider, kind, target, action, before, after, fingerprint,
risk, reversibility, reason and dependencies, in order. Excluded are the fields the apply engine writes:
`Plan.Status`, each step's `Status` and `Result`, and `Subject.Id` when the plan was sealed without one (the engine
fills it in after the create step; the audit log must then show this plan's create step producing that id).
`New-TenurePlan` seals every plan, so every builder's plan is sealed. `Import-TenurePlan`, `Export-TenurePlan`,
`Test-TenurePlan` and `Invoke-TenurePlan` recompute it and refuse a mismatch with `Tenure.Plan.Tampered`.

What the value stops, and what it does not. It stops an edit made by someone who does not recompute it: a hand
edit, a script, a tool that rewrites the file. It does not stop someone who recomputes it, and anyone who can read
the source can. A resealed plan is a new plan that nobody reviewed, and it is bound only by the checks the engine
makes on every plan, whoever built it:
- each step's `Target.Kind` and `Action` must be its provider's own `TargetKind` and one of its `Actions`, so a role
  step cannot be labelled `Update` or `Create` (`DirectoryRole.Member` only removes), and a step on a user cannot be
  labelled a group to slip past the protection check;
- identifiers are non-empty strings, and a mailbox or drive is named by its owner's object id, so the account the
  protection check reads is the account the provider changes;
- the subject-protection preflight reads every account a step changes, from the provider's kind, and refuses the
  signed-in account and the protected users of `-Policy` or, without `-Policy`, of the list the plan records;
- a plan that records no policy is refused without `-Policy`, and a `-Policy` must carry the plan's recorded hash;
- the plan must name the connected tenant;
- an Onboard, RoleChange or Offboard plan acts on its subject only;
- each step's fingerprint binds its target and its state, and a Create binds its target as absent;
- the audit log this run reads: an Invoke step it records as done never fires again, a plan it shows finished
  `Applied` is refused without `-Force`, and a subject id filled in after sealing must come from the plan's own
  create step. Only that log counts: a plan applied on one machine can be applied again from its file on another
  machine, whose audit log has no record of it, within `-MaxAge`;
- the providers' own preconditions (a wipe or retire refuses a device whose primary user is not the subject;
  `OneDrive.Access` changes only the subject's own drive; `DirectoryRole.Member` refuses any add, and `Group.Member`
  refuses an add to a role-assignable group, so no plan, resealed or not, grants a directory role, directly or
  through a role-assignable group, even through a step labelled `Remove` whose `After` says `member = $true`).

What a builder decided beyond the provider's own floor is content too: a raised risk (Destructive for a license
removal that deletes a mailbox) and the dependencies between steps (a license removal after the mailbox conversion)
are whatever a forger who reseals writes; the engine keeps only the provider's own risk as a floor.
Those checks do not stop a resealed plan that uses an action its provider allows with a harmful desired state on
an account nobody protects (a forwarding address changed, an unprotected user added to a group), a provider
swapped for another that reads the same snapshot (retire to wipe; the destructive prompt names the provider and its
own description of the change, so an operator who answers it sees "wipe"), or, without `-Policy`, a protected list
the forger rewrote: the recorded list is the plan's own word, and only `-Policy` checks it against the policy file.

## Consequences
- Easy: hand edits and naive tooling are refused with a message that says to plan again; review and apply can
  happen on different machines and by different administrators.
- Hard: anything that legitimately changes a plan after it is built (a test fixture, a future migration) has to
  reseal it with the module's own function. Statuses and results stay editable, so a plan file can still be
  resumed.
- Not provided: proof of who built a plan, or protection from someone who can write the plan file and read the
  source; such a person makes a new plan, bound only by the checks above. The CHANGELOG and README must not say
  otherwise.

## Revisit when
Plans start crossing a trust boundary (built by one team, applied by another without review), or a customer
needs to prove which reviewed plan was applied. Then sign plans, and record the signer in the audit log.
