# ADR-0006: how Exchange Online objects are named

Date: 2026-10-11
Status: accepted

## Context
Every Graph call names a user by its Entra object id, and the first Exchange providers
passed that same id to `-Identity`, `-Member` and `-ForwardingAddress`. Exchange accepts
an object id in some of those places and not in others, and the fake used by the unit
suite accepted it everywhere, so the tests could not see the difference. A separate
problem hid behind it: a transient Exchange failure whose message contained "couldn't be
found" was read as "this user has no mailbox", which made the offboard builder drop
every mailbox step and carry on.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Keep passing the Entra id everywhere and widen the fake to accept it | No code change | Encodes an assumption the real service does not keep; the live run would find it |
| Resolve the primary SMTP address once per plan and pass addresses to every write; read mailboxes by `-ExternalDirectoryObjectId` | Matches what Exchange documents for each parameter; the id read cannot return someone else's mailbox | One extra Exchange read per mailbox at plan time, and a small address table on the plan context |
| Pass the user principal name everywhere | Simple | A UPN can change between plan and apply; a renamed user would be written under the old name |

## Decision
`Get-EXOMailbox` and `Get-EXOMailboxStatistics` read by `-ExternalDirectoryObjectId`, and
the provider refuses a mailbox whose id is not the one it asked for. Every other Exchange
cmdlet receives a user principal name or primary SMTP address. The address comes from the
current state when the provider already has it, else from the plan-time table
`Context.ExchangeAddresses`, else from a read by id. Distribution groups are named by
their mail address, and the provider checks that the group Exchange returns carries the
expected object id before it writes.

"Not found" is narrow: a failure counts as not found only when Exchange names the exact
value the read asked for. Any other failure is a failure. The offboard builder drops the
mailbox steps only with positive evidence that the user has never had a mailbox, which
means no Exchange service plan in `licenseDetails`. With a plan present and no mailbox
found, the plan is refused with `Tenure.Plan.MailboxUnknown` and the operator can pass
`-SkipMailbox` after looking.

## Consequences
- Easy: the unit fake now rejects an id where Exchange would, so the tests stand for
  something.
- Hard: offboard planning costs one more Graph read (`licenseDetails`) and one Exchange
  read per mailbox; a user with a mailbox that the id read cannot see will be refused
  rather than skipped.
- To confirm on the live run: that a not-found from `Get-EXOMailbox
  -ExternalDirectoryObjectId` echoes the id in quotes, and that an onboard's distribution
  list add waits for the new mailbox to exist.

## Revisit when
- Exchange documents object ids as accepted on the write cmdlets.
- The live run shows the not-found text differs from the pattern the helper matches.
