# Hunting queries

One hunting query per detection. An analytics rule answers "did this happen in the
last hour, above a threshold?" and raises an incident. A hunting query answers "show
me everything of this shape over the last month" and is read by a person.

| Query | ATT&CK | What it adds to the rule |
|---|---|---|
| [kerberoasting](kerberoasting.kql) | T1558.003 | No threshold. Shows slow roasting and the RC4-only services behind false positives |
| [asrep-roasting](asrep-roasting.kql) | T1558.004 | Every account without pre-authentication, any encryption type. The fix list |
| [dcsync](dcsync.kql) | T1003.006 | Everyone who replicates, DCs included. The baseline for the rule's allow-lists |
| [password-spraying](password-spraying.kql) | T1110.003 | Floor of three accounts, plus which accounts then logged on from the same source |
| [golden-ticket](golden-ticket.kql) | T1558.001 | Whole time range, and whether the account holds a TGT anywhere else |

Each query has two files that CI keeps identical:

- `<name>.kql` is the query, ready to paste into Sentinel **Logs**.
- `<name>.yaml` is the same query in the hunting query format Microsoft uses in the
  Azure-Sentinel repository, with its ATT&CK mapping.

## Use them

In Sentinel, open **Hunting** > **Queries** > **New query**. Paste the `.kql` file,
then copy the name, description, tactic and technique from the `.yaml` file.

Hunting queries have no time filter inside them. Set the range in the portal. The
`// Use:` line at the top of each query says what range suits it and which rows to
read first.

## What is checked

- Every query parses against Microsoft's Kusto language service and reads only
  columns in [`scripts/securityevent.schema`](../scripts/securityevent.schema).
- Every query runs on a Kusto engine in CI against the same attack events its
  analytics rule is tested with, and must return them.
- They have not yet been run in a live workspace. See [PROGRESS.md](../PROGRESS.md).
