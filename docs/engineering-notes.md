# Engineering notes

Problems found while building and reviewing this content, and what changed as a
result. Each one shaped a check that now runs in CI, so the same mistake fails the
build instead of reaching a workspace.

## Detection logic

**Fields that look like columns but are not.** The first Kerberoasting rule filtered on
`TicketEncryptionType` as a column. `SecurityEvent` has no such column; the rule would
have failed when saved in Sentinel. Checking the column list against Microsoft's table
reference found the same for `PreAuthType` and for every 5136 and 4742 field the
DCShadow and AdminSDHolder rules need (`ObjectDN`, `AttributeLDAPDisplayName`,
`AttributeValue`, `ServicePrincipalNames`). All are parsed from `EventData`.
*Check now:* every query is analysed by the Kusto language service against
[tools/securityevent.schema](../tools/securityevent.schema). When the AdminSDHolder rule
used `OperationType`, the check failed until the column was confirmed in the reference
and added.

**Gaps between scheduled runs.** Sentinel runs scheduled rules about five minutes
behind real time. A rule whose window equals its frequency never sees a slice of
events at every boundary, and a burst split across that boundary can fall under the
threshold twice. Windows now cover frequency plus five minutes, and incident grouping
absorbs the occasional duplicate alert.

**Joins that would silently match nothing.** 4768 logs `alice`, 4769 logs
`alice@CONTOSO.LOCAL`, and both log IPv4 addresses as `::ffff:10.10.1.5`. Compared raw,
the Golden Ticket anti-join would flag every service ticket. Account names and
addresses are normalised before every join and count, and the Golden Ticket tests use
mixed forms (`alice.lab` against `alice.lab@CONTOSO.LOCAL`, plain against `::ffff:`
addresses) so a regression fails.

**Counting per domain controller.** Grouping by the reporting DC split activity spread
across several DCs, so a spray or roast could stay under the threshold everywhere.
Counts are now grouped by account and source, with the DCs kept as a column.

**Non-deterministic enrichment.** The DCSync rule took `take_any(IpAddress)` for a logon
ID. It now keeps the most recent logon, and a test asserts which address is reported.

**Testing that a rule fires is not enough.** Early tests only counted rows. Fire cases
now assert the values the rule reports (account, source address), and a
wrong expectation was confirmed to fail.

## Operations

**Allow-lists inside queries.** Exclusions were `dynamic([])` arrays in the query text,
so every tuning change was a code change with no owner, reason or end date. They now
live in two watchlists; exclusions carry an owner and reason, and stop applying after
`ExpiresOn`.

**A redeploy that switches rules off.** The template created every rule with
`enabled: false`. Deployed from a pipeline, every routine update would have disabled
live rules. Enablement is now a template parameter set once per environment.

**Taxonomy drift.** ATT&CK has replaced the Defense Evasion tactic; Sentinel's API has
not caught up. The DCShadow rule records both rather than picking one silently. ATT&CK
also has no entry for AdminSDHolder, so that mapping is documented as a judgement.

## Tooling

**A validator that passed on the wrong text.** The check that entity mappings use real
output columns first searched the whole query, so a column named in a comment, or as a
function argument inside the final `project`, passed. It now parses the final
`project` and counts only aliases and bare column names, with unit tests for each
bypass.

**One copy of each query.** Queries were kept in both a `.kql` file and the rule YAML,
with a CI check holding them in step. The YAML is now the only copy and every tool
reads it.

## Lab

No findings recorded yet: the lab has not been run end to end. See
[evidence](evidence/README.md).
