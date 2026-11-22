# Testing

Detection content is tested in three layers. The first two run on every push and
pull request; the third needs a lab.

| Layer | Command | What it proves |
|---|---|---|
| Static | `make check` | Rule and hunting YAML match the Sentinel schema; ATT&CK ids are valid; entity mappings, custom details and alert titles only use columns the query outputs; every query parses with Microsoft's Kusto language service against the real `SecurityEvent` columns; the tooling's unit tests pass |
| Emulator | `make emulator emulator-test` | Every analytic query fires on its attack cases and stays silent on its benign cases when run on a Kusto engine. Every hunting query returns the attack cases |
| Lab | [simulation.md](simulation.md) | The rule raises an incident on real telemetry in a live workspace |

## Test cases

Each detection's `tests.json` holds a list of cases:

```json
{
  "cases": [
    {
      "name": "one user pulls RC4 tickets for three SPNs",
      "expect": "fire",
      "events": [
        {"age_minutes": 5, "EventID": 4769, "Status": "0x0", "ServiceName": "svc-sql", "...": "..."}
      ]
    }
  ]
}
```

- `expect` is `fire` (the analytic query must return at least one row) or `silent` (it
  must return none). The hunting query is run on `fire` cases only, since it has no
  thresholds.
- Event keys are `SecurityEvent` columns from
  [tools/securityevent.schema](../tools/securityevent.schema), plus `age_minutes`: how
  long before the test run the event happened, so relative time filters such as
  `ago(20m)` behave as they would in a workspace.
- Columns an event leaves out are empty. Fields with no typed column, such as
  `TicketEncryptionType`, go in `EventData` as XML.
- `make lint` rejects unknown columns and requires at least one `fire` and one
  `silent` case per detection.

## How the emulator run works

[tools/emulator_test.py](../tools/emulator_test.py) prefixes each query with
`let SecurityEvent = datatable(...)[...]` holding the case's events, then runs the
query unchanged on the
[Kusto emulator](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview)
over its REST endpoint. CI runs the emulator as a service container pinned by digest.

## Adding a detection

1. Create `detections/<name>/` with `analytic.yaml`, `hunting.yaml`, `tests.json` and
   `README.md`. Use an existing detection as the template.
2. Generate new GUIDs for both `id` fields.
3. Add at least one `fire` and one `silent` case.
4. Run `make check` and `make emulator-test`.
