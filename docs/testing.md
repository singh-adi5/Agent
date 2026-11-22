# Testing

Detection content is tested in three layers. The first two run on every push and
pull request; the third needs a lab.

| Layer | Command | What it proves |
|---|---|---|
| Static | `make check` | Rule and hunting YAML match the Sentinel schema; ATT&CK ids are valid; entity mappings, custom details and alert titles only use columns the query outputs; every watchlist a query reads exists and its CSV is valid; every query parses with Microsoft's Kusto language service against the real `SecurityEvent` columns; the tooling's unit tests pass |
| Emulator | `make emulator emulator-test` | Every analytic query fires on its attack cases, with the expected values, and stays silent on its benign cases when run on a Kusto engine. Every hunting query returns the attack cases |
| Lab | [simulation.md](simulation.md) | The rule raises an incident on real telemetry in a live workspace |

## Test cases

Each detection's `tests.json` holds a list of cases:

```json
{
  "cases": [
    {
      "name": "one user pulls RC4 tickets for three SPNs",
      "expect": "fire",
      "assert": {"Requester": "alice.lab", "SpnCount": 3},
      "watchlist": [
        {"alias": "ADDetectionExclusions", "Detection": "kerberoasting", "Value": "svc-scanner", "ExpiresOn": "2099-01-01"}
      ],
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
- `assert` (optional, `fire` cases only) lists column values that at least one returned
  row must have. It must name columns the analytic query outputs.
- `watchlist` (optional) adds watchlist items for this case only, on top of the items in
  [watchlists/](../watchlists/). Columns must exist in that watchlist's CSV.
- `make lint` rejects unknown columns and watchlists, and requires at least one `fire`
  and one `silent` case per detection.

## How the emulator run works

[tools/emulator_test.py](../tools/emulator_test.py) prefixes each query with
`let SecurityEvent = datatable(...)[...]` holding the case's events, and with a
stand-in for Sentinel's `_GetWatchlist()` function serving the watchlist items, then
runs the query unchanged on the
[Kusto emulator](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview)
over its REST endpoint. CI runs the emulator as a service container pinned by digest.

## Adding a detection

1. Create `detections/<name>/` with `analytic.yaml`, `hunting.yaml`, `tests.json` and
   `README.md`. Use an existing detection as the template.
2. Read any field that is not in [tools/securityevent.schema](../tools/securityevent.schema)
   from `EventData`. Add a column to the schema only after confirming it in the Azure
   Monitor table reference.
3. Generate new GUIDs for both `id` fields.
4. Add at least one `fire` case with `assert`, and one `silent` case.
5. Run `make check` and `make emulator-test`.
