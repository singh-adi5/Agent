# Deployment

Each detection's `analytic.yaml` is in the format Microsoft uses for rule templates in
the Azure-Sentinel repository. The Sentinel portal imports ARM templates, not that
YAML, so the rules are built into one ARM template first.

> The template is covered by unit tests but has not yet been deployed to a live
> workspace.

## Before deploying

1. Events are arriving in `SecurityEvent` ([lab setup, step 10](lab-setup.md#10-check-that-events-arrive)).
2. `domain_controllers` in `detections/dcsync/analytic.yaml` lists the lower-case
   computer account of every DC. The default, `["dc01$"]`, fits the lab.
3. Allow-lists are reviewed. The hunting queries produce the baselines: run the DCSync
   hunting query before enabling the DCSync rule.
4. `make check` passes.

## Build and deploy

```bash
make arm
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file build/sentinel-analytics.json \
  --parameters workspace=<WORKSPACE_NAME>
```

`build/` is ignored by git. Redeploying updates rules in place, because each rule's
resource name is the GUID in its `id` field.

To import through the portal instead: **Sentinel > Analytics > Import**, then select
`build/sentinel-analytics.json`.

## What the template sets

| Setting | Value | Reason |
|---|---|---|
| `enabled` | `false` | Allow-lists are set per environment before a rule runs |
| Incident creation | on | |
| Incident grouping | on, all entities, 5 hour lookback | Overlapping runs can alert twice on the same activity |
| Alert title | from `alertDetailsOverride` | Puts the account or source address in the incident queue |
| Techniques | parent ids only | API version `2023-02-01` does not accept sub-techniques; the full id stays in the YAML and description |

## Schedules

| Rule | Runs every | Looks back | Severity |
|---|---|---|---|
| Kerberoasting | 1 hour | 65 minutes | Medium |
| AS-REP roasting | 1 hour | 65 minutes | Medium |
| DCSync | 15 minutes | 1 hour (20 minute detection window) | High |
| Password spraying | 15 minutes | 30 minutes | Medium |
| Golden Ticket | 1 hour | 12 hours (65 minute detection window) | Medium |

## Enabling

In **Analytics**, enable each rule once its allow-lists are set. A rule only runs on
its schedule; to check a result immediately, paste its query into **Logs**.

## Hunting queries

Hunting queries are not part of the ARM template. In **Sentinel > Hunting > Queries >
New query**, paste the `query` block from the detection's `hunting.yaml` and copy the
name, description, tactic and technique across. The time range is set in the portal.

## Removal

Delete the rules in **Analytics**, or delete the resource group ([teardown](lab-setup.md#11-teardown)).
