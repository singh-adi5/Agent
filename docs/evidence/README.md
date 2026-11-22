# Evidence

Screenshots from a live Sentinel workspace, one set per detection. CI proves the
queries are valid and behave correctly on test events; this folder proves they fire
on real telemetry.

## Status

Not yet captured. When a detection's set is committed, change its status in the
[README coverage table](../../README.md#coverage) to "Lab-validated".

## What to capture

After running a detection's validation step ([simulation](../simulation.md)):

1. **Incident.** Sentinel > Incidents: the incident raised by the rule, showing title,
   severity and mapped entities.
2. **Query result.** Sentinel > Logs: the rule's query returning the simulated activity.
3. **Rule.** Sentinel > Analytics: the rule enabled, with its schedule.

File names:

```
kerberoasting-incident.png      kerberoasting-logs.png
asrep-roasting-incident.png     asrep-roasting-logs.png
dcsync-incident.png             dcsync-logs.png
password-spraying-incident.png  password-spraying-logs.png
golden-ticket-incident.png      golden-ticket-logs.png
dcshadow-incident.png           dcshadow-logs.png
adminsdholder-incident.png      adminsdholder-logs.png
```

Add `evidence.md` with the capture date for each set and the lab build used.

## Redaction

Before committing a screenshot:

- Redact public IP addresses, tenant and subscription IDs, and workspace names.
- Crop out the portal account name.
- Exclude anything showing a hash, ticket or password, even from a disposable lab.
