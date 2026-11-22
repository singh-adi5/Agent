# Deployment

Each detection's `analytic.yaml` is in the format Microsoft uses for rule templates in
the Azure-Sentinel repository. The build turns every rule, plus every watchlist that has
items, into one ARM template, which is deployed by hand or by the pipeline.

> Status: the template is covered by unit tests and the pipeline is written, but neither
> has been run against a live workspace yet.

## What gets deployed

| Resource | Source | Notes |
|---|---|---|
| Scheduled analytics rules | `detections/*/analytic.yaml` | Resource name is the rule's `id`, so redeploys update in place |
| `ADDomainControllers` watchlist | `watchlists/ADDomainControllers.csv` | Must list every DC before DCSync and DCShadow are enabled |
| `ADDetectionExclusions` watchlist | `watchlists/ADDetectionExclusions.csv` | Deployed only once it has rows |

Template parameters:

| Parameter | Default | Meaning |
|---|---|---|
| `workspace` | none | Log Analytics workspace with Sentinel enabled |
| `enableRules` | `false` | Create the rules enabled. Use the same value on every deployment: a redeploy with `false` switches enabled rules off |

Other settings in the template: incident creation on; incident grouping on matching
entities with a 5 hour lookback, because overlapping runs can alert twice on the same
activity; alert titles from `alertDetailsOverride`; parent technique ids only, because
API version `2023-02-01` does not accept sub-techniques there (the full id stays in the
YAML and description).

## Before the first deployment

1. Events are arriving in `SecurityEvent` ([lab setup, step 10](lab-setup.md#10-check-that-events-arrive)).
2. `watchlists/ADDomainControllers.csv` lists the lower-case computer account of every DC.
   Run the DCSync and DCShadow hunting queries to check it is complete.
3. `make check` passes.

Watchlists can be managed in the repository (deployed with the rules) or in the
Sentinel portal, not both. How a redeploy treats items added in the portal has not been
verified, so pick one.

## Manual deployment

```bash
make arm
az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file build/sentinel-analytics.json \
  --parameters workspace=<WORKSPACE_NAME> enableRules=false
```

`build/` is ignored by git. To import through the portal instead: **Sentinel >
Analytics > Import**, then select the file.

## Pipeline deployment

The `deploy` job in [.github/workflows/ci.yml](../.github/workflows/ci.yml) runs on
`main` after the static checks and the emulator tests pass. It builds the template,
shows an `az deployment group what-if` preview, then deploys. It is skipped until the
variables below are set, so the repository works without an Azure subscription.

Authentication is OpenID Connect: GitHub issues a short-lived token for the job, and
Microsoft Entra ID exchanges it for an Azure token. No client secret or credential is
stored in GitHub. The job runs in a GitHub environment named `sentinel`; add required
reviewers to it to put a manual approval in front of every deployment.

### One-time setup

In Azure (Cloud Shell works). Replace each `<PLACEHOLDER>`:

```bash
APP_ID=$(az ad app create --display-name sentinel-detections-deploy --query appId -o tsv)
az ad sp create --id "$APP_ID"

# Trust GitHub tokens issued to jobs in this repository's `sentinel` environment only.
az ad app federated-credential create --id "$APP_ID" --parameters '{
  "name": "github-sentinel-environment",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<OWNER>/<REPOSITORY>:environment:sentinel",
  "audiences": ["api://AzureADTokenExchange"]
}'

# Least privilege: Sentinel content and ARM deployments in one resource group.
az role assignment create --assignee "$APP_ID" \
  --role "Microsoft Sentinel Contributor" \
  --scope "$(az group show --name <RESOURCE_GROUP> --query id -o tsv)"
```

Microsoft Sentinel Contributor includes `Microsoft.SecurityInsights/*` (rules and
watchlists) and `Microsoft.Resources/deployments/*` (ARM deployments and what-if), so no
broader role is needed.

In GitHub, **Settings > Environments > New environment**, name it `sentinel`, add
required reviewers, and add these environment variables:

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID` | `$APP_ID` from above |
| `AZURE_TENANT_ID` | `az account show --query tenantId -o tsv` |
| `AZURE_SUBSCRIPTION_ID` | `az account show --query id -o tsv` |
| `SENTINEL_RESOURCE_GROUP` | resource group of the workspace |
| `SENTINEL_WORKSPACE` | workspace name |
| `SENTINEL_ENABLE_RULES` | `false` until the watchlists are populated, then `true` |

These are identifiers, not credentials, but they stay in GitHub settings, not in the
repository. If the repository is renamed, update the federated credential's `subject`.

## Schedules

| Rule | Runs every | Looks back | Severity |
|---|---|---|---|
| Kerberoasting | 1 hour | 65 minutes | Medium |
| AS-REP roasting | 1 hour | 65 minutes | Medium |
| Golden Ticket | 1 hour | 12 hours (65 minute detection window) | Medium |
| DCSync | 15 minutes | 1 hour (20 minute detection window) | High |
| DCShadow | 15 minutes | 20 minutes | High |
| AdminSDHolder | 15 minutes | 20 minutes | High |
| Password spraying | 15 minutes | 30 minutes | Medium |

## Hunting queries

Hunting queries are not in the ARM template. In **Sentinel > Hunting > Queries > New
query**, paste the `query` block from the detection's `hunting.yaml` and copy the name,
description, tactic and technique across. Set the time range in the portal.

## Removal

Delete the rules and watchlists in Sentinel, or delete the resource group
([teardown](lab-setup.md#11-teardown)).
