# Standards mapping

What this repository maps to, what it does about each item, and what it leaves to
the person running it. A row that says "owner" is not done by the repository.

## MITRE ATT&CK

Every analytics rule and hunting query carries a technique id. CI fails without one.

| Detection | ATT&CK tactic | Sentinel tactic | Technique |
|---|---|---|---|
| Kerberoasting | Credential Access | CredentialAccess | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| AS-REP roasting | Credential Access | CredentialAccess | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| Golden Ticket | Credential Access | CredentialAccess | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) |
| DCSync | Credential Access | CredentialAccess | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| Password spraying | Credential Access | CredentialAccess | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| DCShadow | Defense Impairment | DefenseEvasion | [T1207](https://attack.mitre.org/techniques/T1207/) |
| AdminSDHolder | Persistence, Privilege Escalation | Persistence, PrivilegeEscalation | [T1098](https://attack.mitre.org/techniques/T1098/) |

Tactics were checked against the current ATT&CK dataset (mitre/cti). Two need a note:

- ATT&CK has replaced Defense Evasion with Defense Impairment and Stealth, and lists
  T1207 under Defense Impairment. Sentinel's API (checked at 2023-02-01 and 2025-06-01)
  has no such tactic, so the rule uses `DefenseEvasion`.
- ATT&CK does not mention AdminSDHolder. T1098 is this repository's judgement; Splunk
  maps the same behaviour to T1546. See the [detection README](../detections/adminsdholder/README.md#attck-mapping).

Each detection README also lists the ATT&CK mitigations (M-ids) that remove the
weakness, and the variants of the technique the detection does not catch.

## OWASP

OWASP standards cover applications and delivery pipelines, not Active Directory
detections. They apply here in two places: the logging and monitoring the lab sets
up, and the pipeline that validates the content.

### OWASP Top 10:2021, A09 Security Logging and Monitoring Failures

| A09 concern | In this repository |
|---|---|
| Auditable events are not logged | [Lab setup](lab-setup.md#5-turn-on-the-audit-policy) enables the audit subcategories that produce each event the detections read |
| Logs are only stored locally | Events are forwarded off the host to a Log Analytics workspace by the Azure Monitor Agent |
| No alerting on suspicious activity | Seven scheduled analytics rules raise incidents with mapped entities and specific alert titles |
| Alerting thresholds are not effective | Thresholds are named values at the top of each query; exclusions are reviewed watchlist entries with an owner and expiry; every rule has fire and no-fire test cases |
| Logs are not monitored | Seven hunting queries for analyst review. Response steps are in each detection README |

### OWASP Top 10 CI/CD Security Risks

| Risk | Status | How |
|---|---|---|
| CICD-SEC-1 Insufficient Flow Control | Partly | The deploy job needs the static checks and emulator tests to pass, and its YAML limits it to `main`. Owner: branch protection on `main`, the `sentinel` environment restricted to `main` (the YAML check alone can be edited on a branch), required reviewers with prevent self-review |
| CICD-SEC-2 Inadequate Identity and Access Management | Partly | The deploy identity is a dedicated app registration whose federated credential accepts only this repository's `sentinel` environment, with Microsoft Sentinel Contributor on one resource group. Owner: 2FA and minimal collaborators |
| CICD-SEC-3 Dependency Chain Abuse | Addressed | Exact versions. Python installs with `--require-hashes`; npm installs from the lockfile with integrity hashes. Dependabot raises updates for actions, pip and npm |
| CICD-SEC-4 Poisoned Pipeline Execution | Partly | The workflow uses `pull_request`, not `pull_request_target`, holds no secrets, and npm install scripts are disabled; fork pull requests cannot obtain an OIDC token. A contributor with write access could still edit the workflow on a branch; the environment's branch restriction (owner setting) is what stops that branch deploying |
| CICD-SEC-5 Insufficient Pipeline-Based Access Controls | Addressed | Workflow token is `contents: read`. Only the deploy job adds `id-token: write`. Checkout does not persist credentials |
| CICD-SEC-6 Insufficient Credential Hygiene | Addressed | No secrets in the repository or the workflow. Azure access uses OpenID Connect, so there is no client secret to store or rotate. `.gitignore` blocks key and ticket files |
| CICD-SEC-7 Insecure System Configuration | Partly | GitHub-hosted `ubuntu-24.04` runners, which GitHub patches weekly. Nothing self-hosted |
| CICD-SEC-8 Ungoverned Usage of Third-Party Services | Addressed | Three GitHub actions and one Azure action, all first-party, and one Microsoft container image. No third-party apps |
| CICD-SEC-9 Improper Artifact Integrity Validation | Addressed | Actions pinned to commit SHAs. The Kusto engine image is pinned by digest. Content is escaped before it enters the ARM template, so text in a rule cannot become a template expression |
| CICD-SEC-10 Insufficient Logging and Visibility | Partly | Workflow run logs, a what-if record in each deployment's log, and the Azure activity log for the deployment itself. The what-if is a record, not an approval gate |

## NIST SP 800-53 Rev. 5

| Control | In this repository |
|---|---|
| AU-2 Event Logging | The audit policy and the collection rule name the exact events collected, and why |
| AU-12 Audit Record Generation | Audit subcategories are enabled on the domain controller in the setup guide |
| AU-6 Audit Record Review, Analysis and Reporting | Analytics rules and hunting queries over the collected events |
| SI-4 System Monitoring | Detections for seven Active Directory attack techniques, with documented gaps |
| AC-2(12) Account Monitoring for Atypical Usage | Password spraying, DCSync and Golden Ticket detections flag atypical account use |
| CM-3 Configuration Change Control | Detection changes go through review and CI; AdminSDHolder and DCShadow detections flag unauthorised directory configuration changes |
| IR-4 Incident Handling | A response section in each detection README |

## CIS Controls v8

| Safeguard | In this repository |
|---|---|
| 8.2 Collect Audit Logs | Audit policy and Data Collection Rule |
| 8.5 Collect Detailed Audit Logs | Detailed Kerberos and directory service events, including the raw event data |
| 8.11 Conduct Audit Log Reviews | Hunting queries with guidance on range and reading order |
| 13.1 Centralize Security Event Alerting | Alerts and incidents raised in one Sentinel workspace |

## NIST Cybersecurity Framework 2.0

| Category | In this repository |
|---|---|
| DE.CM Continuous Monitoring | Scheduled analytics rules over domain controller events |
| DE.AE Adverse Event Analysis | Entity mapping, incident grouping and hunting queries |

## Detection-as-code practice

Not a published standard. These are the rules the repository enforces in CI:

- Each query exists once, in its YAML file. Nothing is copied between files.
- A query reads only columns listed in `tools/securityevent.schema`, which was checked
  against the Azure Monitor table reference, and must parse with Microsoft's Kusto
  language service.
- Entity mappings, custom details and alert titles reference only columns the query
  outputs.
- Every analytic rule has at least one case that must fire and one that must stay
  silent, run on a Kusto engine.
- Python tooling is linted with ruff, including its bandit security rules.
- A detection is called lab-validated only once workspace evidence is in
  [evidence/](evidence/).

## Limits

This is a lab on synthetic data. The mappings show which controls the content
supports. They are not a compliance assessment of any environment.
