# Simulation

Each detection README has a **Validation** section describing the activity that
should fire it, the tools that generate that activity, and the events to expect. This
page covers scope, order and evidence capture for all of them.

## Scope

Run the validation steps only against the lab built from [lab-setup.md](lab-setup.md).
Using these tools against systems you do not own, or are not authorised in writing to
test, is an offence in most jurisdictions, including under the UK Computer Misuse Act
1990. See [SECURITY.md](../SECURITY.md).

The validation sections name the public tools and link to their documentation and to
the matching [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests,
which are the maintained source for exact invocations. They do not reproduce attack
command lines.

## Order

| Step | Detection | Technique | Notes |
|---|---|---|---|
| 1 | [Kerberoasting](../detections/kerberoasting/README.md#validation) | T1558.003 | As `alice.lab` |
| 2 | [AS-REP roasting](../detections/asrep-roasting/README.md#validation) | T1558.004 | Disables pre-authentication on `svc-legacy` for the test |
| 3 | [Password spraying](../detections/password-spraying/README.md#validation) | T1110.003 | No credentials needed |
| 4 | [AdminSDHolder](../detections/adminsdholder/README.md#validation) | T1098 | Administrative change; revert afterwards |
| 5 | [DCShadow](../detections/dcshadow/README.md#validation) | T1207 | Needs a second domain-joined Windows host |
| 6 | [DCSync](../detections/dcsync/README.md#validation) | T1003.006 | Produces the `krbtgt` key used in step 7 |
| 7 | [Golden Ticket](../detections/golden-ticket/README.md#validation) | T1558.001 | Leaves the lab compromised |

## Conventions

- Commands run on `attacker01` (10.10.1.10) unless stated otherwise.
- The domain controller is `dc01.contoso.local` at 10.10.1.4.
- Tool output is credential material. Do not keep it and never commit it; `.gitignore`
  blocks the common file types.
- Events reach the workspace within a few minutes, but a rule only runs on its
  schedule. Paste the rule's query into **Logs** to see the result immediately.

## Evidence

For each detection, capture the incident, the query result in **Logs** and the
enabled rule. File names and redaction rules are in [evidence/README.md](evidence/README.md).
When a detection's evidence is committed, change its status in the README coverage
table from "Emulator-tested" to "Lab-validated".
