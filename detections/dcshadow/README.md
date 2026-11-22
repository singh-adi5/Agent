# DCShadow

| | |
|---|---|
| ATT&CK | [T1207](https://attack.mitre.org/techniques/T1207/) Rogue Domain Controller |
| Data | `SecurityEvent` 4742 and 5136 from domain controllers |
| Analytic rule | [analytic.yaml](analytic.yaml), High, runs every 15 minutes over 20 minutes |
| Hunting query | [hunting.yaml](hunting.yaml) |
| Tests | [tests.json](tests.json), 6 cases |

## Technique

DCShadow registers a host the attacker controls as a temporary domain controller,
pushes changes into Active Directory through normal replication, then unregisters.
Changes made this way do not pass through the usual directory write path, so they do
not produce the change events a defender would normally rely on.

To be accepted as a replication partner the rogue host needs, among other objects,
two service principal names on its computer account: a Global Catalog SPN (`GC/...`)
and the directory replication interface SPN
(`E3514235-4B06-11D1-AB04-00C04FC2DCD2/...`). Writing those SPNs is the step this rule
detects.

## Detection logic

Two events record SPN changes on a computer account:

| Event | Source | Where the SPN is |
|---|---|---|
| 4742 | Computer account management | `ServicePrincipalNames` |
| 5136 | Directory service changes | `AttributeValue` when `AttributeLDAPDisplayName` is `servicePrincipalName` |

The rule keeps changes whose SPN contains `GC/` or the replication interface GUID and
whose target is not in the `ADDomainControllers` watchlist. For 4742 the target account
is `TargetUserName`; for 5136 it is the object's CN plus `$`. Additions and removals
both match, because DCShadow removes the SPNs after use.

None of these fields are typed columns in `SecurityEvent`; all are parsed from
`EventData`. The logic follows the public Sigma rule *Possible DC Shadow Attack*
(`win_security_possible_dc_shadow`), adapted to the Sentinel schema and extended with
the replication interface SPN.

## ATT&CK tactic

ATT&CK now places T1207 under Defense Impairment, one of the two tactics that replaced
Defense Evasion. Sentinel's API does not have that tactic yet (checked against API
versions 2023-02-01 and 2025-06-01), so the rule is tagged `DefenseEvasion`, the
closest value the API accepts.

## Tuning

- **Domain controller promotion** writes the same SPNs to the new DC's account. Add the
  DC to `ADDomainControllers` as part of the build, or expect one alert per promotion.
- **Exclusions** go in `ADDetectionExclusions` with `Detection` set to `dcshadow` and
  the computer account (`name$`) as `Value`. There should be very few.

## Coverage gaps

- Requires "Audit Computer Account Management" for 4742, or "Audit Directory Service
  Changes" plus auditing on computer objects for 5136.
- An attacker who already controls a genuine DC does not need to register SPNs.
- DCShadow also creates an `nTDSDSA` object in the configuration partition. That is a
  stronger signal but needs auditing on the Sites container, which is not set by
  default, so it is not used here.

## Hunting query

Lists every `GC/` and replication SPN change on any computer account, domain
controllers included, and whether the account is in the watchlist. Run it over 30 days
before enabling the rule to confirm the watchlist is complete.

## Validation

**Emulator.** [tests.json](tests.json) covers a 4742 and a 5136 true positive, a listed
DC registering its own SPN, an ordinary SPN change, an active exclusion, and an expired
exclusion that must fire again.

**Lab.** Telemetry can be generated with Mimikatz `lsadump::dcshadow`
([gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz/wiki)) or
[Atomic Red Team T1207](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1207/T1207.md).
It needs a domain-joined host and Domain Admin rights; the lab has one domain
controller, so a second Windows host must be added for this test. Expected on DC01: a
4742 or 5136 adding a `GC/` SPN to the host's computer account.

## Response

1. Identify the computer account and the account that made the change.
2. Isolate the host. Treat the actor as compromised with Domain Admin rights.
3. Review directory changes from the window, including objects that changed without
   matching change events, which is what DCShadow is used for.

## Mitigations

- M1026 Privileged Account Management: limit who holds Domain Admin and equivalent rights.
- M1015 Active Directory Configuration: monitor the configuration partition and SPNs on computer objects.
