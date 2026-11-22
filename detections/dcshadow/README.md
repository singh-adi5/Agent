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
whose target is not a listed domain controller:

- **4742** names the computer account, matched against the watchlist's `SamAccountName`.
  4742 records the account's full SPN list after the change, so it shows the SPN being
  added but cannot show it being removed.
- **5136** names the object, matched against the watchlist's full `DistinguishedName`.
  A CN is only unique within its container, so matching on CN would let a rogue object
  named like a DC in another container pass as that DC. 5136 records additions
  (`%%14674`) and removals (`%%14675`), so it also catches the clean-up step.

None of these fields are typed columns in `SecurityEvent`; all are parsed from
`EventData`. The logic follows the public Sigma rule *Possible DC Shadow Attack*
(`win_security_possible_dc_shadow`), adapted to the Sentinel schema and extended with
the replication interface SPN.

## ATT&CK tactic

ATT&CK now places T1207 under Defense Impairment, one of the two tactics that replaced
Defense Evasion. Sentinel's API does not have that tactic yet (checked against API
versions 2023-02-01 and 2025-06-01), so the rule is tagged `DefenseEvasion`, the
closest value the API accepts.

The reported `TargetAccount` for a 5136 is the object's CN plus `$`; `Objects` holds
the full DN.

## Tuning

- **Domain controller promotion** writes the same SPNs to the new DC's account. Add the
  DC to `ADDomainControllers` (account, host name and DN) as part of the build, or
  expect one alert per promotion.
- **Exclusions** go in `ADDetectionExclusions` with `Detection` set to `dcshadow` and
  the computer account (`name$`) as `Value`. There should be very few.

## Coverage gaps

- Requires "Audit Computer Account Management" for 4742, or "Audit Directory Service
  Changes" plus auditing on computer objects for 5136. Collect both: only 5136 sees the
  SPNs being removed, and the public Mimikatz sample checked during review contained
  5136 events only.
- An attacker who already controls a genuine DC does not need to register SPNs.
- DCShadow also creates an `nTDSDSA` object in the configuration partition. That is a
  stronger signal but needs auditing on the Sites container, which is not set by
  default, so it is not used here.

## Hunting query

Lists every `GC/` and replication SPN change on any computer account, domain
controllers included, and whether the account is in the watchlist. Run it over 30 days
before enabling the rule to confirm the watchlist is complete.

## Validation

**Emulator.** [tests.json](tests.json) covers 4742 and 5136 true positives, including
the multi-line SPN list 4742 really records, an SPN removal, and an object reusing a
DC's CN in another container; listed DCs writing their own SPNs by account and by DN;
an ordinary SPN change; and exclusions that are active, expire today, or have expired.

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
