# DCSync

| | |
|---|---|
| ATT&CK | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) OS Credential Dumping: DCSync |
| Data | `SecurityEvent` 4662 and 4624 from domain controllers |
| Analytic rule | [analytic.yaml](analytic.yaml), High, runs every 15 minutes over 1 hour |
| Hunting query | [hunting.yaml](hunting.yaml) |
| Tests | [tests.json](tests.json), 3 cases |

## Technique

Domain controllers replicate through the Directory Replication Service (DRS)
protocol. An account holding the replication extended rights on the domain object can
call the same interface and request any object's secrets, including password hashes
and the `krbtgt` key. The attacker never logs on to the DC or touches `ntds.dit`.

## Detection logic

Use of a replication right writes 4662 on the DC that served the request, with the
right's GUID in `Properties`:

| Right | GUID |
|---|---|
| DS-Replication-Get-Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

The rule alerts on any 4662 carrying one of these GUIDs whose subject is not in
`domain_controllers` or `approved_replication_accounts`. 4662 has no network address,
so the rule joins on logon ID to the 4624 network logon on the same DC to recover it.
If no logon is found the alert still fires with `SourceIp` empty.

The detection window is 20 minutes on a 15 minute schedule. The extra five minutes
cover the scheduled run delay. The one hour query period only feeds the 4624 lookup.

Many public versions of this rule exclude every account ending in `$`. That misses
DCSync from a compromised computer account that has been granted replication rights,
a known persistence technique. Listing the DCs by name costs some maintenance and
closes that gap.

## Tuning

- **Directory synchronisation.** Microsoft Entra Connect replicates by design through
  an account usually named `MSOL_` followed by a hex string. Add it to
  `approved_replication_accounts` in lower case. It should only ever originate from
  the sync server.
- **New domain controllers** alert until they are added to `domain_controllers`. Make
  that part of the DC build procedure.
- **Other products that replicate**, such as password filters, identity governance
  tools and AD backup agents. Confirm with the owner, then add the account.

Every account on the allow-list can dump the domain. Keep the list short and review it.

## Coverage gaps

- Requires "Audit Directory Service Access" on every DC and the default audit entries
  on the domain object. An attacker with Domain Admin rights can remove those first.
- 4662 must be collected. Sentinel's "Common" event tier does not include it. See
  [architecture](../../docs/architecture.md#event-collection).
- DCSync run as a genuine domain controller account is not detected.

## Hunting query

Lists every account that used a replication right, domain controllers included. Run it
over 30 days to baseline legitimate replication and populate the allow-lists before
enabling the rule.

## Validation

**Emulator.** [tests.json](tests.json) covers one true positive (a user account using
Get-Changes-All) and two silent cases: replication by the DC computer account, and
directory access without a replication right.

**Lab.** Requires an account with replication rights; in the lab, `labadmin` is a
Domain Admin. Telemetry can be generated with Impacket `secretsdump.py` (DRSUAPI
method, [fortra/impacket](https://github.com/fortra/impacket)), Mimikatz
`lsadump::dcsync` ([gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz/wiki))
or [Atomic Red Team T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md).
Target a single account; the Golden Ticket validation uses `krbtgt`. Expected on DC01:

| Field | Value |
|---|---|
| `EventID` | 4662 |
| `ObjectServer` | `DS` |
| `Properties` | contains one of the GUIDs above |
| `SubjectUserName` | `labadmin` |

The output is credential material. Do not keep or commit it. After this step the lab
is compromised by design; see [teardown](../../docs/lab-setup.md#11-teardown).

## Response

1. Treat as full domain compromise until shown otherwise.
2. Isolate the source host.
3. Establish how the account gained replication rights: group membership or a direct
   ACE on the domain object.
4. Reset `krbtgt` twice, allowing replication between resets, and reset all
   privileged accounts.

## Mitigations

- M1026 Privileged Account Management: replication rights for domain controllers only.
- M1015 Active Directory Configuration: audit the domain object ACL for replication rights.
- M1027 Password Policies: reduces the value of dumped hashes.
