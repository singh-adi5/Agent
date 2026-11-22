# AdminSDHolder

| | |
|---|---|
| ATT&CK | [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation (see [mapping](#attck-mapping)) |
| Data | `SecurityEvent` 5136 from domain controllers |
| Analytic rule | [analytic.yaml](analytic.yaml), High, runs every 15 minutes over 20 minutes |
| Hunting query | [hunting.yaml](hunting.yaml) |
| Tests | [tests.json](tests.json), 5 cases |

## Technique

`CN=AdminSDHolder,CN=System,<domain>` holds the permission template for protected
accounts and groups, including Domain Admins, Enterprise Admins and Administrators.
About once an hour the SDProp process overwrites the permissions on every protected
object with those on AdminSDHolder. An entry added to AdminSDHolder therefore spreads
to all privileged principals and returns after an administrator removes it from them,
which makes it a persistence mechanism for domain-level control.

## Detection logic

A change to the object's permissions writes 5136 for the `nTSecurityDescriptor`
attribute. Each change produces a pair of events: operation `%%14675` (value deleted)
carrying the old descriptor, and `%%14674` (value added) carrying the new one. The rule
keeps the value-added half, so one change is one result, and reports the new
descriptor in SDDL.

`ObjectDN`, `AttributeLDAPDisplayName` and `AttributeValue` are parsed from
`EventData`. `OperationType` is a typed column, so the rule reads it first and accepts
either the raw code (`%%14674`) or the resolved text (`Value Added`), falling back to
`EventData`.

The logic follows Splunk's published detection *Windows AD AdminSDHolder ACL
Modified*, without its ACE-level parsing.

## ATT&CK mapping

ATT&CK has no AdminSDHolder-specific technique; the ATT&CK dataset does not mention the
object. This rule maps to T1098 Account Manipulation (Persistence, Privilege
Escalation), because the effect is a lasting change to what accounts can do. Splunk maps
the same behaviour to T1546 Event Triggered Execution, on the grounds that SDProp
applies the change. Either is defensible; the choice is recorded here so it is not
mistaken for an ATT&CK statement.

## Prerequisites

5136 is only written when "Audit Directory Service Changes" is enabled and the
object's SACL audits the write. Check the Auditing tab of AdminSDHolder's advanced
security settings (Active Directory Users and Computers, Advanced Features on) and add
a success entry for Everyone covering "Write all properties" and "Modify permissions"
if none applies. See [lab setup, step 5](../../docs/lab-setup.md#5-turn-on-the-audit-policy).

## Tuning

- Legitimate changes are rare and should go through change control. Add a planned
  change's actor to `ADDetectionExclusions` with `Detection` set to `adminsdholder` and
  an `ExpiresOn` date that closes the change window.

## Coverage gaps

- No SACL on the object means no 5136 and no detection.
- The rule reports any new descriptor, not which entry was added. Compare
  `NewDescriptors` with the previous value from the matching `%%14675` event, or use the
  hunting query to see every change.
- Permissions granted directly on protected objects are overwritten by SDProp and are
  not this technique.

## Hunting query

Lists every audited change to AdminSDHolder by actor, any attribute and either
operation. Run it over 90 days. Each change should map to a change record.

## Validation

**Emulator.** [tests.json](tests.json) covers a new descriptor (raw and resolved
operation), the old-descriptor half on its own, the same attribute on another object,
and an excluded actor.

**Lab.** As `labadmin` on DC01, add a test entry to AdminSDHolder's permissions in its
advanced security settings, or follow
[Atomic Red Team T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md)
where a test fits. Expected on DC01: a 5136 for `nTSecurityDescriptor` on
`CN=AdminSDHolder,CN=System,DC=contoso,DC=local` with operation `%%14674`. Remove the
entry afterwards.

## Response

1. Identify the actor and read the new descriptor for the added principal.
2. Restore the previous descriptor and let SDProp run, or trigger it.
3. Check every protected account and group for the added entry.
4. Treat the actor as compromised with Domain Admin rights.

## Mitigations

- M1026 Privileged Account Management: limit who can write to objects under `CN=System`.
- M1015 Active Directory Configuration: baseline the AdminSDHolder descriptor and review changes.
