# Kerberoasting

| | |
|---|---|
| ATT&CK | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting |
| Data | `SecurityEvent` 4769 from domain controllers |
| Analytic rule | [analytic.yaml](analytic.yaml), Medium, runs hourly over 65 minutes |
| Hunting query | [hunting.yaml](hunting.yaml) |
| Tests | [tests.json](tests.json), 4 cases |

## Technique

Any authenticated user can request a service ticket for any SPN. Part of the ticket
is encrypted with a key derived from the service account's password, so tickets for
SPNs registered on user accounts can be taken offline and cracked. The request is
valid Kerberos and succeeds, so there is no failure to alert on.

## Detection logic

Each service ticket issued writes 4769 on the DC. The rule keeps requests that:

1. succeeded (`Status` 0x0);
2. were RC4 encrypted (`TicketEncryptionType` 0x17 or 0x18). Roasting tools request
   RC4 because it cracks far faster than AES. `SecurityEvent` has no typed column for
   this field, so it is read from `EventData`;
3. were for a service that is not a machine account or `krbtgt`;
4. came from a user account asking for an SPN other than its own.

It then counts distinct SPNs per requester and source address across all DCs, and
alerts at three or more. One RC4 ticket is routine in most domains. Several
different user-backed SPNs from one account in an hour is enumeration.

The rule runs hourly over 65 minutes. The overlap covers the delay Sentinel applies
to scheduled runs, so a burst split across a run boundary is still counted whole.

## Tuning

- **RC4-only legacy services.** A user of three such services in an hour matches. Fix
  the cause by setting `msDS-SupportedEncryptionTypes` to AES on those accounts, and
  raise `spn_threshold` until that is done.
- **Scanners and AD assessment tools** that request tickets by design. Add their
  accounts to `excluded_requesters`.
- **`spn_threshold`** defaults to 3. In a domain with no RC4-only services it can drop
  to 1, which alerts on any RC4 ticket for a user-backed SPN.

## Coverage gaps

- AES roasting (for example `Rubeus kerberoast /aes`) is not matched by the RC4 filter.
  Catching it needs a per-account volume baseline instead.
- One SPN per hour stays under the threshold. The hunting query covers this.
- A honeypot SPN (an unused account with an SPN and a long random password) gives a
  near-zero false positive signal on any 4769. That is an environment change, so it
  is not part of this rule.

## Hunting query

Lists every account that received RC4 tickets for user-backed SPNs, ranked by
distinct SPNs, with no threshold. Run it over 7 to 30 days to find slow roasting and
to list the RC4-only services behind false positives.

## Validation

**Emulator.** [tests.json](tests.json) covers one true positive (three RC4 SPNs from
one user) and three cases that must stay silent: AES tickets, two SPNs only, and a
computer account.

**Lab.** Requires the three SPN accounts from [lab setup](../../docs/lab-setup.md#6-create-lab-accounts),
requested as the low-privilege user `alice.lab`. Telemetry can be generated with
Impacket `GetUserSPNs.py` ([fortra/impacket](https://github.com/fortra/impacket)),
Rubeus `kerberoast` ([GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)) or
[Atomic Red Team T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md).
Expected on DC01, one 4769 per SPN:

| Field | Value |
|---|---|
| `TicketEncryptionType` (in `EventData`) | `0x17` |
| `Status` | `0x0` |
| `ServiceName` | `svc-sql`, `svc-web`, `svc-backup` |
| `TargetUserName` | `alice.lab@CONTOSO.LOCAL` |

The rule should return one row for `alice.lab` with `SpnCount` 3. See
[simulation](../../docs/simulation.md) for scope and evidence capture.

## Response

1. Identify the requester and source address from the alert entities.
2. Treat the password of every account in `Services` as exposed. Rotate to long random
   values or move the accounts to group managed service accounts.
3. Investigate how the requesting account was compromised.

## Mitigations

- M1027 Password Policies: 25+ character random passwords on service accounts, or gMSA.
- M1041 Encrypt Sensitive Information: enforce AES and disable RC4 for Kerberos.
- M1026 Privileged Account Management: service accounts hold only the rights the service needs.
