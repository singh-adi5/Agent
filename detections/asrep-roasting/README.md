# AS-REP roasting

| | |
|---|---|
| ATT&CK | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) Steal or Forge Kerberos Tickets: AS-REP Roasting |
| Data | `SecurityEvent` 4768 from domain controllers |
| Analytic rule | [analytic.yaml](analytic.yaml), Medium, runs hourly over 65 minutes |
| Hunting query | [hunting.yaml](hunting.yaml) |
| Tests | [tests.json](tests.json), 3 cases |

## Technique

Kerberos pre-authentication makes a client prove knowledge of its password, by
encrypting a timestamp, before the KDC replies. An account with "Do not require
Kerberos preauthentication" set skips that step. Anyone who knows the account name
can request its AS-REP, part of which is encrypted with the account's password key,
and crack it offline. No credentials are needed.

## Detection logic

The AS-REP is logged as 4768 on the DC. The rule keeps events that:

1. succeeded (`Status` 0x0);
2. have pre-authentication type 0, meaning none was performed. A normal logon is type
   2 (encrypted timestamp) or a PKINIT type;
3. were RC4 encrypted (0x17 or 0x18);
4. were for a user account, not a computer account.

`SecurityEvent` has no typed columns for the pre-authentication or encryption type,
so both are read from `EventData`.

Results are grouped by source address across DCs. The rule alerts on a single
account: an RC4 TGT issued without pre-authentication means both the configuration
and the request are wrong.

## Tuning

- **Accounts that need pre-authentication disabled.** Some appliances and Unix
  Kerberos integrations do. Each one is a standing weakness. Add it to
  `excluded_targets` and track the fix.
- **`account_threshold`** defaults to 1. Raise it to alert only on bulk roasting if
  single-account alerts are too frequent, but fixing the accounts is the better route.

## Coverage gaps

- A no-pre-authentication account roasted with AES is not matched. The hunting query
  lists every such account regardless of encryption type.
- If `EventData` is not collected in full, the pre-authentication filter cannot run.

## Hunting query

Lists every account issued a TGT without pre-authentication over the time range,
with its sources and encryption types. Run it over 30 days. The output is the list of
accounts to fix.

## Validation

**Emulator.** [tests.json](tests.json) covers one true positive and two silent cases:
a normal TGT with pre-authentication, and a no-pre-authentication TGT using AES.

**Lab.** Disable pre-authentication on a lab account, on DC01:

```powershell
Set-ADAccountControl -Identity svc-legacy -DoesNotRequirePreAuth $true
```

Telemetry can be generated with Impacket `GetNPUsers.py`
([fortra/impacket](https://github.com/fortra/impacket)), Rubeus `asreproast`
([GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)) or
[Atomic Red Team T1558.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.004/T1558.004.md).
Expected on DC01:

| Field | Value |
|---|---|
| `PreAuthType` (in `EventData`) | `0` |
| `TicketEncryptionType` (in `EventData`) | `0x17` |
| `Status` | `0x0` |
| `TargetUserName` | `svc-legacy@CONTOSO.LOCAL` |

Re-enable pre-authentication afterwards with `-DoesNotRequirePreAuth $false`.

## Response

1. Identify the targeted accounts from `Accounts` and the source from `SourceIp`.
2. Rotate those passwords to long random values.
3. Re-enable pre-authentication unless there is a documented reason not to.
4. Investigate the source address.

## Mitigations

- M1015 Active Directory Configuration: audit for and remove `DONT_REQ_PREAUTH`.
- M1027 Password Policies: long random passwords on any account that must keep the flag.
- M1041 Encrypt Sensitive Information: enforce AES so RC4 requests stand out.
