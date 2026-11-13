# AS-REP roasting

| | |
|---|---|
| ATT&CK | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) Steal or Forge Kerberos Tickets: AS-REP Roasting |
| Tactic | Credential Access |
| Data source | `SecurityEvent`, EventID 4768 |
| Severity | Medium |
| Files | [`query.kql`](query.kql), [`rule.yaml`](rule.yaml), [simulation](../../simulations/asrep-roasting.md) |

## Technique

Kerberos normally proves who you are before the KDC replies, with pre-authentication:
the client encrypts a timestamp with its password hash. An account flagged "do not
require Kerberos pre-authentication" skips that step. Anyone can ask the KDC for that
account's AS-REP, part of which is encrypted with the account's password key, and
crack it offline. It is Kerberoasting's quieter cousin: no prior credentials are
needed, only the account name.

## Detection logic

Requesting the AS-REP writes event 4768 on the domain controller. The query keeps one when:

1. It succeeded (`Status` 0x0).
2. Pre-authentication type is 0, read from `EventData`. `SecurityEvent` has no column
   for this field. Type 0 is the no-pre-auth case; a normal logon is type 2 (encrypted
   timestamp) or a PKINIT type.
3. The ticket is RC4 encrypted (0x17 or 0x18), read from `EventData`. Roasting tools
   request RC4 because it cracks faster than AES.
4. The target is not a machine account.

It groups by source address across domain controllers and fires on one or more
targeted accounts. A single RC4, no-pre-auth TGT is already worth an alert: the
account should not be configured this way.

## False positives and tuning

- **Accounts legitimately set to not require pre-authentication.** Some old
  appliances and Unix Kerberos integrations need it. Each is a standing weakness.
  Add the account to `excluded_targets`, in lower case, and plan to fix the root cause.
- **`account_threshold`** defaults to 1. Raise it to alert only on bulk roasting
  (one source pulling several such accounts) if single accounts are too noisy, but
  prefer fixing the accounts.

## Known gaps

- **AES roasting.** A no-pre-auth account roasted with AES is not caught by the RC4
  filter. If every such account is removed, the misconfiguration is gone and the
  filter does not matter.
- **One request per account.** The signal is the configuration, not the volume, so
  there is no low-and-slow evasion here, unlike Kerberoasting.
- **Pre-auth type must be in `EventData`.** If the collection drops the event detail,
  the pre-auth filter cannot run.

## Response

1. Identify the targeted accounts from `Accounts` and the source from `SourceIp`.
2. Treat those account passwords as exposed. Reset them to long random values.
3. Remove the "do not require pre-authentication" flag unless there is a documented
   reason, then keep the account in `excluded_targets` only if the flag must stay.
4. Investigate the source address.

## Mitigations

- M1015 Active Directory Configuration: audit for accounts with pre-authentication disabled; remove the flag.
- M1027 Password Policies: long random passwords, or gMSA, on any account that must keep the flag.
- M1041 Encrypt Sensitive Information: enforce AES so RC4 requests stand out.
