# Password spraying

| | |
|---|---|
| ATT&CK | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying |
| Data | `SecurityEvent` 4771 and 4625 |
| Analytic rule | [analytic.yaml](analytic.yaml), Medium, runs every 15 minutes over 30 minutes |
| Hunting query | [hunting.yaml](hunting.yaml) |
| Tests | [tests.json](tests.json), 3 cases |

## Technique

The attacker tries one or two common passwords against many accounts instead of many
passwords against one. Each account sees one failure, so lockout policy never
triggers and per-account alerting stays quiet.

## Detection logic

The signal is the source, not the account. The rule combines two failure types:

| Event | Protocol | Filter |
|---|---|---|
| 4771 | Kerberos pre-authentication | `Status` 0x18 (wrong password) |
| 4625 | NTLM and interactive logon | `SubStatus` 0xC000006A (wrong password) or 0xC0000064 (unknown user) |

Kerbrute sprays over Kerberos and only produces 4771. SMB and LDAP spraying produces
4625. A rule on either event alone misses the other family.

Failures are grouped by source address. The rule alerts when one source fails against
10 or more distinct accounts in 30 minutes with 5 or fewer attempts per account. The
second condition separates a spray (wide and shallow) from a brute force (narrow and
deep) and from a single service account retrying a stale password.

The rule runs every 15 minutes over 30 minutes, so a spray crossing a run boundary is
counted whole. The same spray can then alert twice; incident grouping on the source
address folds both into one incident.

## Tuning

- **Shared egress addresses** such as VPN concentrators, reverse proxies, RDP
  gateways and terminal servers put many users behind one address and can look like
  a spray after a password expiry wave. Add them to `excluded_sources`, or raise the
  threshold for them.
- **`account_threshold`** defaults to 10. Size it to the estate and to how much NAT
  sits in front of the DCs.
- **`max_attempts_per_account`** defaults to 5. Raise it if sprays with several
  passwords per run are expected.

## Coverage gaps

- Fewer than 10 accounts per 30 minutes stays under the threshold. The hunting query
  covers slow sprays.
- A spray distributed across many source addresses keeps each source under the threshold.
- 4625 for SMB spraying against a member server is written on that server. This lab
  collects from the DC only.
- The rule sees failures. Whether any attempt succeeded is answered by the hunting
  query, which should be run on every alert.

## Hunting query

Ranks sources by the number of accounts they failed against, from a floor of three,
and lists accounts that also authenticated successfully from the same source. Run it
over 1 to 7 days, and against the alert's source address whenever the rule fires.

## Validation

**Emulator.** [tests.json](tests.json) covers one true positive (12 accounts from one
source) and two silent cases: one account failing repeatedly, and failures against
only four accounts.

**Lab.** Use the fifteen `userNN` accounts from
[lab setup](../../docs/lab-setup.md#6-create-lab-accounts), a wrong
password, and one or two attempts per account. Telemetry can be generated with
Kerbrute `passwordspray` ([ropnop/kerbrute](https://github.com/ropnop/kerbrute)) for
4771, any SMB or LDAP authentication loop for 4625, or
[Atomic Red Team T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md).
The rule should return one row for the attacker address with `TargetedAccounts` of 10
or more. Unlock any account that locks out with `Unlock-ADAccount`.

## Response

1. Run the hunting query for `SourceIp`. Any account in `SucceededAfterFailing` is
   compromised: reset it and review its activity.
2. Block or isolate the source.
3. Check `Accounts` for names that do not exist in the domain. An accurate list
   suggests earlier reconnaissance.

## Mitigations

- M1032 Multi-factor Authentication.
- M1027 Password Policies: block common and breached passwords.
- M1036 Account Use Policies: lockout threshold with an observation window.
