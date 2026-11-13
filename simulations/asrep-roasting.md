# Simulate AS-REP roasting

Detection: [`detections/asrep-roasting`](../detections/asrep-roasting/README.md) · ATT&CK T1558.004

## Prerequisites

At least one account set to not require Kerberos pre-authentication. Create one in
the lab ([SETUP.md](../docs/SETUP.md)); on DC01:

```powershell
Set-ADAccountControl -Identity svc-legacy -DoesNotRequirePreAuth $true
```

`svc-legacy` is a lab account. Never set this on a real account outside the lab.

## What generates the telemetry

AS-REP roasting asks the KDC for the AS-REP of a no-pre-auth account; the reply holds
crackable material. It needs only the account name, no credentials.

Standard tools that produce this telemetry, with their documented function:

- **Impacket `GetNPUsers.py`** — finds accounts without pre-authentication and
  requests their AS-REPs. Docs: <https://github.com/fortra/impacket>.
- **Rubeus** `asreproast` action, on a domain-joined Windows host. Docs:
  <https://github.com/GhostPack/Rubeus>.
- **Atomic Red Team T1558.004** — maintained lab commands:
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.004/T1558.004.md>.

## Expected log artifacts

On DC01, event **4768** with:

| Field | Value | Meaning |
|---|---|---|
| `PreAuthType` (in `EventData`) | `0` | no pre-authentication |
| `TicketEncryptionType` (in `EventData`) | `0x17` | RC4, crackable offline |
| `Status` | `0x0` | the TGT was issued |
| `TargetUserName` | `svc-legacy@CONTOSO.LOCAL` | the roasted account |
| `IpAddress` | the attacker address | source |

## Confirm the detection

Paste `detections/asrep-roasting/query.kql` into Sentinel **Logs** over the last
hour. One row should return for the attacker address, with `svc-legacy` in
`Accounts`. The scheduled rule then raises an alert. Screenshot it into
[`docs/evidence/`](../docs/evidence/).

## Reset the lab

Remove the flag you set:

```powershell
Set-ADAccountControl -Identity svc-legacy -DoesNotRequirePreAuth $false
```
