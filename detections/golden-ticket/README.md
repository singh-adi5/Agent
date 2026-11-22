# Golden Ticket

| | |
|---|---|
| ATT&CK | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) Steal or Forge Kerberos Tickets: Golden Ticket |
| Data | `SecurityEvent` 4768, 4769 and 4770 from every domain controller |
| Analytic rule | [analytic.yaml](analytic.yaml), Medium, runs hourly over 12 hours |
| Hunting query | [hunting.yaml](hunting.yaml) |
| Tests | [tests.json](tests.json), 2 cases |

## Technique

Every TGT in a domain is encrypted with the `krbtgt` key. With that key, typically
obtained through DCSync, an attacker can build a TGT offline for any user with any
group membership, and the KDC accepts it because it decrypts correctly.

## What the logs show

The forged TGT is built off the domain, so the DC never issues it and there is no
4768 for it. Its lifetime and group membership are inside the ticket and are not
written to any Security event; rules that claim to read ticket lifetime from
`SecurityEvent` are not reading a real field.

The DC does log the next step. Using the TGT means requesting service tickets, which
writes ordinary 4769 events. The detectable pattern is service ticket requests with
no TGT issued to that account and address beforehand.

## Detection logic

1. Collect successful 4768 (TGT issued) and 4770 (TGT renewed) over 12 hours. This is
   every account and address pair holding a legitimate TGT. The default TGT lifetime
   is 10 hours.
2. Collect successful 4769 over the last 65 minutes, excluding the `krbtgt` service and
   computer accounts. The extra five minutes cover the scheduled run delay.
3. Keep service ticket requests whose account and address have no TGT on record.

Both sides are normalised before the join: lower case, realm removed, `::ffff:`
prefix stripped. 4768 records `alice` and 4769 records `alice@CONTOSO.LOCAL`, so a raw
comparison matches nothing. Results are grouped across DCs.

## Tuning

This is a correlation and is noisier than the other rules, which is why it ships at
Medium. Raise it to High once it is quiet in the environment.

- **Uncollected domain controllers.** A TGT issued by a DC that is not sending logs
  makes every later service ticket look forged. Collect 4768 to 4770 from every DC
  before enabling the rule.
- **Address changes.** A laptop moving from Wi-Fi to VPN keeps its TGT but arrives
  from a new address. Add roaming accounts to `excluded_accounts`.
- **TGT lifetime over 10 hours.** Raise `tgt_lookback` and keep `queryPeriod` at least
  as long.
- **Ingestion gaps.** A dropped 4768 produces a false positive. Check agent health
  before acting on an alert.

## Coverage gaps

- An attacker who already holds a real TGT for the same account from the same address
  is hidden by it.
- Computer accounts are excluded.
- Silver tickets forge the service ticket and never contact the KDC, so there is no
  4769 to see.
- Diamond and sapphire tickets modify a genuinely issued TGT, so a 4768 exists.

Further signals not implemented here: RC4 service tickets for privileged accounts in
an AES-only domain, 4769 for account names that do not exist in the directory, and
widespread Kerberos errors 0x1F or 0x40 shortly after a `krbtgt` reset.

## Hunting query

Lists account and address pairs that received service tickets with no TGT from that
address over the whole time range, and whether the account holds a TGT from any other
address. Run it over 1 to 7 days and disregard results from the first 12 hours of the
range, whose TGTs may predate it.

## Validation

**Emulator.** [tests.json](tests.json) covers one true positive (4769 with no TGT on
record) and one silent case (4769 preceded by a 4768 for the same account and address).

**Lab.** Requires the `krbtgt` key from the [DCSync](../dcsync/README.md#validation)
step. Telemetry can be generated with Mimikatz `kerberos::golden`
([gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz/wiki)), Rubeus `golden`
([GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)), Impacket `ticketer.py`
([fortra/impacket](https://github.com/fortra/impacket)) or
[Atomic Red Team T1558.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.001/T1558.001.md).
The forged ticket must then be used against a service on DC01 to produce the 4769.

Use an account and host that have not authenticated normally in the previous 12
hours, otherwise the real TGT masks the forged one. Expected on DC01: a successful
4769 for `labadmin@CONTOSO.LOCAL` from the attacker address, with no 4768 or 4770 for
that pair in the lookback.

Afterwards the lab is fully compromised. Delete it, see
[teardown](../../docs/lab-setup.md#11-teardown). Do not keep or commit ticket files.

## Response

1. Treat as domain compromise: the `krbtgt` key is known.
2. Reset `krbtgt` twice, allowing replication between resets. A single reset leaves
   the previous key valid.
3. Find the original credential theft, starting with DCSync alerts and access to `ntds.dit`.
4. Isolate the source address and review all activity by the account.

## Mitigations

- M1015 Active Directory Configuration: rotate `krbtgt` on a schedule and after any DC compromise.
- M1026 Privileged Account Management: limit who can replicate or log on to DCs.
- M1041 Encrypt Sensitive Information: in an AES-only domain, RC4 forgeries stand out.
