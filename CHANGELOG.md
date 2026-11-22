# Changelog

## 1.0.0 - 2026-11-22

First complete release.

- Analytic rule, hunting query, test cases and documentation for five techniques:
  Kerberoasting (T1558.003), AS-REP roasting (T1558.004), Golden Ticket (T1558.001),
  DCSync (T1003.006) and password spraying (T1110.003).
- Content linter for the Sentinel rule and hunting query schema, ATT&CK ids, entity
  mappings, alert titles and test fixtures.
- Query parsing with Microsoft's Kusto language service against the `SecurityEvent`
  schema, and execution tests on the Kusto emulator.
- ARM template build for the analytic rules, created disabled with incident grouping.
- Lab build guide for Azure, a Windows Server 2022 domain controller, the Azure
  Monitor Agent and a filtered Data Collection Rule.
