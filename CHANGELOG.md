# Changelog

## 1.1.0 - 2026-11-22

- Added DCShadow (T1207) and AdminSDHolder (T1098) detections, with hunting queries and
  tests. Collection now includes events 4742 and 5136.
- Moved domain controller lists and exclusions out of query text into the
  `ADDomainControllers` and `ADDetectionExclusions` watchlists. Exclusions carry an
  owner, a reason and an expiry date.
- DCSync reports the address of the most recent logon for the session, instead of an
  arbitrary one.
- Test cases can assert the values a rule reports and add watchlist items per case.
  46 cases in total.
- Rule enablement is an ARM template parameter. Added a deploy job that runs after the
  CI checks on `main`, authenticates with OpenID Connect, previews with what-if, and is
  skipped until Azure variables are configured.
- Added engineering notes.

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
