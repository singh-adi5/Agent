# Security policy

## Reporting

Report a committed secret, or a detection flaw that would mislead a defender, through
GitHub private vulnerability reporting: **Security > Report a vulnerability** on this
repository. Do not open a public issue for a committed secret.

## Authorised use

The detection READMEs name public offensive tools (Impacket, Rubeus, Kerbrute,
Mimikatz) that generate the telemetry each detection is validated against. Use them
only in a lab you own and built for the purpose. Using them against any system
without written authorisation is an offence in most jurisdictions, including under
the UK Computer Misuse Act 1990.

## Content rules

The repository must never contain:

- tenant, subscription or workspace identifiers, keys, passwords or tokens;
- hashes, tickets or other credential material, including from a disposable lab;
- screenshots showing any of the above.

Examples use placeholders such as `<WORKSPACE_NAME>`. `.gitignore` blocks key, ticket
and hash files and local copies of deployment files.

## Supply chain

- GitHub Actions are pinned to commit SHAs; the Kusto emulator image to a digest.
- Workflows run with a read-only token, hold no secrets and do not persist checkout
  credentials. The deploy job alone may request an OpenID Connect token, exchanged for
  short-lived Azure access scoped to one resource group.
- Python dependencies install with `--require-hashes`. npm installs from the lockfile
  with install scripts disabled.
- Dependabot raises updates for actions, pip and npm.
