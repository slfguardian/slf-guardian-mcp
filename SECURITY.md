# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to `team@slfguardian.com`. Do not open a public issue for an unpatched security problem. Include the affected version, a minimal reproduction, impact, and whether any user data was accessed. We will acknowledge reports as soon as practical and coordinate disclosure with the reporter.

Do not test SLF Guardian infrastructure beyond the documented API behavior, do not submit real secrets, and do not perform denial-of-service, credential attacks, or high-volume probing.

## Data handling

The API is designed to analyze submitted content in memory. Source code is not retained for product operation; operational records contain request metadata and aggregate result counts. Do not submit production credentials, private keys, personal data, or customer secrets in examples or issue reports.

## Scope and limitations

SLF Guardian is static/passive analysis, not malware detonation or a guarantee of safety. A `pass` result means no known pattern matched. Integrators remain responsible for approval and enforcement before an agent takes an action.
