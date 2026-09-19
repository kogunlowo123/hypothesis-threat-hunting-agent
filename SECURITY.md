# Security Policy

## Supported versions

Security fixes are released for the latest minor version on the `main` branch.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Do not open a public issue for security reports. Use GitHub's private vulnerability reporting (the
**Report a vulnerability** button on this repository's **Security** tab) and include a description and
impact, the affected version or commit, and a minimal reproduction. Please remove real telemetry first.
You can expect an acknowledgement within 3 business days and a triage decision within 10 business days.

## Trust boundary

| Input | Trust |
| ----- | ----- |
| Telemetry files | Untrusted. Logs carry attacker-controlled strings such as command lines, domains and user names |
| Configuration files (thresholds, indicators, allowlist, geography, suppressions) | Trusted operator input, parsed safely and validated |
| Model output used for summaries | Untrusted text, accepted only if grounded in supplied counts |

## Security controls

| Threat | Control | Location |
| ------ | ------- | -------- |
| Secrets in logged command lines | Redaction at ingestion, before storage, reports and logs | `security.redact`, `normalizers.py` |
| Malformed or hostile telemetry | Per-line byte limit, total event limit, strict per-format adapters, schema validation | `normalizers.py`, `models.py` |
| Leaky error messages | Rejected lines report a line number and reason, never content. CLI errors are redacted | `normalizers.py`, `cli.py` |
| Code execution through configuration | `yaml.safe_load` only, 2 MB limit, strict models that forbid unknown fields | `config.py` |
| Markup injection into reports | Table cells escaped, evidence shown as sanitised code spans, HTML characters encoded | `security.py`, `reporting.py` |
| Spreadsheet formula injection in CSV | Cells starting with `=`, `+`, `-`, `@`, tab or carriage return get a leading quote | `security.csv_safe` |
| Prompt injection into summaries | The model receives only aggregate counts. Output containing numbers absent from those counts is discarded | `summary.py` |
| Silent, permanent suppression of real findings | Suppressions need a reason and an approver, expire, and expired ones are reported | `models.Suppression`, `engine.py` |
| Over-trusting an allowlist | Allowlisted destinations are configured explicitly and appear in the configuration you review | `config.py` |
| Vulnerable dependencies | `pip-audit`, Dependabot, CodeQL | `.github/` |

## Known limits

- The tool cannot see attacker activity that is not in the telemetry it is given.
- An attacker who can write to the telemetry or the configuration can hide from the hunts. Protect both.
- Reports may contain hostnames, user names and addresses. Handle them like any incident record.
