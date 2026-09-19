# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [Unreleased]

## [0.1.0]

### Added

- Adapters for Sysmon, authentication, DNS, flow, CloudTrail-style and generic JSON Lines telemetry.
- Baseline learned from events before the hunt window.
- Eleven hunts: beaconing, DNS tunnelling, DGA, exfiltration, password attacks, impossible travel, lateral
  fan-out, process chains, persistence, rare processes and risky cloud activity.
- Allowlists, threat-intelligence matching, geography and reviewed, expiring suppressions.
- Correlation of findings into ranked leads with next steps.
- Markdown, JSON and CSV reports, plus SPL, KQL and Sigma output for each hunt.
- Coverage view of which hunts can run with the data available.
- Deterministic simulator with a planted intrusion and benign look-alikes.
- Optional model-written summary that only sees aggregate counts, command-line interface, Docker image and CI
  workflows.
