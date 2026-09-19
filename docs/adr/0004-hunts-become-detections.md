# ADR 0004: Every hunt can become a detection

- Status: Accepted
- Date: 2026-09-19

## Context

A hunt that finds something once is worth much more if the same logic keeps running. Rewriting a finding as a
detection by hand loses detail and takes time.

## Decision

Every hunt renders its logic as a Splunk search and a Kusto query with the configured thresholds filled in.
Pattern-based hunts also produce Sigma rules from the same rule table that drives the hunt. Statistical hunts do
not, because Sigma cannot express them, and the tool says so. Output is written only for hunts that produced
findings.

## Consequences

- Detection content cannot drift from the hunt that produced it.
- The generated queries are starting points. Field names and schemas differ between products and must be
  checked before deployment.
- Adding a process rule updates detection and Sigma output together.
