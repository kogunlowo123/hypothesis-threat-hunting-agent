# ADR 0003: Correlate into leads without over-merging

- Status: Accepted
- Date: 2026-09-19

## Context

An intrusion produces findings from several hunts. Analysts want them together. Merging on every shared name
does the opposite of helping: a password spray that lists twelve accounts would join every incident that involves
one of those accounts, and one hub host would join everything.

## Decision

Findings link on shared hosts, users, addresses and domains within a time window. A finding that names many
users (more than 3), hosts (more than 10) or addresses (more than 5) does not link through that list. Sign-in
target hosts such as a VPN gateway are not reported as affected hosts. Known noisy entities are handled by the
allowlist and noisy-user list rather than by a degree cap, because a host with many findings is usually the
compromised one.

## Consequences

- A whole intrusion collapses into one lead, while unrelated campaigns stay separate.
- A spray that hits a victim's account is a separate lead, with a next step to check for a successful sign-in.
- The limits are constants in `correlate.py` and are easy to change.
