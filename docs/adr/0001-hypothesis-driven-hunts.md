# ADR 0001: Hunts are explicit hypotheses with explained results

- Status: Accepted
- Date: 2026-09-19

## Context

Anomaly scores that cannot be explained are hard to act on. A hunter needs to know what pattern was seen, why it
might matter, and what harmless thing might look the same, so the next question is obvious.

## Decision

Each hunt encodes one hypothesis (for example, regular connections to a new external address suggest a beacon).
It returns findings with the numbers behind the decision, a plain explanation, the technique it maps to, benign
explanations, and the events involved. Thresholds are named settings, and every formula is in the source.

## Consequences

- An analyst can see why something fired and how to tell it from a benign cause.
- Hunts only find what they were written to find. Coverage is stated in the `coverage` command.
- Tuning is a configuration change, not a retraining exercise.
