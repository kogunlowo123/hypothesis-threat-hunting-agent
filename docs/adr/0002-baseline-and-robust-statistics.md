# ADR 0002: Learn a baseline and use robust statistics

- Status: Accepted
- Date: 2026-09-19

## Context

Many suspicious behaviours are only suspicious relative to normal: a new destination, a much larger upload, a
program that never ran here before. A mean and standard deviation are easily distorted by the very outliers a
hunt is looking for.

## Decision

Events before the hunt window form a baseline of sets (processes per host, destinations per host, hosts per
user, countries per user) and small samples (daily outbound bytes per host). Volume anomalies use the median and
the median absolute deviation. Because a very steady baseline makes that score explode, an exfiltration finding
based only on volume also needs the day to be at least double the median.

## Consequences

- Outliers in the baseline do not hide a real outlier.
- A hunt that needs a baseline says so and is skipped when there is none, rather than reporting everything as new.
- A short baseline weakens the statistical hunts, and the report warns below three days.
