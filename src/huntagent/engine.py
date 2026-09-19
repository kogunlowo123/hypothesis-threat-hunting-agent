"""Hunt engine: split events into baseline and hunt window, run hunts, suppress, correlate."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from huntagent.baseline import Baseline
from huntagent.config import HuntConfig
from huntagent.correlate import build_leads
from huntagent.errors import HuntError
from huntagent.hunts import ALL_HUNTS, Hunt
from huntagent.hunts.base import HuntContext
from huntagent.logging_setup import get_logger
from huntagent.models import (
    Coverage,
    CoverageRow,
    Event,
    EventKind,
    EvidenceEvent,
    Finding,
    HuntReport,
    Suppression,
)
from huntagent.summary import SummaryWriter, facts_for

_log = get_logger("engine")
MIN_BASELINE_DAYS = 3
_KINDS: tuple[EventKind, ...] = ("process", "auth", "dns", "flow", "cloud")


class HuntEngine:
    """Runs a set of hunts over a window of events."""

    def __init__(self, summary_writer: SummaryWriter, hunts: Sequence[Hunt] = ALL_HUNTS) -> None:
        self._hunts = tuple(hunts)
        self._summary = summary_writer

    @property
    def hunts(self) -> tuple[Hunt, ...]:
        return self._hunts

    def hunt(
        self,
        events: Iterable[Event],
        config: HuntConfig,
        *,
        hunt_start: datetime,
        hunt_end: datetime,
        baseline_start: datetime | None = None,
        only: Sequence[str] | None = None,
    ) -> HuntReport:
        """Hunt in ``[hunt_start, hunt_end)`` using events before ``hunt_start`` as the baseline.

        Raises:
            HuntError: If the window is empty or an unknown hunt id is requested.
        """
        if hunt_end <= hunt_start:
            raise HuntError("the hunt window must end after it starts")
        selected = self._select(only)
        window: list[Event] = []
        history: list[Event] = []
        for e in events:
            if hunt_start <= e.time < hunt_end:
                window.append(e)
            elif e.time < hunt_start and (baseline_start is None or e.time >= baseline_start):
                history.append(e)

        baseline = Baseline.build(history, config)
        ctx = HuntContext(window, baseline, config)
        present = {kind for kind in _KINDS if ctx.by_kind(kind)}

        findings: list[Finding] = []
        skipped: list[str] = []
        for hunt in selected:
            missing = [k for k in hunt.required if k not in present]
            if missing:
                skipped.append(f"{hunt.id}: no {', '.join(missing)} events in the hunt window")
                continue
            reason = hunt.unavailable(ctx)
            if reason:
                skipped.append(f"{hunt.id}: {reason}")
                continue
            found = hunt.run(ctx)
            _log.info("hunt finished", extra={"hunt": hunt.id, "findings": len(found)})
            findings.extend(found)

        kept, suppressed, expired = self._suppress(findings, config.suppressions, hunt_end)
        kept.sort(key=lambda f: (-f.score, f.id))
        warnings = self._warnings(window, baseline, config)
        report = HuntReport(
            hunt_start=hunt_start,
            hunt_end=hunt_end,
            baseline_start=baseline_start,
            events_hunted=len(window),
            events_baseline=len(history),
            kinds={k: len(ctx.by_kind(k)) for k in sorted(present)},
            findings=kept,
            leads=build_leads(kept, config.thresholds),
            evidence=self._evidence(window, kept),
            suppressed=suppressed,
            expired_suppressions=expired,
            skipped_hunts=skipped,
            warnings=warnings,
        )
        return report.model_copy(
            update={"summary": self._summary.write(facts_for(report, len(selected)))}
        )

    def coverage(self, kinds_present: dict[str, int]) -> Coverage:
        """Which hunts can run with the data kinds present, and which techniques are therefore blind."""
        rows: list[CoverageRow] = []
        for hunt in self._hunts:
            missing = [k for k in hunt.required if not kinds_present.get(k)]
            rows.append(
                CoverageRow(
                    hunt=hunt.id,
                    name=hunt.name,
                    tactic=hunt.tactic,
                    techniques=list(hunt.techniques),
                    required=list(hunt.required),
                    missing=missing,
                    runnable=not missing,
                )
            )
        covered = sorted({t for r in rows if r.runnable for t in r.techniques})
        blind = sorted({t for r in rows if not r.runnable for t in r.techniques} - set(covered))
        return Coverage(
            kinds_present=kinds_present,
            rows=rows,
            blind_techniques=blind,
            covered_techniques=covered,
        )

    def _select(self, only: Sequence[str] | None) -> tuple[Hunt, ...]:
        if not only:
            return self._hunts
        known = {h.id: h for h in self._hunts}
        unknown = [i for i in only if i not in known]
        if unknown:
            raise HuntError(f"unknown hunt {unknown[0]!r}; choose from {', '.join(sorted(known))}")
        return tuple(known[i] for i in dict.fromkeys(only))

    @staticmethod
    def _evidence(window: list[Event], findings: list[Finding]) -> list[EvidenceEvent]:
        wanted = {i for f in findings for i in f.event_ids}
        return [
            EvidenceEvent(
                id=e.id, time=e.time, kind=e.kind, host=e.host, user=e.user, summary=e.describe()
            )
            for e in sorted(window, key=lambda e: (e.time, e.id))
            if e.id in wanted
        ]

    @staticmethod
    def _suppress(
        findings: list[Finding], rules: Sequence[Suppression], on: datetime
    ) -> tuple[list[Finding], int, list[Suppression]]:
        today = on.date()
        active = [r for r in rules if r.expires >= today]
        expired = [r for r in rules if r.expires < today]
        kept: list[Finding] = []
        suppressed = 0
        for finding in findings:
            entities = finding.entities()
            if any(
                r.hunt in (finding.hunt, "*") and f"{r.entity}:{r.value.lower()}" in entities
                for r in active
            ):
                suppressed += 1
            else:
                kept.append(finding)
        return kept, suppressed, expired

    @staticmethod
    def _warnings(window: list[Event], baseline: Baseline, config: HuntConfig) -> list[str]:
        warnings: list[str] = []
        if not window:
            warnings.append("there are no events in the hunt window")
        if baseline.days < MIN_BASELINE_DAYS:
            warnings.append(
                f"the baseline covers {baseline.days} day(s); statistical hunts are more reliable with at least {MIN_BASELINE_DAYS}"
            )
        if not config.ioc_ips and not config.ioc_domains and not config.ioc_hashes:
            warnings.append(
                "no threat intelligence indicators are configured, so no finding can be matched to one"
            )
        return warnings
