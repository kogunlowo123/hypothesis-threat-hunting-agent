"""Application service: load telemetry, hunt, and report coverage."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path

from huntagent.config import HuntConfig, Settings
from huntagent.engine import HuntEngine
from huntagent.errors import HuntError, TelemetryError
from huntagent.models import Coverage, Event, HuntReport, IngestReport
from huntagent.normalizers import NORMALIZERS, normalize_lines

_DURATION_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_duration(text: str) -> timedelta:
    """Parse ``90m``, ``24h`` or ``7d`` into a timedelta."""
    if (
        len(text) < 2
        or text[-1] not in _DURATION_UNITS
        or not text[:-1].isdigit()
        or int(text[:-1]) == 0
    ):
        raise HuntError(f"invalid duration {text!r}; use forms like 90m, 24h, 7d")
    return timedelta(**{_DURATION_UNITS[text[-1]]: int(text[:-1])})


class HuntService:
    """Facade used by the CLI and library callers."""

    def __init__(self, engine: HuntEngine, settings: Settings) -> None:
        self._engine = engine
        self._settings = settings

    @property
    def engine(self) -> HuntEngine:
        return self._engine

    def load(self, inputs: Sequence[tuple[str, Path]]) -> tuple[list[Event], list[IngestReport]]:
        """Read telemetry files. Each input is a source format and a JSON Lines path.

        Raises:
            TelemetryError: If a file cannot be read or a format is unknown.
        """
        events: list[Event] = []
        reports: list[IngestReport] = []
        seen: set[str] = set()
        for source, _ in inputs:
            if source not in NORMALIZERS:
                raise TelemetryError(
                    f"unknown source format {source!r}; choose from {', '.join(sorted(NORMALIZERS))}"
                )
        for source, path in inputs:
            try:
                with path.open(encoding="utf-8", errors="replace") as handle:
                    batch, report = normalize_lines(
                        handle,
                        source,
                        max_line_bytes=self._settings.max_line_bytes,
                        max_events=self._settings.max_events,
                    )
            except OSError as exc:
                raise TelemetryError(f"cannot read {path.name}: {exc.strerror or exc}") from exc
            reports.append(report)
            for event in batch:
                if event.id not in seen:
                    seen.add(event.id)
                    events.append(event)
        return events, reports

    def hunt(
        self,
        events: list[Event],
        config: HuntConfig,
        *,
        window: timedelta = timedelta(hours=24),
        hunt_start: datetime | None = None,
        baseline_days: int | None = None,
        only: Sequence[str] | None = None,
    ) -> HuntReport:
        """Hunt in a window. Without ``hunt_start`` the window ends just after the newest event.

        Raises:
            HuntError: If there are no events or the options are inconsistent.
        """
        if not events:
            raise HuntError("no events were loaded")
        if hunt_start is None:
            end = max(e.time for e in events) + timedelta(seconds=1)
            start = end - window
        else:
            start = hunt_start if hunt_start.tzinfo else hunt_start.replace(tzinfo=timezone.utc)
            end = start + window
        baseline_start = start - timedelta(days=baseline_days) if baseline_days else None
        return self._engine.hunt(
            events, config, hunt_start=start, hunt_end=end, baseline_start=baseline_start, only=only
        )

    def coverage(self, events: list[Event]) -> Coverage:
        kinds: dict[str, int] = {}
        for e in events:
            kinds[e.kind] = kinds.get(e.kind, 0) + 1
        return self._engine.coverage(kinds)
