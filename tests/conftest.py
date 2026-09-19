"""Shared fixtures and builders."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from huntagent.baseline import Baseline
from huntagent.config import HuntConfig, Settings
from huntagent.container import build_service
from huntagent.hunts.base import HuntContext
from huntagent.models import Event, EventKind
from huntagent.providers.http import JsonClient
from huntagent.service import HuntService

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIGS = REPO_ROOT / "configs"
HUNT_DAY = datetime(2026, 9, 18, tzinfo=timezone.utc)
T0 = HUNT_DAY + timedelta(hours=10)
_counter = 0


def ev(
    kind: EventKind, minutes: float = 0, *, seconds: float = 0, base: datetime = T0, **fields: Any
) -> Event:
    """A normalized event at ``base + minutes``. Each call gets a unique id."""
    global _counter
    _counter += 1
    return Event(
        id=f"t{_counter}",
        time=base + timedelta(minutes=minutes, seconds=seconds),
        kind=kind,
        **fields,
    )


def make_ctx(
    events: Sequence[Event],
    *,
    baseline: Sequence[Event] = (),
    config: HuntConfig | None = None,
) -> HuntContext:
    cfg = config or HuntConfig()
    return HuntContext(list(events), Baseline.build(list(baseline), cfg), cfg)


def make_settings(**overrides: object) -> Settings:
    """Settings that ignore the developer's environment."""
    base: dict[str, object] = {
        "retry_min_wait": 0.0,
        "retry_max_wait": 0.0,
        "log_level": "CRITICAL",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def make_service(**overrides: object) -> HuntService:
    return build_service(make_settings(**overrides))


def json_client(
    handler: Callable[[httpx.Request], httpx.Response], attempts: int = 2
) -> JsonClient:
    """A JsonClient backed by an in-process mock transport."""
    return JsonClient(
        httpx.Client(transport=httpx.MockTransport(handler)),
        attempts=attempts,
        min_wait=0.0,
        max_wait=0.0,
    )
