"""Command-line interface ``huntagent``.

Exit codes: 0 success, 1 a gate failed (``--fail-on-lead``), 2 invalid input or a runtime error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from huntagent.config import HuntConfig, Settings, load_config
from huntagent.container import build_service
from huntagent.errors import HuntError
from huntagent.hunts import ALL_HUNTS, hunt_by_id
from huntagent.logging_setup import configure_logging
from huntagent.models import Severity
from huntagent.normalizers import NORMALIZERS
from huntagent.reporting import (
    FORMATS,
    QUERY_LANGUAGES,
    render_coverage,
    render_json,
    render_markdown,
    render_query,
    write_report,
)
from huntagent.security import redact
from huntagent.service import HuntService, parse_duration
from huntagent.simulate import simulate, write_records

_SEVERITIES = [s.value for s in Severity]


def _parse_time(text: str) -> datetime:
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HuntError(f"invalid timestamp {text!r}; use ISO 8601") from exc
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _input(text: str) -> tuple[str, Path]:
    source, sep, path = text.partition("=")
    if not sep or source not in NORMALIZERS:
        raise argparse.ArgumentTypeError(
            f"use FORMAT=PATH with FORMAT one of: {', '.join(sorted(NORMALIZERS))}"
        )
    return source, Path(path)


def _add_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--thresholds", type=Path, help="thresholds YAML (default: HUNTAGENT_THRESHOLDS_FILE)"
    )
    parser.add_argument("--iocs", type=Path, help="threat intelligence indicators")
    parser.add_argument(
        "--allowlist", type=Path, help="known-benign destinations, scanners and processes"
    )
    parser.add_argument(
        "--geo", type=Path, help="address ranges and countries, for impossible travel"
    )
    parser.add_argument("--suppressions", type=Path, help="reviewed, time-limited suppressions")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="huntagent", description="Threat hunting agent")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("hunts", help="list the hunts")

    sim = sub.add_parser(
        "simulate", help="write synthetic telemetry: a normal week, then a hunt day with attacks"
    )
    sim.add_argument("--out", type=Path, required=True)
    sim.add_argument("--start", help="ISO date of the hunt day (default: yesterday)")
    sim.add_argument("--seed", type=int, default=7)

    hunt = sub.add_parser("hunt", help="run hunts over telemetry")
    hunt.add_argument(
        "--input",
        "-i",
        type=_input,
        action="append",
        required=True,
        metavar="FORMAT=PATH",
        help="telemetry file; repeat for several",
    )
    _add_config(hunt)
    hunt.add_argument("--window", default="24h", help="hunt window length, for example 12h or 2d")
    hunt.add_argument(
        "--hunt-start",
        help="ISO start of the hunt window (default: window ending at the newest event)",
    )
    hunt.add_argument(
        "--baseline-days", type=int, help="limit the baseline to this many days before the window"
    )
    hunt.add_argument(
        "--only", action="append", metavar="HUNT", help="run only this hunt; repeat for several"
    )
    hunt.add_argument(
        "--out", type=Path, help="write the report, findings CSV, queries and Sigma rules here"
    )
    hunt.add_argument("--format", default="md,json", help=f"comma list from: {', '.join(FORMATS)}")
    hunt.add_argument(
        "--fail-on-lead", choices=_SEVERITIES, help="exit 1 if a lead is at least this severe"
    )

    coverage = sub.add_parser("coverage", help="show which hunts can run with the data you have")
    coverage.add_argument("--input", "-i", type=_input, action="append", metavar="FORMAT=PATH")
    coverage.add_argument(
        "--kinds",
        help="comma list of data kinds you have instead of files: process,auth,dns,flow,cloud",
    )

    query = sub.add_parser(
        "query", help="print a hunt as an SPL search, a KQL query or Sigma rules"
    )
    query.add_argument("hunt")
    query.add_argument("--lang", choices=list(QUERY_LANGUAGES), default="spl")
    query.add_argument("--thresholds", type=Path)
    return parser


def _cmd_hunts() -> int:
    print(f"{'id':<18} {'tactic':<22} {'needs':<9} techniques")
    for hunt in ALL_HUNTS:
        print(
            f"{hunt.id:<18} {hunt.tactic:<22} {','.join(hunt.required):<9} {', '.join(hunt.techniques)}"
        )
    return 0


def _config(args: argparse.Namespace, settings: Settings) -> HuntConfig:
    return load_config(
        thresholds_file=args.thresholds or settings.thresholds_file,
        iocs_file=getattr(args, "iocs", None) or settings.iocs_file,
        allowlist_file=getattr(args, "allowlist", None) or settings.allowlist_file,
        geo_file=getattr(args, "geo", None) or settings.geo_file,
        suppressions_file=getattr(args, "suppressions", None) or settings.suppressions_file,
    )


def _cmd_hunt(args: argparse.Namespace, settings: Settings, service: HuntService) -> int:
    config = _config(args, settings)
    events, reports = service.load(args.input)
    for ingest in reports:
        note = f", {ingest.rejected} rejected" if ingest.rejected else ""
        print(f"loaded {ingest.accepted} {ingest.source} events{note}", file=sys.stderr)
    report = service.hunt(
        events,
        config,
        window=parse_duration(args.window),
        hunt_start=_parse_time(args.hunt_start) if args.hunt_start else None,
        baseline_days=args.baseline_days,
        only=args.only,
    )
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    if args.out:
        for path in write_report(report, args.out, config.thresholds, formats):
            print(f"wrote {path}")
        print(report.summary)
    else:
        print(render_json(report) if formats == ["json"] else render_markdown(report))
    if args.fail_on_lead:
        floor = Severity(args.fail_on_lead).rank
        if any(lead.severity.rank >= floor for lead in report.leads):
            return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        if args.command == "hunts":
            return _cmd_hunts()
        settings = Settings()
        configure_logging(settings.log_level, json_output=settings.log_json)
        if args.command == "simulate":
            day = (
                _parse_time(args.start)
                if args.start
                else datetime.now(timezone.utc) - parse_duration("1d")
            )
            for path in write_records(simulate(start=day, seed=args.seed), args.out):
                print(f"wrote {path}")
            return 0
        if args.command == "query":
            hunt = hunt_by_id(args.hunt)
            if hunt is None:
                raise HuntError(f"unknown hunt {args.hunt!r}; run 'huntagent hunts' for the list")
            thresholds = load_config(
                thresholds_file=args.thresholds or settings.thresholds_file
            ).thresholds
            print(render_query(hunt, args.lang, thresholds))
            return 0
        service = build_service(settings)
        if args.command == "coverage":
            if args.input:
                events, _ = service.load(args.input)
                print(render_coverage(service.coverage(events)))
            else:
                kinds = {k.strip(): 1 for k in (args.kinds or "").split(",") if k.strip()}
                print(render_coverage(service.engine.coverage(kinds)))
            return 0
        return _cmd_hunt(args, settings, service)
    except (HuntError, ValidationError) as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
