"""Reporting: Markdown and JSON reports, hunt queries and Sigma rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from huntagent.errors import ReportError
from huntagent.hunts import ALL_HUNTS, Hunt
from huntagent.models import Coverage, HuntReport, Thresholds
from huntagent.security import csv_safe, md_cell, md_code, slugify

FORMATS = ("md", "json")
QUERY_LANGUAGES = ("spl", "kql", "sigma")


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append(
            "| "
            + " | ".join(cell if isinstance(cell, _Code) else md_cell(cell) for cell in row)
            + " |"
        )
    return out


class _Code(str):
    """A pre-rendered inline-code cell."""


def code(value: object) -> _Code:
    return _Code(md_code(value))


def render_markdown(report: HuntReport) -> str:
    """The hunt report: leads first, then findings with their evidence."""
    r = report
    events = {e.id: e for e in r.evidence}
    findings = {f.id: f for f in r.findings}
    out = [
        f"# Threat hunt {r.hunt_start.strftime('%Y-%m-%d %H:%M')} to {r.hunt_end.strftime('%Y-%m-%d %H:%M')} UTC",
        "",
    ]
    if r.summary:
        out += ["## Summary", "", r.summary, ""]

    out += ["## Leads", ""]
    if r.leads:
        out += _table(
            ["Lead", "Score", "Severity", "Title", "Tactics", "Hosts", "Users", "Indicator match"],
            [
                [
                    lead.id,
                    lead.score,
                    lead.severity.value,
                    lead.title,
                    ", ".join(lead.tactics),
                    ", ".join(lead.hosts) or "none",
                    ", ".join(lead.users) or "none",
                    "yes" if lead.ioc_match else "no",
                ]
                for lead in r.leads
            ],
        )
    else:
        out.append("No leads.")

    for lead in r.leads:
        out += ["", f"### {md_cell(lead.id)}: {md_cell(lead.title)}", ""]
        out.append(
            f"Score {lead.score}, {lead.severity.value}. Active {lead.first_seen.strftime('%Y-%m-%d %H:%M')} to {lead.last_seen.strftime('%Y-%m-%d %H:%M')} UTC."
        )
        out += ["", "Next steps:", ""]
        out += [f"- {md_cell(step)}" for step in lead.next_steps]
        for fid in lead.finding_ids:
            f = findings[fid]
            out += [
                "",
                f"**{md_cell(f.id)} {md_cell(f.title)}** ({f.hunt}, score {f.score}, {', '.join(f.techniques)})",
                "",
                md_cell(f.explanation),
                "",
            ]
            if f.benign_causes:
                out += [
                    "Possible benign causes: "
                    + "; ".join(md_cell(c) for c in f.benign_causes)
                    + ".",
                    "",
                ]
            shown = [events[i] for i in f.event_ids[:12] if i in events]
            if shown:
                out += _table(
                    ["Time (UTC)", "Kind", "Host", "User", "Event"],
                    [
                        [e.time.strftime("%H:%M:%S"), e.kind, e.host, e.user, code(e.summary)]
                        for e in shown
                    ],
                )
                if len(f.event_ids) > len(shown):
                    out += [
                        "",
                        f"{len(f.event_ids) - len(shown)} more event(s) in the JSON report.",
                    ]

    out += ["", "## Data", ""]
    out += _table(
        ["Kind", "Events in window"], [[k, v] for k, v in r.kinds.items()] or [["none", 0]]
    )
    out += ["", f"Baseline: {r.events_baseline:,} events. Hunt window: {r.events_hunted:,} events."]
    if r.skipped_hunts:
        out += ["", "## Hunts that did not run", ""] + [f"- {md_cell(s)}" for s in r.skipped_hunts]
    if r.suppressed:
        out += ["", f"{r.suppressed} finding(s) were suppressed by reviewed rules."]
    if r.expired_suppressions:
        out += ["", "## Expired suppressions", ""]
        out += _table(
            ["Hunt", "Entity", "Value", "Approved by", "Expired"],
            [
                [s.hunt, s.entity, s.value, s.approved_by, s.expires.isoformat()]
                for s in r.expired_suppressions
            ],
        )
    if r.warnings:
        out += ["", "## Warnings", ""] + [f"- {md_cell(w)}" for w in r.warnings]
    return "\n".join(out) + "\n"


def render_json(report: HuntReport) -> str:
    return report.model_dump_json(indent=2)


def render_findings_csv(report: HuntReport) -> str:
    """One row per finding, with spreadsheet formulas neutralised."""
    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "id",
            "hunt",
            "severity",
            "score",
            "title",
            "tactic",
            "techniques",
            "hosts",
            "users",
            "ips",
            "first_seen",
            "last_seen",
        ]
    )
    for f in report.findings:
        writer.writerow(
            [
                csv_safe(v)
                for v in (
                    f.id,
                    f.hunt,
                    f.severity.value,
                    f.score,
                    f.title,
                    f.tactic,
                    " ".join(f.techniques),
                    " ".join(f.hosts),
                    " ".join(f.users),
                    " ".join(f.ips),
                    f.first_seen.isoformat(),
                    f.last_seen.isoformat(),
                )
            ]
        )
    return buffer.getvalue()


def render_coverage(coverage: Coverage) -> str:
    """A text table of which hunts can run with the data present."""
    lines = [
        "Data present: "
        + (
            ", ".join(f"{k} ({v})" for k, v in sorted(coverage.kinds_present.items()) if v)
            or "none"
        )
    ]
    lines.append(f"{'hunt':<18} {'tactic':<22} {'runs':<5} techniques")
    for row in coverage.rows:
        note = "" if row.runnable else f"  (needs {', '.join(row.missing)})"
        lines.append(
            f"{row.hunt:<18} {row.tactic:<22} {'yes' if row.runnable else 'no':<5} {', '.join(row.techniques)}{note}"
        )
    if coverage.blind_techniques:
        lines.append("Blind techniques: " + ", ".join(coverage.blind_techniques))
    return "\n".join(lines)


def render_query(hunt: Hunt, language: str, thresholds: Thresholds) -> str:
    """The hunt as an SPL search, a KQL query or Sigma rules (YAML documents)."""
    if language == "spl":
        return hunt.spl(thresholds)
    if language == "kql":
        return hunt.kql(thresholds)
    if language == "sigma":
        rules = hunt.sigma(thresholds)
        if not rules:
            raise ReportError(
                f"{hunt.id} is a statistical hunt and has no Sigma rule; use spl or kql"
            )
        return "---\n".join(yaml.safe_dump(rule, sort_keys=False) for rule in rules)
    raise ReportError(
        f"unknown query language {language!r}; choose from {', '.join(QUERY_LANGUAGES)}"
    )


def write_report(
    report: HuntReport,
    out_dir: Path,
    thresholds: Thresholds,
    formats: list[str],
    *,
    with_rules: bool = True,
) -> list[Path]:
    """Write reports, and detection content for every hunt that produced findings."""
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise ReportError(f"unknown format {unknown[0]!r}; choose from {', '.join(FORMATS)}")
    renderers = {"md": render_markdown, "json": render_json}
    paths: list[Path] = []
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for fmt in formats:
            path = out_dir / f"hunt-report.{fmt}"
            path.write_text(renderers[fmt](report), encoding="utf-8")
            paths.append(path)
        (out_dir / "findings.csv").write_text(render_findings_csv(report), encoding="utf-8")
        paths.append(out_dir / "findings.csv")
        if with_rules:
            active = {f.hunt for f in report.findings}
            for hunt in ALL_HUNTS:
                if hunt.id not in active:
                    continue
                queries = out_dir / "queries"
                queries.mkdir(exist_ok=True)
                for language, suffix in (("spl", "spl"), ("kql", "kql")):
                    path = queries / f"{slugify(hunt.id)}.{suffix}"
                    path.write_text(
                        render_query(hunt, language, thresholds) + "\n", encoding="utf-8"
                    )
                    paths.append(path)
                if hunt.sigma(thresholds):
                    rules = out_dir / "sigma"
                    rules.mkdir(exist_ok=True)
                    path = rules / f"{slugify(hunt.id)}.yml"
                    path.write_text(render_query(hunt, "sigma", thresholds), encoding="utf-8")
                    paths.append(path)
    except OSError as exc:
        raise ReportError(f"cannot write to {out_dir}: {exc}") from exc
    return paths
