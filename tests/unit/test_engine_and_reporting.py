"""Unit tests for correlation, the engine, reports and summaries."""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from huntagent.config import HuntConfig
from huntagent.correlate import PIVOTS, build_leads, linkable_entities
from huntagent.engine import HuntEngine
from huntagent.errors import HuntError, ProviderError, ReportError
from huntagent.hunts import ALL_HUNTS, hunt_by_id
from huntagent.hunts.base import make_finding
from huntagent.models import Finding, Severity, Suppression, Thresholds
from huntagent.reporting import (
    render_coverage,
    render_findings_csv,
    render_json,
    render_markdown,
    render_query,
    write_report,
)
from huntagent.summary import LLMSummaryWriter, SummaryFacts, TemplateSummaryWriter, facts_for
from tests.conftest import HUNT_DAY, ev

END = HUNT_DAY + timedelta(days=1)
TEMPLATE = TemplateSummaryWriter()


def finding(
    hunt: str = "beaconing",
    score: int = 70,
    tactic: str = "Command and Control",
    minutes: float = 0,
    **entities: Any,
) -> Finding:
    e = ev("flow", minutes, host=(entities.get("hosts") or ["h"])[0], dst_ip="203.0.113.5")
    return make_finding(
        hunt,
        f"{hunt} {minutes} {entities}",
        [e],
        score=score,
        tactic=tactic,
        techniques=["T1"],
        explanation="x",
        config=HuntConfig(),
        **entities,
    )


class TestLeads:
    def test_shared_host_links_and_tactics_add_a_bonus(self) -> None:
        a = finding("beaconing", 80, "Command and Control", 0, hosts=["ws-1"])
        b = finding("process_chains", 70, "Execution", 30, hosts=["ws-1"])
        leads = build_leads([a, b], Thresholds())
        assert (
            len(leads) == 1
            and leads[0].score == 85
            and leads[0].tactics == ["Execution", "Command and Control"]
        )
        assert leads[0].finding_ids == [a.id, b.id] and leads[0].title.endswith(
            "(and 1 related finding)"
        )

    def test_unrelated_findings_stay_separate_and_rank_by_score(self) -> None:
        leads = build_leads(
            [finding(score=50, hosts=["a"]), finding("dga", 90, hosts=["b"])], Thresholds()
        )
        assert [lead.score for lead in leads] == [90, 50]

    def test_window_limits_linking(self) -> None:
        far = finding(minutes=60 * 30, hosts=["ws-1"])
        assert len(build_leads([finding(hosts=["ws-1"]), far], Thresholds())) == 2
        assert (
            len(build_leads([finding(hosts=["ws-1"]), far], Thresholds(lead_window_hours=48))) == 1
        )

    def test_broad_findings_do_not_link_through_their_user_lists(self) -> None:
        spray = finding(
            "password_attacks", 88, "Credential Access", users=[f"u{n}" for n in range(12)]
        )
        victim = finding("process_chains", 80, "Execution", 5, hosts=["ws-4"], users=["u4"])
        assert len(build_leads([spray, victim], Thresholds())) == 2
        assert "user:u4" not in linkable_entities(spray) and "user:u4" in linkable_entities(victim)

    def test_shared_ip_and_domain_link(self) -> None:
        a = finding("beaconing", 80, hosts=["a"], ips=["203.0.113.66"])
        b = finding("exfiltration", 70, "Exfiltration", 5, hosts=["b"], ips=["203.0.113.66"])
        c = finding("dns_tunnel", 60, hosts=["c"], domains=["x.example"])
        d = finding("dga", 50, hosts=["d"], domains=["x.example"])
        assert sorted(
            len(lead.finding_ids) for lead in build_leads([a, b, c, d], Thresholds())
        ) == [2, 2]

    def test_ioc_flag_severity_next_steps_and_ids(self) -> None:
        f = finding("beaconing", 84, "Command and Control", hosts=["h"])
        hit = make_finding(
            "exfiltration",
            "t",
            [ev("flow", 1, host="h", dst_ip="203.0.113.66")],
            score=60,
            tactic="Exfiltration",
            techniques=["T1"],
            explanation="x",
            config=replace(HuntConfig(), ioc_ips=frozenset({"203.0.113.66"})),
            hosts=["h"],
            ips=["203.0.113.66"],
        )
        lead = build_leads([f, hit], Thresholds())[0]
        assert lead.ioc_match and lead.severity is Severity.CRITICAL and lead.score == 89
        assert lead.next_steps == [
            PIVOTS["beaconing"],
            PIVOTS["exfiltration"],
        ] and lead.id.startswith("L-")
        assert lead.id == build_leads([hit, f], Thresholds())[0].id

    def test_empty(self) -> None:
        assert build_leads([], Thresholds()) == []

    def test_every_hunt_has_a_pivot(self) -> None:
        assert {h.id for h in ALL_HUNTS} <= set(PIVOTS)


def flows(
    n: int = 20, host: str = "ws-1", start: datetime = HUNT_DAY + timedelta(hours=8)
) -> list[Any]:
    return [
        ev(
            "flow",
            0,
            base=start,
            seconds=i * 60,
            host=host,
            dst_ip="203.0.113.66",
            dst_port=443,
            bytes_out=400,
        )
        for i in range(n)
    ]


class TestEngine:
    def engine(self) -> HuntEngine:
        return HuntEngine(TEMPLATE)

    def test_window_split_and_report_counts(self) -> None:
        history = [
            ev(
                "flow",
                0,
                base=HUNT_DAY - timedelta(days=d),
                host="ws-1",
                dst_ip="192.0.2.1",
                bytes_out=5,
            )
            for d in range(1, 5)
        ]
        after = [ev("flow", 0, base=END + timedelta(hours=1), host="ws-1", dst_ip="192.0.2.1")]
        report = self.engine().hunt(
            history + flows() + after, HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END
        )
        assert (report.events_hunted, report.events_baseline) == (20, 4) and report.kinds == {
            "flow": 20
        }
        assert (
            len(report.findings) == 1
            and report.findings[0].hunt == "beaconing"
            and len(report.leads) == 1
            and report.evidence
        )
        assert "Hunted 20 events against a baseline of 4" in report.summary

    def test_baseline_start_limits_history(self) -> None:
        history = [
            ev("flow", 0, base=HUNT_DAY - timedelta(days=d), host="ws-1", dst_ip="192.0.2.1")
            for d in (1, 10)
        ]
        report = self.engine().hunt(
            history + flows(),
            HuntConfig(),
            hunt_start=HUNT_DAY,
            hunt_end=END,
            baseline_start=HUNT_DAY - timedelta(days=5),
        )
        assert report.events_baseline == 1

    def test_hunts_without_their_data_are_skipped_with_a_reason(self) -> None:
        report = self.engine().hunt(flows(), HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END)
        skipped = dict(s.split(": ", 1) for s in report.skipped_hunts)
        assert (
            "no dns events" in skipped["dns_tunnel"]
            and "no process events" in skipped["process_chains"]
            and "beaconing" not in skipped
        )
        assert len(skipped) == 9

    def test_config_dependent_hunts_explain_why_they_did_not_run(self) -> None:
        events = [
            ev("auth", 0, host="v", user="a", src_ip="192.0.2.1", outcome="success"),
            ev("process", 0, host="h", process="a.exe"),
        ]
        report = self.engine().hunt(events, HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END)
        text = " ".join(report.skipped_hunts)
        assert (
            "impossible_travel: no geography file" in text
            and "rare_process: no baseline process data" in text
        )

    def test_only_selects_and_validates_hunt_ids(self) -> None:
        report = self.engine().hunt(
            flows(),
            HuntConfig(),
            hunt_start=HUNT_DAY,
            hunt_end=END,
            only=["beaconing", "beaconing"],
        )
        assert report.skipped_hunts == [] and len(report.findings) == 1
        with pytest.raises(HuntError, match="unknown hunt 'nope'"):
            self.engine().hunt(
                flows(), HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END, only=["nope"]
            )

    def test_invalid_window(self) -> None:
        with pytest.raises(HuntError, match="end after"):
            self.engine().hunt(flows(), HuntConfig(), hunt_start=END, hunt_end=HUNT_DAY)

    def test_suppressions_apply_until_they_expire(self) -> None:
        def rule(expires: date) -> Suppression:
            return Suppression(
                hunt="beaconing",
                entity="host",
                value="ws-1",
                reason="known backup client",
                approved_by="lead",
                expires=expires,
            )

        active = replace(HuntConfig(), suppressions=(rule(date(2026, 12, 31)),))
        report = self.engine().hunt(flows(), active, hunt_start=HUNT_DAY, hunt_end=END)
        assert (
            report.findings == [] and report.suppressed == 1 and report.expired_suppressions == []
        )
        expired = replace(HuntConfig(), suppressions=(rule(date(2026, 1, 1)),))
        report = self.engine().hunt(flows(), expired, hunt_start=HUNT_DAY, hunt_end=END)
        assert (
            len(report.findings) == 1
            and report.suppressed == 0
            and len(report.expired_suppressions) == 1
        )

    def test_suppression_is_specific_to_hunt_and_entity(self) -> None:
        other_hunt = Suppression(
            hunt="dga",
            entity="host",
            value="ws-1",
            reason="not this hunt at all",
            approved_by="lead",
            expires=date(2026, 12, 31),
        )
        other_host = Suppression(
            hunt="beaconing",
            entity="host",
            value="ws-2",
            reason="a different host only",
            approved_by="lead",
            expires=date(2026, 12, 31),
        )
        wildcard = Suppression(
            hunt="*",
            entity="ip",
            value="203.0.113.66",
            reason="known-good address for all hunts",
            approved_by="lead",
            expires=date(2026, 12, 31),
        )
        assert (
            len(
                self.engine()
                .hunt(
                    flows(),
                    replace(HuntConfig(), suppressions=(other_hunt, other_host)),
                    hunt_start=HUNT_DAY,
                    hunt_end=END,
                )
                .findings
            )
            == 1
        )
        assert (
            self.engine()
            .hunt(
                flows(),
                replace(HuntConfig(), suppressions=(wildcard,)),
                hunt_start=HUNT_DAY,
                hunt_end=END,
            )
            .suppressed
            == 1
        )

    def test_warnings(self) -> None:
        report = self.engine().hunt(flows(), HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END)
        text = " ".join(report.warnings)
        assert "baseline covers 0 day(s)" in text and "no threat intelligence" in text
        empty = self.engine().hunt([], HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END)
        assert (
            "no events in the hunt window" in " ".join(empty.warnings)
            and "No findings." in empty.summary
        )

    def test_coverage(self) -> None:
        cov = self.engine().coverage({"flow": 10, "dns": 0})
        by_hunt = {r.hunt: r for r in cov.rows}
        assert (
            by_hunt["beaconing"].runnable
            and not by_hunt["dns_tunnel"].runnable
            and by_hunt["dns_tunnel"].missing == ["dns"]
        )
        assert (
            "T1071" in cov.covered_techniques
            and "T1071.004" in cov.blind_techniques
            and "T1071" not in cov.blind_techniques
        )
        text = render_coverage(cov)
        assert (
            "Data present: flow (10)" in text
            and "(needs dns)" in text
            and "Blind techniques:" in text
        )
        assert "Data present: none" in render_coverage(self.engine().coverage({}))

    def test_custom_hunt_set(self) -> None:
        engine = HuntEngine(TEMPLATE, [hunt_by_id("beaconing")])  # type: ignore[list-item]
        assert (
            len(engine.hunts) == 1
            and engine.hunt(flows(), HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END).skipped_hunts
            == []
        )


def report_with_findings() -> Any:
    return HuntEngine(TEMPLATE).hunt(flows(), HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END)


class TestReporting:
    def test_markdown_sections(self) -> None:
        md = render_markdown(report_with_findings())
        for heading in (
            "# Threat hunt 2026-09-18 00:00 to 2026-09-19 00:00 UTC",
            "## Summary",
            "## Leads",
            "## Data",
            "## Hunts that did not run",
            "## Warnings",
        ):
            assert heading in md
        assert (
            "Next steps:" in md
            and "`connect 203.0.113.66:443 400 bytes`" in md
            and "Possible benign causes" in md
        )

    def test_no_leads(self) -> None:
        md = render_markdown(
            HuntEngine(TEMPLATE).hunt([], HuntConfig(), hunt_start=HUNT_DAY, hunt_end=END)
        )
        assert "No leads." in md

    def test_hostile_text_is_escaped(self) -> None:
        hostile = report_with_findings()
        hostile.findings[0].title = "evil | <script>alert(1)</script>\n# injected"
        hostile.findings[0].explanation = "<img src=x onerror=1> | pipe"
        hostile.leads[0].title = "<b>bold</b> | lead"
        hostile.evidence[0].summary = "cmd `injected` | <i>x</i>"
        hostile.warnings = ["<u>warn</u>"]
        md = render_markdown(hostile)
        outside_code = re.sub(r"`[^`]*`", "", md)
        for tag in ("<script>", "<img", "<b>", "<i>", "<u>"):
            assert tag not in outside_code
        assert "\n# injected" not in md

    def test_json_round_trip(self) -> None:
        report = report_with_findings()
        assert json.loads(render_json(report))["events_hunted"] == 20

    def test_csv_neutralises_formulas(self) -> None:
        report = report_with_findings()
        report.findings[0].title = '=HYPERLINK("http://evil")'
        rows = list(csv.reader(io.StringIO(render_findings_csv(report))))
        assert rows[0][0] == "id" and rows[1][4].startswith("'=")

    def test_query_rendering(self) -> None:
        t = Thresholds()
        beacon = hunt_by_id("beaconing")
        assert beacon is not None
        assert render_query(beacon, "spl", t).startswith("index=network") and render_query(
            beacon, "kql", t
        ).startswith("DeviceNetworkEvents")
        with pytest.raises(ReportError, match="statistical hunt"):
            render_query(beacon, "sigma", t)
        with pytest.raises(ReportError, match="unknown query language"):
            render_query(beacon, "sql", t)
        chains = hunt_by_id("process_chains")
        assert chains is not None
        docs = list(yaml.safe_load_all(render_query(chains, "sigma", t)))
        assert len(docs) == 7 and all(
            d["logsource"]["category"] == "process_creation" for d in docs
        )

    def test_write_report_outputs(self, tmp_path: Path) -> None:
        report = report_with_findings()
        paths = write_report(report, tmp_path / "out", Thresholds(), ["md", "json"])
        names = {p.relative_to(tmp_path / "out").as_posix() for p in paths}
        assert {
            "hunt-report.md",
            "hunt-report.json",
            "findings.csv",
            "queries/beaconing.spl",
            "queries/beaconing.kql",
        } <= names
        assert not any(n.startswith("sigma/") for n in names) and not any(
            "dns-tunnel" in n for n in names
        )
        bare = write_report(report, tmp_path / "bare", Thresholds(), ["md"], with_rules=False)
        assert {p.name for p in bare} == {"hunt-report.md", "findings.csv"}

    def test_write_report_errors(self, tmp_path: Path) -> None:
        report = report_with_findings()
        with pytest.raises(ReportError, match="unknown format"):
            write_report(report, tmp_path, Thresholds(), ["pdf"])
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(ReportError):
            write_report(report, blocker / "sub", Thresholds(), ["md"])


class TestSummary:
    def facts(self) -> SummaryFacts:
        return facts_for(report_with_findings(), len(ALL_HUNTS))

    def test_facts_are_aggregates_only(self) -> None:
        facts = self.facts()
        assert (
            facts.findings == 1
            and facts.leads == 1
            and facts.hunts_skipped == 9
            and facts.hunts_run == 2
        )
        payload = facts.model_dump_json()
        for word in ("ws-1", "203.0.113.66", "beaconing"):
            assert word not in payload

    def test_template_and_llm_guard(self) -> None:
        facts = self.facts()
        text = TEMPLATE.write(facts)
        assert "1 findings" in text and "grouped into 1 lead(s)" in text

        class Good:
            def complete(self, system: str, user: str) -> str:
                return f"{facts.findings} finding and {facts.leads} lead."

        class Invented:
            def complete(self, system: str, user: str) -> str:
                return "There were 4242 alerts."

        class Down:
            def complete(self, system: str, user: str) -> str:
                raise ProviderError("down")

        assert LLMSummaryWriter(Good()).write(facts) == "1 finding and 1 lead."
        assert (
            LLMSummaryWriter(Invented()).write(facts) == text
            and LLMSummaryWriter(Down()).write(facts) == text
        )

    def test_template_optional_sentences(self) -> None:
        base: dict[str, Any] = {
            "events_hunted": 1,
            "events_baseline": 1,
            "hunts_run": 1,
            "hunts_skipped": 0,
            "findings": 2,
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "leads": 1,
            "top_lead_score": 90,
            "tactics_in_top_lead": 2,
            "ioc_leads": 1,
            "suppressed": 3,
        }
        text = TEMPLATE.write(SummaryFacts(**base))
        assert "match known-bad indicators" in text and "3 finding(s) were suppressed" in text
        assert "match known-bad" not in TEMPLATE.write(
            SummaryFacts(**{**base, "ioc_leads": 0, "suppressed": 0})
        )
        assert "utc" not in text and timezone.utc
