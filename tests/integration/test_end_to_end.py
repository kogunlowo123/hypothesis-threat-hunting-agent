"""End-to-end tests: simulated week plus a hunt day, through the service and the CLI."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml
from pydantic import SecretStr

from huntagent.cli import main
from huntagent.config import load_config
from huntagent.container import build_service
from huntagent.errors import ConfigurationError, HuntError, TelemetryError
from huntagent.models import HuntReport
from huntagent.service import HuntService, parse_duration
from huntagent.simulate import C2_IP, IMPLANT_SHA256, SPRAY_IP, simulate, write_records
from tests.conftest import CONFIGS, make_service, make_settings

DAY = datetime(2026, 9, 18, tzinfo=timezone.utc)
FORMATS = ("sysmon", "auth", "dns", "flow", "cloudtrail")


@pytest.fixture(scope="module")
def feeds(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("feeds")
    write_records(simulate(start=DAY), directory)
    return directory


def inputs(feeds: Path, kinds: tuple[str, ...] = FORMATS) -> list[tuple[str, Path]]:
    return [(k, feeds / f"{k}.jsonl") for k in kinds]


def full_config(**skip: bool):
    files = {
        "iocs_file": CONFIGS / "iocs.example.json",
        "allowlist_file": CONFIGS / "allowlist.example.yaml",
        "geo_file": CONFIGS / "geo.example.yaml",
        "suppressions_file": CONFIGS / "suppressions.example.yaml",
    }
    return load_config(**{k: v for k, v in files.items() if not skip.get(k.removesuffix("_file"))})


def run(feeds: Path, service: HuntService | None = None, **config_skip: bool) -> HuntReport:
    svc = service or make_service()
    events, _ = svc.load(inputs(feeds))
    return svc.hunt(events, full_config(**config_skip), hunt_start=DAY, window=timedelta(hours=24))


class TestSimulatedIntrusion:
    def test_headline_results(self, feeds: Path) -> None:
        r = run(feeds)
        assert (r.events_hunted, r.events_baseline) == (1056, 5509) and r.skipped_hunts == []
        assert len(r.findings) == 17 and len(r.leads) == 7 and r.suppressed == 1
        assert [f.severity.value for f in r.findings].count("critical") == 6

    def test_every_planted_attack_is_found(self, feeds: Path) -> None:
        by_hunt = {}
        for f in run(feeds).findings:
            by_hunt.setdefault(f.hunt, []).append(f)
        assert set(by_hunt) == {
            "beaconing",
            "dns_tunnel",
            "dga",
            "exfiltration",
            "password_attacks",
            "impossible_travel",
            "lateral_fanout",
            "process_chains",
            "persistence",
            "rare_process",
            "cloud_abuse",
        }
        assert by_hunt["beaconing"][0].hosts == ["ws-004"] and by_hunt["beaconing"][0].ips == [
            C2_IP
        ]
        assert by_hunt["password_attacks"][0].ips == [SPRAY_IP] and by_hunt["password_attacks"][
            0
        ].details["successful_accounts"] == ["u005"]
        assert by_hunt["impossible_travel"][0].users == ["alice"] and by_hunt["dga"][0].hosts == [
            "ws-007"
        ]
        assert {f.details["rule"] for f in by_hunt["process_chains"]} == {
            "office_shell",
            "encoded_command",
            "download_cradle",
        }
        assert (
            by_hunt["exfiltration"][0].details["bytes_out"] == 180_000_000
            and by_hunt["persistence"][0].details["rule"] == "scheduled_task"
        )
        assert {f.title.split(" ")[0] for f in by_hunt["cloud_abuse"]} >= {
            "deploy-bot",
            "Root",
            "svc-ci",
        }

    def test_the_intrusion_becomes_one_lead_spanning_the_kill_chain(self, feeds: Path) -> None:
        lead = run(feeds).leads[0]
        assert lead.score == 100 and lead.ioc_match and len(lead.finding_ids) == 10
        assert lead.tactics == [
            "Execution",
            "Persistence",
            "Defense Evasion",
            "Lateral Movement",
            "Command and Control",
            "Exfiltration",
        ]
        assert (
            {"ws-004", "srv-file01"} <= set(lead.hosts)
            and C2_IP in lead.ips
            and len(lead.next_steps) == 7
        )

    def test_password_spray_is_kept_apart_from_the_intrusion(self, feeds: Path) -> None:
        r = run(feeds)
        spray = next(lead for lead in r.leads if SPRAY_IP in lead.ips)
        assert len(spray.finding_ids) == 1 and "ws-004" not in spray.hosts

    def test_benign_lookalikes_do_not_appear(self, feeds: Path) -> None:
        text = json.dumps([f.model_dump(mode="json") for f in run(feeds).findings])
        for benign in (
            "bk-01",
            "198.18.0.50",
            "198.18.0.1",
            "198.18.0.20",
            "svc-patch",
            "build-01",
        ):
            assert benign not in text

    def test_without_the_allowlist_the_lookalikes_become_findings(self, feeds: Path) -> None:
        r = run(feeds, allowlist=True, suppressions=True)
        text = json.dumps([f.model_dump(mode="json") for f in r.findings])
        assert "bk-01" in text and "198.18.0.1" in text and "build-01" in text
        assert len(r.findings) > 17

    def test_suppression_hides_only_the_reviewed_finding(self, feeds: Path) -> None:
        with_rules = run(feeds)
        without = run(feeds, suppressions=True)
        assert len(without.findings) == len(with_rules.findings) + 1 and without.suppressed == 0
        hidden = {f.id for f in without.findings} - {f.id for f in with_rules.findings}
        assert [f.hosts for f in without.findings if f.id in hidden] == [["build-01"]]
        assert [s.value for s in with_rules.expired_suppressions] == ["retired-host"]

    def test_secrets_never_reach_the_report(self, feeds: Path) -> None:
        report = run(feeds)
        assert "hunter2xyz" not in report.model_dump_json()
        assert any("[REDACTED]" in e.summary for e in report.evidence)

    def test_ioc_hash_matches_the_implant(self, feeds: Path) -> None:
        events, _ = make_service().load(inputs(feeds, ("sysmon",)))
        implant = next(e for e in events if e.image == "svch0st.exe")
        assert implant.attrs["sha256"] == "SHA256=" + IMPLANT_SHA256
        assert next(
            f for f in run(feeds).findings if f.hunt == "rare_process" and "svch0st" in f.title
        ).ioc_match

    def test_deterministic(self, feeds: Path) -> None:
        assert run(feeds) == run(feeds)

    def test_windows_shift_what_is_found(self, feeds: Path) -> None:
        svc = make_service()
        events, _ = svc.load(inputs(feeds))
        quiet = svc.hunt(
            events, full_config(), hunt_start=DAY - timedelta(days=3), window=timedelta(hours=24)
        )
        assert quiet.findings == [] and "No findings." in quiet.summary
        default = svc.hunt(events, full_config())
        assert len(default.findings) == 17

    def test_baseline_days_limits_history(self, feeds: Path) -> None:
        svc = make_service()
        events, _ = svc.load(inputs(feeds))
        short = svc.hunt(events, full_config(), hunt_start=DAY, baseline_days=1)
        assert short.events_baseline < 2000

    def test_missing_data_kinds_skip_hunts_and_narrow_coverage(self, feeds: Path) -> None:
        svc = make_service()
        events, _ = svc.load(inputs(feeds, ("flow", "dns")))
        report = svc.hunt(events, full_config(), hunt_start=DAY)
        assert len(report.skipped_hunts) == 7 and {f.hunt for f in report.findings} == {
            "beaconing",
            "dns_tunnel",
            "dga",
            "exfiltration",
        }
        cov = svc.coverage(events)
        assert "T1059" in cov.blind_techniques and "T1071" in cov.covered_techniques

    def test_no_events_is_an_error(self) -> None:
        with pytest.raises(HuntError, match="no events"):
            make_service().hunt([], full_config())

    def test_load_errors(self, tmp_path: Path) -> None:
        with pytest.raises(TelemetryError, match="cannot read"):
            make_service().load([("flow", tmp_path / "missing.jsonl")])
        with pytest.raises(TelemetryError, match="unknown source"):
            make_service().load([("nope", tmp_path / "x")])

    def test_duplicate_events_across_files_are_loaded_once(self, feeds: Path) -> None:
        events, _ = make_service().load(inputs(feeds, ("flow",)) * 2)
        single, _ = make_service().load(inputs(feeds, ("flow",)))
        assert len(events) == len(single)

    def test_parse_duration(self) -> None:
        assert parse_duration("90m") == timedelta(minutes=90) and parse_duration("2d") == timedelta(
            days=2
        )
        for bad in ("", "h", "0h", "5x", "-3h"):
            with pytest.raises(HuntError, match="invalid duration"):
                parse_duration(bad)


class TestLlmSummary:
    def _service(self, reply: str, seen: list[dict[str, object]]) -> HuntService:
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [{"message": {"content": reply}}]})

        settings = make_settings(llm_provider="openai", openai_api_key=SecretStr("k"))
        return build_service(
            settings, http_client=httpx.Client(transport=httpx.MockTransport(handler))
        )

    def test_grounded_reply_is_used_and_prompt_has_only_counts(self, feeds: Path) -> None:
        seen: list[dict[str, object]] = []
        report = run(feeds, self._service("Seventeen findings became seven leads.", seen))
        assert report.summary == "Seventeen findings became seven leads."
        sent = json.dumps(seen[0])
        for word in ("ws-004", C2_IP, "alice", "beaconing", "deploy-bot"):
            assert word not in sent
        assert "1056" in sent

    def test_invented_numbers_fall_back(self, feeds: Path) -> None:
        report = run(feeds, self._service("We saw 31337 alerts.", []))
        assert "31337" not in report.summary and "17 findings" in report.summary

    @pytest.mark.parametrize("provider", ["openai", "anthropic"])
    def test_missing_keys_are_a_configuration_error(self, provider: str) -> None:
        with pytest.raises(ConfigurationError, match="API_KEY"):
            build_service(
                make_settings(llm_provider=provider, openai_api_key=None, anthropic_api_key=None)
            )


class TestCli:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        for name in (
            "HUNTAGENT_LLM_PROVIDER",
            "HUNTAGENT_IOCS_FILE",
            "HUNTAGENT_GEO_FILE",
            "HUNTAGENT_ALLOWLIST_FILE",
        ):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("HUNTAGENT_LOG_LEVEL", "CRITICAL")
        monkeypatch.chdir(tmp_path)

    def args(self, feeds: Path, *extra: str) -> list[str]:
        base = ["hunt"]
        for kind in FORMATS:
            base += ["-i", f"{kind}={feeds / (kind + '.jsonl')}"]
        return [
            *base,
            "--iocs",
            str(CONFIGS / "iocs.example.json"),
            "--allowlist",
            str(CONFIGS / "allowlist.example.yaml"),
            "--geo",
            str(CONFIGS / "geo.example.yaml"),
            "--hunt-start",
            "2026-09-18T00:00:00Z",
            *extra,
        ]

    def test_hunts_and_query(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["hunts"]) == 0
        out = capsys.readouterr().out
        assert "beaconing" in out and len(out.splitlines()) == 12
        assert main(["query", "beaconing"]) == 0 and capsys.readouterr().out.startswith(
            "index=network"
        )
        assert (
            main(["query", "cloud_abuse", "--lang", "kql"]) == 0
            and "AWSCloudTrail" in capsys.readouterr().out
        )
        assert main(["query", "process_chains", "--lang", "sigma"]) == 0
        assert len(list(yaml.safe_load_all(capsys.readouterr().out))) == 7
        assert (
            main(["query", "beaconing", "--lang", "sigma"]) == 2
            and "statistical" in capsys.readouterr().err
        )
        assert main(["query", "nope"]) == 2

    def test_query_uses_custom_thresholds(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "t.yaml"
        path.write_text("beacon_min_connections: 99\n", encoding="utf-8")
        assert main(["query", "beaconing", "--thresholds", str(path)]) == 0
        assert "count>=99" in capsys.readouterr().out

    def test_simulate_then_hunt_writes_everything(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        feeds = tmp_path / "feeds"
        assert main(["simulate", "--out", str(feeds), "--start", "2026-09-18"]) == 0
        assert {p.name for p in feeds.iterdir()} == {f"{k}.jsonl" for k in FORMATS}
        capsys.readouterr()
        out = tmp_path / "out"
        assert (
            main(
                self.args(
                    feeds,
                    "--out",
                    str(out),
                    "--suppressions",
                    str(CONFIGS / "suppressions.example.yaml"),
                )
            )
            == 0
        )
        printed = capsys.readouterr()
        assert (
            "17 findings" in printed.out
            and "loaded 1056" not in printed.err
            and "loaded" in printed.err
        )
        names = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
        assert {
            "hunt-report.md",
            "hunt-report.json",
            "findings.csv",
            "sigma/process-chains.yml",
            "sigma/cloud-abuse.yml",
            "queries/beaconing.spl",
            "queries/exfiltration.kql",
        } <= names
        for sigma in (out / "sigma").glob("*.yml"):
            assert all(
                isinstance(doc, dict) and "detection" in doc
                for doc in yaml.safe_load_all(sigma.read_text(encoding="utf-8"))
            )

    def test_prints_markdown_or_json_without_out(
        self, feeds: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(self.args(feeds)) == 0
        assert capsys.readouterr().out.startswith("# Threat hunt 2026-09-18")
        assert main(self.args(feeds, "--format", "json", "--only", "beaconing")) == 0
        payload = json.loads(capsys.readouterr().out)
        assert [f["hunt"] for f in payload["findings"]] == ["beaconing"]

    def test_fail_on_lead(self, feeds: Path) -> None:
        assert main(self.args(feeds, "--out", "o", "--fail-on-lead", "critical")) == 1
        assert main(self.args(feeds, "--out", "o", "--only", "dga", "--fail-on-lead", "high")) == 0
        assert (
            main(self.args(feeds, "--out", "o", "--only", "dga", "--fail-on-lead", "medium")) == 1
        )

    def test_window_and_baseline_options(
        self, feeds: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            main(self.args(feeds, "--window", "12h", "--baseline-days", "2", "--format", "json"))
            == 0
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["hunt_end"].startswith("2026-09-18T12:00")

    def test_coverage(self, feeds: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["coverage", "-i", f"flow={feeds / 'flow.jsonl'}"]) == 0
        out = capsys.readouterr().out
        assert "Data present: flow (" in out and "(needs dns)" in out
        assert main(["coverage", "--kinds", "process,auth"]) == 0
        assert "process_chains" in capsys.readouterr().out
        assert main(["coverage"]) == 0 and "Data present: none" in capsys.readouterr().out

    def test_errors_exit_two(
        self, feeds: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["hunt", "-i", f"flow={tmp_path / 'missing.jsonl'}"]) == 2
        empty = tmp_path / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        assert main(["hunt", "-i", f"flow={empty}"]) == 2
        assert main(self.args(feeds, "--window", "soon")) == 2
        assert main(self.args(feeds, "--hunt-start", "yesterday")) == 2
        assert main(self.args(feeds, "--only", "nope")) == 2
        bad = tmp_path / "bad.yaml"
        bad.write_text("beacon_min_connections: 1\n", encoding="utf-8")
        assert main(self.args(feeds, "--thresholds", str(bad))) == 2
        assert main(self.args(feeds, "--out", str(tmp_path / "o"), "--format", "pdf")) == 2
        assert capsys.readouterr().err.count("error:") == 7

    def test_bad_arguments_are_rejected_by_argparse(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as info:
            main(["hunt", "-i", "not-a-pair"])
        assert info.value.code == 2
        with pytest.raises(SystemExit):
            main(["hunt", "-i", f"nope={tmp_path / 'x'}"])
        with pytest.raises(SystemExit):
            main(["hunt"])

    def test_bad_lines_are_reported_without_content(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "flow.jsonl"
        good = json.dumps(
            {"timestamp": "2026-09-18T10:00:00Z", "src_host": "h", "dst_ip": "203.0.113.5"}
        )
        path.write_text(good + "\nnot json password=Sup3rSecret\n", encoding="utf-8")
        assert main(["hunt", "-i", f"flow={path}", "--format", "json"]) == 0
        err = capsys.readouterr().err
        assert "1 rejected" in err and "Sup3rSecret" not in err

    def test_llm_provider_without_key(
        self, feeds: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("HUNTAGENT_LLM_PROVIDER", "anthropic")
        monkeypatch.delenv("HUNTAGENT_ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert main(self.args(feeds)) == 2
        assert "API_KEY" in capsys.readouterr().err

    def test_environment_configuration(
        self, feeds: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("HUNTAGENT_IOCS_FILE", str(CONFIGS / "iocs.example.json"))
        monkeypatch.setenv("HUNTAGENT_ALLOWLIST_FILE", str(CONFIGS / "allowlist.example.yaml"))
        monkeypatch.setenv("HUNTAGENT_GEO_FILE", str(CONFIGS / "geo.example.yaml"))
        argv = [
            "hunt",
            "--hunt-start",
            "2026-09-18T00:00:00Z",
            "--format",
            "json",
            *[arg for k in FORMATS for arg in ("-i", f"{k}={feeds / (k + '.jsonl')}")],
        ]
        assert main(argv) == 0
        payload = json.loads(capsys.readouterr().out)
        assert len(payload["findings"]) == 18 and payload["skipped_hunts"] == []
