"""Unit tests for statistics, telemetry adapters and configuration."""

from __future__ import annotations

import json
import math
from datetime import date, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from huntagent.config import Settings, load_config
from huntagent.errors import ConfigurationError, TelemetryError
from huntagent.normalizers import (
    NORMALIZERS,
    NormalizeError,
    auth,
    cloudtrail,
    dns,
    flow,
    generic,
    normalize_lines,
    parse_time,
    sysmon,
)
from huntagent.security import (
    is_internal_ip,
    normalize_domain,
    normalize_ip,
    normalize_name,
    redact,
)
from huntagent.stats import (
    coefficient_of_variation,
    edit_distance,
    intervals,
    robust_zscore,
    shannon_entropy,
)
from tests.conftest import CONFIGS


class TestStats:
    def test_entropy(self) -> None:
        assert shannon_entropy("") == 0.0 and shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("abcd") == pytest.approx(2.0)
        assert shannon_entropy("google") < 2.0 < shannon_entropy("x7f9q2k8w1z5m3v6b4n0c")

    def test_coefficient_of_variation(self) -> None:
        assert coefficient_of_variation([60, 60, 60]) == 0.0
        assert coefficient_of_variation([50, 70]) == pytest.approx(10 / 60)
        assert math.isinf(coefficient_of_variation([5])) and math.isinf(
            coefficient_of_variation([0, 0])
        )

    def test_robust_zscore(self) -> None:
        sample = [10, 11, 9, 10, 12, 10]
        assert robust_zscore(10, sample) == pytest.approx(0.0, abs=0.01)
        assert robust_zscore(100, sample) > 10
        assert robust_zscore(100, [1, 2]) == 0.0
        assert robust_zscore(50, [5, 5, 5, 5]) == 0.0
        assert robust_zscore(9, [5, 5, 5, 6, 4, 5, 5]) > 3

    def test_outliers_in_the_sample_do_not_hide_an_outlier(self) -> None:
        assert robust_zscore(500, [10, 10, 11, 9, 10, 400]) > 3

    def test_intervals(self) -> None:
        assert intervals([30, 0, 10]) == [10, 20] and intervals([1]) == []

    def test_edit_distance(self) -> None:
        assert edit_distance("svchost.exe", "svch0st.exe") == 1
        assert edit_distance("abc", "abc") == 0
        assert edit_distance("abcdef", "uvwxyz", limit=2) == 3
        assert edit_distance("a", "abcdefgh", limit=2) == 3


class TestSecurity:
    def test_redaction(self) -> None:
        assert "hunter2xyz" not in redact("tool.exe -password hunter2xyz")
        assert "abcd1234efgh" not in redact("token=abcd1234efgh") and "S3cretPass" not in redact(
            "x --password=S3cretPass"
        )
        assert redact("powershell -enc AAAA") == "powershell -enc AAAA"

    def test_observables(self) -> None:
        assert (
            normalize_ip(" [2001:db8::1] ") == "2001:db8::1" and normalize_ip("999.1.1.1") is None
        )
        assert (
            normalize_domain("Evil.Example.") == "evil.example"
            and normalize_domain("nodots") is None
        )
        assert (
            normalize_name("CORP\\Alice") == "alice" and normalize_name("Bob@corp.example") == "bob"
        )

    @pytest.mark.parametrize(
        ("ip", "internal"),
        [
            ("10.1.1.1", True),
            ("172.20.0.1", True),
            ("192.168.5.5", True),
            ("127.0.0.1", True),
            ("fe80::1", True),
            ("203.0.113.5", False),
            ("198.18.0.1", False),
            ("8.8.8.8", False),
            ("bad", False),
        ],
    )
    def test_internal_addresses(self, ip: str, internal: bool) -> None:
        assert is_internal_ip(ip) is internal


class TestParseTime:
    @pytest.mark.parametrize(
        ("raw", "iso"),
        [
            ("2026-09-18T10:00:00Z", "2026-09-18T10:00:00+00:00"),
            ("2026-09-18T12:00:00+02:00", "2026-09-18T10:00:00+00:00"),
            ("2026-09-18 10:00:00", "2026-09-18T10:00:00+00:00"),
            (1789725600, "2026-09-18T10:00:00+00:00"),
            (1789725600000, "2026-09-18T10:00:00+00:00"),
            ("1789725600", "2026-09-18T10:00:00+00:00"),
        ],
    )
    def test_formats(self, raw: Any, iso: str) -> None:
        moment = parse_time(raw)
        assert moment.isoformat() == iso and moment.tzinfo == timezone.utc

    @pytest.mark.parametrize("raw", [None, "", "yesterday", True, []])
    def test_errors(self, raw: Any) -> None:
        with pytest.raises(NormalizeError):
            parse_time(raw)


class TestAdapters:
    def test_sysmon_process_flow_dns(self) -> None:
        p = sysmon(
            {
                "EventID": 1,
                "UtcTime": "2026-09-18T10:00:00Z",
                "Computer": "WS-1",
                "User": "CORP\\Alice",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "ParentImage": "C:\\Program Files\\winword.exe",
                "CommandLine": "cmd.exe /c tool -password hunter2xyz",
                "Hash": "SHA256=" + "a" * 64,
            }
        )
        assert (
            p.kind == "process" and p.host == "ws-1" and p.user == "alice" and p.image == "cmd.exe"
        )
        assert "hunter2xyz" not in p.cmdline and p.attrs["sha256"] == "SHA256=" + "a" * 64
        f = sysmon(
            {
                "EventID": "3",
                "UtcTime": "2026-09-18T10:00:00Z",
                "Computer": "ws-1",
                "DestinationIp": "203.0.113.5",
                "DestinationPort": "443",
                "BytesSent": "1200",
                "SourceIp": "10.0.0.5",
            }
        )
        assert (f.kind, f.dst_ip, f.dst_port, f.bytes_out) == ("flow", "203.0.113.5", 443, 1200)
        d = sysmon(
            {
                "EventID": 22,
                "UtcTime": "2026-09-18T10:00:00Z",
                "Computer": "ws-1",
                "QueryName": "Evil.Example.",
                "QueryStatus": "NXDOMAIN",
            }
        )
        assert (d.kind, d.domain, d.outcome) == ("dns", "evil.example", "failure")
        nested = sysmon(
            {
                "EventID": 1,
                "EventData": {
                    "UtcTime": "2026-09-18T10:00:00Z",
                    "Computer": "ws-2",
                    "Image": "a.exe",
                },
            }
        )
        assert nested.host == "ws-2"

    def test_sysmon_unsupported_event(self) -> None:
        with pytest.raises(NormalizeError, match="unsupported"):
            sysmon({"EventID": 11, "UtcTime": "2026-09-18T10:00:00Z"})

    @pytest.mark.parametrize(
        ("result", "outcome"),
        [
            ("success", "success"),
            ("Accepted", "success"),
            ("FAILED", "failure"),
            ("denied", "failure"),
        ],
    )
    def test_auth_results(self, result: str, outcome: str) -> None:
        e = auth(
            {
                "timestamp": "2026-09-18T10:00:00Z",
                "user": "CORP\\Bob",
                "host": "srv1",
                "src_ip": "198.51.100.5",
                "result": result,
                "logon_type": 3,
                "src_host": "ws-1",
            }
        )
        assert (
            e.outcome == outcome
            and e.user == "bob"
            and e.attrs == {"logon_type": "3", "src_host": "ws-1"}
        )

    def test_auth_rejects_unknown_result(self) -> None:
        with pytest.raises(NormalizeError, match="result"):
            auth({"timestamp": "2026-09-18T10:00:00Z", "result": "maybe"})

    def test_dns_flow_cloudtrail(self) -> None:
        d = dns(
            {
                "timestamp": "2026-09-18T10:00:00Z",
                "client": "ws-1",
                "query": "A.B.Example.com",
                "qtype": "txt",
                "rcode": "NXDOMAIN",
            }
        )
        assert (d.domain, d.query_type, d.outcome) == ("a.b.example.com", "TXT", "failure")
        with pytest.raises(NormalizeError):
            dns({"timestamp": "2026-09-18T10:00:00Z", "query": "not a domain"})
        f = flow(
            {
                "timestamp": "2026-09-18T10:00:00Z",
                "src_host": "ws-1",
                "dst_ip": "203.0.113.5",
                "dst_port": 8443,
                "bytes_out": "99",
                "proto": "tcp",
            }
        )
        assert (f.dst_port, f.bytes_out, f.attrs["proto"]) == (8443, 99, "tcp")
        with pytest.raises(NormalizeError):
            flow({"timestamp": "2026-09-18T10:00:00Z", "dst_ip": "not-an-ip"})

    def test_cloudtrail_identity_and_mfa(self) -> None:
        base = {
            "eventTime": "2026-09-18T10:00:00Z",
            "eventName": "StopLogging",
            "sourceIPAddress": "198.51.100.7",
            "awsRegion": "us-east-1",
        }
        named = cloudtrail(
            {
                **base,
                "userIdentity": {"userName": "Bot", "type": "IAMUser"},
                "additionalEventData": {"MFAUsed": "No"},
            }
        )
        assert (named.user, named.mfa, named.outcome, named.api) == (
            "bot",
            False,
            "success",
            "StopLogging",
        )
        root = cloudtrail(
            {
                **base,
                "userIdentity": {"type": "Root"},
                "additionalEventData": {"MFAUsed": "Yes"},
                "errorCode": "AccessDenied",
            }
        )
        assert (root.user, root.mfa, root.outcome) == ("root", True, "failure")
        session = cloudtrail(
            {
                **base,
                "userIdentity": {
                    "userName": "x",
                    "sessionContext": {"attributes": {"mfaAuthenticated": "true"}},
                },
            }
        )
        assert session.mfa is True
        login = cloudtrail(
            {
                **base,
                "eventName": "ConsoleLogin",
                "userIdentity": {"userName": "x"},
                "responseElements": {"ConsoleLogin": "Failure"},
            }
        )
        assert login.outcome == "failure" and login.mfa is None
        with pytest.raises(NormalizeError, match="event name"):
            cloudtrail({"eventTime": "2026-09-18T10:00:00Z"})

    def test_generic_validation_and_redaction(self) -> None:
        e = generic(
            {
                "time": "2026-09-18T10:00:00Z",
                "kind": "process",
                "host": "h",
                "cmdline": "x --token abc12345",
            }
        )
        assert e.kind == "process" and "abc12345" not in e.cmdline and e.id.startswith("generic:")
        with pytest.raises(NormalizeError):
            generic({"time": "2026-09-18T10:00:00Z", "kind": "nonsense"})
        with pytest.raises(NormalizeError):
            generic({"time": "2026-09-18T10:00:00Z", "kind": "auth", "surprise": 1})

    def test_ids_are_stable_and_content_based(self) -> None:
        a = flow({"timestamp": "2026-09-18T10:00:00Z", "src_host": "h", "dst_ip": "203.0.113.5"})
        b = flow({"timestamp": "2026-09-18T10:00:00Z", "src_host": "h", "dst_ip": "203.0.113.5"})
        c = flow({"timestamp": "2026-09-18T10:00:01Z", "src_host": "h", "dst_ip": "203.0.113.5"})
        assert a.id == b.id != c.id

    def test_registry(self) -> None:
        assert set(NORMALIZERS) == {"sysmon", "auth", "dns", "flow", "cloudtrail", "generic"}

    def test_describe(self) -> None:
        assert (
            "203.0.113.5:443"
            in flow(
                {
                    "timestamp": "2026-09-18T10:00:00Z",
                    "dst_ip": "203.0.113.5",
                    "dst_port": 443,
                    "bytes_out": 5,
                }
            ).describe()
        )
        assert (
            "NXDOMAIN"
            in dns(
                {"timestamp": "2026-09-18T10:00:00Z", "query": "a.example.com", "rcode": "NXDOMAIN"}
            ).describe()
        )
        assert (
            "sign-in success"
            in auth(
                {"timestamp": "2026-09-18T10:00:00Z", "result": "success", "src_ip": "198.51.100.5"}
            ).describe()
        )
        assert (
            "StopLogging"
            in cloudtrail(
                {
                    "eventTime": "2026-09-18T10:00:00Z",
                    "eventName": "StopLogging",
                    "userIdentity": {"userName": "x"},
                }
            ).describe()
        )
        assert (
            "cmd.exe"
            in sysmon(
                {
                    "EventID": 1,
                    "UtcTime": "2026-09-18T10:00:00Z",
                    "Image": "C:\\x\\cmd.exe",
                    "CommandLine": "cmd /c dir",
                }
            ).describe()
        )


class TestNormalizeLines:
    def _line(self, **kw: Any) -> str:
        record = {"timestamp": "2026-09-18T10:00:00Z", "src_host": "h", "dst_ip": "203.0.113.5"}
        record.update(kw)
        return json.dumps(record)

    def test_counts_dedupes_and_never_echoes_content(self) -> None:
        lines = [
            self._line(),
            self._line(),
            "not json password=Sup3rSecret",
            "[1,2]",
            json.dumps({"timestamp": "bad", "dst_ip": "203.0.113.5"}),
            "",
            self._line(dst_ip="203.0.113.6"),
        ]
        events, report = normalize_lines(lines, "flow")
        assert (
            len(events) == 2 and report.accepted == 2 and report.rejected == 3 and report.lines == 6
        )
        assert "Sup3rSecret" not in json.dumps(report.model_dump())
        assert report.errors[0].startswith("line 3:")

    def test_limits(self) -> None:
        events, report = normalize_lines(["x" * 500, self._line()], "flow", max_line_bytes=100)
        assert len(events) == 1 and "exceeds 100 bytes" in report.errors[0]
        with pytest.raises(TelemetryError, match="limit"):
            normalize_lines(
                [self._line(dst_ip=f"203.0.113.{n}") for n in range(5)], "flow", max_events=3
            )

    def test_unknown_source(self) -> None:
        with pytest.raises(TelemetryError, match="unknown source"):
            normalize_lines([], "carrier-pigeon")

    def test_error_list_is_capped(self) -> None:
        _, report = normalize_lines(["nope"] * 50, "flow")
        assert report.rejected == 50 and len(report.errors) == 20


class TestConfig:
    def test_example_configs_load(self) -> None:
        cfg = load_config(
            thresholds_file=CONFIGS / "thresholds.example.yaml",
            iocs_file=CONFIGS / "iocs.example.json",
            allowlist_file=CONFIGS / "allowlist.example.yaml",
            geo_file=CONFIGS / "geo.example.yaml",
            suppressions_file=CONFIGS / "suppressions.example.yaml",
        )
        assert (
            cfg.thresholds.beacon_min_connections == 12
            and "203.0.113.66" in cfg.ioc_ips
            and "c2-tunnel.example" in cfg.ioc_domains
        )
        assert (
            cfg.scanner_ips == {"198.18.0.1"}
            and "svc-patch" in cfg.noisy_users
            and len(cfg.suppressions) == 2
            and len(cfg.geo) == 3
        )

    def test_defaults_without_files(self) -> None:
        cfg = load_config()
        assert cfg.thresholds.spray_min_users == 8 and cfg.geo == () and cfg.suppressions == ()

    def test_geo_lookup_prefers_the_most_specific_range(self, tmp_path: Path) -> None:
        geo = tmp_path / "g.yaml"
        geo.write_text(
            yaml.safe_dump(
                {
                    "ranges": [
                        {"cidr": "203.0.0.0/16", "country": "AA"},
                        {"cidr": "203.0.113.0/24", "country": "BB"},
                        {"cidr": "2001:db8::/32", "country": "CC"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        cfg = load_config(geo_file=geo)
        assert (
            cfg.country_of("203.0.113.9") == "BB"
            and cfg.country_of("203.0.5.5") == "AA"
            and cfg.country_of("2001:db8::1") == "CC"
        )
        assert cfg.country_of("8.8.8.8") == "" and cfg.country_of("junk") == ""

    def test_allowlist_matching(self, tmp_path: Path) -> None:
        allow = tmp_path / "a.yaml"
        allow.write_text(
            yaml.safe_dump(
                {
                    "destination_ips": ["198.18.0.0/24", "203.0.113.7"],
                    "destination_domains": [".Example.org"],
                }
            ),
            encoding="utf-8",
        )
        cfg = load_config(allowlist_file=allow)
        assert (
            cfg.is_allowed_destination(ip="198.18.0.9")
            and cfg.is_allowed_destination(ip="203.0.113.7")
            and not cfg.is_allowed_destination(ip="203.0.113.8")
        )
        assert cfg.is_allowed_destination(domain="a.b.example.org") and cfg.is_allowed_destination(
            domain="example.org"
        )
        assert (
            not cfg.is_allowed_destination(domain="notexample.org")
            and not cfg.is_allowed_destination()
            and not cfg.is_allowed_destination(ip="junk")
        )

    @pytest.mark.parametrize(
        ("kwarg", "content", "message"),
        [
            ("thresholds_file", "beacon_min_connections: 1\n", "invalid configuration"),
            ("thresholds_file", "surprise: 1\n", "invalid configuration"),
            ("thresholds_file", "- a\n- b\n", "mapping"),
            ("allowlist_file", "destination_ips: [not-an-ip]\n", "invalid address"),
            ("geo_file", "ranges: [{cidr: 1.2.3.0/24, country: usa}]\n", "invalid configuration"),
            ("geo_file", "just: text\n", "list of ranges"),
            (
                "suppressions_file",
                "suppressions: [{hunt: x, entity: host, value: h, reason: short, approved_by: a, expires: 2026-01-01}]\n",
                "invalid configuration",
            ),
            ("suppressions_file", "suppressions: {a: 1}\n", "list of suppressions"),
            ("iocs_file", "ips: {a: 1}\n", "invalid configuration"),
        ],
    )
    def test_invalid_files(self, tmp_path: Path, kwarg: str, content: str, message: str) -> None:
        path = tmp_path / "c.yaml"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ConfigurationError, match=message):
            load_config(**{kwarg: path})

    def test_unreadable_and_oversized(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError, match="cannot read"):
            load_config(thresholds_file=tmp_path / "missing.yaml")
        big = tmp_path / "big.yaml"
        big.write_text("a: " + "x" * 2_100_000, encoding="utf-8")
        with pytest.raises(ConfigurationError, match="larger"):
            load_config(thresholds_file=big)

    def test_ioc_values_are_normalised(self, tmp_path: Path) -> None:
        path = tmp_path / "i.json"
        path.write_text(
            json.dumps(
                {
                    "ips": [" 203.0.113.66 ", "bad"],
                    "domains": ["Evil.Example.", "nodots"],
                    "hashes": [" ABC123 "],
                }
            ),
            encoding="utf-8",
        )
        cfg = load_config(iocs_file=path)
        assert (
            cfg.ioc_ips == {"203.0.113.66"}
            and cfg.ioc_domains == {"evil.example"}
            and cfg.ioc_hashes == {"abc123"}
        )

    def test_settings(self) -> None:
        with pytest.raises(ValueError, match="retry_max_wait"):
            Settings(_env_file=None, retry_min_wait=5.0, retry_max_wait=1.0)  # type: ignore[call-arg]
        assert Settings(_env_file=CONFIGS.parent / ".env.example").llm_provider == "none"  # type: ignore[call-arg]
        assert date(2026, 1, 1) < date(2027, 1, 1)
