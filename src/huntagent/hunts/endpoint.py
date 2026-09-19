"""Endpoint hunts: suspicious process chains, persistence and rare processes."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from huntagent.hunts.base import Hunt, HuntContext, make_finding
from huntagent.models import Event, Finding, Thresholds
from huntagent.stats import edit_distance

OFFICE = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "onenote.exe",
        "acrord32.exe",
        "msaccess.exe",
    }
)
SHELLS = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "bash",
        "sh",
    }
)
WEB_SERVERS = frozenset({"w3wp.exe", "httpd", "nginx", "php-fpm", "tomcat9.exe", "java.exe"})
SYSTEM_NAMES = (
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "explorer.exe",
    "services.exe",
    "winlogon.exe",
    "smss.exe",
    "spoolsv.exe",
    "taskhost.exe",
    "wininit.exe",
)
WRITABLE_PATHS = (
    "/temp/",
    "/appdata/",
    "/users/public/",
    "/downloads/",
    "/tmp/",  # noqa: S108
    "/dev/shm/",  # noqa: S108
    "/programdata/",
)


@dataclass(frozen=True)
class ProcessRule:
    """A pattern over parent, image and command line. The same table drives detection and Sigma output."""

    id: str
    title: str
    score: int
    tactic: str
    techniques: tuple[str, ...]
    parents: frozenset[str] = frozenset()
    images: frozenset[str] = frozenset()
    cmdline: str = ""
    benign: tuple[str, ...] = ()

    def matches(self, event: Event) -> bool:
        parent = event.parent.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if self.parents and parent not in self.parents:
            return False
        if self.images and event.image not in self.images:
            return False
        haystack = f"{event.process} {event.cmdline}"
        return not (self.cmdline and not re.search(self.cmdline, haystack, re.IGNORECASE))


EXECUTION_RULES: tuple[ProcessRule, ...] = (
    ProcessRule(
        "office_shell",
        "Office application launched a shell",
        80,
        "Execution",
        ("T1204.002", "T1059"),
        parents=OFFICE,
        images=SHELLS,
        benign=("a macro-enabled finance workbook that calls a script",),
    ),
    ProcessRule(
        "encoded_command",
        "Encoded PowerShell command",
        65,
        "Defense Evasion",
        ("T1027", "T1059.001"),
        images=frozenset({"powershell.exe", "pwsh.exe"}),
        cmdline=r"\s-(?:e|en|enc|enco|encod\w*)\s+[A-Za-z0-9+/=]{20,}",
        benign=("some management agents pass encoded commands",),
    ),
    ProcessRule(
        "download_cradle",
        "Command that downloads and runs content",
        70,
        "Command and Control",
        ("T1105", "T1059.001"),
        cmdline=r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|certutil\S*\s.*-urlcache|bitsadmin\S*\s.*/transfer|curl\s.*\|\s*(?:ba)?sh",
        benign=("installer scripts and package managers",),
    ),
    ProcessRule(
        "lolbin_proxy",
        "Signed binary used to run remote or script content",
        75,
        "Defense Evasion",
        ("T1218",),
        images=frozenset({"regsvr32.exe", "mshta.exe", "rundll32.exe"}),
        cmdline=r"https?://|/i:http|javascript:|scrobj\.dll",
    ),
    ProcessRule(
        "credential_dump",
        "Credential dumping tool or technique",
        90,
        "Credential Access",
        ("T1003",),
        cmdline=r"sekurlsa|lsass.*(?:minidump|dump)|procdump\S*\s.*lsass|comsvcs\.dll.*minidump|ntdsutil.*ifm|mimikatz",
        benign=("authorised red-team or crash-dump collection",),
    ),
    ProcessRule(
        "webshell_child",
        "Web server process spawned a shell",
        85,
        "Persistence",
        ("T1505.003", "T1190"),
        parents=WEB_SERVERS,
        images=SHELLS,
        benign=("an application that legitimately shells out for maintenance",),
    ),
    ProcessRule(
        "remote_service_exec",
        "Remote service execution",
        70,
        "Lateral Movement",
        ("T1021.002", "T1569.002"),
        cmdline=r"psexesvc|\\\\[^\\\s]+\\admin\$|sc(?:\.exe)?\s+\\\\\S+\s+create",
        benign=("IT administrators using sanctioned remote tools",),
    ),
)

PERSISTENCE_RULES: tuple[ProcessRule, ...] = (
    ProcessRule(
        "scheduled_task",
        "Scheduled task created",
        60,
        "Persistence",
        ("T1053.005",),
        cmdline=r"schtasks(?:\.exe)?\s+.*/create",
        benign=("software installers and IT automation",),
    ),
    ProcessRule(
        "run_key",
        "Run key added",
        60,
        "Persistence",
        ("T1547.001",),
        cmdline=r"reg(?:\.exe)?\s+add\s+.*\\currentversion\\run",
        benign=("installers that register a tray application",),
    ),
    ProcessRule(
        "service_created",
        "Service created from the command line",
        60,
        "Persistence",
        ("T1543.003",),
        cmdline=r"\bsc(?:\.exe)?\s+create\b|new-service",
        benign=("installers and management agents",),
    ),
    ProcessRule(
        "wmi_subscription",
        "WMI event subscription",
        70,
        "Persistence",
        ("T1546.003",),
        cmdline=r"__eventfilter|commandlineeventconsumer|wmic\S*\s.*eventfilter",
    ),
    ProcessRule(
        "startup_folder",
        "File placed in a startup folder",
        55,
        "Persistence",
        ("T1547.001",),
        cmdline=r"start menu\\programs\\startup",
    ),
)


def _rule_findings(hunt: Hunt, rules: tuple[ProcessRule, ...], ctx: HuntContext) -> list[Finding]:
    grouped: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    for e in ctx.by_kind("process"):
        if e.image in ctx.config.trusted_processes:
            continue
        for rule in rules:
            if rule.matches(e):
                grouped[(rule.id, e.host, e.user)].append(e)
    by_id = {r.id: r for r in rules}
    findings: list[Finding] = []
    for (rule_id, host, user), events in sorted(grouped.items()):
        rule = by_id[rule_id]
        sample = events[0]
        findings.append(
            make_finding(
                hunt.id,
                f"{rule.title} on {host}",
                events,
                score=rule.score + min(10, 2 * (len(events) - 1)),
                tactic=rule.tactic,
                techniques=list(rule.techniques),
                explanation=f"{len(events)} matching process event(s). First: {sample.parent.rsplit(chr(92), 1)[-1] or 'unknown parent'} started {sample.image}: {sample.cmdline[:160]}",
                config=ctx.config,
                hosts=[host],
                users=[user],
                details={"rule": rule.id, "events": len(events)},
                benign=list(rule.benign),
            )
        )
    return findings


def _sigma(rules: tuple[ProcessRule, ...]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rule in rules:
        selection: dict[str, Any] = {}
        if rule.parents:
            selection["ParentImage|endswith"] = sorted("\\" + p for p in rule.parents)
        if rule.images:
            selection["Image|endswith"] = sorted("\\" + i for i in rule.images)
        if rule.cmdline:
            selection["CommandLine|re"] = "(?i)" + rule.cmdline
        out.append(
            {
                "title": rule.title,
                "id": rule.id,
                "status": "experimental",
                "description": f"Generated from a hunt. {rule.title}.",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {"selection": selection, "condition": "selection"},
                "falsepositives": list(rule.benign) or ["unknown"],
                "level": "critical"
                if rule.score >= 85
                else "high"
                if rule.score >= 70
                else "medium",
                "tags": [
                    "attack." + rule.tactic.lower().replace(" ", "_"),
                    *[f"attack.{t.lower()}" for t in rule.techniques],
                ],
            }
        )
    return out


class ProcessChainHunt(Hunt):
    id = "process_chains"
    name = "Suspicious process chains and commands"
    tactic = "Execution"
    techniques = (
        "T1059",
        "T1204.002",
        "T1027",
        "T1105",
        "T1218",
        "T1003",
        "T1505.003",
        "T1021.002",
    )
    required = ("process",)
    description = (
        "Parent and child relationships and command lines that ordinary software rarely produces: Office "
        "spawning shells, encoded or downloading commands, signed binaries running remote content, "
        "credential dumping, web servers spawning shells and remote service execution."
    )

    def run(self, ctx: HuntContext) -> list[Finding]:
        return _rule_findings(self, EXECUTION_RULES, ctx)

    def spl(self, t: Thresholds) -> str:
        parents = " OR ".join(f'ParentImage="*\\\\{p}"' for p in sorted(OFFICE))
        shells = " OR ".join(f'Image="*\\\\{s}"' for s in sorted(SHELLS))
        return f"index=sysmon EventCode=1 ({parents}) ({shells})\n| stats count values(CommandLine) as commands by host ParentImage Image"

    def kql(self, t: Thresholds) -> str:
        parents = ", ".join(f'"{p}"' for p in sorted(OFFICE))
        shells = ", ".join(f'"{s}"' for s in sorted(SHELLS))
        return f"DeviceProcessEvents\n| where InitiatingProcessFileName in~ ({parents}) and FileName in~ ({shells})\n| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine"

    def sigma(self, t: Thresholds) -> list[dict[str, Any]]:
        return _sigma(EXECUTION_RULES)


class PersistenceHunt(Hunt):
    id = "persistence"
    name = "Persistence mechanisms"
    tactic = "Persistence"
    techniques = ("T1053.005", "T1547.001", "T1543.003", "T1546.003")
    required = ("process",)
    description = "Command lines that install scheduled tasks, run keys, services, WMI subscriptions or startup items."

    def run(self, ctx: HuntContext) -> list[Finding]:
        return _rule_findings(self, PERSISTENCE_RULES, ctx)

    def spl(self, t: Thresholds) -> str:
        return 'index=sysmon EventCode=1 (CommandLine="*schtasks*/create*" OR CommandLine="*\\\\CurrentVersion\\\\Run*" OR CommandLine="*sc*create*")\n| stats count values(CommandLine) by host user'

    def kql(self, t: Thresholds) -> str:
        return (
            'DeviceProcessEvents\n| where ProcessCommandLine has_any ("schtasks", "\\\\CurrentVersion\\\\Run", "New-Service") and ProcessCommandLine has_any ("/create", "add", "New-Service")\n'
            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine"
        )

    def sigma(self, t: Thresholds) -> list[dict[str, Any]]:
        return _sigma(PERSISTENCE_RULES)


class RareProcessHunt(Hunt):
    id = "rare_process"
    name = "Rare processes (least-frequency stacking)"
    tactic = "Defense Evasion"
    techniques = ("T1036", "T1204")
    required = ("process",)
    description = (
        "Programs that run on very few hosts and were never seen during the baseline, especially from "
        "user-writable folders or with names that imitate system binaries."
    )

    def unavailable(self, ctx: HuntContext) -> str:
        return "" if ctx.baseline.has_processes else "no baseline process data to compare against"

    def run(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        seen: dict[str, list[Event]] = defaultdict(list)
        for e in ctx.by_kind("process"):
            if e.image and e.image not in ctx.config.trusted_processes:
                seen[e.image].append(e)
        findings: list[Finding] = []
        for image, events in sorted(seen.items()):
            hosts = {e.host for e in events}
            if len(hosts) > t.rare_max_hosts or image in ctx.baseline.process_hosts:
                continue
            path = events[0].process.replace("\\", "/").lower()
            writable = any(p in path for p in WRITABLE_PATHS)
            lookalike = next(
                (
                    n
                    for n in SYSTEM_NAMES
                    if n != image and edit_distance(image, n, 2) <= 2 and len(image) >= 6
                ),
                "",
            )
            score = 35 + (20 if writable else 0) + (30 if lookalike else 0)
            findings.append(
                make_finding(
                    self.id,
                    f"Rare process {image} on {len(hosts)} host(s)",
                    events,
                    score=score,
                    tactic=self.tactic,
                    techniques=list(self.techniques),
                    explanation=(
                        f"{image} ran {len(events)} time(s) on {len(hosts)} host(s) and never appeared in the baseline"
                        + ("; it runs from a user-writable folder" if writable else "")
                        + (f"; its name is close to {lookalike}" if lookalike else "")
                        + "."
                    ),
                    config=ctx.config,
                    hosts=sorted(hosts),
                    users=[e.user for e in events],
                    details={
                        "image": image,
                        "hosts": len(hosts),
                        "runs": len(events),
                        "user_writable_path": writable,
                        "lookalike_of": lookalike,
                    },
                    benign=[
                        "newly deployed software",
                        "a developer's own build output",
                        "an updated version that renamed its binary",
                    ],
                )
            )
        return findings

    def spl(self, t: Thresholds) -> str:
        return f'index=sysmon EventCode=1\n| eval image=lower(replace(Image, "^.*\\\\\\\\", ""))\n| stats dc(host) as hosts count by image\n| where hosts<={t.rare_max_hosts}\n| sort hosts count'

    def kql(self, t: Thresholds) -> str:
        return f"DeviceProcessEvents\n| summarize Hosts=dcount(DeviceName), Runs=count() by FileName\n| where Hosts <= {t.rare_max_hosts}\n| sort by Hosts asc, Runs asc"
