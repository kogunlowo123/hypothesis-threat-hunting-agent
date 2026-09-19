"""Network hunts: beaconing, DNS tunnelling, algorithmic domains and data exfiltration."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict

from huntagent.hunts.base import Hunt, HuntContext, is_off_hours, make_finding, registered_domain
from huntagent.models import Event, Finding, Thresholds
from huntagent.security import is_internal_ip
from huntagent.stats import coefficient_of_variation, intervals, robust_zscore, shannon_entropy


class BeaconingHunt(Hunt):
    id = "beaconing"
    name = "Periodic outbound connections (beaconing)"
    tactic = "Command and Control"
    techniques = ("T1071", "T1573")
    required = ("flow",)
    description = (
        "Implants often call home on a timer. Connections from one host to one external address and port "
        "at very regular intervals, with little jitter, are unusual for human-driven traffic."
    )

    def run(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        groups: dict[tuple[str, str, int | None], list[Event]] = defaultdict(list)
        for e in ctx.by_kind("flow"):
            if (
                not e.dst_ip
                or is_internal_ip(e.dst_ip)
                or ctx.config.is_allowed_destination(ip=e.dst_ip)
            ):
                continue
            groups[(e.host, e.dst_ip, e.dst_port)].append(e)
        findings: list[Finding] = []
        for (host, dst, port), events in sorted(
            groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or 0)
        ):
            if len(events) < t.beacon_min_connections:
                continue
            gaps = intervals([e.time.timestamp() for e in events])
            mean_gap = statistics.fmean(gaps)
            if mean_gap < t.beacon_min_interval_seconds:
                continue
            jitter = coefficient_of_variation(gaps)
            if jitter > t.beacon_max_jitter:
                continue
            new = dst not in ctx.baseline.host_destinations.get(host, set())
            regularity = 1 - jitter / t.beacon_max_jitter
            score = (
                50
                + int(25 * regularity)
                + min(15, (len(events) - t.beacon_min_connections) // 2)
                + (10 if new else 0)
            )
            findings.append(
                make_finding(
                    self.id,
                    f"Regular connections from {host} to {dst}:{port}",
                    events,
                    score=score,
                    tactic=self.tactic,
                    techniques=list(self.techniques),
                    explanation=(
                        f"{len(events)} connections about every {mean_gap:.0f} seconds with jitter {jitter:.2f} "
                        f"(threshold {t.beacon_max_jitter}). "
                        + (
                            "The host had never contacted this address before."
                            if new
                            else "The host has contacted this address before."
                        )
                    ),
                    config=ctx.config,
                    hosts=[host],
                    ips=[dst],
                    details={
                        "connections": len(events),
                        "mean_interval_seconds": round(mean_gap, 1),
                        "jitter": round(jitter, 3),
                        "new_destination": new,
                        "port": port,
                    },
                    benign=[
                        "software update checks",
                        "monitoring or backup agents",
                        "chat and mail clients polling",
                        "heartbeat services",
                    ],
                )
            )
        return findings

    def spl(self, t: Thresholds) -> str:
        return (
            'index=network sourcetype=flow NOT cidrmatch("10.0.0.0/8", dest_ip) NOT cidrmatch("172.16.0.0/12", dest_ip) NOT cidrmatch("192.168.0.0/16", dest_ip)\n'
            "| sort 0 _time\n"
            "| streamstats current=f last(_time) as prev by src_host dest_ip dest_port\n"
            "| eval gap=_time-prev\n"
            "| stats count avg(gap) as mean_gap stdev(gap) as sd_gap by src_host dest_ip dest_port\n"
            f"| eval jitter=sd_gap/mean_gap\n| where count>={t.beacon_min_connections} AND mean_gap>={t.beacon_min_interval_seconds} AND jitter<={t.beacon_max_jitter}"
        )

    def kql(self, t: Thresholds) -> str:
        return (
            'DeviceNetworkEvents\n| where RemoteIPType == "Public"\n| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc\n'
            "| extend Gap = datetime_diff('second', Timestamp, prev(Timestamp))\n| where DeviceName == prev(DeviceName) and RemoteIP == prev(RemoteIP) and RemotePort == prev(RemotePort)\n"
            f"| summarize Connections=count(), MeanGap=avg(Gap), SdGap=stdev(Gap) by DeviceName, RemoteIP, RemotePort\n"
            f"| extend Jitter = SdGap / MeanGap\n| where Connections >= {t.beacon_min_connections} and MeanGap >= {t.beacon_min_interval_seconds} and Jitter <= {t.beacon_max_jitter}"
        )


def _subdomain(domain: str) -> str:
    registered = registered_domain(domain)
    return domain[: -len(registered)].rstrip(".") if domain != registered else ""


class DnsTunnelHunt(Hunt):
    id = "dns_tunnel"
    name = "DNS tunnelling"
    tactic = "Command and Control"
    techniques = ("T1071.004", "T1048.003")
    required = ("dns",)
    description = (
        "Data smuggled through DNS shows up as many unique, long, random-looking subdomains of one domain "
        "queried by one host."
    )

    def run(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for e in ctx.by_kind("dns"):
            if not e.domain or ctx.config.is_allowed_destination(domain=e.domain):
                continue
            reg = registered_domain(e.domain)
            if e.domain != reg:
                groups[(e.host, reg)].append(e)
        findings: list[Finding] = []
        for (host, reg), events in sorted(groups.items()):
            subs = {_subdomain(e.domain) for e in events}
            if len(subs) < t.dns_min_subdomains:
                continue
            flat = [s.replace(".", "") for s in subs]
            entropy = statistics.fmean(shannon_entropy(s) for s in flat)
            length = statistics.fmean(len(s) for s in flat)
            if entropy < t.dns_min_entropy or length < t.dns_min_label_length:
                continue
            txt = sum(1 for e in events if e.query_type in {"TXT", "NULL", "CNAME"}) / len(events)
            score = (
                55
                + min(20, (len(subs) - t.dns_min_subdomains) // 5)
                + int(10 * min(1.0, (entropy - t.dns_min_entropy) / 1.0))
                + (10 if txt >= 0.5 else 0)
            )
            findings.append(
                make_finding(
                    self.id,
                    f"Possible DNS tunnel from {host} via {reg}",
                    events,
                    score=score,
                    tactic=self.tactic,
                    techniques=list(self.techniques),
                    explanation=(
                        f"{len(subs)} unique subdomains of {reg}, average entropy {entropy:.2f} bits per character "
                        f"and average length {length:.0f}."
                    ),
                    config=ctx.config,
                    hosts=[host],
                    domains=[reg],
                    details={
                        "unique_subdomains": len(subs),
                        "mean_entropy": round(entropy, 2),
                        "mean_length": round(length, 1),
                        "record_type_ratio": round(txt, 2),
                    },
                    benign=[
                        "CDN or antivirus reputation lookups that encode hashes in names",
                        "DNS-based blocklists and mail filters",
                    ],
                )
            )
        return findings

    def spl(self, t: Thresholds) -> str:
        return (
            'index=dns\n| eval reg=replace(query, "^.*?([^.]+\\.[^.]+)$", "\\1"), sub=replace(query, "\\.".reg."$", "")\n'
            "| eval sublen=len(sub)\n| stats dc(sub) as unique_subdomains avg(sublen) as mean_len by client reg\n"
            f"| where unique_subdomains>={t.dns_min_subdomains} AND mean_len>={t.dns_min_label_length}"
        )

    def kql(self, t: Thresholds) -> str:
        return (
            "DnsEvents\n| extend Reg = strcat_array(array_slice(split(Name, '.'), -2, -1), '.')\n| extend Sub = replace_string(Name, strcat('.', Reg), '')\n"
            f"| summarize Unique=dcount(Sub), MeanLen=avg(strlen(Sub)) by ClientIP, Reg\n| where Unique >= {t.dns_min_subdomains} and MeanLen >= {t.dns_min_label_length}"
        )


class DgaHunt(Hunt):
    id = "dga"
    name = "Algorithmically generated domains"
    tactic = "Command and Control"
    techniques = ("T1568.002",)
    required = ("dns",)
    description = (
        "Malware that generates domain names tries many random-looking names, most of which do not exist. "
        "A host with many distinct high-entropy failed lookups is a candidate."
    )

    def run(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        groups: dict[str, dict[str, list[Event]]] = defaultdict(lambda: defaultdict(list))
        for e in ctx.by_kind("dns"):
            if (
                e.outcome != "failure"
                or not e.domain
                or ctx.config.is_allowed_destination(domain=e.domain)
            ):
                continue
            groups[e.host][registered_domain(e.domain)].append(e)
        findings: list[Finding] = []
        for host, by_domain in sorted(groups.items()):
            if len(by_domain) < t.dga_min_nxdomain:
                continue
            labels = [d.split(".")[0] for d in by_domain]
            entropy = statistics.fmean(shannon_entropy(label) for label in labels)
            if entropy < t.dns_min_entropy - 0.4:
                continue
            events = [e for evs in by_domain.values() for e in evs]
            score = (
                50
                + min(25, (len(by_domain) - t.dga_min_nxdomain) // 3)
                + int(10 * min(1.0, max(0.0, entropy - 3.0)))
            )
            findings.append(
                make_finding(
                    self.id,
                    f"{host} looked up {len(by_domain)} random-looking domains that do not exist",
                    events,
                    score=score,
                    tactic=self.tactic,
                    techniques=list(self.techniques),
                    explanation=f"{len(by_domain)} distinct failed lookups with average label entropy {entropy:.2f}.",
                    config=ctx.config,
                    hosts=[host],
                    domains=sorted(by_domain)[:5],
                    details={"distinct_domains": len(by_domain), "mean_entropy": round(entropy, 2)},
                    benign=[
                        "misconfigured software with retired hostnames",
                        "typo-squatting scans by security tools",
                    ],
                )
            )
        return findings

    def spl(self, t: Thresholds) -> str:
        return (
            'index=dns rcode=NXDOMAIN\n| eval label=mvindex(split(query, "."), -2)\n| eval entropy=len(label)\n'
            f"| stats dc(query) as distinct_domains by client\n| where distinct_domains>={t.dga_min_nxdomain}"
        )

    def kql(self, t: Thresholds) -> str:
        return f"DnsEvents\n| where ResultCode == 3\n| summarize Distinct=dcount(Name) by ClientIP\n| where Distinct >= {t.dga_min_nxdomain}"


class ExfiltrationHunt(Hunt):
    id = "exfiltration"
    name = "Unusual outbound data volume"
    tactic = "Exfiltration"
    techniques = ("T1041", "T1048")
    required = ("flow",)
    description = (
        "A host sending far more data than usual, especially to a destination it has never contacted, "
        "may be exfiltrating data."
    )

    def run(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        totals: dict[tuple[str, str], list[Event]] = defaultdict(list)
        host_total: dict[str, int] = defaultdict(int)
        for e in ctx.by_kind("flow"):
            if (
                not e.bytes_out
                or not e.dst_ip
                or is_internal_ip(e.dst_ip)
                or ctx.config.is_allowed_destination(ip=e.dst_ip)
            ):
                continue
            totals[(e.host, e.dst_ip)].append(e)
            host_total[e.host] += e.bytes_out
        span_days = (
            max(1.0, (ctx.events[-1].time - ctx.events[0].time).total_seconds() / 86400)
            if ctx.events
            else 1.0
        )
        findings: list[Finding] = []
        for (host, dst), events in sorted(totals.items()):
            volume = sum(e.bytes_out or 0 for e in events)
            if volume < t.exfil_min_bytes:
                continue
            new = dst not in ctx.baseline.host_destinations.get(host, set())
            sample = ctx.baseline.host_daily_out.get(host, [])
            daily = host_total[host] / span_days
            z = robust_zscore(daily, sample)
            # A very steady baseline makes the deviation score explode, so also require a doubling.
            if sample and daily < 2 * statistics.median(sample):
                z = min(z, t.exfil_min_zscore - 0.01)
            if not new and z < t.exfil_min_zscore:
                continue
            off = sum(
                1 for e in events if is_off_hours(e.time, t.off_hours_start, t.off_hours_end)
            ) / len(events)
            score = (
                50
                + (15 if new else 0)
                + (15 if z >= t.exfil_min_zscore else 0)
                + (10 if off >= 0.5 else 0)
                + min(10, int(math.log10(volume / t.exfil_min_bytes + 1) * 10))
            )
            findings.append(
                make_finding(
                    self.id,
                    f"{host} sent {volume / 1_000_000:.0f} MB to {dst}",
                    events,
                    score=score,
                    tactic=self.tactic,
                    techniques=list(self.techniques),
                    explanation=(
                        f"{volume / 1_000_000:.0f} MB outbound to {dst}. "
                        + ("This destination is new for the host. " if new else "")
                        + (
                            f"The host's daily volume is {z:.1f} robust deviations above its baseline. "
                            if z
                            else ""
                        )
                        + ("Most of the traffic was outside business hours." if off >= 0.5 else "")
                    ).strip(),
                    config=ctx.config,
                    hosts=[host],
                    ips=[dst],
                    details={
                        "bytes_out": volume,
                        "new_destination": new,
                        "zscore": round(z, 2),
                        "off_hours_share": round(off, 2),
                    },
                    benign=[
                        "cloud backup or sync",
                        "software distribution",
                        "large legitimate uploads to a partner",
                    ],
                )
            )
        return findings

    def spl(self, t: Thresholds) -> str:
        return (
            'index=network sourcetype=flow NOT cidrmatch("10.0.0.0/8", dest_ip) NOT cidrmatch("172.16.0.0/12", dest_ip) NOT cidrmatch("192.168.0.0/16", dest_ip)\n'
            f"| stats sum(bytes_out) as bytes by src_host dest_ip\n| where bytes>={t.exfil_min_bytes}\n| sort - bytes"
        )

    def kql(self, t: Thresholds) -> str:
        return (
            'DeviceNetworkEvents\n| where RemoteIPType == "Public"\n| summarize Bytes=sum(SentBytes) by DeviceName, RemoteIP\n'
            f"| where Bytes >= {t.exfil_min_bytes}\n| sort by Bytes desc"
        )
