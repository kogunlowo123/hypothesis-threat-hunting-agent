"""Adapters that turn raw telemetry records into :class:`Event`.

The field names below follow common public formats (Sysmon, CloudTrail and typical auth, DNS and flow
exports). Real exports differ by product and version, so validate an adapter against a sample of your own
data before trusting a hunt that depends on it. Missing optional fields stay empty rather than guessed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from huntagent.errors import TelemetryError
from huntagent.models import Event, IngestReport
from huntagent.security import normalize_domain, normalize_ip, normalize_name, redact

MAX_ATTR_LENGTH = 200


class NormalizeError(TelemetryError):
    """A record cannot be turned into an event. The message never contains record content."""


def _get(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _dig(record: dict[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def parse_time(value: Any) -> datetime:
    """Parse ISO 8601 strings and epoch seconds or milliseconds into UTC."""
    if isinstance(value, datetime):
        return (
            value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        )
    if isinstance(value, bool):
        raise NormalizeError("missing or invalid timestamp")
    if isinstance(value, (int, float)) or (
        isinstance(value, str) and re.fullmatch(r"\d+(\.\d+)?", value.strip())
    ):
        number = float(value)
        if number > 1e11:
            number /= 1000.0
        return datetime.fromtimestamp(number, tz=timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            raise NormalizeError("unrecognised timestamp") from exc
        return (
            moment.astimezone(timezone.utc)
            if moment.tzinfo
            else moment.replace(tzinfo=timezone.utc)
        )
    raise NormalizeError("missing or invalid timestamp")


def _event_id(source: str, record: dict[str, Any]) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return f"{source}:{hashlib.sha256(body.encode('utf-8')).hexdigest()[:14]}"


def _text(value: Any, limit: int = 4000) -> str:
    return redact(str(value))[:limit] if value is not None else ""


def _port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _count(value: Any) -> int | None:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _ip(value: Any) -> str:
    return (normalize_ip(str(value)) or "") if value else ""


def _attrs(**values: Any) -> dict[str, str]:
    return {k: str(v)[:MAX_ATTR_LENGTH] for k, v in values.items() if v not in (None, "")}


def sysmon(raw: dict[str, Any]) -> Event:
    """Sysmon-style records: event id 1 (process), 3 (network connection) and 22 (DNS query)."""
    nested = raw.get("EventData")
    data: dict[str, Any] = {**raw, **(nested if isinstance(nested, dict) else {})}
    event_id = _count(_get(data, "EventID", "event_id"))
    common = {
        "id": _event_id("sysmon", raw),
        "time": parse_time(_get(data, "UtcTime", "TimeCreated", "timestamp")),
        "source": "sysmon",
        "host": normalize_name(str(_get(data, "Computer", "Hostname", "host") or "")),
        "user": normalize_name(str(_get(data, "User", "user") or "")),
    }
    if event_id == 1:
        return Event(
            kind="process",
            process=_text(_get(data, "Image", "process"), 500),
            parent=_text(_get(data, "ParentImage", "parent"), 500),
            cmdline=_text(_get(data, "CommandLine", "cmdline")),
            attrs=_attrs(
                sha256=_get(data, "Hash", "sha256"), integrity=_get(data, "IntegrityLevel")
            ),
            **common,
        )
    if event_id == 3:
        return Event(
            kind="flow",
            process=_text(_get(data, "Image", "process"), 500),
            src_ip=_ip(_get(data, "SourceIp", "src_ip")),
            dst_ip=_ip(_get(data, "DestinationIp", "dst_ip")),
            dst_port=_port(_get(data, "DestinationPort", "dst_port")),
            bytes_out=_count(_get(data, "BytesSent", "bytes_out")),
            **common,
        )
    if event_id == 22:
        return Event(
            kind="dns",
            process=_text(_get(data, "Image", "process"), 500),
            domain=normalize_domain(str(_get(data, "QueryName", "domain") or "")) or "",
            query_type=str(_get(data, "QueryType", "qtype") or "").upper(),
            outcome="failure"
            if str(_get(data, "QueryStatus", "rcode") or "").upper() in {"NXDOMAIN", "3", "9003"}
            else "success",
            **common,
        )
    raise NormalizeError(f"unsupported Sysmon event id {event_id}")


def auth(raw: dict[str, Any]) -> Event:
    """Authentication records with a result of success or failure."""
    result = str(_get(raw, "result", "outcome", "status") or "").lower()
    if result in {"success", "succeeded", "ok", "accepted"}:
        outcome = "success"
    elif result in {"failure", "failed", "fail", "denied", "rejected"}:
        outcome = "failure"
    else:
        raise NormalizeError("unrecognised authentication result")
    return Event(
        id=_event_id("auth", raw),
        time=parse_time(_get(raw, "timestamp", "time", "@timestamp")),
        kind="auth",
        source="auth",
        host=normalize_name(str(_get(raw, "host", "hostname", "target_host") or "")),
        user=normalize_name(str(_get(raw, "user", "username", "account") or "")),
        outcome=outcome,
        src_ip=_ip(_get(raw, "src_ip", "source_ip", "client_ip")),
        attrs=_attrs(
            logon_type=_get(raw, "logon_type"),
            method=_get(raw, "method"),
            src_host=_get(raw, "src_host"),
        ),
    )


def dns(raw: dict[str, Any]) -> Event:
    """DNS resolver query logs."""
    domain = normalize_domain(str(_get(raw, "query", "domain", "qname") or ""))
    if domain is None:
        raise NormalizeError("invalid or missing query name")
    rcode = str(_get(raw, "rcode", "response_code") or "").upper()
    return Event(
        id=_event_id("dns", raw),
        time=parse_time(_get(raw, "timestamp", "time")),
        kind="dns",
        source="dns",
        host=normalize_name(str(_get(raw, "client", "host", "src_host") or "")),
        src_ip=_ip(_get(raw, "client_ip", "src_ip")),
        domain=domain,
        query_type=str(_get(raw, "qtype", "query_type") or "").upper(),
        outcome="failure" if rcode == "NXDOMAIN" else "success",
    )


def flow(raw: dict[str, Any]) -> Event:
    """Network flow records."""
    dst = _ip(_get(raw, "dst_ip", "destination_ip"))
    if not dst:
        raise NormalizeError("invalid or missing destination address")
    return Event(
        id=_event_id("flow", raw),
        time=parse_time(_get(raw, "timestamp", "start", "time")),
        kind="flow",
        source="flow",
        host=normalize_name(str(_get(raw, "src_host", "host") or "")),
        user=normalize_name(str(_get(raw, "user") or "")),
        src_ip=_ip(_get(raw, "src_ip", "source_ip")),
        dst_ip=dst,
        dst_port=_port(_get(raw, "dst_port", "destination_port")),
        bytes_out=_count(_get(raw, "bytes_out", "bytes_sent", "orig_bytes")),
        attrs=_attrs(
            proto=_get(raw, "proto", "protocol"), bytes_in=_get(raw, "bytes_in", "resp_bytes")
        ),
    )


def cloudtrail(raw: dict[str, Any]) -> Event:
    """CloudTrail-style management events."""
    api = _get(raw, "eventName")
    if not api:
        raise NormalizeError("missing event name")
    raw_identity = raw.get("userIdentity")
    identity: dict[str, Any] = raw_identity if isinstance(raw_identity, dict) else {}
    user = (
        identity.get("userName")
        or (identity.get("type") == "Root" and "root")
        or identity.get("principalId")
        or ""
    )
    mfa_raw = _dig(raw, "additionalEventData.MFAUsed")
    mfa = None if mfa_raw is None else str(mfa_raw).lower() in {"yes", "true"}
    if mfa is None:
        session_mfa = (
            _dig(identity, "sessionContext.attributes.mfaAuthenticated") if identity else None
        )
        mfa = None if session_mfa is None else str(session_mfa).lower() == "true"
    failed = (
        bool(raw.get("errorCode"))
        or str(_dig(raw, "responseElements.ConsoleLogin") or "").lower() == "failure"
    )
    return Event(
        id=_event_id("cloudtrail", raw),
        time=parse_time(_get(raw, "eventTime", "timestamp")),
        kind="cloud",
        source="cloudtrail",
        user=normalize_name(str(user)),
        outcome="failure" if failed else "success",
        src_ip=_ip(_get(raw, "sourceIPAddress")),
        api=str(api),
        mfa=mfa,
        attrs=_attrs(region=_get(raw, "awsRegion"), error=raw.get("errorCode")),
    )


def generic(raw: dict[str, Any]) -> Event:
    """Records already in the canonical event shape."""
    body = dict(raw)
    body.setdefault("id", _event_id("generic", raw))
    for key in ("cmdline", "process", "parent"):
        if isinstance(body.get(key), str):
            body[key] = redact(body[key])
    body["time"] = parse_time(body.get("time"))
    try:
        return Event.model_validate(body)
    except ValidationError as exc:
        raise NormalizeError("record does not match the event schema") from exc


NORMALIZERS: dict[str, Callable[[dict[str, Any]], Event]] = {
    "sysmon": sysmon,
    "auth": auth,
    "dns": dns,
    "flow": flow,
    "cloudtrail": cloudtrail,
    "generic": generic,
}


def normalize_lines(
    lines: Iterable[str],
    source: str,
    *,
    max_line_bytes: int = 200_000,
    max_events: int = 2_000_000,
) -> tuple[list[Event], IngestReport]:
    """Normalize JSON Lines. Bad lines are counted and described, never echoed and never fatal.

    Raises:
        TelemetryError: If ``source`` is unknown or the input has more than ``max_events`` records.
    """
    if source not in NORMALIZERS:
        raise TelemetryError(
            f"unknown source format {source!r}; choose from {', '.join(sorted(NORMALIZERS))}"
        )
    adapter = NORMALIZERS[source]
    report = IngestReport(source=source)
    events: list[Event] = []
    seen: set[str] = set()
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        report.lines += 1
        if report.lines > max_events:
            raise TelemetryError(f"input exceeds the limit of {max_events} records")

        def reject(reason: str, line: int = number) -> None:
            report.rejected += 1
            if len(report.errors) < 20:
                report.errors.append(f"line {line}: {reason}")

        if len(raw.encode("utf-8", errors="replace")) > max_line_bytes:
            reject(f"line exceeds {max_line_bytes} bytes")
            continue
        try:
            record = json.loads(raw)
        except ValueError:
            reject("not valid JSON")
            continue
        if not isinstance(record, dict):
            reject("not a JSON object")
            continue
        try:
            event = adapter(record)
        except NormalizeError as exc:
            reject(str(exc))
            continue
        except (ValidationError, ValueError, TypeError):
            reject("record does not match the expected format")
            continue
        if event.id in seen:
            continue
        seen.add(event.id)
        events.append(event)
        report.accepted += 1
    return events, report
