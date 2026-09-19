"""Secret redaction, observable validation and output escaping."""

from __future__ import annotations

import ipaddress
import re

REDACTION = "[REDACTED]"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END "
        r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    re.compile(
        r"(?i)(?:^|[\s\"'/-])(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?"
        r"(?!\[REDACTED\])[^\s'\",;]{4,}"
    ),
)
_ARG_SECRET = re.compile(
    r"(?i)(?P<flag>(?:--?)(?:password|passwd|pwd|pass|token|secret|apikey|api-key))(?P<sep>[\s=:]+)"
    r"(?P<value>(?!\[REDACTED\])[^\s'\"]+)"
)
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


def redact(text: str) -> str:
    """Replace credential-shaped substrings, including secrets passed as command-line arguments."""
    text = _ARG_SECRET.sub(lambda m: f"{m['flag']}{m['sep']}{REDACTION}", text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_replace, text)
    return text


def _replace(match: re.Match[str]) -> str:
    value = match.group(0)
    key = re.search(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]", value)
    if key:
        return f"{value[: key.end()]} {REDACTION}"
    return REDACTION


def normalize_ip(value: str) -> str | None:
    """Canonical form of an IP address, or ``None`` if invalid."""
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def is_internal_ip(value: str) -> bool:
    """True for RFC 1918, loopback, link-local and IPv6 unique-local addresses.

    Documentation and benchmarking ranges count as external, unlike ``ipaddress.is_private``.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in network for network in _INTERNAL_NETWORKS if network.version == ip.version)


def normalize_domain(value: str) -> str | None:
    """Lowercase DNS name without a trailing dot, or ``None`` if it is not a plausible domain."""
    candidate = value.strip().lower().rstrip(".")
    return candidate if _DOMAIN.match(candidate) else None


def normalize_name(value: str) -> str:
    """Lowercase host or user name, dropping a Windows domain prefix or an e-mail suffix."""
    text = value.strip().lower()
    if "\\" in text:
        text = text.rsplit("\\", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text


def slugify(text: str) -> str:
    """Lowercase ``text`` into a filename- and identifier-safe slug."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "item"


def md_cell(value: object) -> str:
    """Make ``value`` safe inside a Markdown table cell (no pipes, markup or line breaks)."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|").strip()


def md_code(value: object) -> str:
    """Inline code for a Markdown table cell. Backticks, pipes and line breaks are neutralised."""
    text = " ".join(str(value).replace("`", "'").split())
    return "`" + text.replace("|", "\\|") + "`"


def csv_safe(value: object) -> str:
    """Neutralise spreadsheet formula injection by prefixing risky cells with a quote."""
    text = str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text
