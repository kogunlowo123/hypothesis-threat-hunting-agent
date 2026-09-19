"""Configuration: settings, thresholds, threat intelligence, allowlists, geography and suppressions."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from huntagent.errors import ConfigurationError
from huntagent.models import Suppression, Thresholds
from huntagent.security import normalize_domain, normalize_ip

MAX_FILE_BYTES = 2_000_000


class Settings(BaseSettings):
    """Runtime settings from ``HUNTAGENT_*`` environment variables and ``.env``."""

    model_config = SettingsConfigDict(
        env_prefix="HUNTAGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    thresholds_file: Path | None = None
    iocs_file: Path | None = None
    allowlist_file: Path | None = None
    geo_file: Path | None = None
    suppressions_file: Path | None = None
    max_line_bytes: int = Field(default=200_000, ge=1000)
    max_events: int = Field(default=2_000_000, ge=1)

    llm_provider: Literal["none", "openai", "anthropic"] = "none"
    openai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("HUNTAGENT_OPENAI_API_KEY", "OPENAI_API_KEY")
    )
    openai_base_url: str = "https://api.openai.com/v1"
    openai_chat_model: str = "gpt-4o-mini"
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("HUNTAGENT_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_model: str = "claude-sonnet-5"
    anthropic_max_tokens: int = Field(default=500, gt=0)

    http_timeout_seconds: float = Field(default=30.0, gt=0)
    retry_attempts: int = Field(default=3, ge=1)
    retry_min_wait: float = Field(default=0.5, ge=0)
    retry_max_wait: float = Field(default=8.0, ge=0)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "WARNING"
    log_json: bool = True

    @model_validator(mode="after")
    def _check_consistency(self) -> Settings:
        if self.retry_max_wait < self.retry_min_wait:
            raise ValueError("retry_max_wait must be >= retry_min_wait")
        return self


class Allowlist(BaseModel):
    """Known-benign infrastructure that hunts should not report."""

    model_config = ConfigDict(extra="forbid")

    destination_ips: list[str] = Field(default_factory=list)
    destination_domains: list[str] = Field(default_factory=list)
    scanner_ips: list[str] = Field(default_factory=list)
    trusted_processes: list[str] = Field(default_factory=list)
    noisy_users: list[str] = Field(default_factory=list)


class GeoEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str
    country: str = Field(pattern=r"^[A-Z]{2}$")


class Iocs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class HuntConfig:
    """Everything a hunt needs besides events."""

    thresholds: Thresholds = field(default_factory=Thresholds)
    ioc_ips: frozenset[str] = frozenset()
    ioc_domains: frozenset[str] = frozenset()
    ioc_hashes: frozenset[str] = frozenset()
    allow_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    allow_domains: tuple[str, ...] = ()
    scanner_ips: frozenset[str] = frozenset()
    trusted_processes: frozenset[str] = frozenset()
    noisy_users: frozenset[str] = frozenset()
    geo: tuple[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str], ...] = ()
    suppressions: tuple[Suppression, ...] = ()

    def country_of(self, ip: str) -> str:
        """Country for ``ip`` from the geography file, or an empty string when unknown."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        best = ""
        best_len = -1
        for network, country in self.geo:
            if (
                network.version == address.version
                and address in network
                and network.prefixlen > best_len
            ):
                best, best_len = country, network.prefixlen
        return best

    def is_allowed_destination(self, ip: str = "", domain: str = "") -> bool:
        if ip:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                address = None
            if address is not None and any(
                network.version == address.version and address in network
                for network in self.allow_networks
            ):
                return True
        if domain:
            return any(domain == d or domain.endswith("." + d) for d in self.allow_domains)
        return False


def _read(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ConfigurationError(f"{path.name} is larger than {MAX_FILE_BYTES} bytes")
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"cannot read {path.name}: {exc}") from exc


def _mapping(path: Path) -> dict[str, Any]:
    data = _read(path)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigurationError(f"{path.name} must contain a mapping at the top level")
    return data


def _network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError as exc:
        raise ConfigurationError(f"invalid address or network {text!r}") from exc


def load_config(
    *,
    thresholds_file: Path | None = None,
    iocs_file: Path | None = None,
    allowlist_file: Path | None = None,
    geo_file: Path | None = None,
    suppressions_file: Path | None = None,
) -> HuntConfig:
    """Load and validate every optional configuration file.

    Raises:
        ConfigurationError: If a file is unreadable or contains invalid values.
    """
    try:
        thresholds = (
            Thresholds.model_validate(_mapping(thresholds_file))
            if thresholds_file
            else Thresholds()
        )

        iocs = Iocs.model_validate(_mapping(iocs_file)) if iocs_file else Iocs()
        ioc_ips = frozenset(ip for v in iocs.ips if (ip := normalize_ip(v)))
        ioc_domains = frozenset(d for v in iocs.domains if (d := normalize_domain(v)))
        hashes = frozenset(h.strip().lower() for h in iocs.hashes if h.strip())

        allow = (
            Allowlist.model_validate(_mapping(allowlist_file)) if allowlist_file else Allowlist()
        )
        networks = tuple(_network(v) for v in allow.destination_ips)
        scanners = frozenset(ip for v in allow.scanner_ips if (ip := normalize_ip(v)))

        geo: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        if geo_file:
            document = _read(geo_file)
            entries = document.get("ranges") if isinstance(document, dict) else document
            if not isinstance(entries, list):
                raise ConfigurationError(f"{geo_file.name} must contain a list of ranges")
            geo = [
                (_network(g.cidr), g.country) for g in (GeoEntry.model_validate(e) for e in entries)
            ]

        suppressions: list[Suppression] = []
        if suppressions_file:
            document = _read(suppressions_file)
            entries = document.get("suppressions") if isinstance(document, dict) else document
            if entries is not None and not isinstance(entries, list):
                raise ConfigurationError(
                    f"{suppressions_file.name} must contain a list of suppressions"
                )
            suppressions = [Suppression.model_validate(e) for e in entries or []]
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "value"
        raise ConfigurationError(f"invalid configuration ({where}: {first['msg']})") from exc

    return HuntConfig(
        thresholds=thresholds,
        ioc_ips=ioc_ips,
        ioc_domains=ioc_domains,
        ioc_hashes=hashes,
        allow_networks=networks,
        allow_domains=tuple(d.lower().lstrip(".") for d in allow.destination_domains),
        scanner_ips=scanners,
        trusted_processes=frozenset(p.lower() for p in allow.trusted_processes),
        noisy_users=frozenset(u.lower() for u in allow.noisy_users),
        geo=tuple(geo),
        suppressions=tuple(suppressions),
    )


def config_from_settings(settings: Settings) -> HuntConfig:
    return load_config(
        thresholds_file=settings.thresholds_file,
        iocs_file=settings.iocs_file,
        allowlist_file=settings.allowlist_file,
        geo_file=settings.geo_file,
        suppressions_file=settings.suppressions_file,
    )
