"""Exception hierarchy for huntagent."""

from __future__ import annotations


class HuntError(Exception):
    """Base class for errors raised deliberately by this package."""


class ConfigurationError(HuntError):
    """Settings or a configuration file are missing or invalid."""


class TelemetryError(HuntError):
    """Telemetry or configuration input cannot be read or fails validation."""


class ReportError(HuntError):
    """A report could not be rendered or written."""


class ProviderError(HuntError):
    """An external model provider returned an error or an unusable response."""


class TransientProviderError(ProviderError):
    """A provider failure worth retrying (timeouts, rate limits, 5xx)."""
