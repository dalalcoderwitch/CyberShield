"""Immutable, non-executing context for security check evaluation."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from math import isfinite
from types import MappingProxyType
from urllib.parse import urlsplit

from .limits import (
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADER_COUNT,
    response_header_size_bytes,
)
from .disclosure_evidence import DisclosureEvidence
from .disclosure_evidence import SERVER_HEADER_NAMES


_COOKIE_SAMESITE_STATES = frozenset(
    {"strict", "lax", "none", "missing", "invalid", "ambiguous"}
)
_PRIVATE_RESPONSE_HEADERS = {"set-cookie", "location"} | {name.lower() for name in SERVER_HEADER_NAMES}


def normalize_cookie_observations(available, observations):
    """Validate and retain only non-sensitive parsed cookie attributes."""
    if available is not None and type(available) is not bool:
        raise TypeError("cookie_evidence_available must be bool or None")
    if not isinstance(observations, (tuple, list)):
        raise TypeError("cookie_observations must be a sequence")
    if len(observations) > MAX_RESPONSE_HEADER_COUNT:
        raise ValueError("cookie_observations exceed maximum cookie count")
    normalized = []
    for observation in observations:
        if not isinstance(observation, (tuple, list)) or len(observation) != 3:
            raise ValueError("cookie observations must contain parsed attributes only")
        secure, httponly, samesite = observation
        if type(secure) is not bool or type(httponly) is not bool:
            raise TypeError("parsed cookie flags must be bools")
        if not isinstance(samesite, str) or samesite not in _COOKIE_SAMESITE_STATES:
            raise ValueError("cookie SameSite state is unsupported")
        normalized.append((secure, httponly, samesite))
    if normalized and available is not True:
        raise ValueError("cookie observations require available evidence")
    return tuple(normalized)


def _is_sanitized_https_origin(value: str) -> bool:
    """Validate the shape of a sanitized HTTPS reporting origin."""
    if not value or any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return False

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False

    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return False

    hostname = parsed.hostname

    if any(char.isspace() for char in hostname):
        return False

    try:
        hostname.encode("idna")
    except UnicodeError:
        return False

    return True


@dataclass(frozen=True)
class CheckContext:
    """Snapshot of the shared HTTP response and scan constraints.

    Raw response header values are retained only in memory for evaluation.
    They are excluded from repr and must never be copied into report evidence.
    """

    safe_target_url: str
    deadline: float | None = None
    http_status: int | None = None
    connection_error: str | None = None
    response_headers: Mapping[str, str] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    tls_metadata: Mapping[str, object] = field(default_factory=dict, repr=False, compare=False)
    redirect_dns_answers: tuple[str, ...] = field(default_factory=tuple, repr=False, compare=False)
    tls_verified: bool | None = None
    http_probe_status: int | None = None
    http_probe_error: str | None = field(default=None, repr=False, compare=False)
    http_probe_location: str | None = field(default=None, repr=False, compare=False)
    http_probe_request_url: str | None = field(default=None, repr=False, compare=False)
    redirect_destination_url: str | None = field(default=None, repr=False, compare=False)
    cookie_evidence_available: bool | None = None
    cookie_observations: tuple[tuple[bool, bool, str], ...] = field(
        default_factory=tuple, repr=False, compare=False
    )
    cors_probe_status: int | None = None
    cors_probe_error: str | None = field(default=None, repr=False, compare=False)
    cors_probe_available: bool | None = None
    cors_headers: Mapping[str, tuple[str, ...]] = field(default_factory=dict, repr=False, compare=False)
    redirect_location_values: tuple[str, ...] = field(default_factory=tuple, repr=False, compare=False)
    redirect_evidence_available: bool | None = None
    redirect_request_url: str | None = field(default=None, repr=False, compare=False)
    disclosure_evidence: DisclosureEvidence | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.safe_target_url, str):
            raise TypeError("safe_target_url must be a string")

        if not _is_sanitized_https_origin(self.safe_target_url):
            raise ValueError(
                "safe_target_url must be a sanitized HTTPS origin"
            )

        if self.deadline is not None:
            if (
                isinstance(self.deadline, bool)
                or not isinstance(self.deadline, (int, float))
                or not isfinite(self.deadline)
            ):
                raise ValueError("deadline must be a finite number or None")

        if self.http_status is not None:
            if (
                type(self.http_status) is not int
                or not 100 <= self.http_status <= 599
            ):
                raise ValueError("http_status must be between 100 and 599")

        if self.tls_verified is not None and type(self.tls_verified) is not bool:
            raise TypeError("tls_verified must be a bool or None")
        if self.http_probe_status is not None and (
            type(self.http_probe_status) is not int
            or not 100 <= self.http_probe_status <= 599
        ):
            raise ValueError("http_probe_status must be between 100 and 599")
        if self.cors_probe_status is not None and (
            type(self.cors_probe_status) is not int or not 100 <= self.cors_probe_status <= 599
        ):
            raise ValueError("cors_probe_status must be between 100 and 599")
        if self.cors_probe_error is not None and not isinstance(self.cors_probe_error, str):
            raise TypeError("cors_probe_error must be a string or None")
        if self.cors_probe_available is not None and type(self.cors_probe_available) is not bool:
            raise TypeError("cors_probe_available must be a bool or None")
        if not isinstance(self.cors_headers, Mapping):
            raise TypeError("cors_headers must be a mapping")
        normalized_cors = {}
        cors_count = 0
        cors_bytes = 0
        for name, values in self.cors_headers.items():
            if not isinstance(name, str) or name.lower() not in {
                "access-control-allow-origin", "access-control-allow-credentials",
                "access-control-allow-methods", "access-control-allow-headers", "vary",
            }:
                raise ValueError("cors_headers contains an unsupported header")
            if isinstance(values, str):
                values = (values,)
            if not isinstance(values, (tuple, list)) or not all(isinstance(v, str) for v in values):
                raise TypeError("CORS header values must be string sequences")
            key = name.lower()
            normalized_cors.setdefault(key, []).extend(values)
            for value in values:
                cors_count += 1
                cors_bytes += response_header_size_bytes(name, value)
                if cors_count > MAX_RESPONSE_HEADER_COUNT or cors_bytes > MAX_RESPONSE_HEADER_BYTES:
                    raise ValueError("CORS evidence exceeds response header limits")
        if normalized_cors and self.cors_probe_available is not True:
            raise ValueError("CORS headers require available probe evidence")
        object.__setattr__(self, "cors_headers", MappingProxyType({k: tuple(v) for k, v in normalized_cors.items()}))
        if not isinstance(self.redirect_location_values, (tuple, list)) or not all(isinstance(v, str) for v in self.redirect_location_values):
            raise TypeError("redirect_location_values must be a sequence of strings")
        if self.redirect_evidence_available is not None and type(self.redirect_evidence_available) is not bool:
            raise TypeError("redirect_evidence_available must be a bool or None")
        if self.redirect_location_values and self.redirect_evidence_available is not True:
            raise ValueError("redirect location values require available evidence")
        if len(self.redirect_location_values) > MAX_RESPONSE_HEADER_COUNT or any(len(v) > 8192 for v in self.redirect_location_values):
            raise ValueError("redirect_location_values exceed limits")
        object.__setattr__(self, "redirect_location_values", tuple(self.redirect_location_values))
        if self.redirect_request_url is not None and (not isinstance(self.redirect_request_url, str) or len(self.redirect_request_url) > 2048):
            raise ValueError("redirect_request_url must be a bounded string or None")
        if self.disclosure_evidence is not None and not isinstance(self.disclosure_evidence, DisclosureEvidence):
            raise TypeError("disclosure_evidence must be a sanitized DisclosureEvidence or None")
        for field_name in (
            "http_probe_error",
            "http_probe_location",
            "http_probe_request_url",
            "redirect_destination_url",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string or None")
        if self.http_probe_location is not None and len(self.http_probe_location) > 8192:
            raise ValueError("http_probe_location exceeds maximum length")
        for field_name in ("http_probe_request_url", "redirect_destination_url"):
            value = getattr(self, field_name)
            if value is not None and len(value) > 2048:
                raise ValueError(f"{field_name} exceeds maximum length")

        if (
            self.connection_error is not None
            and not isinstance(self.connection_error, str)
        ):
            raise TypeError("connection_error must be a string or None")

        if not isinstance(self.response_headers, Mapping):
            raise TypeError("response_headers must be a mapping")

        copied_headers = {}
        header_count = 0
        header_bytes = 0

        for name, value in self.response_headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise TypeError("header names and values must be strings")

            if not name.strip():
                raise ValueError("Header names must not be empty")

            # Set-Cookie values can contain credentials. They travel only as
            # parsed flags in cookie_observations and never enter generic evidence.
            if name.lower() in _PRIVATE_RESPONSE_HEADERS:
                continue

            header_count += 1
            if header_count > MAX_RESPONSE_HEADER_COUNT:
                raise ValueError(
                    "response headers exceed maximum header count"
                )

            header_bytes += response_header_size_bytes(name, value)
            if header_bytes > MAX_RESPONSE_HEADER_BYTES:
                raise ValueError(
                    "response headers exceed maximum byte limit"
                )

            copied_headers[name] = value

        object.__setattr__(
            self,
            "response_headers",
            MappingProxyType(copied_headers),
        )
        object.__setattr__(
            self,
            "cookie_observations",
            normalize_cookie_observations(
                self.cookie_evidence_available,
                self.cookie_observations,
            ),
        )

        if not isinstance(self.tls_metadata, Mapping):
            raise TypeError("tls_metadata must be a mapping")
        # Retain only non-sensitive, typed handshake observations.
        allowed_tls = {"version", "cipher", "not_before", "not_after", "chain_available"}
        copied_tls = {key: value for key, value in self.tls_metadata.items() if key in allowed_tls}
        object.__setattr__(self, "tls_metadata", MappingProxyType(copied_tls))
        if not isinstance(self.redirect_dns_answers, (tuple, list)):
            raise TypeError("redirect_dns_answers must be a sequence")
        answers = tuple(self.redirect_dns_answers)
        if len(answers) > 32 or not all(isinstance(answer, str) for answer in answers):
            raise ValueError("redirect_dns_answers must contain at most 32 IP strings")
        object.__setattr__(self, "redirect_dns_answers", answers)

    @property
    def has_http_response(self) -> bool:
        """Whether a successful HTTP response was obtained."""
        return (
            self.http_status is not None
            and self.connection_error is None
        )
