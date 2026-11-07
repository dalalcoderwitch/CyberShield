"""Evidence collection without security interpretation."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .context import CheckContext, normalize_cookie_observations
from .disclosure_evidence import DisclosureEvidence, SERVER_HEADER_NAMES

from .limits import (
    MAX_RESPONSE_HEADER_BYTES,
    MAX_RESPONSE_HEADER_COUNT,
    response_header_size_bytes,
)
_PRIVATE_RESPONSE_HEADERS = {"set-cookie", "location"} | {name.lower() for name in SERVER_HEADER_NAMES}


@dataclass(frozen=True)
class EvidenceCollection:
    """Immutable snapshot of response observations.

    Header values are retained for evaluation but excluded from repr.
    This class does not decide whether any observation is secure.
    """

    http_status: int | None
    _headers: Mapping[str, tuple[str, ...]] = field(
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
        if self.tls_verified is not None and type(self.tls_verified) is not bool:
            raise TypeError("tls_verified must be a bool or None")
        if self.http_probe_status is not None and (
            type(self.http_probe_status) is not int
            or not 100 <= self.http_probe_status <= 599
        ):
            raise ValueError("http_probe_status must be between 100 and 599")
        if self.cors_probe_status is not None and (type(self.cors_probe_status) is not int or not 100 <= self.cors_probe_status <= 599):
            raise ValueError("cors_probe_status must be between 100 and 599")
        if self.cors_probe_error is not None and not isinstance(self.cors_probe_error, str):
            raise TypeError("cors_probe_error must be a string or None")
        if self.cors_probe_available is not None and type(self.cors_probe_available) is not bool:
            raise TypeError("cors_probe_available must be a bool or None")
        if not isinstance(self.cors_headers, Mapping):
            raise TypeError("cors_headers must be a mapping")
        normalized_cors = {}
        for name, values in self.cors_headers.items():
            if not isinstance(name, str) or name.lower() not in {
                "access-control-allow-origin", "access-control-allow-credentials",
                "access-control-allow-methods", "access-control-allow-headers", "vary",
            }:
                raise ValueError("cors_headers contains an unsupported header")
            if isinstance(values, str): values = (values,)
            if not isinstance(values, (tuple, list)) or not all(isinstance(v, str) for v in values):
                raise TypeError("CORS header values must be string sequences")
            normalized_cors.setdefault(name.lower(), []).extend(values)
        if normalized_cors and self.cors_probe_available is not True:
            raise ValueError("CORS headers require available probe evidence")
        object.__setattr__(self, "cors_headers", MappingProxyType({k: tuple(v) for k, v in normalized_cors.items()}))
        if not isinstance(self.redirect_location_values, (tuple, list)) or not all(isinstance(v, str) for v in self.redirect_location_values):
            raise TypeError("redirect_location_values must be a sequence of strings")
        if self.redirect_evidence_available is not None and type(self.redirect_evidence_available) is not bool:
            raise TypeError("redirect_evidence_available must be a bool or None")
        if self.redirect_location_values and self.redirect_evidence_available is not True:
            raise ValueError("redirect location values require available evidence")
        object.__setattr__(self, "redirect_location_values", tuple(self.redirect_location_values))
        if self.redirect_request_url is not None and (not isinstance(self.redirect_request_url, str) or len(self.redirect_request_url) > 2048):
            raise ValueError("redirect_request_url must be a bounded string or None")
        if self.disclosure_evidence is not None and not isinstance(self.disclosure_evidence, DisclosureEvidence):
            raise TypeError("disclosure_evidence must be sanitized evidence or None")
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
        if self.http_status is not None:
            if (
                type(self.http_status) is not int
                or not 100 <= self.http_status <= 599
            ):
                raise ValueError(
                    "http_status must be between 100 and 599"
                )

        if not isinstance(self._headers, Mapping):
            raise TypeError("_headers must be a mapping")

        normalized = {}
        header_count = 0
        header_bytes = 0

        for name, values in self._headers.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("Header names must be non-empty strings")

            # Raw cookie fields must never be retained in generic evidence.
            if name.lower() in _PRIVATE_RESPONSE_HEADERS:
                continue

            if isinstance(values, str):
                values = (values,)
            elif isinstance(values, (tuple, list)):
                values = tuple(values)
            else:
                raise TypeError(
                    "Header values must be strings or sequences of strings"
                )

            normalized_values = normalized.setdefault(name.lower(), [])

            for value in values:
                if not isinstance(value, str):
                    raise TypeError("Header values must be strings")

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

                normalized_values.append(value)

        immutable_headers = {
            name: tuple(values)
            for name, values in normalized.items()
        }

        object.__setattr__(
            self,
            "_headers",
            MappingProxyType(immutable_headers),
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
        object.__setattr__(self, "tls_metadata", MappingProxyType(dict(self.tls_metadata)))
        if not isinstance(self.redirect_dns_answers, (tuple, list)):
            raise TypeError("redirect_dns_answers must be a sequence")
        answers = tuple(self.redirect_dns_answers)
        if len(answers) > 32 or not all(isinstance(answer, str) for answer in answers):
            raise ValueError("redirect_dns_answers must contain at most 32 IP strings")
        object.__setattr__(self, "redirect_dns_answers", answers)

    @classmethod
    def from_context(cls, context: CheckContext):
        """Collect response observations from a validated context."""
        if not isinstance(context, CheckContext):
            raise TypeError("context must be a CheckContext")

        if not context.has_http_response:
            return cls(
                http_status=None,
                tls_metadata=context.tls_metadata,
                redirect_dns_answers=context.redirect_dns_answers,
                tls_verified=context.tls_verified,
                http_probe_status=context.http_probe_status,
                http_probe_error=context.http_probe_error,
                http_probe_location=context.http_probe_location,
                http_probe_request_url=context.http_probe_request_url,
                redirect_destination_url=context.redirect_destination_url,
                cookie_evidence_available=context.cookie_evidence_available,
                cookie_observations=context.cookie_observations,
                cors_probe_status=context.cors_probe_status,
                cors_probe_error=context.cors_probe_error,
                cors_probe_available=context.cors_probe_available,
                cors_headers=context.cors_headers,
                redirect_location_values=context.redirect_location_values,
                redirect_evidence_available=context.redirect_evidence_available,
                redirect_request_url=context.redirect_request_url,
                disclosure_evidence=context.disclosure_evidence,
            )

        return cls(
            http_status=context.http_status,
            _headers=context.response_headers,
            tls_metadata=context.tls_metadata,
            redirect_dns_answers=context.redirect_dns_answers,
            tls_verified=context.tls_verified,
            http_probe_status=context.http_probe_status,
            http_probe_error=context.http_probe_error,
            http_probe_location=context.http_probe_location,
            http_probe_request_url=context.http_probe_request_url,
            redirect_destination_url=context.redirect_destination_url,
            cookie_evidence_available=context.cookie_evidence_available,
            cookie_observations=context.cookie_observations,
            cors_probe_status=context.cors_probe_status,
            cors_probe_error=context.cors_probe_error,
            cors_probe_available=context.cors_probe_available,
            cors_headers=context.cors_headers,
            redirect_location_values=context.redirect_location_values,
            redirect_evidence_available=context.redirect_evidence_available,
            redirect_request_url=context.redirect_request_url,
            disclosure_evidence=context.disclosure_evidence,
        )

    def values_for_header(self, name: str) -> tuple[str, ...]:
        """Return raw observed values for evaluation only."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Header name must be a non-empty string")

        return self._headers.get(name.lower(), ())

    @property
    def header_names(self) -> tuple[str, ...]:
        """Return normalized header names without exposing their values."""
        return tuple(self._headers.keys())
