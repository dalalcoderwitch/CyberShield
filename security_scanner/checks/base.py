"""Metadata primitives for CyberShield security checks.

This module defines check metadata only. It does not execute checks,
perform network requests, or modify the existing scanner.
"""

from dataclasses import dataclass
import re


_CHECK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

_ALLOWED_CATEGORIES = frozenset(
    {
        "tls",
        "headers",
        "cookies",
        "access",
        "disclosure",
        "dns",
        "cache",
        "passive",
    }
)

_ALLOWED_PHASES = frozenset({"foundational", "expanded"})
_ALLOWED_IMPLEMENTATION_STATUSES = frozenset({"implemented", "planned"})


@dataclass(frozen=True)
class CheckDefinition:
    """Immutable metadata describing one security check."""

    check_id: str
    title: str
    category: str
    phase: str
    implementation_status: str

    def __post_init__(self):
        string_fields = {
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "phase": self.phase,
            "implementation_status": self.implementation_status,
        }

        for field_name, value in string_fields.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")

        if not _CHECK_ID_PATTERN.fullmatch(self.check_id):
            raise ValueError(f"Invalid check_id: {self.check_id!r}")

        if self.category not in _ALLOWED_CATEGORIES:
            raise ValueError(f"Unsupported category: {self.category!r}")

        if self.phase not in _ALLOWED_PHASES:
            raise ValueError(f"Unsupported phase: {self.phase!r}")

        if self.implementation_status not in _ALLOWED_IMPLEMENTATION_STATUSES:
            raise ValueError(
                "Unsupported implementation_status: "
                f"{self.implementation_status!r}"
            )

        if self.phase == "foundational":
            if self.implementation_status != "implemented":
                raise ValueError(
                    "Foundational checks must be marked as implemented"
                )

        if self.phase == "expanded":
            if self.implementation_status != "planned":
                raise ValueError(
                    "Expanded checks must remain planned in this catalog"
                )
