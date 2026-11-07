"""Validated result contract for a single security check."""

from dataclasses import dataclass, field
import re


_ALLOWED_STATUSES = frozenset(
    {
        "passed",
        "warning",
        "not_verified",
        "error",
        "skipped",
    }
)

_ALLOWED_SEVERITIES = frozenset({"info", "low", "medium", "high"})
_ALLOWED_CONFIDENCES = frozenset({"low", "medium", "high"})

_CHECK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True)
class CheckResult:
    """One interpreted finding using the existing report schema.

    Evidence must be a safe descriptive summary, not a raw response value.
    """

    check_id: str
    title: str
    status: str
    severity: str
    confidence: str
    evidence: str = field(repr=False)
    explanation: str
    recommendation: str
    limitations: tuple[str, ...] | list[str] = ()

    def __post_init__(self):
        required_text_fields = (
            "check_id",
            "title",
            "status",
            "severity",
            "confidence",
            "evidence",
            "explanation",
            "recommendation",
        )

        for field_name in required_text_fields:
            value = getattr(self, field_name)

            if not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string")

            if not value.strip():
                raise ValueError(f"{field_name} must not be empty")

        if not _CHECK_ID_PATTERN.fullmatch(self.check_id):
            raise ValueError(f"Invalid check_id: {self.check_id!r}")

        if self.status not in _ALLOWED_STATUSES:
            raise ValueError(f"Unsupported status: {self.status!r}")

        if self.severity not in _ALLOWED_SEVERITIES:
            raise ValueError(f"Unsupported severity: {self.severity!r}")

        if self.confidence not in _ALLOWED_CONFIDENCES:
            raise ValueError(f"Unsupported confidence: {self.confidence!r}")

        if not isinstance(self.limitations, (list, tuple)):
            raise TypeError("limitations must be a list or tuple")

        if not all(
            isinstance(item, str) and item.strip()
            for item in self.limitations
        ):
            raise ValueError(
                "Each limitation must be a non-empty string"
            )

        object.__setattr__(
            self,
            "limitations",
            tuple(self.limitations),
        )

    def to_dict(self) -> dict:
        """Return a fresh dictionary matching the existing report schema."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "limitations": list(self.limitations),
        }
