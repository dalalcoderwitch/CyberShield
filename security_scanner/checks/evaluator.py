"""Interfaces for interpreting collected security evidence."""

from abc import ABC, abstractmethod

from .base import CheckDefinition
from .evidence import EvidenceCollection
from .result import CheckResult


class CheckEvaluator(ABC):
    """Base interface for evidence-only security evaluation.

    Evaluators receive collected observations, not a target URL,
    resolved IP addresses, HTTP sessions, or network access parameters.
    """

    def __init__(self, definition: CheckDefinition):
        if not isinstance(definition, CheckDefinition):
            raise TypeError("definition must be a CheckDefinition")

        self.definition = definition

    def evaluate(self, evidence: EvidenceCollection) -> CheckResult:
        """Validate inputs and output around the check-specific evaluator."""
        if not isinstance(evidence, EvidenceCollection):
            raise TypeError(
                "evidence must be an EvidenceCollection"
            )

        result = self._evaluate(evidence)

        if not isinstance(result, CheckResult):
            raise TypeError(
                "_evaluate must return a CheckResult"
            )

        if result.check_id != self.definition.check_id:
            raise ValueError(
                "Result check_id does not match evaluator definition"
            )

        return result

    def _not_verified_result(
        self,
        title: str,
        recommendation: str,
    ) -> CheckResult:
        """Return a non-judgmental result when no HTTP response exists."""
        return CheckResult(
            check_id=self.definition.check_id,
            title=title,
            status="not_verified",
            severity="info",
            confidence="low",
            evidence=(
                "\u0644\u0645 \u064a\u062a\u0645 "
                "\u0627\u0644\u062d\u0635\u0648\u0644 "
                "\u0639\u0644\u0649 \u0627\u0633\u062a\u062c\u0627\u0628\u0629 "
                "HTTP \u0642\u0627\u0628\u0644\u0629 "
                "\u0644\u0644\u0641\u062d\u0635."
            ),
            explanation=(
                "\u062a\u0639\u0630\u0631 "
                "\u0627\u0644\u062d\u0635\u0648\u0644 "
                "\u0639\u0644\u0649 \u0627\u0633\u062a\u062c\u0627\u0628\u0629 "
                "HTTP\u061b \u0644\u0630\u0644\u0643 "
                "\u0644\u0627 \u064a\u0645\u0643\u0646 "
                "\u0627\u0639\u062a\u0628\u0627\u0631 "
                "\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 "
                "\u0645\u0648\u062c\u0648\u062f\u0629 "
                "\u0623\u0648 \u0645\u0641\u0642\u0648\u062f\u0629."
            ),
            recommendation=recommendation,
            limitations=(
                "\u0644\u0645 \u062a\u062a\u0648\u0641\u0631 "
                "\u0627\u0633\u062a\u062c\u0627\u0628\u0629 HTTP "
                "\u0644\u062a\u0642\u064a\u064a\u0645 "
                "\u0647\u0630\u0627 \u0627\u0644\u0641\u062d\u0635.",
            ),
        )

    @abstractmethod
    def _evaluate(
        self,
        evidence: EvidenceCollection,
    ) -> CheckResult:
        """Interpret observations and return one normalized result."""
        raise NotImplementedError
