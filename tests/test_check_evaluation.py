from abc import ABC

import pytest

from security_scanner.checks.base import CheckDefinition
from security_scanner.checks.evidence import EvidenceCollection
from security_scanner.checks.evaluator import CheckEvaluator
from security_scanner.checks.result import CheckResult


def make_result(**overrides):
    values = {
        "check_id": "demo_check",
        "title": "Demo check",
        "status": "passed",
        "severity": "info",
        "confidence": "high",
        "evidence": "The expected response header was observed.",
        "explanation": "The observed value meets this check's rule.",
        "recommendation": "Keep the setting under review.",
        "limitations": ["Only the first response was evaluated."],
    }
    values.update(overrides)
    return CheckResult(**values)


def make_definition():
    return CheckDefinition(
        "demo_check",
        "Demo check",
        "passive",
        "expanded",
        "planned",
    )


def make_evidence():
    return EvidenceCollection(
        http_status=200,
        _headers={"X-Test": "observed"},
    )


@pytest.mark.parametrize(
    "status",
    ["passed", "warning", "not_verified", "error", "skipped"],
)
def test_check_result_accepts_existing_statuses(status):
    result = make_result(status=status)

    assert result.status == status


def test_check_result_rejects_unknown_status():
    with pytest.raises(ValueError, match="Unsupported status"):
        make_result(status="unknown")


def test_check_result_exports_exact_existing_report_schema():
    result = make_result()
    finding = result.to_dict()

    assert set(finding) == {
        "check_id",
        "title",
        "status",
        "severity",
        "confidence",
        "evidence",
        "explanation",
        "recommendation",
        "limitations",
    }

    assert isinstance(finding["evidence"], str)
    assert isinstance(finding["limitations"], list)


def test_check_result_returns_independent_output_dictionary():
    result = make_result()
    first = result.to_dict()
    first["limitations"].append("Changed outside the result")

    second = result.to_dict()

    assert second["limitations"] == [
        "Only the first response was evaluated."
    ]


def test_check_result_copies_limitations_and_is_immutable():
    limitations = ["First limitation"]
    result = make_result(limitations=limitations)

    limitations.append("Later change")

    assert result.limitations == ("First limitation",)

    with pytest.raises(AttributeError):
        result.status = "warning"


def test_check_result_repr_does_not_expose_evidence():
    result = make_result(evidence="sensitive-raw-value")

    assert "sensitive-raw-value" not in repr(result)


def test_check_result_rejects_invalid_id():
    with pytest.raises(ValueError, match="Invalid check_id"):
        make_result(check_id="Bad-ID")


def test_check_result_rejects_empty_required_text():
    with pytest.raises(ValueError, match="must not be empty"):
        make_result(explanation=" ")


def test_check_result_rejects_non_string_evidence():
    with pytest.raises(TypeError, match="evidence must be a string"):
        make_result(evidence=123)


def test_check_result_rejects_invalid_limitations():
    with pytest.raises(ValueError, match="non-empty string"):
        make_result(limitations=[""])


class DemoEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        return make_result(
            status="passed" if evidence.http_status == 200 else "warning"
        )


class WrongIdEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        return make_result(check_id="different_check")


class InvalidReturnEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        return {"status": "passed"}


def test_evaluator_receives_evidence_and_returns_check_result():
    evaluator = DemoEvaluator(make_definition())

    result = evaluator.evaluate(make_evidence())

    assert isinstance(result, CheckResult)
    assert result.check_id == "demo_check"
    assert result.status == "passed"


def test_evaluator_rejects_non_evidence_input():
    evaluator = DemoEvaluator(make_definition())

    with pytest.raises(TypeError, match="EvidenceCollection"):
        evaluator.evaluate(object())


def test_evaluator_rejects_result_for_another_check():
    evaluator = WrongIdEvaluator(make_definition())

    with pytest.raises(ValueError, match="does not match"):
        evaluator.evaluate(make_evidence())


def test_evaluator_rejects_non_result_output():
    evaluator = InvalidReturnEvaluator(make_definition())

    with pytest.raises(TypeError, match="must return a CheckResult"):
        evaluator.evaluate(make_evidence())


def test_evaluator_is_an_abstract_interface():
    with pytest.raises(TypeError):
        CheckEvaluator(make_definition())


@pytest.mark.parametrize(
    "severity",
    ["info", "low", "medium", "high"],
)
def test_check_result_accepts_existing_severity_levels(severity):
    result = make_result(severity=severity)

    assert result.severity == severity


@pytest.mark.parametrize(
    "severity",
    ["critical", "unknown"],
)
def test_check_result_rejects_unsupported_severity(severity):
    with pytest.raises(ValueError, match="Unsupported severity"):
        make_result(severity=severity)


@pytest.mark.parametrize(
    "confidence",
    ["low", "medium", "high"],
)
def test_check_result_accepts_existing_confidence_levels(confidence):
    result = make_result(confidence=confidence)

    assert result.confidence == confidence


@pytest.mark.parametrize(
    "confidence",
    ["info", "critical", "unknown"],
)
def test_check_result_rejects_unsupported_confidence(confidence):
    with pytest.raises(ValueError, match="Unsupported confidence"):
        make_result(confidence=confidence)
