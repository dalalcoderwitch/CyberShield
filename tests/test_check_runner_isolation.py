import security_scanner.checks.response_runner as response_runner
from security_scanner.checks.evidence import EvidenceCollection


def test_runner_isolates_failure_and_continues_other_checks(monkeypatch):
    original = response_runner._RESPONSE_EVALUATORS
    failed_check_id = original[0][0]

    class FailingEvaluator:
        def __init__(self, definition):
            self.definition = definition

        def evaluate(self, evidence):
            raise RuntimeError("SECRET_INTERNAL_ERROR_DETAILS")

    monkeypatch.setattr(
        response_runner,
        "_RESPONSE_EVALUATORS",
        (
            (failed_check_id, FailingEvaluator),
            *original[1:],
        ),
    )

    results = response_runner.evaluate_response_evidence_prototypes(
        EvidenceCollection(http_status=200)
    )

    assert len(results) == 3

    by_id = {result.check_id: result for result in results}
    failed = by_id[failed_check_id]

    assert failed.status == "error"
    assert failed.confidence == "low"
    assert "SECRET_INTERNAL_ERROR_DETAILS" not in repr(failed)
    assert "SECRET_INTERNAL_ERROR_DETAILS" not in str(failed.to_dict())

    # The other evaluators must still run.
    for check_id, _ in original[1:]:
        assert check_id in by_id
        assert by_id[check_id].status != "error"

    expected_fields = {
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
    assert set(failed.to_dict()) == expected_fields
