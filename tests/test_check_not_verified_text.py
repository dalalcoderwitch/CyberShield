from security_scanner.checks.context import CheckContext
from security_scanner.checks.response_runner import (
    evaluate_shared_response_prototypes,
)


def test_not_verified_results_have_valid_arabic_text():
    context = CheckContext(
        safe_target_url="https://example.com",
        http_status=None,
    )

    results = evaluate_shared_response_prototypes(context)

    expected_titles = {
        "header_referrer_policy": "سياسة الإحالة (Referrer-Policy)",
        "header_permissions_policy": "سياسة صلاحيات المتصفح (Permissions-Policy)",
        "cache_security": "أمان التخزين المؤقت (Cache Security)",
    }

    assert len(results) == 3

    for result in results:
        assert result.status == "not_verified"
        assert result.title == expected_titles[result.check_id]

        text_fields = (
            result.title,
            result.evidence,
            result.explanation,
            result.recommendation,
            *result.limitations,
        )

        assert all("????" not in text for text in text_fields)
