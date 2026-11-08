"""واجهة ثابتة لدمج محرك الفحص مع Flask."""

from security_scanner.report import scan_target as _scan_target


def scan_target(
    target_url: str,
    resolved_target=None,
    deadline: float | None = None,
    include_expanded_checks: bool = False,
) -> dict:
    """تمرير خيارات الفحص إلى محرك التقرير مع الحفاظ على التوافق السابق."""
    if type(include_expanded_checks) is not bool:
        raise TypeError("include_expanded_checks must be a bool")

    kwargs = {}
    if resolved_target is not None:
        kwargs["resolved_target"] = resolved_target
    if deadline is not None:
        kwargs["deadline"] = deadline
    if include_expanded_checks:
        kwargs["include_expanded_checks"] = True

    return _scan_target(target_url, **kwargs)
