"""واجهة ثابتة لدمج محرك الفحص مع Flask."""

from security_scanner.report import scan_target as _scan_target


def scan_target(
    target_url: str,
    resolved_target=None,
    deadline: float | None = None,
) -> dict:
    """
    تمرير رابط الهدف ونتيجة التحقق الاختيارية إلى محرك التقرير.

    عند عدم توفير نتيجة تحقق مسبقة، يحافظ المحرك على سلوكه
    السابق ويتحقق من الهدف بنفسه.
    """
    if deadline is None:
        if resolved_target is None:
            return _scan_target(target_url)
        return _scan_target(
            target_url,
            resolved_target=resolved_target,
        )

    if resolved_target is None:
        return _scan_target(target_url, deadline=deadline)
    return _scan_target(
        target_url,
        resolved_target=resolved_target,
        deadline=deadline,
    )