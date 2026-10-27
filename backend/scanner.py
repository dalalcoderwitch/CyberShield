"""واجهة مستقرة لاستدعاء محرك فحص CyberShield."""

from security_scanner.report import scan_target as _scan_target


def scan_target(target_url: str) -> dict:
    """
    تنفيذ الفحص وإرجاع التقرير الموحد.

    يجب على المستدعي تطبيق التحقق من الطلب وسياسة الهدف.
    يتولى محرك الفحص أيضًا التحقق من الرابط قبل الاتصال.
    """
    return _scan_target(target_url)