/// Only display plain, bounded, scanner-approved evidence. The UI is not a
/// substitute for server-side data minimization and sanitization.
class SafeEvidence {
  static const maxLength = 6000;
  static const forbidden = <String>[
    'set-cookie:', 'cookie:', 'authorization:', 'proxy-authorization:',
    'bearer ', 'password=', 'access_token=', 'refresh_token=', 'sessionid=',
    'session_token=', 'api_key=', 'secret=', 'private_key=',
    '-----begin private key-----',
  ];

  static String display(Object? evidence) {
    if (evidence == null) return '';
    // This scanner's approved evidence is a sanitized string. Never render
    // arbitrary JSON objects: their nested fields could contain raw cookies.
    if (evidence is! String) {
      return 'نوع الدليل غير متوقع؛ حُجب احترازياً لحماية البيانات.';
    }
    final raw = evidence;
    final lower = raw.toLowerCase();
    final secretAssignment = RegExp(r'\b(token|password|secret|session|cookie|api[_-]?key|credential)\s*[:=]', caseSensitive: false);
    if (forbidden.any(lower.contains) || secretAssignment.hasMatch(raw)) {
      return 'تم إخفاء الدليل لاحتمال احتوائه على معلومات حساسة. يرجى مراجعة مصدر التقرير.';
    }
    if (raw.length > maxLength) {
      return 'الدليل طويل جداً للعرض الآمن داخل التطبيق. راجعي التقرير في بيئة موثوقة.';
    }
    return raw;
  }
}
