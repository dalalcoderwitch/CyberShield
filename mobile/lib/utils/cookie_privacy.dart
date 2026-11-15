class CookiePrivacy {
  const CookiePrivacy._();

  static const String hidden = '[REDACTED]';

  // Raw Set-Cookie/Cookie header lines must never reach report widgets.
  static final RegExp _cookieHeader = RegExp(
    r'\b(Set-Cookie|Cookie)\s*:\s*[^\r\n]+',
    caseSensitive: false,
  );
  static final RegExp _bearerToken = RegExp(
    r'\bBearer\s+\S+',
    caseSensitive: false,
  );
  static final RegExp _assignment = RegExp(
    r'\b([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*([^;\s,]+)',
  );

  static const Set<String> _publicCookieAttributes = {
    'secure',
    'httponly',
    'samesite',
    'max-age',
    'expires',
    'path',
    'domain',
    'partitioned',
    'priority',
    'version',
  };

  static const Set<String> _sensitiveKeys = {
    'value',
    'cookievalue',
    'rawvalue',
    'raw',
    'rawcookie',
    'rawheader',
    'setcookie',
    'cookieheader',
    'token',
    'authtoken',
    'accesstoken',
    'refreshtoken',
    'session',
    'sessionid',
    'sessiontoken',
    'authorization',
    'secret',
    'password',
  };

  static String redactText(String input) {
    final noHeaders = input.replaceAllMapped(
      _cookieHeader,
      (match) => '${match.group(1)}: $hidden',
    );
    final noBearerTokens = noHeaders.replaceAll(_bearerToken, 'Bearer $hidden');
    return noBearerTokens.replaceAllMapped(_assignment, (match) {
      final key = match.group(1)!;
      if (_publicCookieAttributes.contains(key.toLowerCase())) {
        return match.group(0)!;
      }
      return '$key=$hidden';
    });
  }

  // Returns a new value; never mutates the JSON object received from Flask.
  static Object? redactEvidence(Object? evidence) {
    if (evidence is Map) {
      return evidence.map((key, value) {
        final keyText = key.toString();
        final normalizedKey = keyText.toLowerCase().replaceAll(
          RegExp(r'[^a-z0-9]'),
          '',
        );
        if (_sensitiveKeys.contains(normalizedKey)) {
          // Keep boolean flags, not potentially secret textual values.
          return MapEntry(key, value is bool ? value : hidden);
        }
        return MapEntry(key, redactEvidence(value));
      });
    }
    if (evidence is List) {
      return evidence.map(redactEvidence).toList();
    }
    if (evidence is String) {
      return redactText(evidence);
    }
    return evidence;
  }
}
