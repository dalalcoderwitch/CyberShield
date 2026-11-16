import '../models/finding.dart';

class CheckCategory {
  const CheckCategory(this.id, this.label, this.icon, this.checkIds);

  final String id;
  final String label;
  final String icon;
  final Set<String> checkIds;
}

const categories = [
  CheckCategory('tls', 'TLS والاتصال الآمن', 'lock', {
    'https_connection',
    'tls_certificate_expiry',
    'tls_certificate_chain',
    'tls_protocol_config',
    'http_to_https_redirect',
    'redirect_destination_safety',
  }),
  CheckCategory('headers', 'ترويسات الحماية', 'shield', {
    'header_hsts',
    'header_csp',
    'header_x_content_type_options',
    'header_x_frame_options',
    'header_referrer_policy',
    'header_permissions_policy',
  }),
  CheckCategory('cookies', 'أمان ملفات Cookies', 'cookie', {
    'cookie_secure',
    'cookie_httponly',
    'cookie_samesite',
  }),
  CheckCategory('access', 'صلاحيات الوصول والتحويلات', 'route', {
    'cors_misconfiguration',
    'open_redirect',
  }),
  CheckCategory('disclosure', 'كشف المعلومات', 'description', {
    'sensitive_file_exposure',
    'source_maps_exposure',
    'directory_listing',
    'server_information_disclosure',
    'error_information_disclosure',
    'public_security_files',
  }),
  CheckCategory('dns', 'أمان DNS', 'dns', {
    'dns_spf',
    'dns_dmarc',
    'dnssec',
    'subdomain_takeover_indicators',
  }),
  CheckCategory('cache', 'أمان التخزين المؤقت', 'storage', {
    'cache_security',
  }),
  CheckCategory('passive', 'المؤشرات السلبية', 'visibility', {
    'xss_passive_indicators',
    'sqli_passive_indicators',
  }),
  CheckCategory('other', 'فحوص إضافية', 'more', {}),
];

Map<CheckCategory, List<Finding>> groupFindings(
  List<Finding> findings,
) {
  final result = <CheckCategory, List<Finding>>{
    for (final category in categories) category: <Finding>[],
  };

  for (final finding in findings) {
    final matching = categories.where(
      (category) => category.checkIds.contains(finding.checkId),
    );

    final group = matching.isEmpty ? categories.last : matching.first;
    result[group]!.add(finding);
  }

  // Preserve input order inside categories; omit empty categories.
  result.removeWhere((_, value) => value.isEmpty);

  return result;
}
