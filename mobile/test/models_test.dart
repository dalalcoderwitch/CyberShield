import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/finding.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/utils/check_categories.dart';
import 'package:mobile/utils/safe_evidence.dart';

Map<String, dynamic> fakeFinding(String id, {String status = 'passed'}) => {
      'check_id': id,
      'title': 'Test $id',
      'status': status,
      'severity': 'info',
      'confidence': 'medium',
      'evidence': 'Sanitized evidence',
      'explanation': 'Explanation',
      'recommendation': 'Recommendation',
      'limitations': <String>[],
    };

Map<String, dynamic> fakeReport(List<Map<String, dynamic>> findings) {
  final statuses = ['passed', 'warning', 'not_verified', 'error', 'skipped'];
  return {
    'scan_id': 'test-scan',
    'status': 'completed',
    'target_url': 'https://example.com',
    'scanned_at': '2026-11-14T00:00:00Z',
    'engine_version': '1.0.0',
    'summary': {
      'total': findings.length,
      for (final status in statuses)
        status: findings.where((f) => f['status'] == status).length,
    },
    'findings': findings,
    'limitations': <String>[],
    'notice': 'Limited security assessment',
  };
}

void main() {
  test('parses all five statuses without converting failures to passed', () {
    final statuses = ['passed', 'warning', 'not_verified', 'error', 'skipped'];
    final findings = [
      for (final status in statuses) fakeFinding(status, status: status)
    ];
    final report = ScanReport.fromJson(fakeReport(findings));
    expect(report.findings.map((f) => f.status).toList(), statuses);
  });

  test('parses partial, empty, 5, 12 and 23-result reports', () {
    for (final size in [0, 5, 12, 23]) {
      final f = [for (var i = 0; i < size; i++) fakeFinding('x$i')];
      expect(ScanReport.fromJson(fakeReport(f)).findings.length, size);
    }
  });

  test('rejects invalid required fields and contradictory totals', () {
    final json = fakeReport([fakeFinding('https_connection')]);
    (json['summary'] as Map<String, dynamic>)['total'] = 25;
    final partial = ScanReport.fromJson(json);
    expect(partial.summary['total'], 25);
    expect(partial.findings.length, 1);
    final invalid = fakeReport([fakeFinding('https_connection')]);
    ((invalid['findings'] as List).first as Map<String, dynamic>)['severity'] =
        42;
    expect(() => ScanReport.fromJson(invalid), throwsFormatException);
  });

  test('groups actual 23-check catalog without dropping findings', () {
    final ids = [
      'https_connection',
      'tls_certificate_expiry',
      'tls_certificate_chain',
      'tls_protocol_config',
      'http_to_https_redirect',
      'redirect_destination_safety',
      'header_hsts',
      'header_csp',
      'header_x_content_type_options',
      'header_x_frame_options',
      'header_referrer_policy',
      'header_permissions_policy',
      'cookie_secure',
      'cookie_httponly',
      'cookie_samesite',
      'cors_misconfiguration',
      'open_redirect',
      'sensitive_file_exposure',
      'source_maps_exposure',
      'directory_listing',
      'server_information_disclosure',
      'error_information_disclosure',
      'public_security_files',
    ];
    final findings =
        ids.map((id) => Finding.fromJson(fakeFinding(id))).toList();
    final groups = groupFindings(findings);
    expect(groups.keys.map((c) => c.id).toList(),
        ['tls', 'headers', 'cookies', 'access', 'disclosure']);
    expect(groups.values.map((f) => f.length).toList(), [6, 6, 3, 2, 6]);
    expect(groups.values.expand((x) => x).length, 23);
  });

  test('unknown check is retained and categorized under other', () {
    final groups = groupFindings([Finding.fromJson(fakeFinding('dns_spf'))]);
    expect(groups.keys.single.id, 'other');
  });

  test('raw cookie headers and token-like values are not displayed', () {
    expect(SafeEvidence.display('Set-Cookie: sessionid=1234; HttpOnly'),
        isNot(contains('1234')));
    expect(SafeEvidence.display('Authorization: Bearer abc'),
        isNot(contains('abc')));
  });
}
