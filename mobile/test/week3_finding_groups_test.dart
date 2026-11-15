import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/screens/report_screen.dart';

ScanReport _report(List<String> ids, {int? total}) {
  final findings = <Map<String, Object?>>[];
  for (var i = 0; i < ids.length; i++) {
    findings.add(<String, Object?>{
      'check_id': ids[i],
      'title': 'Finding ${i + 1}',
      'status': i.isEven ? 'passed' : 'not_verified',
      'severity': 'low',
      'confidence': 'medium',
      'evidence': null,
      'explanation': '',
      'recommendation': '',
      'limitations': <String>[],
    });
  }
  return ScanReport.fromJson(<String, Object?>{
    'scan_id': 'week3-groups',
    'status': 'completed',
    'target_url': 'https://example.com',
    'scanned_at': '2026-11-15T12:00:00Z',
    'summary': <String, int>{
      'total': total ?? ids.length,
      'passed': (ids.length + 1) ~/ 2,
      'warning': 0,
      'not_verified': ids.length ~/ 2,
      'error': 0,
      'skipped': 0,
    },
    'findings': findings,
    'notice': 'Limited assessment.',
  });
}

Future<void> _see(WidgetTester tester, String title) async {
  final finder = find.text(title);
  await tester.scrollUntilVisible(
    finder,
    250,
    scrollable: find.byType(Scrollable).first,
    maxScrolls: 100,
  );
  await tester.pumpAndSettle();
  expect(finder, findsOneWidget);
}

void main() {
  testWidgets('week 3 groups 11 added findings into 3 categories', (
    tester,
  ) async {
    final report = _report(<String>[
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
    ]);
    await tester.pumpWidget(MaterialApp(home: ReportScreen(report: report)));
    await tester.pumpAndSettle();
    expect(report.findings.length, 11);
    await _see(tester, 'Cookies (3)');
    await _see(tester, 'Access (2)');
    await _see(tester, 'Disclosure (6)');
  });

  testWidgets('partial mixed report preserves previous and unknown groups', (
    tester,
  ) async {
    final report = _report(<String>[
      'tls_certificate_expiry',
      'header_referrer_policy',
      'cookie_secure',
      'open_redirect',
      'directory_listing',
      'dns_spf',
    ], total: 23);
    await tester.pumpWidget(MaterialApp(home: ReportScreen(report: report)));
    await tester.pumpAndSettle();
    expect(report.summary['total'], 23);
    expect(report.findings.length, 6);
    await _see(tester, 'اتصال HTTPS وشهادات TLS (1)');
    await _see(tester, 'ترويسات الأمان (1)');
    await _see(tester, 'Cookies (1)');
    await _see(tester, 'Access (1)');
    await _see(tester, 'Disclosure (1)');
    await _see(tester, 'فحوصات أخرى (1)');
  });

  testWidgets('full 23 findings remain accessible without hardcoded count', (
    tester,
  ) async {
    final report = _report(<String>[
      'https_connection',
      'header_hsts',
      'header_csp',
      'header_x_frame_options',
      'header_x_content_type_options',
      'tls_certificate_expiry',
      'tls_certificate_chain',
      'tls_protocol_config',
      'http_to_https_redirect',
      'redirect_destination_safety',
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
    ]);
    await tester.pumpWidget(MaterialApp(home: ReportScreen(report: report)));
    await tester.pumpAndSettle();
    expect(report.findings.length, 23);
    expect(report.findings.map((f) => f.checkId).toSet().length, 23);
    await _see(tester, 'Disclosure (6)');
    await _see(tester, 'Finding 23');
  });
}
