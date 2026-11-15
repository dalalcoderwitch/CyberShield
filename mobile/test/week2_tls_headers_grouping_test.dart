import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/screens/report_screen.dart';

ScanReport _report(List<String> ids, {int? reportedTotal}) {
  const statuses = <String>[
    'passed',
    'warning',
    'not_verified',
    'skipped',
    'error',
  ];
  final counts = <String, int>{
    'passed': 0,
    'warning': 0,
    'not_verified': 0,
    'error': 0,
    'skipped': 0,
  };
  final findings = <Map<String, Object?>>[];
  for (var i = 0; i < ids.length; i++) {
    final status = statuses[i % statuses.length];
    counts[status] = counts[status]! + 1;
    findings.add(<String, Object?>{
      'check_id': ids[i],
      'title': 'Check ${i + 1}',
      'status': status,
      'severity': 'low',
      'confidence': 'medium',
      'evidence': i.isEven ? null : <String, Object?>{'code': 200},
      'explanation': 'Short explanation ${i + 1}',
      'recommendation': 'Review the security configuration',
      'limitations': <String>[],
    });
  }
  return ScanReport.fromJson(<String, Object?>{
    'scan_id': 'week2-group-test',
    'status': 'completed',
    'target_url': 'https://example.com',
    'scanned_at': '2026-11-15T12:00:00Z',
    'summary': <String, int>{'total': reportedTotal ?? ids.length, ...counts},
    'findings': findings,
    'notice': 'Limited security assessment.',
  });
}

void main() {
  testWidgets('twelve checks display under TLS and Headers sections', (
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
    ]);

    await tester.pumpWidget(MaterialApp(home: ReportScreen(report: report)));
    await tester.pumpAndSettle();

    expect(report.findings.length, 12);
    await tester.scrollUntilVisible(
      find.text('اتصال HTTPS وشهادات TLS (6)'),
      250,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    expect(find.text('اتصال HTTPS وشهادات TLS (6)'), findsOneWidget);
    await tester.scrollUntilVisible(
      find.text('ترويسات الأمان (6)'),
      250,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    expect(find.text('ترويسات الأمان (6)'), findsOneWidget);
    // No finding has been removed or overwritten by grouping.
    expect(report.findings.map((f) => f.checkId).toSet().length, 12);
  });

  testWidgets('partial report keeps TLS, Header and unrelated findings', (
    tester,
  ) async {
    final report = _report(<String>[
      'tls_certificate_expiry',
      'header_referrer_policy',
      'dns_spf',
    ], reportedTotal: 12);
    await tester.pumpWidget(MaterialApp(home: ReportScreen(report: report)));
    await tester.pumpAndSettle();

    expect(report.summary['total'], 12);
    expect(report.findings.length, 3);
    await tester.scrollUntilVisible(
      find.text('اتصال HTTPS وشهادات TLS (1)'),
      250,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    expect(find.text('اتصال HTTPS وشهادات TLS (1)'), findsOneWidget);
    await tester.scrollUntilVisible(
      find.text('ترويسات الأمان (1)'),
      250,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    expect(find.text('ترويسات الأمان (1)'), findsOneWidget);
    await tester.scrollUntilVisible(
      find.text('فحوصات أخرى (1)'),
      250,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    expect(find.text('فحوصات أخرى (1)'), findsOneWidget);
  });

  test('malformed findings reject invalid JSON without assuming passed', () {
    final valid = _report(<String>['tls_certificate_chain']);
    expect(valid.findings.single.status, 'passed');
    expect(valid.findings.single.evidence, isNull);

    final invalid = valid.toJson();
    invalid['findings'] = <Object?>[null];
    expect(() => ScanReport.fromJson(invalid), throwsFormatException);
  });
}
