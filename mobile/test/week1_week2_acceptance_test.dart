import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/screens/report_screen.dart';

const weekTwoIds = <String>[
  'https_connection',
  'header_hsts',
  'header_content_security_policy',
  'header_x_content_type_options',
  'header_x_frame_options',
  'tls_certificate_expiry',
  'tls_certificate_chain',
  'tls_protocol_config',
  'http_to_https_redirect',
  'redirect_destination_safety',
  'header_referrer_policy',
  'header_permissions_policy',
];

Map<String, dynamic> makeFinding(
  String id, {
  String status = 'passed',
  String severity = 'low',
  String confidence = 'high',
  String? explanation,
  String? recommendation,
}) => <String, dynamic>{
  'check_id': id,
  'title': 'Security check $id',
  'status': status,
  'severity': severity,
  'confidence': confidence,
  'evidence': <String, dynamic>{'check': id, 'observed': true},
  'explanation': explanation ?? 'A clear explanation for $id.',
  'recommendation': recommendation ?? 'A concrete recommendation for $id.',
  'limitations': <String>['Passive assessment only'],
};

Map<String, dynamic> makeReport(
  List<Map<String, dynamic>> findings, {
  int? declaredTotal,
}) => <String, dynamic>{
  'scan_id': 'week1-week2-acceptance',
  'status': 'completed',
  'target_url': 'https://example.com',
  'scanned_at': '2026-11-15T12:00:00Z',
  'summary': <String, int>{
    'total': declaredTotal ?? findings.length,
    'passed': findings.where((f) => f['status'] == 'passed').length,
    'warning': findings.where((f) => f['status'] == 'warning').length,
    'not_verified': findings.where((f) => f['status'] == 'not_verified').length,
    'error': findings.where((f) => f['status'] == 'error').length,
    'skipped': findings.where((f) => f['status'] == 'skipped').length,
  },
  'findings': findings,
  'notice': 'This is a limited security assessment.',
};

void main() {
  test('week 2: parses all 12 required checks and preserves detail fields', () {
    final json = makeReport([for (final id in weekTwoIds) makeFinding(id)]);
    final report = ScanReport.fromJson(json);

    expect(report.findings.length, 12);
    expect(report.findings.map((f) => f.checkId).toSet(), weekTwoIds.toSet());
    expect(report.summary['total'], 12);
    for (final finding in report.findings) {
      expect(finding.evidence, isA<Map>());
      expect(finding.explanation, isNotEmpty);
      expect(finding.recommendation, isNotEmpty);
      expect(finding.limitations, contains('Passive assessment only'));
      expect(finding.toJson()['status'], finding.status);
    }
  });

  test(
    'week 1: five outcomes remain distinct from severity and confidence',
    () {
      const statuses = <String>[
        'passed',
        'warning',
        'not_verified',
        'error',
        'skipped',
      ];
      final report = ScanReport.fromJson(
        makeReport([
          for (final status in statuses)
            makeFinding(
              'check_$status',
              status: status,
              severity: 'high',
              confidence: 'low',
            ),
        ]),
      );

      expect(report.findings.map((f) => f.status).toList(), statuses);
      expect(report.summary['total'], 5);
      for (final status in statuses) {
        expect(report.summary[status], 1);
      }
      for (final finding in report.findings) {
        expect(finding.severity, 'high');
        expect(finding.confidence, 'low');
      }
    },
  );

  test(
    'week 2: a partial report is not filled with invented passed checks',
    () {
      final report = ScanReport.fromJson(
        makeReport(<Map<String, dynamic>>[
          makeFinding('tls_certificate_expiry', status: 'not_verified'),
          makeFinding('header_referrer_policy', status: 'warning'),
        ], declaredTotal: 12),
      );

      expect(report.summary['total'], 12);
      expect(report.findings.length, 2);
      expect(
        report.findings.map((f) => f.status),
        orderedEquals(<String>['not_verified', 'warning']),
      );
    },
  );

  test('week 1: missing required summary counters are rejected', () {
    final json = makeReport([makeFinding('https_connection')]);
    (json['summary'] as Map<String, int>).remove('not_verified');

    expect(() => ScanReport.fromJson(json), throwsFormatException);
  });

  test('week 2: malformed finding fields and limitations are rejected', () {
    final badSeverity = makeReport([makeFinding('tls_certificate_chain')]);
    ((badSeverity['findings'] as List).first
            as Map<String, dynamic>)['severity'] =
        null;
    expect(() => ScanReport.fromJson(badSeverity), throwsFormatException);

    final badLimits = makeReport([makeFinding('header_permissions_policy')]);
    ((badLimits['findings'] as List).first
        as Map<String, dynamic>)['limitations'] = <Object>[
      'valid',
      7,
    ];
    expect(() => ScanReport.fromJson(badLimits), throwsFormatException);
  });

  testWidgets('week 1: all five statuses render in original report cards', (
    tester,
  ) async {
    const statuses = <String>[
      'passed',
      'warning',
      'not_verified',
      'error',
      'skipped',
    ];
    final report = ScanReport.fromJson(
      makeReport([
        for (final status in statuses)
          makeFinding('check_$status', status: status),
      ]),
    );
    await tester.pumpWidget(MaterialApp(home: ReportScreen(report: report)));
    await tester.pumpAndSettle();

    // The existing ListView may need scrolling for lower cards.
    final lastFinding = find.text('Security check check_skipped');
    await tester.scrollUntilVisible(
      lastFinding,
      280,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    expect(lastFinding, findsOneWidget);
    expect(find.text('تم تخطيه'), findsWidgets);
    expect(tester.takeException(), isNull);
  });
}
