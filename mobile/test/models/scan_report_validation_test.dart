import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/scan_report.dart';

Map<String, dynamic> buildReport({
  List<Map<String, dynamic>> findings = const [],
}) {
  const statuses = ['passed', 'warning', 'not_verified', 'error', 'skipped'];

  final summary = <String, dynamic>{
    for (final status in statuses)
      status: findings.where((item) => item['status'] == status).length,
    'total': findings.length,
  };

  return {
    'scan_id': 'scan-validation-001',
    'status': 'completed',
    'target_url': 'https://example.com',
    'scanned_at': '2026-11-14T12:00:00Z',
    'summary': summary,
    'findings': findings,
    'limitations': [],
    'notice': 'CyberShield assessment',
  };
}

void main() {
  group('ScanReport validation', () {
    test('accepts an empty report with a valid structure', () {
      final report = ScanReport.fromJson(buildReport());

      expect(report.findings, isEmpty);
      expect(report.summary['total'], 0);
    });

    test('preserves all five finding statuses', () {
      const statuses = [
        'passed',
        'warning',
        'not_verified',
        'error',
        'skipped',
      ];

      final findings = statuses.map((status) {
        return <String, dynamic>{
          'check_id': 'check_$status',
          'title': 'Test $status',
          'status': status,
          'severity': 'info',
          'confidence': 'medium',
          'limitations': <String>[],
        };
      }).toList();

      final report = ScanReport.fromJson(buildReport(findings: findings));

      expect(report.findings.map((item) => item.status).toList(), statuses);
      expect(report.summary['total'], 5);
    });

    test('rejects a report missing findings', () {
      final json = buildReport()..remove('findings');

      expect(() => ScanReport.fromJson(json), throwsA(isA<FormatException>()));
    });

    test('rejects a report with a missing summary counter', () {
      final json = buildReport();
      (json['summary'] as Map<String, dynamic>).remove('skipped');

      expect(() => ScanReport.fromJson(json), throwsA(isA<FormatException>()));
    });

    test('rejects a finding with an invalid status type', () {
      final json = buildReport(
        findings: [
          {
            'check_id': 'https_connection',
            'title': 'HTTPS',
            'status': 123,
            'severity': 'info',
            'confidence': 'high',
          },
        ],
      );

      expect(() => ScanReport.fromJson(json), throwsA(isA<FormatException>()));
    });
  });
}
