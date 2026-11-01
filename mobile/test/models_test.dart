import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/finding.dart';
import 'package:mobile/models/scan_report.dart';

void main() {
  group('Finding model tests', () {
    test('should parse and serialize finding JSON', () {
      final json = <String, dynamic>{
        'check_id': 'https_connection',
        'title': 'HTTPS Connection',
        'status': 'passed',
        'severity': 'low',
        'confidence': 'high',
        'evidence': {
          'protocol': 'https',
        },
        'explanation': 'HTTPS connection was established.',
        'recommendation': 'Keep HTTPS enabled.',
        'limitations': [],
      };

      final finding = Finding.fromJson(json);

      expect(finding.checkId, 'https_connection');
      expect(finding.status, 'passed');
      expect(finding.confidence, 'high');
      expect(finding.evidence, {'protocol': 'https'});

      expect(finding.toJson(), equals(json));
    });
  });

  group('ScanReport model tests', () {
    test('should parse a complete scan report', () {
      final json = <String, dynamic>{
        'scan_id': 'scan-001',
        'status': 'completed',
        'target_url': 'https://example.com',
        'scanned_at': '2026-11-01T12:00:00Z',
        'summary': {
          'total': 1,
          'passed': 1,
          'warning': 0,
          'not_verified': 0,
          'error': 0,
          'skipped': 0,
        },
        'findings': [
          {
            'check_id': 'https_connection',
            'title': 'HTTPS Connection',
            'status': 'passed',
            'severity': 'low',
            'confidence': 'high',
            'evidence': {
              'protocol': 'https',
            },
            'explanation': 'HTTPS connection was established.',
            'recommendation': 'Keep HTTPS enabled.',
            'limitations': [],
          },
        ],
        'notice': 'This is a limited security assessment.',
      };

      final report = ScanReport.fromJson(json);

      expect(report.scanId, 'scan-001');
      expect(report.status, 'completed');
      expect(report.targetUrl, 'https://example.com');
      expect(report.findings.length, 1);
      expect(report.findings.first.checkId, 'https_connection');
      expect(report.summary['total'], 1);

      expect(report.toJson(), equals(json));
    });
  });
}
