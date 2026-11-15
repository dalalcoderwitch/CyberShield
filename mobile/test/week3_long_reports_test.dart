import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/screens/report_screen.dart';

const _twentyThreeIds = <String>[
  'https_connection',
  'header_hsts',
  'header_csp',
  'header_x_content_type_options',
  'header_x_frame_options',
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
];

Map<String, dynamic> _finding(
  String id, {
  String status = 'passed',
  String severity = 'low',
  String confidence = 'medium',
  Object? evidence,
  String explanation = '',
  String recommendation = '',
  List<String>? limitations,
}) {
  final finding = <String, dynamic>{
    'check_id': id,
    'title': 'فحص $id',
    'status': status,
    'severity': severity,
    'confidence': confidence,
    'explanation': explanation,
    'recommendation': recommendation,
  };
  if (evidence != null) finding['evidence'] = evidence;
  if (limitations != null) finding['limitations'] = limitations;
  return finding;
}

ScanReport _report(List<Map<String, dynamic>> findings) {
  final counters = <String, int>{
    'passed': 0,
    'warning': 0,
    'not_verified': 0,
    'error': 0,
    'skipped': 0,
  };
  for (final finding in findings) {
    final status = finding['status'] as String;
    counters[status] = counters[status]! + 1;
  }
  return ScanReport.fromJson({
    'scan_id': 'week3-regression',
    'status': 'completed',
    'target_url': 'https://example.com',
    'scanned_at': '2026-11-15T12:00:00Z',
    'summary': {'total': findings.length, ...counters},
    'findings': findings,
    'notice': 'هذا تقييم أولي محدود.',
  });
}

Future<void> _show(WidgetTester tester, ScanReport report) async {
  await tester.pumpWidget(MaterialApp(home: ReportScreen(report: report)));
  await tester.pumpAndSettle();
}

Future<void> _findByScrolling(WidgetTester tester, String value) async {
  final finder = find.text(value);
  await tester.scrollUntilVisible(
    finder,
    300,
    scrollable: find.byType(Scrollable).first,
  );
  await tester.pumpAndSettle();
  expect(finder, findsOneWidget);
}

void main() {
  testWidgets('week3 report renders 23 cumulative checks without omissions', (
    tester,
  ) async {
    final findings = <Map<String, dynamic>>[
      for (var i = 0; i < _twentyThreeIds.length; i++)
        _finding(
          _twentyThreeIds[i],
          status: const [
            'passed',
            'warning',
            'not_verified',
            'error',
            'skipped',
          ][i % 5],
          evidence: {'check_index': i + 1},
        ),
    ];
    final report = _report(findings);
    expect(report.findings.length, 23);
    await _show(tester, report);
    expect(find.text('23'), findsOneWidget);
    await _findByScrolling(tester, 'فحص public_security_files');
    expect(tester.takeException(), isNull);
  });

  testWidgets('all five statuses have readable Arabic text', (tester) async {
    final statuses = ['passed', 'warning', 'not_verified', 'error', 'skipped'];
    final labels = ['اجتاز', 'تحذير', 'غير متحقق', 'خطأ', 'تم تخطيه'];
    final report = _report([
      for (var i = 0; i < statuses.length; i++)
        _finding('status_$i', status: statuses[i]),
    ]);
    await _show(tester, report);
    for (final label in labels) {
      await _findByScrolling(tester, label);
    }
    expect(tester.takeException(), isNull);
  });

  testWidgets('empty findings shows a useful message and does not crash', (
    tester,
  ) async {
    await _show(tester, _report([]));
    await _findByScrolling(tester, 'لا توجد نتائج فحص متاحة في هذا التقرير.');
    expect(tester.takeException(), isNull);
  });

  testWidgets('partial report retains not verified and skipped findings', (
    tester,
  ) async {
    final report = _report([
      _finding('cookie_secure', status: 'not_verified'),
      _finding('open_redirect', status: 'skipped'),
      _finding(
        'source_maps_exposure',
        status: 'warning',
        evidence: {'observed': 'public map reference'},
        explanation: 'الدليل محدود وليس تأكيداً لثغرة.',
        recommendation: 'راجع الملفات العامة.',
        limitations: ['لم يُختبر الاستغلال الفعلي.'],
      ),
    ]);
    expect(report.findings.first.status, 'not_verified');
    expect(report.findings[1].status, 'skipped');
    await _show(tester, report);
    await _findByScrolling(tester, 'فحص source_maps_exposure');
    await _findByScrolling(tester, 'راجع الملفات العامة.');
    expect(tester.takeException(), isNull);
  });

  testWidgets('long multiline explanation and recommendation remain readable', (
    tester,
  ) async {
    final explanation = List.filled(
      12,
      'سطر توضيحي طويل مع تفاصيل تقنية يجب عدم حذفها.',
    ).join('\n');
    final recommendation = List.filled(
      12,
      'توصية تفصيلية قابلة للقراءة حتى مع النصوص الطويلة.',
    ).join('\n');
    final report = _report([
      _finding(
        'sensitive_file_exposure',
        status: 'warning',
        explanation: explanation,
        recommendation: recommendation,
        evidence: {'paths': List.filled(12, '/public/sample.txt')},
        limitations: ['هذا فحص أولي فقط.'],
      ),
    ]);
    await _show(tester, report);
    await _findByScrolling(tester, explanation);
    await _findByScrolling(tester, recommendation);
    expect(tester.takeException(), isNull);
  });

  testWidgets('missing TLS and Headers groups does not hide week3 results', (
    tester,
  ) async {
    final report = _report([
      _finding('cookie_samesite'),
      _finding('cors_misconfiguration', status: 'not_verified'),
      _finding('directory_listing', status: 'passed'),
    ]);
    await _show(tester, report);
    await _findByScrolling(tester, 'فحص directory_listing');
    expect(tester.takeException(), isNull);
  });

  test(
    'Access and Disclosure fields preserve source status and confidence',
    () {
      final report = _report([
        _finding(
          'cors_misconfiguration',
          status: 'not_verified',
          severity: 'high',
          confidence: 'low',
          evidence: {'origin': 'https://example.org'},
          limitations: ['Insufficient evidence'],
        ),
        _finding(
          'server_information_disclosure',
          status: 'warning',
          severity: 'info',
          confidence: 'medium',
        ),
        _finding('open_redirect', status: 'skipped'),
      ]);
      expect(report.findings.map((finding) => finding.checkId).toList(), [
        'cors_misconfiguration',
        'server_information_disclosure',
        'open_redirect',
      ]);
      expect(report.findings.first.status, 'not_verified');
      expect(report.findings.first.severity, 'high');
      expect(report.findings.first.confidence, 'low');
      expect(report.findings.first.limitations, ['Insufficient evidence']);
      expect(report.findings[1].status, 'warning');
      expect(report.findings.last.status, 'skipped');
    },
  );
}
