import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/main.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/services/scan_api_service.dart';

class _FakeScanService extends ScanApiService {
  int calls = 0;
  String? lastTarget;
  bool? lastAuthorization;
  Future<ScanReport> Function()? response;

  @override
  Future<ScanReport> scan({
    required String targetUrl,
    required bool authorizationConfirmed,
  }) {
    calls++;
    lastTarget = targetUrl;
    lastAuthorization = authorizationConfirmed;
    return response!();
  }
}

ScanReport _sampleReport() => ScanReport.fromJson({
  'scan_id': 'home-widget-test',
  'status': 'completed',
  'target_url': 'https://example.com',
  'scanned_at': '2026-11-15T12:00:00Z',
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
      'evidence': {'protocol': 'https'},
      'explanation': 'HTTPS connected',
      'recommendation': 'Keep HTTPS enabled',
      'limitations': <String>[],
    },
  ],
  'notice': 'Limited assessment',
});

Future<void> _prepareForm(WidgetTester tester, _FakeScanService service) async {
  await tester.pumpWidget(
    MaterialApp(
      home: Directionality(
        textDirection: TextDirection.rtl,
        child: HomeScreen(scanApiService: service),
      ),
    ),
  );
  await tester.enterText(find.byType(TextField), 'https://example.com');
  await tester.ensureVisible(find.byType(CheckboxListTile));
  await tester.tap(find.byType(CheckboxListTile));
  await tester.pump();
  await tester.ensureVisible(find.text('بدء الفحص الأمني'));
}

void main() {
  testWidgets('authorized valid URL sends one request then shows report', (
    tester,
  ) async {
    final service = _FakeScanService();
    service.response = () async => _sampleReport();
    await _prepareForm(tester, service);

    await tester.tap(find.text('بدء الفحص الأمني'));
    await tester.pumpAndSettle();

    expect(service.calls, 1);
    expect(service.lastTarget, 'https://example.com');
    expect(service.lastAuthorization, isTrue);
    expect(find.text('تقرير الفحص'), findsOneWidget);
    service.dispose();
  });

  testWidgets('scan button disables during request to prevent double scan', (
    tester,
  ) async {
    final service = _FakeScanService();
    final pending = Completer<ScanReport>();
    service.response = () => pending.future;
    await _prepareForm(tester, service);

    await tester.tap(find.text('بدء الفحص الأمني'));
    await tester.pump();

    expect(service.calls, 1);
    expect(find.text('جارٍ تنفيذ الفحص...'), findsOneWidget);
    final button = tester.widget<FilledButton>(
      find.byWidgetPredicate((widget) => widget is FilledButton),
    );
    expect(button.onPressed, isNull);

    pending.complete(_sampleReport());
    await tester.pumpAndSettle();
    expect(service.calls, 1);
    expect(find.text('تقرير الفحص'), findsOneWidget);
    service.dispose();
  });

  testWidgets('server failure shows user message and re-enables scan', (
    tester,
  ) async {
    final service = _FakeScanService();
    service.response = () async => throw const ApiException(
      code: 'CONNECTION_FAILED',
      message: 'تعذر الاتصال بخادم CyberShield.',
    );
    await _prepareForm(tester, service);

    await tester.tap(find.text('بدء الفحص الأمني'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 350));

    expect(service.calls, 1);
    expect(find.text('تعذر الاتصال بخادم CyberShield.'), findsOneWidget);
    expect(find.text('بدء الفحص الأمني'), findsOneWidget);
    final button = tester.widget<FilledButton>(
      find.byWidgetPredicate((widget) => widget is FilledButton),
    );
    expect(button.onPressed, isNotNull);
    service.dispose();
  });

  testWidgets('invalid authorization never invokes scan API', (tester) async {
    final service = _FakeScanService();
    service.response = () async => _sampleReport();
    await tester.pumpWidget(
      MaterialApp(home: HomeScreen(scanApiService: service)),
    );
    await tester.enterText(find.byType(TextField), 'https://example.com');
    await tester.ensureVisible(find.text('بدء الفحص الأمني'));
    await tester.tap(find.text('بدء الفحص الأمني'));
    await tester.pump();
    expect(service.calls, 0);
    expect(
      find.text('يرجى تأكيد امتلاكك تصريحاً لفحص الموقع.'),
      findsOneWidget,
    );
    service.dispose();
  });
}
