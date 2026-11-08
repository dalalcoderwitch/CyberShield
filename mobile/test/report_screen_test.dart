import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/screens/report_screen.dart';

void main() {
  testWidgets(
    'ReportScreen displays report details and findings',
    (WidgetTester tester) async {
      final report = ScanReport.fromJson({
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
            'title': 'فحص اتصال HTTPS',
            'status': 'passed',
            'severity': 'low',
            'confidence': 'high',
            'evidence': {'protocol': 'https'},
            'explanation': 'تم إنشاء اتصال HTTPS بنجاح.',
            'recommendation': 'استمر باستخدام HTTPS.',
            'limitations': [],
          },
        ],
        'notice': 'هذا تقييم أولي محدود.',
      });

      await tester.pumpWidget(
        MaterialApp(
          home: ReportScreen(report: report),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('تقرير الفحص'), findsOneWidget);
      expect(find.text('https://example.com'), findsOneWidget);

      Future<void> checkVisibleText(String text) async {
        final finder = find.text(text);

        await tester.scrollUntilVisible(
          finder,
          250,
          scrollable: find.byType(Scrollable).first,
        );

        await tester.pumpAndSettle();

        expect(finder, findsOneWidget);
      }

      await checkVisibleText('فحص اتصال HTTPS');
      await checkVisibleText('اجتاز');
      await checkVisibleText('تم إنشاء اتصال HTTPS بنجاح.');
      await checkVisibleText('استمر باستخدام HTTPS.');
      await checkVisibleText('هذا تقييم أولي محدود.');
    },
  );
}

  testWidgets(
    'ReportScreen renders a report with 30 findings dynamically',
    (WidgetTester tester) async {
      final findings = List.generate(
        30,
        (index) => {
          'check_id': 'expanded_check_${index + 1}',
          'title': 'فحص موسع ${index + 1}',
          'status': index.isEven ? 'not_verified' : 'warning',
          'severity': 'info',
          'confidence': 'low',
          'evidence': {'sample': index + 1},
          'explanation': 'توضيح الفحص ${index + 1}',
          'recommendation': 'مراجعة الفحص ${index + 1}',
          'limitations': <String>[],
        },
      );

      final report = ScanReport.fromJson({
        'scan_id': 'scan-030',
        'status': 'completed',
        'target_url': 'https://example.com',
        'scanned_at': '2026-11-09T12:00:00Z',
        'summary': {
          'total': 30,
          'passed': 0,
          'warning': 15,
          'not_verified': 15,
          'error': 0,
          'skipped': 0,
        },
        'findings': findings,
        'notice': 'هذا تقييم أولي محدود.',
      });

      await tester.pumpWidget(
        MaterialApp(home: ReportScreen(report: report)),
      );
      await tester.pumpAndSettle();

      expect(find.text('30'), findsOneWidget);

      final lastFinding = find.text('فحص موسع 30');
      await tester.scrollUntilVisible(
        lastFinding,
        300,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.pumpAndSettle();

      expect(lastFinding, findsOneWidget);
      expect(find.text('غير متحقق'), findsWidgets);
    },
  );
