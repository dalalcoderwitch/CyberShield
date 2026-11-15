import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:mobile/main.dart';

void main() {
  testWidgets('renders the Arabic CyberShield home screen', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const CyberShieldApp());

    expect(find.text('CYBER'), findsOneWidget);
    expect(find.text('SHIELD'), findsOneWidget);
    expect(find.text('درعك الذكي لعالم رقمي أكثر أماناً'), findsOneWidget);
    expect(find.text('رابط الموقع الإلكتروني'), findsOneWidget);
    expect(find.text('بدء الفحص الأمني'), findsOneWidget);

    final direction = Directionality.of(
      tester.element(find.text('رابط الموقع الإلكتروني')),
    );

    expect(direction, TextDirection.rtl);
  });

  testWidgets('rejects HTTP URLs', (WidgetTester tester) async {
    await tester.pumpWidget(const CyberShieldApp());

    await tester.enterText(find.byType(TextField), 'http://example.com');

    final scanButton = find.text('بدء الفحص الأمني');

    await tester.ensureVisible(scanButton);
    await tester.tap(scanButton);

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));

    expect(
      find.text('أدخل رابط HTTPS صحيحاً، مثل https://example.com'),
      findsOneWidget,
    );
  });

  testWidgets('requires authorization before scanning', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const CyberShieldApp());

    await tester.enterText(find.byType(TextField), 'https://example.com');

    final scanButton = find.text('بدء الفحص الأمني');

    await tester.ensureVisible(scanButton);
    await tester.tap(scanButton);

    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));

    expect(
      find.text('يرجى تأكيد امتلاكك تصريحاً لفحص الموقع.'),
      findsOneWidget,
    );
  });
}
