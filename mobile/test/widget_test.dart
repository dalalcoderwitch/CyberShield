import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:mobile/main.dart';

void main() {
  testWidgets('renders the Arabic CyberShield home screen', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const CyberShieldApp());

    expect(find.text('CyberShield'), findsOneWidget);
    expect(find.text('درعك الأول في الأمن السيبراني'), findsOneWidget);
    expect(find.text('رابط الموقع'), findsOneWidget);
    expect(find.text('بدء الفحص'), findsOneWidget);

    final direction = Directionality.of(
      tester.element(find.text('رابط الموقع')),
    );

    expect(direction, TextDirection.rtl);
  });

  testWidgets('rejects HTTP URLs', (WidgetTester tester) async {
    await tester.pumpWidget(const CyberShieldApp());

    await tester.enterText(find.byType(TextField), 'http://example.com');

    final scanButton = find.text('بدء الفحص');

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

    final scanButton = find.text('بدء الفحص');

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
