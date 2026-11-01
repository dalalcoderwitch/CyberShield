import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/main.dart';

void main() {
  testWidgets(
    'CyberShield home screen renders correctly',
    (WidgetTester tester) async {
      await tester.pumpWidget(const CyberShieldApp());

      expect(find.text('CyberShield'), findsOneWidget);
      expect(find.text('بدء الفحص'), findsOneWidget);
      expect(find.text('رابط الموقع'), findsOneWidget);
    },
  );
}
