import 'package:flutter/material.dart';

import '../models/scan_report.dart';
import '../utils/check_categories.dart';
import '../widgets/finding_tile.dart';

class ReportScreen extends StatelessWidget {
  const ReportScreen({super.key, required this.report});
  final ScanReport report;

  @override
  Widget build(BuildContext context) {
    final groups = groupFindings(report.findings);
    return Scaffold(
      appBar: AppBar(title: const Text('تقرير الفحص الأمني')),
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 920),
            child: ListView(
              padding: const EdgeInsets.all(16),
              children: [
                _panel(Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  const Text('CYBERSHIELD • SECURITY REPORT', textDirection: TextDirection.ltr,
                      style: TextStyle(color: Color(0xFF48C7FF), fontSize: 12, letterSpacing: 1.0)),
                  const SizedBox(height: 10),
                  SelectableText(report.targetUrl, textDirection: TextDirection.ltr,
                      style: const TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 6),
                  Text('الحالة: ${report.status}  |  HTTP: ${report.httpStatus?.toString() ?? 'غير متاح'}',
                      style: const TextStyle(color: Color(0xFFB9CBE0))),
                  const SizedBox(height: 5),
                  Text('وقت الفحص: ${report.scannedAt}', style: const TextStyle(color: Color(0xFFB9CBE0))),
                ])),
                const SizedBox(height: 16),
                const Text('ملخص النتائج', style: TextStyle(fontSize: 21, fontWeight: FontWeight.bold)),
                const SizedBox(height: 10),
                Wrap(spacing: 8, runSpacing: 8, children: [
                  _counter('الإجمالي', report.summary['total'] ?? report.findings.length, const Color(0xFF82B5F5)),
                  _counter('اجتاز', report.summary['passed'] ?? 0, findingStatusColor('passed')),
                  _counter('تحذير', report.summary['warning'] ?? 0, findingStatusColor('warning')),
                  _counter('غير متحقق', report.summary['not_verified'] ?? 0, findingStatusColor('not_verified')),
                  _counter('خطأ', report.summary['error'] ?? 0, findingStatusColor('error')),
                  _counter('متجاوز', report.summary['skipped'] ?? 0, findingStatusColor('skipped')),
                ]),
                const SizedBox(height: 20),
                const Text('مجموعات الفحوص', style: TextStyle(fontSize: 21, fontWeight: FontWeight.bold)),
                const SizedBox(height: 10),
                if (groups.isEmpty)
                  _panel(const Text('لا توجد نتائج فحص في هذا التقرير.')),
                ...groups.entries.map((entry) => Card(
                      color: const Color(0xFF091B35),
                      margin: const EdgeInsets.only(bottom: 12),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16),
                          side: const BorderSide(color: Color(0xFF25476D))),
                      child: ExpansionTile(
                        key: ValueKey('category-${entry.key.id}'),
                        initiallyExpanded: entry.key == groups.keys.first,
                        title: Text(entry.key.label, style: const TextStyle(fontWeight: FontWeight.bold)),
                        subtitle: Text('${entry.value.length} فحوص', style: const TextStyle(color: Color(0xFF92B1D1))),
                        childrenPadding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
                        children: entry.value.map((f) => FindingTile(finding: f)).toList(),
                      ),
                    )),
                if (report.limitations.isNotEmpty) ...[
                  const SizedBox(height: 15),
                  const Text('حدود التقييم', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                  _panel(Text(report.limitations.join('\n• '))),
                ],
                if (report.notice.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  _panel(Text(report.notice, style: const TextStyle(color: Color(0xFFFFD598)))),
                ],
                const SizedBox(height: 20),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _panel(Widget child) => Container(
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(color: const Color(0xFF0B213F), borderRadius: BorderRadius.circular(15),
            border: Border.all(color: const Color(0xFF26466B))),
        child: child,
      );

  Widget _counter(String label, int value, Color color) => Container(
        width: 130,
        padding: const EdgeInsets.all(13),
        decoration: BoxDecoration(color: const Color(0xFF0B213F), borderRadius: BorderRadius.circular(12),
            border: Border.all(color: color.withValues(alpha: .5))),
        child: Column(children: [
          Text('$value', style: TextStyle(fontSize: 27, color: color, fontWeight: FontWeight.bold)),
          Text(label, style: const TextStyle(fontSize: 12, color: Color(0xFFCFDDF0))),
        ]),
      );
}
