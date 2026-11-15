import 'package:flutter/material.dart';
import '../models/finding.dart';
import '../utils/safe_evidence.dart';

String findingStatusLabel(String status) => switch (status) {
      'passed' => 'اجتاز',
      'warning' => 'تحذير',
      'not_verified' => 'غير متحقق',
      'error' => 'خطأ',
      'skipped' => 'متجاوز',
      _ => 'غير معروف',
    };

Color findingStatusColor(String status) => switch (status) {
      'passed' => const Color(0xFF48D9BD),
      'warning' => const Color(0xFFFFC66D),
      'not_verified' => const Color(0xFF82B5F5),
      'error' => const Color(0xFFFF7C91),
      _ => const Color(0xFFB5C4D9),
    };

String severityLabel(String level) => switch (level.toLowerCase()) {
      'critical' => 'حرج', 'high' => 'مرتفع', 'medium' => 'متوسط',
      'low' => 'منخفض', 'info' => 'معلوماتي', _ => level,
    };

String confidenceLabel(String level) => switch (level.toLowerCase()) {
      'high' => 'عالية', 'medium' => 'متوسطة', 'low' => 'منخفضة', _ => level,
    };

class FindingTile extends StatelessWidget {
  const FindingTile({super.key, required this.finding});
  final Finding finding;

  @override
  Widget build(BuildContext context) {
    final color = findingStatusColor(finding.status);
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 5),
      clipBehavior: Clip.antiAlias,
      color: const Color(0xFF0C2344),
      shape: RoundedRectangleBorder(
        side: const BorderSide(color: Color(0xFF254365)),
        borderRadius: BorderRadius.circular(14),
      ),
      child: ExpansionTile(
        key: ValueKey('finding-${finding.checkId}'),
        iconColor: Colors.white,
        collapsedIconColor: Colors.white70,
        title: Text(finding.title, style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 6),
          child: Wrap(spacing: 8, runSpacing: 6, crossAxisAlignment: WrapCrossAlignment.center, children: [
            Chip(
              visualDensity: VisualDensity.compact,
              backgroundColor: color.withValues(alpha: .12),
              side: BorderSide(color: color.withValues(alpha: .55)),
              label: Text(findingStatusLabel(finding.status), style: TextStyle(color: color, fontSize: 12)),
            ),
            Text(finding.checkId, textDirection: TextDirection.ltr, style: const TextStyle(color: Color(0xFF91ABC8), fontSize: 11)),
          ]),
        ),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          const Divider(color: Color(0xFF27415F)),
          _detail('الخطورة', severityLabel(finding.severity)),
          _detail('الثقة', confidenceLabel(finding.confidence)),
          if (finding.explanation.isNotEmpty) _detail('التفسير', finding.explanation),
          if (finding.evidence != null) _detail('الدليل المنقح', SafeEvidence.display(finding.evidence)),
          if (finding.recommendation.isNotEmpty) _detail('التوصية', finding.recommendation),
          if (finding.limitations.isNotEmpty) _detail('حدود الفحص', finding.limitations.join('\n• ')),
        ],
      ),
    );
  }

  Widget _detail(String title, String value) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 7),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Text(title, style: const TextStyle(color: Color(0xFF38C7FF), fontWeight: FontWeight.bold, fontSize: 13)),
          const SizedBox(height: 5),
          SelectableText(value, style: const TextStyle(color: Color(0xFFD3E3F6), height: 1.55)),
        ]),
      );
}
