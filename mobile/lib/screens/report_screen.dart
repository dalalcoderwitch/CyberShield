import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:mobile/models/finding.dart';
import 'package:mobile/models/scan_report.dart';

class ReportScreen extends StatelessWidget {
  final ScanReport report;

  const ReportScreen({super.key, required this.report});

  static const Color accent = Color(0xFF35C8FF);
  static const Color cardColor = Color(0xFF081A35);
  static const Color muted = Color(0xFFB7C9E4);

  @override
  Widget build(BuildContext context) {
    return Directionality(
      textDirection: TextDirection.rtl,
      child: Scaffold(
        appBar: AppBar(
          title: const Text(
            'تقرير الفحص',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          centerTitle: true,
        ),
        body: SafeArea(
          child: ListView(
            padding: const EdgeInsets.all(18),
            children: [
              _buildHeader(),
              const SizedBox(height: 22),

              const Text(
                'ملخص الفحص',
                style: TextStyle(fontSize: 19, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 12),

              _buildSummary(),
              const SizedBox(height: 24),

              const Text(
                'تفاصيل نتائج الفحص',
                style: TextStyle(fontSize: 19, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 12),

              if (report.findings.isEmpty)
                _buildEmptyMessage()
              else
                ...report.findings.map(_buildFindingCard),

              if (report.limitations.isNotEmpty) ...[
                const SizedBox(height: 18),
                _buildReportLimitations(),
              ],

              const SizedBox(height: 18),
              _buildNotice(),
            ],
          ),
        ),
      ),
    );
  }

  // معلومات التقرير الأساسية
  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0xFF29364C)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.shield_outlined, color: accent, size: 32),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'تقرير CyberShield الأمني',
                  style: TextStyle(fontSize: 19, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          const Text(
            'الموقع الذي تم فحصه',
            style: TextStyle(color: muted, fontSize: 13),
          ),
          const SizedBox(height: 7),

          Directionality(
            textDirection: TextDirection.ltr,
            child: SelectableText(
              report.targetUrl,
              textAlign: TextAlign.left,
              style: const TextStyle(color: accent, fontSize: 15),
            ),
          ),

          const SizedBox(height: 16),

          _InfoRow(label: 'رقم الفحص', value: report.scanId),
          const SizedBox(height: 9),

          _InfoRow(label: 'تاريخ الفحص', value: _formatDate(report.scannedAt)),
          const SizedBox(height: 14),

          _StatusChip(
            label: _reportStatusLabel(report.status),
            color: _statusColor(report.status),
          ),
        ],
      ),
    );
  }

  // ملخص نتائج الفحوصات
  Widget _buildSummary() {
    return Wrap(
      spacing: 10,
      runSpacing: 10,
      children: [
        _SummaryCard(
          title: 'إجمالي الفحوصات',
          value: _summaryValue('total', report.findings.length),
          color: const Color(0xFF8FA7C9),
          icon: Icons.fact_check_outlined,
        ),
        _SummaryCard(
          title: 'اجتازت',
          value: _summaryValue('passed'),
          color: accent,
          icon: Icons.check_circle_outline,
        ),
        _SummaryCard(
          title: 'تحذيرات',
          value: _summaryValue('warning'),
          color: const Color(0xFFFFC66D),
          icon: Icons.warning_amber_outlined,
        ),
        _SummaryCard(
          title: 'غير متحقق',
          value: _summaryValue('not_verified'),
          color: const Color(0xFF82B5F5),
          icon: Icons.help_outline,
        ),
        _SummaryCard(
          title: 'أخطاء',
          value: _summaryValue('error'),
          color: const Color(0xFFFF7373),
          icon: Icons.error_outline,
        ),
        _SummaryCard(
          title: 'تم تخطيها',
          value: _summaryValue('skipped'),
          color: muted,
          icon: Icons.skip_next_outlined,
        ),
      ],
    );
  }

  // بطاقة نتيجة الفحص الواحدة
  Widget _buildFindingCard(Finding finding) {
    final color = _statusColor(finding.status);

    return Container(
      margin: const EdgeInsets.only(bottom: 13),
      padding: const EdgeInsets.all(17),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(17),
        border: Border.all(color: const Color(0xFF29364C)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Text(
                  finding.title,
                  style: const TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              _StatusChip(label: _statusLabel(finding.status), color: color),
            ],
          ),

          const SizedBox(height: 9),

          Directionality(
            textDirection: TextDirection.ltr,
            child: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                finding.checkId,
                style: const TextStyle(color: muted, fontSize: 12),
              ),
            ),
          ),

          const Divider(height: 24, color: Color(0xFF29364C)),

          _InfoRow(
            label: 'مستوى الخطورة',
            value: _severityLabel(finding.severity),
          ),
          const SizedBox(height: 9),

          _InfoRow(
            label: 'مستوى الثقة',
            value: _confidenceLabel(finding.confidence),
          ),

          if (finding.explanation.isNotEmpty) ...[
            const SizedBox(height: 16),
            const Text(
              'التوضيح',
              style: TextStyle(fontWeight: FontWeight.bold, color: accent),
            ),
            const SizedBox(height: 6),
            Text(
              finding.explanation,
              style: const TextStyle(color: muted, height: 1.7),
            ),
          ],

          if (finding.evidence != null) ...[
            const SizedBox(height: 16),
            const Text(
              'الأدلة والملاحظات',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 7),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFF0B1120),
                borderRadius: BorderRadius.circular(10),
              ),
              child: SelectableText(
                _formatEvidence(finding.evidence),
                style: const TextStyle(color: muted, fontSize: 12, height: 1.6),
              ),
            ),
          ],

          if (finding.impact.isNotEmpty) ...[
            const SizedBox(height: 16),
            const Text('الأثر المحتمل', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 6),
            Text(finding.impact, style: const TextStyle(color: muted, height: 1.7)),
          ],
          if (finding.priority.isNotEmpty) ...[
            const SizedBox(height: 12),
            _InfoRow(label: 'أولوية المعالجة', value: finding.priority),
          ],
          if (finding.relations.isNotEmpty) ...[
            const SizedBox(height: 12),
            const Text('النتائج المرتبطة', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 6),
            ...finding.relations.map((item) => Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Text('• $item', style: const TextStyle(color: muted, height: 1.5)),
            )),
          ],
          if (finding.recommendation.isNotEmpty) ...[
            const SizedBox(height: 16),
            const Text(
              'التوصية',
              style: TextStyle(fontWeight: FontWeight.bold, color: accent),
            ),
            const SizedBox(height: 6),
            Text(finding.recommendation, style: const TextStyle(height: 1.7)),
          ],
          if (finding.remediation.isNotEmpty) ...[
            const SizedBox(height: 16),
            const Text('خطوات المعالجة', style: TextStyle(fontWeight: FontWeight.bold, color: accent)),
            const SizedBox(height: 6),
            Text(finding.remediation, style: const TextStyle(height: 1.7)),
          ],

          if (finding.limitations.isNotEmpty) ...[
            const SizedBox(height: 16),
            const Text(
              'حدود الفحص',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 7),

            ...finding.limitations.map(
              (item) => Padding(
                padding: const EdgeInsets.only(bottom: 5),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.info_outline, size: 17, color: muted),
                    const SizedBox(width: 7),
                    Expanded(
                      child: Text(
                        item,
                        style: const TextStyle(color: muted, height: 1.5),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  // رسالة عند عدم وجود نتائج
  Widget _buildEmptyMessage() {
    return Container(
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: const Text(
        'لا توجد نتائج فحص متاحة في هذا التقرير.',
        textAlign: TextAlign.center,
        style: TextStyle(color: muted),
      ),
    );
  }

  // حدود التقييم الأمني العامة القادمة من Flask
  Widget _buildReportLimitations() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF332A19),
        borderRadius: BorderRadius.circular(15),
        border: Border.all(color: const Color(0xFF66502B)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'حدود التقييم الأمني',
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.bold,
              color: Color(0xFFFFD27A),
            ),
          ),
          const SizedBox(height: 12),

          ...report.limitations.map(
            (item) => Padding(
              padding: const EdgeInsets.only(bottom: 9),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(
                    Icons.info_outline,
                    size: 17,
                    color: Color(0xFFFFD27A),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      item,
                      style: const TextStyle(
                        color: Color(0xFFFFE5B0),
                        height: 1.7,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  // التنبيه العام للتقرير
  Widget _buildNotice() {
    if (report.notice.isEmpty) {
      return const SizedBox.shrink();
    }

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF332A19),
        borderRadius: BorderRadius.circular(15),
        border: Border.all(color: const Color(0xFF66502B)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.info_outline, color: Color(0xFFFFD27A)),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              report.notice,
              style: const TextStyle(color: Color(0xFFFFE5B0), height: 1.7),
            ),
          ),
        ],
      ),
    );
  }

  // قراءة أرقام الملخص
  int _summaryValue(String key, [int fallback = 0]) {
    final value = report.summary[key];

    if (value is num) {
      return value.toInt();
    }

    return int.tryParse(value?.toString() ?? '') ?? fallback;
  }

  // تنسيق تاريخ الفحص
  String _formatDate(String value) {
    final date = DateTime.tryParse(value);

    if (date == null) {
      return value;
    }

    final local = date.toLocal();

    return '${local.year}-'
        '${local.month.toString().padLeft(2, '0')}-'
        '${local.day.toString().padLeft(2, '0')} '
        '${local.hour.toString().padLeft(2, '0')}:'
        '${local.minute.toString().padLeft(2, '0')}';
  }

  // تنسيق الأدلة
  String _formatEvidence(Object? evidence) {
    if (evidence is Map || evidence is List) {
      try {
        return const JsonEncoder.withIndent('  ').convert(evidence);
      } catch (_) {
        return evidence.toString();
      }
    }

    return evidence.toString();
  }

  // ترجمة حالة التقرير
  String _reportStatusLabel(String status) {
    switch (status) {
      case 'completed':
        return 'اكتمل الفحص';
      case 'running':
        return 'الفحص قيد التنفيذ';
      case 'failed':
        return 'تعذر إكمال الفحص';
      default:
        return status.isEmpty ? 'حالة غير محددة' : status;
    }
  }

  // ترجمة حالة الفحص
  String _statusLabel(String status) {
    switch (status) {
      case 'passed':
        return 'اجتاز';
      case 'warning':
        return 'تحذير';
      case 'not_verified':
        return 'غير متحقق';
      case 'error':
        return 'خطأ';
      case 'skipped':
        return 'تم تخطيه';
      default:
        return status;
    }
  }

  // ترجمة مستوى الخطورة
  String _severityLabel(String severity) {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'حرج';
      case 'high':
        return 'مرتفع';
      case 'medium':
        return 'متوسط';
      case 'low':
        return 'منخفض';
      case 'info':
        return 'معلوماتي';
      default:
        return severity.isEmpty ? 'غير محدد' : severity;
    }
  }

  // ترجمة مستوى الثقة
  String _confidenceLabel(String confidence) {
    switch (confidence.toLowerCase()) {
      case 'high':
        return 'عالية';
      case 'medium':
        return 'متوسطة';
      case 'low':
        return 'منخفضة';
      default:
        return confidence.isEmpty ? 'غير محدد' : confidence;
    }
  }

  // تحديد لون الحالة
  Color _statusColor(String status) {
    switch (status) {
      case 'passed':
      case 'completed':
        return accent;
      case 'warning':
        return const Color(0xFFFFC66D);
      case 'not_verified':
      case 'running':
        return const Color(0xFF82B5F5);
      case 'error':
      case 'failed':
        return const Color(0xFFFF7373);
      case 'skipped':
      default:
        return muted;
    }
  }
}

// صف معلومات التقرير
class _InfoRow extends StatelessWidget {
  final String label;
  final String value;

  const _InfoRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 105,
          child: Text(
            label,
            style: const TextStyle(color: ReportScreen.muted, fontSize: 13),
          ),
        ),
        Expanded(
          child: Text(
            value.isEmpty ? 'غير متوفر' : value,
            style: const TextStyle(fontSize: 13),
          ),
        ),
      ],
    );
  }
}

// شارة حالة الفحص
class _StatusChip extends StatelessWidget {
  final String label;
  final Color color;

  const _StatusChip({required this.label, required this.color});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: 12,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}

// بطاقة ملخص واحدة
class _SummaryCard extends StatelessWidget {
  final String title;
  final int value;
  final Color color;
  final IconData icon;

  const _SummaryCard({
    required this.title,
    required this.value,
    required this.color,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 145,
      padding: const EdgeInsets.all(13),
      decoration: BoxDecoration(
        color: ReportScreen.cardColor,
        borderRadius: BorderRadius.circular(15),
        border: Border.all(color: const Color(0xFF29364C)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: color, size: 23),
          const SizedBox(height: 12),
          Text(
            value.toString(),
            style: TextStyle(
              color: color,
              fontSize: 25,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 5),
          Text(
            title,
            style: const TextStyle(color: ReportScreen.muted, fontSize: 12),
          ),
        ],
      ),
    );
  }
}
