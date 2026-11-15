import 'finding.dart';

class ScanReport {
  const ScanReport({
    required this.scanId,
    required this.status,
    required this.targetUrl,
    required this.scannedAt,
    required this.engineVersion,
    required this.httpStatus,
    required this.summary,
    required this.findings,
    required this.limitations,
    required this.notice,
  });

  final String scanId;
  final String status;
  final String targetUrl;
  final String scannedAt;
  final String engineVersion;
  final int? httpStatus;
  final Map<String, int> summary;
  final List<Finding> findings;
  final List<String> limitations;
  final String notice;

  factory ScanReport.fromJson(Map<String, dynamic> data) {
    String text(String key, {bool required = true}) {
      final value = data[key];
      if (!required && value == null) return '';
      if (value is! String || (required && value.trim().isEmpty)) {
        throw FormatException('Invalid report field: $key');
      }
      return value;
    }
    final rawFindings = data['findings'];
    if (rawFindings is! List) throw const FormatException('Missing findings list');
    final findings = <Finding>[];
    for (final item in rawFindings) {
      if (item is! Map) throw const FormatException('Invalid finding');
      findings.add(Finding.fromJson(Map<String, dynamic>.from(item)));
    }
    final rawSummary = data['summary'];
    if (rawSummary is! Map) throw const FormatException('Missing summary');
    const keys = ['total', 'passed', 'warning', 'not_verified', 'error', 'skipped'];
    final summary = <String, int>{};
    for (final key in keys) {
      final n = rawSummary[key];
      if (n is! int || n < 0) throw FormatException('Invalid summary: $key');
      summary[key] = n;
    }
    // Reject contradictory reports instead of giving a misleading count.
    if (summary['total'] != findings.length) {
      throw const FormatException('Summary total does not match findings');
    }
    for (final key in keys.skip(1)) {
      if (summary[key] != findings.where((f) => f.status == key).length) {
        throw FormatException('Summary $key does not match findings');
      }
    }
    final code = data['http_status'];
    if (code != null && (code is! int || code < 100 || code > 599)) {
      throw const FormatException('Invalid HTTP status');
    }
    return ScanReport(
      scanId: text('scan_id'),
      status: text('status'),
      targetUrl: text('target_url'),
      scannedAt: text('scanned_at'),
      engineVersion: text('engine_version', required: false),
      httpStatus: code as int?,
      summary: Map.unmodifiable(summary),
      findings: List.unmodifiable(findings),
      limitations: Finding.readStringList(data['limitations'], 'report.limitations'),
      notice: text('notice'),
    );
  }
}
