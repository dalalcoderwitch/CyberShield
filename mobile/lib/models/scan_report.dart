import 'finding.dart';

class ScanReport {
  final String scanId;
  final String status;
  final String targetUrl;
  final String scannedAt;
  final String engineVersion;
  final int? httpStatus;
  final Map<String, dynamic> summary;
  final List<Finding> findings;
  final List<String> limitations;
  final String notice;

  const ScanReport({
    required this.scanId,
    required this.status,
    required this.targetUrl,
    required this.scannedAt,
    this.engineVersion = '',
    this.httpStatus,
    this.summary = const {},
    this.findings = const [],
    this.limitations = const [],
    required this.notice,
  });

  factory ScanReport.fromJson(Map<String, dynamic> json) {
    return ScanReport(
      scanId: _requiredString(json, 'scan_id'),
      status: _requiredString(json, 'status'),
      targetUrl: _requiredString(json, 'target_url'),
      scannedAt: _requiredString(json, 'scanned_at'),
      engineVersion: _optionalString(json['engine_version'], 'engine_version'),
      httpStatus: _readNullableInt(json['http_status']),
      summary: _readSummary(json['summary']),
      findings: _readFindings(json['findings']),
      limitations: _readOptionalStringList(json['limitations'], 'limitations'),
      notice: _requiredString(json, 'notice'),
    );
  }

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'scan_id': scanId,
      'status': status,
      'target_url': targetUrl,
      'scanned_at': scannedAt,
      'summary': summary,
      'findings': findings.map((finding) => finding.toJson()).toList(),
      'notice': notice,
    };

    if (engineVersion.isNotEmpty) {
      json['engine_version'] = engineVersion;
    }

    if (httpStatus != null) {
      json['http_status'] = httpStatus;
    }

    if (limitations.isNotEmpty) {
      json['limitations'] = limitations;
    }

    return json;
  }

  static String _requiredString(Map<String, dynamic> json, String key) {
    final value = json[key];

    if (value is! String || value.trim().isEmpty) {
      throw FormatException('Missing or invalid report field: $key');
    }

    return value;
  }

  static String _optionalString(Object? value, String field) {
    if (value == null) return '';

    if (value is! String) {
      throw FormatException('Invalid report field: $field');
    }

    return value;
  }

  static Map<String, dynamic> _readSummary(Object? value) {
    if (value is! Map) {
      throw const FormatException('Report summary must be an object.');
    }

    final summary = Map<String, dynamic>.from(value);

    const requiredCounters = [
      'total',
      'passed',
      'warning',
      'not_verified',
      'error',
      'skipped',
    ];

    for (final key in requiredCounters) {
      final count = summary[key];

      if (count is! int || count < 0) {
        throw FormatException('Missing or invalid summary counter: $key');
      }
    }

    return summary;
  }

  static int? _readNullableInt(Object? value) {
    if (value == null) return null;

    if (value is int) return value;

    throw const FormatException('Invalid report HTTP status.');
  }

  static List<Finding> _readFindings(Object? value) {
    if (value is! List) {
      throw const FormatException('Report findings must be a list.');
    }

    final results = <Finding>[];

    for (var index = 0; index < value.length; index++) {
      final item = value[index];

      if (item is! Map) {
        throw FormatException('Invalid finding at index $index.');
      }

      final findingJson = Map<String, dynamic>.from(item);

      for (final field in [
        'check_id',
        'title',
        'status',
        'severity',
        'confidence',
      ]) {
        final fieldValue = findingJson[field];

        if (fieldValue is! String || fieldValue.trim().isEmpty) {
          throw FormatException('Missing or invalid finding field: $field');
        }
      }

      _readOptionalStringList(
        findingJson['limitations'],
        'findings[$index].limitations',
      );

      results.add(Finding.fromJson(findingJson));
    }

    return results;
  }

  static List<String> _readOptionalStringList(Object? value, String field) {
    if (value == null) return [];

    if (value is! List || value.any((item) => item is! String)) {
      throw FormatException('Invalid list field: $field');
    }

    return value.cast<String>();
  }
}
