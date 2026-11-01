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
      scanId: _readString(json['scan_id']),
      status: _readString(json['status']),
      targetUrl: _readString(json['target_url']),
      scannedAt: _readString(json['scanned_at']),
      engineVersion: _readString(json['engine_version']),
      httpStatus: _readNullableInt(json['http_status']),
      summary: _readMap(json['summary']),
      findings: _readFindings(json['findings']),
      limitations: _readStringList(json['limitations']),
      notice: _readString(json['notice']),
    );
  }

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'scan_id': scanId,
      'status': status,
      'target_url': targetUrl,
      'scanned_at': scannedAt,
      'summary': summary,
      'findings': findings
          .map((finding) => finding.toJson())
          .toList(),
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

  static String _readString(Object? value) {
    if (value == null) return '';
    return value.toString();
  }

  static int? _readNullableInt(Object? value) {
    if (value is num) return value.toInt();
    if (value is String) return int.tryParse(value);
    return null;
  }

  static Map<String, dynamic> _readMap(Object? value) {
    if (value is Map) {
      return Map<String, dynamic>.from(value);
    }
    return {};
  }

  static List<Finding> _readFindings(Object? value) {
    if (value is! List) return [];

    final results = <Finding>[];

    for (final item in value) {
      if (item is Map) {
        results.add(
          Finding.fromJson(
            Map<String, dynamic>.from(item),
          ),
        );
      }
    }

    return results;
  }

  static List<String> _readStringList(Object? value) {
    if (value is! List) return [];

    return value
        .map((item) => _readString(item))
        .where((item) => item.isNotEmpty)
        .toList();
  }
}
