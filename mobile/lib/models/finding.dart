
class Finding {
  final String checkId;
  final String title;
  final String status;
  final String severity;
  final String confidence;
  final Object? evidence;
  final String explanation;
  final String recommendation;
  final List<String> limitations;

  const Finding({
    required this.checkId,
    required this.title,
    required this.status,
    required this.severity,
    required this.confidence,
    this.evidence,
    required this.explanation,
    required this.recommendation,
    this.limitations = const [],
  });

  factory Finding.fromJson(Map<String, dynamic> json) {
    return Finding(
      checkId: _readString(json['check_id']),
      title: _readString(json['title']),
      status: _readString(json['status']),
      severity: _readString(json['severity']),
      confidence: _readString(json['confidence']),
      evidence: json['evidence'],
      explanation: _readString(json['explanation']),
      recommendation: _readString(json['recommendation']),
      limitations: _readStringList(json['limitations']),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'check_id': checkId,
      'title': title,
      'status': status,
      'severity': severity,
      'confidence': confidence,
      'evidence': evidence,
      'explanation': explanation,
      'recommendation': recommendation,
      'limitations': limitations,
    };
  }

  static String _readString(Object? value) {
    if (value == null) return '';
    return value.toString();
  }

  static List<String> _readStringList(Object? value) {
    if (value == null) return [];

    if (value is List) {
      return value
          .map((item) => _readString(item))
          .where((item) => item.isNotEmpty)
          .toList();
    }

    if (value is String && value.trim().isNotEmpty) {
      return [value.trim()];
    }

    return [];
  }
}
