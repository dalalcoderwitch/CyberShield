class Finding {
  const Finding({
    required this.checkId,
    required this.title,
    required this.status,
    required this.severity,
    required this.confidence,
    required this.evidence,
    required this.explanation,
    required this.recommendation,
    required this.limitations,
  });

  final String checkId;
  final String title;
  final String status;
  final String severity;
  final String confidence;
  final Object? evidence;
  final String explanation;
  final String recommendation;
  final List<String> limitations;

  static const allowedStatuses = {
    'passed', 'warning', 'not_verified', 'error', 'skipped',
  };

  factory Finding.fromJson(Map<String, dynamic> json) {
    String requiredText(String key) {
      final value = json[key];
      if (value is! String || value.trim().isEmpty) {
        throw FormatException('Invalid finding field: $key');
      }
      return value;
    }

    String optionalText(String key) {
      final value = json[key];
      if (value == null) return '';
      if (value is! String) throw FormatException('Invalid finding field: $key');
      return value;
    }

    final status = requiredText('status');
    if (!allowedStatuses.contains(status)) {
      throw FormatException('Unknown finding status: $status');
    }
    return Finding(
      checkId: requiredText('check_id'),
      title: requiredText('title'),
      status: status,
      severity: requiredText('severity'),
      confidence: requiredText('confidence'),
      evidence: json['evidence'],
      explanation: optionalText('explanation'),
      recommendation: optionalText('recommendation'),
      limitations: readStringList(json['limitations'], 'limitations'),
    );
  }

  Map<String, dynamic> toJson() => {
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

  static List<String> readStringList(Object? value, String field) {
    if (value == null) return const [];
    if (value is! List || value.any((element) => element is! String)) {
      throw FormatException('Invalid string list: $field');
    }
    return List<String>.unmodifiable(value.cast<String>());
  }
}
