import '../utils/cookie_privacy.dart';

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
  final String impact;
  final String remediation;
  final List<String> relations;
  final String priority;

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
    this.impact = '',
    this.remediation = '',
    this.relations = const [],
    this.priority = '',
  });

  factory Finding.fromJson(Map<String, dynamic> json) {
    final checkId = _readString(json['check_id']);
    final isCookieFinding = checkId.toLowerCase().startsWith('cookie_');

    String readText(Object? value) {
      final text = _readString(value);
      return isCookieFinding ? CookiePrivacy.redactText(text) : text;
    }

    List<String> readList(Object? value) {
      final items = _readStringList(value);
      return isCookieFinding
          ? items.map(CookiePrivacy.redactText).toList()
          : items;
    }

    return Finding(
      checkId: checkId,
      title: readText(json['title']),
      status: _readString(json['status']),
      severity: _readString(json['severity']),
      confidence: _readString(json['confidence']),
      evidence: isCookieFinding
          ? CookiePrivacy.redactEvidence(json['evidence'])
          : json['evidence'],
      explanation: readText(json['explanation']),
      recommendation: readText(json['recommendation']),
      limitations: readList(json['limitations']),
      impact: readText(json['impact']),
      remediation: readText(json['remediation']),
      relations: readList(json['relations']),
      priority: readText(json['priority']),
    );
  }

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
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
    if (impact.isNotEmpty) json['impact'] = impact;
    if (remediation.isNotEmpty) json['remediation'] = remediation;
    if (relations.isNotEmpty) json['relations'] = relations;
    if (priority.isNotEmpty) json['priority'] = priority;
    return json;
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
