# Flutter Correlation Model — Implementation Handoff

**Contract:** API 1.3  
**Backend source of truth:** \`main\`  
**Correlation catalog version at this baseline:** \`2.0.0\`  
**Status:** Implementation-ready handoff; Flutter source files have not been changed.

## 1. Current client state

The current \`ScanReport\` model parses report metadata and findings but has no correlation fields. There is no \`mobile/lib/models/correlation.dart\` on \`main\`.

The current \`ScanApiService.scan()\` already sends \`include_expanded_checks: true\`. No request-service change is needed to receive expanded metadata.

The Backend contract requires both \`correlations\` and \`correlation_rules_version\` in expanded mode. The list may be empty, but the version must still be present. Both fields are omitted together in base mode.

## 2. Add \`mobile/lib/models/correlation.dart\`

Use strict parsing for the fields defined by API 1.3. Unknown JSON keys may be ignored for forward compatibility; required fields and list element types must not be silently coerced.

~~~dart
class Correlation {
  final String correlationId;
  final List<String> contributingCheckIds;
  final String severity;
  final String confidence;
  final String explanation;
  final String recommendation;
  final String rulesVersion;
  final String ruleVersion;
  final List<String> limitations;

  const Correlation({
    required this.correlationId,
    required this.contributingCheckIds,
    required this.severity,
    required this.confidence,
    required this.explanation,
    required this.recommendation,
    required this.rulesVersion,
    required this.ruleVersion,
    required this.limitations,
  });

  factory Correlation.fromJson(Map<String, dynamic> json) {
    return Correlation(
      correlationId: _requiredString(json, 'correlation_id'),
      contributingCheckIds: _requiredStringList(
        json['contributing_check_ids'],
        'contributing_check_ids',
      ),
      severity: _requiredLevel(json, 'severity'),
      confidence: _requiredLevel(json, 'confidence'),
      explanation: _requiredString(json, 'explanation'),
      recommendation: _requiredString(json, 'recommendation'),
      rulesVersion: _requiredString(json, 'rules_version'),
      ruleVersion: _requiredString(json, 'rule_version'),
      limitations: _requiredStringList(json['limitations'], 'limitations'),
    );
  }

  Map<String, dynamic> toJson() => {
        'correlation_id': correlationId,
        'contributing_check_ids': contributingCheckIds,
        'severity': severity,
        'confidence': confidence,
        'explanation': explanation,
        'recommendation': recommendation,
        'rules_version': rulesVersion,
        'rule_version': ruleVersion,
        'limitations': limitations,
      };

  static String _requiredString(Map<String, dynamic> json, String field) {
    final value = json[field];

    if (value is! String || value.trim().isEmpty) {
      throw FormatException('Missing or invalid correlation field: $field');
    }

    return value;
  }

  static String _requiredLevel(Map<String, dynamic> json, String field) {
    final value = _requiredString(json, field);

    if (!const {'low', 'medium', 'high'}.contains(value)) {
      throw FormatException('Invalid correlation level: $field');
    }

    return value;
  }

  static List<String> _requiredStringList(Object? value, String field) {
    if (value is! List ||
        value.isEmpty ||
        value.any((item) => item is! String || item.trim().isEmpty)) {
      throw FormatException('Missing or invalid correlation list: $field');
    }

    return value.cast<String>();
  }
}
~~~

Notes:
- The correlation severity and confidence are context labels; do not use them to create or modify a Finding.
- The scanner currently emits \`low\` for both fields, while the contract permits \`low\`, \`medium\`, or \`high\`.
- Do not read or display raw evidence from a correlation. Its contract contains only the nine fields above.

## 3. Extend \`ScanReport\`

Import the new model:

~~~dart
import 'correlation.dart';
import 'finding.dart';
~~~

Add these fields to \`ScanReport\`:

~~~dart
final List<Correlation> correlations;
final String? correlationRulesVersion;
~~~

Add optional constructor parameters while keeping old report construction source-compatible:

~~~dart
this.correlations = const [],
this.correlationRulesVersion,
~~~

In \`ScanReport.fromJson\`, parse correlation metadata before constructing the report:

~~~dart
final correlationMetadata = _readCorrelationMetadata(json);
~~~

Then pass these values to the constructor:

~~~dart
correlations: correlationMetadata.correlations,
correlationRulesVersion: correlationMetadata.rulesVersion,
~~~

Add this helper inside \`ScanReport\`:

~~~dart
static _CorrelationMetadata _readCorrelationMetadata(
  Map<String, dynamic> json,
) {
  final hasCorrelations = json.containsKey('correlations');
  final hasRulesVersion = json.containsKey('correlation_rules_version');

  // Base reports and older reports omit both fields.
  if (!hasCorrelations && !hasRulesVersion) {
    return const _CorrelationMetadata(
      correlations: [],
      rulesVersion: null,
    );
  }

  // API 1.3 defines the two fields as a pair.
  if (hasCorrelations != hasRulesVersion) {
    throw const FormatException(
      'Correlation metadata must include both fields.',
    );
  }

  final version = json['correlation_rules_version'];
  if (version is! String || version.trim().isEmpty) {
    throw const FormatException('Invalid correlation rules version.');
  }

  final rawCorrelations = json['correlations'];
  if (rawCorrelations is! List) {
    throw const FormatException('Report correlations must be a list.');
  }

  final correlations = <Correlation>[];
  for (var index = 0; index < rawCorrelations.length; index++) {
    final item = rawCorrelations[index];

    if (item is! Map) {
      throw FormatException('Invalid correlation at index $index.');
    }

    correlations.add(
      Correlation.fromJson(Map<String, dynamic>.from(item)),
    );
  }

  return _CorrelationMetadata(
    correlations: correlations,
    rulesVersion: version,
  );
}
~~~

Add this private helper class outside \`ScanReport\`:

~~~dart
class _CorrelationMetadata {
  final List<Correlation> correlations;
  final String? rulesVersion;

  const _CorrelationMetadata({
    required this.correlations,
    required this.rulesVersion,
  });
}
~~~

In \`ScanReport.toJson()\`, after building the existing report map, serialize the pair together:

~~~dart
if (correlationRulesVersion != null) {
  json['correlations'] =
      correlations.map((correlation) => correlation.toJson()).toList();
  json['correlation_rules_version'] = correlationRulesVersion;
} else if (correlations.isNotEmpty) {
  throw StateError(
    'Cannot serialize correlations without correlation_rules_version.',
  );
}
~~~

This pairing is important. In expanded mode an empty list is meaningful and the version is still required. Do not conditionally serialize the pair based only on \`correlations.isNotEmpty\`.

## 4. Add model tests in \`mobile/test/models_test.dart\`

Keep the existing base-report tests. Add a fixture:

~~~dart
Map<String, dynamic> fakeCorrelation() => {
      'correlation_id': 'cookie_defense_gaps',
      'contributing_check_ids': ['cookie_secure', 'cookie_httponly'],
      'severity': 'low',
      'confidence': 'low',
      'explanation': 'Two observed cookie-control gaps need joint review.',
      'recommendation': 'Review Secure and HttpOnly for the observed cookies.',
      'rules_version': '2.0.0',
      'rule_version': '1',
      'limitations': [
        'Context only; this is not an additional vulnerability or summary count.',
      ],
    };
~~~

Add tests for these cases:

1. **Base/legacy report:** when both correlation keys are absent, parsing succeeds, \`correlations\` is empty, \`correlationRulesVersion\` is null, and \`toJson()\` omits both keys.
2. **Populated expanded report:** add one \`fakeCorrelation()\` and version \`2.0.0\`; verify all nine values are parsed and both keys survive \`toJson()\`.
3. **Empty expanded report:** set \`correlations\` to an empty list and version to \`2.0.0\`; verify serialization still contains both keys and preserves the version.
4. **Malformed metadata:** reject a one-sided key pair, a non-string/empty version, a non-list \`correlations\` value, a non-map list item, a missing required string, an invalid severity/confidence, and non-string/empty list entries.

Suggested core assertion for the empty expanded case:

~~~dart
final json = fakeReport([]);
json['correlations'] = <Map<String, dynamic>>[];
json['correlation_rules_version'] = '2.0.0';

final report = ScanReport.fromJson(json);
final serialized = report.toJson();

expect(report.correlations, isEmpty);
expect(report.correlationRulesVersion, '2.0.0');
expect(serialized['correlations'], isEmpty);
expect(serialized['correlation_rules_version'], '2.0.0');
~~~

## 5. Files intentionally not changed in this model step

- \`mobile/lib/models/finding.dart\`: correlations are not findings.
- \`mobile/lib/services/scan_api_service.dart\`: it already requests expanded checks.
- \`mobile/lib/screens/report_screen.dart\`: display is a separate UI step.
- \`mobile/lib/utils/check_categories.dart\`: category integration is a separate UI step.

## 6. Acceptance checklist

- [ ] Add the Correlation model using strict required-field parsing.
- [ ] Extend ScanReport with the correlation list and nullable catalog version.
- [ ] Preserve the distinction between base/legacy reports and expanded reports with an empty list.
- [ ] Add populated, empty-expanded, legacy/base, and malformed-input model tests.
- [ ] Run \`dart format\` on changed Dart files.
- [ ] Run \`flutter test\` and \`flutter analyze\` from the mobile project.
- [ ] Verify an API expanded response can be parsed and serialized without losing correlation metadata.

**Ownership note:** this document is a Backend-to-Flutter handoff. The Flutter implementation and its test execution remain with the mobile owner; the Backend CI suite does not run Flutter tests.
