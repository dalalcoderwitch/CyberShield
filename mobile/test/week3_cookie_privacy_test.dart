import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/models/finding.dart';

Map<String, dynamic> sampleCookieFinding({
  Object? evidence,
  String status = 'not_verified',
}) {
  return <String, dynamic>{
    'check_id': 'cookie_secure',
    'title': 'Cookie Secure',
    'status': status,
    'severity': 'info',
    'confidence': 'low',
    'evidence': evidence,
    'explanation': 'Cookie flags are partially available.',
    'recommendation': 'Enable Secure where appropriate.',
    'limitations': <String>[],
  };
}

void main() {
  group('Week 3 cookie privacy', () {
    test('masks nested cookie values but preserves public attributes', () {
      final finding = Finding.fromJson(
        sampleCookieFinding(
          evidence: {
            'cookies': [
              {
                'name': 'sessionid',
                'value': 'SECRET_ONE_9821',
                'secure': true,
                'httpOnly': false,
                'sameSite': 'Lax',
              },
              {'name': 'prefs', 'value': 'SECRET_TWO_4392', 'secure': false},
            ],
          },
        ),
      );

      final text = jsonEncode(finding.toJson());
      expect(text, isNot(contains('SECRET_ONE_9821')));
      expect(text, isNot(contains('SECRET_TWO_4392')));
      expect(text, contains('[REDACTED]'));
      expect(text, contains('Lax'));
      expect(text, contains('sessionid'));
      expect(text, contains('secure'));
    });

    test('does not expose raw Set-Cookie header, tokens, or value fields', () {
      final finding = Finding.fromJson(
        sampleCookieFinding(
          evidence: {
            'headers': {
              'Set-Cookie': 'sid=ABC123; Secure; HttpOnly; SameSite=Lax',
            },
            'cookie_value': 'SUPER_SECRET',
            'notes': 'Cookie: sid=OTHER_SECRET; theme=dark',
            'metadata': 'SameSite=Lax; Secure=true; HttpOnly=true',
          },
        ),
      );
      final text = jsonEncode(finding.toJson());
      for (final secret in [
        'ABC123',
        'SUPER_SECRET',
        'OTHER_SECRET',
        'theme=dark',
      ]) {
        expect(text, isNot(contains(secret)));
      }
      expect(text, contains('SameSite=Lax'));
      expect(text, contains('Secure=true'));
    });

    test('masks sensitive assignments in user-visible textual fields', () {
      final json = sampleCookieFinding(
        evidence: 'sid=private123; SameSite=None',
      );
      json['explanation'] = 'Observed sid=explanation_secret';
      json['recommendation'] = 'Avoid value=advice_secret';
      json['limitations'] = ['Cookie: auth=limitations_secret'];
      json['impact'] = 'Bearer bearer_secret';
      json['relations'] = ['session=related_secret'];
      final finding = Finding.fromJson(json);
      final serialized = jsonEncode(finding.toJson());
      for (final secret in [
        'private123',
        'explanation_secret',
        'advice_secret',
        'limitations_secret',
        'bearer_secret',
        'related_secret',
      ]) {
        expect(serialized, isNot(contains(secret)));
      }
      expect(serialized, contains('SameSite=None'));
    });

    test('non-cookie findings keep their original evidence untouched', () {
      final json = sampleCookieFinding(evidence: {'value': 'public_data'});
      json['check_id'] = 'header_referrer_policy';
      final finding = Finding.fromJson(json);
      expect(finding.evidence, {'value': 'public_data'});
      expect(finding.toJson(), equals(json));
    });

    test('missing evidence and skipped cookie checks remain valid', () {
      final finding = Finding.fromJson(
        sampleCookieFinding(evidence: null, status: 'skipped'),
      );
      expect(finding.evidence, isNull);
      expect(finding.status, 'skipped');
      expect(finding.toJson()['status'], 'skipped');
    });
  });
}
