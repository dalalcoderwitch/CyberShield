import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobile/services/scan_api_service.dart';

void main() {
  const target = 'https://example.com';

  Future<ApiException> scanError(
    http.Client client, {
    Duration? timeout,
  }) async {
    final service = ScanApiService(
      client: client,
      timeout: timeout ?? const Duration(milliseconds: 100),
    );
    try {
      await service.scan(targetUrl: target, authorizationConfirmed: true);
      throw StateError('Expected ApiException, but scan succeeded');
    } on ApiException catch (error) {
      return error;
    } finally {
      service.dispose();
      client.close();
    }
  }

  test('health endpoint rejects non-ok status', () async {
    final client = MockClient(
      (_) async => http.Response(jsonEncode({'status': 'degraded'}), 200),
    );
    final service = ScanApiService(client: client);
    try {
      await expectLater(
        service.checkHealth(),
        throwsA(
          isA<ApiException>().having(
            (error) => error.code,
            'code',
            'API_UNAVAILABLE',
          ),
        ),
      );
    } finally {
      service.dispose();
      client.close();
    }
  });

  test('health endpoint handles network disconnection', () async {
    final client = MockClient(
      (_) async => throw http.ClientException('offline'),
    );
    final service = ScanApiService(client: client);
    try {
      await expectLater(
        service.checkHealth(),
        throwsA(
          isA<ApiException>().having(
            (error) => error.code,
            'code',
            'CONNECTION_FAILED',
          ),
        ),
      );
    } finally {
      service.dispose();
      client.close();
    }
  });

  test('health endpoint handles timeout', () async {
    final client = MockClient((_) async {
      await Future<void>.delayed(const Duration(milliseconds: 70));
      return http.Response(jsonEncode({'status': 'ok'}), 200);
    });
    final service = ScanApiService(
      client: client,
      timeout: const Duration(milliseconds: 5),
    );
    try {
      await expectLater(
        service.checkHealth(),
        throwsA(
          isA<ApiException>().having(
            (error) => error.code,
            'code',
            'REQUEST_TIMEOUT',
          ),
        ),
      );
    } finally {
      service.dispose();
      client.close();
    }
  });

  test('scan handles timeout', () async {
    final client = MockClient((_) async {
      await Future<void>.delayed(const Duration(milliseconds: 70));
      return http.Response('{}', 200);
    });
    final error = await scanError(
      client,
      timeout: const Duration(milliseconds: 5),
    );
    expect(error.code, 'REQUEST_TIMEOUT');
  });

  test('scan handles network disconnection', () async {
    final client = MockClient(
      (_) async => throw http.ClientException('offline'),
    );
    final error = await scanError(client);
    expect(error.code, 'CONNECTION_FAILED');
  });

  test('scan rejects invalid JSON response', () async {
    final client = MockClient(
      (_) async => http.Response('<html>bad</html>', 200),
    );
    final error = await scanError(client);
    expect(error.code, 'INVALID_RESPONSE');
  });

  test('scan rejects incomplete report JSON', () async {
    final client = MockClient(
      (_) async => http.Response(
        jsonEncode({'scan_id': 'scan-1', 'status': 'completed'}),
        200,
      ),
    );
    final error = await scanError(client);
    expect(error.code, 'INVALID_REPORT');
  });

  test('scan handles gateway timeout response', () async {
    final client = MockClient(
      (_) async => http.Response('Gateway timeout', 504),
    );
    final error = await scanError(client);
    expect(error.code, 'SCAN_TIMEOUT');
    expect(error.statusCode, 504);
  });

  test('scan preserves partial report, counts, and optional fields', () async {
    final client = MockClient(
      (_) async => http.Response(
        jsonEncode({
          'scan_id': 'partial-scan',
          'status': 'partial',
          'target_url': target,
          'scanned_at': '2026-11-15T10:00:00Z',
          'summary': {
            'total': 3,
            'passed': 1,
            'warning': 1,
            'not_verified': 1,
            'error': 0,
            'skipped': 0,
          },
          'findings': [
            {
              'check_id': 'tls_protocol_config',
              'title': 'TLS protocol',
              'status': 'passed',
              'severity': 'low',
              'confidence': 'high',
              'evidence': {'protocol': 'TLSv1.3'},
              'explanation': 'Protocol observed',
              'recommendation': 'Keep settings',
              'limitations': <String>[],
            },
            {
              'check_id': 'header_referrer_policy',
              'title': 'Referrer Policy',
              'status': 'warning',
              'severity': 'medium',
              'confidence': 'medium',
              'evidence': null,
            },
            {
              'check_id': 'header_permissions_policy',
              'title': 'Permissions Policy',
              'status': 'not_verified',
              'severity': 'info',
              'confidence': 'low',
            },
          ],
          'notice': 'Partial scan result',
        }),
        200,
      ),
    );
    final service = ScanApiService(client: client);
    try {
      final report = await service.scan(
        targetUrl: target,
        authorizationConfirmed: true,
      );
      expect(report.status, 'partial');
      expect(report.findings, hasLength(3));
      expect(report.summary['total'], 3);
      expect(report.summary['warning'], 1);
      expect(report.summary['not_verified'], 1);
      expect(report.findings[1].evidence, isNull);
      expect(report.findings[2].explanation, isEmpty);
      expect(report.findings[2].limitations, isEmpty);
    } finally {
      service.dispose();
      client.close();
    }
  });
}
