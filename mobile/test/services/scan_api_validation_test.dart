import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobile/services/scan_api_service.dart';

void main() {
  group('Scan API invalid response handling', () {
    test('rejects invalid JSON response', () async {
      final client = MockClient(
        (_) async => http.Response('not valid json', 200),
      );

      final service = ScanApiService(client: client);

      addTearDown(() {
        service.dispose();
        client.close();
      });

      await expectLater(
        service.scan(
          targetUrl: 'https://example.com',
          authorizationConfirmed: true,
        ),
        throwsA(
          isA<ApiException>().having(
            (error) => error.code,
            'error code',
            'INVALID_RESPONSE',
          ),
        ),
      );
    });

    test('rejects JSON with an invalid report structure', () async {
      final client = MockClient(
        (_) async => http.Response(
          jsonEncode({
            'scan_id': 'scan-invalid',
            'status': 'completed',
            'target_url': 'https://example.com',
            'scanned_at': '2026-11-14T12:00:00Z',
            'summary': {},
            'findings': [],
            'notice': 'Test',
          }),
          200,
        ),
      );

      final service = ScanApiService(client: client);

      addTearDown(() {
        service.dispose();
        client.close();
      });

      await expectLater(
        service.scan(
          targetUrl: 'https://example.com',
          authorizationConfirmed: true,
        ),
        throwsA(
          isA<ApiException>().having(
            (error) => error.code,
            'error code',
            'INVALID_REPORT',
          ),
        ),
      );
    });
    test('handles connection failure correctly', () async {
      final client = MockClient(
        (_) async {
          throw http.ClientException('Connection failed');
        },
      );

      final service = ScanApiService(client: client);

      addTearDown(() {
        service.dispose();
        client.close();
      });

      await expectLater(
        service.scan(
          targetUrl: 'https://example.com',
          authorizationConfirmed: true,
        ),
        throwsA(
          isA<ApiException>().having(
            (error) => error.code,
            'error code',
            'CONNECTION_FAILED',
          ),
        ),
      );
    });
    test('handles request timeout correctly', () async {
      final client = MockClient((_) async {
        await Future<void>.delayed(
          const Duration(milliseconds: 200),
        );
        return http.Response('{}', 200);
      });

      final service = ScanApiService(
        client: client,
        timeout: const Duration(milliseconds: 20),
      );

      addTearDown(() {
        service.dispose();
        client.close();
      });

      await expectLater(
        service.scan(
          targetUrl: 'https://example.com',
          authorizationConfirmed: true,
        ),
        throwsA(
          isA<ApiException>().having(
            (error) => error.code,
            'error code',
            'REQUEST_TIMEOUT',
          ),
        ),
      );
    });


  });
}
