import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobile/services/scan_api_service.dart';

void main() {
  group('ScanApiService tests', () {
    test('checkHealth returns successful API status', () async {
      final mockClient = MockClient((request) async {
        expect(request.method, 'GET');
        expect(request.url.path, '/api/v1/health');

        return http.Response(
          jsonEncode({
            'status': 'ok',
            'service': 'CyberShield API',
          }),
          200,
        );
      });

      final service = ScanApiService(
        client: mockClient,
      );

      final result = await service.checkHealth();

      expect(result['status'], 'ok');
      expect(result['service'], 'CyberShield API');

      service.dispose();
      mockClient.close();
    });

    test('scan sends authorization and returns a report', () async {
      final mockClient = MockClient((request) async {
        expect(request.method, 'POST');
        expect(request.url.path, '/api/v1/scan');

        final body = jsonDecode(request.body);

        expect(
          body['target_url'],
          'https://example.com',
        );

        expect(
          body['authorization_confirmed'],
          true,
        );

        return http.Response(
          jsonEncode({
            'scan_id': 'scan-test-001',
            'status': 'completed',
            'target_url': 'https://example.com',
            'scanned_at': '2026-11-01T12:00:00Z',
            'engine_version': '1.0.0',
            'http_status': 200,
            'summary': {
              'total': 1,
              'passed': 1,
              'warning': 0,
              'not_verified': 0,
              'error': 0,
              'skipped': 0,
            },
            'findings': [],
            'limitations': [
              'This is a limited security assessment.',
            ],
            'notice': 'Limited security assessment.',
          }),
          200,
        );
      });

      final service = ScanApiService(
        client: mockClient,
      );

      final report = await service.scan(
        targetUrl: 'https://example.com',
        authorizationConfirmed: true,
      );

      expect(report.scanId, 'scan-test-001');
      expect(report.status, 'completed');
      expect(report.targetUrl, 'https://example.com');
      expect(report.engineVersion, '1.0.0');
      expect(report.httpStatus, 200);
      expect(report.summary['passed'], 1);
      expect(report.limitations.length, 1);

      service.dispose();
      mockClient.close();
    });

    test('scan throws ApiException when authorization is rejected',
        () async {
      final mockClient = MockClient((request) async {
        return http.Response(
          jsonEncode({
            'error': {
              'code': 'AUTHORIZATION_REQUIRED',
              'message': 'Authorization is required.',
            },
          }),
          403,
        );
      });

      final service = ScanApiService(
        client: mockClient,
      );

      await expectLater(
        service.scan(
          targetUrl: 'https://example.com',
          authorizationConfirmed: false,
        ),
        throwsA(
          isA<ApiException>().having(
            (error) => error.code,
            'error code',
            'AUTHORIZATION_REQUIRED',
          ),
        ),
      );

      service.dispose();
      mockClient.close();
    });
  });
}
