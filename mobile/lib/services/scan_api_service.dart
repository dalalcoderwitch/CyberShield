import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:mobile/models/scan_report.dart';

class ScanApiService {
  static const String defaultBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://10.0.2.2:5000',
  );

  final http.Client _client;
  final String _baseUrl;
  final Duration _timeout;
  final bool _ownsClient;

  ScanApiService({
    String baseUrl = defaultBaseUrl,
    http.Client? client,
    Duration timeout = const Duration(seconds: 35),
  })  : _baseUrl = baseUrl.replaceFirst(RegExp(r'/+$'), ''),
        _client = client ?? http.Client(),
        _timeout = timeout,
        _ownsClient = client == null;

  Future<Map<String, dynamic>> checkHealth() async {
    final response = await _get('/api/v1/health');

    if (response.statusCode != 200) {
      throw _readApiError(response);
    }

    final data = _decodeObject(response.body);

    if (data['status'] != 'ok') {
      throw const ApiException(
        code: 'API_UNAVAILABLE',
        message: 'خدمة CyberShield غير متاحة حاليًا.',
      );
    }

    return data;
  }

  Future<ScanReport> scan({
    required String targetUrl,
    required bool authorizationConfirmed,
  }) async {
    final response = await _post(
      '/api/v1/scan',
      {
        'target_url': targetUrl,
        'authorization_confirmed': authorizationConfirmed,
        'include_expanded_checks': true,
      },
    );

    if (response.statusCode != 200) {
      throw _readApiError(response);
    }

    final data = _decodeObject(response.body);

    try {
      return ScanReport.fromJson(data);
    } catch (_) {
      throw const ApiException(
        code: 'INVALID_REPORT',
        message: 'تعذر قراءة تقرير الفحص القادم من الخادم.',
      );
    }
  }

  Future<http.Response> _get(String path) async {
    try {
      return await _client
          .get(
            _uri(path),
            headers: _headers,
          )
          .timeout(_timeout);
    } on TimeoutException {
      throw const ApiException(
        code: 'REQUEST_TIMEOUT',
        message: 'انتهت مهلة الاتصال بالخادم. حاول مرة أخرى.',
      );
    } on http.ClientException {
      throw const ApiException(
        code: 'CONNECTION_FAILED',
        message: 'تعذر الاتصال بخادم CyberShield.',
      );
    }
  }

  Future<http.Response> _post(
    String path,
    Map<String, dynamic> body,
  ) async {
    try {
      return await _client
          .post(
            _uri(path),
            headers: _headers,
            body: jsonEncode(body),
          )
          .timeout(_timeout);
    } on TimeoutException {
      throw const ApiException(
        code: 'REQUEST_TIMEOUT',
        message: 'انتهت مهلة الفحص. حاول مرة أخرى.',
      );
    } on http.ClientException {
      throw const ApiException(
        code: 'CONNECTION_FAILED',
        message: 'تعذر الاتصال بخادم CyberShield.',
      );
    }
  }

  Uri _uri(String path) {
    return Uri.parse('$_baseUrl$path');
  }

  Map<String, String> get _headers => const {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      };

  Map<String, dynamic> _decodeObject(String body) {
    try {
      final decoded = jsonDecode(body);

      if (decoded is Map) {
        return Map<String, dynamic>.from(decoded);
      }
    } on FormatException {
      // سيتم التعامل مع الاستجابة غير الصالحة أدناه.
    }

    throw const ApiException(
      code: 'INVALID_RESPONSE',
      message: 'استجابة الخادم غير صالحة.',
    );
  }

  ApiException _readApiError(http.Response response) {
    try {
      final data = _decodeObject(response.body);
      final error = data['error'];

      if (error is Map) {
        return ApiException(
          code: error['code']?.toString() ?? 'HTTP_ERROR',
          message: error['message']?.toString() ??
              'تعذر تنفيذ الطلب.',
          statusCode: response.statusCode,
        );
      }
    } on ApiException {
      // الاستجابة لا تحتوي على رسالة خطأ بالتنسيق المتوقع.
    }

    final fallbackMessage = response.statusCode == 504
        ? 'انتهت المهلة الزمنية المسموحة للفحص.'
        : response.statusCode == 429
            ? 'تم تجاوز الحد المسموح للطلبات. حاول لاحقًا.'
            : 'تعذر تنفيذ الطلب. رمز الاستجابة: ${response.statusCode}';
    return ApiException(
      code: response.statusCode == 504 ? 'SCAN_TIMEOUT' : 'HTTP_ERROR',
      message: fallbackMessage,
      statusCode: response.statusCode,
    );
  }

  void dispose() {
    if (_ownsClient) {
      _client.close();
    }
  }
}

class ApiException implements Exception {
  final String code;
  final String message;
  final int? statusCode;

  const ApiException({
    required this.code,
    required this.message,
    this.statusCode,
  });

  @override
  String toString() => message;
}
