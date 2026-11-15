import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import '../models/scan_report.dart';

class ApiException implements Exception {
  const ApiException(this.code, this.message, [this.statusCode]);
  final String code;
  final String message;
  final int? statusCode;
  @override
  String toString() => message;
}

class ScanApiService {
  static const defaultBaseUrl = String.fromEnvironment(
    'API_BASE_URL', defaultValue: 'http://10.0.2.2:5000',
  );
  ScanApiService({
    String baseUrl = defaultBaseUrl,
    http.Client? client,
    Duration timeout = const Duration(seconds: 35),
  })  : _baseUrl = baseUrl.replaceFirst(RegExp(r'/+$'), ''),
        _client = client ?? http.Client(),
        _ownsClient = client == null,
        _timeout = timeout;

  final String _baseUrl;
  final http.Client _client;
  final bool _ownsClient;
  final Duration _timeout;

  Uri _uri(String endpoint) => Uri.parse('$_baseUrl$endpoint');
  static const headers = {'Accept': 'application/json', 'Content-Type': 'application/json'};

  Future<Map<String, dynamic>> checkHealth() async {
    final response = await _request(() => _client.get(_uri('/api/v1/health'), headers: headers));
    final json = _decodeResponse(response);
    if (json['status'] != 'ok') {
      throw const ApiException('API_UNAVAILABLE', 'الخادم لا يعلن أنه جاهز.');
    }
    return json;
  }

  Future<ScanReport> scan({required String targetUrl, required bool authorizationConfirmed}) async {
    final response = await _request(() => _client.post(
          _uri('/api/v1/scan'),
          headers: headers,
          body: jsonEncode({
            'target_url': targetUrl,
            'authorization_confirmed': authorizationConfirmed,
            'include_expanded_checks': true,
          }),
        ));
    final decoded = _decodeResponse(response);
    try {
      return ScanReport.fromJson(decoded);
    } on FormatException {
      throw const ApiException('INVALID_REPORT', 'تقرير الفحص غير متوافق مع صيغة البيانات المعتمدة.');
    } on TypeError {
      throw const ApiException('INVALID_REPORT', 'تقرير الفحص يحتوي حقولاً غير صالحة.');
    }
  }

  Future<http.Response> _request(Future<http.Response> Function() request) async {
    try {
      return await request().timeout(_timeout);
    } on TimeoutException {
      throw const ApiException('REQUEST_TIMEOUT', 'انتهت مهلة الاتصال أو الفحص. يمكنك إعادة المحاولة.');
    } on http.ClientException {
      throw const ApiException('CONNECTION_FAILED', 'تعذر الاتصال بالخادم. تحققي من تشغيل Flask والاتصال.');
    } on FormatException {
      throw const ApiException('CONNECTION_FAILED', 'عنوان خادم API غير صالح.');
    }
  }

  Map<String, dynamic> _decodeResponse(http.Response response) {
    dynamic decoded;
    try {
      decoded = jsonDecode(utf8.decode(response.bodyBytes));
    } on FormatException {
      throw const ApiException('INVALID_RESPONSE', 'استجابة الخادم ليست JSON صالحاً.');
    }
    if (decoded is! Map) {
      throw const ApiException('INVALID_RESPONSE', 'استجابة الخادم ليست كائناً JSON صالحاً.');
    }
    Map<String, dynamic> json;
    try {
      json = Map<String, dynamic>.from(decoded);
    } on TypeError {
      throw const ApiException('INVALID_RESPONSE', 'استجابة الخادم تحتوي مفاتيح غير صالحة.');
    }
    if (response.statusCode >= 200 && response.statusCode < 300) return json;
    final error = json['error'];
    final errorMap = error is Map ? error : const {};
    final code = errorMap['code'] is String ? errorMap['code'] as String : 'HTTP_ERROR';
    // Stable user-facing messages; don't expose arbitrary remote error details.
    final message = switch (code) {
      'AUTHORIZATION_REQUIRED' => 'يجب تأكيد التصريح قبل إجراء الفحص.',
      'TARGET_NOT_ALLOWED' => 'رابط الموقع غير مسموح بفحصه وفق سياسة الخادم.',
      'INVALID_REQUEST' => 'طلب الفحص غير صالح. راجعي الرابط.',
      'RATE_LIMIT_EXCEEDED' => 'تم تجاوز عدد الطلبات المسموح. حاولي لاحقاً.',
      'SCAN_CAPACITY_EXCEEDED' => 'الخادم مشغول حالياً. حاولي لاحقاً.',
      'SCAN_TIMEOUT' => 'انتهت مهلة الفحص على الخادم.',
      _ => switch (response.statusCode) {
          400 => 'الطلب غير صالح.',
          403 => 'تم رفض طلب الفحص.',
          429 => 'تم تجاوز عدد الطلبات المسموح.',
          503 => 'خدمة الفحص غير متاحة حالياً.',
          504 => 'انتهت مهلة الخادم.',
          _ => 'تعذر تنفيذ الطلب (HTTP ${response.statusCode}).',
        },
    };
    throw ApiException(code, message, response.statusCode);
  }

  void dispose() {
    if (_ownsClient) _client.close();
  }
}
