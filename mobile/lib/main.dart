import 'package:flutter/material.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/screens/report_screen.dart';
import 'package:mobile/services/scan_api_service.dart';

void main() {
  runApp(const CyberShieldApp());
}

class CyberShieldApp extends StatelessWidget {
  const CyberShieldApp({super.key});

  @override
  Widget build(BuildContext context) {
    const backgroundColor = Color(0xFF0B1120);
    const cardColor = Color(0xFF151F32);
    const accentColor = Color(0xFF36D6B5);

    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'CyberShield',
      locale: const Locale('ar'),
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: backgroundColor,
        colorScheme: ColorScheme.fromSeed(
          seedColor: accentColor,
          brightness: Brightness.dark,
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: cardColor,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(14),
            borderSide: BorderSide.none,
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(14),
            borderSide: const BorderSide(color: Color(0xFF29364C)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(14),
            borderSide: const BorderSide(color: accentColor),
          ),
        ),
      ),
      builder: (context, child) {
        return Directionality(textDirection: TextDirection.rtl, child: child!);
      },
      home: const HomeScreen(),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  static const Color accent = Color(0xFF36D6B5);
  static const Color muted = Color(0xFF9BAAC0);

  final TextEditingController _urlController = TextEditingController();

  final ScanApiService _apiService = ScanApiService();

  bool _authorizationConfirmed = false;
  bool _isScanning = false;

  @override
  void dispose() {
    _urlController.dispose();
    _apiService.dispose();
    super.dispose();
  }

  Future<void> _startScan() async {
    final input = _urlController.text.trim();
    final uri = Uri.tryParse(input);

    final validUrl =
        uri != null &&
        uri.scheme.toLowerCase() == 'https' &&
        uri.host.isNotEmpty &&
        uri.userInfo.isEmpty;

    if (!validUrl) {
      _showMessage('أدخل رابط HTTPS صحيحاً، مثل https://example.com');
      return;
    }

    if (!_authorizationConfirmed) {
      _showMessage('يرجى تأكيد امتلاكك تصريحاً بفحص الموقع.');
      return;
    }

    if (_isScanning) return;

    setState(() {
      _isScanning = true;
    });

    ScanReport? report;

    try {
      report = await _apiService.scan(
        targetUrl: input,
        authorizationConfirmed: _authorizationConfirmed,
      );
    } on ApiException catch (error) {
      if (mounted) {
        _showMessage(error.message);
      }
    } catch (_) {
      if (mounted) {
        _showMessage('حدث خطأ غير متوقع أثناء الاتصال بالخادم.');
      }
    } finally {
      if (mounted) {
        setState(() {
          _isScanning = false;
        });
      }
    }

    if (report != null && mounted) {
      await Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (context) {
            return ReportScreen(report: report!);
          },
        ),
      );
    }
  }

  void _openDemoReport() {
    final demoReport = ScanReport.fromJson({
      'scan_id': 'DEMO-001',
      'status': 'معاينة تجريبية',
      'target_url': 'https://example.com',
      'scanned_at': DateTime.now().toUtc().toIso8601String(),
      'summary': {
        'total': 5,
        'passed': 2,
        'warning': 1,
        'not_verified': 1,
        'error': 0,
        'skipped': 1,
      },
      'findings': [
        {
          'check_id': 'https_connection',
          'title': 'فحص اتصال HTTPS',
          'status': 'passed',
          'severity': 'low',
          'confidence': 'high',
          'evidence': {'protocol': 'HTTPS', 'certificate_validation': 'valid'},
          'explanation':
              'في هذا المثال التجريبي، تم تسجيل اتصال HTTPS '
              'وشهادة TLS صالحة.',
          'recommendation':
              'حافظ على تفعيل HTTPS وتجديد شهادة TLS '
              'قبل انتهاء صلاحيتها.',
          'limitations': ['هذه بيانات توضيحية وليست نتيجة اتصال حقيقي.'],
        },
        {
          'check_id': 'header_hsts',
          'title': 'فحص ترويسة HSTS',
          'status': 'warning',
          'severity': 'medium',
          'confidence': 'high',
          'evidence': {
            'header': 'Strict-Transport-Security',
            'demo_observation': 'Example warning',
          },
          'explanation': 'يعرض المثال ملاحظة تجريبية حول إعداد ترويسة HSTS.',
          'recommendation':
              'راجع إعداد Strict-Transport-Security '
              'وفعّله بالقيمة المناسبة بعد التأكد من إعداد الموقع.',
          'limitations': [],
        },
        {
          'check_id': 'header_csp',
          'title': 'فحص ترويسة CSP',
          'status': 'not_verified',
          'severity': 'info',
          'confidence': 'low',
          'evidence': {
            'header': 'Content-Security-Policy',
            'reason': 'Demo data only',
          },
          'explanation':
              'لا توجد أدلة فعلية كافية في هذا المثال '
              'لتحديد نتيجة الفحص.',
          'recommendation':
              'تحقق من سياسة أمان المحتوى CSP '
              'واضبط المصادر المسموح بها.',
          'limitations': ['لا تمثل هذه النتيجة فحصاً حقيقياً للترويسة.'],
        },
        {
          'check_id': 'header_x_content_type_options',
          'title': 'فحص X-Content-Type-Options',
          'status': 'skipped',
          'severity': 'info',
          'confidence': 'high',
          'evidence': null,
          'explanation': 'تم تخطي هذا الفحص في بيانات المعاينة التجريبية.',
          'recommendation': 'تحقق من إعداد الترويسة nosniff على خادم الموقع.',
          'limitations': [],
        },
        {
          'check_id': 'header_x_frame_options',
          'title': 'فحص X-Frame-Options',
          'status': 'passed',
          'severity': 'low',
          'confidence': 'high',
          'evidence': {
            'header': 'X-Frame-Options',
            'demo_observation': 'Example configuration',
          },
          'explanation': 'يعرض المثال حالة اجتياز توضيحية لفحص حماية الإطارات.',
          'recommendation':
              'حافظ على إعداد حماية الإطارات، '
              'وراجع توافقه مع CSP.',
          'limitations': [
            'هذه نتيجة تجريبية وليست دليلاً على إعداد الموقع الفعلي.',
          ],
        },
      ],
      'notice':
          'تنبيه: هذا تقرير تجريبي ببيانات توضيحية فقط. '
          'لم يتم إرسال طلب إلى الموقع ولم يتم تنفيذ فحص حقيقي. '
          'لا تستخدم هذه النتائج للحكم على أمان أي موقع.',
    });

    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (context) {
          return ReportScreen(report: demoReport);
        },
      ),
    );
  }

  void _showMessage(String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(content: Text(message), behavior: SnackBarBehavior.floating),
      );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF0B1120),
        titleSpacing: 20,
        title: const Row(
          children: [
            Icon(Icons.shield_outlined, color: accent, size: 30),
            SizedBox(width: 10),
            Text('CyberShield', style: TextStyle(fontWeight: FontWeight.bold)),
          ],
        ),
      ),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(22),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 560),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Container(
                    padding: const EdgeInsets.all(24),
                    decoration: BoxDecoration(
                      color: const Color(0xFF151F32),
                      borderRadius: BorderRadius.circular(24),
                      border: Border.all(color: const Color(0xFF29364C)),
                    ),
                    child: Column(
                      children: [
                        Container(
                          width: 82,
                          height: 82,
                          decoration: BoxDecoration(
                            color: accent.withValues(alpha: 0.10),
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(
                            Icons.security,
                            size: 46,
                            color: accent,
                          ),
                        ),
                        const SizedBox(height: 22),
                        const Text(
                          'درعك الأول في الأمن السيبراني',
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            fontSize: 23,
                            fontWeight: FontWeight.bold,
                            height: 1.5,
                          ),
                        ),
                        const SizedBox(height: 12),
                        const Text(
                          'افحص مؤشرات أمن الموقع وتعرّف على '
                          'الملاحظات والتوصيات بطريقة واضحة.',
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            fontSize: 15,
                            color: muted,
                            height: 1.8,
                          ),
                        ),
                        const SizedBox(height: 28),
                        const Align(
                          alignment: Alignment.centerRight,
                          child: Text(
                            'رابط الموقع',
                            style: TextStyle(
                              fontSize: 15,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                        const SizedBox(height: 10),
                        TextField(
                          controller: _urlController,
                          keyboardType: TextInputType.url,
                          textDirection: TextDirection.ltr,
                          textAlign: TextAlign.left,
                          decoration: const InputDecoration(
                            hintText: 'https://example.com',
                            prefixIcon: Icon(Icons.link),
                          ),
                        ),
                        const SizedBox(height: 18),
                        Container(
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            color: const Color(0xFF0B1120),
                            borderRadius: BorderRadius.circular(14),
                          ),
                          child: Material(
                            color: Colors.transparent,
                            child: CheckboxListTile(
                              value: _authorizationConfirmed,
                              onChanged: _isScanning
                                  ? null
                                  : (value) {
                                      setState(() {
                                        _authorizationConfirmed =
                                            value ?? false;
                                      });
                                    },
                              contentPadding: EdgeInsets.zero,
                              controlAffinity: ListTileControlAffinity.leading,
                              activeColor: accent,
                              title: const Text(
                                'أؤكد أن لدي تصريحاً بفحص هذا الموقع.',
                                style: TextStyle(fontSize: 14, height: 1.6),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(height: 22),
                        SizedBox(
                          width: double.infinity,
                          height: 54,
                          child: FilledButton.icon(
                            onPressed: _isScanning ? null : _startScan,
                            icon: _isScanning
                                ? const SizedBox(
                                    width: 19,
                                    height: 19,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                      color: Color(0xFF07151A),
                                    ),
                                  )
                                : const Icon(Icons.search),
                            label: Text(
                              _isScanning ? 'جارٍ تنفيذ الفحص...' : 'بدء الفحص',
                              style: const TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            style: FilledButton.styleFrom(
                              backgroundColor: accent,
                              foregroundColor: const Color(0xFF07151A),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(14),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(height: 12),
                        SizedBox(
                          width: double.infinity,
                          height: 50,
                          child: OutlinedButton.icon(
                            onPressed: _isScanning ? null : _openDemoReport,
                            icon: const Icon(Icons.description_outlined),
                            label: const Text(
                              'معاينة تقرير تجريبي',
                              style: TextStyle(
                                fontSize: 15,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            style: OutlinedButton.styleFrom(
                              foregroundColor: accent,
                              side: const BorderSide(color: accent),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(14),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 20),
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: const Color(0xFF332A19),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: const Color(0xFF66502B)),
                    ),
                    child: const Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(Icons.info_outline, color: Color(0xFFFFD27A)),
                        SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            'هذا التطبيق يقدم تقييماً أولياً محدوداً '
                            'لاتصال HTTPS وبعض ترويسات الأمان. '
                            'لا يمثل اختبار اختراق شاملاً ولا يضمن '
                            'أن الموقع آمن بالكامل.',
                            style: TextStyle(
                              color: Color(0xFFFFE5B0),
                              height: 1.8,
                              fontSize: 13,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 24),
                  const Text(
                    'HTTPS  •  TLS  •  Security Headers',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: muted,
                      fontSize: 12,
                      letterSpacing: 0.4,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
