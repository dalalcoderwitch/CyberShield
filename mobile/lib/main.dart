import 'package:flutter/material.dart';

import 'models/scan_report.dart';
import 'screens/report_screen.dart';
import 'services/scan_api_service.dart';

void main() => runApp(const CyberShieldApp());

class CyberShieldApp extends StatelessWidget {
  const CyberShieldApp({super.key});

  @override
  Widget build(BuildContext context) {
    const navy = Color(0xFF020817);
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'CyberShield',
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: navy,
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF168CFF), brightness: Brightness.dark),
        appBarTheme: const AppBarTheme(backgroundColor: navy),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFF081A35),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(13)),
        ),
      ),
      builder: (context, child) => Directionality(
        textDirection: TextDirection.rtl,
        child: child ?? const SizedBox.shrink(),
      ),
      home: const HomeScreen(),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, this.apiService});
  final ScanApiService? apiService;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _controller = TextEditingController();
  late final ScanApiService _service = widget.apiService ?? ScanApiService();
  bool _authorized = false;
  bool _scanning = false;
  bool _checkingHealth = false;
  bool? _serverHealthy;
  String? _serverMessage;

  @override
  void dispose() {
    _controller.dispose();
    if (widget.apiService == null) _service.dispose();
    super.dispose();
  }

  void _message(String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message), behavior: SnackBarBehavior.floating));
  }

  Future<void> _checkHealth() async {
    if (_checkingHealth) return;
    setState(() {
      _checkingHealth = true;
      _serverMessage = null;
    });
    try {
      await _service.checkHealth();
      if (mounted) setState(() { _serverHealthy = true; _serverMessage = 'الخادم متصل وجاهز.'; });
    } on ApiException catch (e) {
      if (mounted) setState(() { _serverHealthy = false; _serverMessage = e.message; });
    } catch (_) {
      if (mounted) setState(() { _serverHealthy = false; _serverMessage = 'تعذر التحقق من اتصال الخادم.'; });
    } finally {
      if (mounted) setState(() => _checkingHealth = false);
    }
  }

  static bool isValidTarget(String value) {
    final url = Uri.tryParse(value.trim());
    return url != null &&
        url.scheme.toLowerCase() == 'https' &&
        url.host.isNotEmpty &&
        url.userInfo.isEmpty &&
        url.port == 443 &&
        !value.contains('\\') &&
        !value.contains(RegExp(r'[\r\n\t]'));
  }

  Future<void> _scan() async {
    if (_scanning) return;
    final target = _controller.text.trim();
    if (!isValidTarget(target)) {
      _message('أدخلي رابط HTTPS صالحاً دون بيانات اعتماد أو منفذ مخصص.');
      return;
    }
    if (!_authorized) {
      _message('يرجى تأكيد امتلاكك تصريحاً لفحص هذا الموقع.');
      return;
    }
    setState(() => _scanning = true);
    ScanReport? report;
    try {
      report = await _service.scan(targetUrl: target, authorizationConfirmed: true);
    } on ApiException catch (e) {
      if (mounted) _message(e.message);
    } catch (_) {
      if (mounted) _message('حدث خطأ غير متوقع. حاولي مجدداً.');
    } finally {
      if (mounted) setState(() => _scanning = false);
    }
    if (mounted && report != null) {
      await Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (_) => ReportScreen(report: report!),
      ));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Row(children: [
          Icon(Icons.shield_outlined, color: Color(0xFF38C7FF)),
          SizedBox(width: 10),
          Text('CYBERSHIELD', textDirection: TextDirection.ltr,
              style: TextStyle(fontWeight: FontWeight.w900, letterSpacing: 1.1)),
        ]),
      ),
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 680),
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                Container(
                  padding: const EdgeInsets.all(25),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(20),
                    gradient: const LinearGradient(colors: [Color(0xFF0E3561), Color(0xFF09172C)]),
                    border: Border.all(color: const Color(0xFF245E9C)),
                  ),
                  child: const Column(children: [
                    Icon(Icons.security_rounded, size: 64, color: Color(0xFF3BD2FF)),
                    SizedBox(height: 12),
                    Text('درعك الذكي لعالم رقمي أكثر أماناً',
                        textAlign: TextAlign.center, style: TextStyle(fontSize: 23, fontWeight: FontWeight.w800)),
                    SizedBox(height: 9),
                    Text('تقييم أمني محدود للمواقع المصرّح بفحصها، مع أدلة وتوصيات واضحة.',
                        textAlign: TextAlign.center, style: TextStyle(color: Color(0xFFC3D7EA), height: 1.5)),
                  ]),
                ),
                const SizedBox(height: 22),
                const Text('رابط الموقع الإلكتروني', style: TextStyle(fontSize: 17, fontWeight: FontWeight.bold)),
                const SizedBox(height: 9),
                TextField(
                  controller: _controller,
                  enabled: !_scanning,
                  textDirection: TextDirection.ltr,
                  keyboardType: TextInputType.url,
                  decoration: const InputDecoration(
                    hintText: 'https://example.com',
                    hintTextDirection: TextDirection.ltr,
                    prefixIcon: Icon(Icons.link),
                  ),
                  onSubmitted: (_) => _scan(),
                ),
                const SizedBox(height: 12),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _authorized,
                  onChanged: _scanning ? null : (v) => setState(() => _authorized = v ?? false),
                  title: const Text('أؤكد أن لدي تصريحاً بفحص هذا الموقع.'),
                  subtitle: const Text('هذا إقرار من المستخدم وليس إثبات ملكية تقنياً.',
                      style: TextStyle(color: Color(0xFF98B1C9), fontSize: 12)),
                  controlAffinity: ListTileControlAffinity.leading,
                ),
                const SizedBox(height: 8),
                FilledButton.icon(
                  onPressed: _scanning ? null : _scan,
                  icon: _scanning
                      ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.radar),
                  label: Text(_scanning ? 'جارٍ تنفيذ الفحص...' : 'بدء الفحص الأمني'),
                  style: FilledButton.styleFrom(
                    minimumSize: const Size.fromHeight(54),
                    backgroundColor: const Color(0xFF168CFF),
                    foregroundColor: Colors.white,
                  ),
                ),
                const SizedBox(height: 26),
                const Divider(color: Color(0xFF2B4B6A)),
                Row(children: [
                  const Expanded(child: Text('حالة الاتصال بخادم Flask',
                      style: TextStyle(fontWeight: FontWeight.bold))),
                  OutlinedButton.icon(
                    onPressed: _checkingHealth ? null : _checkHealth,
                    icon: _checkingHealth
                        ? const SizedBox(height: 15, width: 15, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.refresh, size: 18),
                    label: const Text('تحقق'),
                  ),
                ]),
                if (_serverMessage != null)
                  Semantics(
                    liveRegion: true,
                    child: Text(_serverMessage!, style: TextStyle(
                      color: _serverHealthy == true ? const Color(0xFF5DE1C4) : const Color(0xFFFFC66D),
                    )),
                  ),
                const SizedBox(height: 16),
                const Text('الفئات المدعومة: TLS • Headers • Cookies • Access • Disclosure',
                    style: TextStyle(color: Color(0xFF91ABC9)), textAlign: TextAlign.center),
                const SizedBox(height: 18),
                const Text('CyberShield يقدم مؤشرات وتحليلاً محدوداً، ولا يؤكد خلو الموقع من جميع الثغرات.',
                    style: TextStyle(fontSize: 12, color: Color(0xFF91ABC9)), textAlign: TextAlign.center),
              ]),
            ),
          ),
        ),
      ),
    );
  }
}
