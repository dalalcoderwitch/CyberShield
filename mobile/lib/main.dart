import 'package:flutter/material.dart';
import 'package:mobile/models/scan_report.dart';
import 'package:mobile/screens/report_screen.dart';
import 'package:mobile/services/scan_api_service.dart';

void main() => runApp(const CyberShieldApp());

class CyberShieldApp extends StatelessWidget {
  const CyberShieldApp({super.key});

  static const navy = Color(0xFF020817);
  static const panel = Color(0xFF081A35);
  static const blue = Color(0xFF168CFF);
  static const cyan = Color(0xFF35C8FF);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'CyberShield',
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: navy,
        colorScheme: ColorScheme.fromSeed(
          seedColor: blue,
          brightness: Brightness.dark,
          surface: panel,
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFF061329),
          hintStyle: const TextStyle(color: Color(0xFF7185A5)),
          contentPadding: const EdgeInsets.symmetric(
            horizontal: 16,
            vertical: 18,
          ),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(15),
            borderSide: const BorderSide(color: Color(0xFF173B68)),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(15),
            borderSide: const BorderSide(color: Color(0xFF173B68)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(15),
            borderSide: const BorderSide(color: cyan, width: 1.4),
          ),
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
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _urlController = TextEditingController();
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
    final validUrl = uri != null &&
        uri.scheme.toLowerCase() == 'https' &&
        uri.host.isNotEmpty &&
        uri.userInfo.isEmpty;

    if (!validUrl) {
      _showMessage('أدخل رابط HTTPS صحيحاً، مثل https://example.com');
      return;
    }
    if (!_authorizationConfirmed) {
      _showMessage('يرجى تأكيد امتلاكك تصريحاً لفحص الموقع.');
      return;
    }
    if (_isScanning) return;

    setState(() => _isScanning = true);
    ScanReport? report;
    try {
      report = await _apiService.scan(
        targetUrl: uri.toString(),
        authorizationConfirmed: _authorizationConfirmed,
      );
    } on ApiException catch (error) {
      if (mounted) _showMessage(error.message);
    } catch (_) {
      if (mounted) _showMessage('حدث خطأ غير متوقع أثناء الاتصال بالخادم.');
    } finally {
      if (mounted) setState(() => _isScanning = false);
    }

    if (report != null && mounted) {
      await Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (_) => ReportScreen(report: report!),
        ),
      );
    }
  }

  void _showMessage(String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(
          content: Text(message),
          behavior: SnackBarBehavior.floating,
          backgroundColor: const Color(0xFF12345B),
        ),
      );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: CyberShieldApp.navy,
        surfaceTintColor: Colors.transparent,
        titleSpacing: 20,
        title: const Row(
          children: [
            Icon(
              Icons.shield_moon_outlined,
              color: CyberShieldApp.cyan,
              size: 30,
            ),
            SizedBox(width: 10),
            Text(
              'CYBER',
              style: TextStyle(fontWeight: FontWeight.w800, letterSpacing: 1.5),
            ),
            SizedBox(width: 5),
            Text(
              'SHIELD',
              style: TextStyle(
                color: CyberShieldApp.blue,
                fontWeight: FontWeight.w900,
                letterSpacing: 1.5,
              ),
            ),
          ],
        ),
        actions: const [
          Padding(
            padding: EdgeInsetsDirectional.only(end: 18),
            child: Icon(Icons.language, color: Color(0xFF91A9CC)),
          ),
        ],
      ),
      body: Stack(
        children: [
          const Positioned(top: -110, left: -100, child: _GlowOrb(size: 280)),
          SafeArea(
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(20, 12, 20, 30),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 620),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _brandHero(),
                      const SizedBox(height: 24),
                      _sectionTitle(
                        'ابدأ بفحص موقعك',
                        'تقييم أولي لمؤشرات الأمان الخارجية',
                      ),
                      const SizedBox(height: 14),
                      _scanCard(),
                      const SizedBox(height: 22),
                      _sectionTitle('ماذا نراجع؟', 'مجموعات الفحوصات الأمنية'),
                      const SizedBox(height: 12),
                      _checkCategories(),
                      const SizedBox(height: 20),
                      _notice(),
                      const SizedBox(height: 22),
                      const Text(
                        'SECURE  •  PREVENT  •  THRIVE',
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          color: Color(0xFF52749F),
                          fontSize: 11,
                          letterSpacing: 2,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _brandHero() => Container(
    padding: const EdgeInsets.fromLTRB(22, 25, 22, 23),
    decoration: BoxDecoration(
      borderRadius: BorderRadius.circular(24),
      gradient: const LinearGradient(
        begin: Alignment.topRight,
        end: Alignment.bottomLeft,
        colors: [Color(0xFF0C2D59), Color(0xFF06152D), Color(0xFF030B1A)],
      ),
      border: Border.all(color: const Color(0xFF14549A).withValues(alpha: .65)),
      boxShadow: [
        BoxShadow(
          color: CyberShieldApp.blue.withValues(alpha: .12),
          blurRadius: 28,
          spreadRadius: 1,
        ),
      ],
    ),
    child: Column(
      children: [
        Container(
          width: 86,
          height: 86,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: CyberShieldApp.blue.withValues(alpha: .10),
            border: Border.all(
              color: CyberShieldApp.cyan.withValues(alpha: .55),
            ),
            boxShadow: [
              BoxShadow(
                color: CyberShieldApp.blue.withValues(alpha: .28),
                blurRadius: 25,
              ),
            ],
          ),
          child: const Icon(
            Icons.shield_outlined,
            size: 55,
            color: CyberShieldApp.cyan,
          ),
        ),
        const SizedBox(height: 16),
        const Text(
          'CYBER SHIELD',
          style: TextStyle(
            fontSize: 25,
            fontWeight: FontWeight.w900,
            letterSpacing: 2,
          ),
        ),
        const SizedBox(height: 7),
        const Text(
          'درعك الذكي لعالم رقمي أكثر أماناً',
          textAlign: TextAlign.center,
          style: TextStyle(color: Color(0xFFB7C9E4), fontSize: 14, height: 1.7),
        ),
        const SizedBox(height: 18),
        const Row(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: [
            _MiniFeature(icon: Icons.verified_user_outlined, label: 'الحماية'),
            _MiniFeature(icon: Icons.fingerprint, label: 'الخصوصية'),
            _MiniFeature(icon: Icons.hub_outlined, label: 'التهديدات'),
            _MiniFeature(icon: Icons.cloud_outlined, label: 'السحابة'),
          ],
        ),
      ],
    ),
  );

  Widget _sectionTitle(String title, String subtitle) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(
        title,
        style: const TextStyle(fontSize: 19, fontWeight: FontWeight.bold),
      ),
      const SizedBox(height: 4),
      Text(
        subtitle,
        style: const TextStyle(fontSize: 12, color: Color(0xFF8299B9)),
      ),
    ],
  );

  Widget _scanCard() => Container(
    padding: const EdgeInsets.all(19),
    decoration: BoxDecoration(
      color: const Color(0xFF081A35),
      borderRadius: BorderRadius.circular(21),
      border: Border.all(color: const Color(0xFF174477)),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(
          'رابط الموقع الإلكتروني',
          style: TextStyle(fontWeight: FontWeight.w700),
        ),
        const SizedBox(height: 10),
        TextField(
          controller: _urlController,
          keyboardType: TextInputType.url,
          textDirection: TextDirection.ltr,
          textAlign: TextAlign.left,
          decoration: const InputDecoration(
            hintText: 'https://example.com',
            prefixIcon: Icon(Icons.link, color: CyberShieldApp.cyan),
          ),
        ),
        const SizedBox(height: 13),
        Container(
          decoration: BoxDecoration(
            color: const Color(0xFF061329),
            borderRadius: BorderRadius.circular(13),
          ),
          child: CheckboxListTile(
            value: _authorizationConfirmed,
            onChanged: (value) =>
                setState(() => _authorizationConfirmed = value ?? false),
            activeColor: CyberShieldApp.blue,
            checkColor: Colors.white,
            controlAffinity: ListTileControlAffinity.leading,
            contentPadding: const EdgeInsets.symmetric(horizontal: 10),
            title: const Text(
              'أؤكد أن لدي تصريحاً بفحص هذا الموقع.',
              style: TextStyle(fontSize: 13, height: 1.5),
            ),
          ),
        ),
        const SizedBox(height: 16),
        SizedBox(
          height: 54,
          child: DecoratedBox(
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [CyberShieldApp.blue, CyberShieldApp.cyan],
              ),
              borderRadius: BorderRadius.circular(14),
              boxShadow: [
                BoxShadow(
                  color: CyberShieldApp.blue.withValues(alpha: .25),
                  blurRadius: 16,
                ),
              ],
            ),
            child: FilledButton.icon(
              onPressed: _isScanning ? null : _startScan,
              icon: _isScanning
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.radar),
              label: Text(
                _isScanning ? 'جارٍ تنفيذ الفحص...' : 'بدء الفحص الأمني',
                style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
              ),
              style: FilledButton.styleFrom(
                backgroundColor: Colors.transparent,
                shadowColor: Colors.transparent,
                foregroundColor: const Color(0xFF00152B),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
              ),
            ),
          ),
        ),
      ],
    ),
  );

  Widget _checkCategories() => const Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(
        'مجالات الفحص في خطة CyberShield',
        style: TextStyle(fontSize: 12, color: Color(0xFF91A9CC)),
      ),
      SizedBox(height: 10),
      Wrap(
        spacing: 10,
        runSpacing: 10,
        children: [
          _CategoryChip(icon: Icons.lock_outline, label: 'HTTPS وTLS'),
          _CategoryChip(icon: Icons.tune, label: 'ترويسات الأمان'),
          _CategoryChip(icon: Icons.cookie_outlined, label: 'الكوكيز'),
          _CategoryChip(icon: Icons.dns_outlined, label: 'DNS'),
          _CategoryChip(icon: Icons.visibility_outlined, label: 'كشف المعلومات'),
          _CategoryChip(icon: Icons.policy_outlined, label: 'سياسات الوصول'),
          _CategoryChip(icon: Icons.cached_outlined, label: 'التخزين المؤقت'),
          _CategoryChip(icon: Icons.code_outlined, label: 'مؤشرات XSS وSQLi'),
        ],
      ),
      SizedBox(height: 9),
      Text(
        'تظهر في التقرير نتائج الفحوصات التي ينفذها المحرك فعلياً فقط.',
        style: TextStyle(fontSize: 11, color: Color(0xFF8299B9), height: 1.6),
      ),
    ],
  );

  Widget _notice() => Container(
    padding: const EdgeInsets.all(15),
    decoration: BoxDecoration(
      color: const Color(0xFF17233A),
      borderRadius: BorderRadius.circular(15),
      border: Border.all(color: const Color(0xFF365174)),
    ),
    child: const Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(Icons.info_outline, color: CyberShieldApp.cyan),
        SizedBox(width: 11),
        Expanded(
          child: Text(
            'يقدم CyberShield تقييماً أولياً لمؤشرات أمن محددة، ولا يمثل اختبار اختراق شاملاً أو ضماناً بأن الموقع آمن بالكامل. لا تفحص إلا المواقع التي تملك تصريحاً بفحصها.',
            style: TextStyle(
              color: Color(0xFFB7C9E4),
              fontSize: 12,
              height: 1.8,
            ),
          ),
        ),
      ],
    ),
  );
}

class _MiniFeature extends StatelessWidget {
  const _MiniFeature({required this.icon, required this.label});
  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) => Column(
    children: [
      Icon(icon, color: CyberShieldApp.cyan, size: 23),
      const SizedBox(height: 6),
      Text(
        label,
        style: const TextStyle(color: Color(0xFFB7C9E4), fontSize: 10),
      ),
    ],
  );
}

class _CategoryChip extends StatelessWidget {
  const _CategoryChip({required this.icon, required this.label});
  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 13, vertical: 11),
    decoration: BoxDecoration(
      color: const Color(0xFF081A35),
      borderRadius: BorderRadius.circular(13),
      border: Border.all(color: const Color(0xFF173B68)),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, color: CyberShieldApp.cyan, size: 18),
        const SizedBox(width: 8),
        Text(
          label,
          style: const TextStyle(fontSize: 12, color: Color(0xFFD7E6FA)),
        ),
      ],
    ),
  );
}

class _GlowOrb extends StatelessWidget {
  const _GlowOrb({required this.size});
  final double size;

  @override
  Widget build(BuildContext context) => IgnorePointer(
    child: Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: RadialGradient(
          colors: [
            CyberShieldApp.blue.withValues(alpha: .13),
            Colors.transparent,
          ],
        ),
      ),
    ),
  );
}


/// صفحة معاينة النتائج.
/// البيانات هنا ليست نتائج فحص فعلية؛ ستُستبدل باستجابة API عند التكامل.
