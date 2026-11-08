import 'package:flutter/material.dart';

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
  bool _authorizationConfirmed = false;

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  void _startScan() {
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
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ResultsScreen(targetUrl: uri.toString()),
      ),
    );
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
              onPressed: _startScan,
              icon: const Icon(Icons.radar),
              label: const Text(
                'بدء الفحص الأمني',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
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

  Widget _checkCategories() => const Wrap(
    spacing: 10,
    runSpacing: 10,
    children: [
      _CategoryChip(icon: Icons.lock_outline, label: 'HTTPS وTLS'),
      _CategoryChip(icon: Icons.tune, label: 'ترويسات الأمان'),
      _CategoryChip(icon: Icons.cookie_outlined, label: 'الكوكيز'),
      _CategoryChip(icon: Icons.dns_outlined, label: 'DNS'),
      _CategoryChip(icon: Icons.visibility_outlined, label: 'كشف المعلومات'),
      _CategoryChip(icon: Icons.policy_outlined, label: 'سياسات الوصول'),
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
class ResultsScreen extends StatelessWidget {
  const ResultsScreen({super.key, required this.targetUrl});

  final String targetUrl;

  static const _muted = Color(0xFF91A9CC);
  static const _line = Color(0xFF173B68);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: CyberShieldApp.navy,
        surfaceTintColor: Colors.transparent,
        title: const Text(
          'تقرير الفحص',
          style: TextStyle(fontWeight: FontWeight.bold),
        ),
        actions: const [
          Padding(
            padding: EdgeInsetsDirectional.only(end: 18),
            child: Icon(Icons.shield_outlined, color: CyberShieldApp.cyan),
          ),
        ],
      ),
      body: Stack(
        children: [
          const Positioned(
            top: -110,
            left: -100,
            child: _GlowOrb(size: 260),
          ),
          SafeArea(
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(20, 12, 20, 30),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 620),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _buildTargetCard(),
                      const SizedBox(height: 16),
                      _buildStatusCard(),
                      const SizedBox(height: 18),
                      const Text(
                        'ملخص الفحص',
                        style: TextStyle(
                          fontSize: 19,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 10),
                      _buildSummaryGrid(),
                      const SizedBox(height: 22),
                      const Text(
                        'تفاصيل مجموعات الفحص',
                        style: TextStyle(
                          fontSize: 19,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 10),
                      _buildCheckList(),
                      const SizedBox(height: 18),
                      _buildLimitNotice(),
                      const SizedBox(height: 22),
                      SizedBox(
                        height: 52,
                        child: FilledButton.icon(
                          onPressed: () => Navigator.of(context).pop(),
                          icon: const Icon(Icons.arrow_forward),
                          label: const Text(
                            'العودة إلى الصفحة الرئيسية',
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                          style: FilledButton.styleFrom(
                            backgroundColor: CyberShieldApp.blue,
                            foregroundColor: Colors.white,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(14),
                            ),
                          ),
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

  Widget _buildTargetCard() => Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: const Color(0xFF081A35),
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: _line),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'الموقع المستهدف',
              style: TextStyle(color: _muted, fontSize: 12),
            ),
            const SizedBox(height: 7),
            Directionality(
              textDirection: TextDirection.ltr,
              child: SelectableText(
                targetUrl,
                textAlign: TextAlign.left,
                style: const TextStyle(
                  color: CyberShieldApp.cyan,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ),
      );

  Widget _buildStatusCard() => Container(
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(20),
          gradient: const LinearGradient(
            begin: Alignment.topRight,
            end: Alignment.bottomLeft,
            colors: [Color(0xFF0C2D59), Color(0xFF06152D), Color(0xFF030B1A)],
          ),
          border: Border.all(color: const Color(0xFF14549A)),
          boxShadow: [
            BoxShadow(
              color: CyberShieldApp.blue.withValues(alpha: .12),
              blurRadius: 24,
            ),
          ],
        ),
        child: const Column(
          children: [
            Icon(
              Icons.hourglass_top_rounded,
              color: CyberShieldApp.cyan,
              size: 38,
            ),
            SizedBox(height: 10),
            Text(
              'الواجهة جاهزة لاستقبال النتائج',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 7),
            Text(
              'لم يتم تنفيذ فحص أمني فعلي بعد',
              textAlign: TextAlign.center,
              style: TextStyle(color: Color(0xFFB7C9E4), fontSize: 13),
            ),
            SizedBox(height: 12),
            _DemoBadge(),
          ],
        ),
      );

  Widget _buildSummaryGrid() => GridView.count(
        crossAxisCount: 2,
        shrinkWrap: true,
        physics: NeverScrollableScrollPhysics(),
        crossAxisSpacing: 10,
        mainAxisSpacing: 10,
        childAspectRatio: 2.25,
        children: [
          _SummaryTile(
            icon: Icons.verified_outlined,
            label: 'سليم',
            value: '—',
            color: Color(0xFF35C8FF),
          ),
          _SummaryTile(
            icon: Icons.warning_amber_rounded,
            label: 'تحذيرات',
            value: '—',
            color: Color(0xFFFFC857),
          ),
          _SummaryTile(
            icon: Icons.error_outline,
            label: 'مخاطر',
            value: '—',
            color: Color(0xFFFF6B78),
          ),
          _SummaryTile(
            icon: Icons.help_outline,
            label: 'لم يتم التحقق',
            value: '—',
            color: Color(0xFF91A9CC),
          ),
        ],
      );

  Widget _buildCheckList() => Container(
        decoration: BoxDecoration(
          color: const Color(0xFF081A35),
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: _line),
        ),
        child: const Column(
          children: [
            _PendingCheckTile(
              icon: Icons.lock_outline,
              title: 'HTTPS وTLS',
            ),
            Divider(height: 1, color: _line),
            _PendingCheckTile(
              icon: Icons.tune,
              title: 'ترويسات الأمان',
            ),
            Divider(height: 1, color: _line),
            _PendingCheckTile(
              icon: Icons.cookie_outlined,
              title: 'الكوكيز',
            ),
            Divider(height: 1, color: _line),
            _PendingCheckTile(
              icon: Icons.dns_outlined,
              title: 'DNS',
            ),
            Divider(height: 1, color: _line),
            _PendingCheckTile(
              icon: Icons.visibility_outlined,
              title: 'كشف المعلومات',
            ),
            Divider(height: 1, color: _line),
            _PendingCheckTile(
              icon: Icons.policy_outlined,
              title: 'سياسات الوصول',
            ),
          ],
        ),
      );

  Widget _buildLimitNotice() => Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: const Color(0xFF17233A),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: const Color(0xFF365174)),
        ),
        child: const Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.info_outline, color: CyberShieldApp.cyan),
            SizedBox(width: 10),
            Expanded(
              child: Text(
                'هذه معاينة لشكل التقرير فقط. ستظهر حالة كل فحص ودرجة الخطورة والأدلة والتوصيات بعد ربط التطبيق بخدمة الفحص. عدم ظهور نتيجة لا يعني أن الموقع آمن.',
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

class _DemoBadge extends StatelessWidget {
  const _DemoBadge();

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
        decoration: BoxDecoration(
          color: CyberShieldApp.cyan.withValues(alpha: .10),
          borderRadius: BorderRadius.circular(30),
          border: Border.all(
            color: CyberShieldApp.cyan.withValues(alpha: .45),
          ),
        ),
        child: const Text(
          'معاينة الواجهة — دون نتائج حقيقية',
          style: TextStyle(
            color: CyberShieldApp.cyan,
            fontSize: 11,
            fontWeight: FontWeight.w600,
          ),
        ),
      );
}

class _SummaryTile extends StatelessWidget {
  const _SummaryTile({
    required this.icon,
    required this.label,
    required this.value,
    required this.color,
  });

  final IconData icon;
  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF081A35),
          borderRadius: BorderRadius.circular(15),
          border: Border.all(color: const Color(0xFF173B68)),
        ),
        child: Row(
          children: [
            Icon(icon, color: color, size: 22),
            const SizedBox(width: 9),
            Expanded(
              child: Text(
                label,
                style: const TextStyle(
                  color: Color(0xFFB7C9E4),
                  fontSize: 11,
                ),
              ),
            ),
            Text(
              value,
              style: TextStyle(
                color: color,
                fontSize: 19,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
      );
}

class _PendingCheckTile extends StatelessWidget {
  const _PendingCheckTile({
    required this.icon,
    required this.title,
  });

  final IconData icon;
  final String title;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
        child: Row(
          children: [
            Icon(icon, color: CyberShieldApp.cyan, size: 21),
            const SizedBox(width: 11),
            Expanded(
              child: Text(
                title,
                style: const TextStyle(
                  color: Color(0xFFD7E6FA),
                  fontSize: 13,
                ),
              ),
            ),
            const Text(
              'بانتظار التكامل',
              style: TextStyle(
                color: Color(0xFF91A9CC),
                fontSize: 11,
              ),
            ),
            const SizedBox(width: 6),
            const Icon(
              Icons.schedule_rounded,
              color: Color(0xFF91A9CC),
              size: 16,
            ),
          ],
        ),
      );
}
