5
import 'package:flutter/material.dart';

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
            borderSide: const BorderSide(
              color: Color(0xFF29364C),
            ),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(14),
            borderSide: const BorderSide(
              color: accentColor,
            ),
          ),
        ),
      ),
      builder: (context, child) {
        return Directionality(
          textDirection: TextDirection.rtl,
          child: child!,
        );
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
  final TextEditingController _urlController =
      TextEditingController();

  bool _authorizationConfirmed = false;

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  void _startScan() {
    final input = _urlController.text.trim();
    final uri = Uri.tryParse(input);

    final validUrl = uri != null &&
        uri.scheme.toLowerCase() == 'https' &&
        uri.host.isNotEmpty &&
        uri.userInfo.isEmpty;

    if (!validUrl) {
      _showMessage(
        'أدخل رابط HTTPS صحيحاً، مثل https://example.com',
      );
      return;
    }

    if (!_authorizationConfirmed) {
      _showMessage(
        'يرجى تأكيد امتلاكك تصريحاً لفحص الموقع.',
      );
      return;
    }

    _showMessage(
      'الواجهة جاهزة، وسيتم ربط محرك الفحص في الخطوة القادمة.',
    );
  }

  void _showMessage(String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(
          content: Text(message),
          behavior: SnackBarBehavior.floating,
        ),
      );
  }

  @override
  Widget build(BuildContext context) {
    const accent = Color(0xFF36D6B5);
    const muted = Color(0xFF9BAAC0);

    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF0B1120),
        titleSpacing: 20,
        title: const Row(
          children: [
            Icon(
              Icons.shield_outlined,
              color: accent,
              size: 30,
            ),
            SizedBox(width: 10),
            Text(
              'CyberShield',
              style: TextStyle(
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
      ),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(22),
            child: ConstrainedBox(
              constraints: const BoxConstraints(
                maxWidth: 560,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Container(
                    padding: const EdgeInsets.all(24),
                    decoration: BoxDecoration(
                      color: const Color(0xFF151F32),
                      borderRadius: BorderRadius.circular(24),
                      border: Border.all(
                        color: const Color(0xFF29364C),
                      ),
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
                              onChanged: (value) {
                                setState(() {
                                  _authorizationConfirmed =
                                      value ?? false;
                                });
                              },
                              contentPadding: EdgeInsets.zero,
                              controlAffinity:
                                  ListTileControlAffinity.leading,
                              activeColor: accent,
                              title: const Text(
                                'أؤكد أن لدي تصريحاً بفحص هذا الموقع.',
                                style: TextStyle(
                                  fontSize: 14,
                                  height: 1.6,
                                ),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(height: 22),
                        SizedBox(
                          width: double.infinity,
                          height: 54,
                          child: FilledButton.icon(
                            onPressed: _startScan,
                            icon: const Icon(Icons.search),
                            label: const Text(
                              'بدء الفحص',
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            style: FilledButton.styleFrom(
                              backgroundColor: accent,
                              foregroundColor:
                                  const Color(0xFF07151A),
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
                      border: Border.all(
                        color: const Color(0xFF66502B),
                      ),
                    ),
                    child: const Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          Icons.info_outline,
                          color: Color(0xFFFFD27A),
                        ),
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
