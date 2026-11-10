حزمة تخصيص هوية CyberShield - Android

1) فك ضغط CyberShield_Branding_Assets.zip داخل مجلد:
   C:\CyberShield\mobile
   يجب أن يصبح المسار:
   C:\CyberShield\mobile\cybershield_branding\apply_branding.ps1

2) افتح PowerShell داخل C:\CyberShield\mobile ثم نفّذ:
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\cybershield_branding\apply_branding.ps1

3) عند اكتمال السكربت، ابنِ APK:
   flutter build apk --debug

4) ثبّت النسخة الجديدة على المحاكي:
   $Adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
   $Apk = ".\build\app\outputs\flutter-apk\app-debug.apk"
   & $Adb install -r $Apk

5) ارجع إلى الشاشة الرئيسية للمحاكي. يجب أن يظهر الاسم CyberShield والأيقونة الجديدة.

ملاحظات:
- السكربت يأخذ نسخاً احتياطية من pubspec.yaml وAndroidManifest.xml وأي صور أيقونات موجودة قبل استبدالها.
- التغيير يخص Android فقط. لم يتم تعديل iOS.
- لم يتم تغيير applicationId أو ملفات main.dart أو Backend أو Scanner.
- إذا بقيت الأيقونة القديمة ظاهرة بسبب ذاكرة Launcher المؤقتة، أعد تشغيل Launcher/المحاكي أولاً قبل التفكير في إزالة التطبيق.
