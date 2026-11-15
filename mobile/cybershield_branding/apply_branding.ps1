$ErrorActionPreference = 'Stop'

# This script must remain inside the extracted 'cybershield_branding' folder.
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $ProjectRoot

$PubspecPath = Join-Path $ProjectRoot 'pubspec.yaml'
$ManifestPath = Join-Path $ProjectRoot 'android\app\src\main\AndroidManifest.xml'
$SourceAssets = Join-Path $PSScriptRoot 'assets\icon'
$DestinationAssets = Join-Path $ProjectRoot 'assets\icon'
$ConfigSource = Join-Path $PSScriptRoot 'flutter_launcher_icons.yaml'
$ConfigDestination = Join-Path $ProjectRoot 'flutter_launcher_icons.yaml'

if (-not (Test-Path $PubspecPath)) { throw 'لم أجد pubspec.yaml. فك ضغط الحزمة داخل مجلد mobile ثم شغّل السكربت.' }
if (-not (Test-Path $ManifestPath)) { throw 'لم أجد AndroidManifest.xml في مسار Android المعتاد.' }
if (-not (Test-Path (Join-Path $SourceAssets 'app_icon.png'))) { throw 'ملف app_icon.png غير موجود داخل الحزمة.' }
if (-not (Test-Path (Join-Path $SourceAssets 'adaptive_foreground.png'))) { throw 'ملف adaptive_foreground.png غير موجود داخل الحزمة.' }

$BackupBase = Join-Path $env:LOCALAPPDATA 'CyberShield\branding_backups'
$BackupDir = Join-Path $BackupBase (Get-Date -Format 'yyyyMMdd_HHmmss')
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
Copy-Item $PubspecPath (Join-Path $BackupDir 'pubspec.yaml')
Copy-Item $ManifestPath (Join-Path $BackupDir 'AndroidManifest.xml')
if (Test-Path $ConfigDestination) { Copy-Item $ConfigDestination (Join-Path $BackupDir 'flutter_launcher_icons.yaml') }

New-Item -ItemType Directory -Path $DestinationAssets -Force | Out-Null
foreach ($FileName in @('app_icon.png', 'adaptive_foreground.png')) {
    $Target = Join-Path $DestinationAssets $FileName
    if (Test-Path $Target) { Copy-Item $Target (Join-Path $BackupDir $FileName) }
    Copy-Item (Join-Path $SourceAssets $FileName) $Target -Force
}
Copy-Item $ConfigSource $ConfigDestination -Force

# Change only the Android launcher label; do not touch applicationId/package ID.
$Manifest = Get-Content -Path $ManifestPath -Raw
if ($Manifest -notmatch 'android:label\s*=\s*"[^"]+"') {
    throw 'لم أجد android:label داخل AndroidManifest.xml. لم أغيّر الملف؛ أرسل محتواه لمراجعته.'
}
$Manifest = [regex]::Replace($Manifest, 'android:label\s*=\s*"[^"]+"', 'android:label="CyberShield"', 1)
[System.IO.File]::WriteAllText($ManifestPath, $Manifest, (New-Object System.Text.UTF8Encoding($false)))

# Add the icon generator only if it is not already declared in pubspec.yaml.
$Pubspec = Get-Content -Path $PubspecPath -Raw
if ($Pubspec -notmatch '(?m)^\s*flutter_launcher_icons\s*:') {
    Write-Host 'إضافة flutter_launcher_icons إلى dev_dependencies...' -ForegroundColor Cyan
    & flutter pub add --dev 'flutter_launcher_icons:^0.14.4'
    if ($LASTEXITCODE -ne 0) { throw 'فشلت إضافة حزمة flutter_launcher_icons. لم تُحذف النسخ الاحتياطية.' }
} else {
    Write-Host 'الحزمة flutter_launcher_icons موجودة مسبقاً؛ لم أضف نسخة مكررة.' -ForegroundColor Yellow
}

Write-Host 'تحديث الاعتماديات...' -ForegroundColor Cyan
& flutter pub get
if ($LASTEXITCODE -ne 0) { throw 'فشل flutter pub get. احتفظت بالنسخ الاحتياطية.' }

Write-Host 'إنشاء أيقونات Android...' -ForegroundColor Cyan
& dart run flutter_launcher_icons -f flutter_launcher_icons.yaml
if ($LASTEXITCODE -ne 0) { throw 'فشل توليد الأيقونات. احتفظت بالنسخ الاحتياطية.' }

Write-Host ''
Write-Host 'اكتملت إعدادات الاسم والأيقونة.' -ForegroundColor Green
Write-Host "الاسم الجديد: CyberShield"
Write-Host "النسخ الاحتياطية: $BackupDir"
Write-Host 'لم يتم تغيير applicationId أو كود Flutter أو ملفات Backend/Scanner.'
