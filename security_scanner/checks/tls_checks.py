"""Evidence-based TLS and redirect policy evaluators."""

from datetime import datetime, timezone
import ipaddress
from urllib.parse import urlsplit, urljoin

from .evaluator import CheckEvaluator
from .result import CheckResult
from ..scanner import _is_allowed_ip


def _parse_asn1_date(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class TLSMetadataEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        cid = self.definition.check_id
        md = evidence.tls_metadata
        if evidence.tls_verified is not True:
            return self._not_verified_result(self.definition.title, "لم ينجح اتصال TLS مع التحقق من الشهادة؛ لا يمكن إصدار حكم تابع للبيانات الوصفية.")
        if cid == "tls_certificate_chain":
            if md.get("chain_available") is True:
                return CheckResult(cid, self.definition.title, "passed", "info", "high", "نجح اتصال verify=True وأكدت المكتبة وجود سلسلة الشهادات المتحقق منها.", "توفر دليل اتصال موثق وسلسلة فعلية من طبقة TLS.", "حافظ على التحقق من الشهادات مفعلاً.", ("لا تُحفظ الشهادات الخام في التقرير.",))
            return self._not_verified_result(self.definition.title, "نجح الاتصال الموثق لكن لم تتوفر سلسلة متحقق منها قابلة للفحص.")
        if cid == "tls_certificate_expiry":
            start, expiry = _parse_asn1_date(md.get("not_before")), _parse_asn1_date(md.get("not_after"))
            if start is None or expiry is None:
                return self._not_verified_result(self.definition.title, "بيانات تاريخ صلاحية الشهادة غير متاحة أو غير قابلة للتحليل.")
            now = datetime.now(timezone.utc)
            if start > now:
                return CheckResult(cid, self.definition.title, "warning", "high", "high", "تاريخ بدء الشهادة ما زال في المستقبل وفق الدليل المرصود.", "الشهادة غير صالحة بعد.", "تحقق من إصدار الشهادة ووقت النظام.", ())
            if expiry <= now:
                return CheckResult(cid, self.definition.title, "warning", "high", "high", "انتهت صلاحية الشهادة وفق تاريخ الانتهاء المرصود.", "الشهادة منتهية الصلاحية.", "جدد الشهادة.", ())
            days = (expiry - now).total_seconds() / 86400
            if days <= 30:
                return CheckResult(cid, self.definition.title, "warning", "medium", "high", "تنتهي صلاحية الشهادة خلال 30 يوماً شاملاً.", "الشهادة قريبة الانتهاء ضمن الحد المعتمد.", "جدد الشهادة قبل انتهائها.", ())
            return CheckResult(cid, self.definition.title, "passed", "info", "high", "الشهادة صالحة ويتبقى على انتهائها أكثر من 30 يوماً.", "تاريخ الشهادة المرصود يتجاوز حد قرب الانتهاء.", "راقب تاريخ التجديد.", ())
        version, cipher = md.get("version"), md.get("cipher")
        if not isinstance(version, str) or not isinstance(cipher, str):
            return self._not_verified_result(self.definition.title, "بيانات الإصدار ومجموعة التشفير الفعلية غير متاحة.")
        name = cipher.upper().replace("-", "_")
        name = name.replace("AES128", "AES_128").replace("AES256", "AES_256")
        if version not in ("TLSv1.2", "TLSv1.3"):
            return CheckResult(cid, self.definition.title, "warning", "high", "high", f"تم التفاوض على إصدار TLS قديم: {version}.", "الإصدار أقل من TLS 1.2.", "فعّل TLS 1.2 على الأقل.", ())
        forbidden = ("RC4", "3DES", "NULL", "EXPORT", "ANON", "CBC")
        static_key_exchange = (
            name.startswith("TLS_RSA_") or name.startswith("TLS_DH_")
            or "_ECDH_" in name or name.startswith("ECDH_")
        )
        if any(token in name for token in forbidden) or static_key_exchange:
            return CheckResult(cid, self.definition.title, "warning", "high", "high", "مجموعة التشفير المرصودة تطابق نمطاً محظوراً.", "مجموعة التشفير تستخدم خوارزمية أو تبادل مفاتيح مرفوضاً.", "اختر مجموعة متوافقة مع سياسة TLS المعتمدة.", ())
        if version == "TLSv1.2":
            acceptable = "ECDHE" in name and (("AES_128_GCM" in name or "AES_256_GCM" in name) or "CHACHA20_POLY1305" in name)
        else:
            acceptable = name in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")
        if not acceptable:
            return self._not_verified_result(self.definition.title, "اسم مجموعة التشفير معروف الصياغة لكنه غير مصنف ضمن سياسة القبول دون دليل ضعف محدد.")
        return CheckResult(cid, self.definition.title, "passed", "info", "high", f"اتصال TLS الفعلي تفاوض على {version} ومجموعة متوافقة مع السياسة.", "إعداد TLS يطابق الحد الأدنى وقائمة القبول.", "حافظ على إعداد TLS الحالي محدثاً.", ())


class RedirectPolicyEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        cid = self.definition.check_id
        if cid == "http_to_https_redirect":
            if evidence.http_probe_error:
                if evidence.http_probe_error == "internal":
                    return CheckResult(cid, self.definition.title, "error", "info", "low", "تعذر تنفيذ مسبار HTTP بسبب خطأ داخلي.", "لم ينتج دليل قابل للتقييم.", "راجع سجل التنفيذ الداخلي.", ())
                return self._not_verified_result(self.definition.title, "تعذر الحصول على استجابة HTTP من مسبار الأصل.")
            code = evidence.http_probe_status
            if code is None:
                return self._not_verified_result(self.definition.title, "لم تتوفر استجابة من مسبار HTTP.")
            if code in (301, 302, 303, 307, 308):
                if not evidence.http_probe_location:
                    return CheckResult(cid, self.definition.title, "warning", "medium", "high", f"استجابة HTTP {code} لا تتضمن Location.", "تعذر إثبات ترقية إلى HTTPS دون وجهة تحويل.", "أعد Location صالحة على HTTPS/443.", ())
                destination = evidence.redirect_destination_url
                if not destination:
                    return self._not_verified_result(self.definition.title, "تعذر تحليل Location وفق عنوان طلب HTTP الفعلي.")
                try:
                    parsed = urlsplit(destination)
                    port = parsed.port
                except ValueError:
                    return CheckResult(cid, self.definition.title, "warning", "medium", "medium", "قيمة Location غير صالحة.", "تعذر إثبات وجهة HTTPS.", "أرسل Location صالحة.", ())
                if parsed.scheme.lower() == "https" and port in (None, 443) and parsed.username is None and parsed.password is None:
                    return CheckResult(cid, self.definition.title, "passed", "info", "high", f"استجابة HTTP {code} تتضمن وجهة HTTPS على المنفذ 443.", "تم إثبات استجابة ترقية دون اتباعها.", "حافظ على التحويل الآمن.", ("لم يتم الاتصال بوجهة التحويل.",))
                return CheckResult(cid, self.definition.title, "warning", "medium", "high", "استجابة HTTP وجهتها لا تحقق HTTPS/443 أو تحتوي بيانات اعتماد.", "لم تثبت ترقية آمنة إلى HTTPS.", "استخدم وجهة HTTPS/443 دون بيانات اعتماد.", ("لم يتم الاتصال بوجهة التحويل.",))
            return CheckResult(cid, self.definition.title, "warning", "medium", "high", f"الأصل قابل للوصول عبر HTTP ويرد بالرمز {code} دون تحويل مقبول إلى HTTPS.", "الاستجابة لا تستخدم رمز تحويل HTTP إلى HTTPS معتمداً.", "حوّل طلبات HTTP إلى HTTPS.", ())

        location = evidence.http_probe_location
        if not evidence.http_probe_status or evidence.http_probe_status not in (301, 302, 303, 307, 308):
            return self._result("skipped", "info", "high", "لا توجد وجهة تحويل HTTP منطبقة على هذه الاستجابة.", "تم تخطي تقييم الوجهة لعدم انطباقه.")
        if not location:
            return self._not_verified_result(self.definition.title, "استجابة تحويل HTTP لا تتضمن Location.")
        destination = evidence.redirect_destination_url
        if not destination:
            return self._not_verified_result(self.definition.title, "تعذر تحليل الوجهة أو جمع DNS ضمن المهلة.")
        try:
            parsed = urlsplit(destination)
            port = parsed.port
        except ValueError:
            return self._blocked("صيغة Location غير صالحة.")
        if parsed.scheme.lower() != "https" or port not in (None, 443) or parsed.username is not None or parsed.password is not None or "\\" in parsed.netloc:
            return self._blocked("الوجهة تخالف سياسة HTTPS/443 أو تتضمن بيانات اعتماد.")
        if not parsed.hostname:
            return self._blocked("الوجهة لا تتضمن مضيفاً صالحاً.")
        try:
            literal = ipaddress.ip_address(parsed.hostname)
            addresses = (literal,)
        except ValueError:
            if not evidence.redirect_dns_answers:
                return self._not_verified_result(self.definition.title, "لم تتوفر إجابات DNS كاملة للوجهة.")
            try:
                addresses = tuple(ipaddress.ip_address(item) for item in evidence.redirect_dns_answers)
            except ValueError:
                return self._blocked("تتضمن إجابات DNS عنواناً غير صالح.")
        if any(not _is_allowed_ip(item) for item in addresses):
            return self._blocked("إجابة واحدة على الأقل خاصة أو محجوزة؛ رُفضت مجموعة DNS كاملة.")
        return self._result("passed", "info", "high", "الوجهة HTTPS/443 وكل عناوين DNS المرصودة عامة.", "اجتازت الوجهة سياسة العناوين دون الاتصال بها.")

    def _result(self, status, severity, confidence, evidence, explanation):
        return CheckResult(self.definition.check_id, self.definition.title, status, severity, confidence, evidence, explanation, "لا تتبع التحويلات تلقائياً.", ("لم يتم الاتصال بوجهة التحويل.",))

    def _blocked(self, text):
        return CheckResult(self.definition.check_id, self.definition.title, "warning", "high", "high", text, "حُظرت الوجهة محلياً قبل أي اتصال.", "استخدم وجهة عامة على HTTPS/443.", ("لم يتم الاتصال بوجهة التحويل.",))
