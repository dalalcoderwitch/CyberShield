"""Conservative CORS and open-redirect evaluators."""

from urllib.parse import urljoin, urlsplit
import ipaddress
import re

from .evaluator import CheckEvaluator
from .result import CheckResult


_TEST_ORIGIN = "https://cybershield.invalid"
_REDIRECT_STATUS_CODES = frozenset({300, 301, 302, 303, 305, 307, 308})


class CORSConfigurationEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        headers = evidence.cors_headers
        if evidence.cors_probe_available is not True or evidence.cors_probe_error:
            return self._result("not_verified", "info", "low",
                                "لم تتوفر استجابة OPTIONS موثوقة قابلة للتحليل.",
                                "تعذر الحكم على استجابة CORS من هذا الفحص المحدود.",
                                ("لم يُرسل سوى طلب preflight واحد، ولم تُرسل Cookies أو Authorization.",))
        status = evidence.cors_probe_status
        if status is None or not 200 <= status < 300:
            return self._result("not_verified", "info", "low",
                                "لم تُرجع استجابة OPTIONS ناجحة قابلة لتقييم preflight.",
                                "قد لا يدعم المسار OPTIONS أو تعذر الحصول على استجابة مناسبة.",
                                ("هذه النتيجة لا تحكم على استجابات أو مسارات أخرى.",))

        origin_values = headers.get("access-control-allow-origin", ())
        if not origin_values:
            return self._result("passed", "info", "medium",
                                f"استجابة OPTIONS {status} لم تمنح الإذن للأصل الاختباري { _TEST_ORIGIN }.",
                                "لم يظهر إذن CORS لهذا الطلب الاختباري؛ وهذا لا يثبت سلوك بقية المسارات أو أنواع الطلبات.",
                                ("النتيجة تخص طلب OPTIONS واحداً إلى URL الهدف فقط.",))
        if len(origin_values) != 1 or "," in origin_values[0]:
            return self._not_verified("تعددت قيم Access-Control-Allow-Origin أو تعارضت.")
        origin = origin_values[0].strip()
        if not origin or any(ord(c) < 32 or ord(c) == 127 for c in origin):
            return self._not_verified("قيمة Access-Control-Allow-Origin غير صالحة.")
        wildcard = origin == "*"
        accepts_test_origin = wildcard or origin == _TEST_ORIGIN

        credentials_values = headers.get("access-control-allow-credentials", ())
        if len(credentials_values) > 1:
            return self._not_verified("تعددت قيم Access-Control-Allow-Credentials.")
        credentials = False
        if credentials_values:
            token = credentials_values[0].strip()
            if token not in ("true", "false"):
                return self._not_verified("قيمة Access-Control-Allow-Credentials غير صالحة.")
            credentials = token == "true"

        methods = self._tokens(headers.get("access-control-allow-methods", ()))
        allowed_headers = self._tokens(headers.get("access-control-allow-headers", ()))
        if methods is None or allowed_headers is None:
            return self._not_verified("تعذر تحليل قيم الطرق أو الترويسات المسموحة.")
        method_allowed = "get" in methods or "*" in methods
        header_allowed = "x-cybershield-audit" in allowed_headers or "*" in allowed_headers
        vary_values = headers.get("vary", ())
        vary_tokens = {token.strip().lower() for value in vary_values for token in value.split(",") if token.strip()}
        varies_by_origin = "origin" in vary_tokens or "*" in vary_tokens

        if accepts_test_origin and method_allowed and header_allowed:
            if wildcard and credentials:
                explanation = (
                    "ظهر Origin كـ wildcard مع credentials=true. المتصفحات ترفض استخدام wildcard "
                    "للاستجابة credentialed؛ لذلك لا يثبت هذا الطلب نجاح وصول credentialed، "
                    "مع بقاء السماح الواسع للأصل غير الموثق إشارة تستحق المراجعة."
                )
                confidence = "medium"
            elif wildcard:
                explanation = "قبلت الاستجابة الاختبارية Origin wildcard والطلب المسبق؛ هذا إعداد واسع لكنه لا يثبت وحده استغلالاً."
                confidence = "high"
            else:
                explanation = "قبلت الاستجابة الاختبارية أصلاً خارجياً محدداً والطلب المسبق؛ هذه إشارة محتملة وليست إثبات استغلال."
                confidence = "high"
            return self._result(
                "warning", "medium", confidence,
                f"استجابة OPTIONS {status}: origin={'wildcard' if wildcard else 'test-origin'}؛ GET={'allowed' if method_allowed else 'not-allowed'}؛ requested-header={'allowed' if header_allowed else 'not-allowed'}؛ credentials={'true' if credentials else 'not-true'}؛ Vary-Origin={'yes' if varies_by_origin else 'no'}.",
                explanation,
                ("أُرسل preflight واحد بلا بيانات اعتماد؛ لا يثبت ذلك قابلية استغلال أو سلوك كل المسارات.",),
            )
        return self._result(
            "passed", "info", "medium",
            f"استجابة OPTIONS {status}: لم تسمح مجتمعةً بالأصل الاختباري والطريقة والترويسة المطلوبة؛ Vary-Origin={'yes' if varies_by_origin else 'no'}.",
            "لم يمنح هذا preflight المحدود إذناً كاملاً للطلب المحدد.",
            ("النتيجة لا تعمم على مسارات أو طرق أو ترويسات أخرى.",),
        )

    @staticmethod
    def _tokens(values):
        result = set()
        for value in values:
            if not value or any(ord(c) < 32 and c != "\t" for c in value):
                return None
            result.update(token.strip().lower() for token in value.split(",") if token.strip())
        return result

    def _not_verified(self, reason):
        return self._result("not_verified", "info", "low", reason,
                            "تعذر حسم سياسة CORS بسبب دليل متعدد أو غير صالح.",
                            ("لم يُستنتج حكم من قيم متعارضة أو غير قابلة للتحليل.",))

    def _result(self, status, severity, confidence, evidence, explanation, limitations):
        return CheckResult(self.definition.check_id, self.definition.title, status,
                           severity, confidence, evidence, explanation,
                           "راجع إعداد CORS على الخادم مع الإبقاء على أقل صلاحيات لازمة.",
                           limitations)


class OpenRedirectEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        status = evidence.http_status
        if status is None:
            return self._result("not_verified", "info", "low", "لم تتوفر استجابة HTTPS الأصلية.",
                                "تعذر تقييم Location من الطلب الأصلي.",
                                ("لم تُرسل معاملات تخمينية أو طلبات إضافية.",))
        if status not in _REDIRECT_STATUS_CODES:
            return self._result("skipped", "info", "high", f"استجابة HTTPS الأصلية كانت {status} وليست إعادة توجيه.",
                                "لا ينطبق فحص Location على هذه الاستجابة.", ())
        if evidence.redirect_evidence_available is not True:
            return self._not_verified("تعذر جمع Location من حقول الاستجابة الخام متعددة القيم.")
        locations = evidence.redirect_location_values
        if not locations:
            return self._result("passed", "info", "medium", f"استجابة التحويل {status} لا تتضمن Location.",
                                "لم تُرصد وجهة يمكن أن تشير إلى تحويل مفتوح.",
                                ("الحكم يخص استجابة الطلب الأصلي فقط.",))
        if len(locations) != 1:
            return self._not_verified("تعددت قيم Location؛ لم تُختر وجهة واحدة للتقييم.")
        location = locations[0]
        if not location.strip() or len(location) > 8192 or "\\" in location or any(ord(c) < 32 or ord(c) == 127 for c in location):
            return self._not_verified("قيمة Location فارغة أو مشوهة.")
        base = evidence.redirect_request_url
        if not base:
            return self._not_verified("عنوان الطلب الأصلي اللازم لحل Location النسبي غير متاح.")
        try:
            destination = urljoin(base, location.strip())
            parsed = urlsplit(destination)
            target = urlsplit(base)
            port = parsed.port
            target_port = target.port
        except (TypeError, ValueError):
            return self._not_verified("تعذر تحليل Location أو منفذها.")
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return self._result("warning", "low", "medium", "تستخدم Location scheme خارج HTTP/HTTPS.",
                                "وجهة التحويل لا تستخدم scheme ويب مقبولاً لهذا الفحص.",
                                ("لم يتم اتباع التحويل أو الاتصال بالوجهة.",))
        if not parsed.hostname:
            return self._not_verified("Location لا تنتج مضيفاً صالحاً بعد الحل النسبي.")
        if any(char.isspace() for char in parsed.hostname):
            return self._not_verified("اسم المضيف في Location غير صالح.")
        try:
            try:
                ipaddress.ip_address(parsed.hostname)
            except ValueError:
                host_ascii = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
                labels = host_ascii.split(".")
                if (not host_ascii or len(host_ascii) > 253 or any(
                    not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                    for label in labels
                )):
                    return self._not_verified("اسم المضيف في Location غير صالح.")
        except UnicodeError:
            return self._not_verified("اسم المضيف في Location غير صالح.")
        effective_port = port if port is not None else (443 if scheme == "https" else 80)
        target_scheme = target.scheme.lower()
        target_effective_port = target_port if target_port is not None else (443 if target_scheme == "https" else 80)
        same_origin = (
            scheme == target_scheme
            and parsed.hostname.rstrip(".").lower() == (target.hostname or "").rstrip(".").lower()
            and effective_port == target_effective_port
            and parsed.username is None and parsed.password is None
        )
        if same_origin:
            return self._result("passed", "info", "high", "Location نسبية أو من الأصل نفسه.",
                                "لم تُرصد وجهة خارجية في Location الخاصة بالاستجابة الأصلية.",
                                ("لم يتم اتباع التحويل أو الاتصال بالوجهة.",))
        return self._result("warning", "medium", "medium",
                            f"استجابة التحويل {status} تشير إلى وجهة {scheme.upper()} خارج أصل الهدف.",
                            "هذه إشارة محتملة إلى Open Redirect وليست إثباتاً قاطعاً؛ لم تُختبر قابلية الاستغلال.",
                            ("لم يتم اتباع التحويل أو الاتصال بالوجهة.",))

    def _not_verified(self, reason):
        return self._result("not_verified", "info", "low", reason,
                            "تعذر تفسير Location على نحو موثوق.",
                            ("لم يتم اتباع التحويل أو الاتصال بالوجهة.",))

    def _result(self, status, severity, confidence, evidence, explanation, limitations):
        return CheckResult(self.definition.check_id, self.definition.title, status,
                           severity, confidence, evidence,
                           explanation,
                           "تحقق من منطق التحويل وقيّد الوجهات إلى المسارات والأصول المتوقعة.",
                           limitations)
