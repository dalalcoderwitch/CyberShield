import time
from threading import BoundedSemaphore, Lock

from flask import Flask, jsonify, request

from backend.scanner import scan_target
from security_scanner.scanner import resolve_target


# حدود أولية للتطوير، وتحتاج إلى مراجعة قبل النشر.
_MAX_CONCURRENT_SCANS = 4
_SCAN_DEADLINE_SECONDS = 25.0

_SCAN_RATE_LIMIT_REQUESTS = 5
_SCAN_RATE_LIMIT_WINDOW_SECONDS = 60.0
_SCAN_RATE_LIMIT_MAX_SOURCES = 4096

_SCAN_SLOTS = BoundedSemaphore(_MAX_CONCURRENT_SCANS)


def create_app():
    """إنشاء تطبيق Flask وإعداد مسارات API."""

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

    # تحديد معدل الطلبات داخل عملية Python الحالية.
    # هذا الحد ليس مشتركًا بين عدة عمليات أو خوادم.
    rate_limit_lock = Lock()
    scan_request_times: dict[str, list[float]] = {}

    def is_scan_rate_limited(source: str) -> bool:
        """تحديد ما إذا تجاوز المصدر حد طلبات الفحص."""

        now = time.monotonic()
        cutoff = now - _SCAN_RATE_LIMIT_WINDOW_SECONDS

        with rate_limit_lock:
            # تنظيف السجلات القديمة لتقليل استهلاك الذاكرة.
            for tracked_source in list(scan_request_times):
                recent = [
                    timestamp
                    for timestamp in scan_request_times[tracked_source]
                    if timestamp > cutoff
                ]

                if recent:
                    scan_request_times[tracked_source] = recent
                else:
                    del scan_request_times[tracked_source]

            recent = scan_request_times.get(source, [])

            if len(recent) >= _SCAN_RATE_LIMIT_REQUESTS:
                return True

            # عند امتلاء جدول المصادر، نرفض المصادر الجديدة
            # بدل السماح بتجاوز حد الذاكرة.
            if (
                source not in scan_request_times
                and len(scan_request_times) >= _SCAN_RATE_LIMIT_MAX_SOURCES
            ):
                return True

            recent.append(now)
            scan_request_times[source] = recent
            return False

    def scan_timeout_response():
        """إرجاع استجابة موحدة عند انتهاء مهلة الفحص."""

        return jsonify({
            "error": {
                "code": "SCAN_TIMEOUT",
                "message": "انتهت المهلة الزمنية المسموحة للفحص.",
            }
        }), 504

    @app.get("/api/v1/health")
    def health():
        """التحقق من أن API يعمل."""

        return jsonify({
            "status": "ok",
            "service": "CyberShield API",
        }), 200

    @app.post("/api/v1/scan")
    def scan():
        """التحقق من طلب الفحص ثم تشغيل المحرك."""

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "error": {
                    "code": "INVALID_REQUEST",
                    "message": "بيانات الطلب غير صالحة.",
                }
            }), 400

        target_url = data.get("target_url")
        authorization_confirmed = data.get(
            "authorization_confirmed"
        )
        include_expanded_checks = data.get(
            "include_expanded_checks", False
        )

        if (
            not isinstance(target_url, str)
            or not target_url
            or target_url != target_url.strip()
            or len(target_url) > 2048
            or not isinstance(authorization_confirmed, bool)
            or not isinstance(include_expanded_checks, bool)
        ):
            return jsonify({
                "error": {
                    "code": "INVALID_REQUEST",
                    "message": "بيانات الطلب غير صالحة.",
                }
            }), 400

        if authorization_confirmed is not True:
            return jsonify({
                "error": {
                    "code": "AUTHORIZATION_REQUIRED",
                    "message": "يجب تأكيد امتلاك تصريح لفحص الموقع.",
                }
            }), 403

        # استخدام عنوان المصدر الذي يراه Flask مباشرة.
        # لا نعتمد على X-Forwarded-For دون وكيل موثوق ومضبوط.
        source = request.remote_addr or "unknown"

        if is_scan_rate_limited(source):
            return jsonify({
                "error": {
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": (
                        "تم تجاوز عدد طلبات الفحص المسموح به. "
                        "يرجى المحاولة لاحقًا."
                    ),
                }
            }), 429

        # رفض الفحص الجديد إذا امتلأت السعة المتزامنة.
        if not _SCAN_SLOTS.acquire(blocking=False):
            return jsonify({
                "error": {
                    "code": "SCAN_CAPACITY_EXCEEDED",
                    "message": (
                        "بلغ عدد عمليات الفحص النشطة الحد المسموح. "
                        "أعيدي المحاولة لاحقًا."
                    ),
                }
            }), 503

        try:
            # ميزانية زمنية واحدة للتحقق من الهدف وطلب HTTPS.
            deadline = (
                time.monotonic() + _SCAN_DEADLINE_SECONDS
            )

            # التحقق من الرابط وحل DNS مرة واحدة.
            resolved_target = resolve_target(
                target_url,
                deadline=deadline,
            )

            if time.monotonic() >= deadline:
                return scan_timeout_response()

            if resolved_target is None:
                return jsonify({
                    "error": {
                        "code": "TARGET_NOT_ALLOWED",
                        "message": (
                            "الرابط غير مسموح بفحصه "
                            "أو تعذر التحقق من عنوانه."
                        ),
                    }
                }), 403

            # تمرير نتيجة التحقق نفسها والمهلة المتبقية إلى المحرك.
            scan_options = {
                "resolved_target": resolved_target,
                "deadline": deadline,
            }
            if include_expanded_checks:
                scan_options["include_expanded_checks"] = True

            report = scan_target(target_url, **scan_options)

            if time.monotonic() >= deadline:
                return scan_timeout_response()

            return jsonify(report), 200

        except Exception:
            # عدم تسجيل تفاصيل الاستثناء؛ فقد تحتوي على بيانات حساسة.
            app.logger.error(
                "Scan request failed; exception details omitted."
            )

            return jsonify({
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "تعذر تنفيذ الفحص.",
                }
            }), 500

        finally:
            # تحرير السعة حتى عند الفشل أو الاستثناء.
            _SCAN_SLOTS.release()

    @app.errorhandler(405)
    def method_not_allowed(error):
        # الاحتفاظ بترويسة Allow التي ينشئها Werkzeug.
        response = error.get_response()
        response.set_data(app.json.dumps({
            "error": {
                "code": "METHOD_NOT_ALLOWED",
                "message": "طريقة الطلب غير مدعومة.",
            }
        }))
        response.content_type = "application/json"
        return response
    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({
            "error": {
                "code": "REQUEST_TOO_LARGE",
                "message": "حجم الطلب أكبر من المسموح.",
            }
        }), 413

    @app.errorhandler(500)
    def internal_server_error(_error):
        return jsonify({
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "حدث خطأ داخلي في الخادم.",
            }
        }), 500

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )