from flask import Flask, jsonify, request

from backend.scanner import scan_target
from security_scanner.scanner import resolve_target


def create_app():
    """إنشاء تطبيق Flask وإعداد مسارات API."""

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

    @app.get("/api/v1/health")
    def health():
        """التحقق من أن API يعمل."""
        return jsonify({
            "status": "ok",
            "service": "CyberShield API",
        }), 200

    @app.post("/api/v1/scan")
    def scan():
        """التحقق من الطلب ثم تشغيل الماسح."""

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

        if (
            not isinstance(target_url, str)
            or not target_url
            or target_url != target_url.strip()
            or len(target_url) > 2048
            or not isinstance(authorization_confirmed, bool)
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

        try:
            # التحقق من الهدف وحل DNS مرة واحدة في مسار API.
            resolved_target = resolve_target(target_url)

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

            # تمرير نتيجة التحقق نفسها إلى محرك الفحص.
            report = scan_target(
                target_url,
                resolved_target=resolved_target,
            )

            return jsonify(report), 200

        except Exception:
            # لا نسجل نص الاستثناء أو تفاصيله؛ فقد يحتوي
            # على الرابط أو بيانات حساسة.
            app.logger.error(
                "Scan request failed; exception details omitted."
            )

            return jsonify({
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "تعذر تنفيذ الفحص.",
                }
            }), 500

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