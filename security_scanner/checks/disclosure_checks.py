"""Evidence-only evaluators for bounded Disclosure probes."""

from .evaluator import CheckEvaluator
from .result import CheckResult
from .disclosure_evidence import DisclosureEvidence


_DISCLOSURE_IDS = (
    "sensitive_file_exposure",
    "source_maps_exposure",
    "directory_listing",
    "server_information_disclosure",
    "error_information_disclosure",
    "public_security_files",
)


class DisclosureEvaluator(CheckEvaluator):
    def _evaluate(self, evidence):
        if (self.definition.check_id == "error_information_disclosure"
                and evidence.http_status is not None
                and not 400 <= evidence.http_status <= 599):
            return self._result("skipped", "info", "high",
                                "الاستجابة الأصلية ليست 4xx أو 5xx.",
                                "لم يُنشأ خطأ متعمد ولم يُرسل طلب إضافي لهذا الفحص.", ())
        if not isinstance(evidence.disclosure_evidence, DisclosureEvidence):
            return self._result("not_verified", "info", "low",
                                "لم تتوفر نتائج جمع أدلة Disclosure محدودة.",
                                "تعذر تقييم هذا الفحص دون دليل مصنف.",
                                ("لم تُحفظ أجسام الاستجابة أو بياناتها الحساسة.",))
        data = evidence.disclosure_evidence
        check_id = self.definition.check_id
        if check_id not in _DISCLOSURE_IDS:
            raise ValueError("Unsupported Disclosure check")
        if check_id == "sensitive_file_exposure":
            return self._sensitive(data)
        if check_id == "source_maps_exposure":
            return self._source_maps(data)
        if check_id == "directory_listing":
            return self._directory_listing(data)
        if check_id == "server_information_disclosure":
            return self._server_information(data)
        if check_id == "error_information_disclosure":
            return self._error_information(data)
        return self._public_files(data)

    def _sensitive(self, data):
        detected = [(i, marker) for i, (_status, outcome, marker) in enumerate(data.sensitive_results, 1) if outcome == "found"]
        uncertain = sum(outcome == "unknown" for _status, outcome, _marker in data.sensitive_results)
        absent = sum(outcome == "not_found" for _status, outcome, _marker in data.sensitive_results)
        if detected:
            return self._result("warning", "high", "high",
                                f"تم تأكيد محتوى حساس في {len(detected)} من ستة مسارات ثابتة (المؤشرات: {', '.join(str(i) for i, _ in detected)}).",
                                "تطابقت استجابة واحدة أو أكثر مع توقيع محتوى محدد؛ لم يُحتفظ بالمحتوى أو الأسرار.",
                                ("اقتصر الفحص على ستة مسارات ثابتة، ولا يمثل قائمة شاملة.",))
        if uncertain or len(data.sensitive_results) < 6:
            return self._result("not_verified", "info", "low",
                                f"تعذر تصنيف {uncertain + max(0, 6-len(data.sensitive_results))} من ستة مسارات ضمن العينة المحدودة.",
                                "HTTP 200 وحده أو عينة غير حاسمة لا يثبت وجود ملف حساس.",
                                ("المسارات غير المختبرة أو غير الحاسمة لا يمكن استنتاج حالتها.",))
        return self._result("passed", "info", "medium",
                            f"لم يُعثر على محتوى مطابق في المسارات المختبرة؛ {absent} منها أعاد 404/410.",
                            "لم يظهر توقيع محتوى حساس في المسارات الثابتة التي أمكن فحصها.",
                            ("هذه النتيجة تخص المسارات الستة المحددة فقط.",))

    def _source_maps(self, data):
        if data.source_map_state == "confirmed":
            return self._result("warning", "medium", "high",
                                "تأكدت قراءة عينة Source Map صالحة من المصدر نفسه.",
                                "تطابق الملف المستجاب مع بنية Source Map؛ لم تُحفظ الخريطة أو مصادرها أو أسماؤها.",
                                ("اقتصر الفحص على HTML واحد وملف JS/CSS واحد وخريطة واحدة كحد أقصى.",))
        if data.source_map_state == "clear":
            return self._result("passed", "info", "medium",
                                "لم يُؤكد وجود Source Map قابلة للقراءة ضمن العينة المكتملة.",
                                "لم يظهر مرجع قابل للوصول إلى Source Map في العينة التي أمكن فحصها.",
                                ("اقتصر الفحص على HTML واحد وملف JS/CSS واحد وخريطة واحدة كحد أقصى.",))
        if data.source_map_state == "reference_only":
            return self._result("not_verified", "info", "low",
                                "رُصد مرجع SourceMappingURL دون تأكيد قراءة خريطة صالحة.",
                                "وجود مرجع وحده لا يثبت تسريب Source Map.",
                                ("لم تُتبع أي وجهة خارج الأصل؛ أو تعذر حسم ملف الخريطة ضمن الحدود.",))
        return self._result("not_verified", "info", "low",
                            "عينة HTML أو asset غير مكتملة أو غير متاحة للحسم.",
                            "لا يمكن اعتبار غياب المرجع في عينة جزئية دليلاً على عدم وجوده.",
                            ("حُدّ HTML إلى 16 KiB وكل asset/خريطة إلى 4 KiB.",))

    def _directory_listing(self, data):
        listings = sum(state == "listing" for _status, state in data.directory_results)
        uncertain = sum(state == "unknown" for _status, state in data.directory_results)
        if listings:
            return self._result("warning", "medium", "high",
                                f"ظهرت علامة directory index موثوقة في {listings} من مسارين مختبرين.",
                                "تطابقت عينة HTML مع مؤشر واضح لقائمة مجلد.",
                                ("لم تُستخرج أسماء الملفات ولم يحدث زحف.",))
        if uncertain or len(data.directory_results) < 2:
            return self._result("not_verified", "info", "low",
                                f"تعذر حسم {uncertain + max(0, 2-len(data.directory_results))} من مساري المجلدات.",
                                "403 أو timeout أو redirect أو عينة غير حاسمة لا تثبت غياب listing.",
                                ("اقتصر الفحص على مسارين ثابتين وعينة بحد أقصى 4 KiB لكل منهما.",))
        return self._result("passed", "info", "medium",
                            "لم تظهر علامة listing موثوقة في المسارين المختبرين.",
                            "لم يُرصد دليل directory index في عينات المسارين المحددين.",
                            ("404/410 تعني عدم العثور على listing في ذلك المسار فقط.",))

    def _server_information(self, data):
        if data.server_headers_available is not True:
            return self._result("not_verified", "info", "low",
                                "تعذر جمع ترويسات تعريف الخادم الخام ضمن الحدود.",
                                "لا يمكن استنتاج غياب المعلومات من دليل ترويسات غير متاح.",
                                ("لم تُحفظ القيم الخام أو إصدارات الخادم.",))
        revealing = {"version", "technology"} & set(data.server_info_types)
        if revealing:
            return self._result("warning", "low", "medium",
                                f"كشفت {len(data.server_header_names)} ترويسة مرصودة نوع معلومات محدداً؛ جرى حجب القيم.",
                                "تدل الترويسات المرصودة على إصدار أو تقنية محددة دون عرض اسمها أو إصدارها.",
                                ("اسم Server وحده أو Via وحده لا يُعد كشفاً محدداً.",))
        return self._result("passed", "info", "medium",
                            f"رُصدت {len(data.server_header_names)} ترويسة تعريف دون إثبات إصدار أو تقنية محددة.",
                            "لم يثبت من القيم المرصودة كشف إصدار أو تقنية محددة.",
                            ("النتيجة مقتصرة على الترويسات المحددة في الاستجابة الأصلية.",))

    def _error_information(self, data):
        if data.error_status is None:
            return self._result("not_verified", "info", "low",
                                "لم تتوفر حالة HTTP للاستجابة الأصلية.",
                                "تعذر تحديد ما إذا كان ينبغي فحص صفحة خطأ.",
                                ("لم يُنشأ خطأ متعمد ولم يُرسل طلب إضافي لهذا الفحص.",))
        if not 400 <= data.error_status <= 599:
            return self._result("skipped", "info", "high",
                                "الاستجابة الأصلية ليست 4xx أو 5xx.",
                                "لم يُنشأ خطأ متعمد ولم يُرسل طلب إضافي لهذا الفحص.", ())
        if data.error_sample_complete is not True:
            return self._result("not_verified", "info", "low",
                                f"استجابة الخطأ {data.error_status} لم توفر عينة مكتملة ضمن الحد.",
                                "لا يمكن اعتبار عدم ظهور توقيع في عينة ناقصة دليلاً على غيابه.",
                                ("اقتصر التحليل على 4 KiB؛ لم يُحتفظ بنص الخطأ.",))
        if data.error_patterns:
            return self._result("warning", "medium", "high",
                                f"ظهرت {len(data.error_patterns)} فئات عامة من مؤشرات الخطأ في استجابة {data.error_status}.",
                                "رُصدت علامات stack trace أو مسار داخلي أو SQL أو framework/debug؛ لم تُحفظ الأسطر أو القيم.",
                                ("اقتصر التحليل على عينة لا تتجاوز 4 KiB من الاستجابة الأصلية.",))
        return self._result("passed", "info", "medium",
                            f"لم تظهر مؤشرات الخطأ المحددة في عينة الاستجابة {data.error_status} المكتملة.",
                            "لم يُرصد توقيع معروف ضمن الأنماط المحددة.",
                            ("النتيجة محدودة بعينة 4 KiB وبقائمة المؤشرات المعروفة.",))

    def _public_files(self, data):
        security = [item for item in data.public_file_results if item[1] == "security"]
        robots = [item for item in data.public_file_results if item[1] == "robots"]
        present_security = sum(item[2] == "present" for item in security)
        uncertain = sum(item[2] == "unknown" for item in data.public_file_results)
        robots_present = any(item[2] == "present" for item in robots)
        if present_security:
            return self._result("passed", "info", "high",
                                f"تم رصد ملف security.txt صالح النوع في {present_security} من موضعين ثابتين.",
                                "وجود الملف وسيلة اتصال منشورة ولا يثبت بحد ذاته سلامة التطبيق.",
                                ("لم تُقرأ مسارات أو روابط إضافية من محتوى الملفات.",
                                 "وجود robots.txt لا يشكل وسيلة حماية أمنية."))
        if uncertain or len(data.public_file_results) < 3:
            return self._result("not_verified", "info", "low",
                                f"تعذر حسم {uncertain + max(0, 3-len(data.public_file_results))} من ثلاثة ملفات عامة بسبب حالة أو نوع محتوى غير متوقع.",
                                "لا يُستنتج وجود الملف أو غيابه من استجابة غير حاسمة.",
                                ("فُحصت الملفات الثلاثة المحددة فقط بعينات لا تتجاوز 4 KiB.",))
        evidence = "لم يُرصد security.txt في الموضعين الثابتين؛ رُصد robots.txt." if robots_present else "لم يُرصد security.txt في الموضعين الثابتين."
        explanation = "لم يظهر ملف security.txt لتوفير جهة اتصال أمنية منشورة؛ robots.txt لا يوفر حماية أمنية بحد ذاته."
        return self._result("warning", "low", "medium", evidence, explanation,
                            ("غياب security.txt ليس إثباتاً لثغرة، والفحص محدود بثلاثة مسارات ثابتة.",))

    def _result(self, status, severity, confidence, evidence, explanation, limitations):
        return CheckResult(
            self.definition.check_id, self.definition.title, status, severity,
            confidence, evidence, explanation,
            "راجع إعدادات النشر وأزل الملفات أو التفاصيل غير اللازمة، مع إبقاء معلومات الاتصال الأمني مناسبة.",
            limitations,
        )
