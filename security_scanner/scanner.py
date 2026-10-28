import ipaddress
import socket
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from urllib.parse import urlparse, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager


# حدود DNS: مهلة لكل محاولة وأربع محاولات متزامنة كحد أقصى.
_DNS_TIMEOUT_SECONDS = 2.0
_DNS_MAX_CONCURRENT_LOOKUPS = 4
_DNS_LOOKUP_SLOTS = BoundedSemaphore(_DNS_MAX_CONCURRENT_LOOKUPS)


# نرفض أشكال IPv6 الانتقالية المعروفة في هذه النسخة من الماسح.
_BLOCKED_IPV6_NETWORKS = tuple(
    ipaddress.ip_network(prefix)
    for prefix in (
        "::/96",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2001::/32",
        "2002::/16",
    )
)


def _resolve_dns_with_timeout(hostname: str):
    """
    تنفيذ DNS بمهلة محددة وسعة متزامنة محدودة.

    لا يمكن إلغاء getaddrinfo المعلق مباشرةً. لذلك، إذا انتهت
    المهلة، تُرفض العملية وتبقى خانتها مشغولة إلى أن تنتهي
    عملية DNS الخلفية. يمنع هذا إنشاء عدد غير محدود من العمال.
    """
    if not _DNS_LOOKUP_SLOTS.acquire(blocking=False):
        return None

    result_queue = Queue(maxsize=1)

    def lookup():
        try:
            try:
                addresses = socket.getaddrinfo(
                    hostname,
                    443,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
            except Exception:
                addresses = None

            result_queue.put(addresses)
        finally:
            _DNS_LOOKUP_SLOTS.release()

    worker = Thread(
        target=lookup,
        name="CyberShield-DNS",
        daemon=True,
    )

    try:
        worker.start()
    except RuntimeError:
        _DNS_LOOKUP_SLOTS.release()
        return None

    try:
        return result_queue.get(timeout=_DNS_TIMEOUT_SECONDS)
    except Empty:
        return None


def _is_allowed_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """رفض العناوين غير العالمية وأشكال IPv6 الانتقالية المختارة."""

    if not ip.is_global:
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        if (
            ip.ipv4_mapped is not None
            or ip.teredo is not None
            or ip.sixtofour is not None
        ):
            return False

        if any(ip in network for network in _BLOCKED_IPV6_NETWORKS):
            return False

    return True


class PinnedIPAdapter(HTTPAdapter):
    """الاتصال بعنوان IP محدد مع التحقق من اسم الموقع عبر TLS."""

    def __init__(self, hostname: str):
        self.hostname = hostname
        super().__init__(max_retries=0)

    def init_poolmanager(
        self,
        connections,
        maxsize,
        block=False,
        **pool_kwargs,
    ):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        pool_kwargs["server_hostname"] = self.hostname
        pool_kwargs["assert_hostname"] = self.hostname

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


def _resolve_target(url: str):
    """
    التحقق من الرابط وحصر الاتصال بعناوين IP مسموحة.
    لا يرسل هذا الإجراء أي طلب HTTP.
    """
    if (
        not isinstance(url, str)
        or not url
        or len(url) > 2048
        or any(ord(char) < 32 or ord(char) == 127 for char in url)
    ):
        return None

    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return None

    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or "\\" in parsed.netloc
    ):
        return None

    try:
        hostname = (
            parsed.hostname.encode("idna")
            .decode("ascii")
            .lower()
            .rstrip(".")
        )
    except UnicodeError:
        return None

    if not hostname:
        return None

    blocked_suffixes = (
        ".localhost",
        ".local",
        ".internal",
        ".home.arpa",
    )

    if hostname == "localhost" or hostname.endswith(blocked_suffixes):
        return None

    addresses = _resolve_dns_with_timeout(hostname)

    if not addresses or len(addresses) > 32:
        return None

    public_ips = []

    for address in addresses:
        if address[0] not in (socket.AF_INET, socket.AF_INET6):
            return None

        try:
            raw_ip = address[4][0].split("%", 1)[0]
            ip = ipaddress.ip_address(raw_ip)
        except (ValueError, IndexError, TypeError):
            return None

        # نرفض جميع النتائج إذا وُجد عنوان غير مسموح.
        if not _is_allowed_ip(ip):
            return None

        if ip.compressed not in public_ips:
            public_ips.append(ip.compressed)

    if not public_ips:
        return None

    # تفضيل IPv4 عندما يتوفر.
    public_ips.sort(key=lambda value: ":" in value)

    return parsed, hostname, public_ips


def resolve_target(url: str):
    """
    حل الرابط والتحقق منه مرة واحدة.

    تُمرر النتيجة إلى محرك الفحص لتجنب إعادة حل DNS.
    """
    return _resolve_target(url)


def validate_url(url: str) -> bool:
    """التحقق من الرابط دون إرسال طلب HTTP."""
    return resolve_target(url) is not None


def _safe_get_response(url: str, resolved_target=None):
    """
    إرسال طلب HTTPS واحد إلى عنوان IP اجتاز سياسة الهدف.

    إذا مررت طبقة API نتيجة التحقق السابقة، يعاد استخدامها
    بدل إجراء عملية DNS جديدة.
    """
    target = (
        resolved_target
        if resolved_target is not None
        else _resolve_target(url)
    )

    if target is None:
        return None, {}, "invalid"

    parsed, hostname, public_ips = target

    ip = public_ips[0]
    ip_for_url = f"[{ip}]" if ":" in ip else ip

    pinned_url = urlunsplit(
        (
            "https",
            f"{ip_for_url}:443",
            parsed.path or "/",
            parsed.query,
            "",
        )
    )

    host_header = f"[{hostname}]" if ":" in hostname else hostname

    session = requests.Session()
    session.trust_env = False
    session.mount("https://", PinnedIPAdapter(hostname))

    response = None

    try:
        response = session.get(
            pinned_url,
            headers={
                "Host": host_header,
                "User-Agent": "CyberShield/1.0",
                "Connection": "close",
            },
            timeout=(3, 5),
            allow_redirects=False,
            stream=True,
            verify=True,
        )

        return (
            response.status_code,
            response.headers.copy(),
            None,
        )

    except requests.exceptions.SSLError:
        return None, {}, "tls"

    except requests.exceptions.RequestException:
        return None, {}, "connection"

    finally:
        if response is not None:
            response.close()

        session.close()


def check_https(url: str) -> dict:
    """التحقق من اتصال HTTPS وشهادة TLS."""
    _, _, error = _safe_get_response(url)

    if error == "invalid":
        return {
            "status": "warning",
            "message": "الرابط غير صالح أو غير مسموح بفحصه",
        }

    if error == "tls":
        return {
            "status": "warning",
            "message": "تعذر التحقق من شهادة TLS",
        }

    if error == "connection":
        return {
            "status": "error",
            "message": "تعذر الاتصال بالموقع",
        }

    return {
        "status": "passed",
        "message": "نجح الاتصال والتحقق من شهادة TLS",
    }


def check_security_headers(headers: dict) -> dict:
    """فحص وجود ترويسات الحماية الأساسية وصحة قيمها الأولية."""
    if not hasattr(headers, "items"):
        headers = {}

    normalized = {
        str(key).lower(): str(value)
        for key, value in headers.items()
    }

    results = {}

    # 1. Strict-Transport-Security (HSTS)
    hsts = normalized.get("strict-transport-security", "")
    max_age = None

    for directive in hsts.split(";"):
        key, separator, value = directive.strip().partition("=")

        if separator and key.strip().lower() == "max-age":
            try:
                max_age = int(value.strip())
            except ValueError:
                max_age = None

            break

    hsts_ok = max_age is not None and max_age > 0

    results["HSTS"] = {
        "status": "passed" if hsts_ok else "warning",
        "message": (
            "قيمة max-age موجبة"
            if hsts_ok
            else "ترويسة HSTS مفقودة أو قيمتها غير صالحة"
        ),
    }

    # 2. Content-Security-Policy (CSP)
    csp = normalized.get("content-security-policy", "").strip()

    results["CSP"] = {
        "status": "passed" if csp else "warning",
        "message": (
            "الترويسة موجودة وتحتاج مراجعة سياستها"
            if csp
            else "ترويسة CSP مفقودة"
        ),
    }

    # 3. X-Content-Type-Options
    xcto = (
        normalized.get("x-content-type-options", "")
        .strip()
        .lower()
    )

    results["X-Content-Type-Options"] = {
        "status": "passed" if xcto == "nosniff" else "warning",
        "message": (
            "القيمة nosniff صحيحة"
            if xcto == "nosniff"
            else "الترويسة مفقودة أو قيمتها غير صحيحة"
        ),
    }

    # 4. X-Frame-Options
    xfo = normalized.get("x-frame-options", "").strip().upper()
    xfo_ok = xfo in {"DENY", "SAMEORIGIN"}

    results["X-Frame-Options"] = {
        "status": "passed" if xfo_ok else "warning",
        "message": (
            "قيمة الترويسة معروفة"
            if xfo_ok
            else "الترويسة مفقودة أو قيمتها غير معروفة"
        ),
    }

    return results