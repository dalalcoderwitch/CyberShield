import ipaddress
import socket
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from urllib.parse import urlparse, urlunsplit
import time
from urllib3.util import Timeout
import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager


# DNS limits: per-attempt timeout and at most four concurrent attempts.
_DNS_TIMEOUT_SECONDS = 2.0
_DNS_MAX_CONCURRENT_LOOKUPS = 4
_DNS_LOOKUP_SLOTS = BoundedSemaphore(_DNS_MAX_CONCURRENT_LOOKUPS)


# Reject known IPv6 transition mechanisms in this scanner version.
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


def _resolve_dns_with_status(hostname: str, deadline=None):
    """Return DNS addresses and a precise resolution error, if any."""
    timeout = _DNS_TIMEOUT_SECONDS

    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, "timeout"
        timeout = min(timeout, remaining)

    if not _DNS_LOOKUP_SLOTS.acquire(blocking=False):
        if deadline is not None and time.monotonic() >= deadline:
            return None, "timeout"
        return None, "dns_capacity"

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
                result_queue.put((None, "dns_error"))
            else:
                if addresses:
                    result_queue.put((addresses, None))
                else:
                    result_queue.put((None, "dns_error"))
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
        return None, "dns_capacity"

    try:
        return result_queue.get(timeout=timeout)
    except Empty:
        if deadline is not None and time.monotonic() >= deadline:
            return None, "timeout"
        return None, "dns_timeout"


def _resolve_dns_with_timeout(hostname: str, deadline=None):
    """Compatibility wrapper returning addresses or None."""
    addresses, _error = _resolve_dns_with_status(
        hostname,
        deadline=deadline,
    )
    return addresses



def _is_allowed_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Reject non-public addresses and prohibited transition addresses."""

    # Allow only public addresses and explicitly reject multicast.
    if not ip.is_global or ip.is_multicast:
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        # Reject IETF-reserved IPv6 and deprecated site-local space.
        if ip.is_reserved or ip.is_site_local:
            return False

        # Reject IPv4-mapped, Teredo, and 6to4 addresses.
        if (
            ip.ipv4_mapped is not None
            or ip.teredo is not None
            or ip.sixtofour is not None
        ):
            return False

        # Reject IPv6 transition networks prohibited by project policy.
        if any(ip in network for network in _BLOCKED_IPV6_NETWORKS):
            return False

    return True

class PinnedIPAdapter(HTTPAdapter):
    """Connect to a specific IP address while verifying the hostname through TLS."""

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


def _resolve_target_with_status(url: str, deadline=None):
    """Validate a target and preserve the reason when resolution fails."""
    if (
        not isinstance(url, str)
        or not url
        or len(url) > 2048
        or any(ord(char) < 32 or ord(char) == 127 for char in url)
    ):
        return None, "invalid"

    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return None, "invalid"

    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or "\\" in parsed.netloc
    ):
        return None, "invalid"

    try:
        hostname = (
            parsed.hostname.encode("idna")
            .decode("ascii")
            .lower()
            .rstrip(".")
        )
    except UnicodeError:
        return None, "invalid"

    if not hostname:
        return None, "invalid"

    blocked_suffixes = (
        ".localhost",
        ".local",
        ".internal",
        ".home.arpa",
    )

    if hostname == "localhost" or hostname.endswith(blocked_suffixes):
        return None, "invalid"

    if deadline is None:
        addresses, dns_error = _resolve_dns_with_status(hostname)
    else:
        addresses, dns_error = _resolve_dns_with_status(
            hostname,
            deadline=deadline,
        )

    if dns_error is not None:
        return None, dns_error

    if not addresses or len(addresses) > 32:
        return None, "invalid"

    public_ips = []

    for address in addresses:
        try:
            family = address[0]
            raw_ip = address[4][0].split("%", 1)[0]
            ip = ipaddress.ip_address(raw_ip)
        except (ValueError, IndexError, TypeError, AttributeError):
            return None, "invalid"

        if family not in (socket.AF_INET, socket.AF_INET6):
            return None, "invalid"

        expected_version = 4 if family == socket.AF_INET else 6
        if ip.version != expected_version:
            return None, "invalid"

        if not _is_allowed_ip(ip):
            return None, "invalid"

        if ip.compressed not in public_ips:
            public_ips.append(ip.compressed)

    if not public_ips:
        return None, "invalid"

    public_ips.sort(key=lambda value: ":" in value)
    return (parsed, hostname, public_ips), None


def _resolve_target(url: str, deadline=None):
    """Compatibility wrapper returning a target or None."""
    target, _error = _resolve_target_with_status(
        url,
        deadline=deadline,
    )
    return target


def resolve_target_with_status(url: str, deadline=None):
    """Public detailed resolver for coordinated scanner/API integration."""
    return _resolve_target_with_status(url, deadline=deadline)


def resolve_target(url: str, deadline=None):
    """Backward-compatible resolver returning a target or None."""
    target, _error = resolve_target_with_status(
        url,
        deadline=deadline,
    )
    return target



def validate_url(url: str) -> bool:
    """Validate the URL without sending an HTTP request."""
    return resolve_target(url) is not None


def _safe_get_response(
    url: str,
    resolved_target=None,
    deadline: float | None = None,
):
    """
    Send a single HTTPS request to an IP address that passed the target policy.

    If the API layer supplies the result of the previous validation, reuse it
    instead of performing another DNS lookup.
    """
    if resolved_target is not None:
        target = resolved_target
        resolution_error = None
    else:
        target, resolution_error = resolve_target_with_status(
            url,
            deadline=deadline,
        )

    if target is None:
        if resolution_error is not None:
            return None, {}, resolution_error
        if deadline is not None and time.monotonic() >= deadline:
            return None, {}, "timeout"
        return None, {}, "invalid"

    parsed, hostname, public_ips = target
    request_timeout = (3, 5)

    if deadline is not None:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return None, {}, "timeout"

        request_timeout = Timeout(
            total=remaining,
            connect=min(3.0, remaining),
            read=min(5.0, remaining),
        )
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
            timeout=request_timeout,
            allow_redirects=False,
            stream=True,
            verify=True,
        )

        return (
            response.status_code,
            response.headers.copy(),
            None,
        )

    except requests.exceptions.Timeout:
        return None, {}, "timeout"

    except requests.exceptions.SSLError:
        return None, {}, "tls"

    except requests.exceptions.RequestException:
        return None, {}, "connection"

    finally:
        if response is not None:
            response.close()

        session.close()


def check_https(url: str) -> dict:
    """Verify the HTTPS connection and TLS certificate without treating errors as success."""

    status_code, _, error = _safe_get_response(url)

    if error == "invalid":
        return {
            "status": "warning",
            "message": "\u0627\u0644\u0631\u0627\u0628\u0637 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d \u0623\u0648 \u063a\u064a\u0631 \u0645\u0633\u0645\u0648\u062d \u0628\u0641\u062d\u0635\u0647",
        }

    if error == "tls":
        return {
            "status": "warning",
            "message": "\u062a\u0639\u0630\u0631 \u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0634\u0647\u0627\u062f\u0629 TLS",
        }

    if error == "timeout":
        return {
            "status": "error",
            "message": "\u0627\u0646\u062a\u0647\u062a \u0627\u0644\u0645\u0647\u0644\u0629 \u0627\u0644\u0632\u0645\u0646\u064a\u0629 \u0627\u0644\u0645\u0633\u0645\u0648\u062d\u0629 \u0644\u0644\u0627\u062a\u0635\u0627\u0644",
        }

    # Any other unexpected error must not be treated as success.
    if error is not None:
        return {
            "status": "error",
            "message": "\u062a\u0639\u0630\u0631 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0628\u0627\u0644\u0645\u0648\u0642\u0639",
        }

    # Do not report success without an actual HTTP response code.
    if status_code is None:
        return {
            "status": "error",
            "message": "\u0644\u0645 \u064a\u062a\u0645 \u0627\u0644\u062d\u0635\u0648\u0644 \u0639\u0644\u0649 \u0627\u0633\u062a\u062c\u0627\u0628\u0629 HTTP \u0635\u0627\u0644\u062d\u0629",
        }

    return {
        "status": "passed",
        "message": "\u0646\u062c\u062d \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0648\u0627\u0644\u062a\u062d\u0642\u0642 \u0645\u0646 \u0634\u0647\u0627\u062f\u0629 TLS",
    }


def check_security_headers(headers: dict) -> dict:
    """Check for security header presence and basic value validity."""

    if not hasattr(headers, "items"):
        headers = {}

    security_header_names = {
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
    }

    normalized = {}

    for key, value in headers.items():
        normalized_key = str(key).lower()

        if normalized_key not in security_header_names:
            continue

        normalized_value = str(value)

        if normalized_key in normalized:
            normalized[normalized_key] += ", " + normalized_value
        else:
            normalized[normalized_key] = normalized_value

    results = {}

    # 1. Strict-Transport-Security (HSTS)
    hsts = normalized.get("strict-transport-security", "")
    max_age_values = []

    for directive in hsts.split(";"):
        key, separator, value = directive.strip().partition("=")

        if key.strip().lower() == "max-age":
            max_age_values.append(value.strip() if separator else "")

    hsts_ok = False

    # Accept only one max-age directive, using ASCII digits and a positive value.
    if len(max_age_values) == 1:
        age_value = max_age_values[0]

        if age_value.isascii() and age_value.isdecimal():
            hsts_ok = any(character != "0" for character in age_value)

    results["HSTS"] = {
        "status": "passed" if hsts_ok else "warning",
        "message": (
            "\u0642\u064a\u0645\u0629 max-age \u0645\u0648\u062c\u0628\u0629 \u0648\u0635\u064a\u063a\u062a\u0647\u0627 \u0627\u0644\u0623\u0648\u0644\u064a\u0629 \u0645\u0642\u0628\u0648\u0644\u0629"
            if hsts_ok
            else "\u062a\u0631\u0648\u064a\u0633\u0629 HSTS \u0645\u0641\u0642\u0648\u062f\u0629 \u0623\u0648 \u0623\u0646 \u0642\u064a\u0645\u0629 max-age \u063a\u064a\u0631 \u0635\u0627\u0644\u062d\u0629"
        ),
    }

    # 2. Content-Security-Policy (CSP)
    csp = normalized.get("content-security-policy", "").strip()
    csp_present = bool(csp)

    # Check CSP header presence only; policy quality and effectiveness are not evaluated.
    results["CSP"] = {
        "status": "warning",
        "message": (
            "\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 \u0645\u0648\u062c\u0648\u062f\u0629\u061b \u0644\u0645 \u064a\u062a\u0645 \u062a\u0642\u064a\u064a\u0645 \u062c\u0648\u062f\u0629 \u0627\u0644\u0633\u064a\u0627\u0633\u0629 \u0623\u0648 \u0641\u0639\u0627\u0644\u064a\u062a\u0647\u0627"
            if csp_present
            else "\u062a\u0631\u0648\u064a\u0633\u0629 CSP \u0645\u0641\u0642\u0648\u062f\u0629"
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
            "\u0627\u0644\u0642\u064a\u0645\u0629 nosniff \u0635\u062d\u064a\u062d\u0629"
            if xcto == "nosniff"
            else "\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 \u0645\u0641\u0642\u0648\u062f\u0629 \u0623\u0648 \u0642\u064a\u0645\u062a\u0647\u0627 \u063a\u064a\u0631 \u0635\u062d\u064a\u062d\u0629"
        ),
    }

    # 4. X-Frame-Options
    xfo = normalized.get("x-frame-options", "").strip().upper()
    xfo_ok = xfo in {"DENY", "SAMEORIGIN"}

    results["X-Frame-Options"] = {
        "status": "passed" if xfo_ok else "warning",
        "message": (
            "\u0642\u064a\u0645\u0629 \u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 \u0645\u0639\u0631\u0648\u0641\u0629"
            if xfo_ok
            else "\u0627\u0644\u062a\u0631\u0648\u064a\u0633\u0629 \u0645\u0641\u0642\u0648\u062f\u0629 \u0623\u0648 \u0642\u064a\u0645\u062a\u0647\u0627 \u063a\u064a\u0631 \u0645\u0639\u0631\u0648\u0641\u0629"
        ),
    }

    return results