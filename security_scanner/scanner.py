import ipaddress
import socket
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from urllib.parse import urlparse, urlunsplit, urljoin, urlsplit
import time
from urllib3.util import Timeout
import requests
from requests.adapters import HTTPAdapter
from urllib3 import HTTPSConnectionPool, PoolManager
from urllib3.connection import HTTPSConnection


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

def _capture_tls_socket_metadata(tls_socket, destination):
    """Copy non-sensitive metadata from an already verified TLS socket."""
    try:
        destination["version"] = tls_socket.version()
    except Exception:
        pass
    try:
        cipher = tls_socket.cipher()
        if cipher:
            destination["cipher"] = cipher[0]
    except Exception:
        pass
    try:
        certificate = tls_socket.getpeercert()
    except Exception:
        certificate = {}
    if certificate:
        destination["not_before"] = certificate.get("notBefore")
        destination["not_after"] = certificate.get("notAfter")
    try:
        get_verified_chain = getattr(tls_socket, "get_verified_chain", None)
        destination["chain_available"] = (
            bool(get_verified_chain()) if callable(get_verified_chain) else None
        )
    except Exception:
        destination["chain_available"] = None


class _MetadataHTTPSConnection(HTTPSConnection):
    def connect(self):
        super().connect()
        destination = getattr(self, "_tls_metadata_destination", None)
        if destination is not None and self.sock is not None:
            _capture_tls_socket_metadata(self.sock, destination)


class _MetadataHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _MetadataHTTPSConnection

    def __init__(self, *args, tls_metadata_destination=None, **kwargs):
        self._tls_metadata_destination = tls_metadata_destination
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        connection = super()._new_conn()
        connection._tls_metadata_destination = self._tls_metadata_destination
        return connection


class _TLSMetadataPoolManager(PoolManager):
    def __init__(self, *args, tls_metadata_destination=None, **kwargs):
        self._tls_metadata_destination = tls_metadata_destination
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = self.pool_classes_by_scheme.copy()
        self.pool_classes_by_scheme["https"] = _MetadataHTTPSConnectionPool

    def _new_pool(self, scheme, host, port, request_context=None):
        if scheme == "https":
            context = dict(request_context or self.connection_pool_kw)
            context["tls_metadata_destination"] = self._tls_metadata_destination
            request_context = context
        return super()._new_pool(scheme, host, port, request_context)


class PinnedIPAdapter(HTTPAdapter):
    """Connect to a specific IP address while verifying the hostname through TLS."""

    def __init__(self, hostname: str, tls_metadata: dict | None = None):
        self.hostname = hostname
        self.tls_metadata = tls_metadata
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

        self.poolmanager = _TLSMetadataPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            tls_metadata_destination=self.tls_metadata,
            **pool_kwargs,
        )


def _parse_target_url(url: str):
    """Apply existing URL/name restrictions without DNS or a connection."""
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
        or parsed.netloc.endswith(":")
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
        return None, "not_allowed"

    return (parsed, hostname), None


def _diagnostic_hostname(url):
    """Strict DNS-only eligibility; this never authorizes an HTTP target."""
    from .checks.dns_checks import _normalize_domain

    parsed_target, error = _parse_target_url(url)
    if error is not None:
        return None
    return _normalize_domain(parsed_target[1])


def _resolve_target_with_status(url: str, deadline=None, diagnostic_capture=None):
    """Preserve policy failures and separately capture DNS-only eligibility."""
    if diagnostic_capture is not None:
        diagnostic_capture.pop("takeover_hostname", None)
    parsed_target, error = _parse_target_url(url)
    if error is not None:
        return None, error
    parsed, hostname = parsed_target
    if deadline is None:
        addresses, dns_error = _resolve_dns_with_status(hostname)
    else:
        addresses, dns_error = _resolve_dns_with_status(
            hostname,
            deadline=deadline,
        )

    if dns_error is not None:
        # Only a failed lookup with NO returned addresses permits DNS-only
        # diagnosis. Rejected, malformed or partially returned answers do not.
        if dns_error == "dns_error" and not addresses and diagnostic_capture is not None:
            diagnostic_capture["takeover_hostname"] = _diagnostic_hostname(url)
        return None, dns_error

    if not addresses:
        if diagnostic_capture is not None:
            diagnostic_capture["takeover_hostname"] = _diagnostic_hostname(url)
        return None, "dns_error"

    if len(addresses) > 32:
        return None, "not_allowed"

    public_ips = []

    for address in addresses:
        try:
            family = address[0]
            raw_ip = address[4][0].split("%", 1)[0]
            ip = ipaddress.ip_address(raw_ip)
        except (ValueError, IndexError, TypeError, AttributeError):
            return None, "dns_error"

        if family not in (socket.AF_INET, socket.AF_INET6):
            return None, "dns_error"

        expected_version = 4 if family == socket.AF_INET else 6
        if ip.version != expected_version:
            return None, "dns_error"

        if not _is_allowed_ip(ip):
            return None, "not_allowed"

        if ip.compressed not in public_ips:
            public_ips.append(ip.compressed)

    if not public_ips:
        return None, "dns_error"

    public_ips.sort(key=lambda value: ":" in value)
    if diagnostic_capture is not None:
        diagnostic_capture["takeover_hostname"] = _diagnostic_hostname(url)
    return (parsed, hostname, public_ips), None


def _resolve_target(url: str, deadline=None):
    """Compatibility wrapper returning a target or None."""
    target, _error = _resolve_target_with_status(
        url,
        deadline=deadline,
    )
    return target


def resolve_target_with_status(url: str, deadline=None, *, diagnostic_capture=None):
    """Detailed resolution; optional metadata never authorizes connections."""
    return _resolve_target_with_status(url, deadline=deadline, diagnostic_capture=diagnostic_capture)


def resolve_target(url: str, deadline=None):
    """Backward-compatible resolver returning a target or None."""
    target, _error = resolve_target_with_status(
        url,
        deadline=deadline,
    )
    return target


def _resolve_redirect_location_addresses(location: str, deadline=None):
    """Collect bounded DNS answers for an absolute policy-shaped redirect.

    This helper never opens a connection to the destination. It intentionally
    returns every address, including prohibited ones, so the evaluator can
    reject mixed public/private answers rather than silently filtering them.
    """
    if (
        not isinstance(location, str)
        or not location
        or len(location) > 2048
        or any(ord(char) < 32 or ord(char) == 127 for char in location)
    ):
        return None
    try:
        parsed = urlparse(location)
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
        or parsed.netloc.endswith(":")
    ):
        return None
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return None
    if not hostname:
        return None
    blocked_suffixes = (".localhost", ".local", ".internal", ".home.arpa")
    if hostname == "localhost" or hostname.endswith(blocked_suffixes):
        return None
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        return (literal_ip.compressed,)

    if deadline is None:
        addresses, error = _resolve_dns_with_status(hostname)
    else:
        addresses, error = _resolve_dns_with_status(hostname, deadline=deadline)
    if error is not None or not addresses or len(addresses) > 32:
        return None
    results = []
    for address in addresses:
        try:
            family = address[0]
            raw_ip = address[4][0].split("%", 1)[0]
            parsed_ip = ipaddress.ip_address(raw_ip)
        except (ValueError, IndexError, TypeError, AttributeError):
            return None
        expected_family = socket.AF_INET if parsed_ip.version == 4 else socket.AF_INET6
        if family != expected_family:
            return None
        if parsed_ip.compressed not in results:
            results.append(parsed_ip.compressed)
    return tuple(results) if results else None


def _parse_set_cookie_attributes(raw_value):
    """Return attribute flags only; never return cookie names or values."""
    attribute_start = raw_value.find(";")
    if attribute_start < 0:
        return False, False, "missing"

    secure = False
    httponly = False
    samesite_values = []
    for attribute in raw_value[attribute_start + 1 :].split(";"):
        name, separator, value = attribute.strip().partition("=")
        normalized_name = name.strip().lower()
        if normalized_name == "secure":
            secure = True
        elif normalized_name == "httponly":
            httponly = True
        elif normalized_name == "samesite":
            normalized_value = value.strip().lower() if separator else ""
            if normalized_value in ("strict", "lax", "none"):
                samesite_values.append(normalized_value)
            else:
                samesite_values.append("invalid")

    if not samesite_values:
        samesite = "missing"
    elif len(samesite_values) == 1:
        samesite = samesite_values[0]
    elif "invalid" in samesite_values or len(set(samesite_values)) != 1:
        samesite = "ambiguous"
    else:
        samesite = samesite_values[0]
    return secure, httponly, samesite


def _collect_set_cookie_observations(response):
    """Read separate raw Set-Cookie fields and retain parsed flags only.

    Set-Cookie is never split on commas: Expires values commonly contain one.
    If raw multi-value access or existing header limits cannot be confirmed,
    cookie evidence is unavailable instead of inferred from merged headers.
    """
    from .checks.limits import (
        MAX_RESPONSE_HEADER_BYTES,
        MAX_RESPONSE_HEADER_COUNT,
        response_header_size_bytes,
    )

    try:
        raw_headers = response.raw.headers
        getlist = getattr(raw_headers, "getlist", None)
        keys = getattr(raw_headers, "keys", None)
        if not callable(getlist) or not callable(keys):
            return False, ()

        header_count = 0
        header_bytes = 0
        observations = []
        for header_name in keys():
            values = getlist(header_name)
            if not isinstance(values, (tuple, list)):
                return False, ()
            for raw_value in values:
                if not isinstance(header_name, str) or not isinstance(raw_value, str):
                    return False, ()
                header_count += 1
                if header_count > MAX_RESPONSE_HEADER_COUNT:
                    return False, ()
                header_bytes += response_header_size_bytes(header_name, raw_value)
                if header_bytes > MAX_RESPONSE_HEADER_BYTES:
                    return False, ()
                if header_name.lower() == "set-cookie":
                    observations.append(_parse_set_cookie_attributes(raw_value))
                    if len(observations) > MAX_RESPONSE_HEADER_COUNT:
                        return False, ()
                raw_value = None
            values = ()
        return True, tuple(observations)
    except Exception:
        # Do not log or include exception text: it may contain raw header data.
        return False, ()


def _collect_selected_response_headers(response, selected_names):
    """Read bounded raw multi-value response headers without merged fallback."""
    try:
        from .checks.limits import (
            MAX_RESPONSE_HEADER_BYTES,
            MAX_RESPONSE_HEADER_COUNT,
            response_header_size_bytes,
        )
        raw_headers = response.raw.headers
        if not callable(getattr(raw_headers, "getlist", None)):
            return False, {}
        count = 0
        size = 0
        for name in raw_headers.keys():
            for value in raw_headers.getlist(name):
                count += 1
                if count > MAX_RESPONSE_HEADER_COUNT:
                    return False, {}
                size += response_header_size_bytes(str(name), str(value))
                if size > MAX_RESPONSE_HEADER_BYTES:
                    return False, {}
        captured = {}
        for name in selected_names:
            values = tuple(raw_headers.getlist(name))
            if values:
                captured[name.lower()] = values
        return True, captured
    except Exception:
        # Header values can contain sensitive query or policy data; never log parser errors.
        return False, {}



def _read_bounded_identity_sample(response, limit):
    """Read at most `limit` raw bytes, without decompression."""
    try:
        if response.headers.get("Content-Encoding", "identity").strip().lower() not in ("", "identity"):
            return b"", False
        stream = getattr(response.raw, "stream", None)
        if not callable(stream):
            return b"", False
        sample = bytearray()
        exhausted = False
        while len(sample) < limit:
            amount = min(4096, limit - len(sample))
            got_chunk = False
            for chunk in stream(amt=amount, decode_content=False):
                got_chunk = True
                if not isinstance(chunk, (bytes, bytearray)):
                    return bytes(sample), False
                sample.extend(chunk[:limit - len(sample)])
                if len(sample) >= limit:
                    break
            if not got_chunk:
                exhausted = True
                break
        try:
            length = int(response.headers.get("Content-Length"))
        except (TypeError, ValueError):
            length = None
        complete = exhausted or (length is not None and length <= limit and len(sample) == length)
        return bytes(sample), complete
    except Exception:
        return b"", False


def _safe_disclosure_get(target, path, deadline=None, limit=4096):
    """Request one statically allowlisted same-origin path with strict caps."""
    result = {"status": None, "media_type": "unknown", "sample": b"", "complete": False,
              "error": None, "attempted": False}
    if (limit not in (4096, 16384) or not isinstance(path, str) or not path.startswith("/")
            or path.startswith("//") or "\\" in path or len(path) > 2048
            or any(ord(char) < 32 or ord(char) == 127 for char in path)):
        result["error"] = "invalid"
        return result
    target, target_error = _validate_internal_http_target(target)
    if target is None:
        result["error"] = target_error
        return result
    parsed, hostname, public_ips = target
    try:
        if not public_ips or any(not _is_allowed_ip(ipaddress.ip_address(value)) for value in public_ips):
            result["error"] = "invalid"
            return result
    except (ValueError, TypeError):
        result["error"] = "invalid"
        return result
    remaining = None if deadline is None else deadline - time.monotonic()
    if remaining is not None and remaining <= 0:
        result["error"] = "timeout"
        return result
    ip = public_ips[0]
    ip_for_url = f"[{ip}]" if ":" in ip else ip
    request_url = urlunsplit(("https", f"{ip_for_url}:443", path, "", ""))
    timeout = Timeout(connect=2.0, read=2.0) if remaining is None else Timeout(
        total=remaining, connect=min(2.0, remaining), read=min(2.0, remaining)
    )
    session = None
    response = None
    try:
        session = requests.Session()
        session.trust_env = False
        session.mount("https://", PinnedIPAdapter(hostname))
        result["attempted"] = True
        response = session.get(
            request_url,
            headers={
                "Host": f"[{hostname}]" if ":" in hostname else hostname,
                "User-Agent": "CyberShield/1.0", "Connection": "close",
                "Accept-Encoding": "identity", "Range": f"bytes=0-{limit - 1}",
            },
            timeout=timeout, allow_redirects=False, stream=True, verify=True,
        )
        result["status"] = response.status_code
        raw_headers_available, response_fields = _collect_selected_response_headers(
            response, ("Content-Type", "Content-Encoding", "Content-Length")
        )
        if not raw_headers_available:
            result["error"] = "evidence"
            return result
        content_types = response_fields.get("content-type", ())
        media = content_types[0].split(";", 1)[0].strip().lower() if len(content_types) == 1 else ""
        allowed_media = {"text/plain", "text/html", "text/css", "application/json", "application/javascript", "text/javascript", "application/octet-stream"}
        result["media_type"] = media if media in allowed_media else ("unknown" if not media else "other")
        if response.status_code not in (200, 206):
            return result
        result["sample"], result["complete"] = _read_bounded_identity_sample(response, limit)
        if response.status_code == 206:
            result["complete"] = False
        return result
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        return result
    except requests.exceptions.SSLError:
        result["error"] = "tls"
        return result
    except requests.exceptions.RequestException:
        result["error"] = "connection"
        return result
    except Exception:
        result["error"] = "internal"
        return result
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


def _collect_disclosure_evidence(target, original_status, original_capture, deadline=None):
    """Run the fixed 13-request Disclosure plan and retain sanitized categories."""
    from .checks.disclosure_evidence import (
        DIRECTORY_PATHS, PUBLIC_SECURITY_PATHS, SENSITIVE_PATHS, DisclosureEvidence,
        classify_error_sample, classify_sensitive_sample, has_directory_index_marker,
        is_same_https_origin, is_source_map_json, local_asset_references,
        source_map_reference,
    )
    if target is None:
        return DisclosureEvidence()
    request_count = 0
    sensitive_results = []
    directory_results = []
    public_results = []
    original_sample = original_capture.pop("sample", b"") if original_capture else b""
    original_complete = original_capture.pop("sample_complete", False) if original_capture else False
    original_media = original_capture.pop("media_type", "unknown") if original_capture else "unknown"
    from .checks.passive_evidence import collect_passive_xss_sample
    passive_xss = collect_passive_xss_sample(
        original_sample, status=original_status, media_type=original_media, complete=original_complete,
    )
    header_available = original_capture.pop("header_available", None) if original_capture else None
    server_names = original_capture.pop("server_header_names", ()) if original_capture else ()
    server_types = original_capture.pop("server_info_types", ()) if original_capture else ()
    is_error = original_status is not None and 400 <= original_status <= 599
    error_patterns = classify_error_sample(original_sample) if is_error else ()
    error_complete = original_complete if is_error else None
    source_state = "unknown"
    origin_host = f"[{target[1]}]" if ":" in target[1] else target[1]
    base_url = urlunsplit(("https", origin_host, target[0].path or "/", target[0].query, ""))

    def probe(path, limit=4096):
        nonlocal request_count
        if request_count >= 13:
            return {"status": None, "media_type": "unknown", "sample": b"", "complete": False, "error": "budget", "attempted": False}
        try:
            result = _safe_disclosure_get(target, path, deadline=deadline, limit=limit)
        except Exception:
            # Isolate one path failure; do not expose exception text or stop other checks.
            result = {"status": None, "media_type": "unknown", "sample": b"", "complete": False,
                      "error": "internal", "attempted": False}
        request_count += int(result.get("attempted", False))
        return result

    for path in SENSITIVE_PATHS:
        item = probe(path)
        status = item["status"]
        if status in (404, 410):
            sensitive_results.append((status, "not_found", None))
        elif status in (200, 206):
            marker = classify_sensitive_sample(path, item["sample"])
            sensitive_results.append((status, "found" if marker else "unknown", marker))
        else:
            sensitive_results.append((status, "unknown", None))

    if original_status is not None and 200 <= original_status < 300 and original_media == "text/html":
        raw_refs = local_asset_references(original_sample)
        html_map_ref = source_map_reference(original_sample)
        local_refs = []
        disallowed_ref = False
        for ref in raw_refs:
            if not is_same_https_origin(base_url, ref):
                disallowed_ref = True
                continue
            absolute = urljoin(base_url, ref)
            if urlsplit(absolute).path.lower().endswith((".js", ".css")):
                local_refs.append(absolute)
        if html_map_ref is not None:
            if not is_same_https_origin(base_url, html_map_ref):
                source_state = "reference_only"
            elif request_count >= 13:
                source_state = "reference_only"
            else:
                html_map_url = urljoin(base_url, html_map_ref)
                html_map_parts = urlsplit(html_map_url)
                html_map_item = probe(html_map_parts.path)
                source_state = "confirmed" if (
                    html_map_item["status"] in (200, 206)
                    and is_source_map_json(html_map_item["sample"])
                ) else "reference_only"
        elif not raw_refs:
            source_state = "clear" if original_complete else "unknown"
        elif not local_refs:
            source_state = "unknown"
        elif request_count >= 13:
            source_state = "unknown"
        else:
            asset_url = local_refs[0]
            asset_parts = urlsplit(asset_url)
            asset_path = asset_parts.path
            asset = probe(asset_path)
            if asset["status"] in (200, 206) and asset["media_type"] in ("application/javascript", "text/javascript", "text/css"):
                map_ref = source_map_reference(asset["sample"])
                if map_ref is None:
                    source_state = "clear" if asset["complete"] and len(local_refs) == 1 and not disallowed_ref else "unknown"
                elif not is_same_https_origin(asset_url, map_ref):
                    source_state = "reference_only"
                elif request_count >= 13:
                    source_state = "reference_only"
                else:
                    map_url = urljoin(asset_url, map_ref)
                    map_parts = urlsplit(map_url)
                    map_path = map_parts.path
                    map_item = probe(map_path)
                    source_state = "confirmed" if map_item["status"] in (200, 206) and is_source_map_json(map_item["sample"]) else "reference_only"
            else:
                source_state = "unknown"

    for path in DIRECTORY_PATHS:
        item = probe(path)
        status = item["status"]
        if status in (404, 410):
            state = "not_found"
        elif status in (200, 206):
            state = "listing" if has_directory_index_marker(item["sample"]) else ("not_listing" if item["complete"] else "unknown")
        else:
            state = "unknown"
        directory_results.append((status, state))

    for index, path in enumerate(PUBLIC_SECURITY_PATHS):
        item = probe(path)
        status = item["status"]
        kind = "robots" if index == 2 else "security"
        state = "not_found" if status in (404, 410) else (
            "present" if status in (200, 206) and item["media_type"] == "text/plain" else "unknown"
        )
        public_results.append((status, kind, state, item["media_type"]))

    original_sample = b""
    if original_capture is not None:
        original_capture.clear()
    return DisclosureEvidence(
        sensitive_results=tuple(sensitive_results), source_map_state=source_state,
        directory_results=tuple(directory_results), server_headers_available=header_available,
        server_header_names=tuple(server_names), server_info_types=tuple(server_types),
        error_status=original_status if is_error else None, error_sample_complete=error_complete,
        error_patterns=tuple(error_patterns), public_file_results=tuple(public_results),
        request_count=request_count, passive_xss=passive_xss,
    )


def validate_url(url: str) -> bool:
    """Validate the URL without sending an HTTP request."""
    return resolve_target(url) is not None


def _validate_internal_http_target(target):
    try:
        return _validate_resolved_target(target[0].geturl(), target)
    except (TypeError, IndexError, AttributeError, KeyError):
        return None, "invalid"


def _validate_resolved_target(url, target):
    """Revalidate cached resolution without DNS; return a fresh pinned snapshot."""
    expected, error = _parse_target_url(url)
    if error is not None:
        return None, error
    try:
        if not isinstance(target, (tuple, list)) or len(target) != 3:
            return None, "invalid"
        parsed, hostname, addresses = target
        if parsed != expected[0] or hostname != expected[1]:
            return None, "invalid"
        if not isinstance(addresses, (tuple, list)) or not 0 < len(addresses) <= 32:
            return None, "not_allowed"
        normalized = []
        for address in addresses:
            if not isinstance(address, str) or "%" in address:
                return None, "not_allowed"
            ip = ipaddress.ip_address(address)
            if not _is_allowed_ip(ip):
                return None, "not_allowed"
            normalized.append(ip.compressed)
        # A literal URL can only authorize that literal address.
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        if literal is not None and any(ipaddress.ip_address(a) != literal for a in normalized):
            return None, "not_allowed"
        return (expected[0], expected[1], list(dict.fromkeys(normalized))), None
    except (TypeError, ValueError, AttributeError):
        return None, "invalid"


def _safe_get_response(
    url: str,
    resolved_target=None,
    deadline: float | None = None,
    tls_metadata: dict | None = None,
    redirect_dns_answers: dict | None = None,
    validated_target_capture: dict | None = None,
    cookie_evidence_capture: dict | None = None,
    access_evidence_capture: dict | None = None,
    disclosure_evidence_capture: dict | None = None,
):
    """
    Send a single HTTPS request to an IP address that passed the target policy.

    If the API layer supplies the result of the previous validation, reuse it
    instead of performing another DNS lookup.
    """
    for capture in (tls_metadata, redirect_dns_answers, cookie_evidence_capture,
                    access_evidence_capture, disclosure_evidence_capture):
        if capture is not None:
            capture.clear()
    if validated_target_capture is not None:
        validated_target_capture.pop("takeover_hostname", None)
        validated_target_capture.pop("target", None)
    if resolved_target is not None:
        target, resolution_error = _validate_resolved_target(url, resolved_target)
    else:
        resolution_options = {"deadline": deadline}
        if validated_target_capture is not None:
            resolution_options["diagnostic_capture"] = validated_target_capture
        target, resolution_error = resolve_target_with_status(url, **resolution_options)

    if target is None:
        if resolution_error is not None:
            return None, {}, resolution_error
        if deadline is not None and time.monotonic() >= deadline:
            return None, {}, "timeout"
        return None, {}, "invalid"

    target, validation_error = _validate_resolved_target(url, target)
    if target is None:
        return None, {}, validation_error
    parsed, hostname, public_ips = target
    if validated_target_capture is not None:
        validated_target_capture["target"] = target
        # A supplied target is still subject to DNS-only eligibility checks.
        candidate = _diagnostic_hostname(url)
        try:
            eligible = (
                candidate == hostname and candidate is not None
                and 0 < len(public_ips) <= 32
                and all(_is_allowed_ip(ipaddress.ip_address(value)) for value in public_ips)
            )
        except (TypeError, ValueError):
            eligible = False
        if eligible:
            validated_target_capture["takeover_hostname"] = candidate
    request_timeout = (2, 2) if disclosure_evidence_capture is not None else (3, 5)

    if deadline is not None:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return None, {}, "timeout"

        request_timeout = Timeout(
            total=remaining,
            connect=min(2.0 if disclosure_evidence_capture is not None else 3.0, remaining),
            read=min(2.0 if disclosure_evidence_capture is not None else 5.0, remaining),
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
    session.mount("https://", PinnedIPAdapter(hostname, tls_metadata=tls_metadata))

    response = None

    try:
        response = session.get(
            pinned_url,
            headers={
                "Host": host_header,
                "User-Agent": "CyberShield/1.0",
                "Connection": "close",
                "Accept-Encoding": "identity",
            },
            timeout=request_timeout,
            allow_redirects=False,
            stream=True,
            verify=True,
        )

        if cookie_evidence_capture is not None:
            available, observations = _collect_set_cookie_observations(response)
            cookie_evidence_capture.update(
                available=available,
                observations=observations,
            )

        if access_evidence_capture is not None:
            available, selected = _collect_selected_response_headers(
                response,
                ("Location",),
            )
            access_evidence_capture.update(
                available=available,
                location_values=selected.get("location", ()),
            )

        if disclosure_evidence_capture is not None:
            from .checks.disclosure_evidence import classify_server_headers, media_type as normalize_media_type
            from .checks.disclosure_evidence import SERVER_HEADER_NAMES
            selected_names = tuple(SERVER_HEADER_NAMES) + ("Content-Type", "Content-Encoding", "Content-Length")
            available, selected = _collect_selected_response_headers(response, selected_names)
            server_names, server_types = classify_server_headers(selected) if available else ((), ())
            content_types = selected.get("content-type", ())
            raw_content_type = content_types[0] if len(content_types) == 1 else None
            response_media_type = normalize_media_type(raw_content_type)
            if 400 <= response.status_code <= 599:
                sample_limit = 4096
            elif 200 <= response.status_code < 300 and response_media_type == "text/html":
                sample_limit = 16384
            else:
                sample_limit = 0
            sample, sample_complete = _read_bounded_identity_sample(response, sample_limit) if sample_limit else (b"", False)
            if response.status_code == 206:
                sample_complete = False
            disclosure_evidence_capture.update(
                status=response.status_code,
                header_available=available,
                server_header_names=server_names,
                server_info_types=server_types,
                media_type=response_media_type,
                sample=sample,
                sample_complete=sample_complete,
            )

        # Exclude Set-Cookie entirely from generic response evidence/report data.
        response_headers = {
            name: response.headers[name]
            for name in response.headers
            if name.lower() != "set-cookie"
        }
        return response.status_code, response_headers, None

    except requests.exceptions.Timeout:
        return None, {}, "timeout"

    except requests.exceptions.SSLError:
        return None, {}, "tls"

    except requests.exceptions.RequestException:
        return None, {}, "connection"

    finally:
        try:
            if response is not None:
                response.close()
        finally:
            session.close()


def _safe_cors_preflight(target, deadline=None, capture=None):
    """Send exactly one bounded, pinned OPTIONS preflight to the target URL."""
    if capture is not None:
        capture.clear()
    target, target_error = _validate_internal_http_target(target)
    if target is None:
        if capture is not None:
            capture.update(available=False, error=target_error)
        return target_error
    parsed, hostname, public_ips = target
    if deadline is not None and time.monotonic() >= deadline:
        if capture is not None:
            capture.update(available=False, error="timeout")
        return "timeout"
    ip = public_ips[0]
    ip_for_url = f"[{ip}]" if ":" in ip else ip
    request_url = urlunsplit(("https", f"{ip_for_url}:443", parsed.path or "/", parsed.query, ""))
    remaining = None if deadline is None else deadline - time.monotonic()
    if remaining is not None and remaining <= 0:
        if capture is not None:
            capture.update(available=False, error="timeout")
        return "timeout"
    timeout = Timeout(connect=3.0, read=5.0) if remaining is None else Timeout(
        total=remaining, connect=min(3.0, remaining), read=min(5.0, remaining)
    )
    session = requests.Session()
    session.trust_env = False
    session.mount("https://", PinnedIPAdapter(hostname))
    response = None
    try:
        response = session.options(
            request_url,
            headers={
                "Host": f"[{hostname}]" if ":" in hostname else hostname,
                "Origin": "https://cybershield.invalid",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-cybershield-audit",
                "User-Agent": "CyberShield/1.0",
                "Connection": "close",
            },
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        available, headers = _collect_selected_response_headers(
            response,
            (
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials",
                "Access-Control-Allow-Methods",
                "Access-Control-Allow-Headers",
                "Vary",
            ),
        )
        if capture is not None:
            capture.update(status=response.status_code, available=available, error=None if available else "evidence")
            if available:
                capture["headers"] = headers
        return None if available else "evidence"
    except requests.exceptions.Timeout:
        if capture is not None:
            capture.update(available=False, error="timeout")
        return "timeout"
    except requests.exceptions.SSLError:
        if capture is not None:
            capture.update(available=False, error="tls")
        return "tls"
    except requests.exceptions.RequestException:
        if capture is not None:
            capture.update(available=False, error="connection")
        return "connection"
    except Exception:
        if capture is not None:
            capture.update(available=False, error="internal")
        return "internal"
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            session.close()


def _safe_http_redirect_probe(target, deadline=None, capture=None):
    """Make one pinned, body-free GET to the authorized target's HTTP root."""
    if capture is not None:
        capture.clear()
    target, target_error = _validate_internal_http_target(target)
    if target is None:
        if capture is not None:
            capture.update(available=False, error=target_error)
        return target_error
    parsed, hostname, public_ips = target
    if deadline is not None and time.monotonic() >= deadline:
        return "timeout"
    ip = public_ips[0]
    ip_for_url = f"[{ip}]" if ":" in ip else ip
    request_url = f"http://{ip_for_url}:80/"
    remaining = None if deadline is None else deadline - time.monotonic()
    if remaining is not None and remaining <= 0:
        return "timeout"
    if remaining is None:
        timeout = Timeout(connect=3.0, read=5.0)
    else:
        timeout = Timeout(total=remaining, connect=min(3.0, remaining), read=min(5.0, remaining))
    session = requests.Session()
    session.trust_env = False
    response = None
    try:
        response = session.get(
            request_url,
            headers={"Host": f"[{hostname}]" if ":" in hostname else hostname,
                     "User-Agent": "CyberShield/1.0", "Connection": "close"},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        if capture is not None:
            capture.update(status=response.status_code,
                           location=response.headers.get("Location"),
                           request_url=request_url)
        return None
    except requests.exceptions.Timeout:
        return "timeout"
    except requests.exceptions.RequestException:
        return "connection"
    except Exception:
        return "internal"
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            session.close()


def check_https(url: str) -> dict:
    """Verify the HTTPS connection and TLS certificate without treating errors as success."""

    status_code, _, error = _safe_get_response(url)

    if error == "invalid":
        return {
            "status": "warning",
            "message": "\u0627\u0644\u0631\u0627\u0628\u0637 \u063a\u064a\u0631 \u0635\u0627\u0644\u062d \u0623\u0648 \u063a\u064a\u0631 \u0645\u0633\u0645\u0648\u062d \u0628\u0641\u062d\u0635\u0647",
        }

    if error == "not_allowed":
        return {
            "status": "warning",
            "message": "\u0627\u0644\u0647\u062f\u0641 \u0645\u062d\u0638\u0648\u0631 \u0648\u0641\u0642 \u0633\u064a\u0627\u0633\u0629 \u0627\u0644\u062d\u0645\u0627\u064a\u0629 \u0648\u0644\u0627 \u064a\u0645\u0643\u0646 \u0641\u062d\u0635\u0647.",
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
