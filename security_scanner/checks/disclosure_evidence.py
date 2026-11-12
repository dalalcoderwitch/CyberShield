"""Bounded, sanitized evidence helpers for Disclosure checks."""

from dataclasses import dataclass
from html.parser import HTMLParser
import json
import re
from urllib.parse import urljoin, urlsplit

from .passive_evidence import PassiveXSSEvidence


SENSITIVE_PATHS = (
    "/.env", "/.git/HEAD", "/.git/config", "/.DS_Store",
    "/backup.zip", "/database.sql",
)
DIRECTORY_PATHS = ("/uploads/", "/files/")
PUBLIC_SECURITY_PATHS = ("/.well-known/security.txt", "/security.txt", "/robots.txt")
SERVER_HEADER_NAMES = (
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Runtime", "X-PHP-Version", "Via",
)

_SENSITIVE_ENV = re.compile(
    r"(?im)^\s*(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET_ACCESS_KEY|API_KEY|TOKEN)\s*=\s*\S+"
)
_GIT_HEAD = re.compile(rb"(?m)^ref:\s*refs/(?:heads|tags)/[A-Za-z0-9._/-]+\s*$")
_GIT_CONFIG = re.compile(rb"(?im)^\[(?:core|remote\s+\"[^\"]+\"|branch\s+\"[^\"]+\")\]\s*$")
_SQL_DUMP = re.compile(rb"(?is)(?:--\s*(?:MySQL dump|PostgreSQL database dump)|\bCREATE\s+TABLE\b.{0,300}\b(?:ENGINE|PRIMARY KEY|INSERT INTO)\b|\bINSERT\s+INTO\s+[`\"\w]+\s+VALUES\s*\()")
_SOURCE_MAP = re.compile(r"(?m)(?:[#@]\s*sourceMappingURL\s*=\s*)([^\s*]+)")


@dataclass(frozen=True)
class DisclosureEvidence:
    """Only bounded result categories; never contains response bodies or values."""

    sensitive_results: tuple[tuple[int | None, str, str | None], ...] = ()
    source_map_state: str = "unknown"
    directory_results: tuple[tuple[int | None, str], ...] = ()
    server_headers_available: bool | None = None
    server_header_names: tuple[str, ...] = ()
    server_info_types: tuple[str, ...] = ()
    error_status: int | None = None
    error_sample_complete: bool | None = None
    error_patterns: tuple[str, ...] = ()
    public_file_results: tuple[tuple[int | None, str, str, str], ...] = ()
    request_count: int = 0
    passive_xss: PassiveXSSEvidence | None = None

    def __post_init__(self):
        if self.passive_xss is not None and not isinstance(self.passive_xss, PassiveXSSEvidence):
            raise TypeError("Expected sanitized passive HTML evidence")
        if self.source_map_state not in {"confirmed", "reference_only", "clear", "unknown"}:
            raise ValueError("unsupported source-map evidence state")
        if self.server_headers_available is not None and type(self.server_headers_available) is not bool:
            raise TypeError("server_headers_available must be bool or None")
        if not 0 <= self.request_count <= 13:
            raise ValueError("Disclosure request count exceeds its per-scan bound")
        allowed_patterns = {"stack_trace", "internal_path", "sql_error", "framework_debug"}
        if not set(self.error_patterns) <= allowed_patterns:
            raise ValueError("unsupported error signature category")
        if not all(isinstance(name, str) and name in SERVER_HEADER_NAMES for name in self.server_header_names):
            raise ValueError("server header evidence must contain approved names only")
        if not all(isinstance(item, tuple) and len(item) == 3 for item in self.sensitive_results):
            raise ValueError("invalid sensitive-path result shape")
        for status, outcome, marker in self.sensitive_results:
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError("invalid sensitive-path HTTP status")
            if outcome not in {"found", "not_found", "unknown"} or marker not in {None, "dotenv", "git_head", "git_config", "ds_store", "zip_archive", "sql_dump"}:
                raise ValueError("invalid sensitive-path classification")
        if not all(isinstance(item, tuple) and len(item) == 2 for item in self.directory_results):
            raise ValueError("invalid directory result shape")
        for status, state in self.directory_results:
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError("invalid directory HTTP status")
            if state not in {"listing", "not_listing", "not_found", "unknown"}:
                raise ValueError("invalid directory classification")
        if not all(isinstance(item, tuple) and len(item) == 4 for item in self.public_file_results):
            raise ValueError("invalid public-file result shape")
        for status, kind, state, media in self.public_file_results:
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise ValueError("invalid public-file HTTP status")
            if kind not in {"security", "robots"} or state not in {"present", "not_found", "unknown"}:
                raise ValueError("invalid public-file classification")
            if media not in {"text/plain", "text/html", "text/css", "application/json", "application/javascript", "text/javascript", "application/octet-stream", "unknown", "other"}:
                raise ValueError("invalid public-file media type")
        if not set(self.server_info_types) <= {"version", "technology", "proxy", "runtime", "platform"}:
            raise ValueError("invalid server-information classification")
        if self.error_status is not None and (type(self.error_status) is not int or not 400 <= self.error_status <= 599):
            raise ValueError("error_status must be an HTTP error status")
        if self.error_sample_complete is not None and type(self.error_sample_complete) is not bool:
            raise TypeError("error_sample_complete must be bool or None")


def classify_sensitive_sample(path: str, sample: bytes) -> str | None:
    """Return a fixed content type marker; no file data or secrets are retained."""
    if path not in SENSITIVE_PATHS or not isinstance(sample, bytes):
        return None
    if path == "/.env":
        return "dotenv" if _SENSITIVE_ENV.search(sample.decode("utf-8", "ignore")) else None
    if path == "/.git/HEAD":
        return "git_head" if _GIT_HEAD.search(sample) else None
    if path == "/.git/config":
        return "git_config" if _GIT_CONFIG.search(sample) else None
    if path == "/.DS_Store":
        return "ds_store" if sample.startswith(b"\x00\x00\x00\x01Bud1") or sample.startswith(b"Bud1") else None
    if path == "/backup.zip":
        return "zip_archive" if sample.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) else None
    if path == "/database.sql":
        return "sql_dump" if _SQL_DUMP.search(sample) else None
    return None


def has_directory_index_marker(sample: bytes) -> bool:
    if not isinstance(sample, bytes):
        return False
    text = sample[:4096].decode("utf-8", "ignore")
    return bool(re.search(
        r"(?is)<title\s*>\s*Index of\s+[^<]*</title\s*>|<h1\s*>\s*Index of\s+[^<]*</h1\s*>|Directory Listing for\s+[^<\r\n]+",
        text,
    ))


def classify_server_headers(header_values: dict[str, tuple[str, ...]]):
    """Reduce raw values to approved header names and generic disclosure types."""
    names = []
    kinds = set()
    technology = re.compile(r"(?i)\b(?:apache|nginx|microsoft-iis|kestrel|express|tomcat|jetty|php|asp\.net|node\.js|gunicorn|uwsgi|openresty|wordpress|drupal|django|laravel|rails|flask)\b")
    version = re.compile(r"\b\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?\b")
    for approved in SERVER_HEADER_NAMES:
        values = header_values.get(approved.lower(), ())
        if not values:
            continue
        names.append(approved)
        joined = " ".join(values)[:8192]
        if approved.lower() != "via" and version.search(joined):
            kinds.add("version")
        if technology.search(joined):
            kinds.add("technology")
        if approved.lower() == "via":
            kinds.add("proxy")
        if approved.lower() in ("x-powered-by", "x-php-version", "x-runtime"):
            kinds.add("runtime")
        if approved.lower() in ("x-aspnet-version", "x-aspnetmvc-version"):
            kinds.add("platform")
    return tuple(names), tuple(sorted(kinds))


class _ErrorText(HTMLParser):
    """Ignore documentation/code and inactive HTML regions for SQL indicators."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ignored = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag in {"pre", "code", "script", "style", "template"}:
            self.ignored.append(tag)
        elif not self.ignored:
            self.text.append("\n")

    def handle_endtag(self, tag):
        if self.ignored and tag == self.ignored[-1]:
            self.ignored.pop()
        elif not self.ignored:
            self.text.append("\n")

    def handle_data(self, data):
        if not self.ignored:
            self.text.append(data)


def _has_sql_error_signature(data):
    parser = _ErrorText()
    try:
        parser.feed(data)
        parser.close()
    except Exception:
        return False
    visible = "".join(parser.text)
    # Only recognizable error lines, never a database/framework name alone.
    for line in visible.splitlines():
        if re.search(r"(?i)\b(?:tutorial|example|documentation)\b", line):
            continue
        sqlstate = re.search(
            r"(?i)^\s*(?:(?:Fatal error|Uncaught)\s*:?\s*)?(?:PDOException:\s*)?"
            r"SQLSTATE\[[0-9A-Z]{5}\](?:\s*\[\d+\])?\s*:?.{0,160}"
            r"(?:syntax error|table missing|does not exist|access denied|connection refused|"
            r"constraint violation|unknown (?:table|column|database)|could not connect)", line,
        )
        if sqlstate or re.search(
            r"(?i)^\s*(?:ORA-\d{5}:\s*\S|ERROR:\s*syntax error at or near\b|"
            r"(?:sqlite3\.OperationalError|SQLite3?Exception):\s*\S|"
            r"Warning:\s*mysql_(?:query|fetch\w*)\(\).{0,120}(?:expects|error|failed))", line,
        ):
            return True
    return False


def classify_error_sample(sample: bytes) -> tuple[str, ...]:
    """Recognize common error disclosure families without retaining matched text."""
    if not isinstance(sample, bytes):
        return ()
    data = sample[:4096].decode("utf-8", "ignore")
    patterns = set()
    if re.search(r"(?i)Traceback \(most recent call last\)|Exception in thread|\bat [\w.$]+\([^\r\n]*:\d+\)|\b[A-Za-z0-9_.]+Exception\b", data):
        patterns.add("stack_trace")
    if re.search(r"(?i)(?:/var/www/|/home/[^/]+/|/srv/[^/]+/|/usr/src/|[A-Z]:\\(?:inetpub|wwwroot)\\)", data):
        patterns.add("internal_path")
    if _has_sql_error_signature(data):
        patterns.add("sql_error")
    if re.search(r"(?i)Werkzeug Debugger|Django Version|DEBUG\s*=\s*True|Laravel Ignition|Rails\.root|ASP\.NET.*Server Error|Whoops, looks like something went wrong", data):
        patterns.add("framework_debug")
    return tuple(sorted(patterns))


class _AssetParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []

    def handle_starttag(self, tag, attrs):
        attrs = {name.lower(): value for name, value in attrs if name}
        candidate = None
        if tag.lower() == "script":
            candidate = attrs.get("src")
        elif tag.lower() == "link" and "stylesheet" in (attrs.get("rel") or "").lower().split():
            candidate = attrs.get("href")
        if candidate and len(self.references) < 128:
            self.references.append(candidate)


def local_asset_references(sample: bytes):
    try:
        parser = _AssetParser()
        parser.feed(sample[:16384].decode("utf-8", "replace"))
        return tuple(parser.references)
    except Exception:
        return ()


def source_map_reference(sample: bytes):
    if not isinstance(sample, bytes):
        return None
    match = _SOURCE_MAP.search(sample[:4096].decode("utf-8", "ignore"))
    return match.group(1).rstrip("*/") if match else None


def is_same_https_origin(base_url: str, candidate: str) -> bool:
    if not isinstance(candidate, str) or not candidate or "\\" in candidate or any(ord(c) < 32 or ord(c) == 127 for c in candidate):
        return False
    try:
        base = urlsplit(base_url)
        resolved = urljoin(base_url, candidate)
        parsed = urlsplit(resolved)
        port = parsed.port
        base_port = base.port
    except (TypeError, ValueError):
        return False
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        return False
    if port not in (None, 443) or base_port not in (None, 443) or base.scheme.lower() != "https":
        return False
    try:
        return parsed.hostname.rstrip(".").encode("idna").lower() == (base.hostname or "").rstrip(".").encode("idna").lower()
    except UnicodeError:
        return False


def is_source_map_json(sample: bytes) -> bool:
    if not isinstance(sample, bytes) or len(sample) > 4096:
        return False
    try:
        data = json.loads(sample.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError):
        return False
    return (
        isinstance(data, dict)
        and data.get("version") == 3
        and ((isinstance(data.get("sources"), list) and isinstance(data.get("mappings"), str))
             or isinstance(data.get("sections"), list))
    )


def media_type(content_type: str | None) -> str:
    if not isinstance(content_type, str):
        return "unknown"
    return content_type.split(";", 1)[0].strip().lower()[:100] or "unknown"
