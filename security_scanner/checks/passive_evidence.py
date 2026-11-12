"""Small bounded static HTML observation; never executes or retains scripts.

Only direct assignments of location.hash/search to an HTML sink are recognized.
This is a code-review indicator, not a JavaScript parser or data-flow proof.
"""

from dataclasses import dataclass
from html.parser import HTMLParser
import re


@dataclass(frozen=True)
class PassiveXSSEvidence:
    response_status: int | None = None
    state: str = "unavailable"

    def __post_init__(self):
        if self.response_status is not None and (
            type(self.response_status) is not int or not 200 <= self.response_status < 300
        ):
            raise ValueError("Invalid original HTML response status")
        if self.state not in {"unavailable", "inconclusive", "no_indicator", "direct_url_html_sink"}:
            raise ValueError("Unsupported static HTML observation")
        if self.state in {"no_indicator", "direct_url_html_sink"} and (
            self.response_status is None or self.response_status == 206
        ):
            raise ValueError("Observation requires a complete original response")


def _tokens(script):
    """Discard strings/comments; reject syntax outside this deliberately tiny lexer.

    Regex literals, template strings and escaped identifiers are unsupported,
    so they cannot be mistaken for executing source/sink statements.
    """
    tokens = []
    index = 0
    while index < len(script):
        char = script[index]
        if char.isspace():
            index += 1
        elif script.startswith("//", index):
            end = script.find("\n", index + 2)
            index = len(script) if end < 0 else end + 1
        elif script.startswith("/*", index):
            end = script.find("*/", index + 2)
            if end < 0:
                return None
            index = end + 2
        elif char in "\"'":
            quote = char
            index += 1
            while index < len(script) and script[index] != quote:
                if script[index] in "\r\n":
                    return None
                if script[index] == "\\":
                    index += 1
                index += 1
            if index >= len(script):
                return None
            index += 1
            tokens.append("STRING")
        elif char in "`\\/":
            return None
        else:
            match = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*|[0-9]+|[^\s]", script[index:])
            tokens.append(match.group())
            index += len(match.group())
    return tokens


def _has_direct_pattern(tokens):
    if tokens is None:
        return False
    # No variable aliases, concatenation, decoding, computed properties or
    # source-only/sink-only heuristic. Require a direct complete statement.
    sinks = (
        ["document", ".", "body", ".", "innerHTML", "="],
        ["document", ".", "getElementById", "(", "STRING", ")", ".", "innerHTML", "="],
    )
    sources = (["location", ".", "hash"], ["location", ".", "search"],
               ["window", ".", "location", ".", "hash"],
               ["window", ".", "location", ".", "search"])
    for start in range(len(tokens)):
        if start and tokens[start - 1] not in {";", "{"}:
            continue
        for sink in sinks:
            for source in sources:
                pattern = sink + source
                end = start + len(pattern)
                if tokens[start:end] == pattern and (end == len(tokens) or tokens[end] == ";"):
                    return True
    return False


class _ScriptObserver(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_script = False
        self.active_script = False
        self.ignored_depth = 0
        self.ignored_tags = []
        self.parts = []
        self.found = False
        self.unsupported = False

    def handle_starttag(self, tag, attrs):
        if tag in {"template", "noscript"}:
            self.ignored_tags.append(tag)
            self.ignored_depth = len(self.ignored_tags)
        if tag != "script":
            return
        self.in_script = True
        names = [key for key, _ in attrs]
        attributes = dict(attrs)
        self.active_script = not self.ignored_depth and "src" not in attributes and (
            attributes.get("type") or ""
        ).strip().lower() in {"", "text/javascript", "application/javascript", "module"}
        if len(names) != len(set(names)):
            self.active_script = False
            self.unsupported = True
        self.parts = []

    def handle_data(self, data):
        if self.in_script and self.active_script:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag in {"template", "noscript"}:
            if self.ignored_tags and self.ignored_tags[-1] == tag:
                self.ignored_tags.pop()
                self.ignored_depth = len(self.ignored_tags)
            else:
                # An unrelated closing tag must not activate inert content.
                self.unsupported = True
        if tag != "script" or not self.in_script:
            return
        if self.active_script:
            tokens = _tokens("".join(self.parts))
            self.unsupported |= tokens is None
            self.found |= _has_direct_pattern(tokens)
        self.in_script = False
        self.parts = []


def collect_passive_xss_sample(sample, *, status, media_type, complete):
    """Reduce an already read original sample to a fixed category, without I/O."""
    if type(status) is not int or not 200 <= status < 300:
        return PassiveXSSEvidence()
    if media_type != "text/html" or complete is not True or status == 206:
        return PassiveXSSEvidence(status, "inconclusive")
    if not isinstance(sample, bytes) or not sample or len(sample) > 16384:
        return PassiveXSSEvidence(status, "inconclusive")
    try:
        text = sample.decode("utf-8", "strict")
        if "\x00" in text:
            return PassiveXSSEvidence(status, "inconclusive")
        parser = _ScriptObserver()
        parser.feed(text)
        parser.close()
        if parser.in_script or parser.ignored_depth:
            state = "inconclusive"
        elif parser.found:
            state = "direct_url_html_sink"
        elif parser.unsupported:
            state = "inconclusive"
        else:
            state = "no_indicator"
        return PassiveXSSEvidence(status, state)
    except Exception:
        return PassiveXSSEvidence(status, "inconclusive")
