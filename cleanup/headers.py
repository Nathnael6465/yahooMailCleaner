import email.header
import re

_MAILTO_RE = re.compile(r"<mailto:([^>]+)>")
_HTTP_RE = re.compile(r"<(https?://[^>]+)>")
_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=([a-zA-Z]+)")


def parse_list_unsubscribe(header):
    result = {"mailto": None, "http": None}
    if not header:
        return result

    mailto_match = _MAILTO_RE.search(header)
    if mailto_match:
        result["mailto"] = mailto_match.group(1)

    http_match = _HTTP_RE.search(header)
    if http_match:
        result["http"] = http_match.group(1)

    return result


def has_one_click_unsubscribe(header):
    if not header:
        return False
    return "List-Unsubscribe=One-Click" in header


def parse_authentication_results(header):
    result = {"spf": None, "dkim": None, "dmarc": None}
    if not header:
        return result

    for mechanism, value in _AUTH_RESULT_RE.findall(header):
        result[mechanism.lower()] = value.lower()

    return result


def decode_mime_words(value):
    """Decode an RFC 2047 MIME-encoded header value (e.g. a Subject or
    From display name carrying non-ASCII characters) into a plain
    string. Falls back to returning the raw value untouched if there's
    nothing to decode or decoding fails — never raises, since a
    malformed header shouldn't crash a scan."""
    if not value:
        return ""
    try:
        parts = email.header.decode_header(value)
    except (email.header.HeaderParseError, UnicodeDecodeError):
        return value
    decoded = []
    for part, encoding in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(encoding or "utf-8", errors="replace"))
            except LookupError:
                # `encoding` came from email.header.decode_header itself,
                # but isn't always a real Python codec name — e.g.
                # "unknown-8bit" is the label decode_header uses for raw
                # 8-bit bytes with no declared charset, not something
                # bytes.decode() understands. Fall back to utf-8.
                decoded.append(part.decode("utf-8", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)