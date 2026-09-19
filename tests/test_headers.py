from cleanup.headers import (
    parse_list_unsubscribe,
    has_one_click_unsubscribe,
    parse_authentication_results,
    decode_mime_words,
)


# --- parse_list_unsubscribe ---

def test_parses_mailto_and_https_together():
    header = "<mailto:unsub@example.com>, <https://example.com/unsubscribe?id=123>"
    result = parse_list_unsubscribe(header)
    assert result["mailto"] == "unsub@example.com"
    assert result["http"] == "https://example.com/unsubscribe?id=123"


def test_parses_https_only():
    header = "<https://example.com/unsubscribe?id=123>"
    result = parse_list_unsubscribe(header)
    assert result["http"] == "https://example.com/unsubscribe?id=123"
    assert result["mailto"] is None


def test_parses_mailto_only():
    header = "<mailto:unsub@example.com>"
    result = parse_list_unsubscribe(header)
    assert result["mailto"] == "unsub@example.com"
    assert result["http"] is None


def test_missing_list_unsubscribe_header_returns_no_links():
    result = parse_list_unsubscribe(None)
    assert result["mailto"] is None
    assert result["http"] is None


# --- has_one_click_unsubscribe (RFC 8058) ---

def test_one_click_flag_present():
    assert has_one_click_unsubscribe("List-Unsubscribe=One-Click") is True


def test_one_click_flag_missing_header():
    assert has_one_click_unsubscribe(None) is False


def test_one_click_flag_wrong_value():
    assert has_one_click_unsubscribe("something-else") is False


# --- parse_authentication_results ---

def test_parses_all_pass():
    header = (
        "mta1234.mail.yahoo.com; "
        "dkim=pass header.i=@example.com; "
        "spf=pass smtp.mailfrom=example.com; "
        "dmarc=pass header.from=example.com"
    )
    result = parse_authentication_results(header)
    assert result["spf"] == "pass"
    assert result["dkim"] == "pass"
    assert result["dmarc"] == "pass"


def test_parses_mixed_results():
    header = "mta.mail.yahoo.com; dkim=fail; spf=softfail smtp.mailfrom=example.com; dmarc=none"
    result = parse_authentication_results(header)
    assert result["spf"] == "softfail"
    assert result["dkim"] == "fail"
    assert result["dmarc"] == "none"


def test_missing_authentication_results_header():
    result = parse_authentication_results(None)
    assert result["spf"] is None
    assert result["dkim"] is None
    assert result["dmarc"] is None


# --- decode_mime_words ---

def test_decodes_utf8_base64_encoded_header():
    # Real padding character (U+00B7) followed by "JoinAARP", base64
    # encoded exactly as email.header.Header would produce it.
    header = "=?utf-8?b?wrcgwrcgwrcgSm9pbkFBUlA=?="
    assert decode_mime_words(header) == "· · · JoinAARP"


def test_decodes_utf8_quoted_printable_encoded_header():
    header = "=?utf-8?q?Protect_Your_401=28k=29?="
    assert decode_mime_words(header) == "Protect Your 401(k)"


def test_returns_plain_ascii_header_unchanged():
    assert decode_mime_words("Weekly Digest") == "Weekly Digest"


def test_returns_empty_string_for_missing_header():
    assert decode_mime_words(None) == ""
    assert decode_mime_words("") == ""


def test_decodes_unknown_8bit_header_without_raising():
    # Real crash found running against a live inbox: raw 8-bit bytes with
    # no RFC 2047 encoding marker get labeled "unknown-8bit" by
    # email.header.decode_header — a marker string, not an actual Python
    # codec name, so bytes.decode() raises LookupError on it directly.
    import email
    msg = email.message_from_bytes(b"Subject: Hello \xe2\x80\xa2 World\r\n\r\n")
    result = decode_mime_words(msg.get("Subject"))
    assert result == "Hello • World"