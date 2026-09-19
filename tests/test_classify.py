from cleanup.classify import classify_message


# --- Net 0b: .gov is inherently trusted, even with a blank allowlist ---

def test_gov_domain_passes_with_empty_allowlist():
    result = classify_message(
        sender="notice@bentoncountyar.gov",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": None, "dkim": None, "dmarc": None},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


def test_gov_lookalike_domain_is_not_treated_as_gov():
    # "notreallygov.com" must NOT match — only a real ".gov" TLD counts.
    result = classify_message(
        sender="alerts@notreallygov.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["unverified_domain"]


# --- Net 1 (FR4.1): auth failure — checked first, short-circuits ---

def test_flags_via_auth_failure_even_with_suspicious_local_part():
    # rnk4wxc is also a suspicious local-part, but auth failure is net 1
    # and short-circuits before net 2 is ever evaluated.
    result = classify_message(
        sender="rnk4wxc@t4r.plasticcars.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": None, "dkim": None, "dmarc": None},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["auth_failed_or_missing"]


def test_flags_message_when_authentication_fails_even_with_readable_name():
    result = classify_message(
        sender="alerts@suspicious-domain.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["auth_failed_or_missing"]


# --- Net 2 (FR4.2): suspicious local-part, isolated with clean auth ---

def test_flags_machine_generated_local_part_with_digits_when_auth_is_clean():
    # Original rnk4wxc example, but with clean auth so net 2 (local-part)
    # is what actually gets tested in isolation. Domain isn't verified,
    # so if this net didn't fire it would still flag via unverified_domain
    # — but we assert the more specific reason wins.
    result = classify_message(
        sender="rnk4wxc@t4r.plasticcars.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["suspicious_local_part"]


def test_flags_pure_letter_gibberish_local_part_via_consonant_run():
    # Real example from a live scan: no digits at all, so the original
    # digit-gated vowel-ratio check alone would miss this — the added
    # consonant-run check (>=5) is what catches it.
    result = classify_message(
        sender="michpjlhjrnpndjz@gtonfamilyattorney.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["suspicious_local_part"]


# --- Net 3 (FR4.3): display name / subject padding-evasion ---

def test_flags_display_name_with_dot_padding_both_sides():
    # Real example from a live inbox screenshot.
    result = classify_message(
        sender="promo@aarpdeals.example.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="· · · · JoinAARP · · · ·",
        subject="25% off AARP membership for you",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["padding_evasion"]


def test_flags_subject_with_dot_padding_when_display_name_is_clean():
    # Real example from a live inbox screenshot — the padding is on the
    # subject this time, with a symbol token glued to the first real word.
    result = classify_message(
        sender="alerts@prioritygold.example.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="PriorityGoldAlerts",
        subject="· · · · Protect Your 401(k) With Gold & Silver · · · ·",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["padding_evasion"]


def test_padding_evasion_short_circuits_before_list_unsubscribe():
    # Same message would also match net 4 (list_unsubscribe present) —
    # confirms padding_evasion, the more specific signal, wins per NFR12.
    result = classify_message(
        sender="promo@aarpdeals.example.com",
        list_unsubscribe={"mailto": None, "http": "https://aarpdeals.example.com/unsub"},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="· · · · JoinAARP · · · ·",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["padding_evasion"]


def test_does_not_flag_apostrophe_in_display_name():
    result = classify_message(
        sender="obrien@company.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist={"company.com"},
        display_name="O'Brien",
        subject="Re: Fwd: quarterly report",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


def test_does_not_flag_comma_and_hyphen_in_display_name_and_subject():
    result = classify_message(
        sender="jsmith@company.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist={"company.com"},
        display_name="Smith, John",
        subject="50% OFF - Ends Friday!",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


def test_does_not_flag_ampersand_in_display_name():
    result = classify_message(
        sender="hello@jj.example.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist={"jj.example.com"},
        display_name="Johnson & Johnson",
        subject="Invoice #1234",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


def test_does_not_flag_trailing_ellipsis_as_padding():
    # A single '...' token is below min_run (3 SEPARATE symbol tokens
    # required) and extremely common in legitimate casual/marketing copy.
    result = classify_message(
        sender="hello@company.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist={"company.com"},
        display_name="Company Updates",
        subject="Wait for it...",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


# --- Net 4 (FR4.4): List-Unsubscribe present ---

def test_flags_legit_newsletter_because_of_list_unsubscribe_header():
    result = classify_message(
        sender="newsletter@somebrand.com",
        list_unsubscribe={"mailto": None, "http": "https://somebrand.com/unsub"},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["list_unsubscribe_present"]


# --- Net 5 (FR4.5): suspicious TLD ---

def test_flags_suspicious_tld():
    result = classify_message(
        sender="info@somejunkbrand.info",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["suspicious_tld"]


# --- Default-deny fallback (Addendum 8): unverified domain ---

def test_flags_unverified_domain_with_otherwise_clean_signals():
    result = classify_message(
        sender="hello@totallyrandomcompany.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=set(),
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["unverified_domain"]


def test_does_not_flag_domain_in_user_allowlist():
    result = classify_message(
        sender="hello@knowncompany.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist={"knowncompany.com"},
        display_name="",
        subject="",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


def test_does_not_flag_subdomain_of_allowlisted_root_domain():
    # Real brands rotate subdomains constantly (alerts.chase.com,
    # communications.paypal.com, etc.) — a single root-domain allowlist
    # entry must cover all of them via suffix matching, not just an
    # exact string match.
    result = classify_message(
        sender="noreply@alerts.chase.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist={"chase.com"},
        display_name="",
        subject="",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


def test_does_not_flag_sibling_domain_sharing_a_suffix():
    # 'notchase.com' must NOT match an allowlist entry of 'chase.com' —
    # suffix matching requires a '.' boundary, not just a shared tail
    # substring.
    result = classify_message(
        sender="hello@notchase.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist={"chase.com"},
        display_name="",
        subject="",
    )
    assert result["flagged"] is True
    assert result["reasons"] == ["unverified_domain"]


# --- FR17: built-in KNOWN_BRAND_DOMAINS, merged by report.py per scan ---

def test_known_brand_domain_passes_even_with_empty_user_allowlist():
    # classify_message itself doesn't know about KNOWN_BRAND_DOMAINS —
    # report.py's classify_messages merges it into the allowlist once
    # per scan. Here we simulate that merge directly to test the
    # suffix-matching behavior end to end.
    from cleanup.classify import KNOWN_BRAND_DOMAINS
    verified = set() | KNOWN_BRAND_DOMAINS
    result = classify_message(
        sender="orders@amazon.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist=verified,
        display_name="",
        subject="",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


# --- FR5: allowlist overrides every other rule ---

def test_allowlisted_domain_is_never_flagged():
    result = classify_message(
        sender="rnk4wxc@t4r.plasticcars.com",
        list_unsubscribe={"mailto": None, "http": None},
        auth_results={"spf": None, "dkim": None, "dmarc": None},
        allowlist={"t4r.plasticcars.com"},
        display_name="",
        subject="",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []


def test_allowlisted_exact_address_is_never_flagged():
    result = classify_message(
        sender="newsletter@somebrand.com",
        list_unsubscribe={"mailto": None, "http": "https://somebrand.com/unsub"},
        auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        allowlist={"newsletter@somebrand.com"},
        display_name="",
        subject="",
    )
    assert result["flagged"] is False
    assert result["reasons"] == []
