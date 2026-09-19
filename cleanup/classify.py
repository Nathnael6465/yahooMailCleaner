import re

_SUSPICIOUS_TLDS = {"info", "xyz", "top", "click", "buzz", "work"}
_SYMBOL_TOKEN_RE = re.compile(r"^([^\w\s])\1*$")

# Starter set of major, unambiguously-real brand root domains — merged
# into the caller-supplied allowlist (see report.py) so users get broad
# legitimate coverage without hand-typing every known company. Matched
# suffix-aware via is_verified_domain, so a subdomain like
# "alerts.chase.com" is covered by the "chase.com" entry automatically.
KNOWN_BRAND_DOMAINS = {
    # retail / marketplaces
    "amazon.com", "walmart.com", "target.com", "costco.com", "samsclub.com",
    "bestbuy.com", "homedepot.com", "lowes.com", "ikea.com", "etsy.com",
    "ebay.com", "wayfair.com", "kohls.com", "macys.com", "nordstrom.com",
    "gap.com", "oldnavy.com", "nike.com", "adidas.com", "cvs.com",
    "walgreens.com", "staples.com", "officedepot.com",
    # banks / finance / insurance
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "capitalone.com", "americanexpress.com", "discover.com", "usbank.com",
    "ally.com", "fidelity.com", "vanguard.com", "schwab.com", "paypal.com",
    "venmo.com", "amfam.com", "statefarm.com", "geico.com", "progressive.com",
    "allstate.com", "intuit.com", "turbotax.com", "creditkarma.com",
    "experian.com", "equifax.com", "transunion.com",
    # tech / services
    "google.com", "gmail.com", "microsoft.com", "apple.com", "icloud.com",
    "yahoo.com", "spotify.com", "netflix.com", "hulu.com", "disneyplus.com",
    "openai.com", "chatgpt.com", "adobe.com", "dropbox.com", "zoom.us",
    "slack.com", "linkedin.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "reddit.com", "pinterest.com", "tiktok.com",
    "uber.com", "lyft.com", "doordash.com", "grubhub.com", "instacart.com",
    "airbnb.com", "steampowered.com", "xbox.com", "playstation.com",
    "nintendo.com", "github.com", "stackoverflow.com", "indeed.com",
    "glassdoor.com",
    # travel
    "delta.com", "united.com", "aa.com", "southwest.com", "expedia.com",
    "booking.com", "hotels.com", "marriott.com", "hilton.com",
    "choicehotels.com", "choiceprivileges.com", "alaskaair.com",
    # telecom / utilities
    "verizon.com", "att.com", "t-mobile.com", "comcast.com", "xfinity.com",
    "spectrum.com", "cox.com",
    # shipping / delivery
    "ups.com", "fedex.com", "usps.com", "dhl.com",
    # health
    "mychart.com", "cvshealth.com", "unitedhealthgroup.com", "anthem.com",
    "aetna.com", "cigna.com", "kaiserpermanente.org",
}


def classify_message(sender, list_unsubscribe, auth_results, allowlist, display_name, subject):
    """
    Layered sieve, coarsest net first: check nets in order and stop at
    the first match (one reason per message), so a message already
    caught by an obvious/blatant signal never needs a narrower, more
    false-positive-prone check run against it.

    Default-deny: a message that clears every specific net is NOT
    treated as legitimate by default — it's flagged as
    "unverified_domain" unless its domain (or exact address) is in
    `allowlist`. `allowlist` is expected to already include
    KNOWN_BRAND_DOMAINS (merged once per scan by the caller, not per
    message — see report.py's classify_messages) plus the user's own
    curated entries. This inverts the sieve's old "innocent until
    proven guilty" default deliberately: the set of senders a person
    actually trusts is small and finite, while the set of spam-evasion
    tricks is not, so enumerating the former is the more durable
    signal (see Addendum 8).
    """
    domain = sender.split("@")[-1]
    local_part = sender.split("@")[0]

    if domain == "gov" or domain.endswith(".gov"):
        # .gov is a federally restricted TLD — only verified US government
        # entities can register one, so it's inherently trustworthy
        # regardless of whether this specific agency is in the allowlist.
        return {"flagged": False, "reasons": []}

    if sender in allowlist or is_verified_domain(domain, allowlist):
        return {"flagged": False, "reasons": []}

    if _auth_failed_or_missing(auth_results):
        return {"flagged": True, "reasons": ["auth_failed_or_missing"]}

    if _is_suspicious_local_part(local_part):
        return {"flagged": True, "reasons": ["suspicious_local_part"]}

    if _has_padding_evasion(display_name) or _has_padding_evasion(subject):
        return {"flagged": True, "reasons": ["padding_evasion"]}

    if list_unsubscribe.get("mailto") or list_unsubscribe.get("http"):
        return {"flagged": True, "reasons": ["list_unsubscribe_present"]}

    if _is_suspicious_tld(domain):
        return {"flagged": True, "reasons": ["suspicious_tld"]}

    return {"flagged": True, "reasons": ["unverified_domain"]}


def _domain_suffixes(domain):
    """Yield domain, then each parent label-suffix, e.g.
    'alerts.chase.com' -> 'alerts.chase.com', 'chase.com', 'com'."""
    labels = domain.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


def is_verified_domain(domain, verified):
    """O(domain label depth) set-membership check, not a linear scan
    over `verified` — a subdomain is verified if any of its parent
    domains is in the set."""
    return any(suffix in verified for suffix in _domain_suffixes(domain))


def _auth_failed_or_missing(auth_results):
    return not any(auth_results.get(k) == "pass" for k in ("spf", "dkim", "dmarc"))


def _is_suspicious_local_part(local_part):
    return _has_low_vowel_ratio_with_digits(local_part) or _has_long_consonant_run(local_part)


def _has_low_vowel_ratio_with_digits(local_part):
    letters = [c for c in local_part if c.isalpha()]
    digits = [c for c in local_part if c.isdigit()]
    if not (5 <= len(local_part) <= 20):
        return False
    if not letters or not digits:
        return False
    vowels = sum(1 for c in letters if c.lower() in "aeiou")
    vowel_ratio = vowels / len(letters)
    return vowel_ratio < 0.2


def _has_long_consonant_run(local_part, threshold=5):
    """Catches pure-letter gibberish (no digits) that the digit-gated
    vowel-ratio check above never evaluates — real English essentially
    never strings this many consonants together unbroken."""
    run = best = 0
    for c in local_part.lower():
        if c.isalpha() and c not in "aeiou":
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best >= threshold


def _is_suspicious_tld(domain):
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else domain.lower()
    return tld in _SUSPICIOUS_TLDS


def _is_symbol_token(token):
    """True if a whitespace-delimited token is made up entirely of one
    repeated non-alphanumeric character (e.g. '·', '----'), but not
    "O'Brien", "AT&T", or "#1234"."""
    return bool(_SYMBOL_TOKEN_RE.match(token))


def _has_padding_evasion(text, min_run=3):
    """Detect repeated-punctuation/symbol padding used to break exact-
    match/signature spam filters, e.g. '· · · · JoinAARP · · · ·'.

    Looks for a run of >= min_run consecutive whitespace-separated
    tokens, anchored at the very start or end of the string, where
    every token in the run is a bare symbol token. Anchoring at a
    boundary (not anywhere mid-string) matters: legitimate text can
    contain an isolated divider token like '-' or '&' without being
    evasive; real padding brackets the actual name/subject like a
    frame. Requiring multiple separate tokens (not one token with
    repeated characters) is what keeps this from firing on ordinary
    emphatic punctuation like '...' or '!!!' — a single token, below
    min_run, and extremely common in legitimate marketing/casual
    subject lines.
    """
    if not text or not text.strip():
        return False
    tokens = text.split()
    if len(tokens) < min_run:
        return False

    leading_run = 0
    for tok in tokens:
        if _is_symbol_token(tok):
            leading_run += 1
        else:
            break
    if leading_run >= min_run:
        return True

    trailing_run = 0
    for tok in reversed(tokens):
        if _is_symbol_token(tok):
            trailing_run += 1
        else:
            break
    return trailing_run >= min_run
