"""
One-off triage tool — NOT part of the maintained pipeline. Bootstraps a
manually-reviewable candidate list for allowlist.txt now that classify.py
uses a default-deny model (Addendum 8): a message is only NOT flagged if
its domain is in the allowlist (or KNOWN_BRAND_DOMAINS). Everything else
gets flagged as "unverified_domain".

Reads domain_history.json (every domain ever seen across prior scans) and
the most recent scan_report_*.json (domains already flagged for another
reason — no need to review those, they're already handled correctly).
Excludes anything KNOWN_BRAND_DOMAINS already covers, then splits what's
left by root-domain name length: short/plausible names go into the output
file for a human to glance at; long/keyword-stuffed names (validated
against real data as 56%+ junk) are silently dropped — the new default
will already flag those correctly, no need to review them.

Read-only against local JSON files — no live IMAP connection needed.

Rerun-safe: if allowlist_candidates.txt already exists, any domain that
was in it before but isn't in allowlist.txt now is treated as something
you already looked at and deliberately did NOT keep — it's recorded in
rejected_domains.txt and never resurfaces on a later run, even though
it isn't a "known brand" and would otherwise look like a fresh
candidate every time. Without this, re-running the script after a
manual triage pass silently undoes that work.

Usage: python build_allowlist_candidates.py
Output: allowlist_candidates.txt — open it, delete the lines that aren't
real senders you want to keep, then copy the survivors into allowlist.txt.
"""
import glob
import json
import os
import re

from cleanup.classify import KNOWN_BRAND_DOMAINS, is_verified_domain
from cleanup.domain_history import DEFAULT_PATH as DOMAIN_HISTORY_PATH, load_domain_history

CANDIDATES_PATH = "allowlist_candidates.txt"
REJECTED_PATH = "rejected_domains.txt"
MAX_ROOT_LABEL_LENGTH = 12

# Two-label public suffixes where "last two labels" isn't the real root
# (e.g. "hotmail.com.mx" needs 3 labels, not "com.mx"). Not exhaustive —
# just enough to cover what's actually shown up in this inbox's history.
_COMPOUND_SUFFIXES = {
    "co.uk", "com.au", "com.mx", "co.jp", "com.br", "co.nz", "org.uk",
    "ac.uk", "gov.uk", "co.in",
}


def _root_domain(domain):
    """Crude eTLD+1 approximation — good enough for a one-time triage
    aid, not used anywhere in live classification."""
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _COMPOUND_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _looks_short_and_plausible(domain):
    name = re.sub(r"[^a-z]", "", _root_domain(domain).split(".")[0].lower())
    return len(name) <= MAX_ROOT_LABEL_LENGTH


def _latest_scan_report():
    reports = sorted(glob.glob("scan_report_*.json"))
    return reports[-1] if reports else None


def _load_domain_list(path):
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


def main():
    if not os.path.exists(DOMAIN_HISTORY_PATH):
        print(f"No {DOMAIN_HISTORY_PATH} found — run a scan first.")
        return

    all_domains = load_domain_history()
    user_allowlist = _load_domain_list("allowlist.txt")

    # Anything that was in the candidates file last run but isn't in
    # allowlist.txt now was deliberately rejected during manual triage —
    # remember that permanently so it doesn't resurface below.
    previously_shown = _load_domain_list(CANDIDATES_PATH)
    newly_rejected = previously_shown - user_allowlist
    rejected = _load_domain_list(REJECTED_PATH) | newly_rejected
    if newly_rejected:
        with open(REJECTED_PATH, "a") as f:
            for d in sorted(newly_rejected - _load_domain_list(REJECTED_PATH)):
                f.write(d + "\n")
        print(f"Recorded {len(newly_rejected)} previously-shown, not-allowlisted domain(s) as rejected (won't resurface).")

    report_path = _latest_scan_report()
    if report_path:
        with open(report_path) as f:
            already_flagged = set(json.load(f).keys())
        print(f"Using {report_path} to exclude {len(already_flagged)} already-flagged domain(s).")
    else:
        already_flagged = set()
        print("No scan_report_*.json found — reviewing the full domain history instead.")

    currently_passing = all_domains - already_flagged
    verified = KNOWN_BRAND_DOMAINS | user_allowlist
    remaining = {d for d in currently_passing if not is_verified_domain(d, verified)}
    plausible_roots = sorted({
        _root_domain(d) for d in remaining
        if _looks_short_and_plausible(d) and _root_domain(d) not in rejected
    })
    junky_count = len({_root_domain(d) for d in remaining}) - len(plausible_roots)

    with open(CANDIDATES_PATH, "w") as f:
        for domain in plausible_roots:
            f.write(domain + "\n")

    print(f"Total domains in history: {len(all_domains)}")
    print(f"Already flagged (excluded, already handled): {len(already_flagged)}")
    print(f"Auto-matched to a known brand or already in allowlist.txt (excluded): {len(currently_passing) - len(remaining)}")
    print(f"Presumed junk by name shape (excluded, not shown): {junky_count}")
    print(f"Previously reviewed and rejected (excluded, see {REJECTED_PATH}): {len(rejected)}")
    print(f"Written to {CANDIDATES_PATH}: {len(plausible_roots)} domain(s) to review.")
    print(f"\nOpen {CANDIDATES_PATH}, delete the lines that aren't real senders you want,")
    print("then copy the survivors into allowlist.txt (one domain per line).")


if __name__ == "__main__":
    main()
