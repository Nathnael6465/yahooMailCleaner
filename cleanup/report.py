import json
import logging
from datetime import datetime, timezone

from cleanup.classify import classify_message, KNOWN_BRAND_DOMAINS
from cleanup.headers import (
    parse_authentication_results,
    parse_list_unsubscribe,
    has_one_click_unsubscribe,
    decode_mime_words,
)
from cleanup.imap_client import fetch_headers

logger = logging.getLogger(__name__)


def _extract_address(from_header):
    """Pull the bare email address out of a 'Name <addr@domain.com>' string."""
    if "<" in from_header and ">" in from_header:
        return from_header.split("<", 1)[1].split(">", 1)[0].strip().lower()
    return from_header.strip().lower()


def _extract_display_name(from_header):
    """Pull the decoded display name out of a 'Name <addr@domain.com>'
    string. Returns '' when there's no display name (bare address
    only)."""
    decoded = decode_mime_words(from_header)
    if "<" in decoded and ">" in decoded:
        return decoded.split("<", 1)[0].strip().strip('"')
    return ""


def classify_messages(raw_messages, allowlist):
    verified = allowlist | KNOWN_BRAND_DOMAINS
    results = []
    for raw in raw_messages:
        sender = _extract_address(raw.get("from", ""))
        display_name = _extract_display_name(raw.get("from", ""))
        subject = decode_mime_words(raw.get("subject", ""))
        list_unsubscribe = parse_list_unsubscribe(raw.get("list_unsubscribe"))
        one_click = has_one_click_unsubscribe(raw.get("list_unsubscribe_post"))
        auth_results = parse_authentication_results(raw.get("authentication_results"))
        verdict = classify_message(
            sender, list_unsubscribe, auth_results, verified,
            display_name, subject,
        )
        results.append({
            "uid": raw["uid"],
            "sender": sender,
            "domain": sender.split("@")[-1] if "@" in sender else sender,
            "display_name": display_name,
            "subject": subject,
            "flagged": verdict["flagged"],
            "reasons": verdict["reasons"],
            "list_unsubscribe": list_unsubscribe,
            "one_click": one_click,
        })
    flagged_count = sum(1 for r in results if r["flagged"])
    logger.info("Classified %d message(s): %d flagged, %d not flagged.", len(results), flagged_count, len(results) - flagged_count)
    return results


def aggregate_by_domain(classified):
    domains = {}
    for item in classified:
        if not item["flagged"]:
            continue
        entry = domains.setdefault(item["domain"], {"count": 0, "reasons": set(), "messages": []})
        entry["count"] += 1
        entry["reasons"].update(item["reasons"])
        entry["messages"].append({
            "uid": item["uid"],
            "sender": item["sender"],
            "reasons": item["reasons"],
            "list_unsubscribe": item["list_unsubscribe"],
            "one_click": item["one_click"],
        })
    aggregated = {
        domain: {"count": d["count"], "reasons": sorted(d["reasons"]), "messages": d["messages"]}
        for domain, d in domains.items()
    }
    logger.info("Aggregated into %d domain(s).", len(aggregated))
    return aggregated


def write_report(aggregated, path):
    with open(path, "w") as f:
        json.dump(aggregated, f, indent=2)
    logger.info("Report written to %s", path)


def print_summary(aggregated):
    """Human-readable table — this is report output, not a log line, so it
    stays as plain print() rather than logger.info()."""
    total = sum(d["count"] for d in aggregated.values())
    print(f"Flagged {total} messages across {len(aggregated)} domains:\n")
    for domain, data in sorted(aggregated.items(), key=lambda kv: -kv[1]["count"]):
        reasons = ", ".join(data["reasons"])
        print(f"  {domain:40s} {data['count']:5d} msgs   [{reasons}]")


def run_scan(folder="INBOX", allowlist=None):
    allowlist = allowlist or set()
    logger.info("Starting scan of folder=%s (allowlist has %d entries)", folder, len(allowlist))

    raw_messages = fetch_headers(folder=folder)

    classified = classify_messages(raw_messages, allowlist)

    aggregated = aggregate_by_domain(classified)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = f"scan_report_{timestamp}.json"
    write_report(aggregated, report_path)

    print_summary(aggregated)
    logger.info("Scan complete. Full report: %s", report_path)
    return report_path
