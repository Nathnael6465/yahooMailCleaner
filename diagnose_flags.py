"""
One-off diagnostic — NOT part of the maintained pipeline. Prints per-message
classification detail (flag, single reason, and the raw signals behind it).
Safe/read-only: only calls fetch_headers (no moves, no unsubscribes).
"""
import logging

logging.basicConfig(level=logging.WARNING)  # quiet — we just want the printed sample

from cleanup.imap_client import fetch_headers
from cleanup.report import classify_messages

raw = fetch_headers(folder="INBOX")
classified = classify_messages(raw, allowlist=set())

print(f"\n{'sender':40s} {'flag':5s} {'display_name':30s} {'subject':40s} reasons")
print("-" * 150)
for item in classified[:60]:
    print(f"{item['sender'][:40]:40s} {str(item['flagged']):5s} {item['display_name'][:30]:30s} {item['subject'][:40]:40s} {item['reasons']}")

flagged_count = sum(1 for item in classified if item["flagged"])
print(f"\n{flagged_count}/{len(classified)} flagged in this sample.")
