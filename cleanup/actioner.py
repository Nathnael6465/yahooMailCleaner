import concurrent.futures
import imaplib
import json
import logging
import os
import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

import requests

from cleanup.imap_client import (
    connect,
    find_bounce_uids,
    find_stray_unsub_drafts,
    find_trash_folder,
    move_to_trash,
    purge_folder,
)

logger = logging.getLogger(__name__)

UNSUBSCRIBE_WORKERS = 50
MOVE_MAX_RETRIES = 4
PROGRESS_WRITE_EVERY = 25
# Same ceiling empirically found safe for this account's IMAP session limit
# during scan tuning (6+ simultaneous sessions gets a hard login rejection).
MOVE_CONCURRENT_CONNECTIONS = 5


def _unsubscribe_one(message, my_email):
    """
    Priority order per FR7.1: one-click POST, then plain GET, then mailto.
    Never raises — a failed unsubscribe must not block deleting the message.
    Returns (attempted, succeeded, detail).
    """
    link = message.get("list_unsubscribe", {})
    http_url = link.get("http")
    mailto = link.get("mailto")
    sender = message.get("sender", "?")

    if http_url:
        try:
            if message.get("one_click"):
                resp = requests.post(http_url, data={"List-Unsubscribe": "One-Click"}, timeout=10)
            else:
                resp = requests.get(http_url, timeout=10)
            if resp.status_code < 400:
                logger.debug("Unsubscribe OK (http %s) for %s", resp.status_code, sender)
                return True, True, f"http {resp.status_code}"
            if not mailto:
                logger.debug("Unsubscribe failed (http %s) for %s", resp.status_code, sender)
                return True, False, f"http {resp.status_code}"
        except requests.RequestException as exc:
            if not mailto:
                logger.debug("Unsubscribe failed (http error: %s) for %s", exc, sender)
                return True, False, f"http error: {exc}"

    if mailto:
        try:
            msg = MIMEText("Please unsubscribe me from this mailing list.")
            msg["Subject"] = "unsubscribe"
            msg["From"] = my_email
            msg["To"] = mailto
            msg["Date"] = formatdate(localtime=True)
            msg["Message-ID"] = make_msgid()
            with smtplib.SMTP_SSL("smtp.mail.yahoo.com", 465, timeout=10) as smtp:
                smtp.login(my_email, os.environ["YAHOO_APP_PASSWORD"])
                smtp.send_message(msg)
            logger.debug("Unsubscribe OK (mailto sent) for %s", sender)
            return True, True, "mailto sent"
        except Exception as exc:
            logger.debug("Unsubscribe failed (mailto error: %s: %s) for %s", type(exc).__name__, exc, sender)
            return True, False, f"mailto error: {type(exc).__name__}: {exc}"

    logger.debug("No unsubscribe link for %s", sender)
    return False, False, "no unsubscribe link"


def _move_with_retries(conn, uids, trash_folder, folder="INBOX", label=""):
    """FR13: bounded retry with backoff, replacing the old one-shot retry
    that could itself fail uncaught."""
    for attempt in range(1, MOVE_MAX_RETRIES + 1):
        try:
            move_to_trash(conn, uids, trash_folder)
            return conn
        except (imaplib.IMAP4.abort, RuntimeError, TimeoutError, ConnectionError) as exc:
            if attempt == MOVE_MAX_RETRIES:
                logger.error("%sGiving up moving %d message(s) after %d retries: %s", label, len(uids), MOVE_MAX_RETRIES, exc)
                raise
            wait = 2 ** attempt
            logger.warning(
                "%sConnection dropped (%s); retry %d/%d in %ds...",
                label, exc, attempt, MOVE_MAX_RETRIES, wait,
            )
            time.sleep(wait)
            conn = connect()
            conn.select(folder)
    return conn


def _load_progress(progress_path):
    """Load progress, migrating the old domain-only schema (moved and
    unsubscribed tracked as one combined 'completed_domains' flag) into the
    new schema that tracks them independently, since moves no longer wait
    on that domain's unsubscribe attempts to finish."""
    if not os.path.exists(progress_path):
        logger.info("No existing progress file — starting fresh at %s.", progress_path)
        return {"moved_domains": [], "unsubscribed_uids": [], "action_log": []}

    with open(progress_path) as f:
        progress = json.load(f)

    if "moved_domains" not in progress:
        old_completed = progress.get("completed_domains", [])
        action_log = progress.get("action_log", [])
        progress = {
            "moved_domains": sorted(old_completed),
            "unsubscribed_uids": sorted({entry["uid"] for entry in action_log}),
            "action_log": action_log,
        }
        logger.info(
            "Migrated older progress file: %d domain(s) already moved, %d message(s) already unsubscribed.",
            len(progress["moved_domains"]), len(progress["unsubscribed_uids"]),
        )
    else:
        logger.info(
            "Resuming from %s: %d domain(s) moved, %d message(s) already unsubscribed.",
            progress_path, len(progress["moved_domains"]), len(progress["unsubscribed_uids"]),
        )
    return progress


def _sweep_move_uids(uids, folder, sweep_name):
    """Move a flat list of UIDs (already found by a caller-specific search)
    from `folder` to Trash, across up to MOVE_CONCURRENT_CONNECTIONS. Shared
    by the bounce and stray-draft sweeps — both are "find junk this script
    itself caused, move it to Trash" with the same concurrency shape as
    the main pipeline's moves."""
    if not uids:
        logger.info("No %s to clean up.", sweep_name)
        return 0

    lookup_conn = connect()
    lookup_conn.select(folder)
    trash_folder = find_trash_folder(lookup_conn)
    lookup_conn.logout()

    n_workers = min(MOVE_CONCURRENT_CONNECTIONS, len(uids)) or 1
    chunks = [uids[i::n_workers] for i in range(n_workers)]
    logger.info("Sweeping %d %s across %d connection(s)...", len(uids), sweep_name, n_workers)

    def _worker(chunk, label):
        if not chunk:
            return
        conn = connect()
        conn.select(folder)
        _move_with_retries(conn, chunk, trash_folder, folder=folder, label=label)
        conn.logout()

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [pool.submit(_worker, chunk, f"[{sweep_name} {i}] ") for i, chunk in enumerate(chunks)]
        for f in futures:
            f.result()

    logger.info("%s sweep complete: %d message(s) moved to Trash.", sweep_name.capitalize(), len(uids))
    return len(uids)


def _sweep_bounces(folder="INBOX"):
    """Move MAILER-DAEMON delivery-failure notices to Trash — self-
    inflicted junk from failed mailto: unsubscribe attempts, not part of
    the scan report, so this is a live search rather than progress-tracked."""
    return _sweep_move_uids(find_bounce_uids(folder), folder, "bounce notices")


def _sweep_stray_drafts():
    """Move stray 'unsubscribe' drafts to Trash — another self-inflicted-
    junk side effect of failed mailto sends (see find_stray_unsub_drafts)."""
    drafts_folder, uids = find_stray_unsub_drafts()
    return _sweep_move_uids(uids, drafts_folder, "stray unsubscribe drafts")


def run_execute(report_path, confirm=False):
    """
    Reads a scan report and acts on exactly what's in it — never
    re-classifies live. Refuses to run unless confirm=True (NFR1).

    Unsubscribe attempts for every not-yet-done message across the whole
    report run in one global thread pool (FR10), since they're independent
    network calls with no relation to which domain they belong to. IMAP
    moves stay sequential on a single connection (imaplib isn't thread-
    safe) and proceed domain-by-domain without waiting on that domain's
    unsubscribe results — deletion never depended on unsubscribe success,
    so there's no reason moves should be blocked by it either.

    Resumable (FR11/FR12): "moved" and "unsubscribed" are tracked
    independently, and progress is persisted incrementally, not only at
    the end.
    """
    if not confirm:
        logger.error("run_execute called without confirm=True — refusing (NFR1 safety gate).")
        raise RuntimeError(
            "Refusing to run without confirm=True — this is the deliberate "
            "safety gate from NFR1. Re-run with confirm=True once you've "
            "reviewed the scan report."
        )

    with open(report_path) as f:
        report = json.load(f)
    logger.info("Loaded report %s: %d domain(s).", report_path, len(report))

    progress_path = f"progress_{os.path.basename(report_path)}"
    progress = _load_progress(progress_path)
    moved_domains = set(progress["moved_domains"])
    unsubscribed_uids = set(progress["unsubscribed_uids"])
    my_email = os.environ["YAHOO_EMAIL"]
    progress_lock = threading.Lock()

    def _save_progress():
        # Caller must hold progress_lock.
        progress["moved_domains"] = sorted(moved_domains)
        progress["unsubscribed_uids"] = sorted(unsubscribed_uids)
        with open(progress_path, "w") as f:
            json.dump(progress, f, indent=2)

    pending = [
        (domain, message)
        for domain, data in report.items()
        for message in data["messages"]
        if message["uid"] not in unsubscribed_uids
    ]
    domains_to_move = [domain for domain in report if domain not in moved_domains]
    logger.info("Submitting %d message(s) to the unsubscribe pool (up to %d concurrent)...", len(pending), UNSUBSCRIBE_WORKERS)

    logger.info("Looking up Trash folder...")
    lookup_conn = connect()
    lookup_conn.select("INBOX")
    trash_folder = find_trash_folder(lookup_conn)
    lookup_conn.logout()
    logger.info("Trash folder resolved to %r.", trash_folder)

    n_move_workers = min(MOVE_CONCURRENT_CONNECTIONS, len(domains_to_move)) or 1
    move_chunks = [domains_to_move[i::n_move_workers] for i in range(n_move_workers)]
    logger.info("Moving %d domain(s) across %d IMAP connection(s)...", len(domains_to_move), n_move_workers)

    total_moved_this_run = 0
    succeeded_so_far = 0

    def _move_worker(domain_chunk, label):
        nonlocal total_moved_this_run
        if not domain_chunk:
            return
        conn = connect()
        conn.select("INBOX")
        total_domains = len(report)
        for domain in domain_chunk:
            domain_uids = [m["uid"] for m in report[domain]["messages"]]
            conn = _move_with_retries(conn, domain_uids, trash_folder, label=label)
            with progress_lock:
                moved_domains.add(domain)
                total_moved_this_run += len(domain_uids)
                moved_count = len(moved_domains)
                _save_progress()
            logger.info(
                "%sMoved %s: %d message(s) to Trash. (%d/%d domains done)",
                label, domain, len(domain_uids), moved_count, total_domains,
            )
        conn.logout()

    def _drain_done_unsub_futures(futures):
        nonlocal succeeded_so_far
        with progress_lock:
            done = [f for f in futures if f.done()]
            for f in done:
                d, message = futures.pop(f)
                attempted, succeeded, detail = f.result()
                if succeeded:
                    succeeded_so_far += 1
                progress["action_log"].append({
                    "domain": d,
                    "uid": message["uid"],
                    "sender": message["sender"],
                    "unsubscribe_attempted": attempted,
                    "unsubscribe_succeeded": succeeded,
                    "unsubscribe_detail": detail,
                })
                unsubscribed_uids.add(message["uid"])
            if done:
                _save_progress()
        return len(done)

    with concurrent.futures.ThreadPoolExecutor(max_workers=UNSUBSCRIBE_WORKERS) as unsub_pool, \
         concurrent.futures.ThreadPoolExecutor(max_workers=n_move_workers) as move_pool:

        unsub_futures = {
            unsub_pool.submit(_unsubscribe_one, message, my_email): (domain, message)
            for domain, message in pending
        }
        total_pending = len(unsub_futures)

        move_futures = [
            move_pool.submit(_move_worker, chunk, f"[mover {i}] ")
            for i, chunk in enumerate(move_chunks)
        ]

        # Both pools run fully concurrently now — moves across up to 5 IMAP
        # connections, unsubscribes across the unsub pool. The main thread
        # just waits on moves while periodically draining unsub results for
        # live, interleaved progress visibility.
        pending_moves = set(move_futures)
        while pending_moves:
            done, pending_moves = concurrent.futures.wait(pending_moves, timeout=3)
            newly_done = _drain_done_unsub_futures(unsub_futures)
            if newly_done:
                logger.info(
                    "Unsubscribe progress: %d/%d done (%d succeeded so far)...",
                    len(unsubscribed_uids), total_pending, succeeded_so_far,
                )
        for f in move_futures:
            f.result()  # surface any exception from a move worker

        logger.info("All moves done. Draining remaining unsubscribe results...")

        for count, future in enumerate(concurrent.futures.as_completed(list(unsub_futures)), start=1):
            with progress_lock:
                d, message = unsub_futures.pop(future)
                attempted, succeeded, detail = future.result()
                if succeeded:
                    succeeded_so_far += 1
                progress["action_log"].append({
                    "domain": d,
                    "uid": message["uid"],
                    "sender": message["sender"],
                    "unsubscribe_attempted": attempted,
                    "unsubscribe_succeeded": succeeded,
                    "unsubscribe_detail": detail,
                })
                unsubscribed_uids.add(message["uid"])
                if count % PROGRESS_WRITE_EVERY == 0 or count == total_pending:
                    _save_progress()
            if count % PROGRESS_WRITE_EVERY == 0 or count == total_pending:
                logger.info(
                    "Unsubscribe progress: %d/%d done (%d succeeded so far)...",
                    len(unsubscribed_uids), total_pending, succeeded_so_far,
                )

    with progress_lock:
        _save_progress()

    _sweep_bounces()
    _sweep_stray_drafts()

    succeeded_count = sum(1 for r in progress["action_log"] if r["unsubscribe_succeeded"])
    logger.info("Unsubscribe pool done: %d/%d succeeded (cumulative).", succeeded_count, len(progress["action_log"]))
    logger.info("Moved %d message(s) this run.", total_moved_this_run)
    logger.info("%d/%d domains moved overall.", len(moved_domains), len(report))
    logger.info("Progress/action log: %s", progress_path)
    return progress_path


def run_empty_trash(confirm=False):
    logger.info("Connecting to check Trash...")
    conn = connect()
    trash_folder = find_trash_folder(conn)
    conn.select(trash_folder)
    status, data = conn.uid("search", None, "ALL")
    count = len(data[0].split())
    logger.info("Trash (%r) contains %d message(s).", trash_folder, count)

    if not confirm:
        logger.warning("Refusing to permanently delete without --yes.")
        conn.logout()
        return count

    logger.info("Confirmed — permanently purging Trash...")
    purge_folder(conn, trash_folder)
    conn.logout()
    logger.info("Permanently deleted %d message(s) from Trash.", count)
    return count
