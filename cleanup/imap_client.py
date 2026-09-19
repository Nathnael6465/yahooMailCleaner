import concurrent.futures
import email
import imaplib
import logging
import os
import re
import time

logger = logging.getLogger(__name__)

IMAP_HOST = "imap.mail.yahoo.com"
IMAP_PORT = 993

# Tuned empirically for this account: 5 concurrent connections is the
# fastest setting that hasn't hit Yahoo's session limit; 6+ gets an
# outright login rejection ("LOGIN Server error - Please try again later").
CONCURRENT_CONNECTIONS = 5

_UID_RE = re.compile(rb"UID (\d+)")


def connect():
    """Log in to Yahoo Mail over IMAP using an app password from env vars."""
    address = os.environ["YAHOO_EMAIL"]
    logger.debug("Connecting to %s:%s as %s", IMAP_HOST, IMAP_PORT, address)
    app_password = os.environ["YAHOO_APP_PASSWORD"]
    conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=30)
    conn.login(address, app_password)
    logger.debug("Connected and authenticated.")
    return conn


def _find_special_use_folder(conn, special_use_flag):
    """Ask the server which folder has a given SPECIAL-USE flag (RFC 6154),
    e.g. \\Trash or \\Drafts."""
    logger.debug("Looking up %s folder via LIST SPECIAL-USE...", special_use_flag)
    status, folders = conn.list(directory='""', pattern='"*"')
    if status != "OK":
        logger.error("LIST failed: %s", status)
        raise RuntimeError(f"LIST failed: {status}")
    for raw in folders:
        line = raw.decode() if isinstance(raw, bytes) else raw
        if special_use_flag in line:
            folder = line.split('"')[-2]
            logger.debug("%s folder resolved to %r", special_use_flag, folder)
            return folder
    logger.error("Could not find a %s folder via SPECIAL-USE", special_use_flag)
    raise RuntimeError(f"Could not find a {special_use_flag} folder via SPECIAL-USE")


def find_trash_folder(conn):
    return _find_special_use_folder(conn, "\\Trash")


def find_drafts_folder(conn):
    return _find_special_use_folder(conn, "\\Drafts")


def _connect_and_select(folder, delay, max_retries, label=""):
    """
    Log in and SELECT a folder, retrying with backoff on transient Yahoo
    errors — including an outright login rejection (e.g. "LOGIN Server
    error - Please try again later", seen when too many concurrent
    sessions are open at once), not just mid-command drops.
    """
    retries = 0
    while True:
        try:
            conn = connect()
            conn.select(folder)
            return conn
        except (imaplib.IMAP4.error, imaplib.IMAP4.abort, OSError) as exc:
            retries += 1
            if retries > max_retries:
                logger.error("%sGiving up on connect after %d retries: %s", label, max_retries, exc)
                raise
            wait = delay * (2 ** retries)
            logger.warning(
                "%sConnect failed (%s); retrying in %.1fs (attempt %d/%d)...",
                label, exc, wait, retries, max_retries,
            )
            time.sleep(wait)


def _fetch_uid_range(uids, folder, batch_size, delay, max_retries, label=""):
    """
    Fetch headers for one slice of UIDs over its own dedicated connection —
    batched to stay under Yahoo's per-command limits, with a delay between
    batches and automatic reconnect-and-resume if Yahoo's rate limiter
    drops the session mid-scan. Lets fetch_headers run several of these
    concurrently without sharing a single IMAP session.
    """
    conn = _connect_and_select(folder, delay, max_retries, label)

    messages = []
    total = len(uids)
    i = 0
    retries = 0
    while i < total:
        batch = uids[i:i + batch_size]
        uid_set = b",".join(batch)
        try:
            status, msg_data = conn.uid("fetch", uid_set, "(UID BODY.PEEK[HEADER])")
            if status != "OK":
                raise RuntimeError(f"UID FETCH batch failed: {status}")
        except (imaplib.IMAP4.abort, RuntimeError) as exc:
            retries += 1
            if retries > max_retries:
                logger.error("%sGiving up after %d retries at %d/%d: %s", label, max_retries, i, total, exc)
                raise
            wait = delay * (2 ** retries)
            logger.warning(
                "%sConnection dropped (%s); reconnecting in %.1fs, resuming at %d/%d (attempt %d/%d)...",
                label, exc, wait, i, total, retries, max_retries,
            )
            time.sleep(wait)
            conn = _connect_and_select(folder, delay, max_retries, label)
            continue  # retry the SAME batch on the new connection

        for item in msg_data:
            if not isinstance(item, tuple):
                continue
            info, raw_headers = item
            uid_match = _UID_RE.search(info)
            uid = uid_match.group(1).decode() if uid_match else None
            parsed = email.message_from_bytes(raw_headers)
            messages.append({
                "uid": uid,
                "from": parsed.get("From", ""),
                "subject": parsed.get("Subject", ""),
                "list_unsubscribe": parsed.get("List-Unsubscribe"),
                "list_unsubscribe_post": parsed.get("List-Unsubscribe-Post"),
                "authentication_results": parsed.get("Authentication-Results"),
            })

        i += batch_size
        retries = 0
        logger.info("%sFetched %d/%d headers...", label, min(i, total), total)
        time.sleep(delay)

    conn.logout()
    return messages


def fetch_headers(folder="INBOX", batch_size=5000, delay=0.2, max_retries=5):
    """
    Fetch headers for every message in `folder`. Splits the UID list across
    CONCURRENT_CONNECTIONS dedicated IMAP connections that each run the
    same batched-fetch-with-retry logic in parallel.
    """
    logger.info("Starting header scan of folder=%s", folder)
    conn = connect()
    status, _ = conn.select(folder)
    if status != "OK":
        logger.error("SELECT %s failed: %s", folder, status)
        raise RuntimeError(f"SELECT {folder} failed: {status}")

    status, data = conn.uid("search", None, "ALL")
    if status != "OK":
        logger.error("UID SEARCH failed: %s", status)
        raise RuntimeError(f"UID SEARCH failed: {status}")
    uids = data[0].split()
    conn.logout()
    logger.info("Found %d message(s) in %s to scan.", len(uids), folder)

    chunk_size = max(1, (len(uids) + CONCURRENT_CONNECTIONS - 1) // CONCURRENT_CONNECTIONS)
    chunks = [uids[i:i + chunk_size] for i in range(0, len(uids), chunk_size)]
    logger.info("Splitting scan across %d connection(s) (~%d messages each).", len(chunks), chunk_size)

    messages = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_CONNECTIONS) as pool:
        futures = {
            pool.submit(_fetch_uid_range, chunk, folder, batch_size, delay, max_retries, label=f"[worker {idx}] "): idx
            for idx, chunk in enumerate(chunks)
        }
        for future in concurrent.futures.as_completed(futures):
            messages.extend(future.result())

    logger.info("Header scan complete: %d message(s) fetched.", len(messages))
    return messages


def find_bounce_uids(folder="INBOX"):
    """
    Find MAILER-DAEMON delivery-failure notices sitting in the inbox — a
    side effect of failed mailto: unsubscribe attempts that Yahoo's relay
    accepted but the destination server later bounced. Matches narrowly
    on Yahoo's own bounce sender + subject to avoid catching anything else.
    """
    conn = connect()
    conn.select(folder)
    status, data = conn.uid(
        "search", None,
        "FROM", '"mailer-daemon@yahoo.com"',
        "SUBJECT", '"Failure Notice"',
    )
    conn.logout()
    if status != "OK":
        logger.error("Bounce search failed: %s", status)
        raise RuntimeError(f"Bounce search failed: {status}")
    uids = data[0].split()
    logger.info("Found %d bounce notice(s) in %s.", len(uids), folder)
    return uids


def find_stray_unsub_drafts():
    """
    Find stray "unsubscribe" drafts left behind in the Drafts folder by
    failed mailto: unsubscribe sends — another self-inflicted-junk side
    effect, observed empirically (Yahoo's relay appears to stash a copy
    there when a send fails partway through). Matches narrowly on the
    exact subject `_unsubscribe_one` sets, to avoid catching a real draft
    that happens to share that subject.

    Returns (drafts_folder, uids).
    """
    conn = connect()
    drafts_folder = find_drafts_folder(conn)
    conn.select(drafts_folder)
    status, data = conn.uid("search", None, "SUBJECT", '"unsubscribe"')
    conn.logout()
    if status != "OK":
        logger.error("Draft search failed: %s", status)
        raise RuntimeError(f"Draft search failed: {status}")
    uids = data[0].split()
    logger.info("Found %d stray unsubscribe draft(s) in %r.", len(uids), drafts_folder)
    return drafts_folder, uids


def move_to_trash(conn, uids, trash_folder, batch_size=300):
    """Move messages to Trash using IMAP MOVE (RFC 6851), batched for the
    same reason fetch_headers is — Yahoo enforces per-command limits on
    bulk IMAP operations generally, not just FETCH."""
    logger.debug("Moving %d message(s) to %r", len(uids), trash_folder)
    for i in range(0, len(uids), batch_size):
        batch = uids[i:i + batch_size]
        uid_set = b",".join(u.encode() if isinstance(u, str) else u for u in batch)
        status, response = conn.uid("MOVE", uid_set, trash_folder)
        if status != "OK":
            logger.error("UID MOVE failed: %s", response)
            raise RuntimeError(f"UID MOVE failed: {response}")
    logger.debug("Move complete.")


def purge_folder(conn, folder, batch_size=300):
    """Permanently delete every message in `folder` (e.g. Trash) —
    irreversible, unlike move_to_trash. Marks \\Deleted then EXPUNGEs."""
    logger.info("Purging folder=%s (permanent delete)", folder)
    status, _ = conn.select(folder)
    if status != "OK":
        logger.error("SELECT %s failed: %s", folder, status)
        raise RuntimeError(f"SELECT {folder} failed: {status}")

    status, data = conn.uid("search", None, "ALL")
    if status != "OK":
        logger.error("UID SEARCH failed: %s", status)
        raise RuntimeError(f"UID SEARCH failed: {status}")
    uids = data[0].split()
    logger.info("Found %d message(s) in %s to purge.", len(uids), folder)

    for i in range(0, len(uids), batch_size):
        batch = uids[i:i + batch_size]
        uid_set = b",".join(batch)
        status, response = conn.uid("STORE", uid_set, "+FLAGS", "(\\Deleted)")
        if status != "OK":
            logger.error("UID STORE failed: %s", response)
            raise RuntimeError(f"UID STORE failed: {response}")
        logger.info("Marked %d/%d for deletion...", min(i + batch_size, len(uids)), len(uids))

    conn.expunge()
    logger.info("Purge complete: %d message(s) permanently deleted.", len(uids))
    return len(uids)
