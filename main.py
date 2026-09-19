import argparse
import logging
import os
import sys
from cleanup.actioner import run_execute

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def _load_allowlist(path):
    if not path or not os.path.exists(path):
        logger.info("No allowlist file at %s — proceeding with an empty allowlist.", path)
        return set()
    with open(path) as f:
        entries = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
    logger.info("Loaded %d allowlist entries from %s", len(entries), path)
    return entries


def cmd_scan(args):
    from cleanup.report import run_scan
    logger.info("Starting scan (folder=%s, allowlist=%s)", args.folder, args.allowlist)
    allowlist = _load_allowlist(args.allowlist)
    run_scan(folder=args.folder, allowlist=allowlist)
    logger.info("Scan finished.")


def cmd_execute(args):
    if not args.yes:
        logger.warning("Refusing to run: execute requires --yes as an explicit confirmation.")
        logger.info("Review %s first, then re-run with --yes.", args.report)
        sys.exit(1)
    logger.info("Starting execute against report=%s", args.report)
    run_execute(args.report, confirm=True)
    logger.info("Execute finished.")


def cmd_clean(args):
    if not args.yes:
        logger.warning("Refusing to run: clean requires --yes — this skips the scan-report review step and goes straight to execute.")
        sys.exit(1)
    from cleanup.report import run_scan
    from cleanup.actioner import run_execute
    logger.info("Starting full pipeline: scan -> execute (folder=%s, allowlist=%s)", args.folder, args.allowlist)
    allowlist = _load_allowlist(args.allowlist)
    report_path = run_scan(folder=args.folder, allowlist=allowlist)
    run_execute(report_path, confirm=True)
    logger.info("Clean finished.")


def cmd_empty_trash(args):
    from cleanup.actioner import run_empty_trash
    logger.info("Checking Trash (confirm=%s)", args.yes)
    run_empty_trash(confirm=args.yes)
    logger.info("Empty-trash finished.")


def main():
    parser = argparse.ArgumentParser(description="Yahoo Mail cleanup tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Read-only: scan the inbox and write a report")
    scan_parser.add_argument("--folder", default="INBOX")
    scan_parser.add_argument("--allowlist", default="allowlist.txt")
    scan_parser.set_defaults(func=cmd_scan)

    execute_parser = subparsers.add_parser("execute", help="Act on a scan report: unsubscribe + delete")
    execute_parser.add_argument("--report", required=True, help="Path to a scan_report_*.json file")
    execute_parser.add_argument("--yes", action="store_true", help="Required to confirm destructive action")
    execute_parser.set_defaults(func=cmd_execute)

    clean_parser = subparsers.add_parser("clean", help="Full pipeline: scan then execute (move + unsubscribe) in one command")
    clean_parser.add_argument("--folder", default="INBOX")
    clean_parser.add_argument("--allowlist", default="allowlist.txt")
    clean_parser.add_argument("--yes", action="store_true", help="Required to confirm — skips the scan-report review step")
    clean_parser.set_defaults(func=cmd_clean)

    empty_trash_parser = subparsers.add_parser("empty-trash", help="Permanently delete everything in Trash")
    empty_trash_parser.add_argument("--yes", action="store_true", help="Required to confirm permanent deletion")
    empty_trash_parser.set_defaults(func=cmd_empty_trash)

    args = parser.parse_args()
    logger.info("Command: %s", args.command)
    args.func(args)


if __name__ == "__main__":
    main()
