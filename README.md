# Yahoo Mail Cleaner

A free, self-owned CLI tool to bulk-clean a Yahoo Mail inbox: classify
junk via a **default-deny allowlist model**, unsubscribe in bulk (RFC 8058
one-click where supported), and move flagged messages to Trash — all
over plain IMAP with an app password, no paid API, no OAuth review
process.

## How classification works

Most spam filters work by cataloging what junk looks like (bad auth,
gibberish addresses, marketing keywords) — but that's an arms race,
since evasion techniques mutate faster than any pattern list can keep
up. This tool flips that: **a message is only treated as legitimate if
its domain is explicitly trusted** (your own `allowlist.txt`, or the
~150 major companies baked into `KNOWN_BRAND_DOMAINS` in
`cleanup/classify.py`, or a `.gov` domain — a restricted TLD only real
government entities can register). Everything else is flagged by
default. A few narrower checks (auth failure, gibberish local-parts,
padding-evasion tricks like `"· · · · JoinAARP · · · ·"`, suspicious
TLDs) still run, but only to give a more specific reason in the
report — they no longer gate the flag/no-flag decision.

## Setup

**Requirements:** Python 3.9+, a Yahoo Mail account.

1. **Clone and enter the repo:**
   ```
   git clone <this-repo-url>
   cd yahooMailCleaner
   ```

2. **Create a virtual environment and install dependencies:**
   ```
   python3 -m venv .venv
   source .venv/bin/activate      # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Generate a Yahoo app password** (do NOT use your real account
   password — this tool never needs it and you shouldn't type it into
   any script):
   - Go to [Yahoo Account Security](https://login.yahoo.com/account/security)
   - Under "App passwords," generate one, name it something like
     `mail-cleaner`
   - Copy the generated password — you won't see it again

4. **Set your credentials as environment variables** (never commit
   these, never hardcode them):
   ```
   export YAHOO_EMAIL="you@yahoo.com"
   export YAHOO_APP_PASSWORD="the-app-password-from-step-3"
   ```
   To avoid retyping this every session, add those two lines to your
   shell profile (`~/.zshrc`, `~/.bashrc`), or use a `.env` file with a
   tool like `direnv` — just make sure it's gitignored (it already is
   here).

5. **Set up your allowlist** — copy the template and add domains/
   addresses you trust:
   ```
   cp allowlist.example.txt allowlist.txt
   ```
   Anything **not** in `allowlist.txt` (or the built-in
   `KNOWN_BRAND_DOMAINS`, or `.gov`) will be flagged by default, so
   populate this with your bank, employer, subscriptions, and anyone
   else you actually want mail from before running `execute`.

6. **Run the tests** to confirm everything's working (no IMAP
   connection needed — these are pure unit tests):
   ```
   python -m pytest tests/ -q
   ```

## Usage

**Always run `scan` first and review the output before running
anything destructive.** `scan` is read-only.

```
python main.py scan
```

This fetches headers for every message in your inbox, classifies
them, and writes a timestamped `scan_report_<timestamp>.json` plus a
human-readable summary printed to the terminal. Open the report and
skim it — if something you actually want shows up flagged, add its
domain to `allowlist.txt` and re-run `scan`.

Once you trust the report, act on it:

```
python main.py execute --report scan_report_<timestamp>.json --yes
```

This unsubscribes from flagged senders where possible and moves
flagged messages to **Trash** (not permanently deleted — recoverable
within Yahoo's Trash retention window). `--yes` is required; omitting
it refuses to run.

To do both steps back-to-back without a manual review pause (only
recommended once you trust your allowlist):

```
python main.py clean --yes
```

To permanently empty Trash (irreversible — only run this after
you've confirmed nothing important got swept up):

```
python main.py empty-trash --yes
```

### Options

- `--folder` (default `INBOX`) — which IMAP folder to scan
- `--allowlist` (default `allowlist.txt`) — path to your allowlist file

## Project layout

```
cleanup/
  imap_client.py    # IMAP connection, concurrent header fetch, move-to-trash
  headers.py        # Pure header-parsing functions (List-Unsubscribe, auth results, MIME decoding)
  classify.py        # The default-deny classifier — start here to understand the logic
  domain_history.py # Legacy domain-tracking helper, used only by the one-off triage script below
  report.py          # Classifies a scan, writes scan_report_*.json
  actioner.py        # Reads a report, unsubscribes + moves to Trash
main.py               # CLI entrypoint
tests/                 # Unit tests for classify.py and headers.py (no IMAP needed)
allowlist.example.txt # Template — copy to allowlist.txt and edit
build_allowlist_candidates.py  # One-off tool to help bootstrap your allowlist from scan history
diagnose_flags.py               # One-off read-only diagnostic: prints per-message classification detail
```

## Notes

- Yahoo appears to cap concurrent IMAP sessions around 5-6 for a
  single account; `CONCURRENT_CONNECTIONS` in `cleanup/imap_client.py`
  is set conservatively at 5. If you hit
  `[UNAVAILABLE] LOGIN Server error`, lower it.
- This project deliberately avoids Yahoo's OAuth2 mail scope, which
  requires a reviewed partner application — not appropriate for a
  personal script. Plain IMAP app-password auth only.
