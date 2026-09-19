import json
import logging
import os

logger = logging.getLogger(__name__)

DEFAULT_PATH = "domain_history.json"


def load_domain_history(path=DEFAULT_PATH):
    """Every domain ever seen across prior scans, regardless of that
    scan's flag outcome — feeds classify_message's finest net (FR4.5)."""
    if not os.path.exists(path):
        logger.info("No domain history file at %s — starting with empty history.", path)
        return set()
    with open(path) as f:
        data = json.load(f)
    domains = set(data.get("domains", []))
    logger.info("Loaded domain history from %s: %d known domain(s).", path, len(domains))
    return domains


def save_domain_history(domains, path=DEFAULT_PATH):
    with open(path, "w") as f:
        json.dump({"domains": sorted(domains)}, f, indent=2)
    logger.info("Saved domain history to %s: %d known domain(s).", path, len(domains))
