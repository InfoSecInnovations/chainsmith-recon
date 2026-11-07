"""
app/lib/datafiles.py - Externalized check data loader.

Checks that enumerate hosts/endpoints or fire injection payloads keep that *data*
in `app/data/{wordlists,endpoints,payloads}/` rather than as Python literals, so it
can be reviewed, diffed, and adapted per engagement without editing check logic.

Two thin loaders, both **fallback-first**: each check passes its current hardcoded
list/structure as `fallback`, so a missing or unparseable file degrades to exactly
the prior behavior (Wave 2 is additive and behavior-preserving — the shipped data
files contain the same entries the fallbacks do). Config-driven path overrides
(`config.yaml: parameters.wordlist_file`) are a later wave; paths here are relative
to `app/data/` and baked into the call site.

    from app.lib.datafiles import load_wordlist, load_data

    DEFAULT_WORDLIST = load_wordlist("wordlists/subdomains.txt", _FALLBACK_WORDLIST)
    CHAT_PATHS = load_data("endpoints/chat_paths.yaml", _FALLBACK_CHAT_PATHS)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Source-controlled check data ships under app/data/ (alongside
# injection_payloads.json + the proof_templates/ the PayloadLibrary already use).
DATA_ROOT = Path(__file__).resolve().parent.parent / "data"


def load_wordlist(relpath: str, fallback: list[str]) -> list[str]:
    """Load a newline-delimited wordlist from `app/data/<relpath>`.

    One entry per line; blank lines and `#` comments are skipped. Returns
    `fallback` unchanged if the file is missing or yields no usable entries.
    """
    path = DATA_ROOT / relpath
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("Wordlist not found, using inline fallback: %s", path)
        return fallback
    entries = [ln.strip() for ln in text.splitlines()]
    entries = [e for e in entries if e and not e.startswith("#")]
    if not entries:
        logger.warning("Wordlist empty, using inline fallback: %s", path)
        return fallback
    return entries


def load_data(relpath: str, fallback: Any) -> Any:
    """Load a YAML data file from `app/data/<relpath>`.

    Returns the parsed structure (list or dict), or `fallback` unchanged if the
    file is missing, empty, or unparseable. YAML sequences of 2-item pairs
    deserialize as lists, which unpack identically to the tuples the check
    literals used (`for category, payload in ...`).
    """
    path = DATA_ROOT / relpath
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("Data file not found, using inline fallback: %s", path)
        return fallback
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        logger.warning("Data file unparseable (%s), using inline fallback: %s", e, path)
        return fallback
    if data is None:
        logger.warning("Data file empty, using inline fallback: %s", path)
        return fallback
    return data
