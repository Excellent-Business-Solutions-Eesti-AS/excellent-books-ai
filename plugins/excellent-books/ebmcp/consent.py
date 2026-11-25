"""Store consent dates and text hashes by kind and Books connection."""

from datetime import date
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

from . import config, control, page_texts, privacy


def consent_text(copy, kind):
    """The exact text a consent page shows; its sha256 is what consent.record keeps."""
    if kind == "hr":
        points = " ".join("%d. %s: %s" % (n, copy["consent_hr_%d_head" % n],
                                          copy["consent_hr_%d_body" % n]) for n in range(1, 5))
        return copy["consent_hr_intro"] + " " + points
    return copy["consent_gdpr_text"]


def _digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


PLUGIN_LANGUAGES = ("en", "et")


def plugin_gdpr_texts() -> dict:
    """The plugin's GDPR text per settings-page language (the Estonian approved by Kaupo 2026-11-24)."""
    return {language: privacy.gdpr_text("plugin", language) for language in PLUGIN_LANGUAGES}


def plugin_text_language(digest) -> str | None:
    """The settings-page language whose plugin GDPR text has this hash, else None: a yes records
    exactly the wording that page drew."""
    if not isinstance(digest, str):
        return None
    for language, text in plugin_gdpr_texts().items():
        if secrets.compare_digest(_digest(text), digest):
            return language
    return None


def current_hashes(kind: str) -> frozenset[str]:
    """Every current wording for this decision, across the setup and page languages. The plugin's
    GDPR decision is its own text only (design 2026-11-23, Review change 6): the Desktop and ZIP
    texts name another AI service."""
    try:
        plugin = config.mode() == "plugin"
    except config.ConfigError:
        plugin = False
    if plugin and kind == "gdpr":
        return frozenset(_digest(text) for text in plugin_gdpr_texts().values())
    original = {"gdpr": privacy.GDPR_TEXT, "hr": privacy.HR_CONSENT_TEXT}.get(kind)
    if original is None:
        return frozenset()
    return frozenset([_digest(original), *(_digest(consent_text(copy, kind))
                                           for copy in page_texts.TEXTS.values())])


def page_digest(copy, kind) -> str:
    """The hash of the text a consent page draws from `copy`; the page's form carries it."""
    return _digest(consent_text(copy, kind))


def page_language(kind: str, digest: str) -> str | None:
    """The page language whose text for this decision has this hash, when that text is current;
    else None. A consent form names the text it drew, so a yes records exactly that wording
    (Sol review of 14fbad6, MUST-FIX)."""
    if not isinstance(digest, str) or digest not in current_hashes(kind):
        return None
    for language, copy in page_texts.TEXTS.items():
        if secrets.compare_digest(page_digest(copy, kind), digest):
            return language
    return None


def _store() -> Path:
    """The consent store. The plugin keeps its own file even when EBMCP_DATA_DIR points Desktop
    and the plugin at one folder: a Desktop HR yes is never a plugin HR yes (Astra review of
    slice 2, SHOULD 3)."""
    name = "consent-plugin.json" if config.mode() == "plugin" else "consent.json"
    return config.data_dir() / name


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_bytes())
    except (FileNotFoundError, ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def _entries(data: dict, kind: str) -> dict:
    entries = data.get(kind)
    return entries if isinstance(entries, dict) else {}


def _accepted(entry) -> bool:
    """A well-formed acceptance that has not been withdrawn."""
    if not isinstance(entry, dict) or "withdrawn" in entry:
        return False
    day, digest = entry.get("date"), entry.get("sha256")
    if not isinstance(day, str) or not isinstance(digest, str):
        return False
    try:
        return date.fromisoformat(day).isoformat() == day and bool(re.fullmatch("[0-9a-f]{64}", digest))
    except ValueError:
        return False


def status(kind: str, connection_id: str) -> str:
    """Read the decision once: "none" (never decided here), "off" (withdrawn, unreadable or
    malformed), "stale" (accepted an older wording) or "given"."""
    # "none" only when the store PROVES there is no decision: the file or this connection's key is
    # absent. A file that cannot be read or parsed, or a malformed entry, may have held a
    # withdrawal, so it is "off" and never a first consent (Sol re-check of 284f2c8).
    try:
        raw = _store().read_bytes()
    except FileNotFoundError:
        return "none"
    except (OSError, config.ConfigError):
        return "off"
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return "off"
    if not isinstance(data, dict):
        return "off"
    entries = data.get(kind, {})
    if not isinstance(entries, dict):
        return "off"
    if connection_id not in entries:
        # A store that replaced a damaged one cannot prove "never decided" (Sol review of 28b20b2).
        return "off" if data.get("lost") else "none"
    entry = entries[connection_id]
    if not _accepted(entry):
        return "off"
    return "given" if entry["sha256"] in current_hashes(kind) else "stale"


def given(kind: str, connection_id: str) -> bool:
    return status(kind, connection_id) == "given"


def stale(kind: str, connection_id: str) -> bool:
    return status(kind, connection_id) == "stale"


def _save(path: Path, data: dict) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".consent-",
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write((json.dumps(data, sort_keys=True) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        control._replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _evidence(row: dict) -> dict:
    """Only dates and the text hash are kept as history, whatever an old file held."""
    return {key: row[key] for key in ("date", "sha256", "withdrawn") if isinstance(row.get(key), str)}


def _damaged(raw: bytes) -> bool:
    try:
        return not isinstance(json.loads(raw), dict)
    except (ValueError, RecursionError):
        return True


def _update(kind: str, connection_id: str, entry: dict | None) -> bool:
    """True when this call wrote the store."""
    path = _store()
    if entry is None and not path.exists():
        return False
    # The folder may not exist yet (a fresh install; found by a real Edge click, 2026-11-18).
    path.parent.mkdir(parents=True, exist_ok=True)
    # The per-user folder can be shared by multiple connector processes.
    with path.with_suffix(".lock").open("a+b") as lock:
        if os.fstat(lock.fileno()).st_size == 0:
            lock.write(b"\0")
            lock.flush()
        control._take_lock(lock)
        try:
            data = _read(path)
            if not data and entry is not None and path.exists():
                raw = path.read_bytes()
                if _damaged(raw):
                    # A click replaces a store nobody can read (a withdrawal writes nothing to
                    # it: it has nothing to withdraw). What it held (a withdrawal, say)
                    # is unknown: keep the bytes aside and mark the new store, so no connection
                    # in it counts as "never decided" (Sol review of 28b20b2, MUST-FIX 2).
                    aside = path.with_name("%s.corrupt-%s-%s" % (
                        path.name, date.today().isoformat(), secrets.token_hex(4)))
                    aside.write_bytes(raw)
                    data = {"lost": date.today().isoformat()}
            entries = _entries(data, kind)
            old = entries.get(connection_id)
            if entry is None:
                # A withdrawal is DATED, never a deletion: the acceptance it ends stays as the
                # evidence that consent existed while data was read (Task 26 review S3).
                if not _accepted(old):
                    return False
                entries[connection_id] = dict(old, withdrawn=date.today().isoformat())
            else:
                if _accepted(old) and old["sha256"] in current_hashes(kind):
                    return False
                if isinstance(old, dict):
                    history = old.get("history") if isinstance(old.get("history"), list) else []
                    rows = [_evidence(row) for row in history + [old] if isinstance(row, dict)]
                    entry = dict(entry, history=[row for row in rows if row])
                entries[connection_id] = entry
            data[kind] = entries
            _save(path, data)
            return True
        finally:
            control._release_lock(lock)


def record(kind: str, connection_id: str, text: str) -> None:
    """Keep the first acceptance while its wording remains current and consent is active."""
    entry = {"date": date.today().isoformat(), "sha256": _digest(text)}
    _update(kind, connection_id, entry)


def withdraw(kind: str, connection_id: str) -> bool:
    """True when an acceptance was withdrawn (written); False when there was none to withdraw.
    Raises when the store cannot be read or written."""
    return _update(kind, connection_id, None)


def snapshot(kind: str, connection_id: str):
    """This connection's stored entry as it is (None when there is none), for restore()."""
    entry = _entries(_read(_store()), kind).get(connection_id)
    return json.loads(json.dumps(entry)) if entry is not None else None


def restore(kind: str, connection_id: str, previous) -> None:
    """Put back the entry snapshot() returned, after a record() whose purpose failed (the plugin's
    Save could not write its settings): the record is left as it was, never turned into a
    withdrawal (Kaia's review of PR #4). Raises when the store cannot be read or written."""
    path = _store()
    if previous is None and not path.exists():
        return
    with path.with_suffix(".lock").open("a+b") as lock:
        if os.fstat(lock.fileno()).st_size == 0:
            lock.write(b"\0")
            lock.flush()
        control._take_lock(lock)
        try:
            data = _read(path)
            entries = _entries(data, kind)
            if previous is None:
                entries.pop(connection_id, None)
            else:
                entries[connection_id] = previous
            data[kind] = entries
            _save(path, data)
        finally:
            control._release_lock(lock)
