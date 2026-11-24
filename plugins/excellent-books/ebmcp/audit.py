"""The audit trail for everything this server writes.

`CLAUDE.md` asks for two things that pull against each other: *audit every call*, and *never row
data in logs*. A goods receipt's lines are the customer's business data, so a log detailed enough
to reconstruct the delivery is a copy of their data sitting in a file — which is the thing this
product's whole pitch says it does not do.

The resolution is an **allowlist**. A record is assembled from `FIELDS` and nothing else, so a
field added to a tool's result later cannot reach the log by default. A denylist would be one
release behind the code it guards, every time.

What that buys, concretely: the log can answer *when, by which tool, against which register,
which document number resulted, how many lines, did it work, and how long did it take*. It cannot
answer *what was in the delivery* — for that, read the document in Books, which is where the
customer's data belongs.

Best-effort records stay silent on failure because Books may already have changed. Hosted writes
also require a durable begin line before dispatch.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import datetime
import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Optional

from . import config

_logger = logging.getLogger(__name__)

MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 3
RETENTION_DAYS = 90

# The whole control. Every one of these is a count, an identifier, a timing or an outcome —
# never a name, a description, a price or a quantity per item. Adding to this list is a decision
# to record more about a customer, and `tests/test_audit.py` makes somebody mean it.
FIELDS = (
    "tool",        # which tool ran
    "outcome",     # ok | refused | failed
    "reason",      # why it was refused, as OUR short code, never the ERP's wording
    "actor",       # who, when the server knows; absent when running open
    "register",    # which register was written
    "document",    # the resulting document number — the audit trail's anchor
    "lines",       # how many rows, not what they were
    "created",     # how many records a create tool made
    "updated",     # how many existing records a tool changed
    # "vendor" WAS here, recording the contact code on the reasoning that a code is not
    # personal data. Measured 2026-09-16 on the reference demo: 5 of 3,913 numeric contact
    # codes are 11 digits beginning 1-6 — isikukood-shaped, because private-person contacts
    # are commonly coded by their personal ID. So the counterparty's CODE can BE the personal
    # data. Removed rather than hashed: `document` already anchors the trail, and anyone
    # investigating opens that receipt in Books, where the vendor is on the document. Logging
    # the code added nothing the document did not, and could log an isikukood.
    "location",    # the stock location code
    "stock_moved", # whether the measured delta was non-zero
    "ms",          # how long it took
    "approved",    # True when a person approved the exact write (an `Approved` object existed)
    "approval",    # the first 8 characters of the approval id: links the line to the approval page
    "wait_s",      # seconds between the preview and the click
    "via",         # how the hosted browser gained approval authority
    "stage",       # begin | end for a hosted write
    "operation",   # the approved envelope's operation: create | update | approve | batch
)


class Unavailable(Exception):
    """A required audit line could not be written."""


def _oauth_log_dir(folder: Path) -> Optional[Path]:
    if folder != config.PROJECT_ROOT:
        return None
    hosted_db = (os.environ.get("EBMCP_HOSTED_OAUTH_DB", "").strip()
                 if config.mode() == "hosted" else "")
    oauth_db = hosted_db or os.environ.get("OAUTH_DB_PATH")
    return Path(oauth_db).parent if oauth_db else None


def _default_path() -> Path:
    """Use the runtime data folder, with the existing audit and OAuth path overrides."""
    named = os.environ.get("EBMCP_AUDIT_LOG")
    if named:
        return Path(named)
    folder = config.data_dir()
    return (_oauth_log_dir(folder) or folder / "out") / "audit.log"


def _numbered(path: Path, number: int) -> Path:
    return path.with_name("%s.%d" % (path.name, number))


def _shift(path: Path) -> bool:
    """.2 -> .3, then .1 -> .2 (the oldest backup is dropped). Stops at the first move that
    fails, so no backup is ever overwritten by a younger one (Sol re-check of 135795a). True when
    .1 is free for the file set aside. When .1 is already free (an earlier shift finished and only
    the final move failed) nothing is shifted again: that would drop a backup one rotation early."""
    if not _numbered(path, 1).exists():
        return True
    for number in range(BACKUP_COUNT, 1, -1):
        older = _numbered(path, number - 1)
        if not older.exists():
            continue
        try:
            older.replace(_numbered(path, number))
        except OSError:
            return False
    return not _numbered(path, 1).exists()


def _rotate(path: Path, incoming_bytes: int) -> None:
    """Past MAX_BYTES: audit.log -> .1 -> .2 -> .3 (the current file plus BACKUP_COUNT backups).

    The current file is moved ASIDE first. When that fails (Windows: another process holds it
    open), nothing has moved and the caller appends to the oversized file: an audit line is never
    lost and no backup is shifted for a rotation that did not happen (Task 24 review S1). A
    rotation interrupted after the move (a backup held open) is finished by the next write; until
    then the fresh audit.log takes the lines. One process writes the log (an in-process lock)."""
    aside = path.with_name(path.name + ".rotating")
    if aside.exists():
        if not _shift(path):
            return
        try:
            aside.replace(_numbered(path, 1))
        except OSError:
            return
    try:
        current_bytes = path.stat().st_size
    except OSError:
        return
    if not current_bytes or current_bytes + incoming_bytes <= MAX_BYTES:
        return
    try:
        path.replace(aside)
    except OSError:
        return
    if _shift(path):
        try:
            aside.replace(_numbered(path, 1))
        except OSError:
            pass


class AuditLog:
    """Rotating JSON lines. One line per write, written under a lock."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path if self._path is not None else _default_path()

    def write(self, tool: str, **facts) -> None:
        """Record one event, silently on failure."""
        try:
            self._append(tool, facts, durable=False)
        except Exception:
            pass

    def _append(self, tool: str, facts: dict, *, durable: bool) -> None:
        record = {"at": datetime.datetime.now(datetime.timezone.utc)
                              .isoformat(timespec="seconds").replace("+00:00", "Z"),
                  "tool": str(tool)}
        for field in FIELDS:
            if field == "tool" or field not in facts:
                continue
            value = facts[field]
            if value is None:
                continue
            record[field] = value if isinstance(value, (str, int, float, bool)) else str(value)
        from . import privacy
        record = privacy.mask_private_keys(record)[0]
        line = (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode("utf-8")
        with self._lock:
            path = self.path
            path.parent.mkdir(parents=True, exist_ok=True)
            _rotate(path, len(line))
            created = not path.exists()
            with path.open("ab") as handle:
                if handle.write(line) != len(line):
                    raise OSError("Incomplete audit line")
                if durable:
                    handle.flush()
                    os.fsync(handle.fileno())
            if durable and created:
                # A new file's name lives in its folder: without this a power cut can lose the
                # whole file, begin line included (opus review of 45f, N4).
                _fsync_dir(path.parent)

    def _prune(self, cutoff: datetime.datetime) -> int:
        with self._lock:
            return prune_files(self.path, cutoff)


def prune_files(path: Path, cutoff: datetime.datetime) -> int:
    """Remove lines dated before `cutoff` from a rotated log: the file, its backups and a file
    set aside by an interrupted rotation. The caller holds the lock its writer uses. Shared by the
    audit trail and usage.py (Kaupo 2026-11-19: both keep 90 days)."""
    paths = [path, *(_numbered(path, n) for n in range(1, BACKUP_COUNT + 1)),
             path.with_name(path.name + ".rotating")]
    return sum(_prune_file(candidate, cutoff) for candidate in paths)


def _fsync_dir(folder: Path) -> None:
    """Make a folder's entries durable. Windows cannot open a folder for fsync; NTFS journals
    its metadata, so there is nothing to do there."""
    if os.name == "nt":
        return
    descriptor = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _dated_before(line: bytes, cutoff: datetime.datetime) -> bool:
    try:
        return datetime.datetime.fromisoformat(json.loads(line)["at"]) < cutoff
    except (ValueError, TypeError, KeyError):
        # Leave damaged or undated lines available for inspection.
        return False


def _prune_file(path: Path, cutoff: datetime.datetime) -> int:
    temporary = path.with_name(path.name + ".pruning")
    try:
        temporary.unlink(missing_ok=True)  # Clear a rewrite interrupted by a restart.
        try:
            lines = path.read_bytes().splitlines(keepends=True)
        except FileNotFoundError:
            # A backup that does not exist yet: nothing to clean. Only this read is quiet; a file
            # lost during the rewrite is warned about below (Sol re-check 2026-11-20, NIT).
            return 0
        keep =[line for line in lines if not _dated_before(line, cutoff)]
        removed = len(lines) - len(keep)
        if removed:
            mode = path.stat().st_mode & 0o777
            try:
                with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                               "wb") as handle:
                    handle.writelines(keep)
                    handle.flush()
                    # Synced before the rename, and the file's own mode kept, not 0600 (opus
                    # review of 45f, N3).
                    os.fsync(handle.fileno())
                if os.name != "nt":
                    os.chmod(temporary, mode)
                temporary.replace(path)
                # The rename lives in the folder: sync it, or a power cut can bring the old lines
                # back (Sol review 2026-11-20, A). The lines are already gone from the file.
                try:
                    _fsync_dir(path.parent)
                except OSError as exc:
                    _logger.warning("Log cleanup of %s could not sync its folder (%s).",
                                    path.name, type(exc).__name__)
            finally:
                temporary.unlink(missing_ok=True)
        return removed
    except OSError as exc:
        # Operators see the skip; the file name and error type only, never a line (Sol review
        # 2026-11-20, A: a failed rewrite was silent while the text promised deletion).
        _logger.warning("Log cleanup skipped %s (%s); its old lines stay until the next run.",
                        path.name, type(exc).__name__)
        return 0


_log: Optional[AuditLog] = None


def log() -> AuditLog:
    """The process-wide log, created on first use so importing this module touches no disk."""
    global _log
    if _log is None:
        _log = AuditLog()
    return _log


def approval_facts(approved) -> dict:
    """The three approval fields for an executor's audit call: `**audit.approval_facts(approved)`.

    The id is the 8 characters after the `ap_` prefix: enough to match a line to the approval
    (Sol review 2026-11-17: `ap_` + 5 collides too easily), too short to stand in for it. Never
    raises; an object without `approval_id`/`waited_s` adds nothing.
    """
    try:
        return {"approved": True, "approval": str(approved.approval_id).removeprefix("ap_")[:8],
                "wait_s": round(max(float(approved.waited_s), 0.0), 1)}
    except Exception:
        return {}


def record(tool: str, **facts) -> None:
    captured = _executor_facts.get()
    if captured is not None:
        # Hosted executors report into their end line. Keep only fixed outcomes, counts and
        # a verified serial number. The local audit also accepts register-specific details.
        outcome = facts.get("outcome")
        if outcome in ("ok", "failed", "refused", "unverified", "stopped"):
            captured["outcome"] = outcome
        for key in ("created", "updated", "lines", "ms", "stock_moved"):
            if type(facts.get(key)) in (int, bool):
                captured[key] = facts[key]
        reason = facts.get("reason")
        # Our own short codes only ("not_found_after_create", "http_503"): a sentence could
        # quote Books, so it is dropped (opus review of 45f, N2).
        if isinstance(reason, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason):
            captured["reason"] = reason
        number = facts.get("document")
        if isinstance(number, str) and re.fullmatch(r"[0-9]+", number):
            captured["document"] = number
        return
    log().write(tool, **facts)


_executor_facts: ContextVar[dict | None] = ContextVar("executor_audit_facts", default=None)


@contextmanager
def capture_executor():
    facts = {"outcome": "unverified"}
    token = _executor_facts.set(facts)
    try:
        yield facts
    finally:
        _executor_facts.reset(token)


def require(tool: str, **facts) -> None:
    try:
        log()._append(tool, facts, durable=True)
    except Exception:
        raise Unavailable("The write audit is unavailable.") from None


def prune(now: datetime.datetime) -> int:
    """Remove hosted audit lines older than the retention window, including backups."""
    try:
        if config.mode() == "hosted":
            cutoff = now - datetime.timedelta(days=RETENTION_DAYS)
            return log()._prune(cutoff)
    except (OSError, config.ConfigError):
        pass
    return 0
