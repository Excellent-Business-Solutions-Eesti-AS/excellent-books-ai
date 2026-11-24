"""Local, counts-only JSON lines for MCP tool usage."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import threading

from . import audit, config

FIELDS = ("at", "tool", "outcome", "seconds", "version", "build", "client", "actor")
_MAX_TEXT = 128
# Kaupo 2026-11-19 (45f review N5): hosted usage lines are kept as long as the write trail.
RETENTION_DAYS = audit.RETENTION_DAYS
_lock = threading.Lock()
_writer: ThreadPoolExecutor | None = None
_writer_lock = threading.Lock()


def _background() -> ThreadPoolExecutor:
    global _writer
    with _writer_lock:
        if _writer is None:
            # One worker keeps the lines in order; its thread is joined at interpreter exit, so
            # a queued line is still written on a normal shutdown.
            _writer = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ebmcp-usage")
        return _writer


def hosted_plan(state: str) -> None:
    """Count a hosted plan transition without including plan or connection details.

    The callers hold the plan store's lock (an expiry is found under it) or run on the event loop
    (the approve route, `state()` polled by a waiting apply_approved): the line is built here
    and written on a worker thread, never by the caller (opus review of 45f, N1)."""
    record_later("hosted_plan_" + state)


def record_later(tool: str, **facts) -> None:
    """Build the line now and append it on the usage worker. Hosted tool calls run on the event
    loop, and the daily prune holds `_lock` across reads, rewrites, fsync and replace: a direct
    append would stall every answer behind it (Sol review 2026-11-20, A). An EBMCP_USAGE_LOG path
    is read now (no disk work); the data folder is found on the worker, because `config.data_dir`
    can create folders (Sol re-check 2026-11-20, SHOULD 4). Never raises."""
    try:
        named = os.environ.get("EBMCP_USAGE_LOG")
        entry = _entry(tool, facts)
        _background().submit(_write_found, named, entry)
    except Exception:
        pass


def _write_found(named, entry: dict) -> None:
    """On the worker: stamp the line now, so the log's times follow its order (one worker keeps
    the submission order; a caller paused after stamping could put a newer time ahead of an older
    one, Sol re-check of abed9f9, NIT). The time is the write time, normally the same second."""
    try:
        _write(Path(named) if named else _folder_path(), _encode(entry))
    except Exception:
        pass


def flush(timeout: float | None = None) -> bool:
    """Wait until every queued usage line is written (tests, and the hosted shutdown, which gives
    it what is left of the drain window). False when `timeout` seconds pass first."""
    try:
        _background().submit(lambda: None).result(timeout)
    except TimeoutError:
        return False
    return True


def _short_scalar(value) -> bool:
    if type(value) is str:
        return len(value) <= _MAX_TEXT
    if type(value) is int:
        return value.bit_length() <= 64
    if type(value) is float:
        return math.isfinite(value)
    return type(value) is bool


def _path() -> Path:
    """Use the explicit log path or data folder, with the container log beside its OAuth DB."""
    named = os.environ.get("EBMCP_USAGE_LOG")
    if named:
        return Path(named)
    return _folder_path()


def _folder_path() -> Path:
    folder = config.data_dir()
    return (audit._oauth_log_dir(folder) or folder) / "usage.log"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _entry(tool: str, facts: dict) -> dict:
    """Every field but the time, which `_encode` adds."""
    facts = dict(facts, tool=tool)
    facts.pop("at", None)
    if "actor" in facts and config.mode() != "hosted":
        del facts["actor"]
    return {field: facts[field] for field in FIELDS if _short_scalar(facts.get(field))}


def _encode(entry: dict) -> bytes:
    at = _now().isoformat(timespec="seconds").replace("+00:00", "Z")
    return (json.dumps({"at": at, **entry}) + "\n").encode("utf-8")


def _line(tool: str, facts: dict) -> bytes:
    return _encode(_entry(tool, facts))


def _write(path: Path, line: bytes) -> None:
    try:
        with _lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            audit._rotate(path, len(line))
            with path.open("ab") as handle:
                handle.write(line)
    except Exception:
        pass


def record(tool: str, **facts) -> None:
    """Append one event. A usage log failure never affects a tool result."""
    try:
        _write(_path(), _line(tool, facts))
    except Exception:
        pass


def prune(now: datetime) -> int:
    """Remove hosted usage lines older than RETENTION_DAYS, backups included (hosted.py runs it at
    start and daily). Never in local or Desktop mode: there the usage log is the customer's own."""
    try:
        if config.mode() == "hosted":
            cutoff = now - timedelta(days=RETENTION_DAYS)
            with _lock:
                return audit.prune_files(_path(), cutoff)
    except (OSError, config.ConfigError):
        pass
    return 0
