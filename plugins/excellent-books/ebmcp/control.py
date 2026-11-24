"""Signed control policy, shared replay floor, refresh and fail-closed leases."""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import random
import tempfile
import threading
import time
from typing import Optional
from urllib.parse import urlsplit

from . import config, erp, remote_catalog

SIGNED_PREFIX = b"excellent-books-control/1:"
MAX_VALIDITY = 61 * 86400
SKEW = 300
MAX_BYTES = 64 * 1024
STATE_MAX_BYTES = MAX_BYTES + 1024  # the state wraps a policy of up to MAX_BYTES
_LOCK_TIMEOUT = 5.0
_REPLACE_RETRY = 1.0  # Windows: a reader holding the state file open denies os.replace
_after_read = None  # Test subprocesses may pause here while the OS lock is held.


class ControlError(ValueError):
    """An untrusted, malformed, expired, or replayed policy."""


@dataclass(frozen=True)
class Policy:
    serial: int
    issued: datetime
    expires: datetime
    body_sha256: str
    catalogue_hashes: tuple
    stop_all: Optional[str]
    stop_writes: Optional[str]
    reports: dict
    run_names: dict
    registers: dict
    write_registers: dict
    builds_verified: tuple
    builds_pending: dict
    latest: str
    minimum: str
    download: str
    releases: dict
    stop_hosted_writes: Optional[str] = None   # hosted writing only (design 9)


@dataclass
class State:
    serial: int
    sha256: str
    body: dict
    seen_at: float


CORRUPT = object()


def canonical(body: dict) -> bytes:
    """Canonical UTF-8 bytes, excluding the signature itself."""
    return json.dumps({k: v for k, v in body.items() if k != "signature"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(body: dict, private_key, key_id: str, *, prefix: bytes = SIGNED_PREFIX) -> dict:
    """Reference signer for the knowledge repo; catalogue-compatible key_id spelling."""
    result = copy.deepcopy(body)
    signature = private_key.sign(prefix + canonical(result))
    result["signature"] = {"key_id": key_id, "value": base64.b64encode(signature).decode("ascii")}
    return result


def _check_signature(body: dict, content: bytes, *, prefix: bytes = SIGNED_PREFIX) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signature = body.get("signature")
    if (not isinstance(signature, dict) or set(signature) != {"key_id", "value"}
            or not isinstance(signature["key_id"], str)
            or signature["key_id"] not in remote_catalog.PUBLIC_KEYS):
        raise ControlError("signature: unknown signing key")
    try:
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(remote_catalog.PUBLIC_KEYS[signature["key_id"]], validate=True))
        public.verify(base64.b64decode(signature["value"], validate=True), prefix + content)
    except (InvalidSignature, ValueError, TypeError):
        raise ControlError("signature does not match the content") from None


def _keys(value, required, optional=(), closed=False):
    """Required keys must be there. Only a closed section (`stop`) refuses added keys; elsewhere
    an added key is ignored (spec section 5.1: a change of meaning is format 2 at a new URL)."""
    if (not isinstance(value, dict) or not set(required) <= value.keys()
            or (closed and not value.keys() <= set(required) | set(optional))):
        raise ControlError("unexpected or missing policy keys")


def _serial(value):
    return type(value) is int and value >= 0


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _sentence(value):
    return isinstance(value, str) and value.strip() != ""


def _sentences(value):
    if not isinstance(value, dict) or not all(isinstance(k, str) and _sentence(v)
                                              for k, v in value.items()):
        raise ControlError("expected names mapped to sentences")


def _version(value):
    return isinstance(value, str) and re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value) is not None


def _https(value):
    if not isinstance(value, str) or re.search(r"[\s\x00-\x1f\x7f]", value):
        return False
    try:
        parts = urlsplit(value)
        return parts.scheme == "https" and bool(parts.hostname)
    except ValueError:
        return False


def _time(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", value):
        raise ControlError("expected an ISO UTC time ending in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ControlError("invalid policy time") from None


def validate(body, now: datetime, floor: Optional[State]) -> Policy:
    """Verify format, signature, time bounds, replay floor, then the whole schema."""
    if not isinstance(body, dict) or type(body.get("format")) is not int or body["format"] != 1:
        raise ControlError("not control format 1")
    try:
        content = canonical(body)
        wire_size = len(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8"))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ControlError("invalid policy JSON") from None
    if wire_size > MAX_BYTES:
        raise ControlError("control file too large")
    _check_signature(body, content)

    issued, expires = _time(body.get("issued")), _time(body.get("expires"))
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ControlError("now must be timezone-aware")
    if expires <= now:
        raise ControlError("control file expired")
    if issued - now > timedelta(seconds=SKEW):
        raise ControlError("control file issued in the future")
    if expires <= issued or (expires - issued).total_seconds() > MAX_VALIDITY:
        raise ControlError("invalid control validity period")

    serial = body.get("serial")
    if not _serial(serial):
        raise ControlError("invalid serial")
    digest = hashlib.sha256(content).hexdigest()
    if floor is not None:
        if not isinstance(floor, State):
            raise ControlError("invalid control state floor")
        if serial < floor.serial:
            raise ControlError("control serial went backwards")
        if serial == floor.serial and digest != floor.sha256:
            raise ControlError("same control serial with different content")
        # A fast PC clock must not poison the floor for the rest of the signed
        # validity period. Excellent's signed issue time caps the local anchor.
        anchor = min(floor.seen_at, _time(floor.body.get("issued")).timestamp())
        if now.timestamp() < anchor - 600:
            raise ControlError("clock")

    _keys(body, {"format", "serial", "issued", "expires", "catalogue", "stop", "builds",
                 "connector", "signature"})
    catalogue, stop, builds, connector = (body[k] for k in ("catalogue", "stop", "builds", "connector"))
    _keys(catalogue, {"sha256"})
    if not isinstance(catalogue["sha256"], list) or not all(_sha(v) for v in catalogue["sha256"]):
        raise ControlError("invalid catalogue hashes")
    # `stop` stays closed: a stop this version cannot read would otherwise be half-applied.
    _keys(stop, (), {"all", "writes", "hosted_writes", "reports", "run_names", "registers",
                     "write_registers"}, closed=True)
    for key in ("all", "writes", "hosted_writes"):
        if stop.get(key) is not None and not _sentence(stop[key]):
            raise ControlError("invalid stop sentence")
    for key in ("reports", "run_names", "registers", "write_registers"):
        _sentences(stop.get(key, {}))
    _keys(builds, {"verified", "pending"})
    if not isinstance(builds["verified"], list) or not all(isinstance(v, str) for v in builds["verified"]):
        raise ControlError("invalid verified builds")
    _sentences(builds["pending"])
    for pending in builds["pending"].values():
        try:
            if date.fromisoformat(pending).isoformat() != pending:
                raise ValueError
        except ValueError:
            raise ControlError("invalid pending build date") from None
    _keys(connector, {"latest", "minimum", "download", "releases"})
    if not (_version(connector["latest"]) and _version(connector["minimum"])
            and _https(connector["download"])):
        raise ControlError("invalid connector version or download")
    if not isinstance(connector["releases"], dict):
        raise ControlError("invalid releases")
    releases = {}
    for version, release in connector["releases"].items():
        _keys(release, {"mcpb", "zip"})
        if not isinstance(version, str) or not (_sha(release["mcpb"]) and _sha(release["zip"])):
            raise ControlError("invalid release hash")
        releases[version] = {"mcpb": release["mcpb"], "zip": release["zip"]}

    return Policy(serial, issued, expires, digest, tuple(catalogue["sha256"]),
                  stop.get("all"), stop.get("writes"),
                  *(copy.deepcopy(stop.get(k, {})) for k in
                    ("reports", "run_names", "registers", "write_registers")),
                  tuple(builds["verified"]), copy.deepcopy(builds["pending"]),
                  connector["latest"], connector["minimum"], connector["download"],
                  releases, stop.get("hosted_writes"))


def _state(value):
    if not isinstance(value, dict) or set(value) != {"serial", "sha256", "body", "seen_at"}:
        return CORRUPT
    seen = value["seen_at"]
    if (not _serial(value["serial"]) or not _sha(value["sha256"])
            or not isinstance(value["body"], dict) or type(seen) not in (int, float)
            or not math.isfinite(seen) or seen < 0):
        return CORRUPT
    try:
        digest = hashlib.sha256(canonical(value["body"])).hexdigest()
    except (ValueError, TypeError, RecursionError):
        return CORRUPT
    body_serial = value["body"].get("serial")
    if digest != value["sha256"] or not _serial(body_serial) or body_serial != value["serial"]:
        return CORRUPT
    return State(**value)


def _read_state(path: Path):
    """State | None | CORRUPT. An I/O error RAISES OSError: only a file that was read and
    failed to parse or to agree with itself is CORRUPT (and may be overwritten)."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(STATE_MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(raw) > STATE_MAX_BYTES:
        return CORRUPT
    try:
        return _state(json.loads(raw))
    except (ValueError, TypeError, RecursionError, OverflowError):
        return CORRUPT


def load_state(path: Path):
    """Read only the named file, never a temporary sibling; distinguish absent and corrupt.
    An unreadable file is CORRUPT here: the caller refuses writes either way."""
    try:
        return _read_state(path)
    except OSError:
        return CORRUPT


def _take_lock(stream, *, timeout=None):
    deadline = time.monotonic() + _catch_up_timeout(_LOCK_TIMEOUT if timeout is None else timeout)
    while True:
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            left = deadline - time.monotonic()
            if left <= 0:
                raise
            time.sleep(min(0.01, left))


def _release_lock(stream):
    stream.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _replace(source, destination):
    deadline = time.monotonic() + _catch_up_timeout(_REPLACE_RETRY)
    while True:
        try:
            os.replace(source, destination)
            return
        except PermissionError:
            left = deadline - time.monotonic()
            if left <= 0:
                raise
            time.sleep(min(0.02, left))


def save_state(path: Path, state: State, keep_newer_check: bool = False) -> bool:
    """Compare and replace under one cross-process lock; a higher serial always wins.

    `keep_newer_check`: an offline retry of an older check never replaces a later check of the
    same file (same serial and hash) that another connector saved meanwhile (Sol re-check
    2026-11-17). A fresh fetch passes False: it must be able to replace a copy "checked in the
    future" by a clock that ran fast."""
    temporary = None
    try:
        path = Path(path)
        value = {"serial": state.serial, "sha256": state.sha256,
                 "body": state.body, "seen_at": state.seen_at}
        if _state(value) is CORRUPT:
            return False
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(raw) > STATE_MAX_BYTES:
            return False
        with Path(str(path) + ".lock").open("a+b") as lock:
            # Windows locks byte zero; keep a real byte even for the first writer.
            if os.fstat(lock.fileno()).st_size == 0:
                lock.write(b"\0")
                lock.flush()
            _take_lock(lock)
            try:
                # An I/O error raises here (save fails, the disk keeps its serial);
                # only a parsed-and-bad file (CORRUPT) is overwritten.
                previous = _read_state(path)
                if isinstance(previous, State) and previous.serial > state.serial:
                    return True
                if (keep_newer_check and isinstance(previous, State)
                        and previous.serial == state.serial and previous.sha256 == state.sha256
                        and previous.seen_at > state.seen_at):
                    return True
                if _after_read is not None:
                    _after_read()
                fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                _replace(temporary, path)
                temporary = None
            finally:
                _release_lock(lock)
        return True
    except Exception:
        # Persistence is fail-closed at the caller: keep its memory floor, refuse writes.
        return False
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


REFRESH = (55 * 60, 65 * 60)
RETRY = 300
WRITE_LEASE = 24 * 3600
READ_LEASE = 7 * 86400
CATCH_UP = 2 * 3600

_held: Optional[Policy] = None
_floor: Optional[State] = None
# The verified State whose save failed, kept apart from `_floor`: an offline pass may adopt the
# older disk copy of the same serial as the floor, and the retry must still save THIS one, or a
# restart loses the renewed lease (Sol re-check 2026-11-17, MED).
_unsaved: Optional[State] = None
_verified_at: Optional[float] = None
_last_attempt: Optional[float] = None
_saved = False
_last_ok = False
_lock = threading.RLock()
_refresh_thread: Optional[threading.Thread] = None
_refresh_stop = threading.Event()
_generation = 0  # bumped by forget(): a fetch started before it installs nothing
_jitter = random.uniform


def _now() -> datetime:
    """Injectable wall clock; signed expiry and persisted times are UTC."""
    return datetime.now(timezone.utc)


def _state_path() -> Path:
    folder = config.data_dir()
    if folder == config.PROJECT_ROOT:
        folder = folder / ".cache"  # Keep the replay floor from earlier ZIP and container runs.
    return folder / "control-state.json"


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ControlError("duplicate control key")
        result[key] = value
    return result


def _adopt_disk(path: Path, now: datetime) -> None:
    """Adopt another connector's higher floor, including its stops and lease age.

    A failed save never erases our newer memory floor. A stale or expired disk
    policy still supplies the replay floor, but cannot grant a lease.
    """
    global _floor, _held, _verified_at, _saved
    disk = load_state(path)
    if disk is CORRUPT:
        _saved = False
        return
    if disk is None or (_floor is not None and disk.serial < _floor.serial):
        return
    if _floor is not None and disk.serial == _floor.serial and disk.sha256 != _floor.sha256:
        _saved = False
        return
    newer = _floor is None or disk.serial > _floor.serial
    try:
        accepted = validate(disk.body, now, disk)
    except ControlError:
        if _floor is None or disk.serial > _floor.serial:
            _floor = disk
            _held, _verified_at, _saved = None, None, False
        return
    # The very copy already held as the floor grants nothing new: a lease withheld from it
    # (below) stays withheld when it is read again after the clock has passed its time.
    same = _floor is not None and disk.sha256 == _floor.sha256 and disk.seen_at == _floor.seen_at
    _floor = disk
    if same:
        if _held is None:
            _held = accepted  # its stops, no lease
    elif _verified_at is None or accepted.serial > (_held.serial if _held else -1) or disk.seen_at > _verified_at:
        # A check "verified in the future" (a PC clock that ran fast, review M1) grants no
        # lease: keep its floor and stops, and refuse until the next fetch succeeds.
        future = disk.seen_at > now.timestamp() + 600
        _held, _verified_at = accepted, None if future else disk.seen_at
    # A disk read is not a successful save of the renewed lease. In particular,
    # rereading our old copy must not lift a failed-save refusal (M6).
    _saved = _saved or newer


def _save_floor(path: Path, now: datetime, retry: bool = False) -> None:
    """Persist the memory floor (caller holds _lock); `_saved` says whether it is on disk.

    An unsaved verified candidate of the floor's serial or higher is saved instead of the
    floor; one below the floor is obsolete (another connector saved a higher serial), and so is
    one of the same file checked EARLIER than the floor (another connector saved a later check:
    overwriting it would shorten the lease after a restart, Sol re-check 2026-11-17). `retry`:
    an offline pass, whose save also keeps a later same-file check found on disk under the lock."""
    global _saved, _unsaved
    if _unsaved is not None and _floor is not None and (
            _unsaved.serial < _floor.serial
            or (_unsaved.serial == _floor.serial and _unsaved.sha256 == _floor.sha256
                and _unsaved.seen_at < _floor.seen_at)):
        _unsaved = None
    target = _unsaved if _unsaved is not None else _floor
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _saved = save_state(path, target, True) if retry else save_state(path, target)
    except OSError:
        _saved = False
    if not _saved:
        _unsaved = target
    else:
        _unsaved = None
        # save_state may have kept a higher serial written by another process
        # between our read and its lock acquisition. Adopt it before granting.
        _adopt_disk(path, now)


def load(timeout: float = 5.0, _stop: Optional[threading.Event] = None) -> None:
    """Read the shared floor, then fetch once. A failed fetch keeps accepted stops.

    Seeing the same signed file again renews the transport lease only until its
    signed expiry (the accepted replay window, review M7). Failure to persist a
    newer serial keeps that floor in memory and refuses writes (review M6); the
    save is retried on every later pass, fetched or not (review S1).

    The network fetch runs outside `_lock`, so the gates never wait for it (review S5);
    a `forget()` while it runs discards its result.
    """
    global _held, _floor, _verified_at, _last_attempt, _saved, _last_ok, _unsaved
    with _lock:
        if _stop is not None and _stop.is_set():
            return
        generation = _generation
        path = _state_path()
        _adopt_disk(path, _now())
        _last_attempt, _last_ok = _now().timestamp(), False
    try:
        raw = remote_catalog._get(config.control_url(), timeout, max_bytes=MAX_BYTES,
                                  total_timeout=timeout, what="the control file")
        body = json.loads(raw, object_pairs_hook=_unique_pairs)
    except Exception:
        body = None
    with _lock:
        if generation != _generation:
            return
        now = _now()
        try:
            if body is None:
                raise ControlError("the control file could not be fetched")
            accepted = validate(body, now, _floor)
        except Exception:
            # A held floor whose save failed (a newly seen stop) is saved now, even offline,
            # so an offline restart after this pass still meets it (review S1).
            if (not _saved and _floor is not None and _held is not None
                    and _held.body_sha256 == _floor.sha256):
                _save_floor(path, now, retry=True)
            return
        _held, _verified_at = accepted, now.timestamp()
        _floor = _unsaved = State(accepted.serial, accepted.body_sha256, body, _verified_at)
        _save_floor(path, now)
        _last_ok = _saved


def start_refresh() -> threading.Thread:
    """One daemon worker per process; failures retry in five minutes."""
    global _refresh_thread
    with _lock:
        if _refresh_thread is not None and _refresh_thread.is_alive():
            return _refresh_thread
        stopped = _refresh_stop

        def one_pass():
            global _last_ok
            try:
                load(_stop=stopped)
            except Exception:
                # Never let one bad pass end the worker (review S2): ask again in RETRY.
                with _lock:
                    _last_ok = False

        def refresh():
            with _lock:
                if stopped.is_set():
                    return
                first = _last_attempt is None
            if first:
                one_pass()
            while not stopped.wait(_jitter(*REFRESH) if _last_ok else RETRY):
                one_pass()

        _refresh_thread = threading.Thread(target=refresh, name="refresh-control", daemon=True)
        _refresh_thread.start()
        return _refresh_thread


def _catch_up_timeout(timeout: float) -> float:
    try:
        if budget := erp.desktop_write_budget.get():
            return budget.request_timeout(timeout, read_grace=True)
        return erp.desktop_read_timeout(timeout)
    except TimeoutError:
        return 0.0


def _catch_up() -> None:
    with _lock:
        if _last_attempt is None:
            return
        age = _now().timestamp() - _last_attempt
    if age >= CATCH_UP or age < -600:
        if timeout := _catch_up_timeout(5.0):
            load(timeout=timeout)


def policy() -> Optional[Policy]:
    _catch_up()
    with _lock:
        return _held


BOOKS_SERVER = "your Excellent Books server"


def _unavailable() -> dict:
    # The two addresses the connector reaches (plan Review Focus 5); the server names the
    # configured Books server's host in place of BOOKS_SERVER when it knows it.
    return {"error": "control_unavailable", "why":
            "Cannot confirm that this connector is still allowed to use Books. Check this "
            "computer's internet connection, and that it may reach knowledge.excellent.ee and "
            "%s." % BOOKS_SERVER}


def _gate(lease: int) -> Optional[dict]:
    if _held is None:
        return _unavailable()
    # A held stop refuses whatever the lease says, and says so in its own words.
    if _held.stop_all is not None:
        return {"error": "stopped", "why": _held.stop_all}
    if _verified_at is None:
        return _unavailable()
    now = _now().timestamp()
    # A clock set back more than ten minutes before the last verification (or before
    # Excellent signed the file) cannot keep a lease alive (review M1).
    if (now >= _held.expires.timestamp() or now - _verified_at >= lease
            or now < _verified_at - 600 or now < _held.issued.timestamp() - 600):
        return _unavailable()
    return None


def may_read() -> Optional[dict]:
    _catch_up()
    with _lock:
        return _gate(READ_LEASE)


def may_write(hosted: bool = False, fetch: bool = True) -> Optional[dict]:
    """`hosted`: the hosted connector asks, and `stop.hosted_writes` stops it too. Local and
    Desktop read that key and ignore it (hosted writing design, section 9). `fetch=False`: the
    held policy only, no catch-up fetch, for a caller holding a lock of its own (hosted
    `ConnectionPlans`; Sol re-check of a90dac7)."""
    if fetch:
        _catch_up()
    with _lock:
        refused = _gate(WRITE_LEASE)
        if refused is not None and refused["error"] == "stopped":
            return refused
        if _held is not None and _held.stop_writes is not None:
            return {"error": "stopped", "why": _held.stop_writes}
        if hosted and _held is not None and _held.stop_hosted_writes is not None:
            return {"error": "stopped", "why": _held.stop_hosted_writes}
        if refused is not None:
            return refused
        if not _saved:
            return _unavailable()
        return None


def catalogue_allowed(sha256: str) -> bool:
    _catch_up()
    with _lock:
        return _gate(READ_LEASE) is None and sha256 in _held.catalogue_hashes


# -- enforcement: what the connector's tools and its ERP session ask (Task 18) -------------------

class Stopped(erp.NotSent):
    """A control refusal raised by `guard` before any HTTP; `refusal` is the tool answer."""

    def __init__(self, refusal: dict):
        super().__init__(refusal.get("why") or refusal.get("error"))
        self.refusal = refusal


def _held_now() -> Optional[Policy]:
    """The held policy without a catch-up fetch: for the per-entry stops, which the knowledge
    repo's tools also reach (through reports.gate) without any policy."""
    with _lock:
        return _held


def _stop(why: str, **where) -> dict:
    return dict({"error": "stopped", "why": why}, **where)


def report_refusal(doc: dict) -> Optional[dict]:
    """A held stop on this report: everything, its id, or any run name it executes (folded,
    like the do-not-run names). None without a policy: the leases are checked elsewhere."""
    held = _held_now()
    if held is None:
        return None
    report_id = doc.get("id")
    if held.stop_all is not None:
        return _stop(held.stop_all, id=report_id)
    ids = {remote_catalog.fold(k): v for k, v in held.reports.items()}
    if report_id is not None and remote_catalog.fold(report_id) in ids:
        return _stop(ids[remote_catalog.fold(report_id)], id=report_id)
    names = {remote_catalog.fold(k): v for k, v in held.run_names.items()}
    for name in sorted(remote_catalog.run_names(doc)):
        if remote_catalog.fold(name) in names:
            return _stop(names[remote_catalog.fold(name)], id=report_id)
    return None


def register_refusal(register, write: bool = False) -> Optional[dict]:
    """A held stop on reading (or, `write`, on writing) this register. A write also obeys a
    reading stop: every plan reads the register it writes."""
    held = _held_now()
    if held is None:
        return None
    if held.stop_all is not None:
        return _stop(held.stop_all, register=str(register))
    key = remote_catalog.fold(register)
    tables = [held.write_registers, held.registers] if write else [held.registers]
    for table in tables:
        folded = {remote_catalog.fold(k): v for k, v in table.items()}
        if key in folded:
            return _stop(folded[key], register=str(register))
    if write and held.stop_writes is not None:
        return _stop(held.stop_writes, register=str(register))
    return None


def build_status(version) -> tuple:
    """("verified", None), ("pending", "YYYY-MM-DD") or ("unlisted", None) for a Books build."""
    held = _held_now()
    if held is not None and version in held.builds_verified:
        return "verified", None
    if held is not None and version in held.builds_pending:
        return "pending", held.builds_pending[version]
    return "unlisted", None


def _version_tuple(version) -> tuple:
    try:
        return tuple(int(part) for part in str(version).split("."))
    except ValueError:
        return (0,)


UPDATE_REQUIRED = ("This Excellent Books connector (version %s) is older than the oldest version "
                   "Excellent still allows (%s). Download the current connector at %s and install "
                   "it. Nothing was sent to Books.")
UPDATE_AVAILABLE = "A newer Excellent Books connector is available at %s."


def version_refusal(version) -> Optional[dict]:
    """Below the policy's minimum every tool refuses, with the download address. Reads the held
    policy without `_lock` (one attribute read), so a tool may ask it on the event loop."""
    held = _held
    if held is None or _version_tuple(version) >= _version_tuple(held.minimum):
        return None
    return {"error": "update_required",
            "why": UPDATE_REQUIRED % (version, held.minimum, held.download)}


_notice_lock = threading.Lock()
_notice_day = None


def version_notice(version) -> Optional[str]:
    """Below the policy's latest: one line, the first time a day. Reads the held policy without
    `_lock`, because results are finished on the event loop (review S5)."""
    global _notice_day
    held = _held
    if held is None or _version_tuple(version) >= _version_tuple(held.latest):
        return None
    today = _now().date()
    with _notice_lock:
        if _notice_day == today:
            return None
        _notice_day = today
    return UPDATE_AVAILABLE % held.download


def guard(method: str, url: str, api_base: Optional[str] = None, login: bool = False,
          hosted: bool = False) -> None:
    """Called by erp.Session right before every socket (login, each attempt, each redirect hop).
    Raises Stopped. `hosted`: a hosted connection's session, whose writes obey
    `stop.hosted_writes` too (`hosted_guard`).

    A read needs `may_read`; a POST/PATCH outside WebExcellentAPI is a write and needs
    `may_write`. The register (erp.rest_register: the first segment after `api_base`) must not be
    stopped for reading, or for writing on a write. The login read alone is exempt from the
    register stops: it reads one CUVc code. The session has already refused any WebExcellentAPI
    call that is not an allowlisted read."""
    from . import __version__
    path = urlsplit(url).path
    write = str(method).upper() not in ("GET", "HEAD") and "webexcellentapi" not in path.casefold()
    # The lease first: its catch-up fetch may install a policy with a higher minimum.
    lease = may_write(hosted=hosted) if write else may_read()
    refused = version_refusal(__version__) or lease
    register = erp.rest_register(url, api_base) if api_base else None
    if refused is None and register and not (login and not write):
        refused = register_refusal(register, write=write)
    if refused is not None:
        raise Stopped(refused)


def hosted_guard(method: str, url: str, api_base: Optional[str] = None,
                 login: bool = False) -> None:
    """`guard` for a hosted connection's session (erp.HostedSession.sign_in): a hosted stop that
    arrives after the last check before a write (a record change reads the record again first)
    still stops it right before the socket (Sol review of 9c12e6c, MUST-FIX 1)."""
    guard(method, url, api_base, login, hosted=True)


def report_dispatch(doc: dict) -> Optional[dict]:
    """Asked right before a report goes to Books: the version, then the report's own stops."""
    from . import __version__
    return version_refusal(__version__) or report_refusal(doc)


def use(policy: Policy) -> None:
    """Hold an already validated policy (tests)."""
    global _held, _floor, _verified_at, _last_attempt, _saved, _last_ok, _unsaved
    with _lock:
        _held, _floor, _unsaved = policy, None, None
        _verified_at = _last_attempt = _now().timestamp()
        _saved = _last_ok = True


def forget() -> None:
    """Drop process state and stop its refresh worker (tests)."""
    global _held, _floor, _verified_at, _last_attempt, _saved, _last_ok, _unsaved
    global _refresh_thread, _refresh_stop, _generation, _notice_day
    _refresh_stop.set()
    with _notice_lock:
        _notice_day = None
    with _lock:
        _generation += 1
        _held = _floor = _unsaved = _verified_at = _last_attempt = None
        _saved = _last_ok = False
        _refresh_thread = None
        _refresh_stop = threading.Event()
