"""The report fields the customer's OWN ERP declares — checked before any spec is sent.

An unknown report spec field restarts the ERP: hansa.log "Field name not found in
F4FieldNumber", then a restart (measured 2026-09-14 and 2026-09-30). The catalogue's fields
were read from the demo's build, and a customer on another build can lack one. Since 2026-10-04
run_report also sends the client's window defaults on its own, so a field nobody asked for could
restart a customer's server (project review 2026-10-04, its biggest risk).

Kaupo, 2026-10-04: fetch the customer's own `getreportfilters` the first time a Books version is
seen, keep it on disk, and send only the fields that window declares there. The endpoint reads
only productwindows.hal (correction 16), so the windows the catalogue filled from the Books
source (`spec_source: books-window`) are not in it: their fields were probed on the demo's build,
and they are allowed on that build only (Kaupo, 04.10: the Intrastat Declaration's Inside EU box
is one of them).

`allowed(session, doc)` is a set of field names, or None: cannot tell. None means no default
is sent, and since 05.10 a caller's own fields are refused too (`reports.unverified`).
"""
from __future__ import annotations

import json
import os
import re
import time
from hashlib import sha256
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from weakref import WeakKeyDictionary

from . import config

# The demo's build when the Books-window fields were probed on :4455 (2026-10-02); the same
# systemversion is recorded on 2026-09-30 and 2026-10-02 (docs/corrections-for-other-repos.md).
# Review 2026-11-17 (opus, Task 4 MUST-FIX): this is the build an entry WITHOUT `verified_builds` was
# checked on, so it stays 1369 until the catalogue lists 1370 per entry (plan Task 17 step 3). Raising it
# would send 1369-checked fields to a 1370 server unchecked; an unknown field can restart Books.
PROBED_VERSION = "8.5.56.1369"

# On the customer's own computer, next to the connector; never shipped (make_package copies
# named folders only). Field names and window classes only, nothing from the customer's data.
CACHE_DIR: Optional[Path] = None

FETCH_TIMEOUT = 30.0
# A failed read is not repeated on every report, nor remembered for good: the defaults are off
# while it fails, and a report can answer differently without them.
RETRY_AFTER = 300.0
# The background retry gets the full FETCH_TIMEOUT (Task 22 gate, opus C SF1): a shorter one
# fails whenever Books needs 20-30 s, and then the list is never read again. It runs in the single
# ERP turn (server._schedule_field_retry), so a person's next call in the same chat can wait up to
# this long behind it, once per RETRY_AFTER at most.
RETRY_TIMEOUT = FETCH_TIMEOUT
_TIMED_OUT = object()

_memory: dict = {}          # (server, version) -> (windows or None, when, background only)
_hosted_memory = WeakKeyDictionary()  # per-session failures and lists without a known build
_hosted_success: dict[tuple[str, str], dict] = {}


def forget() -> None:
    """Drop what this process remembers (tests; a restarted connector starts this way)."""
    _memory.clear()
    _hosted_memory.clear()
    _hosted_success.clear()


def _memory_for(session, local_memory, hosted_memory):
    """Each hosted session belongs to one grant. Its discovery state expires with it."""
    if config.mode() == "hosted":
        return hosted_memory.setdefault(session, {})
    return local_memory


def _shared_key(session, version) -> tuple[str, str] | None:
    origin = getattr(getattr(session, "cfg", None), "origin", None)
    return (origin, version) if origin and version else None


def windows_from(payload) -> dict:
    """{window_class: sorted field names} of every window the endpoint lists WITH fields. A
    window listed twice gets the fields of both copies: the endpoint reads both sides of an
    if/else, and either side is a field the window has."""
    out: dict = {}
    reports = payload.get("reports") if isinstance(payload, dict) else None
    for report in reports or []:
        names = {f.get("field") for f in report.get("filters") or [] if f.get("field")}
        if names and report.get("window_class"):
            out.setdefault(report["window_class"], set()).update(names)
    return {wc: sorted(names) for wc, names in out.items()}


def _cache_file(server: str, version: str) -> Path:
    folder = CACHE_DIR if CACHE_DIR is not None else config.data_dir() / ".cache" / "report-fields"
    prefix = sha256(server.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9.]+", "-", version).strip("-")
    return folder / f"{prefix}-{slug}.json"


def _read_disk(path: Path) -> Optional[dict]:
    try:
        windows = json.loads(path.read_text(encoding="utf-8")).get("windows")
    except (OSError, ValueError, AttributeError):
        return None
    return windows if isinstance(windows, dict) and windows else None


def _write_disk(path: Path, version: str, windows: dict) -> None:
    """Whole or not at all: two connectors on one PC must not leave half a file (review 04.10)."""
    if config.mode() == "hosted":
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        part = path.with_suffix(".%d.part" % os.getpid())
        part.write_text(json.dumps({"version": version, "fetched": time.strftime("%Y-%m-%d %H:%M"),
                                    "windows": windows}, indent=0), encoding="utf-8")
        os.replace(part, path)
    except OSError:         # a read-only install still has the copy in memory
        try:
            part.unlink()
        except (OSError, NameError):
            pass


def _raise_a_stop(exc: Exception) -> None:
    """A stop from the signed control file is answered as itself, never as a list that could
    not be read (review 2026-11-18). Imported here: control imports erp, not this module."""
    from . import control, erp
    # The REST-API-off login refusal is answered as itself too (Task 22 gate round 2, Sol SHOULD),
    # and so is a hosted session that ended: "sign in again", never a list that could not be read
    # (Task 42).
    if isinstance(exc, (control.Stopped, erp.RestApiNotAllowed, erp.SignInAgain)):
        raise exc


def _is_timeout(exc: Exception) -> bool:
    return isinstance(exc, TimeoutError) or (
        isinstance(exc, URLError) and isinstance(exc.reason, TimeoutError))


def _use_cached(memory, key, session, read, retry, retry_after) -> bool:
    """Honor each failure's backoff. Local timeouts use the background retry when installed.
    Hosted failures use the foreground, inside the origin's gate."""
    cached = memory.get(key)
    if cached is None:
        return False
    value, when, background_only = cached
    now = time.time()
    if not background_only:
        return value is not None or now - when < retry_after
    if retry:
        return False
    schedule = getattr(session, "schedule_field_retry", None)
    if schedule is not None and now - when >= retry_after:
        # Stay unavailable to callers and give only the queued worker this attempt.
        queued = memory[key] = (None, now, True)

        def work(live):
            if memory.get(key) is queued:
                read(live, retry=True)

        schedule(session, work)
    return True


def _fetch(session, timeout):
    try:
        response = session.sub_action("getreportfilters", timeout=timeout)
        if getattr(response, "status", 200) != 200:
            return None
        return windows_from(response.json()) or None
    except Exception as exc:  # an older build without the endpoint, a timeout, a body that is not JSON
        _raise_a_stop(exc)
        return _TIMED_OUT if _is_timeout(exc) else None


def customer_windows(session, *, retry=False) -> Optional[dict]:
    """The customer's {window_class: field names}, or None when they cannot be read."""
    if not hasattr(session, "sub_action"):
        return None
    memory = _memory_for(session, _memory, _hosted_memory)
    local = memory is _memory
    # The version comes back on the login read (erp.Session.login); log in first if no call has
    # been made yet, or a restarted connector would fetch before it could look at its disk copy.
    server = str(getattr(getattr(session, "cfg", None), "api_base", "") or "")
    if getattr(session, "system_version", None) is None and getattr(session, "cookie", "") is None \
            and hasattr(session, "login"):
        # A login that failed is not tried again on every report while the ERP is down: the
        # report call itself still logs in and says what failed (re-review 04.10, N3).
        failed = memory.get((server, "login failed"))
        if failed and time.time() - failed[1] < RETRY_AFTER:
            return None
        try:
            session.login()
        except Exception as exc:
            _raise_a_stop(exc)
            memory[(server, "login failed")] = (None, time.time(), False)
            return None
    version = getattr(session, "system_version", None)
    key = (server, version)
    if _use_cached(memory, key, session, customer_windows, retry, RETRY_AFTER):
        return memory[key][0]
    shared_key = _shared_key(session, version) if not local else None
    if key not in memory and shared_key in _hosted_success:
        return _hosted_success[shared_key]
    windows = _read_disk(_cache_file(server, version)) if version and local else None
    if windows is None:
        windows = _fetch(session, RETRY_TIMEOUT if retry else FETCH_TIMEOUT)
        # A re-login inside the fetch can reveal a new build: the list is that build's (N5).
        version = getattr(session, "system_version", None) or version
        key = (server, version)
        if windows and windows is not _TIMED_OUT and version and local:
            _write_disk(_cache_file(server, version), version, windows)
    timed_out = windows is _TIMED_OUT
    if timed_out:
        windows = None
    shared_key = _shared_key(session, version) if not local else None
    if shared_key is not None and windows is not None:
        _hosted_success[shared_key] = windows
        memory.pop(key, None)
    else:
        background_only = local and (timed_out or (retry and windows is None))
        memory[key] = (windows, time.time(), background_only)
    return windows


def held(session) -> Optional[dict]:
    """The list this process already holds for the session's server and version, without
    asking the ERP: what a caller that must not wait on the ERP may use (nor run outside the
    ERP turn). None when nothing is held yet."""
    key = (str(getattr(getattr(session, "cfg", None), "api_base", "") or ""),
           getattr(session, "system_version", None))
    memory = _memory_for(session, _memory, _hosted_memory)
    if key in memory:
        return memory[key][0]
    if memory is not _memory:
        return _hosted_success.get(_shared_key(session, key[1]))
    return None


def checked_on(doc: dict) -> tuple:
    """The entry's verified builds, falling back to the probed build for an invalid list."""
    builds = doc.get("verified_builds")
    if isinstance(builds, list) and builds and all(isinstance(build, str) for build in builds):
        return tuple(builds)
    return (PROBED_VERSION,)


def allowed(session, doc: dict, fetch: bool = True) -> Optional[frozenset]:
    """The field names this report may be sent on this customer's ERP, or None: cannot tell.

    A window the list does not carry, or carries without fields, declares none here (Kaupo,
    04.10: refuse its fields): the list WAS read, so that is evidence about this build, not a
    gap in what we know. The exception is a Books-window entry, which the endpoint never lists
    (correction 16): allowed on its checked builds only. `fetch=False` uses only what is held."""
    windows = customer_windows(session) if fetch else held(session)
    window = doc.get("window_class")
    if windows and window in windows:
        return frozenset(windows[window])
    if doc.get("spec_source") == "books-window":
        if getattr(session, "system_version", None) in checked_on(doc):
            return frozenset(doc.get("spec") or {})
        return None
    return frozenset() if windows else None


def warm(session) -> None:
    """Read the list at start, in the ERP turn, so the first report does not wait for it. Never raises: a connector without an ERP still starts."""
    # A short login: an ERP that does not answer must not hold the turn for the full timeout.
    before = getattr(session, "timeout", None)
    try:
        if before:
            session.timeout = min(before, 20.0)
        customer_windows(session)
    except Exception:
        pass
    finally:
        if before:
            session.timeout = before
