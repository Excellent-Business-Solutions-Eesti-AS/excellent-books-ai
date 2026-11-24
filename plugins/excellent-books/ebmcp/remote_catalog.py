"""The report and register catalogue, fetched from the Excellent Knowledge server.

Since 2026-10-14 (Kaia) the catalogue lives in ONE place, the knowledge repo's books/, and the
Knowledge MCP answers `books_find_report` / `books_describe_report` from it. The connector still
needs every entry to RUN a report or read a register (the declared spec, the status, the run
name, a register's keys and counting rules), so it reads the whole catalogue at start:

    GET EBMCP_CATALOG_URL   (read by ebmcp.config from .env; default
                             https://knowledge.excellent.ee/books/catalog.json; https only, no
                             redirect to http, at most MAX_BYTES; a file:// URL only with
                             EBMCP_CATALOG_LOCAL=yes; spec: docs/catalogue-endpoint.md)

A valid answer is kept in `.cache/catalogue/<version>.json`; when the server cannot be reached
or answers something invalid, the newest valid copy allowed by the signed control policy is
used. A changed control hash list swaps or drops the held catalogue between calls. With neither, `current()` is
None and run_report and find_records refuse everything (FAIL CLOSED): no report runs on a guess.

Validation is the integrity check: `format` must be FORMAT, `sha256` must be the hash of the
reports and registers as sent (`content_hash`), every report sits under its own id with a status,
and `signature` must be an Ed25519 signature of that hash by a key in PUBLIC_KEYS (Kaupo,
2026-10-19, PR #1 review). The catalogue decides what the connector runs (a new run name, a
field type, the fields of a Books window), so the server that serves it must not be able to
write it: it is signed on a developer's PC (knowledge repo, books/tools/sign_catalog.py) and the
private key never reaches the server. On top of that, a catalogue can only TIGHTEN what the code
refuses: the run names that restart or write
(reports.REFUSED_RUN_NAMES), the windows and run names that print a secret and the action boxes
are in code, and every run name any catalogue this computer has held marked do-not-run is kept
in a ledger next to them (LEDGER_NAME), only ever added to (the cached versions are pruned to
KEEP; the ledger is not), so an older or rolled-back catalogue cannot lift one. A fresh install starts from the in-code
floor plus the catalogue it fetches. Run names compare stripped and casefolded (`fold`).
"""
from __future__ import annotations

import base64
import copy
import datetime
import hashlib
import json
import os
import re
import threading
import time
import zlib
from pathlib import Path
from typing import Optional

from . import config

FORMAT = 1
MAX_BYTES = 20 * 1024 * 1024    # 3 MB on 14.10; a body past this is not a catalogue
_TRANSPORT = None               # tests: an httpx.MockTransport
# On the customer's own computer, next to the connector; never shipped (make_package copies
# named folders only). Public catalogue text, nothing from the customer's data.
CACHE_DIR: Optional[Path] = None
FETCH_TIMEOUT = 20.0        # per read
FETCH_DEADLINE = 60.0       # the whole download, checked at every hop, header and chunk: at most
                            # one read timeout past it (a byte a read cannot hold the start)
MAX_REDIRECTS = 3
RETRY_AFTER = 60.0          # nothing at all: asked again a minute later, not on every call
KEEP = 3                    # cached versions kept
# Every run name ever seen as do-not-run, one per line; never pruned, never a "*.json" version.
LEDGER_NAME = "refused-run-names.txt"         # in CACHE_DIR: _ledger_path()
LEDGER_MAX_BYTES = 1024 * 1024  # read at most this much; a ledger past it is never rewritten
VERSION_SHOWN = 40          # characters of a version put into the chat
SLUG_MAX = 64               # characters of a version in a cache file name (Windows: 260 a path)

# {key id: base64 of the raw 32-byte Ed25519 public key}. A catalogue signed by none of them is
# not used. A new signer runs sign_catalog.py --keygen and the public key is added here (a
# connector release); a lost or leaked key is removed the same way.
PUBLIC_KEYS = {
    "kaupo-2026-10": "YUlOenXOLCoKr+Xgv4/Pex+efspQecfdBt2UEuS3TNU=",
    "kaia-2026-10": "0kMs1xq0+1k/hNnPY8s8o9ddE5H0ZpmzTnephLmIGNw=",  # Kaia signs her own catalogue changes (Kaupo, 2026-10-19)
}
SIGNED_PREFIX = b"excellent-books-catalog/1:"

# Evidence (source files, manual pages) is the knowledge repo's own; it never travels, nor the
# run metadata tied to development (Kaia, 14.10: test servers, people, dates of measuring runs).
# Of `verified` only VERIFIED_SENT goes. Nothing here reads any of them; the knowledge server's
# books_catalog strips the same, so both build the same body.
NOT_SENT = ("sources", "flag_effects", "verified_history", "last_run", "note", "measured",
            "measured_at_volume")
VERIFIED_SENT = ("spec", "seconds")

UNAVAILABLE = (
    "This connector has no report catalogue: it reads it from the Excellent Knowledge server "
    "(%s) when it starts, and could neither reach it nor find a saved copy on this computer. "
    "Without the catalogue it cannot tell which reports are safe to run on this ERP, so it runs "
    "none and reads no register. Tell the person to check that this computer can reach "
    "knowledge.excellent.ee and restart the connector. Do not retry the call."
)


class Catalogue:
    def __init__(self, version: str, reports: dict, registers: dict, source: str,
                 saved_at: Optional[float] = None, sha256: str = ""):
        self.version = version
        self.sha256 = sha256
        self.reports = reports
        self.registers = registers
        self.source = source            # "fetched" or "cache"
        self.saved_at = saved_at        # a cached copy: when it was fetched (epoch seconds)
        self.do_not_run_names = frozenset().union(
            *(run_names(doc) for doc in reports.values() if doc.get("status") == "do-not-run"))
        # This version's plus every valid cached version's: refusals only add up (_load).
        self.refused_names = self.do_not_run_names


_held: Optional[Catalogue] = None
_failed_at: Optional[float] = None
_target_hash: Optional[str] = None
_lock = threading.Lock()


# -- the payload: built by the knowledge server, checked here ------------------------------------

def run_names(doc: dict) -> set:
    """What the ERP executes for an entry: its repname and every run name of its window,
    stripped. Compare them with `fold`."""
    more = doc.get("repnames_all") or []
    more = list(more) if isinstance(more, (list, tuple, set, frozenset)) else [more]
    return {str(n).strip() for n in [doc.get("repname")] + more
            if n is not None and str(n).strip()}


def fold(name) -> str:
    """How run names compare: the connector does not know whether the ERP tells case apart,
    so a refusal holds for any spelling (second opus review, 14.10)."""
    return str(name).strip().casefold()


def _plain(value):
    """YAML gives dates; JSON carries them as ISO text."""
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, (datetime.date, datetime.datetime, datetime.time)):
        return value.isoformat()
    return value


def content_hash(reports: dict, registers: dict) -> str:
    text = json.dumps({"reports": reports, "registers": registers}, sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _served(entry: dict) -> dict:
    out = {k: v for k, v in _plain(entry).items() if k not in NOT_SENT}
    if isinstance(out.get("verified"), dict):
        out["verified"] = {k: v for k, v in out["verified"].items() if k in VERIFIED_SENT}
    return out


def payload(reports: dict, registers: dict, version: str) -> dict:
    """The body of GET /books/catalog.json, from {id: entry} and {register: entry} as the YAML
    loads them. The reference implementation the knowledge server follows."""
    reports = {rid: _served(doc) for rid, doc in reports.items()}
    registers = {name: _served(entry) for name, entry in registers.items()}
    return {"format": FORMAT, "version": str(version),
            "sha256": content_hash(reports, registers),
            "reports": reports, "registers": registers}


def signed_message(digest: str) -> bytes:
    """What the signature covers: the content hash, under a prefix of its own."""
    return SIGNED_PREFIX + digest.encode("ascii")


def sign(body: dict, private_key, key_id: str) -> dict:
    """`body` with its signature (tests; the knowledge repo's sign_catalog.py does the same)."""
    value = private_key.sign(signed_message(body["sha256"]))
    return dict(body, signature={"key_id": key_id,
                                 "value": base64.b64encode(value).decode("ascii")})


def _check_signature(body: dict) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    signature = body.get("signature")
    if not isinstance(signature, dict) or signature.get("key_id") not in PUBLIC_KEYS:
        raise ValueError("not signed by a key this connector knows")
    try:
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(PUBLIC_KEYS[signature["key_id"]]))
        public.verify(base64.b64decode(str(signature.get("value")), validate=True),
                      signed_message(body["sha256"]))
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("the signature does not match the content") from None


def url() -> str:
    """EBMCP_CATALOG_URL, read through ebmcp.config like every other setting."""
    return config.catalog_url()


def validate(body, source: str = "fetched", saved_at: Optional[float] = None) -> Catalogue:
    """A Catalogue, or ValueError saying what is wrong with the body."""
    if not isinstance(body, dict) or body.get("format") != FORMAT:
        raise ValueError("not catalogue format %d" % FORMAT)
    version, reports, registers = body.get("version"), body.get("reports"), body.get("registers")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("no version")
    if not isinstance(reports, dict) or not reports or not isinstance(registers, dict):
        raise ValueError("no reports")
    if body.get("sha256") != content_hash(reports, registers):
        raise ValueError("sha256 does not match the content")
    _check_signature(body)
    for rid, doc in reports.items():
        if not isinstance(doc, dict) or doc.get("id") != rid or not isinstance(doc.get("status"), str):
            raise ValueError("report %r is not filed under its own id with a status" % rid)
        more = doc.get("repnames_all")
        if not isinstance(doc.get("repname"), (str, type(None))) or \
                not isinstance(doc.get("window_class"), (str, type(None))) or \
                not (more is None or isinstance(more, list) and all(isinstance(n, str) for n in more)):
            raise ValueError("report %r has a run name or window that is not text" % rid)
        spec, verified = doc.get("spec"), doc.get("verified")
        if not (spec is None or isinstance(spec, dict)
                and all(isinstance(f, dict) for f in spec.values())) \
                or not (verified is None or isinstance(verified, dict)
                        and isinstance(verified.get("spec"), (dict, type(None)))):
            raise ValueError("report %r has a spec that is not fields" % rid)
    for name, entry in registers.items():
        if not isinstance(entry, dict) or entry.get("register") != name:
            raise ValueError("register %r is not filed under its own name" % name)
    return Catalogue(version, reports, registers, source, saved_at, body["sha256"])


# -- fetching and the cache ------------------------------------------------------------------------

def _too_big(size: int, max_bytes: Optional[int] = None, what: str = "the catalogue") -> None:
    cap = MAX_BYTES if max_bytes is None else max_bytes
    if size > cap:
        raise ValueError("%s is over %d bytes" % (what, cap))


def _get(url: str, timeout: float, max_bytes: int = MAX_BYTES,
         *, total_timeout: Optional[float] = None, what: str = "the catalogue") -> bytes:
    """HTTPS only; cap the unpacked body by max_bytes (and MAX_BYTES).

    A file:// URL needs EBMCP_CATALOG_LOCAL=yes. Control checks also pass a
    total_timeout, checked at every hop, header and chunk alongside read timeouts,
    and `what` names the file in the errors.
    """
    cap = min(MAX_BYTES, max_bytes)
    if url.startswith("file://"):
        if not config.catalog_local_allowed():
            raise ValueError("a file:// catalogue needs %s=yes" % config.CATALOG_LOCAL_KEY)
        from urllib.parse import urlparse
        from urllib.request import url2pathname
        path = Path(url2pathname(urlparse(url).path))   # file:///C:/x is C:\x on Windows
        _too_big(path.stat().st_size, cap, what)
        with path.open("rb") as stream:
            raw = stream.read(cap + 1)
        _too_big(len(raw), cap, what)
        return raw
    if not url.startswith("https://"):
        raise ValueError("%s is fetched over https:// only" % what)
    import httpx

    def https_only(request):
        if request.url.scheme != "https":
            raise ValueError("%s redirected to %s://" % (what, request.url.scheme))

    limit = FETCH_DEADLINE if total_timeout is None else min(FETCH_DEADLINE, total_timeout)
    deadline = time.monotonic() + limit

    def in_time(_=None):
        _in_time(deadline, limit, what)

    with httpx.Client(timeout=timeout, follow_redirects=True, max_redirects=MAX_REDIRECTS,
                      transport=_TRANSPORT,
                      event_hooks={"request": [https_only, in_time],
                                   "response": [in_time]}) as client:
        with client.stream("GET", url, headers={"Accept": "application/json",
                                                "Accept-Encoding": "gzip"}) as response:
            response.raise_for_status()
            _too_big(int(response.headers.get("content-length") or 0), cap, what)
            return _read(response, deadline, cap, limit, what)


def _in_time(deadline: float, limit: Optional[float] = None, what: str = "the catalogue") -> None:
    if time.monotonic() > deadline:
        raise ValueError("%s took over %d s" % (what, FETCH_DEADLINE if limit is None else limit))


def _read(response, deadline: float, max_bytes: Optional[int] = None,
          limit: Optional[float] = None, what: str = "the catalogue") -> bytes:
    """The body, unzipped here rather than by httpx so MAX_BYTES bounds what is unpacked, not
    only what arrives (a small gzip can unpack to gigabytes), within `deadline`."""
    cap = MAX_BYTES if max_bytes is None else max_bytes
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding not in ("", "identity", "gzip"):
        raise ValueError("%s came as %s" % (what, encoding))
    unzip = zlib.decompressobj(wbits=31) if encoding == "gzip" else None
    body = bytearray()
    for chunk in response.iter_raw():
        _in_time(deadline, limit, what)
        if unzip is not None:
            # One gzip member, as the knowledge server sends: anything after it is refused
            # rather than ignored, so a body cannot carry a second, unchecked part.
            if unzip.eof and chunk:
                raise ValueError("%s has data after its gzip stream" % what)
            chunk = unzip.decompress(chunk, cap + 1 - len(body))
            if unzip.unconsumed_tail:
                raise ValueError("%s is over %d bytes" % (what, cap))
            if unzip.unused_data:
                raise ValueError("%s has data after its gzip stream" % what)
        _too_big(len(body) + len(chunk), cap, what)
        body += chunk
    _in_time(deadline, limit, what)
    if unzip is not None and not unzip.eof:
        raise ValueError("%s's gzip stream is cut short" % what)
    return bytes(body)


def _cache_dir() -> Path:
    return CACHE_DIR if CACHE_DIR is not None else config.data_dir() / ".cache" / "catalogue"


def _cache_file(version: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9.]+", "-", version)[:SLUG_MAX].strip("-.") or "catalogue"
    return _cache_dir() / ("%s.json" % slug)


def _save(raw: bytes, version: str) -> None:
    """Whole or not at all; older versions beyond KEEP go."""
    path = _cache_file(version)
    part = path.with_suffix(".%d.part" % os.getpid())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        part.write_bytes(raw)
        os.replace(part, path)
        os.utime(path)
        for old in sorted(path.parent.glob("*.json"), key=lambda p: p.stat().st_mtime,
                          reverse=True)[KEEP:]:
            old.unlink()
    except OSError:         # a read-only install still has the copy in memory
        try:
            part.unlink()
        except OSError:
            pass


def _cached():
    """Every valid cached version, newest first. A file that cannot be read or checked, for
    whatever reason, is skipped; it never stops the others."""
    try:
        paths = sorted(_cache_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        return
    for path in paths:
        try:
            yield validate(json.loads(path.read_bytes()), source="cache",
                           saved_at=path.stat().st_mtime)
        except Exception:
            continue


def _ledger_path() -> Path:
    return _cache_dir() / LEDGER_NAME


def _read_ledger():
    """(run names, whole): the names in the ledger, read line by line so a damaged line loses
    only itself, and whether it was read whole. No ledger yet is whole; one that exists but
    cannot be read, or is over LEDGER_MAX_BYTES, is not, and is never rewritten (_remember)."""
    path = _ledger_path()
    try:
        if not path.exists():
            return frozenset(), True
        with open(path, "rb") as handle:
            raw = handle.read(LEDGER_MAX_BYTES + 1)
    except Exception:
        return frozenset(), False
    whole = len(raw) <= LEDGER_MAX_BYTES
    text = raw[:LEDGER_MAX_BYTES].decode("utf-8", errors="replace")
    return frozenset(line.strip() for line in text.splitlines() if line.strip()), whole


def _ledger() -> frozenset:
    return _read_ledger()[0]


def _remember(names) -> None:
    """Add `names` to the ledger: the union, whole or not at all."""
    ledger = _ledger_path()
    known, whole = _read_ledger()
    if not whole or set(names) <= known:      # never shrink a ledger it could not read whole
        return
    part = ledger.with_name("%s.%d.part" % (ledger.name, os.getpid()))
    try:
        ledger.parent.mkdir(parents=True, exist_ok=True)
        part.write_bytes("".join("%s\n" % n for n in sorted(known | set(names))).encode("utf-8"))
        os.replace(part, ledger)
    except OSError:         # a read-only install still holds them in memory
        try:
            part.unlink()
        except OSError:
            pass


def _from_cache() -> Optional[Catalogue]:
    from . import control
    return next((held for held in _cached() if control.catalogue_allowed(held.sha256)), None)


def _load() -> Optional[Catalogue]:
    from . import control
    unlisted = frozenset()
    try:
        raw = _get(url(), FETCH_TIMEOUT)
        held = validate(json.loads(raw))
        if not control.catalogue_allowed(held.sha256):
            # Signed but not listed: not used, but its do-not-run names only add refusals.
            unlisted = held.do_not_run_names
            raise ValueError("catalogue hash is not listed in the control policy")
    except Exception:       # offline, a 404, a timeout, a body that is not a valid catalogue
        held = _from_cache()
    else:
        _save(raw, held.version)
    if held is not None:
        # A crasher one version refused stays refused in every other (opus review, 14.10),
        # also after its cached version is pruned (the ledger, second opus review).
        held.refused_names = held.do_not_run_names.union(
            unlisted, _ledger(), *(other.do_not_run_names for other in _cached()))
        _remember(held.refused_names)
    elif unlisted:
        _remember(unlisted)
    return held


def current() -> Optional[Catalogue]:
    """Swap between calls when control changes; keep only an allowed catalogue.

    A failed upgrade keeps an allowed older copy and backs off for RETRY_AFTER.
    A different preferred hash bypasses that backoff.
    """
    from . import control
    global _held, _failed_at, _target_hash
    policy = control.policy()
    preferred = policy.catalogue_hashes[0] if policy and policy.catalogue_hashes else None
    with _lock:
        if preferred != _target_hash:
            _target_hash, _failed_at = preferred, None
        if _held is not None and not control.catalogue_allowed(_held.sha256):
            _held = None
        if control.may_read() is not None:
            return None
        if _held is not None and (preferred is None or preferred == _held.sha256):
            return _held
        if _failed_at is not None and time.time() - _failed_at < RETRY_AFTER:
            return _held
        loaded = _load()
        if loaded is not None:
            _held = loaded
        _failed_at = (None if _held is not None and (preferred is None or _held.sha256 == preferred)
                      else time.time())
        return _held


def use(body, source: str = "fetched") -> Catalogue:
    """Hold this payload (tests, a developer's local copy)."""
    global _held, _failed_at
    _held, _failed_at = validate(body, source), None
    return _held


def forget() -> None:
    global _held, _failed_at, _target_hash
    _held, _failed_at, _target_hash = None, None, None


def warm():
    """Load it in the background at start, while the client is still connecting."""
    thread = threading.Thread(target=current, name="warm-catalogue", daemon=True)
    thread.start()
    return thread


def _where(address: str) -> str:
    """Scheme and host of the catalogue URL only: never its user, password, path or query."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(str(address))
        return "%s://%s" % (parts.scheme, parts.hostname or "")
    except Exception:
        return "the configured address"


def unavailable(**extra) -> dict:
    return dict({"error": "catalogue_unavailable", "why": UNAVAILABLE % _where(url())}, **extra)


CACHE_NOTE = ("Report catalogue: a copy saved on this computer (version %s, %s old), because the "
              "Excellent Knowledge server could not be reached at start; restarting the connector "
              "once it can be reached brings the latest.")


def cache_note() -> Optional[str]:
    """One line when the catalogue held is a saved copy, else None."""
    held = _held
    if held is None or held.source != "cache":
        return None
    age = max(0.0, time.time() - (held.saved_at or time.time()))
    days, hours = int(age // 86400), max(1, int(age // 3600))
    when = ("%d day%s" % (days, "s" * (days > 1)) if days
            else "%d hour%s" % (hours, "s" * (hours > 1)))
    return CACHE_NOTE % (held.version[:VERSION_SHOWN], when)


# -- reading it ----------------------------------------------------------------------------------

def report(report_id: str) -> Optional[dict]:
    """A copy of one report entry (callers may change it), or None. The id is looked up, never
    turned into a path."""
    held = current()
    doc = held.reports.get(str(report_id)) if held else None
    return copy.deepcopy(doc) if doc is not None else None


def register(name: str) -> Optional[dict]:
    held = current()
    entry = held.registers.get(str(name)) if held else None
    return copy.deepcopy(entry) if entry is not None else None


def report_ids() -> list:
    held = current()
    return sorted(held.reports) if held else []


def do_not_run_names() -> frozenset:
    """The do-not-run run names of the catalogue held, of every valid cached version and of
    the ledger (they only add up); never a fetch (reports.gate is also called by the maintenance tools in the
    knowledge repo, which have no business here). reports.refused_run_names adds the floor."""
    held = _held    # read once: current() may drop it between two reads
    return held.refused_names if held is not None else _ledger()
