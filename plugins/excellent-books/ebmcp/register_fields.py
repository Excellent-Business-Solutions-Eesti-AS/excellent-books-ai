"""The register fields the customer's OWN ERP declares — checked before find_records reads.

`find_records` checks field names against the register catalogue (fetched with the report
catalogue since 14.10, remote_catalog.py) for the ten registers catalogued there. On any other register a name the register lacks is dropped from `fields` without a word
(it reads as an empty column) and a server-side `filter.` on it returns everything, so `match`
was refused there outright. 12.5% of the stored bench `find_records` calls hit such a register
(VIVc 65, INVc 53 of 1,357).

Kaupo, 2026-10-05: the ERP's own Export/Import Format report (`TC/export-import-format`,
`ExpImpRn`) prints the field list of every register and block on the customer's OWN server and
Books version, more accurate than any copy. It is run once per Books version with the register
code empty and Include Blocks ticked (measured on the demo: 2,372 registers and blocks, 41,936
rows, 2.6 s), kept on disk like `erp_fields`, and `declared(session, register)` answers from it.

**Absence proves nothing.** A register the listing lacks is read unchecked, exactly as before,
never refused for being absent. **The listing has no keys**: `sort` is never checked against it.

The report's labels and its two notes ("Matrix Rows repeated until empty line", "This Register
is base64 encoded data") are in the API user's language, so the rows are read by SHAPE and
POSITION, never by their words (`parse`).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from hashlib import sha256
from pathlib import Path
from typing import Optional
from weakref import WeakKeyDictionary

from . import config, control, erp_fields, remote_catalog

REPORT_ID = "TC/export-import-format"
RUN_NAME = "ExpImpRn"           # the listing's run name: a crash sticks by run name, not only by id
# Every register and block: the register code empty, Include Blocks ticked (blocks are listed
# only with it). Both fields go out only if this ERP's own window declares them (_fetch).
SPEC = {"f1": "", "flags[0]": True}

# On the customer's own computer, next to the connector; never shipped. Register and field
# names and data types only, nothing from the customer's data.
CACHE_DIR: Optional[Path] = None

FETCH_TIMEOUT = 30.0        # the whole listing took 2.6 s on the demo
RETRY_AFTER = 300.0         # a failed read is not repeated on every call, nor given up for good

PACKED = "M4PackedMatrix"   # a data type, never translated

_memory: dict = {}          # (server, version) -> (registers or None, when, background only)
_crashed: set = set()       # local (server, version) whose connection this report closed
_hosted_memory = WeakKeyDictionary()  # per-session failures and lists without a known build
_hosted_success: dict[tuple[str, str], dict] = {}
_CRASHED = object()         # a listing that reset the connection, scoped to its hosted session

_TITLE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)(?: \(.*\))?$")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A short or cut listing is kept in memory only (release review 10-05, M2).
CORE_REGISTERS = frozenset({"CUVc", "IVVc", "INVc"})
# Measured on one build only: the demo's 1369 listing held 2,367 registers. A customer listing
# under it is refetched once per process start (Task 22 gate, opus C N5).
MIN_CACHED_REGISTERS = 1500


def forget() -> None:
    """Drop what this process remembers (tests; a restarted connector starts this way)."""
    _memory.clear()
    _crashed.clear()
    _hosted_memory.clear()
    _hosted_success.clear()


# -- reading the listing ----------------------------------------------------------------------
#
# Measured on the demo (8.5.56.1369), every row seven cells:
#
#   ["IVVc (Invoices)", "-", "IVVc4", "", ...]          a register: code (title), "-" or its
#   ["ActVc (Activities)", "ActView", "ActVc3", ...]    view, its file
#   ["0", "SerNr", "M4Long", "0", "Value with ...]      a header field, numbered
#   ["Matrix Rows repeated until empty line", "", ...]  the line fields start (only cell 0)
#   ["", "stp", "M4Int", "0", ...]                      a line field (cell 0 empty)
#   ["154", "TaxMatrix", "M4PackedMatrix", ...]         a packed sub-register, then INDENTED:
#   ["", "This Register is base64 encoded data", ...]     a note (only cell 1)
#   ["", "TaxMatrixVc (TaxMatrixVc)", "-", ...]           its title at cell 1
#   ["", "0", "SerNr", "M4Long", ...]                     its header fields, numbered at cell 1
#   ["", "Matrix Rows repeated until empty line", ...]    its lines (only cell 1)
#   ["", "VATCode", "M4Code", ...]                        its line fields: SAME shape as the
#                                                         parent's line fields
#
# A packed field in the HEADER ends at the parent's next numbered field. A packed field among
# the LINES (IVVc, VIVc, ORVc... 18 of the 42) prints its sub-register's fields unnumbered, in
# the same shape as the parent's line fields that follow, so where it ends is not in the rows.
# Its fields are then matched against the shape the same sub-register has elsewhere in the
# listing (every one on the demo prints TaxMatrixVc). When that shape is unknown, the rows stay
# with the parent: a name allowed by mistake is what happened before this gate, a name refused
# by mistake breaks a call that works.


def _cells(row) -> list:
    cells = ["" if c is None else str(c).strip() for c in (row or [])]
    return cells + [""] * (7 - len(cells))


def _scan(rows, shapes: dict) -> tuple:
    """(registers, {packed sub-register code: {"header": set, "lines": set}})."""
    out: dict = {}
    learned: dict = {}
    reg = None
    section = "header"
    sub = None

    def add(side, name, dtype):
        if reg is None or not _NAME.match(name):
            return
        if name not in reg["_" + side]:
            reg[side].append(name)
            reg["_" + side].add(name)
        reg["types"].setdefault(name, dtype)
        if side == "lines":
            reg["line_types"].setdefault(name, dtype)   # a name on both sides keeps its own type

    def learn(phase, name):
        if _NAME.match(name):
            learned.setdefault(sub["code"], {"header": set(), "lines": set()})[phase].add(name)

    for raw in rows:
        c = _cells(raw)
        if c[0]:
            sub = None
            if c[0].isdigit():
                add("header", c[1], c[2])
            elif not any(c[1:]):
                section = "lines"
            elif _TITLE.match(c[0]) and c[1] and c[2]:
                code = _TITLE.match(c[0]).group(1)
                reg = out.get(code)
                if reg is None:
                    reg = out[code] = {"title": c[0], "header": [], "lines": [], "types": {},
                                       "line_types": {}, "_header": set(), "_lines": set()}
                section = "header"
            else:                       # the title block of an empty listing, or a page header
                reg = None
            continue
        if reg is None or not c[1]:
            continue
        if c[1].isdigit():              # a numbered field of a packed sub-register
            if sub is not None:
                learn(sub["phase"], c[2])
            continue
        if not any(c[2:]):              # the note before a packed sub-register, or its lines
            if sub is not None:
                sub["phase"] = "lines"
            continue
        if not _NAME.match(c[1]) or c[2] == "-":
            code = (_TITLE.match(c[1]) or _TITLE.match(c[1].split(" ", 1)[0]))
            code = code.group(1) if code else c[1]
            sub = {"code": code, "at": section, "phase": "header",
                   "shape": shapes.get(code), "used": set()}
            continue
        if sub is not None and sub["at"] == "header":
            learn(sub["phase"], c[1])   # ends at the parent's next numbered field
            continue
        if sub is not None:
            shape, key = sub["shape"], (sub["phase"], c[1])
            if shape and c[1] in shape[sub["phase"]] and key not in sub["used"]:
                sub["used"].add(key)
                continue
            sub = None                  # the parent's line fields again (or shape unknown)
        add("lines", c[1], c[2])        # cell 0 empty: a line field
    return out, learned


def parse(rows) -> dict:
    """{register: {"title", "header": [names in order], "lines": [names], "types": {name: type},
    "line_types": {line field: type}}}
    from the Export/Import Format report's rows (lists of cells, by position). A register or
    block listed twice gets the fields of both listings."""
    rows = list(rows or [])
    first, learned = _scan(rows, {})
    shapes = {code: {"header": set(e["header"]), "lines": set(e["lines"])}
              for code, e in first.items()}
    shapes.update(learned)              # the shape it has where it is packed wins
    registers, _ = _scan(rows, shapes)
    return {code: {"title": e["title"], "header": e["header"], "lines": e["lines"],
                   "types": e["types"], "line_types": e["line_types"]}
            for code, e in registers.items() if e["header"] or e["lines"]}


# -- reading it from the customer's own ERP, once per Books version ---------------------------

def _report_doc() -> Optional[dict]:
    from . import reports
    doc = remote_catalog.report(REPORT_ID)  # none held, or without the entry: nothing is sent
    return None if doc is None or reports.gate(doc) else doc


def _cache_file(server: str, version: str) -> Path:
    folder = CACHE_DIR if CACHE_DIR is not None else config.data_dir() / ".cache" / "register-fields"
    prefix = sha256(server.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9.]+", "-", version).strip("-")
    return folder / f"{prefix}-{slug}.json"


def _crash_marker(server: str, version) -> Path:
    """Survives a restart: the report that closed this server's connection is never sent again
    by this install (release review 10-05, I3). Delete the file to allow it."""
    # Keyed by Books version too (re-review 10-05, N2): an upgraded ERP gets one new try.
    return _cache_file(server, str(version)).with_suffix(".crashed")


def _has_crash_marker(server: str, version) -> bool:
    marker = _crash_marker(server, version)
    if marker.exists():
        return True
    # The old cache names also keyed a restart guard. Keep honoring those markers.
    legacy = re.sub(r"[^A-Za-z0-9.]+", "-", f"{server.split('//', 1)[-1]}-{version}")
    return marker.with_name(f"{legacy.strip('-')}.crashed").exists()


def _build_marker(version) -> Path:
    """Hosted mode's restart guard, kept on purpose by Claude over Task 43's per-grant memory: the
    listing that reset one customer's Books is refused on that BUILD for every hosted caller, after
    any restart or redeploy, until the file is deleted. It names no server, company or user
    (Task 39 review S2: in memory only, a redeploy ran the crashing listing again). Refusing the
    listing costs only checked field names: registers are then read unchecked."""
    folder = CACHE_DIR if CACHE_DIR is not None else config.data_dir() / ".cache" / "register-fields"
    slug = re.sub(r"[^A-Za-z0-9.]+", "-", str(version)).strip("-") or "unknown"
    return folder / ("build-%s.crashed" % slug)


def _remember_build_crash(version) -> None:
    try:
        marker = _build_marker(version)
        marker.parent.mkdir(parents=True, exist_ok=True)
        with marker.open("x", encoding="utf-8") as handle:
            handle.write(time.strftime("%Y-%m-%d %H:%M"))
    except OSError:
        pass
    else:
        sys.stderr.write("ebmcp: hosted listing crash markers written: 1\n")


def _remember_crash(server: str, version) -> None:
    _crashed.add((server, version))
    try:
        marker = _crash_marker(server, version)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(time.strftime("%Y-%m-%d %H:%M"), encoding="utf-8")
    except OSError:         # a read-only install still remembers it until the process ends
        pass


def _is_disk_cacheable(registers: object) -> bool:
    return (isinstance(registers, dict) and len(registers) >= MIN_CACHED_REGISTERS
            and CORE_REGISTERS <= registers.keys())


def _read_disk(path: Path) -> Optional[dict]:
    try:
        registers = json.loads(path.read_text(encoding="utf-8")).get("registers")
    except (OSError, ValueError, AttributeError):
        return None
    return registers if _is_disk_cacheable(registers) else None


def _write_disk(path: Path, version: str, registers: dict) -> None:
    """Whole or not at all, like erp_fields: two connectors on one PC never leave half a file."""
    if config.mode() == "hosted":
        return
    part = path.with_suffix(".%d.part" % os.getpid())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        part.write_text(json.dumps({"version": version, "fetched": time.strftime("%Y-%m-%d %H:%M"),
                                    "registers": registers}, separators=(",", ":")),
                        encoding="utf-8")
        os.replace(part, path)
    except OSError:         # a read-only install still has the copy in memory
        try:
            part.unlink()
        except OSError:
            pass


def _fetch(session, server: str, timeout=FETCH_TIMEOUT):
    """The listing, through the same two calls run_report makes (Session.run_report, which wires
    the spec with erp._wire_spec, and report_html.parse_report) — not reports.run, whose gate
    is for the model's requests. Sent only if this ERP's own window declares both fields."""
    from . import report_html, reports
    from .erp import looks_like_a_crash
    # The P6 fallback holds for this automatic report too (Task 22 gate round 2, Sol SHOULD).
    if reports.COMPANY_UNPROVEN and reports._company(session) != 1:
        return None
    doc = _report_doc()
    if not doc:
        return None
    # The model's refusals apply to this automatic run too: a do-not-run entry, or one that
    # crashed the ERP earlier this session (release review 10-05, M1).
    doc = dict(doc, id=REPORT_ID)
    if reports.gate(doc, session):
        return None
    allowed = erp_fields.allowed(session, doc)
    if allowed is None or not set(SPEC) <= set(allowed):
        return None
    # Asked again right before the dispatch: a stop may have arrived with the field list.
    if control.report_dispatch(doc) or reports.crash_refusal(doc, session):
        return None
    try:
        response = session.run_report(doc["window_class"], doc["repname"], dict(SPEC),
                                      timeout=timeout)
        if getattr(response, "status", 200) != 200:
            return None
        return parse(report_html.parse_report(response.body).rows) or None
    except control.Stopped:
        raise
    except Exception as exc:    # a timeout, an error envelope, a version change, a dropped line
        erp_fields._raise_a_stop(exc)   # the REST-API-off refusal too (Task 22 gate round 2)
        if erp_fields._is_timeout(exc):
            return erp_fields._TIMED_OUT
        if looks_like_a_crash(exc):
            reports._remember_hosted_crash(doc, session)
            if config.mode() == "hosted":
                return _CRASHED
            _remember_crash(server, getattr(session, "system_version", None))
        return None


def customer_registers(session, *, retry=False) -> Optional[dict]:
    """The customer's {register: fields}, or None when they cannot be read."""
    if not (hasattr(session, "run_report") and hasattr(session, "sub_action")):
        return None
    memory = erp_fields._memory_for(session, _memory, _hosted_memory)
    local = memory is _memory
    server = str(getattr(getattr(session, "cfg", None), "api_base", "") or "")
    if getattr(session, "system_version", None) is None:
        # Logs in to learn the version, with erp_fields' own memory of a failed login.
        erp_fields.customer_windows(session)
    version = getattr(session, "system_version", None)
    key = (server, version)
    if local and (key in _crashed or _has_crash_marker(server, version)):
        return None
    if _build_marker(version).exists():
        return None             # this build's listing reset a Books server once
    if erp_fields._use_cached(memory, key, session, customer_registers, retry, RETRY_AFTER):
        return held(session)
    shared_key = erp_fields._shared_key(session, version) if not local else None
    if key not in memory and shared_key in _hosted_success:
        return _hosted_success[shared_key]
    registers = _read_disk(_cache_file(server, version)) if local and version else None
    if registers is None:
        registers = _fetch(session, server, erp_fields.RETRY_TIMEOUT if retry else FETCH_TIMEOUT)
        # A re-login inside the fetch can reveal a new build: the list is that build's.
        version = getattr(session, "system_version", None) or version
        key = (server, version)
        if registers is _CRASHED:
            memory[key] = (_CRASHED, time.time(), False)
            return None
        if local and version and _is_disk_cacheable(registers):
            _write_disk(_cache_file(server, version), version, registers)
    timed_out = registers is erp_fields._TIMED_OUT
    if timed_out:
        registers = None
    shared_key = erp_fields._shared_key(session, version) if not local else None
    if shared_key is not None and registers is not None:
        _hosted_success[shared_key] = registers
        memory.pop(key, None)
    else:
        background_only = local and (timed_out or (retry and registers is None))
        memory[key] = (registers, time.time(), background_only)
    return registers


def held(session) -> Optional[dict]:
    """What this process already holds for the session's server and version, never an ERP call."""
    key = (str(getattr(getattr(session, "cfg", None), "api_base", "") or ""),
           getattr(session, "system_version", None))
    memory = erp_fields._memory_for(session, _memory, _hosted_memory)
    if key in memory:
        registers = memory[key][0]
        return None if registers is _CRASHED else registers
    if memory is not _memory:
        return _hosted_success.get(erp_fields._shared_key(session, key[1]))
    return None


def declared(session, register: str, fetch: bool = True) -> Optional[dict]:
    """{"title", "header", "lines", "types"} of `register` on this customer's ERP, or None:
    cannot tell (no ERP, the listing could not be read, or the register is not in it). None is
    never a refusal: the listing is not a complete list of what REST serves."""
    try:
        registers = customer_registers(session) if fetch else held(session)
    except control.Stopped:
        raise
    except Exception as exc:
        erp_fields._raise_a_stop(exc)   # the REST-API-off refusal too (Task 22 gate round 2)
        return None
    return (registers or {}).get(str(register or "")) or None


def names(entry: dict) -> set:
    """Every field the register declares, header and lines."""
    return set(entry.get("header") or []) | set(entry.get("lines") or [])


def closest(asked, entry: dict, limit: int = 10) -> list:
    """The declared names nearest to `asked`, at most `limit`, never a secret-named one."""
    import difflib
    from . import privacy
    pool = sorted(n for n in names(entry) if not privacy.is_secret_field(n))
    by_fold: dict = {}
    for name in pool:
        by_fold.setdefault(name.casefold(), []).append(name)
    out: list = []
    for name in asked:
        folded = str(name).casefold()
        for match in difflib.get_close_matches(folded, list(by_fold), n=limit, cutoff=0.6):
            out.extend(n for n in by_fold[match] if n not in out)
    return out[:limit]


def warm(session) -> None:
    """Read the listing at start, in the ERP turn, so the first find_records does not wait for
    it (2.6 s on the demo). Never raises: a connector without an ERP still starts."""
    before = getattr(session, "timeout", None)
    try:
        if before:
            session.timeout = min(before, 20.0)     # a short login: an ERP that does not answer
        customer_registers(session)
    except Exception:
        pass
    finally:
        if before:
            session.timeout = before
