"""What stands between an AI client's request and a customer's ERP.

Two jobs, both done before any HTTP call is made:

- `gate` refuses a report the catalogue says must not run. Six Nominal Ledger windows restart
  the whole server (measured 2026-09-14), three of them only once an optional flag is set, so
  a report that ran cleanly once is not thereby safe. The refusal carries the entry's own
  explanation and somewhere else to go, because a model that can only say "no" is no help.
- `build_spec` validates what the model asked for against the fields the window actually
  declares. The declared spec is the allowlist: an undeclared field is a typo or an invention,
  and forwarding it would let a model probe the ERP with arbitrary keys.
"""
from __future__ import annotations

import re
import types
from hashlib import sha256
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree

from . import config, control, dates, erp_fields, privacy, register_fields, remote_catalog


class SpecError(ValueError):
    """The requested spec cannot be sent to the ERP as it stands."""


# Reports that closed the ERP's connection, by origin, Books build and run name. A marker on
# disk keeps the report blocked on that build after a connector restart.
CRASHED: set = set()

# Task 34 review SHOULD 3: a network drop looks the same, so say what lifts the block.
CRASH_LIFT = ("The block ends when the Books server moves to a new build. If Books was not "
              "restarted (a VPN or network drop), Excellent support can lift it: they remove the marker "
              "in the connector's data folder (.cache/report-crashes, or .cache/register-fields for "
              "the register listing), then the connector is restarted.")
CRASHED_WHY = ("running this report closed the ERP's connection earlier on this connector, "
               "which is how a server restart looks from here, so it is blocked on this "
               "Books build. " + CRASH_LIFT)
HOSTED_CRASHED_WHY = ("running this report closed a Books connection earlier, which can indicate "
                     "a server restart. The connector has blocked it. It needs a developer.")


# Boxes that turn a report from a read into an action. The report itself stays runnable with
# them unticked; run_report has no step where a person could confirm the action first.
# Keyed by RUN NAME, like WRITE_REACHING_FLAGS: the catalogue id comes from another repo since
# 14.10, and a renamed or split id must never unlock the box (opus review, 2026-10-14).
ACTION_FLAGS = {
    "SyncCheckRn": {"flags[0]", "flags[1]"},       # SY/sync-check: Re-send missing / different
}
ACTION_FLAG_REFUSAL = ("%s would make this report re-send records instead of only reading "
                       "them, an action this connector does not take without a person "
                       "confirming it. Run the report without it.")


# The run names of every entry that was `do-not-run` on 2026-10-14, when the catalogue moved to
# the Excellent Knowledge server: they restart the ERP, write (POS X/Z, production operations),
# act elsewhere or answer wrongly (InvoiceRn ignores its sflags). The run name is what the ERP
# executes; the window is only the form. Refused here whatever a fetched catalogue says, so a
# catalogue from elsewhere can only add refusals (remote_catalog.do_not_run_names), never lift
# one: lifting needs a connector release.
REFUSED_RUN_NAMES = frozenset({
    "ASPListNotUsedServersRn", "ASPRemoteCloudServerListRn", "AssetAtTimeRn", "AT2ListDateRn",
    "CouponRn", "ActListRn", "EMPlanRn", "ActReqListRn", "EstAddrLookupRn", "ChqDepRn", "CCardRn",
    "CouponListRn", "KeyRn", "CredManInfoRn", "IntRn", "TestProdRepRn",
    "EbayGetInventoryLocationsRn", "HalSpecRn", "CashFlowRn", "VATInfRn", "VAT2Rn", "VAT3Rn",
    "XBRLReportRn", "HTSOPStatRn", "POSZRn", "ProdOperationsRn", "AgedRecRn", "IntraStaRn",
    "InvoiceRn", "SLVATBaseSLVRn", "SLVATSLVRn", "LinkListRn",
})
RUN_NAME_REFUSAL = ("%s runs as %s, a run name this connector does not run: it restarts the ERP, "
                    "writes, or answers wrongly over the API.")


def refused_run_names() -> frozenset:
    """The in-code floor plus every do-not-run run name of the catalogue held, its cached
    versions and the never-pruned ledger (remote_catalog.do_not_run_names): refusals only add
    up. Compare with remote_catalog.fold."""
    return REFUSED_RUN_NAMES | remote_catalog.do_not_run_names()


def _folded(table: dict) -> dict:
    out = {}
    for name, value in table.items():
        out.setdefault(remote_catalog.fold(name), set()).update(value)
    return out


_BOX = re.compile(r"(s?flags)\[?([0-9]+)\]?")


def box(name) -> str:
    """The box a spec name reaches on the wire, whatever its spelling: `flags[4]` goes out as
    `flags4` (erp._wire_spec), so `flags[4]`, `flags4` and `FLAGS[4]` are one box. Every block
    and default check compares these (Sol re-check of 6ff701b, MUST B)."""
    folded = str(name).strip().casefold()
    match = _BOX.fullmatch(folded)
    return "%s%s" % (match[1], match[2]) if match else folded


def boxes(table: dict, doc: dict) -> set:
    """The boxes `table` ({run name: boxes}) blocks for any program this entry runs."""
    folded = _folded(table)
    return set().union(*(folded.get(remote_catalog.fold(name), ())
                         for name in remote_catalog.run_names(doc)))


# Hosted mode: the server's own log spans every user of the Books server, other people's logins
# included, so a shared hosted connector does not read it (Sol review of 59de990, MUST 3; Task 44
# decides for good). By reader and by RUN NAME, like every refusal here.
# ServerLogRn prints the same log; UserHistRn lists users' login events (Sol review of fef70bc).
HOSTED_REFUSED_RUN_NAMES = frozenset({"InspectHansaLogRn", "ServerLogRn", "UserHistRn"})
HOSTED_LOG_REFUSAL = ("%s reads the Books server's own log. That log belongs to the whole Books "
                      "server, which several companies can share, and shows every user's logins, so "
                      "the hosted connector does not run it. Ask the person who runs the Books "
                      "server, or use a connector installed on your own computer.")


WRITE_REACHING_REFUSAL = ("%s reaches code in Excellent Books that can write. The connector "
                          "refuses this option. Run the report without it.")


def _hosted() -> bool:
    from . import config
    try:
        return config.mode() == "hosted"
    except config.ConfigError:
        return False


def _stdio() -> bool:
    """Desktop and the plugin (config.stdio_mode); an unreadable mode reads as local."""
    from . import config
    try:
        return config.stdio_mode()
    except config.ConfigError:
        return False


def safe_reason(exc: BaseException) -> str:
    """A failure's text for a result. Desktop and the plugin keep the HTTP status and the kind of
    failure, never the exception's own words: an HTTP reason phrase or a re-login error can echo
    the login or a cookie (Astra recheck of the slice 2 fix, MUST 4). Local keeps the words;
    hosted sessions already replace them (erp._hosted_transport_error)."""
    import urllib.error

    from . import erp
    if not _stdio():
        return str(exc)
    if isinstance(exc, urllib.error.HTTPError):
        return "Excellent Books answered HTTP %d" % exc.code
    if isinstance(exc, (OSError, erp.SignInAgain, erp.RedirectRefused)):
        return str(erp._hosted_transport_error(exc))
    return "the request to Excellent Books failed"


STDIO_USERCODE_NOTE = (
    " NOTE: the Books user's Code for this connection could not be confirmed. On many servers the "
    "sign-in uses an e-mail address while reports need the user's Code, and that gives exactly "
    "this refusal: ask the Books administrator to check the user's Code before the access group.")


def _reads_the_server_log(doc: dict) -> bool:
    folded = {remote_catalog.fold(h) for h in HOSTED_REFUSED_RUN_NAMES}
    return doc.get("reader") == "server_log" or any(
        remote_catalog.fold(n) in folded for n in remote_catalog.run_names(doc))


def log_refusal(doc: dict, session) -> Optional[dict]:
    """Hosted: the server-log readers only on a server proven to hold one company (Task 44)."""
    if _hosted() and _reads_the_server_log(doc) and not _proven_single_company(session):
        return {"error": "not_available_here", "id": doc.get("id"), "alternatives": [],
                "why": HOSTED_LOG_REFUSAL % doc.get("id")}
    return None


def _proven_single_company(session) -> bool:
    """Only a server listed in EBMCP_HOSTED_LOG_SERVERS (proof in the hosted gate, Task 48) may
    have its log read in hosted mode; without a session the origin cannot be proven (Task 44)."""
    import os
    from urllib.parse import urlsplit

    from . import hosted

    origin = getattr(getattr(session, "cfg", None), "origin", None)
    if not origin:
        return False
    parts = urlsplit(origin)
    netloc = parts.netloc.lower()
    if parts.scheme == "https":
        netloc = hosted._default_port(netloc)     # "host:443" is "host", both sides
    return netloc in hosted.log_servers(os.environ)


def _crash_name(doc: dict) -> str:
    """What a crash sticks to: the RUN NAME (another catalogue entry with the same run name
    runs the same Books report and would restart the server too; CLAUDE.md, rechecker of b5e5797),
    else the id."""
    if _is_listing(doc):
        return remote_catalog.fold(register_fields.RUN_NAME)   # however it is named, one key
    # Folded like every run-name refusal here: a spelling variant is the same Books report.
    return remote_catalog.fold(str(doc.get("repname") or doc.get("id") or ""))


def _is_listing(doc: dict) -> bool:
    return (doc.get("id") == register_fields.REPORT_ID
            or doc.get("repname") == register_fields.RUN_NAME)


def _crash_key(doc: dict, session):
    # Catalogue preflight has no Books build. The worker checks again with the live session.
    origin = getattr(getattr(session, "cfg", None), "origin", None)
    if session is None or (not origin and _hosted()):
        return None
    return origin, getattr(session, "system_version", None), _crash_name(doc)


def _hosted_crash_marker(doc: dict, session) -> Path | None:
    name = _crash_name(doc)
    version = getattr(session, "system_version", None)
    if _is_listing(doc):
        return register_fields._build_marker(version)
    if not name or not version:
        return None
    build = re.sub(r"[^A-Za-z0-9.]+", "-", version).strip("-") or "unknown"
    digest = sha256(name.encode("utf-8")).hexdigest()[:32]
    return config.data_dir() / ".cache" / "report-crashes" / f"build-{build}-{digest}.crashed"


def _remember_hosted_crash(doc: dict, session) -> None:
    crash_key = _crash_key(doc, session)
    if crash_key is not None:
        CRASHED.add(crash_key)
    if _is_listing(doc):
        register_fields._remember_build_crash(getattr(session, "system_version", None))
        return
    marker = _hosted_crash_marker(doc, session)
    if marker is not None:
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()
        except OSError:  # The origin's in-memory refusal still holds.
            pass


def crash_refusal(doc: dict, session=None) -> Optional[dict]:
    crash_key = _crash_key(doc, session)
    blocked = crash_key is not None and crash_key in CRASHED
    hosted = _hosted()
    if not blocked and session is not None:
        marker = _hosted_crash_marker(doc, session)
        blocked = marker is not None and marker.exists()
    if blocked:
        return {"error": "not_runnable", "id": doc.get("id"),
                "why": HOSTED_CRASHED_WHY if hosted else CRASHED_WHY,
                "alternatives": doc.get("not_for") or []}
    return None


def gate(doc: dict, session=None) -> Optional[dict]:
    """`None` when the report may run, otherwise the refusal to hand back."""
    # The signed control file's stops first: by id and by folded run name (Task 18).
    stopped = control.report_refusal(doc)
    if stopped:
        return stopped
    if session is not None:
        # Without a session (the catalogue preflight) the origin cannot be proven yet: the check
        # is DEFERRED to dispatch, which every report passes right before it goes to Books - so a
        # listed server is not refused early, and an unlisted one is still refused before any
        # request (Sol review of fef70bc).
        logged = log_refusal(doc, session)
        if logged:
            return logged
    secret_runs = {remote_catalog.fold(n): v for n, v in privacy.SECRET_RUN_NAMES.items()}
    secret_windows = {remote_catalog.fold(n): v for n, v in privacy.SECRET_REPORTS.items()}
    window = doc.get("window_class")
    secret = (secret_windows.get(remote_catalog.fold(window)) if window else None) or next(
        (secret_runs[remote_catalog.fold(n)] for n in sorted(remote_catalog.run_names(doc))
         if remote_catalog.fold(n) in secret_runs), None)
    if secret:
        return {"error": "not_runnable", "id": doc.get("id"), "alternatives": [],
                "why": privacy.SECRET_REPORT_REFUSAL % (doc.get("id"), secret[1])}
    refusing = {remote_catalog.fold(n) for n in refused_run_names()}
    refused = {n for n in remote_catalog.run_names(doc) if remote_catalog.fold(n) in refusing}
    if refused and doc.get("status") != "do-not-run":
        return {"error": "not_runnable", "id": doc.get("id"),
                "why": RUN_NAME_REFUSAL % (doc.get("id"), ", ".join(sorted(refused))),
                "alternatives": doc.get("not_for") or []}
    crashed = crash_refusal(doc, session)
    if crashed:
        return crashed
    if doc.get("status") == "do-not-run":
        pitfalls = doc.get("pitfalls") or []
        return {
            "error": "not_runnable",
            "id": doc.get("id"),
            "why": pitfalls[0] if pitfalls else "this report is not available over the API",
            "alternatives": doc.get("not_for") or [],
        }
    return None


def check_given(doc: dict, given: dict) -> None:
    """The refusals that need no ERP: a field the catalogue does not declare, a box that makes
    the report act. Raises `SpecError`. The tool checks before login, and `_run` checks
    before reading the customer's field list."""
    declared = doc.get("spec") or {}
    unknown = sorted(k for k in given if k not in declared)
    if unknown:
        raise SpecError("unknown field(s) %s. This report accepts: %s"
                        % (", ".join(unknown), ", ".join(sorted(declared)) or "no fields"))

    def ticked(table):
        blocked = {box(name) for name in boxes(table, doc)}
        return sorted(name for name, value in given.items()
                      if box(name) in blocked and not _unticked(value))

    acting = ticked(ACTION_FLAGS)
    if acting:
        raise SpecError(ACTION_FLAG_REFUSAL % ", ".join(acting))
    reaching = ticked(WRITE_REACHING_FLAGS)
    if reaching:
        raise SpecError(WRITE_REACHING_REFUSAL % ", ".join(reaching))


def _unticked(value) -> bool:
    """An action box counts as unticked only when it plainly is. Not by the declared type: the
    catalogue says what that is, and an integer-typed box sent as 2 re-sent records while the
    boolean reading called it false (PR #1 review, 2026-10-19)."""
    if value is None or value is False:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 0
    return str(value).strip().lower() in ("", "0", "false", "no", "off")


def build_spec(doc: dict, given: dict, date_format=None, allowed=None) -> dict:
    """The spec to send, cast to the types the window declares.

    A date goes out in the form the ERP reads for that field (`ebmcp/dates.py`): ISO for a name
    ending in "Date", `date_format` (the ERP's `SysFormatBlock`, or a function that reads it,
    called only when a value needs it) for any other.

    `allowed` is what the window declares on the customer's OWN ERP (`erp_fields.allowed`): a
    field outside it is refused, because an unknown field restarts the ERP, and only defaults
    inside it are sent. None (cannot tell) sends no default at all.

    Raises `SpecError` naming the field and what it is for, so the model can correct itself
    without another round trip.
    """
    declared = doc.get("spec") or {}
    check_given(doc, given)
    lacking = lacks_required(doc, allowed)
    if lacking:
        raise SpecError(REQUIRED_NOT_ON_THIS_ERP % ", ".join(lacking))
    if allowed is not None:
        absent = sorted(k for k in given if k not in allowed)
        if absent:
            # What this ERP has that the catalogue lacks is said too: a renamed field shows up
            # here as one missing and one extra (opus review 04.10, N7).
            extra = sorted(set(allowed) - set(declared))
            raise SpecError(NOT_ON_THIS_ERP % (", ".join(absent),
                                               ", ".join(sorted(set(declared) & set(allowed)))
                                               or "no fields")
                            + (ALSO_ON_THIS_ERP % ", ".join(extra) if extra else ""))

    # The client's window defaults (Kaupo, 2026-10-03): the hook that ticks them when the window
    # opens never runs over the API, so they are sent unless the caller set the field — never a
    # box that makes the report act, reaches write code or costs a timeout.
    defaults = client_defaults(doc, given, allowed)
    given = dict(defaults, **given)

    missing = [(name, f) for name, f in declared.items()
               if f.get("required") and name not in given]
    if missing:
        raise SpecError("missing required field(s): " + "; ".join(
            "%s (%s)" % (name, f.get("meaning") or f.get("label") or "no description")
            for name, f in missing))

    sent = {}
    for name, value in given.items():
        field_type = declared[name].get("type")
        if field_type == "date":
            try:
                value = dates.to_wire(name, value, date_format)
            except ValueError as bad:
                raise SpecError(str(bad)) from None
        sent[name] = _typed(value, field_type)
    return sent


DEFAULTS_NOTE = ("Also sent, as the client sets them when this report's window opens: %s. Send a "
                 "field yourself to change it.")
# Opus review 04.10 (M2): it ended "send them yourself", and the model did, sending exactly what
# the gate held back. The list stays; sending them is the person's decision.
DEFAULTS_UNCONFIRMED = ("Not sent: %s, which the client sets when this report's window opens. This "
                        "connector could not confirm those fields on this ERP's version, and a "
                        "field the ERP does not know restarts it. If the answer looks incomplete, "
                        "say so and why; do not add these fields yourself — sending them is the "
                        "person's decision.")
# Re-review 04.10 (S3): run without it, a report missing its period answered as though it had one.
REQUIRED_NOT_ON_THIS_ERP = ("this report cannot run as catalogued on this ERP's version: its window "
                            "there has no %s, which the catalogue says it needs. Use another report, "
                            "or tell the person this connector's catalogue does not match their "
                            "Books version.")


# `allowed` when nobody asked this ERP (no ERP behind the door): the catalogue alone decides.
_UNCHECKED = object()


def lacks_required(doc: dict, allowed) -> list:
    """The required fields (as "name (label)") this ERP's window does not declare; [] when the
    gate cannot tell or nothing is missing."""
    if allowed is None or allowed is _UNCHECKED:
        return []
    return ["%s (%s)" % (n, f.get("label") or n) for n, f in (doc.get("spec") or {}).items()
            if isinstance(f, dict) and f.get("required") and n not in allowed]


# Astra's review 04.10, Kaupo 05.10: when the customer's own list cannot be read, a caller's fields
# no longer go out on the catalogue's check alone. On another build one unknown field restarts the
# ERP; nothing is sent, and a run with no fields at all still runs.
UNVERIFIED_FIELDS = ("nothing was sent: this connector could not confirm that this ERP's version has "
                     "the field(s) %s, and a field the ERP does not know restarts it. %s %s")
# Release review 10-05 (I1): "run it without fields" on a report that needs fields was a bad_spec,
# a second dead turn. Which advice follows depends on whether the report has required fields.
UNVERIFIED_BARE = ("Run it without fields only if the person wants the report's own defaults; "
                   "otherwise tell them the report cannot be filtered from here right now.")
UNVERIFIED_NEEDED = ("It needs %s, so it cannot run from here on this ERP right now: tell the person, "
                     "and that it runs in Excellent Books itself.")
UNVERIFIED_LIST = ("Its list of report fields could not be read; this connector tries again in a few "
                   "minutes, and if it keeps failing this Books version may not offer that list.")
# Spec section 4.3, word for word, from the control file's `builds` block. Never advice to
# delay or undo a Books update.
OFF_BUILD_PENDING = ("This report is checked on each Excellent Books version before it runs from "
                     "here. Your server runs %s; Excellent is checking that version and expects to "
                     "finish by %s. Until then, run this report in Excellent Books itself. Nothing "
                     "is wrong with your server.")
OFF_BUILD_UNLISTED = ("This report is checked on each Excellent Books version before it runs from "
                      "here. Your server runs %s; Excellent checks each new version within five "
                      "working days of its release. Until then, run this report in Excellent Books "
                      "itself. Nothing is wrong with your server.")
# Kaupo 2026-11-18: Excellent verified the server's build, but this report has not passed on it.
OFF_BUILD_REPORT_NOT_PASSED = ("This report has not passed Excellent's check on your Books version "
                               "yet. Run it in Excellent Books itself. Nothing is wrong with your "
                               "server.")


def off_its_build(doc: dict, session) -> Optional[str]:
    """The refusal text for a Books-window entry whose fields cannot be checked on this ERP,
    known without asking it: the session's version is not among the entry's checked builds.
    None when that is not the case (another entry, a checked build, or a version not known yet)."""
    version = getattr(session, "system_version", None)
    builds = erp_fields.checked_on(doc)
    if doc.get("spec_source") == "books-window" and version and version not in builds:
        status, until = control.build_status(version)
        if status == "verified":
            # The build is verified, this report is not among its checked builds.
            return OFF_BUILD_REPORT_NOT_PASSED
        # Only the version number of Books' own `systemversion` text goes out (Astra recheck of
        # ddce18b, MUST 4).
        from .erp import version_text

        shown = version_text(version)
        return OFF_BUILD_PENDING % (shown, until) if status == "pending"             else OFF_BUILD_UNLISTED % shown
    return None


def unverified(doc: dict, given: dict, session) -> dict:
    """The refusal for fields `erp_fields.allowed` could not check, with which of the two
    reasons it was: a list that could not be read, or a Books-window entry off its build."""
    off_build = off_its_build(doc, session)
    if off_build:
        return {"error": "fields_unverified", "id": doc.get("id"), "why": off_build}
    reason = UNVERIFIED_LIST
    needed = ["%s (%s)" % ((f.get("label") or n).replace("_", ""), n)
              for n, f in (doc.get("spec") or {}).items() if isinstance(f, dict) and f.get("required")]
    advice = UNVERIFIED_NEEDED % ", ".join(needed) if needed else UNVERIFIED_BARE
    return {"error": "fields_unverified", "id": doc.get("id"),
            "why": UNVERIFIED_FIELDS % (", ".join(sorted(given)), reason, advice)}


ALSO_ON_THIS_ERP = ". This ERP also declares %s, which this connector's catalogue does not have"
NOT_ON_THIS_ERP = ("this report on this ERP's version has no field(s) %s (the catalogue was read "
                   "from another Books version), and an unknown field restarts the ERP, so "
                   "nothing was sent. Here it accepts: %s")

# Boxes that reach write code which does not write today (docs/report-descriptions/v2/
# writing-reports.md: re-check after a source upgrade). A caller may send them; a default never.
# Keyed by RUN NAME: POS/fiscal-control-report-sweden is the cash-up program behind another
# window, and its default ticked the same box (opus review, 2026-10-04).
WRITE_REACHING_FLAGS = {
    "ProInvRn": {"flags[4]"},       # TS/project-invoicing: invoice building, stores commented out
    "CashupRn": {"flags[2]"},       # POS/cash-up and its twin: a helper that returns outside a maintenance
}
# A default that turns a common report into a timeout: the window opens the Transaction Journal
# in Detailed, and one month on the 40 GB database took 88 s even in Overview (run_report: 60 s).
COSTLY_DEFAULTS = {
    "TransRn": {"ArtMode"},         # NL/transaction-journal
    "SMJRn": {"ArtMode"},           # NL/simulation-journal
}


def client_defaults(doc: dict, given: dict, allowed=None) -> dict:
    """{field: value} of the window's defaults the caller left out (catalog `client_default`,
    read from the window's defaults hook by tools/window_defaults.py). A box the client ticks
    with 2 is still a ticked box. Only fields in `allowed` (`erp_fields.allowed`: what the
    customer's own ERP declares); None, cannot tell, is none at all."""
    if allowed is None:
        return {}
    blocked = {box(name) for name in boxes(ACTION_FLAGS, doc) | boxes(WRITE_REACHING_FLAGS, doc)
               | boxes(COSTLY_DEFAULTS, doc)}
    set_by_caller = {box(name) for name in given}
    out = {}
    for name, field in (doc.get("spec") or {}).items():
        value = field.get("client_default")
        if (value in (None, 0) or box(name) in set_by_caller or box(name) in blocked
                or name not in allowed):
            continue
        out[name] = bool(value) if field.get("type") == "boolean" else value
    return out


def _typed(value, field_type: Optional[str]):
    """Cast one value to the declared M4 type. The ERP is fed JSON, and a boolean sent as the
    string "1" is a different request from a boolean sent as true."""
    if field_type == "boolean":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if field_type == "integer":
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    if field_type == "number":
        try:
            return float(str(value).replace(",", "."))
        except (TypeError, ValueError):
            return value
    return value


# -- shaping the result ------------------------------------------------------------------
#
# The model never receives raw report output. Transaction Journal returned 14,825 rows for one
# month and Transaction Summary 1,582 in 215 seconds; handing that to a client wastes its
# context and answers nothing. Filter, total and truncate here, and say what was cut.

_COMPARISONS = (">=", "<=", "!=", ">", "<", "=")
_CONTAINS = "contains:"
# An ISO date or timestamp compares as text, which orders it correctly; the ERP's own
# `dd.mm.yyyy` would not, so only this shape qualifies. The cell is cut to the length of the
# value asked for, so `<=2026-09-30 15:38` includes 15:38:54 and `2026-09-30 15:38` is the
# whole minute (the server log, S8).
_ISO = re.compile(r"^\d{4}-\d\d-\d\d(?: \d{1,2}(?::\d{0,2}){0,2})?$")   # "…15:3" = 15:30-15:39

# Any report: the rows of one answer stay under this many characters of JSON, below what an MCP
# client accepts. Measured 2026-09-30: max_rows=20000 on the server log made 1,977,940 chars,
# the client refused it, and the turn was lost.
RESULT_CHARS = 80000


MANY_NEGATIONS = ("where %s: a list matches ANY of its values, so several \"!=\" in one list exclude "
                  "nothing - every row differs from one of them. Exclude one value, or list the "
                  "values wanted instead.")


def check_where(where: Optional[dict]) -> None:
    """Refuse a `where` that would match every row while reading as a filter (re-review 04.10,
    S5: ["!=;;;", "!=LOG"] kept the stock total row and doubled the sum)."""
    for name, condition in (where or {}).items():
        if isinstance(condition, (list, tuple)) and \
                sum(1 for c in condition if str(c).strip().startswith("!=")) > 1:
            raise SpecError(MANY_NEGATIONS % name)


def postprocess(records: list, select: Optional[list] = None, where: Optional[dict] = None,
                sums: Optional[list] = None, group_by: Optional[str] = None,
                max_rows: int = 200) -> dict:
    """Filter, total, group and truncate parsed report rows.

    `totals` and `groups` cover every row that matched `where`, not only the page returned —
    a total that quietly covered the first `max_rows` would be wrong in a way the reader
    cannot see.
    """
    columns = _columns(records)
    for name in list(where or {}):
        _require_column(name, columns, "where")
    check_where(where)
    if group_by:
        _require_column(group_by, columns, "group_by")
    for name in (sums or []):
        _require_column(name, columns, "sum")

    matching = [r for r in records
                if all(_matches(r.get(field), condition) for field, condition in (where or {}).items())]

    totals = {name: _total(matching, name) for name in (sums or [])}
    groups = _grouped(matching, group_by, sums or []) if group_by else []

    rows = matching[:max_rows]
    if select:
        for name in select:
            _require_column(name, columns, "select")
        rows = [{k: r.get(k) for k in select} for r in rows]

    return {
        "rows": rows,
        "row_count_total": len(matching),
        "row_count_before_where": len(records),
        "truncated": len(matching) > len(rows),
        "totals": totals,
        "groups": groups,
    }


def _columns(records: list) -> list:
    seen: dict = {}
    for record in records:
        for key in record:
            seen[key] = True
    return list(seen)


def _require_column(name: str, columns: list, where_used: str) -> None:
    if columns and name not in columns:
        raise SpecError("%s names column %r, which this report does not have. Columns: %s"
                        % (where_used, name, ", ".join(columns)))


def _total(records: list, column: str) -> float:
    return round(sum(n for n in (_as_number(r.get(column)) for r in records) if n is not None), 2)


def _grouped(records: list, column: str, sums: list) -> list:
    order: list = []
    buckets: dict = {}
    for record in records:
        key = record.get(column)
        key = "" if key is None else key
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(record)
    return [{"key": key, "count": len(buckets[key]),
             "sums": {name: _total(buckets[key], name) for name in sums}}
            for key in order]


def _code_equality(cell, condition) -> Optional[bool]:
    """Keep integer codes with leading zeros distinct during equality checks."""
    from .report_html import has_leading_zero

    got = str(cell).strip() if cell is not None else ""
    wanted = str(condition).strip()
    if got and any(has_leading_zero(value) and value.lstrip("-").isdecimal()
                   for value in (got, wanted)):
        return got == wanted
    return None


def _matches(cell, condition) -> bool:
    """One `where` clause. Equality preserves code spellings and can match numeric cells
    against textual numbers. A list matches any of its conditions."""
    if isinstance(condition, (list, tuple)):
        return any(_matches(cell, one) for one in condition)
    text = str(condition).strip()
    if text == "":
        # A blank element is not parsed into the row at all, so "" must match a missing cell:
        # where={"DueDate": ""} lists the undated invoices (order-register re-review M3).
        return cell is None or not str(cell).strip()

    if text.lower().startswith(_CONTAINS):
        return text[len(_CONTAINS):].strip().lower() in str(cell).lower()

    for operator_text in _COMPARISONS:
        if text.startswith(operator_text):
            raw = text[len(operator_text):].strip()
            iso = _iso_pair(cell, raw)
            if iso:
                got, wanted = iso
                return {">=": got >= wanted, "<=": got <= wanted, "!=": got != wanted,
                        ">": got > wanted, "<": got < wanted, "=": got == wanted}[operator_text]
            if operator_text == "=" and raw == "":
                return cell is None or not str(cell).strip()
            if operator_text in ("=", "!=") and not _ISO.match(raw):
                same = _code_equality(cell, raw)
                if same is not None:
                    return same if operator_text == "=" else not same
            wanted = _as_number(raw)
            got = _as_number(cell)
            # "=" and "!=" with a TEXT condition compare the text: before 2026-10-04 they compared
            # numbers only, so {"Location": "!=;;;"} matched nothing. A numeric condition stays
            # numeric (a blank cell is not "!=0": the balance sheet's 19 non-zero lines, not 111),
            # a missing cell never matches, and an ISO date against another form matches nothing.
            if wanted is None and operator_text in ("=", "!=") and cell is not None \
                    and not _ISO.match(raw):
                same = str(cell).strip().lower() == raw.lower()
                return same if operator_text == "=" else not same
            if operator_text == "!=" and wanted is not None and got is None \
                    and cell is not None and str(cell).strip():
                return True             # "!=10001" kept no text code such as ACME (re-review N3)
            if wanted is None or got is None:
                return False
            if operator_text == ">=":
                return got >= wanted
            if operator_text == "<=":
                return got <= wanted
            if operator_text == "!=":
                return got != wanted
            if operator_text == ">":
                return got > wanted
            if operator_text == "<":
                return got < wanted
            return got == wanted

    iso = _iso_pair(cell, text)
    if iso:
        return iso[0] == iso[1]
    same = _code_equality(cell, condition)
    if same is not None:
        return same
    wanted, got = _as_number(text), _as_number(cell)
    if wanted is not None and got is not None:
        return wanted == got
    return str(cell).strip().lower() == text.lower()


def fit_budget(shaped: dict, narrow: str = "where or select") -> dict:
    """Cut `rows` to RESULT_CHARS of JSON, keeping the first ones. Totals and groups are left
    alone — they already cover every matching row — and `budget_note` says what happened."""
    import json
    rows = shaped.get("rows") or []
    if len(json.dumps(rows, ensure_ascii=False)) <= RESULT_CHARS:
        return shaped
    kept, used = [], 2
    for row in rows:
        size = len(json.dumps(row, ensure_ascii=False)) + 2
        if used + size > RESULT_CHARS:
            break
        kept.append(row)
        used += size
    shaped["rows"] = kept
    shaped["truncated"] = True
    shaped["budget_note"] = ("returned %d of the %d matching rows: more would pass %d characters, "
                             "about what an AI client accepts in one answer. Totals and groups "
                             "cover all of them; narrow with %s to see the rest."
                             % (len(kept), shaped.get("row_count_total", len(rows)), RESULT_CHARS,
                                narrow))
    return shaped


def _iso_pair(cell, wanted: str) -> Optional[tuple]:
    """`(cell cut to the value's length, value)` when both are ISO dates or timestamps."""
    got = str(cell).strip()
    if _ISO.match(wanted) and _ISO.match(got) and len(got) >= len(wanted):
        return got[:len(wanted)], wanted
    return None


def _as_number(value) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    from . import report_html            # local: report_html owns the ERP's number format
    return report_html.to_number(value)


# -- running one, end to end ---------------------------------------------------------------


# %s is the refusal sentence. Local mode quotes Books' own words for troubleshooting.
# Hosted mode uses a fixed sentence so the Books text stays on the server.
_ACCESS_DENIED = (
    "%s It gives the same refusal for two different "
    "problems: the run name in the catalogue no longer matches this build, or the API user's "
    "access group lacks Full on the module row and the report window row. Check the access "
    "group first — it is the common one — then the run name."
)


def run(doc: dict, session, spec: dict, select: Optional[list] = None,
        where: Optional[dict] = None, sums: Optional[list] = None,
        group_by: Optional[str] = None, max_rows: int = 200,
        timeout: float = 60.0, join: Optional[dict] = None, raw: bool = False) -> dict:
    """`_run`, and a failure after sending names the client's defaults that went with it: a
    timeout with the Detailed mode ticked by default is narrowed by that box, not the period."""
    if COMPANY_UNPROVEN and _company(session) != 1:     # P6 fallback, before any HTTP
        return {"error": "company_unproven", "id": doc.get("id"), "why": COMPANY_UNPROVEN}
    seen: dict = {}
    result = _run(doc, session, spec, select, where, sums, group_by, max_rows, timeout, join, raw,
                  seen)
    if result.get("error") and seen.get("sending"):
        added = client_defaults(doc, spec or {}, seen.get("allowed"))
        if added:
            result["defaults_sent"] = sorted(added)
    return result


def probe_window_field(doc: dict, session, field: str, value, *, build: str,
                       timeout: float = 90.0) -> dict:
    """Test one parsed Books-window field and return only its outcome and counts."""
    from .erp import ErpError, HTTPException, RestApiNotAllowed, SignInAgain, VersionChanged

    not_sent = {"dispatched": False}
    if config.mode() != "local":
        return dict(not_sent, error="probe_unavailable")
    if not build or getattr(session, "system_version", None) != build or not getattr(session, "cookie", None):
        return dict(not_sent, error="probe_build_mismatch")
    if getattr(session, "usercode_resolved", False) is not True:
        return dict(not_sent, error="probe_usercode_unresolved")
    if COMPANY_UNPROVEN and _company(session) != 1:
        return dict(not_sent, error="company_unproven")
    if doc.get("spec_source") != "books-window" or doc.get("reader") or field not in (doc.get("spec") or {}):
        return dict(not_sent, error="bad_spec")
    probe = dict(doc, spec={field: doc["spec"][field]})
    seen: dict = {}
    try:
        result = _run(probe, session, {field: value}, timeout=timeout, raw=True, seen=seen, probe_field=field)
    except (RestApiNotAllowed, SignInAgain):
        result = {"error": "probe_session_lost"}
    except control.Stopped as exc:
        result = {"error": exc.refusal["error"]}
    except VersionChanged:
        result = {"error": "probe_build_mismatch"}
    except HTTPException:
        result = {"error": "unreachable"}
    except TimeoutError:
        result = {"error": "too_slow"}
    except (OSError, ErpError):
        result = {"error": "transport_error"}
    else:
        if seen.get("sending") and session.system_version != build:
            result = {"error": "probe_build_mismatch"}

    if error := result.get("error"):
        if not seen.get("sending"):
            return dict(not_sent, error=error)
        if error == "probe_field_refused":
            return {"error": error, "field": field}
        if result.get("parsed_books_reply") is True:
            return {"error": error, "parsed_books_reply": True}
        return {"error": error}
    return {"rows": len(result.get("records") or []), "seconds": result.get("seconds")}


def _probe_books_refusal(body: bytes, field: Optional[str] = None) -> Optional[dict]:
    from . import report_html

    # The report parser can extract an errstr from a fragment. Clearing a probe
    # reservation requires a complete Books error envelope.
    try:
        root = ElementTree.fromstring(report_html._decode(body))
    except ElementTree.ParseError:
        return None
    reply = root.find("res") if root.tag == "data" else None
    if reply is None or "errstr" not in reply.attrib:
        return None
    if field is not None and re.fullmatch(
            rf"""Invalid value for field (['"]){re.escape(field)}\1\.?""",
            reply.attrib["errstr"].strip()):
        return {"error": "probe_field_refused"}
    return {"error": "access_denied", "parsed_books_reply": True}


# P6 (Task 35, review 2026-11-17 M12): reports name their company with `compno` (erp.web_api).
# Measured on pkorea 2026-11-18, companies 1 and 4: each answers from its own company
# (docs/probes/2026-11-P6-company.md), so nothing is refused. Should Books ever answer from
# the wrong company, set COMPANY_UNPROVEN = COMPANY_UNPROVEN_TEXT: reports on any company but 1
# are then refused before any HTTP; register reads (REST /api/<n>) are unaffected.
COMPANY_UNPROVEN: Optional[str] = None
COMPANY_UNPROVEN_TEXT = (
    "Reports are tested on Books company 1 only, and this connector is set up for another "
    "company, so it does not run reports here: one could answer from the wrong company. "
    "Registers (find_records, show_documents) still answer from the configured company.")


def _company(session) -> Optional[int]:
    try:
        return session.cfg.company
    except Exception:            # cannot tell = not company 1
        return None


def _drop_log_read(session) -> None:
    try:
        del session._server_log_read
    except AttributeError:
        pass


def _run(doc: dict, session, spec: dict, select: Optional[list] = None,
         where: Optional[dict] = None, sums: Optional[list] = None,
         group_by: Optional[str] = None, max_rows: int = 200,
         timeout: float = 60.0, join: Optional[dict] = None, raw: bool = False,
         seen: Optional[dict] = None, *, probe_field: Optional[str] = None) -> dict:
    """Gate, build, call, parse, shape. Every failure comes back as a payload the model can
    act on, never as an exception and never as the ERP's own wording.

    `raw` hands back every parsed record unshaped — for code in this connector that reads a
    report itself (the bank balance, records.read_block) and must not lose rows to the model's
    row budget. The gate, the crash memory and the error handling are the same."""
    from . import report_html
    from .erp import (VERSION_CHANGED, ErpError, HTTPException, RestApiNotAllowed, SignInAgain,
                      VersionChanged, version_text)

    refusal = gate(doc, session)
    if refusal:
        if refusal.get("error") == "stopped":
            _drop_log_read(session)     # nor served from this session's saved log read
        return refusal

    try:
        if join:
            refusal = check_join(join)
            if refusal:
                return dict(refusal, id=doc.get("id"))
        # The customer's own fields for this window: read after every refusal that needs no ERP,
        # so a refused request never reaches it at all (once per Books version, then from disk).
        check_given(doc, spec or {})
        if join:
            refusal = _check_join_fields(session, join)
            if refusal:
                return dict(refusal, id=doc.get("id"))
        allowed = (erp_fields.allowed(session, doc) if probe_field is None
                   else frozenset({probe_field}))
        checked_on = getattr(session, "system_version", None)
        if seen is not None:
            seen["allowed"] = allowed
        # A Books-window entry off its checked builds is refused with no fields given too: its
        # text says to run it in Books (Task 22 gate, Sol SHOULD).
        if allowed is None and (spec or off_its_build(doc, session)):
            return unverified(doc, spec or {}, session)
        # The ERP's date format is read only if a date needs it, after every refusal above.
        sent = build_spec(doc, spec, date_format=lambda: dates.erp_format(session), allowed=allowed)
    except SpecError as exc:
        return {"error": "bad_spec", "id": doc.get("id"), "why": str(exc)}
    except control.Stopped as exc:          # before the broad handler: a stop is its own answer
        return dict(exc.refusal)
    except (OSError, ErpError, HTTPException) as exc:
        if isinstance(exc, (RestApiNotAllowed, SignInAgain)):   # answered as itself (round 2; Task 42)
            raise
        if probe_field is not None:
            error = "probe_build_mismatch" if isinstance(exc, VersionChanged) else "probe_date_lookup_failed"
            return {"error": error}
        if isinstance(exc, HTTPException):
            raise
        # Reading the date format, not running the report: never a crash to remember.
        return {"error": "unreachable", "id": doc.get("id"),
                "why": "the ERP could not be reached to read its date format: %s"
                       % safe_reason(exc)[:160]}

    # A reader of its own for a reply the table parser cannot read (S8, the server log).
    log_reader = doc.get("reader") == "server_log"
    reader_notes = []
    def _labelled(names):
        return ", ".join("%s (%s)" % ((doc["spec"][name].get("label") or name).replace("_", ""), name)
                         for name in names)
    added = client_defaults(doc, spec or {}, allowed)
    if added:
        reader_notes.append(DEFAULTS_NOTE % _labelled(added))
    elif allowed is None:
        left_out = client_defaults(doc, spec or {}, frozenset(doc.get("spec") or {}))
        if left_out:
            reader_notes.append(DEFAULTS_UNCONFIRMED % _labelled(left_out))
    if log_reader:
        from . import server_log
        # The size is a field the connector writes itself, after build_spec: it goes out only
        # when this ERP declares it (opus review 04.10, M1). Without it the server reads its own
        # default, about the last 100 KB (measured 04.10), and no bigger reread is tried.
        if allowed is not None and "long1" in allowed:
            sent, size_note = server_log.size(sent)
            reader_notes += [size_note] if size_note else []
        else:
            sent = {k: v for k, v in sent.items() if k != "long1"}
            reader_notes.append(server_log.UNSIZED_NOTE)

    # A re-login after the check (reading the date format, say) can reveal an upgraded ERP; the
    # fields were checked against the old build, so nothing is sent (re-review 04.10, S1).
    now_on = getattr(session, "system_version", None)
    if probe_field is not None:
        if now_on != checked_on or not session.cookie:
            return {"error": "probe_build_mismatch"}
    if checked_on and now_on and now_on != checked_on:
        return {"error": "unreachable", "id": doc.get("id"),
                "why": VERSION_CHANGED % (version_text(checked_on), version_text(now_on))}
    # The report's own stops again, right before it goes out: one may have arrived while the
    # fields were read (review 2026-11-18, MUST 2).
    stopped = (control.report_dispatch(doc) or log_refusal(doc, session)
               or crash_refusal(doc, session))
    if stopped:
        _drop_log_read(session)
        return stopped
    if probe_field is not None and getattr(session, "usercode_resolved", False) is not True:
        return {"error": "probe_usercode_unresolved"}
    if seen is not None:
        seen["sending"] = True
    try:
        if log_reader:
            got = server_log.read(session, doc, sent, timeout)
            bound = server_log.lower_bound((where or {}).get("Time"))
            first_kb = None
            bigger = server_log.reread_size(got.kb, got.report, bound) if "long1" in sent else None
            if bigger:
                first_kb, first_seconds = got.kb, got.seconds
                sent = dict(sent, long1=bigger)
                got = server_log.read(session, doc, sent, timeout)
                got.seconds += first_seconds
            report, response = got.report, types.SimpleNamespace(seconds=got.seconds)
            reader_notes += [n for n in (server_log.reuse_note(got),
                                         server_log.reach_note(report, bound, got.kb, first_kb))
                             if n]
        else:
            response = session.run_report(doc["window_class"], doc["repname"], sent,
                                          timeout=timeout)
            if getattr(response, "status", 200) != 200:
                if probe_field is not None:
                    if response.status in (401, 403):
                        return _probe_books_refusal(response.body) or {"error": "access_denied"}
                    if response.status == 408:
                        return {"error": "too_slow"}
                    error = "unreachable" if response.status >= 500 else "probe_unconfirmed"
                    return {"error": error, "id": doc.get("id")}
                failed = report_html.ReportError("the ERP answered HTTP %d" % response.status)
                failed.status = response.status
                raise failed
            report = report_html.parse_report(response.body)
            if probe_field is not None and not re.fullmatch(
                    rb"(?:\xef\xbb\xbf)?\s*(?:<\?xml[^>]*\?>\s*)?<report(?:\s[^>]*)?>.*</report>\s*",
                    response.body, re.DOTALL):
                return {"error": "probe_unconfirmed"}
    except report_html.ReportError as exc:
        if probe_field is not None and exc.errstr is not None:
            return _probe_books_refusal(response.body, probe_field) or {"error": "probe_unconfirmed"}
        if exc.errstr is not None:
            hosted = _hosted()
            # Hosted, Desktop and the plugin pass on neither Books' words nor the login (Astra
            # review of slice 2, MUST 4): the unconfirmed user code is the saved login itself.
            fixed = hosted or _stdio()
            detail = ("Excellent Books refused this report." if fixed else
                      "the ERP refused this report and said: %s." % exc.errstr)
            why = _ACCESS_DENIED % detail
            # The one clue that separates the two causes. If nothing confirmed the UserVc Code,
            # the connector is very likely sending a login e-mail where a Code belongs, and the
            # refusal is the ERP saying it does not know that user — not that rights are short.
            unconfirmed = getattr(session, "usercode_resolved", True) is False
            if unconfirmed and not fixed:
                why += (" NOTE: the UserVc Code for this connector was never confirmed, so %r "
                        "is being sent as `usercode` on trust. On many servers REST logs in "
                        "with an e-mail while the report endpoint wants the Code, and that "
                        "produces exactly this refusal. Check that before the access group, or "
                        "set EBMCP_USERCODE in `.env`."
                        % getattr(session, "usercode", None))
            elif unconfirmed and not hosted:
                why += STDIO_USERCODE_NOTE
            return {"error": "access_denied", "id": doc.get("id"), "why": why}
        status = getattr(exc, "status", None)
        if _stdio() and status:
            # The number is no secret and tells the person what to check (Astra recheck).
            why = "Excellent Books answered HTTP %d and returned no report." % status
        elif _hosted() or _stdio():
            why = "Excellent Books did not return a readable report."
        else:
            why = str(exc)
        return {"error": "report_error", "id": doc.get("id"), "why": why}
    except control.Stopped as exc:
        # The report request can stop during re-login after its first attempt.
        if seen is not None and probe_field is None:
            seen["sending"] = False
        return dict(exc.refusal)
    except (OSError, ErpError) as exc:
        if isinstance(exc, (RestApiNotAllowed, SignInAgain)):   # answered as itself (round 2; Task 42)
            raise
        if isinstance(exc, VersionChanged):     # the report was not resent on the new build
            if probe_field is not None:
                return {"error": "probe_build_mismatch"}
            if seen is not None:
                seen["sending"] = False
            return {"error": "unreachable", "id": doc.get("id"), "why": str(exc)}
        if isinstance(exc, TimeoutError):
            return {"error": "too_slow", "id": doc.get("id"),
                    "why": ("the report was still running after %g s. Most statistics reports "
                            "scan the whole customer or item register whatever period is asked "
                            "for, so this is usually scope rather than load." % timeout),
                    "advice": _how_to_narrow(doc)}
        if _looks_like_a_crash(exc):
            if probe_field is None or _hosted():
                _remember_hosted_crash(doc, session)
            scope = "this Books server" if _hosted() else "this connector"
            return {"error": "crashed_the_server", "id": doc.get("id"),
                    "why": ("running this report closed the ERP's connection, which is how a "
                            f"server restart looks from here. It will not be run again on {scope} "
                            "on this Books build. " + ("It needs a developer." if _hosted()
                                                       else CRASH_LIFT))}
        error = "transport_error" if probe_field is not None else "unreachable"
        return {"error": error, "id": doc.get("id"), "why": safe_reason(exc)[:200]}

    records = report.records()
    # Every private key is withheld from the WHOLE parsed report before anything narrows it: a
    # key printed one line per row loses its BEGIN and END rows to a join or a filter, and
    # server._finish could no longer tell its body lines from data (Task 22 gate, Sol SHOULD;
    # the join and raw paths, parked privacy SHOULD 1).
    records, keys_withheld = privacy.mask_private_keys(records)
    # Withheld already in the raw text (report_html.decode_checked): the answer still says so.
    keys_withheld += repr(report).count(privacy.PRIVATE_KEY_WITHHELD)
    before_join = len(records)
    joined_note = ""
    if join:
        # Asked again right before the lookup: a stop may have arrived while the report ran.
        stopped = control.register_refusal(join.get("register"))
        if stopped:
            return stopped
        try:
            records, joined_note = _join(session, records, join, _columns(records))
        except SpecError as exc:
            return {"error": "bad_spec", "id": doc.get("id"), "why": str(exc)}
        except control.Stopped as exc:
            return dict(exc.refusal)
        except (OSError, ErpError) as exc:
            if isinstance(exc, (RestApiNotAllowed, SignInAgain)):   # answered as itself (round 2; Task 42)
                raise
            return {"error": "join_failed", "id": doc.get("id"),
                    "why": "the report ran, but the %s lookup behind the filter failed: %s"
                           % (join.get("register"), safe_reason(exc)[:120])}

    if raw:
        return {"id": doc.get("id"), "records": records,
                "seconds": getattr(response, "seconds", None)}

    # The log arrives newest first. A lower Time bound asks for what happened FROM that time,
    # so it pages forward from the bound, oldest first; without one the newest page stays.
    page_from_bound = log_reader and bound is not None
    if log_reader:
        max_rows, cap_note = server_log.cap_rows(max_rows)
        reader_notes += [cap_note] if cap_note else []
    try:
        shaped = postprocess(records, select=select, where=where, sums=sums, group_by=group_by,
                             max_rows=(len(records) or 1) if page_from_bound else max_rows)
        # The HR cap judges the whole report: a join narrows rows like a `where` does.
        shaped["row_count_before_where"] = before_join
        if page_from_bound:
            unreached = not server_log.reached(report, bound)
            keep = min(max_rows, server_log.UNREACHED_ROWS) if unreached else max_rows
            shaped["rows"] = shaped["rows"][-keep:][::-1] if keep > 0 else []
            shaped["truncated"] = shaped["row_count_total"] > len(shaped["rows"])
            reader_notes.append(server_log.unreached_note(bound, len(shaped["rows"])) if unreached
                                else server_log.forward_note(bound))
        shaped = fit_budget(shaped)
        if keys_withheld:
            shaped["private_keys_withheld"] = keys_withheld
        if "budget_note" in shaped:
            reader_notes.append(shaped.pop("budget_note"))
    except SpecError as exc:
        # The guard already names every valid column; raised through the MCP tool it would
        # reach the model as a stack trace instead.
        return {"error": "bad_spec", "id": doc.get("id"), "why": str(exc)}
    shaped.update({
        "id": doc.get("id"),
        "repname": doc.get("repname"),
        "spec": sent,
        "seconds": round(getattr(response, "seconds", 0.0), 2),
        "layout": report.layout,
        "header": report.keys(),
        "empty": report.empty,
        "sections": list(dict.fromkeys(report.sections))[:20] if report.sections else [],
        "footer": report.footer,
        "notes": ([joined_note] if joined_note else []) + reader_notes + _notes(doc, report, shaped),
    })
    return shaped


# -- joining to a register the report cannot filter on ---------------------------------------

_JOIN_LIMIT = 20000


_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,31}$")


def check_join(spec: dict) -> Optional[dict]:
    """A join is a register read like any other, so it is refused BEFORE the report runs: by
    the secret gate (a filtered read of the user register answers "which records have this
    value" — opus review, 2026-10-01; a secret-named field likewise), and when its register or
    field is anything but a plain name, since both go into a URL. Returns a refusal, raises SpecError, or None."""
    column, register, field = spec.get("column"), spec.get("register"), spec.get("field")
    if not (column and register and field):
        raise SpecError("join needs column, register and field; got %r" % (spec,))
    if privacy.is_blocked(register):
        return privacy.refusal(register)
    for what, name in (("register", register), ("field", field)):
        if not _NAME.match(str(name)):
            raise SpecError("the join's %s must be a plain name such as CUVc or CountryCode, "
                            "not %r" % (what, name))
    # After the name check: a malformed field is a bad spec whatever it spells.
    secret = privacy.secret_fields([field])
    if secret:
        return {"error": "secret_field", "register": str(register), "fields": secret,
                "why": privacy.SECRET_FIELD_REFUSAL % ", ".join(secret)}
    return control.register_refusal(register)        # a stopped register stops a join too


def _check_join_fields(session, spec: dict) -> Optional[dict]:
    register = spec["register"]
    declared = register_fields.declared(session, register)
    if declared is None:
        return None
    missing = sorted({spec["field"], "Code"} - set(declared.get("header") or []))
    if not missing:
        return None
    return {"error": "unknown_field", "register": register, "unknown": missing,
            "why": ("This ERP's Export/Import Format listing for %s does not declare the "
                    "header field(s) %s needed for the join." % (register, ", ".join(missing)))}


def _join(session, records: list, spec: dict, columns: list) -> tuple:
    """Restrict rows to those whose `column` matches a record in another register.

    A sales report has no country filter, because country lives on the customer. So the codes
    are fetched once and the rows filtered here. `filter.<Field>=<value>` is the only filter
    syntax the REST API supports — no ranges, no LIKE, no OR — and getting it wrong returns
    every record, which makes the join silently do nothing.
    """
    from .erp import ErpError, list_records, reply_problems
    from .write_outcome import has_data_root

    column, register = spec.get("column"), spec.get("register")
    field, value = spec.get("field"), spec.get("value")
    if not (column and register and field):
        raise SpecError("join needs column, register and field; got %r" % (spec,))
    _require_column(column, columns, "join")

    response = session.rest_get("/%s" % register,
                                **{"filter.%s" % field: value, "fields": "Code",
                                   "limit": _JOIN_LIMIT})
    if response.status != 200:
        raise ErpError("HTTP %s" % response.status)
    joined = list_records(response.body, register)
    if not joined:
        if reply_problems(response.body, structured=True):
            raise ErpError("Excellent Books returned an error.")
        if not has_data_root(response.body):
            raise ErpError("Excellent Books did not return a data document.")
    codes = {_code_text(row["Code"]) for row in joined if row.get("Code")}

    if not codes:
        return [], ("no %s record has %s = %s, so there was nothing to match. That is a "
                    "different answer from this report having no rows for them."
                    % (register, field, value))

    kept = [r for r in records if _code_text(r.get(column)) in codes]
    note = ("restricted to the %d %s records where %s = %s; %d of %d rows matched."
            % (len(codes), register, field, value, len(kept), len(records)))
    if len(codes) >= _JOIN_LIMIT:
        note += (" The lookup hit its %d-record ceiling, so the filter may be incomplete —"
                 " narrow it before trusting the total." % _JOIN_LIMIT)
    return kept, note


def _code_text(value) -> str:
    """A customer code like 10000000 comes back from the parser as a float, and `str()` would
    make it "10000000.0" — which matches nothing, silently."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _how_to_narrow(doc: dict) -> str:
    """The window's own optional filters, which are the only honest answer to "too slow".

    A required field cannot narrow anything — it was already sent — so it is left out.
    """
    optional = [(name, f.get("label") or name)
                for name, f in (doc.get("spec") or {}).items() if not f.get("required")]
    if not optional:
        return ("This report declares no optional filters, so the only lever is a shorter "
                "period — or it may simply be too large to run over an API.")
    listed = ", ".join("%s (%s)" % (name, label) for name, label in optional[:8])
    return ("Narrow it with one of the report's own filters and run it again: %s. "
            "A shorter period helps too, but on this report scope usually matters more."
            % listed)


def _looks_like_a_crash(exc: Exception) -> bool:
    from .erp import looks_like_a_crash
    return looks_like_a_crash(exc)


def _notes(doc: dict, report, shaped: dict) -> list:
    notes = ["Column labels come back in the API user's own language, not the language asked "
             "for, so the table is read by position."]
    if report.empty:
        notes.append("The report ran and returned no table. That usually means a definition or "
                     "setting it depends on is missing, not that there is no data — this "
                     "entry's pitfalls say which.")
        # Quoted here so the model does not spend a turn on books_describe_report to find out
        # why: books_find_report sends it straight to run_report (S1), so this is where it learns.
        for pitfall in (doc.get("pitfalls") or [])[:4]:
            notes.append("Pitfall: %s" % _first_sentence(pitfall, 240))
    elif shaped["row_count_total"] and report.width <= 2:
        notes.append("This looks like the report's own title block rather than data: a narrow "
                     "result with very few rows is what an unfilled report prints.")
    if shaped["truncated"]:
        notes.append("Showing %d of %d rows; the totals cover all of them."
                     % (len(shaped["rows"]), shaped["row_count_total"]))
    return notes


# -- describing one ------------------------------------------------------------------------

def _first_sentence(text, limit: int = 160) -> str:
    text = " ".join(str(text or "").split())
    end = re.search(r"(?<=[.!?])\s", text)
    sentence = text[:end.start()] if end else text
    return sentence if len(sentence) <= limit else sentence[:limit - 1].rstrip() + "…"
