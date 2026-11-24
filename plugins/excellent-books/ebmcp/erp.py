"""Talking to one Excellent Books server: REST (`/api/N/…`) and WebExcellentAPI.

Session rule, measured in the HUGE database project and confirmed here: `Authorization: Basic`
goes out ONCE, to log in; every later call carries the `HSESSION` cookie. Each Basic login makes
the ERP build a whole server session (login plus user-context load), so per-call Basic hammers
it. The ERP drops idle sessions, so a 401/403 triggers exactly one re-login and retry — one, so
bad credentials cannot loop.

WebExcellentAPI honours the same cookie (measured 2026-09-14), so one login serves both APIs.
"""
from __future__ import annotations

import base64
import html
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from http.client import HTTPException
from threading import Event
from typing import Callable, Optional

from .config import Config
from . import approval


# A form without a charset is read as Latin-1 by the ERP: "OÜ" is stored as "OÃ" (measured 15.10).
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=UTF-8"


class ErpError(Exception):
    pass


class SignInAgain(ErpError):
    """A hosted connection needs a fresh sign-in from the user."""


class CallerTokenExpired(SignInAgain):
    """A hosted call outwaited the access token it came with: nothing more is sent, the grant
    stays (the client renews the token itself). A SignInAgain so every place that answers an
    ended session as itself answers this as itself too; the server tells the two apart."""


class NotSent(ErpError):
    """Stopped before any write left this connector: an executor reports it `not_attempted`
    (write_outcome.send_failure). A failed login before a write is one; so is a refused write."""


class UnapprovedWrite(NotSent):
    """Refused before any HTTP: no matching, live approval covers this write."""


class WritePolicyRefused(NotSent):
    """A write safety check stopped dispatch, with a reason safe to show to the person."""


WRITE_CHECK_FAILED = ("The write settings could not be checked before this change was sent. "
                      "Nothing was sent.")
GUARD_CHECK_FAILED = ("The connector's stop settings could not be checked before this change was "
                      "sent. Nothing was sent.")


class SignInAgainNotSent(SignInAgain, NotSent):
    """Hosted: the Books session ended before the first send of a write, so nothing left
    (blind judge of 3485c9a, SHOULD 3). Answered as SignInAgain, recorded not_attempted."""


class CallerTokenExpiredNotSent(CallerTokenExpired, NotSent):
    """Hosted: the caller's token expired before the first send of a write; nothing left."""


class DesktopWriteDeadline(WritePolicyRefused):
    def __init__(self):
        super().__init__("This call was running out of time, so the write was not sent.")


class WriteNotConnected(WritePolicyRefused):
    """The connection to Books was refused, or its name not found, before this write's first
    send: the socket never connected, so no byte of the request left (Astra recheck of ddce18b,
    judge (b)). Recorded not_attempted."""

    def __init__(self):
        super().__init__("Excellent Books could not be reached, so this write was not sent.")


def _never_connected(exc: BaseException) -> bool:
    """Only failures that happen before a socket connects: a refused connection (the server
    answered the connect with a reset) or a name that does not resolve. A timeout, a reset or a
    TLS failure can come after bytes left, so they are not here."""
    import socket

    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    return isinstance(reason, (ConnectionRefusedError, socket.gaierror))


class DesktopWriteTimeout(ErpError):
    def __init__(self):
        super().__init__("Books may have saved this record before the request timed out. "
                         "Check it in Excellent Books.")


class DesktopWriteBudget:
    """One apply call's budget, shared by its worker and its ERP requests."""

    READ_BACK_SECONDS = 5
    MIN_SEND_SECONDS = 5
    # 45 s send budget + 10 s batch read-back grace = 55 s < Desktop's ~60 s cutoff.
    # Control-file catch-up shares the time remaining in those windows.
    BATCH_READ_BACK_GRACE_SECONDS = 10

    def __init__(self, remaining: Callable[[], float], *, document: bool):
        self.remaining = remaining
        self.document = document
        self.stopped = False

    def can_write(self, remaining: Optional[float] = None) -> bool:
        if remaining is None:
            remaining = self.remaining()
        if remaining >= self.MIN_SEND_SECONDS + self.READ_BACK_SECONDS:
            return True
        self.stopped = True
        return False

    def check_write(self) -> None:
        if not self.can_write():
            raise DesktopWriteDeadline()

    def request_timeout(self, timeout: float, *, write_attempt: int = 0,
                        read_grace: bool = False) -> float:
        remaining = self.remaining()
        if write_attempt and not self.can_write(remaining):
            if write_attempt > 1:
                raise DesktopWriteTimeout()    # the first attempt was sent
            raise DesktopWriteDeadline()
        if not write_attempt and _desktop_batch_read_back.get():
            remaining += self.BATCH_READ_BACK_GRACE_SECONDS
        elif read_grace and self.document:
            # Keep the existing grace for document reads, including receipt stock reads.
            remaining = min(remaining + self.READ_BACK_SECONDS,
                            max(remaining, self.READ_BACK_SECONDS))
        if remaining <= 0:
            raise TimeoutError("The Desktop write call ran out of time.")
        return min(timeout, remaining)


desktop_write_budget: ContextVar[Optional[DesktopWriteBudget]] = ContextVar(
    "desktop_write_budget", default=None)
_desktop_batch_read_back: ContextVar[bool] = ContextVar("desktop_batch_read_back", default=False)
desktop_read_remaining: ContextVar[Optional[Callable[[], float]]] = ContextVar(
    "desktop_read_remaining", default=None)


def desktop_read_timeout(timeout: float) -> float:
    remaining = desktop_read_remaining.get()
    if remaining is not None:
        timeout = min(timeout, remaining())
        if timeout <= 0:
            raise TimeoutError("The Desktop read call ran out of time.")
    return timeout


@contextmanager
def desktop_batch_read_back():
    """Allow only the batch's final verification reads to use its extra time."""
    token = _desktop_batch_read_back.set(True)
    try:
        yield
    finally:
        _desktop_batch_read_back.reset(token)


def check_desktop_write_budget() -> None:
    if budget := desktop_write_budget.get():
        budget.check_write()


class WriteConnectionLost(ErpError):
    """Books may have saved the record before the connection failed."""

    def __init__(self, books_answering: bool, suspension_reason: str):
        super().__init__("Books stopped answering during the write; check in Excellent Books "
                         "whether the record was saved")
        self.books_answering = books_answering
        self.suspension_reason = suspension_reason


# Current callers: run_report (top level) and erp_fields.allowed (the `action=action`
# dispatcher's register). Two sets, so `action=action&register=report` is not a read
# (Task 11 review NIT).
READ_ACTIONS = frozenset({"report"})
READ_SUB_ACTIONS = frozenset({"getreportfilters"})


def _read_action(action: str, params: dict) -> bool:
    if action == "action":
        registers = params.get("register", [])
        return len(registers) == 1 and registers[0] in READ_SUB_ACTIONS
    return action in READ_ACTIONS


def _web_gate(url: str, method: str, server_root: str, company=None) -> tuple:
    """(web, read): whether `url` is a WebExcellentAPI call, and whether it is one allowlisted
    read. Parameter names case-folded: whether HAL reads `Action` as `action` is not measured,
    so `Action=x&action=report` counts as two actions and is refused. Shared by a first request
    and every redirect it receives (Sol re-check 2026-11-17, HIGH).

    A read also names exactly the configured `company`, once, as `compno` spelled so: Books
    answers from the company `compno` names whatever the cookie (P6), so a URL built anywhere
    but web_api, or a redirect, must not reach another one (Task 22 gate round 2, Sol SHOULD)."""
    parts = urllib.parse.urlsplit(url)
    web_path = urllib.parse.urlsplit(server_root).path + "/WebExcellentAPI.hal"
    params = {}
    for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        params.setdefault(key.casefold(), []).append(value)
    actions = params.get("action", [])
    web = "webexcellentapi" in urllib.parse.unquote(parts.path).casefold()
    compnos = [value for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
               if key.casefold() == "compno"]
    named = [key for key, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
             if key.casefold() == "compno"]
    read = (web and parts.path == web_path and method in ("GET", "POST")
            and len(actions) == 1 and _read_action(actions[0], params)
            and company is not None and compnos == [str(company)] and named == ["compno"])
    return web, read


class RedirectRefused(ErpError):
    """An authenticated request was redirected to another origin."""


def _same_origin(a: str, b: str) -> bool:
    def origin(url):
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
        if port is None:
            port = {"http": 80, "https": 443}.get(parsed.scheme)
        return parsed.scheme, parsed.hostname, port

    return origin(a) == origin(b)


class _SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    """Every redirect destination passes the gate a first request passes (Sol re-check
    2026-11-17, HIGH: an allowed GET was redirected to a same-origin `action=action&register=
    createsalesorderfromquotation` and followed): GET only, the same origin, and no
    WebExcellentAPI call that is not one allowlisted read. Refused before anything is sent to
    it. The ERP's web root rides on the request (`_ROOT`); a request without one is refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if getattr(req, _NO_REDIRECT, False):
            raise RedirectRefused("redirect refused for a single Books read")
        if req.get_method() != "GET":
            # A redirect changes the approved destination (302 can even turn POST into a
            # mutating GET). The original request was sent, so this is not UnapprovedWrite.
            raise RedirectRefused("redirect refused for a non-GET request")
        if not _same_origin(req.full_url, newurl):
            source = urllib.parse.urlsplit(req.full_url)
            target = urllib.parse.urlsplit(newurl)
            raise RedirectRefused("redirect refused from %s://%s to %s://%s" % (
                source.scheme, source.hostname, target.scheme, target.hostname))
        root = getattr(req, _ROOT, None)
        if root is None:
            raise RedirectRefused("redirect refused: no destination check for this request")
        web, read = _web_gate(newurl, "GET", root, getattr(req, _COMPANY, None))
        if web and not read:
            raise RedirectRefused("redirect refused to a WebExcellentAPI call that is not a "
                                  "read this connector makes")
        # Nor to another company's REST path: a cookie answers for whichever company the URL
        # names (P6), so a redirect must not choose one (Sol review of 59de990, SHOULD).
        rest = re.match(re.escape(urllib.parse.urlsplit(root).path) + r"/api/([0-9]+)(?:/|$)",
                        urllib.parse.urlsplit(newurl).path)
        if rest and int(rest[1]) != getattr(req, _COMPANY, None):
            raise RedirectRefused("redirect refused to another company")
        guard = getattr(req, _GUARD, None)
        if guard is not None:
            guard("GET", newurl)        # the signed control file's stops hold for the next hop
        before_send = getattr(req, _BEFORE_SEND, None)
        if before_send is not None:
            before_send()               # the connection is asked again before the cookie hops on
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            setattr(new, _ROOT, root)   # the next hop is checked the same way
            setattr(new, _COMPANY, getattr(req, _COMPANY, None))
            setattr(new, _GUARD, guard)
            setattr(new, _BEFORE_SEND, before_send)
        return new


_ROOT = "_ebmcp_server_root"
_COMPANY = "_ebmcp_company"
_GUARD = "_ebmcp_control_guard"
_NO_REDIRECT = "_ebmcp_no_redirect"
_BEFORE_SEND = "_ebmcp_before_send"
_UNSENT_WRITE = "_ebmcp_unsent_write"


def rest_register(url: str, api_base: str) -> Optional[str]:
    """The register a REST URL (or path) names: the first segment after the configured base's
    own path, so a base like /proxy/api/archive/api/1 is not misread. None for any other path."""
    base = urllib.parse.urlsplit(api_base).path.rstrip("/") + "/"
    path = urllib.parse.urlsplit(url).path
    if not path.startswith(base):
        return None
    first = path[len(base):].split("/", 1)[0]
    return urllib.parse.unquote(first) or None
class _SendCheck(urllib.request.BaseHandler):
    """Runs right before EVERY send: the first request and each redirect hop, after urllib has
    read the previous answer's body (http_error_302 drains it only after redirect_request). A
    request carrying `_BEFORE_SEND` asks its session again here (Sol re-check of b6967c4)."""

    handler_order = 1000            # after urllib's own pre-processors: nothing runs between

    def http_request(self, req):
        before_send = getattr(req, _BEFORE_SEND, None)
        if before_send is not None:
            try:
                before_send()
            except SignInAgain as exc:
                # A pre-processor runs before urllib opens any socket, so on a write's first hop
                # nothing has left yet (Astra recheck of ddce18b, judge SHOULD 3). A redirect hop
                # (never marked) stays a possible write.
                if not getattr(req, _UNSENT_WRITE, False) or isinstance(exc, NotSent):
                    raise
                kind = (CallerTokenExpiredNotSent if isinstance(exc, CallerTokenExpired)
                        else SignInAgainNotSent)
                raise kind(str(exc)) from None
        return req

    https_request = http_request


_OPENER = urllib.request.build_opener(_SameOriginRedirects, _SendCheck)


@dataclass
class Response:
    status: int
    body: bytes
    seconds: float
    content_type: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.text)


# -- the report endpoint's flag naming ---------------------------------------------------------
#
# `getreportfilters` declares a checkbox as `flags[0]` — its real name on the RcVc spec record,
# and the name the catalogue carries and the model uses. The report endpoint does not accept it
# that way. Its parser (ExcellentAPI.hal, ParseReportSpecValues) does, for any key beginning
# "flags", the equivalent of:
#
#     specIndex = mid(spec, 5, len(spec) - 5)      # "flags0"  -> "0"
#     specName  = "flags[" & specIndex & "]"       #           -> "flags[0]"
#
# so it wants the index BARE and re-brackets it itself. Handed `flags[0]` it builds
# `flags[[0]]`, and that restarted the ERP: three reports sat as `do-not-run` because of it,
# and no flag this tool advertised had ever actually been applied.
#
# `sflags[...]` must NOT be rewritten. The parser's test is `left(spec,5) == "flags"`, which
# "sflag" fails, so an sflags name falls through and is used verbatim — the convention is
# inverted between the two, which is worth knowing before "tidying" this.

_FLAG = re.compile(r"^flags\[(\d+)\]$")
# 2026-09-30, :4455 on 8.5.56.1369: `sflags0` sent to InvoiceRn restarted the ERP. hansa.log:
# "Field name not found in F4FieldNumber 1 sflags0", a backtrace, then the server came back up.
# The parser does not refuse a spec field the window lacks, it crashes on it. build_spec only
# lets declared names through; this refuses the one wrong spelling a "tidy" rewrite would make.
_BARE_SFLAG = re.compile(r"^sflags\d+$")
# 2026-10-01: the parser takes what follows "flags" as the index, so plain `flags` (declared by
# two Panama VAT windows, label "Lines") would go in as `flags[]` — the malformed-name class
# that restarts the ERP (correction 1). Inferred from the code, not measured.
_NO_INDEX_FLAG = re.compile(r"^s?flags$")


def _wire_spec(spec: dict) -> dict:
    """The spec as `action=report` wants it: declared names in, endpoint names out.

    Booleans go out as 1/0, never as JSON true/false. That is the quiet half of the same
    problem and it fails worse than the crash: measured 2026-09-14, `flags12` sent as `true`
    returned a 30-byte empty report while `1` returned all 231 accounts, and Budget Journal
    with `flags0: true` printed no "OKed Only" header — the flag was accepted, ignored, and
    nothing said so. A value that silently does nothing is worse than one that errors.
    """
    wire = {}
    for key, value in (spec or {}).items():
        if _BARE_SFLAG.match(key):
            raise ErpError("%s is not a spec field name — sflags go out bracketed, as "
                           "sflags[N]. Sent bare, the ERP restarts (measured 2026-09-30)." % key)
        if _NO_INDEX_FLAG.match(key):
            raise ErpError("%s has no index, so this connector cannot send it: the ERP reads a "
                           "flags name without one as a malformed field, which can restart it. "
                           "Run the report without this field." % key)
        match = _FLAG.match(key)
        wire["flags%s" % match.group(1) if match else key] = (
            int(value) if isinstance(value, bool) else value)
    return wire


VERSION_CHANGED = ("the ERP was upgraded from %s to %s while this connector was running. The "
                   "request was not resent: its fields were checked against the old build. "
                   "Plan it again (or run the report again).")
_VERSION = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,5}")


def version_text(value) -> str:
    """Only the version number of a Books build, for a message: `systemversion` is the ERP's own
    unvalidated text, so anything after the number is dropped (Astra recheck, MUST 4 residual)."""
    match = _VERSION.match(str(value or "").strip())
    return match.group(0) if match else "an unknown build"


# Measured on pkorea 2026-11-18 (docs/probes/2026-11-P1-P2.md): a user whose access group does
# not allow the action Rest API gets HTTP 405 and exactly this element on the login read.
_API_OFF = re.compile(r"\s*<error description='the resource api is not allowed'>\s*</error>\s*")
REST_API_NOT_ALLOWED = ("This Excellent Books user may not use the REST API. An administrator "
                        "can allow it in the user's access group (action Rest API).")


class RestApiNotAllowed(ErpError):
    """The login was refused because the REST API is off for this user."""


class VersionChanged(ErpError):
    """The ERP build changed during authentication; no non-GET is resent."""


class Session:
    _write_reset = "restart the connector"

    def __init__(self, cfg: Config, timeout: float = 120.0):
        self.cfg = cfg
        self.timeout = timeout
        self.cookie: Optional[str] = None
        self.usercode: Optional[str] = None
        # False means nothing confirmed the code — the configured value is being used on trust.
        # A report refusal says so, because that is the moment it explains the symptom.
        self.usercode_resolved = False
        # The Books build, from the login read's `<data systemversion=…>` echo. The report-field
        # gate (erp_fields.py) keys the customer's own window fields by it.
        self.system_version: Optional[str] = None
        # (method, url) -> None, raising before any socket: the signed control file's stops
        # (control.guard, called with api_base= and login=). The server sets it; a session made
        # elsewhere has none.
        self.guard: Optional[Callable[..., None]] = None
        # The connector alone can schedule field-list retries in its shared ERP turn.
        self.schedule_field_retry: Optional[Callable[..., None]] = None
        self._in_login = False          # True while login() resolves the user code
        # (method, url) -> None, raising NotSent: the connector's live check of its write switch,
        # connection and consent, right before every protected dispatch (Astra review of slice 2,
        # MUST 2). The server sets it; a session made elsewhere has none.
        self.write_check: Optional[Callable[[str, str], None]] = None
        self._writes_suspended = Event()

    def suspend_writes(self) -> None:
        self._writes_suspended.set()

    @property
    def write_suspension_reason(self) -> Optional[str]:
        if self._writes_suspended.is_set():
            return ("Writing is suspended. Check in Excellent Books whether the record was "
                    f"saved, then {self._write_reset} to resume writing.")
        return None

    def _still_signed_in(self, *, follow_redirects: bool = True) -> bool:
        # The same small CUVc read as sign-in, with no re-login if the cookie is refused.
        in_login, self._in_login = self._in_login, True
        try:
            response = self.request(self.cfg.api_base + "/CUVc?fields=Code&limit=1",
                                    timeout=15.0, follow_redirects=follow_redirects)
        finally:
            self._in_login = in_login
        # A proxy's sign-in page can also answer HTTP 200.
        return response.status == 200 and _answers_for_cuvc(response.body)

    def __repr__(self) -> str:
        return f"Session(origin={self.cfg.origin!r})"

    # -- login ---------------------------------------------------------------------------
    def login(self) -> None:
        # Never redirected: urllib would carry the Authorization header to the new path, and one
        # host can serve other applications beside Books (Astra review of slice 2, MUST 6).
        self._basic_login(follow_redirects=False)
        self._resolve_login_user()

    def _login_again(self) -> None:
        """After a 401/403: drop the cookie and log in again (the one re-login of `request`)."""
        self.cookie = None
        self.login()

    def _before_send(self) -> None:
        """Right before every dispatch. A configured login has nothing to check here."""

    def _basic_login(self, *, follow_redirects: bool = True) -> None:
        if not login_user_ok(self.cfg.user):
            # RFC 7617: a Basic user-id has no colon. Books splits at the first one, so
            # "A:b" + "c" logs in as A with password "b:c" while every later lookup by the
            # typed name reads "A:b" (opus review of 45d, S1). Refused before any request.
            raise ErpError("the user name cannot contain a colon or a control character")
        url = "%s/CUVc?fields=Code&limit=1" % self.cfg.api_base
        self._guard("GET", url, login=True)
        token = base64.b64encode(("%s:%s" % (self.cfg.user, self.cfg.password)).encode()).decode()
        request = urllib.request.Request(url, headers={"Authorization": "Basic " + token})
        setattr(request, _ROOT, self.cfg.server_root)
        setattr(request, _COMPANY, self.cfg.company)
        setattr(request, _NO_REDIRECT, not follow_redirects)
        setattr(request, _GUARD, self._hop_guard())     # a redirect hop is no login read
        try:
            budget = desktop_write_budget.get()
            timeout = (budget.request_timeout(self.timeout) if budget
                       else desktop_read_timeout(self.timeout))
            response = _OPENER.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 405 and _API_OFF.fullmatch(exc.read().decode("utf-8", "replace")):
                raise RestApiNotAllowed(REST_API_NOT_ALLOWED) from None
            if withholds_books_wording():
                # Desktop and the plugin keep the status only: Books' reason phrase can echo the
                # login or a cookie, and a re-login failure reaches report results (Astra
                # recheck of the slice 2 fix, MUST 4). Hosted sign-in does the same.
                raise _hosted_transport_error(exc) from None
            raise
        finally:
            # The login header holds the password in base64: gone before anything is raised or
            # kept (Task 39 review MUST-FIX).
            token = request = None
        with response:
            for header, value in response.getheaders():
                if header.lower() == "set-cookie" and "HSESSION=" in value:
                    self.cookie = value.split("HSESSION=", 1)[1].split(";", 1)[0]
            self.system_version = data_attrs(response.read()).get("systemversion") or None
        if not self.cookie:
            raise ErpError("login did not return an HSESSION cookie")

    def _resolve_login_user(self) -> None:
        # The user lookup is a REST read: a 401/403 on it must not log in again, or a user who
        # may log in but not read the user registers nests Basic logins (Task 22 gate, Sol SHOULD).
        self._in_login = True
        try:
            self.resolve_usercode()
        finally:
            self._in_login = False

    # -- the signed control file's check, before every socket ----------------------------
    def _guard(self, method: str, url: str, login: bool = False) -> None:
        """Raises (control.Stopped) when a stop or a lapsed lease refuses this request. Only
        the login read is exempt from register reading stops: it reads one CUVc code."""
        if self.guard is not None:
            self.guard(method, url, api_base=self.cfg.api_base, login=login)

    def _hop_guard(self, login: bool = False):
        """The same check for a redirect's next hop (carried on the urllib request)."""
        if self.guard is None:
            return None
        return lambda method, url: self._guard(method, url, login=login)

    # -- which user the REPORT endpoint thinks you are ------------------------------------
    #
    # Two different identifiers, used as one until Sven found it on a Latvian server,
    # 2026-09-16. REST authenticates with a login e-mail on many servers; `action=report` wants
    # the UserVc `Code`. Send the e-mail as `usercode` and every report is refused — and the
    # refusal reads like a rights problem, so the consultant checks access groups that were
    # never wrong. That is the expensive part: the symptom points away from the cause.
    #
    # Resolved ONCE, at login, and kept on the session like the cookie: one extra request per
    # session, not per call.
    #
    # It reads `fields=Code` and nothing else, deliberately. `UserVc` hands out password
    # material — `NewPassWord`, `PassWordAlgorithm`, the `SidC` set, two-factor state — to any
    # API user that can read it, which is why `privacy.py` blocks the register from every TOOL.
    # This internal read is the one exception and it stays exactly one field wide.
    #
    # Measured on the reference demo: 14 users, of which only 7 carry a `LoginEmailAddr` at
    # all, so the e-mail search misses for half of them and the rest of the chain is not
    # decoration.

    USER_REGISTERS = ("/UserVc", "/GlobalUserVc")

    def _first_code(self, path, *, only_row: bool = False, equals: Optional[str] = None,
                    **params) -> Optional[str]:
        """The `Code` a user-register read returns, or None. Never raises. Only `Code` is ever
        read from these registers (they hold password material).

        A row is never taken on position alone (opus review of 45d, S1): the code found here
        becomes the hosted connection's label and the report usercode. `only_row` refuses an
        answer of more than one row (a range read must name one user); `equals` refuses a code
        that is not the one asked for, case-insensitively."""
        try:
            response = self.rest_get(path, timeout=15.0, fields="Code", **params)
        except Exception:
            return None
        if getattr(response, "status", 200) >= 400:
            return None
        rows = [(register, fragment) for register in ("UserVc", "GlobalUserVc")
                for fragment in _elements(response.body, register)]
        if only_row and len(rows) != 1:
            # rows are counted, not codes: a second row without a Code still means "not one
            # user" (Sol re-check of 7fd4980)
            return None
        for _, fragment in rows:
            code = _field(fragment, "Code")
            if not code:
                continue
            if equals is not None and code.strip().casefold() != equals.strip().casefold():
                return None
            return code
        return None

    def resolve_usercode(self) -> str:
        """The UserVc Code for the configured user, looked up once and remembered.

        Order: an explicit override, then each user register by login e-mail, then each by code
        in case the configured value is already one. `GlobalUserVc` is searched because a user
        defined across companies on the same server is not in the company's own `UserVc`
        (Kaupo, 2026-09-16; the register was verified present and served).

        **A failure is not fatal.** Hard-erroring here would break every install where the API
        user cannot read UserVc but the configured value was already correct — which is the
        demo, and probably most customers. So the configured value stands and
        `usercode_resolved` stays False, and the report refusal says that it was never
        confirmed. The diagnosis arrives at the moment the symptom does, without a working
        install being broken to get it.
        """
        if self.cfg.usercode:
            self.usercode, self.usercode_resolved = self.cfg.usercode, True
            return self.usercode
        user = self.cfg.user
        if login_user_ok(user):
            by_email = [(path, dict(only_row=True, sort="LoginEmailAddr", range=user))
                        for path in self.USER_REGISTERS]
            by_code = [("%s/%s" % (path, urllib.parse.quote(user, safe="@")), dict(equals=user))
                       for path in self.USER_REGISTERS]
            # A login that looks like an e-mail is looked up by e-mail first; any other by its
            # own code first, so another user's e-mail field cannot claim it (Sol re-check).
            for path, params in (by_email + by_code if "@" in user else by_code + by_email):
                found = self._first_code(path, **params)
                if found:
                    self.usercode, self.usercode_resolved = found, True
                    return found
        self.usercode, self.usercode_resolved = self.cfg.user, False
        return self.usercode

    # -- one request, with the single re-login --------------------------------------------
    def request(self, url: str, body: Optional[bytes] = None, headers: Optional[dict] = None,
                timeout: Optional[float] = None, method: Optional[str] = None,
                approved=None, *, follow_redirects: bool = True) -> Response:
        """POST with a body, GET without; `method="PATCH"` updates the record at `url` in place
        (a POST there would create another one — see receipts.py).

        The one chokepoint (Task 11 review, 2026-11-17). Before any HTTP it refuses: another
        origin than the configured one (by scheme, host and port, so `host.` and the IP literal
        are other origins); a GET with a body; a header other than Content-Type (the approval
        covers method, path, query and body, not a Content-Length that cuts the body); any
        WebExcellentAPI call that is not one allowlisted read, whatever the verb (a GET there
        creates orders); and a POST or PATCH without the live approval of exactly these bytes.
        """
        method = (method or ("POST" if body is not None else "GET")).upper()
        if method in {"PUT", "DELETE"}:
            raise UnapprovedWrite("PUT and DELETE are not supported. Nothing was sent.")
        if not _same_origin(url, self.cfg.origin):
            raise UnapprovedWrite("This connector talks only to the configured Excellent Books "
                                  "server. Nothing was sent.")
        if method == "GET" and body is not None:
            raise UnapprovedWrite("A GET carries no body. Nothing was sent.")
        if any(str(name).casefold() != "content-type" for name in (headers or {})):
            raise UnapprovedWrite("Only Content-Type may be set on a request. Nothing was sent.")
        parts = urllib.parse.urlsplit(url)
        web, read = _web_gate(url, method, self.cfg.server_root, self.cfg.company)
        if web and not read:
            raise UnapprovedWrite("This WebExcellentAPI call is not a read this connector "
                                  "makes. Nothing was sent.")
        protected = method != "GET" and not read
        budget = desktop_write_budget.get()

        def guard(attempt):
            """The signed control file's check. Before the first send of a write, a check that
            cannot decide (its catch-up fetch failed, say) refuses cleanly: not_attempted, in
            fixed words (Astra recheck of 3485c9a, NEW MUST 2). A read keeps its own failure."""
            try:
                self._guard(method, url)
            except NotSent as exc:
                if protected and attempt == 2:
                    # The first attempt went out, so this is no pre-dispatch refusal.
                    stopped = ErpError("Writing was stopped during re-authentication; this "
                                       "write may already have reached Books.")
                    stopped.refusal = getattr(exc, "refusal", None)
                    raise stopped from exc
                raise
            except Exception:
                if not protected:
                    raise
                if attempt == 2:
                    raise ErpError("Writing was stopped during re-authentication; this write "
                                   "may already have reached Books.") from None
                raise WritePolicyRefused(GUARD_CHECK_FAILED) from None

        guard(1)                            # a stop refuses here, before any login or socket

        def matching_approval():
            return (isinstance(approved, approval.Approved) and approved.live()
                    and approved.matches(self.cfg.origin, self.cfg.company,
                                         self.usercode or self.cfg.user))

        triple = None
        if protected:
            if reason := self.write_suspension_reason:
                raise WritePolicyRefused(reason)
            # Executors store ASCII form text and send its ASCII bytes. Never parse/re-encode
            # the form: spaces, escapes, field order and the query must match exactly.
            form = body.decode("ascii") if isinstance(body, bytes) and body.isascii() else None
            triple = (method, urllib.parse.urlunsplit(("", "", parts.path, parts.query, "")), form)
            # Checked, not consumed: a login that fails next sent nothing (Task 11 review NIT).
            if not matching_approval() or form is None or not approved.peek_next(*triple):
                raise UnapprovedWrite("The approval does not cover this write. Nothing was sent.")
            if budget:
                budget.check_write()
        if not self.cookie:
            try:
                self.login()
            except NotSent:
                raise
            except RestApiNotAllowed as exc:
                if protected:      # nothing was sent: not_attempted, in its own words (round 2)
                    raise NotSent(REST_API_NOT_ALLOWED + " Nothing was sent.") from exc
                raise
            except Exception as exc:
                if protected:
                    if budget:
                        budget.check_write()
                    raise NotSent("Excellent Books could not be logged in to before this "
                                  "write, so nothing was sent.") from exc
                raise
        for attempt in (1, 2):
            if protected:
                register = rest_register(url, self.cfg.api_base)
                if register and register.casefold() == "vivc":
                    from .changes import vivc_build_reason

                    if reason := vivc_build_reason(register, self.system_version):
                        raise WritePolicyRefused(reason)
                # A preflight GET can re-login on a new build before this write starts.
                # Check the store-owned snapshot at dispatch as well as at the server gate.
                build = approved._store.get(approved.plan_id).payload.get("system_version")
                if build and build != self.system_version:
                    raise UnapprovedWrite("The Books build differs from the approved preview. "
                                          "Plan it again. Nothing was sent.")
            if protected and attempt == 2 and not matching_approval():
                # The single authentication retry: the first attempt may already have sent this
                # write, so this is not a pre-dispatch refusal (not_attempted).
                raise ErpError("The connection or approval changed during authentication; write stopped.")
            # Again right before this dispatch: a login or a re-login may have brought a stop.
            guard(attempt)
            if protected and self.write_check is not None:
                # The switch, connection and consent as they are now, after every read the
                # executor made since the approval was checked; the retry asks again. A check
                # that cannot decide (an unreadable settings file) refuses: before the first
                # send that is a clean not_attempted, never a write that may have landed
                # (Astra recheck of the slice 2 fix, NEW MUST).
                try:
                    self.write_check(method, url)
                except Exception as exc:
                    if attempt == 2:
                        stopped = ErpError("Writing was stopped during re-authentication; this "
                                           "write may already have reached Books.")
                        raise stopped from exc
                    if isinstance(exc, NotSent):
                        raise
                    raise WritePolicyRefused(WRITE_CHECK_FAILED) from None
            try:
                self._before_send()         # liveness at send time, not only at the call's start
            except SignInAgain as exc:
                if not (protected and attempt == 1) or isinstance(exc, NotSent):
                    raise
                # Before this write's first send nothing has left (blind judge, SHOULD 3). A
                # redirect hop asks again inside the send and stays a possible write.
                kind = (CallerTokenExpiredNotSent if isinstance(exc, CallerTokenExpired)
                        else SignInAgainNotSent)
                raise kind(str(exc)) from None
            # The send budget is decided before the entry is taken (Astra recheck of 3485c9a,
            # NEW MUST 2): running out of time here leaves the entry and the marker untouched.
            try:
                request_timeout = desktop_read_timeout(timeout or self.timeout)
                if budget:
                    request_timeout = budget.request_timeout(
                        request_timeout, write_attempt=attempt if protected else 0,
                        read_grace=not protected)
            except NotSent:
                raise
            except Exception:
                if protected and attempt == 1:
                    raise DesktopWriteDeadline() from None
                raise
            if protected and attempt == 1:
                # Login can resolve a different user: recheck after it, then consume the entry.
                # Consumed LAST, after every check that can refuse, so a refusal leaves the entry
                # unsent and the approval's counter where it was; after it only the socket can
                # fail (Astra recheck, NEW MUST; recheck of 3485c9a, NEW MUST 2).
                if not matching_approval() or not approved.take_next(*triple, cfg=self.cfg):
                    raise UnapprovedWrite("The connection or approval changed before dispatch. "
                                          "Nothing was sent.")
            hdrs = dict(headers or {})
            hdrs["Cookie"] = "HSESSION=%s" % self.cookie
            req = urllib.request.Request(
                url, data=body, headers=hdrs,
                method=method)
            setattr(req, _ROOT, self.cfg.server_root)
            setattr(req, _COMPANY, self.cfg.company)
            setattr(req, _NO_REDIRECT, not follow_redirects)
            setattr(req, _GUARD, self._hop_guard())
            setattr(req, _BEFORE_SEND, self._before_send)    # every redirect hop asks again
            # This request object is only ever the first hop (a redirect builds a new one): a
            # liveness refusal in its pre-send check is before any byte left (judge SHOULD 3).
            setattr(req, _UNSENT_WRITE, protected and attempt == 1)
            started = time.time()
            try:
                try:
                    with _OPENER.open(req, timeout=request_timeout) as r:
                        return Response(r.status, r.read(), time.time() - started,
                                        r.headers.get("Content-Type", ""))
                except urllib.error.HTTPError as exc:
                    if exc.code in (401, 403) and attempt == 1 and not self._in_login:
                        before = self.system_version
                        try:
                            if budget:
                                budget.request_timeout(self.timeout, write_attempt=2 if protected else 0)
                            self._login_again()
                        except NotSent as refused:
                            if not protected:
                                raise
                            # The first attempt went out: this write may have reached Books.
                            maybe = ErpError("Re-authentication was refused after this write was "
                                             "sent; it may already have reached Books.")
                            maybe.refusal = getattr(refused, "refusal", None)
                            raise maybe from refused
                        except Exception as failed:
                            if not protected:
                                raise
                            # Books answered this write, so it left: any re-login failure (a lost
                            # connection included) must not reach the outer handler, which would
                            # read it as the write's own first connect and say not_attempted
                            # (Astra final recheck: preserve uncertainty once Books has answered).
                            raise ErpError("Re-authentication failed after this write was sent; "
                                           "it may already have reached Books.") from failed
                        # A new build may have different fields. Do not resend the old request.
                        if before != self.system_version \
                                and (method != "GET" or "action=report" in url):
                            raise VersionChanged(VERSION_CHANGED % (
                                version_text(before), version_text(self.system_version)))
                        continue
                    return Response(exc.code, exc.read(), time.time() - started,
                                    exc.headers.get("Content-Type", "") if exc.headers else "")
            except (OSError, HTTPException) as exc:
                if budget and isinstance(getattr(exc, "reason", exc), TimeoutError):
                    if protected:
                        # The write may have landed. Latch without probing or resending it,
                        # and let the executor verify earlier successful writes.
                        self.suspend_writes()
                        budget.can_write()
                        raise DesktopWriteTimeout() from None
                    if not budget.document and not _desktop_batch_read_back.get():
                        budget.can_write()  # A preflight read may have used the send budget.
                if protected and attempt == 1 and _never_connected(exc):
                    # A protected request is never redirected, so this was its first and only
                    # hop: the connect itself failed and nothing left (judge (b)).
                    raise WriteNotConnected() from None
                if not protected or not _write_transport_lost(exc):
                    raise
            # Latch before the probe, and discard the transport exception's details.
            self.suspend_writes()
            try:
                answering = bool(self.cookie) and self._still_signed_in(follow_redirects=False)
            except Exception:
                answering = False
            raise WriteConnectionLost(answering, self.write_suspension_reason)
        raise ErpError("unreachable")

    # -- the two APIs ----------------------------------------------------------------------
    def rest_get(self, path: str, timeout: Optional[float] = None, **params) -> Response:
        """GET {api_base}{path}?params. Path starts with '/', e.g. '/IVVc/1234'.

        `timeout` is reserved, never a query parameter: the ERP has no such argument, and a
        register read CAN hang — sorting on a field a register carries but is not indexed on
        did not answer in 120 s on the demo database.
        """
        query = ("?" + urllib.parse.urlencode(params)) if params else ""
        return self.request(self.cfg.api_base + path + query, timeout=timeout)

    def web_api(self, action: str, body: Optional[dict] = None, timeout: Optional[float] = None,
                **params) -> Response:
        """/WebExcellentAPI.hal?action=…&usercode=… ; JSON body → POST.

        `usercode` is added from the config unless given: the server looks the user's access
        group up from it and answers "Access denied" without it — the same words it uses for a
        repname it cannot find, so check the name before blaming rights.
        """
        if not _read_action(action, {"register": [params.get("register", "")]}):
            raise UnapprovedWrite("This WebExcellentAPI action is not read-only. Nothing was sent.")
        # `compno` is the configured company, always, and last so no caller can name another:
        # Books answers from the company it names even on a cookie logged in to a different
        # one (P6, measured on pkorea 2026-11-18: docs/probes/2026-11-P6-company.md).
        params = {"action": action, "usercode": self.usercode or self.cfg.user, **params,
                  "compno": self.cfg.company}
        url = "%s/WebExcellentAPI.hal?%s" % (self.cfg.server_root, urllib.parse.urlencode(params))
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else None
        return self.request(url, data, headers, timeout)

    def sub_action(self, register: str, **params) -> Response:
        """The `action=action&register=<name>` family: getreportfilters, getstartupitems, …"""
        if register not in READ_SUB_ACTIONS:
            raise UnapprovedWrite("This sub-action is not read-only. Nothing was sent.")
        return self.web_api("action", register=register, **params)

    def run_report(self, window_class: str, repname: str, spec: dict,
                   timeout: Optional[float] = None) -> Response:
        """POST action=report. `lang` is ignored by the server (the API user's language decides),
        so it is not sent. Flag names are put into the shape this endpoint wants — see
        `_wire_spec`, and note that nothing else may call the endpoint around this method."""
        return self.web_api("report",
                            {"reportwindow": window_class, "repname": repname,
                             "spec": _wire_spec(spec)},
                            timeout=timeout)


def scrub_traceback(exc: BaseException) -> None:
    """Clear the locals of every finished frame in `exc`'s traceback and its chained exceptions.

    A failed sign-in (a wrong password, most often) raised an error whose frames held the Config
    with the password, the base64 token and the request with its Authorization header; any code
    that kept the exception kept the password (Task 39 review MUST-FIX). Frames still running
    cannot be cleared; their callers drop their own copies before re-raising."""
    import inspect

    # Generator and coroutine frames are left alone: on Python 3.11-3.12 clearing a SUSPENDED one
    # closes it under its caller (Sol re-check of 581e3b8); the login path has none.
    resumable = inspect.CO_GENERATOR | inspect.CO_COROUTINE | inspect.CO_ASYNC_GENERATOR
    seen, stack = set(), [exc]
    while stack:
        current = stack.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        tb = current.__traceback__
        while tb is not None:
            if not tb.tb_frame.f_code.co_flags & resumable:
                try:
                    tb.tb_frame.clear()
                except RuntimeError:        # still running: its own code drops its copies
                    pass
            tb = tb.tb_next
        stack += [current.__cause__, current.__context__]


# The envelope of a REST register read: the document's ROOT element is <data ...> (after an
# optional XML declaration), answering for CUVc by its register attribute or its first record.
# Not any "<data" in an HTML page or a comment (Sol re-checks of 6ff701b and b6967c4).
_ROOT_DATA = re.compile(rb"\s*(?:<\?xml[^>]*\?>\s*)?(<data(?:\s[^>]*)?/?>)\s*(<CUVc\b)?")


def _answers_for_cuvc(body) -> bool:
    match = _ROOT_DATA.match(body or b"")
    if not match:
        return False
    return data_attrs(match[1]).get("register") == "CUVc" or (
        "register" not in data_attrs(match[1]) and match[2] is not None)


_HOSTED_TRANSPORT_ERRORS = (OSError, SignInAgain, RedirectRefused)


def _hosted_transport_error(exc: Exception) -> Exception:
    """Keep status and exception type while discarding the original transport details."""
    original = exc
    if isinstance(exc, urllib.error.HTTPError):
        error = urllib.error.HTTPError("", exc.code, "Excellent Books returned an HTTP error.",
                                       None, None)
    elif isinstance(exc, CallerTokenExpired):
        # Nothing-sent stays nothing-sent (SignInAgainNotSent): the class is kept, the text fixed.
        error = (CallerTokenExpiredNotSent if isinstance(exc, NotSent) else CallerTokenExpired)(
            "This call's sign-in token expired while it waited.")
    elif isinstance(exc, SignInAgain):
        error = (SignInAgainNotSent if isinstance(exc, NotSent) else SignInAgain)(
            "Sign in to Excellent Books again.")
    elif isinstance(exc, RedirectRefused):
        error = RedirectRefused("Excellent Books redirected the request to a disallowed address.")
    else:
        if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, BaseException):
            original = exc.reason
        if looks_like_a_crash(exc):
            error = ConnectionResetError("Excellent Books closed the connection.")
        elif isinstance(exc, TimeoutError):
            error = TimeoutError("Excellent Books did not answer in time.")
        elif isinstance(original, TimeoutError):
            error = urllib.error.URLError(TimeoutError("Excellent Books did not answer in time."))
        else:
            error = OSError("Could not reach Excellent Books.")
    error.books_error_type = getattr(original, "books_error_type", type(original).__name__)
    return error


class HostedSession(Session):
    """A Books session established by one password sign-in and kept by its cookie."""

    _write_reset = "sign out and sign in again"

    @classmethod
    def sign_in(cls, cfg: Config, timeout: float = 20.0) -> HostedSession:
        """Establish a Books cookie in an already admitted sign-in worker."""
        from . import control

        session = cls(cfg, timeout)
        session.guard = control.hosted_guard       # its writes obey stop.hosted_writes too
        try:
            try:
                session._basic_login(follow_redirects=False)
            finally:
                session.cfg = replace(cfg, password="")
                cfg = None                  # this frame stays in a failure's traceback
            session._resolve_login_user()
        except BaseException as exc:
            if session.cookie:
                try:
                    session.logout()
                finally:
                    session.cookie = None
            scrub_traceback(exc)
            if not isinstance(exc, _HOSTED_TRANSPORT_ERRORS):
                raise
            error = _hosted_transport_error(exc)
        else:
            # The short timeout was for the login only; later calls get the normal one (N5).
            session.timeout = Session.__init__.__defaults__[0]
            return session
        raise error

    def request(self, url: str, body: Optional[bytes] = None, headers: Optional[dict] = None,
                timeout: Optional[float] = None, method: Optional[str] = None,
                approved=None, *, follow_redirects: bool = True) -> Response:
        try:
            return super().request(url, body, headers, timeout, method, approved,
                                   follow_redirects=follow_redirects)
        except _HOSTED_TRANSPORT_ERRORS as exc:
            error = _hosted_transport_error(exc)
        # A suppressed context still carries the original error object. Raise after handling it.
        raise error

    def login(self) -> None:
        raise SignInAgain("Sign in to Excellent Books again.")

    def _login_again(self) -> None:
        """No password is kept, so a 401/403 cannot be answered with a login. Books also answers a
        register this user may not read with HTTP 401 on a LIVE cookie (docs/probes/2026-11-P1-P2.md),
        so one read of what the sign-in itself read tells the two apart (Task 42): still answered,
        the call is resent once and its refusal returned as the person's own rights; refused too,
        the Books session has ended and the person signs in again."""
        if self.cookie and self._still_signed_in():
            return
        self.cookie = None
        raise SignInAgain("Sign in to Excellent Books again.")

    def _before_send(self) -> None:
        """A call resolves its connection, may wait for its turn, then sends: the connection is
        asked again here, so a revoke, a drop or the 12-hour end that came in between sends
        nothing, not even the dead cookie (Sol review of 59de990, MUST 2). `ended` is set by
        hosted.BooksConnection."""
        ended = getattr(self, "ended", None)
        if not self.cookie or (ended is not None and ended()):
            self.cookie = None
            raise SignInAgain("Sign in to Excellent Books again.")
        # The bearer is checked when the request arrives; a call that waited for its turn past
        # the token's end sends nothing more (Sol re-check of 6ff701b, MUST A).
        from . import hosted
        if hosted.caller_token_expired():
            raise CallerTokenExpired("This call's sign-in token expired while it waited.")

    def logout(self) -> bool:
        """Return False. No REST logout was documented on 2026-11-19.

        Source: https://api-docs.excellent.ee/rest-api-docs.html
        """
        return False


# -- reading REST list responses --------------------------------------------------------------
#
# `<data register='CUVc' …><CUVc register='CUVc' sequence='1123' url='…'><Code>C000001</Code>
#  <CountryCode>EE</CountryCode></CUVc>…</data>`
#
# Every element carries attributes, so a pattern looking for `<CUVc>` matches nothing and
# returns a plausible-looking zero. Match the tag followed by a word boundary.

_LEAF = re.compile(r"<([A-Za-z0-9_]+)>([^<]*)</\1>")
_DATA = re.compile(r"<data\b([^>]*)>")
# Either quote (valid-until re-check NIT: a double-quoted 1142 lost its diagnostic).
# A name starts the attribute: `request-range=` never answers as `range` (Sol review 41d7c81).
_ATTR = re.compile(r"""(?<![\w:.-])([A-Za-z0-9_]+)=(?:'([^']*)'|"([^"]*)")""")


def _attrs(text: str) -> dict:
    return {name: single or double for name, single, double in _ATTR.findall(text)}


# A connection the ERP dropped mid-request is how a server restart looks from here. Matched by
# TYPE first: on Windows a reset reads "[WinError 10054] An existing connection was forcibly
# closed by the remote host", and only the Linux wording was matched before (release review
# 10-05, I3). http.client.RemoteDisconnected is a ConnectionResetError.
_CRASH_TEXT = ("remote end closed", "remotedisconnected", "connection reset", "forcibly closed")


def looks_like_a_crash(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.URLError) and isinstance(getattr(exc, "reason", None),
                                                             BaseException):
        exc = exc.reason
    if isinstance(exc, ConnectionResetError):
        return True
    text = ("%s %s" % (type(exc).__name__, exc)).lower()
    return any(mark in text for mark in _CRASH_TEXT)


def _write_transport_lost(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return False
    if isinstance(exc, urllib.error.URLError):
        # urllib can wrap an exception or report the transport failure as text.
        return not isinstance(exc.reason, urllib.error.HTTPError)
    return isinstance(exc, (OSError, HTTPException))


def data_attrs(body) -> dict:
    """The `<data …>` element's own attributes — what the server thought it was asked.

    `register`, `sequence`, `systemversion`, `linkid`, `sort`, `key` and, when one was given,
    `range`. This is not bookkeeping: the ERP answers a span it cannot read in the key's own
    type by SUBSTITUTING one, and the substitute appears here and nowhere else. Measured
    2026-09-16 on the demo, `sort=DueDate&range=0:zzzzzzzz` came back
    `range='2026-09-01:2026-09-16'` — the current month — having returned 0 of 2,210 open
    invoices with an HTTP 200. `filter` is NOT echoed, which is why a filter can only be sent
    against a checked field list; see `ebmcp/records.py`.
    """
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
    found = _DATA.search(text[:2000])
    return _attrs(found.group(1)) if found else {}


_PROBLEM = re.compile(r"<(message|error)\b([^>]*)>")


def reply_problems(body, *, structured: bool = False) -> list:
    """What a write's reply complained about, in the order it said it.

    Measured on :4455 (8.5.56.1370, 2026-11-11), a company contact without a registration number:
    `<message description='Enter Reg.nr.1'/><error code='1501432' description='' field='RegNr1'/>`
    at HTTP 200, and no record. Two root elements, so it is read by shape, not as XML. This
    EXPLAINS a record the read-back did not find; it never decides whether one exists - a
    receipt create returned three errors and a correct record (receipts.py).
    """
    if not body:
        return []
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
    if "-----" in text:
        # Withheld before the elements split it into separate fields (Sol review of 03ad0bf,
        # MUST 1): the outcome is stored for the approval page as well as answered.
        from . import privacy
        text = privacy.mask_key_text(text)[0]
    problems = []
    structured = structured or withholds_books_wording()
    for kind, attrs in _PROBLEM.findall(text[:20000]):
        found = {k: html.unescape(v) for k, v in _attrs(attrs).items()}
        if structured:
            entry = _structured_problem(kind, found)
        elif kind == "message":
            entry = {"message": found.get("description", "")}
        else:
            entry = {"error": found.get("code", ""), "field": found.get("field", ""),
                     "row": found.get("row", ""), "description": found.get("description", "")}
        entry = {k: v for k, v in entry.items() if v}
        if entry:
            problems.append(entry)
    return problems


# Hosted: Books' own wording never leaves in a write outcome (Sol re-check of 186d2fc, finding 5):
# a diagnostic can echo the session cookie, and the outcome is stored for the approval page as
# well as answered. No sweep for that exists (privacy.mask_private_keys withholds private keys),
# so only the structured parts stay: the error code, a field NAME and a row number.
WITHHELD = ("Books' wording is not passed on by this connector: open the record in "
            "Excellent Books, or enter it there, to read Books' own message.")
_CODE = re.compile(r"[0-9]{1,12}")
_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,40}")


def _structured_problem(kind: str, found: dict) -> dict:
    if kind == "message":
        # Kept as a fact (Books said something) so a caller's "an error came back" test holds.
        return {"message": WITHHELD}
    code, field, row = (str(found.get(name, "")) for name in ("code", "field", "row"))
    return {"error": code if _CODE.fullmatch(code) else "",
            "field": field if _FIELD.fullmatch(field) else "",
            "row": row if _CODE.fullmatch(row) else "",
            # A refusal with neither a code nor a field still says one was there.
            "description": WITHHELD if not (_CODE.fullmatch(code) or _FIELD.fullmatch(field))
            else ""}


def withholds_books_wording() -> bool:
    """Hosted, Desktop and the plugin pass on only Books' codes, field names and row numbers: a
    Books diagnostic can echo the session cookie (Astra review of slice 2, MUST 4). The local
    developer install keeps Books' own words."""
    from . import config
    try:
        return config.mode() in ("hosted", "desktop", "plugin")
    except config.ConfigError:
        return False


def _hosted_mode() -> bool:
    from . import config
    try:
        return config.mode() == "hosted"
    except config.ConfigError:
        return False


def _elements(body: bytes, register: str) -> list:
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
    return re.findall(r"<%s\b[^>]*>(.*?)</%s>" % (re.escape(register), re.escape(register)),
                      text, flags=re.S)


def _field(fragment: str, field: str) -> Optional[str]:
    found = re.search(r"<%s\b[^>]*>(.*?)</%s>" % (re.escape(field), re.escape(field)),
                      fragment, flags=re.S)
    return found.group(1).strip() if found else None


def unescape(text: str) -> str:
    """XML entities arrive escaped. Re-escaping them for HTML without decoding first turns
    "Tom &amp; Co" into "Tom &amp;amp; Co" on the page."""
    return (text.replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&apos;", "'").replace("&amp;", "&"))


def list_records(body, register: str) -> list:
    """Every record as a flat dict of its own fields.

    Everything from `<rows` on is dropped: a register with matrix rows would otherwise flatten
    its last row into the record and overwrite the header's own `Sum` with a line's.
    """
    records = []
    for fragment in _elements(body, register):
        head = fragment.split("<rows", 1)[0]
        records.append({k: unescape(v.strip()) for k, v in _LEAF.findall(head) if v.strip()})
    return records


def list_lines(body, register: str) -> list:
    """Every record as one flat dict PER LINE: the header's fields, then the line's own.

    For a register whose answer is on its lines (Payments: which invoice, to whom, how much).
    A line field overrides a header field of the same name. A record without lines is one row
    of its header alone, so no record is lost from a count.
    """
    rows = []
    for fragment in _elements(body, register):
        head, _, rest = fragment.partition("<rows")
        header = {k: unescape(v.strip()) for k, v in _LEAF.findall(head) if v.strip()}
        lines = re.findall(r"<row\b[^>]*>(.*?)</row>", rest, flags=re.S)
        if not lines:
            rows.append(header)
        for line in lines:
            row = dict(header)
            row.update({k: unescape(v.strip()) for k, v in _LEAF.findall(line) if v.strip()})
            rows.append(row)
    return rows


def records_with_lines(body, register: str) -> list:
    """Every record as (its header fields, {line number from 1: that line's fields}). The line
    number is the row's own `rownumber` plus one, as show_documents numbers lines; a row
    without the attribute takes its place in the list."""
    out = []
    for fragment in _elements(body, register):
        head, _, rest = fragment.partition("<rows")
        header = {k: unescape(v.strip()) for k, v in _LEAF.findall(head) if v.strip()}
        lines = {}
        for place, (attrs, inner) in enumerate(
                re.findall(r"<row\b([^>]*)>(.*?)</row>", rest, flags=re.S)):
            number = re.search(r"""rownumber=['"](\d+)['"]""", attrs)
            lines[(int(number.group(1)) if number else place) + 1] = {
                k: unescape(v.strip()) for k, v in _LEAF.findall(inner) if v.strip()}
        out.append((header, lines))
    return out


def login_user_ok(user: str) -> bool:
    """A user name Basic can carry unambiguously: no colon, no control character."""
    return bool(user) and ":" not in user and not any(ord(c) < 32 or ord(c) == 127 for c in user)


def list_values(body, register: str, field: str) -> list:
    """Every record's `field`, in order. Records without it are skipped, not guessed at."""
    values = (_field(fragment, field) for fragment in _elements(body, register))
    return [v for v in values if v]


def list_pairs(body, register: str, key: str, field: str) -> dict:
    """`{key: field}` for records carrying both — the shape a join needs."""
    pairs = {}
    for fragment in _elements(body, register):
        code, value = _field(fragment, key), _field(fragment, field)
        if code and value:
            pairs[code] = value
    return pairs
