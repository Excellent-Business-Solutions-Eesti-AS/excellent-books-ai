"""Browser authority for hosted write approvals, held in memory."""
from __future__ import annotations

import hmac
import logging
import re
import secrets
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from threading import Lock
from typing import Optional
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from pydantic import AnyHttpUrl
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from . import approval, approval_page, config, control, erp, hosted, page_texts, usage

MAX_APPROVERS = 2000
STRIKES = 10
STRIKE_SECONDS = 900
HANDOFF_SECONDS = 60
NONCE_SECONDS = 900
REFRESH_SECONDS = 3
STEPUPS_PER_HOUR = 6
_ATTACH = "/approve/attach"
_HEADERS = approval_page.HEADERS


def base_path(env) -> str:
    return urlsplit(str(AnyHttpUrl(hosted._issuer(env)))).path.rstrip("/")


def cookie_name(env) -> str:
    return "ebmcp_approver_test" if base_path(env) == "/test" else "ebmcp_approver"


@dataclass(frozen=True, repr=False)
class ApproverCookies:
    session: str
    binding: str


def _loopback_http(env) -> bool:
    """Dev mode on a loopback HTTP issuer: the one case whose cookies go without the __Host-
    prefix and Secure. Dev mode alone also allows an https public issuer, where a sibling could
    then plant the binding or the hand-off nonce (opus review of 8e83038, N2)."""
    if not hosted._dev(env):
        return False
    url = hosted._http_url(hosted._issuer(env))
    return url is not None and url.scheme == "http" and hosted._is_loopback(url.host)


def _host_cookie_name(name: str, env) -> str:
    prefix = "" if _loopback_http(env) else "__Host-"
    suffix = "_test" if base_path(env) == "/test" else ""
    return f"{prefix}{name}{suffix}"


def binding_cookie_name(env) -> str:
    return _host_cookie_name("ebmcp_approver_binding", env)


def set_approver_cookies(response: Response, cookies: ApproverCookies, env) -> None:
    secure = "" if _loopback_http(env) else "; Secure"
    attributes = f"HttpOnly{secure}; SameSite=Lax; Max-Age={hosted.MAX_SECONDS}"
    response.headers.append("set-cookie", f"{cookie_name(env)}={cookies.session}; "
                            f"{attributes}; Path={base_path(env)}/approve")
    response.headers.append("set-cookie", f"{binding_cookie_name(env)}={cookies.binding}; "
                            f"{attributes}; Path=/")


def nonce_cookie_name(env) -> str:
    return _host_cookie_name("ebmcp_handoff", env)


def _nonce_cookie(value: str, env, age: int) -> str:
    secure = "" if _loopback_http(env) else "; Secure"
    return f"{nonce_cookie_name(env)}={value}; HttpOnly{secure}; SameSite=Strict; Path=/; Max-Age={age}"


def set_nonce_cookie(value: str, env) -> str:
    return _nonce_cookie(value, env, NONCE_SECONDS)


def _named_cookies(headers, name: str):
    for header in headers.getlist("cookie"):
        for part in header.split(";"):
            key, _, value = part.partition("=")
            if key.strip() == name:
                value = value.strip()
                yield value[1:-1] if value.startswith('"') and value.endswith('"') else value


def _read_named_cookie(headers, name: str) -> Optional[str]:
    values = _named_cookies(headers, name)
    value = next(values, None)
    if next(values, None) is not None:
        return None
    return value or None


def read_approver_cookies(headers, env, approvers: "Approvers") -> ApproverCookies | None:
    """The browser's pair. Every approver value is read, since a sibling site can plant
    duplicates; the store picks the one this binding opens (opus review of 8e83038, S1)."""
    binding = _read_named_cookie(headers, binding_cookie_name(env))
    sessions = [value for value in dict.fromkeys(_named_cookies(headers, cookie_name(env))) if value]
    if binding is None or not sessions:
        return None
    return approvers.pick([ApproverCookies(session, binding) for session in sessions])


def read_nonce_cookie(headers, env) -> Optional[str]:
    return _read_named_cookie(headers, nonce_cookie_name(env))


def _decoded(text: str) -> str:
    """Percent-decoded until stable (a copied link may be encoded more than once)."""
    for _ in range(8):
        plain = unquote(text)
        if plain == text:
            break
        text = plain
    return text.casefold()


def _mentions_attach(text: str) -> bool:
    return _ATTACH in _decoded(text)


def _withheld_target(target: str) -> str:
    path, query_mark, _ = target.partition("?")
    if _decoded(path).rstrip("/").endswith(_ATTACH) and not _mentions_attach(path[:-1]):
        return path + ("?[withheld]" if query_mark else "")
    return "[target withheld]"


class AccessLogFilter(logging.Filter):
    """Keeps the one-time hand-off token out of the app's access log.

    Uvicorn 0.42 logs (client, method, target, http version, status) and its AccessFormatter
    unpacks exactly those five, so that shape is kept and only the target is changed. The token
    only ever travels in the target. A target that is the attach path keeps its path and loses
    its whole query; any other target that mentions the attach path, at any depth of percent
    encoding, is withheld whole. Nothing is decoded into the line. Any other record shape that
    mentions the attach path, and any error here, drops the line: the filter fails closed
    (Sol re-checks of 5c3bbcd and 65d0463).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            args = record.args
            if isinstance(args, tuple) and len(args) == 5 and type(args[2]) is str:
                if _mentions_attach(args[2]):
                    record.args = (*args[:2], _withheld_target(args[2]), *args[3:])
                return True
            return not _mentions_attach(f"{record.msg} {args!r}")
        except Exception:
            return False


def _hash(value: str) -> bytes:
    return sha256(value.encode()).digest()


@dataclass(repr=False)
class _ApproverSession:
    binding_hash: bytes
    csrf_key: bytes
    grants: dict[str, str]
    last_used: float
    strikes: deque[float] = field(default_factory=deque)


@dataclass(repr=False, frozen=True)
class _Handoff:
    grant_id: str
    redirect: str
    nonce_hash: bytes
    expires: float


class Approvers:
    def __init__(self, sessions: hosted.BooksSessions, clock=time.monotonic):
        self._sessions = sessions
        self._clock = clock
        self._lock = Lock()
        self._approvers: dict[bytes, _ApproverSession] = {}
        self._handoffs: dict[bytes, _Handoff] = {}
        # A Books drop calls back here with the Books lock held. Never acquire that lock
        # while holding the approver lock.
        sessions.add_drop_listener(self.forget)

    def handoff(self, grant_id: str, redirect: str, nonce: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            now = self._clock()
            for key, pending in list(self._handoffs.items()):
                if pending.expires <= now:
                    del self._handoffs[key]
            self._handoffs[_hash(token)] = _Handoff(grant_id, redirect, _hash(nonce),
                                                    now + HANDOFF_SECONDS)
        return token

    def redeem(self, token: str, nonce: Optional[str]) -> Optional[tuple]:
        with self._lock:
            pending = self._handoffs.pop(_hash(token), None)
            if (pending is None or pending.expires <= self._clock() or nonce is None
                    or not hmac.compare_digest(pending.nonce_hash, _hash(nonce))):
                return None
        return pending.grant_id, pending.redirect

    def _bound_entry(self, key: bytes, binding: str) -> _ApproverSession | None:
        """Look up a cookie pair with the approver lock held."""
        entry = self._approvers.get(key)
        if entry is not None and hmac.compare_digest(entry.binding_hash, _hash(binding)):
            return entry
        return None

    def pick(self, candidates: list[ApproverCookies]) -> ApproverCookies | None:
        """One approver value is passed on as it is; of several, the one whose entry this binding
        opens. Bindings are random per entry, so at most one matches, and a planted value never
        does: duplicates then cost nothing. None match: as no cookie (the sign-in form)."""
        if len(candidates) == 1:
            return candidates[0]
        with self._lock:
            found = [pair for pair in candidates
                     if self._bound_entry(_hash(pair.session), pair.binding) is not None]
        return found[0] if len(found) == 1 else None

    def attach(self, cookies: ApproverCookies | None, grant_id: str, via: str) -> ApproverCookies:
        fresh = ApproverCookies(secrets.token_urlsafe(32), secrets.token_urlsafe(32))
        csrf_key = secrets.token_bytes(32)
        with self._lock:
            old = None
            if cookies is not None:
                key = _hash(cookies.session)
                old = self._bound_entry(key, cookies.binding)
                if old is not None:
                    del self._approvers[key]
            grants = dict(old.grants) if old is not None else {}
            grants[grant_id] = via
            if len(self._approvers) >= MAX_APPROVERS:
                stalest = min(self._approvers, key=lambda key: self._approvers[key].last_used)
                del self._approvers[stalest]
            entry = _ApproverSession(_hash(fresh.binding), csrf_key, grants, self._clock())
            if old is not None:
                # strikes travel with the grants: a new sign-in does not wash them away
                # (Sol re-check of 7fd4980)
                entry.strikes = deque(old.strikes)
            self._approvers[_hash(fresh.session)] = entry
        # A drop can occur between proving the grant and publishing this entry.
        if not self._sessions.holds(grant_id):
            self.forget(grant_id)
        return fresh

    def _live_grants(self, key: bytes, binding: str) -> list[tuple[hosted.BooksConnection, str]]:
        with self._lock:
            entry = self._bound_entry(key, binding)
            if entry is None:
                return []
            entry.last_used = self._clock()
            grants = tuple(entry.grants)

        found = []
        for grant_id in grants:
            conn = self._sessions.peek(grant_id)   # looking is not using (NIT 3)
            if conn is None:
                self.forget(grant_id)
            else:
                found.append(conn)

        with self._lock:
            if self._approvers.get(key) is not entry:
                return []
            return [(conn, entry.grants[conn.grant_id]) for conn in found
                    if conn.grant_id in entry.grants]

    def connections(self, cookies: ApproverCookies) -> list:
        return [conn for conn, _ in self._live_grants(_hash(cookies.session), cookies.binding)]

    def find(self, cookies: ApproverCookies, plan_id: str) -> Optional[tuple]:
        key = _hash(cookies.session)
        for conn, via in self._live_grants(key, cookies.binding):
            plan = conn.plans.get(plan_id)
            if plan is not None:
                with self._lock:
                    entry = self._bound_entry(key, cookies.binding)
                    if entry is not None and conn.grant_id in entry.grants:
                        return conn, plan, via
        return None

    def csrf(self, cookies: ApproverCookies, plan_id: str, digest: str) -> str:
        with self._lock:
            entry = self._bound_entry(_hash(cookies.session), cookies.binding)
            if entry is None:
                return ""
            entry.last_used = self._clock()
            message = f"{len(plan_id)}:{plan_id}{digest}".encode()
            return hmac.digest(entry.csrf_key, message, "sha256").hex()

    def csrf_ok(self, cookies: ApproverCookies, plan_id: str, digest: str, token: str) -> bool:
        expected = self.csrf(cookies, plan_id, digest)
        return bool(expected) and hmac.compare_digest(expected.encode(), token.encode())

    def strike(self, cookies: ApproverCookies) -> bool:
        key = _hash(cookies.session)
        with self._lock:
            entry = self._bound_entry(key, cookies.binding)
            if entry is None:
                return False
            now = self._clock()
            entry.last_used = now
            while entry.strikes and entry.strikes[0] <= now - STRIKE_SECONDS:
                entry.strikes.popleft()
            entry.strikes.append(now)
            if len(entry.strikes) < STRIKES:
                return False
            del self._approvers[key]
            return True

    def forget(self, grant_id: str) -> None:
        with self._lock:
            for key, entry in list(self._approvers.items()):
                entry.grants.pop(grant_id, None)
                if not entry.grants:
                    del self._approvers[key]
            for key, pending in list(self._handoffs.items()):
                if pending.grant_id == grant_id:
                    del self._handoffs[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._approvers)


def attach_url(token: str, env) -> str:
    return f"{base_path(env)}{_ATTACH}?t={token}"


def add_attach_route(mcp_server, sessions: hosted.BooksSessions, approvers: Approvers, env) -> None:
    issuer_host = urlsplit(str(AnyHttpUrl(hosted._issuer(env)))).netloc
    allow_unforwarded = hosted._dev(env)

    def refused() -> HTMLResponse:
        return HTMLResponse("<!doctype html><html lang=en><title>Sign in again</title>"
                            "<p>Please sign in again.</p></html>", status_code=400, headers=_HEADERS)

    @mcp_server.custom_route(_ATTACH, methods=["GET"])
    async def attach(request: Request) -> Response:
        token = request.query_params.get("t", "")
        # The first attempt burns the token whatever its outcome (plan Step 3; opus review of
        # 45b, NIT 4): every refusal below redeems it first.
        def burned():
            approvers.redeem(token, None)
            return refused()
        # Starlette adds HEAD to GET routes automatically.
        if request.method != "GET":
            approvers.redeem(token, None)
            return Response(status_code=405, headers={**_HEADERS, "Allow": "GET"})
        forwarded = request.headers.getlist("x-forwarded-host")
        if "authorization" in request.headers:
            return burned()
        if forwarded != [issuer_host] and not (allow_unforwarded and not forwarded):
            return burned()
        handoff = approvers.redeem(token, read_nonce_cookie(request.headers, env))
        if handoff is None:
            return refused()
        grant_id, redirect = handoff
        if not sessions.holds(grant_id):
            return refused()
        fresh = approvers.attach(read_approver_cookies(request.headers, env, approvers), grant_id,
                                 "signin")
        response = RedirectResponse(redirect, status_code=303, headers=_HEADERS)
        set_approver_cookies(response, fresh, env)
        response.headers.append("set-cookie", _nonce_cookie("", env, 0))
        return response


_APPROVE = "/approve"
_DECLINE_ALL = "decline-all"
_SIGN_IN = "sign-in"
_FORM_LIMIT = 4096
_SIGN_IN_FIELDS = (
    ("server", "signin_address", "text", "off"),
    ("company", "company", "text", "off"),
    ("user", "books_user", "text", "username"),
    ("password", "signin_password", "password", "current-password"),
)


def _inbox_url(env) -> str:
    return str(AnyHttpUrl(hosted._issuer(env))).rstrip("/") + _APPROVE


def url(plan_id: str, env) -> str:
    return _inbox_url(env) + "/" + quote(plan_id, safe="")


def _timestamp(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _deadline(plan: approval.Plan) -> tuple[str, str]:
    expires = plan._created_wall + approval.PLAN_SECONDS
    if plan._approved_wall is None:
        return "hosted_preview_until", _timestamp(expires)
    expires = min(expires, plan._approved_wall + approval.APPROVAL_SECONDS)
    return "hosted_approval_until", _timestamp(expires)


def _write_refusal(conn, plan):
    if conn.plans.draining():
        exc = hosted.Draining()
        return {"error": exc.code, "why": str(exc)}
    refusal = conn.issue_refusal(fetch=False)
    if refusal:
        return refusal
    registers = {erp.rest_register(path, conn.session.cfg.api_base)
                 for _, path, _ in plan.envelope.writes}
    for register in sorted(registers - {None}):
        refusal = control.register_refusal(register, write=True)
        if refusal:
            return refusal
    return None


def _blocked(stopped, copy):
    """The page's sentence for a refusal: the restart notice in the browser's language (Sol review
    of 14fbad6, SHOULD-FIX; the tool answer stays English), any other as its policy wrote it."""
    if not stopped:
        return None
    if stopped.get("error") == hosted.Draining.code:
        return copy["hosted_draining"]
    return stopped["why"]


async def _read_approval_form(request: Request, *, max_fields=3) -> tuple[int, dict[str, str]]:
    lengths = request.headers.getlist("content-length")
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
            return 400, {}
        length = lengths[0].lstrip("0")
        if len(length) > 4 or (length and int(length) > _FORM_LIMIT):
            return 413, {}
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > _FORM_LIMIT:
                return 413, {}
            body.extend(chunk)
        types = request.headers.getlist("content-type")
        if (len(types) != 1 or types[0].split(";", 1)[0].strip().lower()
                != "application/x-www-form-urlencoded"):
            return 400, {}
        pairs = parse_qsl(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True,
                          errors="strict", max_num_fields=max_fields)
    except (ValueError, ClientDisconnect):
        return 400, {}
    form = dict(pairs)
    return (200, form) if len(pairs) == len(form) else (400, {})


class _ApprovalEndpoint:
    """Let the approval handler reply to all methods with its own response headers."""

    def __init__(self, handle):
        self.handle = handle

    async def __call__(self, scope, receive, send):
        response = await self.handle(Request(scope, receive))
        await response(scope, receive, send)


def add_routes(mcp_server, sessions, approvers, env) -> None:
    if not hosted.writes_enabled(env):
        return
    from . import hosted_signin

    inbox = _inbox_url(env)
    parts = urlsplit(inbox)
    origin = f"{parts.scheme}://{parts.netloc}"
    allow_unforwarded = hosted._dev(env)
    decline_all_url = inbox + "/" + _DECLINE_ALL
    sign_in_url = inbox + "/" + _SIGN_IN
    forms = hosted_signin._browser_forms(mcp_server)

    def show_sign_in(request, plan_id, language, copy, key="hosted_signin", status=200,
                     extra_headers=None):
        browser = hosted_signin._approval_browser(request, env)
        fresh = not hosted_signin._TOKEN.fullmatch(browser)
        if fresh:
            browser = secrets.token_urlsafe(32)
        body = approval_page.render_message(
            key, language=language, copy=copy, sign_in=sign_in_url,
            fields=_SIGN_IN_FIELDS, plan_id=plan_id, csrf=forms.approval_csrf(plan_id, browser),
        )
        response = HTMLResponse(body, status_code=status,
                                headers={**_HEADERS, **(extra_headers or {})})
        if fresh or status == 200:
            # a failure sets no cookie at all: the form's browser cookie is still the one it checked
            response.set_cookie(hosted_signin._approval_cookie_name(env), browser, path="/",
                                max_age=NONCE_SECONDS, secure=not _loopback_http(env),
                                httponly=True, samesite="strict")
        return response

    async def sign_in(request, cookies, language, copy):
        request.state.books_forms = forms
        request.state.approval_signin = True
        refusal = await hosted_signin.check_form(request, env)
        if refusal is not None:
            return refusal
        data = request.state.books_form
        password = data.pop("password", "")
        plan_id = data.get("plan", "")

        attached = []

        def failed():
            # One page for every failure after check_form, with the form again (45d review S3).
            response = show_sign_in(request, plan_id, language, copy, "hosted_signin_failed", 404)
            if attached:
                # attach already moved this browser's grants to the fresh pair and killed the old
                # one: a drop right after it must not cost the other connections (8e83038 N3)
                set_approver_cookies(response, attached[-1], env)
            return response

        try:
            # A browser that already approves for other connections may add this one: attach
            # merges its grants (45d review S2, design section 4).
            books_origin = hosted.check_destination(data.get("server", ""), env)
            user = data.get("user", "")
            api_base = config.compose_api_base(books_origin, data.get("company", ""))
            if not password or not user.strip():
                return failed()
            cfg = config.Config(api_base, user, "")
            # Admission uses the typed Books identity. It must give the same answer for
            # any plan id, including after successful logins made for unknown plans.
            login_key = config.connection_id(cfg)
            attempt = hosted_signin._LoginAttempt(forms.limit, user, stepup=login_key)
            address = request.client.host if request.client else ""
            if not attempt.reserve(address, urlsplit(books_origin).netloc):
                return show_sign_in(request, plan_id, language, copy, "hosted_signin_busy", 429,
                                    {"Retry-After": str(attempt.retry)})

            def prove():
                try:
                    try:
                        proof = erp.HostedSession.sign_in(replace(cfg, password=password))
                    except (OSError, erp.ErpError) as exc:
                        if hosted_signin._credentials_refused(exc):
                            attempt.outcome = False
                        return None
                    attempt.outcome = True
                    try:
                        return hosted._connection_label(proof)
                    finally:
                        try:
                            proof.logout()
                        finally:
                            proof.cookie = None
                finally:
                    usage.record("approval_proof_login")

            label = await hosted.SERVER_GATE.run(books_origin, "signin:" + login_key, prove,
                                                 on_finished=attempt.finish)
            if label is not None:
                for conn in sessions.matching(label):
                    if conn.plans.get(plan_id) is not None:
                        fresh = approvers.attach(cookies, conn.grant_id, "password")
                        attached.append(fresh)
                        if approvers.find(fresh, plan_id) is not None:
                            response = RedirectResponse(url(plan_id, env), status_code=303,
                                                        headers=_HEADERS)
                            set_approver_cookies(response, fresh, env)
                            return response
                        break
        except Exception:
            # Exception text can contain submitted data. Every refusal uses the same page.
            pass
        return failed()

    def pending(connections):
        return [(conn, plan) for conn in connections for plan in conn.plans.pending()]

    def queued(connections, copy, current=None):
        # Two plans with one target must not be two identical links (opus review of 45c, S2):
        # each entry names the operation and until when its preview is valid, and, when this
        # browser approves for more than one connection, whose Books user and company it is.
        several = len(connections) > 1
        entries = []
        for conn, plan in pending(connections):
            if plan.plan_id == current:
                continue
            key, until = _deadline(plan)
            # the plan id's tail separates two plans issued in the same second (Sol re-check)
            label = (f"{plan.envelope.target} ({plan.envelope.operation}, "
                     f"{copy[key].lower()} {until}, #{plan.plan_id[-6:]})")
            if several:
                label = (f"{copy['books_user']} {conn.user}, {copy['company'].lower()} "
                         f"{conn.company}: {label}")
            entries.append((label, url(plan.plan_id, env)))
        return entries

    def decline_all_form(cookies):
        return decline_all_url, approvers.csrf(cookies, _DECLINE_ALL, "")

    def show_plan(cookies, conn, plan, language, copy, *, message=None, blocked=None, status=200):
        if plan.state == "expired":
            status = 410
            message = "expired" if plan._approved_wall is None else "hosted_approval_expired"
        elif plan.state == "done" and (plan.outcome or {}).get("error") == "audit_unavailable":
            message = "hosted_audit_unavailable"
        elif plan.state != "pending":
            message = "hosted_approved" if plan.state == "approved" else plan.state
        waiting = plan.state == "pending"
        who = [
            ("hosted_client", conn.client[:hosted.CLIENT_NAME_CHARS] or copy["hosted_client_unknown"]),
            ("hosted_signin_time", _timestamp(conn.signed_in_at)),
        ]
        if plan.state in ("pending", "approved"):
            who.append(_deadline(plan))
        return HTMLResponse(approval_page.render_plan(
            plan, url(plan.plan_id, env), language=language, copy=copy, message=message,
            csrf=approvers.csrf(cookies, plan.plan_id, plan.envelope.digest()) if waiting else None,
            who=who, queued=queued(approvers.connections(cookies), copy, plan.plan_id),
            refresh=str(REFRESH_SECONDS) if plan.state in ("approved", "executing") else None,
            blocked=blocked, decline_all=decline_all_form(cookies) if waiting else None,
            hosted=True,
        ), status_code=status, headers=_HEADERS)

    async def handle(request: Request) -> Response:
        headers = request.headers
        language = hosted_signin._language(request)
        copy = page_texts.hosted_copy(language)

        def message(key, status, *, extra_headers=None):
            return HTMLResponse(approval_page.render_message(key, language=language, copy=copy),
                                status_code=status, headers={**_HEADERS, **(extra_headers or {})})

        if request.path_params.get("path", "") == _ATTACH.rsplit("/", 1)[1]:
            # Starlette gives a method other than GET/HEAD on the attach route to this catch-all.
            # The first attempt still burns the hand-off token (opus review of 45c, S1).
            approvers.redeem(request.query_params.get("t", ""), None)
            return message("error", 405, extra_headers={"Allow": "GET"})

        if "authorization" in headers:
            return message("error", 400)
        forwarded = headers.getlist("x-forwarded-host")
        if forwarded != [parts.netloc] and not (allow_unforwarded and not forwarded):
            return message("error", 400)
        cookies = read_approver_cookies(headers, env, approvers)

        path = request.path_params.get("path", "")
        plan_id, slash, action = path.partition("/")
        if path == _DECLINE_ALL:
            action, allowed = _DECLINE_ALL, "POST"
        elif path == _SIGN_IN:
            action, allowed = _SIGN_IN, "POST"
        elif not slash:
            allowed = "GET"
        elif plan_id and action in ("approve", "decline"):
            allowed = "POST"
        else:
            return message("gone", 404)
        if request.method != allowed:
            return message("error", 405, extra_headers={"Allow": allowed})

        def refused(status, key="error"):
            if cookies is not None:
                approvers.strike(cookies)
            return message(key, status)

        def answered(status, key="error"):
            # A state outcome (a double click, a click after a decline): no strike (45c review N1).
            return message(key, status)

        if allowed == "GET":
            if cookies is None:
                return show_sign_in(request, plan_id, language, copy)
            if not plan_id:
                connections = approvers.connections(cookies)
                if not connections:
                    return message("gone", 404)
                waiting = queued(connections, copy)
                return HTMLResponse(approval_page.render_list(
                    waiting, language=language, copy=copy,
                    decline_all=decline_all_form(cookies) if waiting else None,
                ), headers=_HEADERS)
            found = approvers.find(cookies, plan_id)
            if found is None:
                # A stale cookie, or one for other connections: the form, as without a cookie
                # (45d review S2). Known and unknown plan ids draw the same page.
                return show_sign_in(request, plan_id, language, copy)
            conn, plan, _ = found
            # 45c review N6; in a worker thread: the control lock may wait on a file lock, and an
            # approved page asks again on every refresh (Sol re-check of 1c932f4)
            stopped = (await run_in_threadpool(_write_refusal, conn, plan)
                       if plan.state in ("pending", "approved") else None)
            page = show_plan(cookies, conn, plan, language, copy,
                             blocked=_blocked(stopped, copy))
            # WHEN it was first drawn: the call's click phase starts there, not when its poller
            # next looks (Sol re-check of 186d2fc, finding 3). A refresh keeps the first time.
            # Stamped once the page exists, never before the policy check (Sol re-check of
            # eadb7c1, B2): a GET cancelled or failed before drawing starts no click phase.
            conn.opened.setdefault(plan_id, time.monotonic())
            return page

        if action == _SIGN_IN:
            # Duplicate approver cookies are no reason to refuse: the read above took the pair
            # this binding opens, or none (opus review of 8e83038, S1).
            return await sign_in(request, cookies, language, copy)

        if headers.getlist("origin") != [origin]:
            return refused(403)
        if headers.getlist("sec-fetch-site") not in ([], ["same-origin"]):
            return refused(403)
        status, form = await _read_approval_form(request)
        if status != 200:
            return refused(status)
        if cookies is None:
            return refused(403)
        token = form.get("csrf", "")
        if action == _DECLINE_ALL:
            connections = approvers.connections(cookies)
            if not connections or not approvers.csrf_ok(cookies, _DECLINE_ALL, "", token):
                return refused(403)
            # The token is bound to the browser, not to the list it was drawn with: a stale page
            # also declines plans issued after it. Accepted: a decline never writes (45c review N3).
            for conn, plan in pending(connections):
                with sessions.hold_connection(conn) as live:
                    latest = conn.plans.get(plan.plan_id) if live else None
                    if latest is None or latest.state != "pending":
                        continue
                    try:
                        conn.plans.decline(plan.plan_id)
                    except approval.ApprovalError:
                        continue
                usage.hosted_plan("declined")
            return RedirectResponse(inbox, status_code=303, headers=_HEADERS)

        found = approvers.find(cookies, plan_id)
        if found is None:
            return refused(404, "gone")
        conn, plan, via = found
        digest = plan.envelope.digest()
        if not approvers.csrf_ok(cookies, plan_id, digest, token):
            return refused(403)
        if not hmac.compare_digest(digest.encode(), form.get("digest", "").encode()):
            return refused(400)
        if plan.state != "pending":
            if plan.state == "expired":
                return show_plan(cookies, conn, plan, language, copy)
            return answered(409)

        acknowledged = form.get("ack") == "1"
        if action == "approve" and plan.envelope.needs_ack and not acknowledged:
            return show_plan(cookies, conn, plan, language, copy, status=400,
                             message="ack_required" + approval_page._ack_kind(plan.envelope))

        stopped = None
        transition = None
        if action == "approve" and not conn.plans.draining():
            # Refresh outside all connection and plan locks. Recheck held policy and browser
            # authority after the wait, just before the store changes state.
            await run_in_threadpool(control.may_write, hosted=True)
        with sessions.hold_connection(conn) as live:
            if not live:
                return refused(404, "gone")
            if not approvers.csrf_ok(cookies, plan_id, digest, token):
                return refused(403)
            latest = conn.plans.get(plan_id)
            if latest is None:
                return refused(404, "gone")
            if latest.state == "pending":
                try:
                    if action == "approve":
                        stopped = _write_refusal(conn, latest)
                        if stopped is None:
                            conn.plans.approve(plan_id, form["digest"], acknowledged, via=via)
                            transition = "approved"
                    else:
                        conn.plans.decline(plan_id)
                        transition = "declined"
                except hosted.Draining as exc:
                    stopped = {"error": exc.code, "why": str(exc)}
                except approval.Expired:
                    latest = conn.plans.get(plan_id)
                except approval.ApprovalError:
                    return answered(409)
        if transition is not None:
            usage.hosted_plan(transition)
        if latest is None:
            return refused(404, "gone")
        if latest.state == "expired" or stopped is not None:
            return show_plan(cookies, conn, latest, language, copy, status=409,
                             blocked=_blocked(stopped, copy))
        if latest.state != "pending":
            return answered(409)
        return RedirectResponse(url(plan_id, env), status_code=303, headers=_HEADERS)

    endpoint = _ApprovalEndpoint(handle)
    # The exact attach endpoint takes precedence over this route.
    mcp_server._custom_starlette_routes.extend([
        Route(_APPROVE, endpoint), Route(_APPROVE + "/{path:path}", endpoint),
    ])
