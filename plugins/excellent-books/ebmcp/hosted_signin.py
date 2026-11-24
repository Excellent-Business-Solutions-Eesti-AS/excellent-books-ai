"""Browser-bound Excellent Books sign-in for hosted OAuth."""
from __future__ import annotations

import hmac
import logging
import re
import secrets
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field
from html import escape
from math import ceil
from threading import Lock
from time import monotonic
from typing import Optional, Protocol
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlsplit

from pydantic import AnyHttpUrl
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from . import approval_page, config, control, erp, hosted, hosted_approve, page_texts, privacy

LOGIN_FAILURES = 5
HOST_FAILURES = 100
LOGIN_SUCCESSES = 20
_FAILURE_WINDOW = 15 * 60
_SUCCESS_WINDOW = 60 * 60
_COOKIE = "ebmcp_signin"
_APPROVAL_COOKIE = "ebmcp_approval_signin"
_BODY_LIMIT = 16 * 1024
_ROUTE = "/auth/books"
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_STATE = re.compile(r"[A-Za-z0-9_-]{1,256}")
_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": approval_page._REFERRER_POLICY,
}
_LOGGER = logging.getLogger(__name__)


class BooksLoginProvider(Protocol):
    def has_pending_books_login(self, state: str) -> bool:
        """Check whether this hosted authorization is pending and unexpired without consuming it."""
        ...

    def complete_books_login(self, state: str, connection: hosted.BooksConnection) -> str:
        """Consume the pending authorization once, store the grant, and return the code redirect.

        Raise ValueError if the state is no longer usable. Persist only OAuth grant metadata.
        The page publishes the in-memory connection before returning the redirect to the browser.
        """
        ...


_BudgetKey = tuple[str, str] | tuple[str, str, str]
_Attempt = tuple[_BudgetKey, _BudgetKey, _BudgetKey]


@dataclass
class _Bucket:
    completed: deque[float] = field(default_factory=deque)
    active: int = 0

    def expire(self, cutoff: float) -> None:
        while self.completed and self.completed[0] <= cutoff:
            self.completed.popleft()


class _LoginLimit:
    """Shared sliding failure budgets and separate success budgets."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._buckets: dict[_BudgetKey, _Bucket] = {}
        self._prune_at = 0.0

    @staticmethod
    def _window(key: _BudgetKey) -> int:
        return _SUCCESS_WINDOW if key[0] in ("address", "stepup") else _FAILURE_WINDOW

    def begin(self, address: str, host: str, user: str, *, stepup: str | None = None
              ) -> _Attempt | int:
        if stepup is None:
            success_key = ("address", hosted._rate_key(address))
            success_limit = LOGIN_SUCCESSES
        else:
            success_key = ("stepup", stepup)
            success_limit = hosted_approve.STEPUPS_PER_HOUR
        keys = (("user", host, user.strip().casefold()), ("host", host), success_key)
        with self._lock:
            now = monotonic()
            if now >= self._prune_at:
                for key, bucket in list(self._buckets.items()):
                    bucket.expire(now - self._window(key))
                    if not bucket.active and not bucket.completed:
                        del self._buckets[key]
                self._prune_at = now + 60

            retry = 0
            for key, limit in zip(keys, (LOGIN_FAILURES, HOST_FAILURES, success_limit)):
                bucket = self._buckets.get(key)
                if bucket is None:
                    continue
                cutoff = now - self._window(key)
                bucket.expire(cutoff)
                if len(bucket.completed) >= limit:
                    retry = max(retry, ceil(bucket.completed[-limit] - cutoff))
                elif key == success_key and len(bucket.completed) + bucket.active >= limit:
                    # Reserve room for a possible success, without charging the failure budgets.
                    retry = max(retry, 1)
                elif key[0] == "user" and len(bucket.completed) + bucket.active >= limit:
                    # Attempts still running count against one user's budget, so guesses started
                    # in parallel through many states cannot pass five (Task 40 recheck SHOULD).
                    # A 502 holds the room only while it runs; it is never charged.
                    retry = max(retry, 1)
            if retry:
                return retry
            if len(self._buckets) + sum(key not in self._buckets for key in keys) > hosted._MAX_TRACKED:
                return 60
            for key in keys:
                self._buckets.setdefault(key, _Bucket()).active += 1
            return keys

    def finish(self, keys: _Attempt, outcome: bool | None) -> None:
        with self._lock:
            now = monotonic()
            for key in keys:
                bucket = self._buckets[key]
                bucket.active -= 1
                if outcome is not None and (key == keys[-1]) == outcome:
                    bucket.completed.append(now)
                if not bucket.active and not bucket.completed:
                    del self._buckets[key]


@dataclass
class _LoginAttempt:
    limit: _LoginLimit
    user: str
    stepup: str | None = None
    reservation: _Attempt | None = None
    retry: int = 0
    outcome: bool | None = None

    def reserve(self, address: str, host: str) -> bool:
        token = _current_attempt.set(self)
        try:
            return login_allowed(address, host)
        finally:
            _current_attempt.reset(token)

    def finish(self) -> None:
        if self.reservation is not None:
            self.limit.finish(self.reservation, self.outcome)
            self.reservation = None


_current_attempt: ContextVar[_LoginAttempt] = ContextVar("books_login_attempt")


def login_allowed(address: str, host: str) -> bool:
    """Reserve a turn in the shared budget for the current form's login attempt."""
    attempt = _current_attempt.get()
    result = attempt.limit.begin(address, host, attempt.user, stepup=attempt.stepup)
    if isinstance(result, int):
        attempt.retry = result
        return False
    attempt.reservation = result
    return True


def _credentials_refused(exc: Exception) -> bool:
    return (isinstance(exc, (erp.SignInAgain, erp.RestApiNotAllowed))
            or isinstance(exc, HTTPError) and exc.code in (401, 403))


def _language(request: Request) -> str:
    return page_texts.language_from_header(request.headers.get("accept-language", ""))


@dataclass(frozen=True)
class _Form:
    state: str
    csrf: str
    server: str = ""
    company: str = "1"
    user: str = ""
    gdpr: bool = False
    hr: bool = False
    writes: bool = False


def _render(path: str, headers: dict[str, str], language: str, form: _Form | None = None,
            message: str = "", status: int = 200, retry: int = 0,
            writing: bool = False) -> HTMLResponse:
    """`writing`: hosted writing is switched on (EBMCP_HOSTED_WRITES), so the form carries the
    writing tick; without the switch there is no tick to give."""
    copy = page_texts.TEXTS[language]
    title = escape(copy["signin_title"])
    html = [f'<!doctype html><html lang="{language}"><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            f'<title>{title}</title><style>{approval_page._STYLE}</style><body><h1>{title}</h1>']
    if message:
        html.append(f'<p role="alert" class="status">{escape(copy[message])}</p>')
    if form is not None:
        # The hosted text of Task 50, in English on every page language: a draft until Kaupo signs
        # it off (Task 48), translated only after that (Task 53 left it). The page copy's
        # consent_gdpr_text is the Desktop text, wrong for hosted where answers pass through
        # Excellent's server.
        gdpr_text = privacy.gdpr_text("hosted")
        # Marked English inside a page in another language (Sol review of 849e1ca, NIT).
        gdpr_lang = ' lang="en"' if language != "en" else ""
        gdpr_checked = " checked" if form.gdpr else ""
        hr_checked = " checked" if form.hr else ""
        html.extend([
            f'<form method="post" action="{escape(path)}">',
            f'<input type="hidden" name="state" value="{escape(form.state)}">',
            f'<input type="hidden" name="csrf" value="{escape(form.csrf)}">',
            f'<p><label>{escape(copy["signin_address"])} '
            f'<input name="server" value="{escape(form.server)}" required></label></p>',
            f'<p><label>{escape(copy["company"])} '
            f'<input name="company" value="{escape(form.company)}" inputmode="numeric" '
            'pattern="[0-9]+" required></label></p>',
            f'<p><label>{escape(copy["books_user"])} '
            f'<input name="user" value="{escape(form.user)}" autocomplete="username" required>'
            '</label></p>',
            f'<p><label>{escape(copy["signin_password"])} '
            '<input type="password" name="password" autocomplete="current-password" required>'
            '</label></p>',
            f'<fieldset><legend>{escape(copy["consent_title_gdpr"])}</legend>',
            f'<label><input type="checkbox" name="gdpr" required{gdpr_checked}> '
            f'{escape(copy["signin_gdpr_tick"])}</label><div{gdpr_lang}>' + "".join(f"<p>{escape(para)}</p>" for para in gdpr_text.split("\n\n") if para.strip()) + f'</div>'
            '</fieldset>',
            f'<fieldset><legend>{escape(copy["consent_title_hr"])}</legend>',
            f'<p>{escape(copy["consent_hr_intro"])}</p><ol>',
        ])
        for n in range(1, 5):
            html.append(f'<li><strong>{escape(copy[f"consent_hr_{n}_head"])}</strong> '
                        f'{escape(copy[f"consent_hr_{n}_body"])}</li>')
        html.append(f'</ol><label><input type="checkbox" name="hr"{hr_checked}> '
                    f'{escape(copy["signin_hr_tick"])}</label></fieldset>')
        if writing:
            writes_checked = " checked" if form.writes else ""
            html.append(f'<p><label><input type="checkbox" name="writes"{writes_checked}> '
                        f'{escape(copy["signin_writes_tick"])}</label></p>')
            notice = page_texts.hosted_text("hosted_audit_notice", language)
            # Translated per language since Task 53; a page language without a translation shows
            # it in English, marked so (opus review of 45f, N6).
            marked = ' lang="en"' if language not in page_texts.HOSTED_TEXTS else ""
            html.append(f'<p{marked}>{escape(notice)}</p>')
        html.append(f'<button type="submit">{escape(copy["signin_submit"])}</button></form>')
    html.append("</body></html>")
    if retry:
        headers = {**headers, "Retry-After": str(retry)}
    return HTMLResponse("".join(html), status_code=status, headers=headers)


async def _read_form(request: Request) -> dict[str, str] | None:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return None
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > _BODY_LIMIT:
                return None
            body.extend(chunk)
        pairs = parse_qsl(body.decode("utf-8"), keep_blank_values=True,
                          errors="strict", max_num_fields=16)
    except (ValueError, ClientDisconnect):
        return None
    form = dict(pairs)
    return form if len(form) == len(pairs) else None


class _BrowserForms:
    def __init__(self) -> None:
        self.signing_key = secrets.token_bytes(32)
        self.limit = _LoginLimit()

    def csrf(self, binding: str) -> str:
        return hmac.digest(self.signing_key, binding.encode(), "sha256").hex()

    def approval_csrf(self, plan: str, browser: str) -> str:
        return self.csrf(f"approval.{browser}.{plan}")


def _browser_forms(mcp_server) -> _BrowserForms:
    # FastMCP registers the two route groups separately. Their state belongs to this app.
    forms = getattr(mcp_server, "_ebmcp_books_forms", None)
    if forms is None:
        forms = mcp_server._ebmcp_books_forms = _BrowserForms()
    return forms


def _approval_cookie_name(env) -> str:
    # Same rule as the approver cookies (opus review of 8e83038, N2): no prefix only on a
    # loopback HTTP issuer, never because dev mode is on with a public https issuer.
    prefix = "" if hosted_approve._loopback_http(env) else "__Host-"
    suffix = "_test" if hosted_approve.base_path(env) == "/test" else ""
    return prefix + _APPROVAL_COOKIE + suffix


def _approval_browser(request: Request, env) -> str:
    return hosted_approve._read_named_cookie(request.headers, _approval_cookie_name(env)) or ""


async def check_form(request: Request, env) -> Optional[Response]:
    """Validate the form's origin, browser cookie and CSRF before any Books work."""
    forms = request.state.books_forms
    stepup = request.state.approval_signin
    issuer = urlsplit(str(AnyHttpUrl(hosted._issuer(env))))
    origin = f"{issuer.scheme}://{issuer.netloc}"
    language = _language(request)

    def invalid(status: int = 400) -> HTMLResponse:
        if stepup:
            return HTMLResponse(approval_page.render_message("error", language=language),
                                status_code=status, headers=approval_page.HEADERS)
        return _render(hosted_approve.base_path(env) + _ROUTE, request.state.signin_headers,
                       language, message="signin_invalid", status=status)

    if request.headers.getlist("origin") != [origin]:
        return invalid(403)
    if stepup:
        if request.headers.getlist("sec-fetch-site") not in ([], ["same-origin"]):
            return invalid(403)
        status, data = await hosted_approve._read_approval_form(request, max_fields=6)
        if status != 200:
            return invalid(status)
        browser = _approval_browser(request, env)
        expected = forms.approval_csrf(data.get("plan", ""), browser)
    else:
        data = await _read_form(request)
        if data is None:
            return invalid()
        state = data.get("state", "")
        browser = request.cookies.get(_COOKIE, "")
        writing = hosted.writes_enabled(env)
        nonce = hosted_approve.read_nonce_cookie(request.headers, env) if writing else None
        if not _STATE.fullmatch(state) or (writing and nonce is None):
            return invalid()
        request.state.books_nonce = nonce
        expected = forms.csrf(f"{state}.{browser}")

    if (not _TOKEN.fullmatch(browser)
            or not hmac.compare_digest(data.get("csrf", "").encode(), expected.encode())):
        return invalid()
    if not erp.login_user_ok(data.get("user", "").strip() or "x"):
        # A colon would let Books read a different user than every later lookup (45d review S1).
        return invalid()
    request.state.books_form = data
    return None


def add_routes(mcp_server, provider: BooksLoginProvider, sessions: hosted.BooksSessions, env,
               approvers: hosted_approve.Approvers | None = None) -> None:
    """Register the two browser routes before FastMCP builds the Starlette app."""
    prefix = hosted_approve.base_path(env)
    cookie_path = prefix + "/auth"
    action = prefix + _ROUTE
    form_action = " ".join(("form-action 'self'", *sorted(hosted.redirect_origins(env))))
    csp = approval_page._CSP.replace("form-action 'self'", form_action)
    headers = {**_HEADERS, "Content-Security-Policy": csp}
    forms = _browser_forms(mcp_server)
    writing = hosted.writes_enabled(env)
    if writing and approvers is None:
        raise ValueError("Hosted writing needs an approver session store.")
    in_flight: set[str] = set()

    def page(language: str, form: _Form | None = None, message: str = "",
             status: int = 200, retry: int = 0) -> HTMLResponse:
        return _render(action, headers, language, form, message, status, retry, writing)

    def pending(state: str) -> bool:
        return bool(_STATE.fullmatch(state) and provider.has_pending_books_login(state))

    def invalid(language: str, status: int = 400) -> HTMLResponse:
        return page(language, message="signin_invalid", status=status)

    def unavailable(language: str) -> HTMLResponse:
        # Exceptions can contain submitted data. Emit only a fixed message.
        _LOGGER.warning("Hosted sign-in could not complete.")
        return page(language, message="signin_unavailable", status=503)

    @mcp_server.custom_route(_ROUTE, methods=["GET"])
    async def get(request: Request) -> Response:
        language = _language(request)
        state = request.query_params.get("state", "")
        try:
            usable = await run_in_threadpool(pending, state)
        except Exception:
            response = unavailable(language)
        else:
            if usable:
                browser = request.cookies.get(_COOKIE, "")
                if not _TOKEN.fullmatch(browser):
                    browser = secrets.token_urlsafe(32)
                # The writing tick starts ticked (Kaupo, 2026-11-19, design section 16).
                csrf = forms.csrf(f"{state}.{browser}")
                response = page(language, _Form(state, csrf, writes=writing))
                response.set_cookie(_COOKIE, browser, path=cookie_path,
                                    secure=True, httponly=True, samesite="lax")
            else:
                response = invalid(language)
        if writing:
            response.headers.append("set-cookie", hosted_approve.set_nonce_cookie(
                secrets.token_urlsafe(32), env))
        return response

    async def submit(request: Request, data: dict[str, str], language: str) -> Response:
        state, csrf = data.get("state", ""), data.get("csrf", "")
        nonce = request.state.books_nonce
        if state in in_flight:
            return page(language, message="signin_in_progress", status=409)
        in_flight.add(state)
        gate_owns_attempt = False
        attempt = _LoginAttempt(forms.limit, data.get("user", ""))

        def finish_attempt():
            in_flight.remove(state)
            attempt.finish()

        try:
            if not await run_in_threadpool(pending, state):
                return invalid(language)
            form = _Form(state, csrf, data.get("server", ""), data.get("company") or "1",
                         data.get("user", ""), data.get("gdpr") == "on", data.get("hr") == "on",
                         writing and data.get("writes") == "on")
            try:
                books_origin = hosted.check_destination(form.server, env)
            except hosted.NotAllowed:
                return page(language, form, "signin_address_refused", 400)
            if not form.gdpr:
                return page(language, form, "signin_gdpr_required", 400)
            try:
                api_base = config.compose_api_base(books_origin, form.company)
            except ValueError:
                return page(language, form, "signin_company_invalid", 400)
            password = data.pop("password", "")
            if not form.user.strip() or not password:
                return page(language, form, "signin_credentials_refused", 400)

            address = request.client.host if request.client else ""
            if not attempt.reserve(address, urlsplit(books_origin).netloc):
                return page(language, form, "signin_limited", 429, retry=attempt.retry)

            def sign_in():
                response, attempt.outcome = complete_sign_in(form, api_base, password, language, nonce)
                return response

            # Pending attempts have no grant yet. Group them by Books login.
            login_key = config.connection_id(config.Config(api_base, form.user, ""))
            gate_owns_attempt = True
            try:
                return await hosted.SERVER_GATE.run(books_origin, "signin:" + login_key, sign_in,
                                                    on_finished=finish_attempt)
            except hosted.Busy:
                return page(language, form, "signin_busy", 503)
        finally:
            if not gate_owns_attempt:
                finish_attempt()

    def complete_sign_in(form: _Form, api_base: str, password: str, language: str, nonce: str | None
                         ) -> tuple[Response, bool | None]:
        outcome = None
        try:
            cfg = config.Config(api_base, form.user, password, gdpr_consent=True)
            with sessions.sign_in(cfg) as (session, slot):
                outcome = True
                conn = hosted.BooksConnection(secrets.token_urlsafe(32), session, form.gdpr, form.hr,
                                              writes=form.writes)
                sessions.put(conn, slot)
                try:
                    redirect = provider.complete_books_login(form.state, conn)
                    if approvers is not None and nonce is not None:
                        token = approvers.handoff(conn.grant_id, redirect, nonce)
                        redirect = hosted_approve.attach_url(token, env)
                except Exception as exc:
                    try:
                        session.logout()
                    finally:
                        sessions.drop(conn.grant_id)
                    response = invalid(language) if isinstance(exc, ValueError) else unavailable(language)
                    return response, outcome
                return RedirectResponse(redirect, status_code=303, headers=headers), outcome
        except (hosted.Full, control.Stopped):
            return page(language, form, "signin_busy", 503), outcome
        except (OSError, erp.ErpError) as exc:
            if outcome is not None:
                return unavailable(language), outcome
            if _credentials_refused(exc):
                return page(language, form, "signin_credentials_refused", 401), False
            return page(language, form, "signin_unreachable", 502), outcome
        except Exception:
            return unavailable(language), outcome

    @mcp_server.custom_route(_ROUTE, methods=["POST"])
    async def post(request: Request) -> Response:
        language = _language(request)
        request.state.books_forms = forms
        request.state.approval_signin = False
        request.state.signin_headers = headers
        try:
            refusal = await check_form(request, env)
            if refusal is not None:
                return refusal
            return await submit(request, request.state.books_form, language)
        except Exception:
            return unavailable(language)
