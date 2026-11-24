"""Loopback approval and consent pages. Only a validated HTTP POST can change state.

The bootstrap capability is exchanged once for an instance- and page-bound cookie.
Cookies alone are insufficient: POST also requires this page's CSRF token and the
exact Origin. This boundary assumes no hostile process controls the user's browser.
"""
from dataclasses import dataclass, field
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import secrets
import socket
import sys
import threading
import time
import unicodedata
from urllib.parse import parse_qs

from . import consent, page_texts, privacy
from .approval import (ApprovalError, ConnectionChanged, Declined, Expired, Finished, InProgress,
                       NotApproved, OwnerUnknown, UnfinishedWriteCheckRequired,
                       UnfinishedWriteUnavailable)
from .config import ConfigError
from .consent import consent_text


BOOTSTRAP_SECONDS = 120
RESULT_GRACE_SECONDS = 5
# An expired or declined preview keeps its page reachable this long after the server first sees
# it end, so a click after sleep or a long pause gets "the preview expired", not "site can't be
# reached" (review 2026-11-17 Task 13 MUST 1). Both clocks, as every other deadline here.
ENDED_GRACE_SECONDS = 120
_IDLE_POLL_SECONDS = 1
_BODY_LIMIT = 4096
# What a refused request may still send, in bytes and seconds, before its socket closes (finish).
_DRAIN_BYTES = 65536
_DRAIN_SECONDS = 1
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'")
# same-origin, not no-referrer: under no-referrer a browser sends "Origin: null" with the
# page's own form POST, and the strict Origin check refused every real click (review M1,
# measured in Edge 157 on 2026-11-17). A cross-origin request still sends no Referer.
_REFERRER_POLICY = "same-origin"
HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": _CSP,
    "Content-Type": "text/html; charset=utf-8",
}
_POST_ACTIONS = {"p": ("approve", "decline", "decline-all"), "c": ("on", "off"),
                 "s": ("save", "options", "forget")}
CONSENT_KINDS = ("hr", "gdpr")
# A loaded consent page answers for this long after its last request, on either clock: long
# enough to read the warnings, not a switch-on capability that outlives a closed tab for days
# (Task 27 review S3).
CONSENT_PAGE_SECONDS = 1800


def _text(value):
    # Keep addresses readable as text, without literal URL schemes in HTML bodies.
    return escape(str(value), quote=True).replace("://", "&#58;//")


def _equal(left, right):
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


@dataclass(frozen=True)
class _Consent:
    kind: str
    connection_id: str


@dataclass(frozen=True)
class _Settings:
    """The plugin's Connect Excellent Books page (settings_page.py): one target, its own route."""


SETTINGS = _Settings()


@dataclass(frozen=True)
class _Bootstrap:
    target: str | _Consent | _Settings
    deadline: float
    wall_deadline: float


@dataclass
class _Page:
    target: str | _Consent | _Settings
    cookie: str
    csrf: str
    active: bool = True
    seen: tuple = (0.0, 0.0)        # (monotonic, wall) of the last request (consent, settings)
    # Settings pages only (settings_page.py): the page language, the forms drawn (each form's own
    # token -> the settings revision, consent text and connection it was drawn for; Astra review
    # of slice 3, MUST 2 and 4), and each spent token's own submission and answer (a double
    # submit of the same form waits for ITS answer and sends no second login; Astra recheck,
    # NEW MUST 1).
    language: str | None = None
    forms: dict = field(default_factory=dict)
    results: dict = field(default_factory=dict)

    @property
    def route(self):
        if isinstance(self.target, _Settings):
            return "s"
        return "c" if isinstance(self.target, _Consent) else "p"


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    # HTTPServer sets SO_REUSEADDR; on Windows that lets another program bind the same port
    # and take the page over (review S3). Windows gets exclusive use of the address instead.
    allow_reuse_address = False
    allow_reuse_port = False

    def server_bind(self):
        if sys.platform == "win32":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def handle_error(self, request, client_address):
        # The standard implementation prints tracebacks, which may contain secrets.
        pass


class PageServer:
    def __init__(self, store, texts=page_texts, clock=time.monotonic, wall_clock=time.time):
        self.store = store
        self.texts = texts
        # Both clocks, as PlanStore: the monotonic one stops while a Mac sleeps.
        self._clock = clock
        self._wall = wall_clock
        self._lock = threading.RLock()
        self._instance = secrets.token_urlsafe(16)
        self._bootstraps = {}
        self._pages = {}
        self._server = None
        self._thread = None
        self._idle_timer = None
        self._done_seen = {}
        self._ended_seen = {}
        # Plans whose bootstrap was exchanged for a page at least once (Approvals relaunches a
        # window that was never loaded, review Task 13 S2).
        self._loaded = set()
        self.port = None

    def start(self):
        with self._lock:
            if self._server is not None:
                return
            server = _Server(("127.0.0.1", 0), _Handler)
            server.owner = self
            self.port = server.server_address[1]
            self._server = server
            self._thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            self._thread.start()
            self._schedule_idle_check(server)

    def _schedule_idle_check(self, server):
        # One daemon timer per running server. A generation check protects a restarted socket.
        def check():
            with self._lock:
                if self._server is not server:
                    return
                self._idle_timer = None
                self.stop_if_idle()
                if self._server is server:
                    self._schedule_idle_check(server)

        self._idle_timer = threading.Timer(_IDLE_POLL_SECONDS, check)
        self._idle_timer.daemon = True
        self._idle_timer.start()

    def stop_if_idle(self):
        with self._lock:
            if self._server is None:
                return
            active = self.store.active()
            # Observe completion even while other previews wait, without resetting its grace.
            known = {page.target for page in self._pages.values() if page.route == "p"}
            known.update(bootstrap.target for bootstrap in self._bootstraps.values()
                         if isinstance(bootstrap.target, str))
            for pid in known:
                plan = self.store.get(pid)
                if plan is None:
                    continue
                if plan.state == "done":
                    self._done_seen.setdefault(pid, (self._clock(), self._wall()))
                elif plan.state in ("expired", "declined"):
                    self._ended_seen.setdefault(pid, (self._clock(), self._wall()))
            grace = (self._within(self._done_seen, RESULT_GRACE_SECONDS)
                     or self._within(self._ended_seen, ENDED_GRACE_SECONDS))
            if active or grace:
                return
            # A loaded consent or settings page keeps the socket available for later withdrawal.
            # Retire write approval state on its own schedule even if that socket stays open.
            self._pages = {key: page for key, page in self._pages.items()
                           if page.route in ("c", "s")}
            self._bootstraps = {
                key: item for key, item in self._bootstraps.items()
                if isinstance(item.target, (_Consent, _Settings)) and self._bootstrap_alive(item)
            }
            self._done_seen.clear()
            self._ended_seen.clear()
            self._loaded.clear()
            self._pages = {key: page for key, page in self._pages.items()
                           if not self._consent_expired(page)}
            if self._pages or self._bootstraps:
                return
            # Hold the lifecycle lock through shutdown so start cannot reuse a closing socket.
            self._server.shutdown()
            self._server.server_close()
            self._thread.join()
            self._server = self._thread = None
            if self._idle_timer is not None:
                self._idle_timer.cancel()
                self._idle_timer = None

    def _within(self, seen, seconds):
        """Any first sighting still inside its grace on BOTH clocks (either one ends it)."""
        now, wall = self._clock(), self._wall()
        return any(now - mono < seconds and wall - at < seconds for mono, at in seen.values())

    def unopened(self, plan_id):
        """True when no page was ever loaded for the plan and no live bootstrap waits for it:
        the window was closed, or opened behind others and never seen."""
        with self._lock:
            if plan_id in self._loaded:
                return False
            return not any(item.target == plan_id and self._bootstrap_alive(item)
                           for item in self._bootstraps.values())

    def bootstrap_url(self, plan_id):
        with self._lock:
            if self.store.get(plan_id) is None:
                raise NotApproved("Unknown plan; make a new preview.")
            return self._bootstrap_url(plan_id)

    def _consent_expired(self, page):
        """A consent or settings page expires CONSENT_PAGE_SECONDS after its last request."""
        if page.route not in ("c", "s"):
            return False
        mono, wall = page.seen
        return (self._clock() - mono >= CONSENT_PAGE_SECONDS
                or self._wall() - wall >= CONSENT_PAGE_SECONDS)

    def consent_waiting(self, kind, connection_id):
        """True while a consent window for this kind and connection can still be used: its
        bootstrap is alive or its page was loaded and has not expired (Task 27 review S2)."""
        target = _Consent(kind, connection_id)
        with self._lock:
            if any(item.target == target and self._bootstrap_alive(item)
                   for item in self._bootstraps.values()):
                return True
            return any(page.target == target and page.active and not self._consent_expired(page)
                       for page in self._pages.values())

    def _language(self, language):
        """A page language the texts have, else the default. The pages follow the browser's
        Accept-Language, as the hosted ones (Sol review of 14fbad6, MUST-FIX)."""
        return language if language in self.texts.TEXTS else self.texts.DEFAULT_LANGUAGE

    def _consent_copy(self, language=None):
        language = self._language(language)
        return language, self.texts.TEXTS[language]

    def consent_bootstrap_url(self, kind, connection_id):
        if kind not in CONSENT_KINDS or not connection_id:
            raise ValueError("Consent requires a supported kind and a connection.")
        with self._lock:
            return self._bootstrap_url(_Consent(kind, connection_id))

    def settings_bootstrap_url(self):
        """A one-time address for the plugin's settings page; only the launcher sees it."""
        with self._lock:
            return self._bootstrap_url(SETTINGS)

    def discard_settings_bootstrap(self, url):
        with self._lock:
            bootstrap = self._bootstraps.get(url.rsplit("/", 1)[1])
            if bootstrap is not None and isinstance(bootstrap.target, _Settings):
                del self._bootstraps[url.rsplit("/", 1)[1]]
            self.stop_if_idle()

    def discard_consent_bootstrap(self, url):
        with self._lock:
            secret = url.rsplit("/", 1)[1]
            bootstrap = self._bootstraps.get(secret)
            if bootstrap is not None and isinstance(bootstrap.target, _Consent):
                del self._bootstraps[secret]
            self.stop_if_idle()

    def _bootstrap_url(self, target):
        self.start()
        self._bootstraps = {key: value for key, value in self._bootstraps.items()
                            if self._bootstrap_alive(value)}
        secret = secrets.token_urlsafe(16)
        self._bootstraps[secret] = _Bootstrap(target, self._clock() + BOOTSTRAP_SECONDS,
                                              self._wall() + BOOTSTRAP_SECONDS)
        return f"http://127.0.0.1:{self.port}/a/{secret}"

    def _bootstrap_alive(self, bootstrap):
        return self._clock() < bootstrap.deadline and self._wall() < bootstrap.wall_deadline

    def _exchange(self, bootstrap):
        target = bootstrap.target
        if isinstance(target, _Settings):
            # One loaded settings page at a time: a newer tab ends an older tab's authority.
            for page_id, page in list(self._pages.items()):
                if page.route == "s":
                    del self._pages[page_id]
        elif isinstance(target, _Consent):
            # One loaded page per kind AND connection keeps withdrawal available without
            # accumulating tabs' authority; another connection's tab stays alive (Sol re-check
            # of fb866b9). Replace it only once the browser has loaded the next one.
            for page_id, page in list(self._pages.items()):
                if isinstance(page.target, _Consent) and page.target == target:
                    del self._pages[page_id]
        else:
            self._loaded.add(target)
        page_id = self._instance + "_" + secrets.token_urlsafe(16)
        authority = _Page(target, secrets.token_urlsafe(32), secrets.token_urlsafe(32),
                          seen=(self._clock(), self._wall()))
        self._pages[page_id] = authority
        return page_id, authority

    def _render(self, plan=None, page_id=None, authority=None, message=None, language=None):
        language = self._language(language)
        copy = self.texts.TEXTS[language]
        if plan is None:
            return render_message(message, language=language, copy=copy)
        csrf = None
        queued = []
        refresh = None
        path = f"/p/{page_id}"
        if authority is not None and authority.active and plan.state == "pending":
            csrf = authority.csrf
            # Only the page plan's own connection's plans, by what each was issued for (Astra
            # recheck of ddce18b, MUST 3), and still that connection's now.
            queued = [(p.envelope.target, None) for p in self.store.pending()
                      if p.plan_id != plan.plan_id and self.store.same_owner(p, plan)
                      and self.store.belongs_now(p)]
        if plan.state in ("approved", "executing") and page_id is not None:
            # A refresh after a local POST must use an explicit GET target.
            refresh = f"1;url={path}"
        marker = self.store.unfinished_marker(plan) if plan.state == "pending" else None
        return render_plan(plan, path, language=language, copy=copy, message=message,
                           csrf=csrf, queued=queued, refresh=refresh, unfinished=marker)


_STYLE = (
    "body{font:1rem/1.4 system-ui,sans-serif;max-width:52rem;margin:0 auto;padding:1rem;"
    "background:#fff;color:#111}"
    "h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.4rem}h3{font-size:1rem}"
    "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
    ".spaces{white-space:pre-wrap;background:#ffe08a;outline:1px dotted #8a5a00}"
    "dl{display:grid;grid-template-columns:fit-content(45%) minmax(0,1fr);gap:.2rem 1rem}"
    "dt{font-weight:bold}dd{margin:0;overflow-wrap:anywhere}"
    "table{border-collapse:collapse;width:100%;table-layout:fixed;margin:.4rem 0}"
    "th,td{border:1px solid #bbb;padding:.3rem .4rem;text-align:left;vertical-align:top;"
    "overflow-wrap:anywhere}"
    "th{background:#f2f2f2}"
    "details{margin:.6rem 0}summary{cursor:pointer;font-weight:bold;padding:.3rem 0}"
    ".scroll{overflow-x:auto;max-width:100%}"
    "table.grid{width:auto;table-layout:auto}"
    "table.grid th{white-space:nowrap}"
    "table.grid td{overflow-wrap:break-word;min-width:3rem;max-width:20rem}"
    "section{padding:.6rem .8rem;margin:1rem 0}section h2{margin:0 0 .4rem}"
    "section.warning{border:2px solid #a40000;background:#fff3f3}"
    "section.confirm{border:1px solid #777;background:#f7f7f7}"
    ".status{font-weight:bold;padding:.6rem;border:1px solid #777}"
    "fieldset{margin:1rem 0}label{display:block}"
    ".buttons{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1rem}"
    "button{font:inherit;padding:.6rem 1rem;min-height:2.75rem}"
    "form.needs-ack:not(:has(input[name=ack]:checked)) button.approve"
    "{pointer-events:none;opacity:.4}")

# Use a native disabled button until checked, with no script or CSP exception. Browsers which
# lack :has keep the approval disabled.
_UNFINISHED_STYLE = (
    "#approval-form .approve-enabled{display:none}"
    "body:has(#unfinished-checked:checked) #approval-form .approve-enabled{display:inline-block}"
    "body:has(#unfinished-checked:checked) #approval-form .approve-disabled{display:none}")


def _page_start(language, title, refresh=None, form_referrer=False, extra_style=""):
    parts = [f'<!doctype html><html lang="{_text(language)}"><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">']
    if refresh is not None:
        parts.append(f'<meta http-equiv="refresh" content="{_text(refresh)}">')
    if form_referrer:
        # Keep the same-origin form POST's Origin header, and withhold cross-origin referrers.
        parts.append(f'<meta name="referrer" content="{_REFERRER_POLICY}">')
    parts.extend([f'<title>{_text(title)}</title><style>{_STYLE}{extra_style}</style>',
                  f'<body><h1>{_text(title)}</h1>'])
    return parts


def _status(text):
    return f'<p role="status" class="status">{_text(text)}</p>'


def render_message(message, *, language="en", copy=None, fields=(), sign_in=None,
                   plan_id="", csrf="", refresh=None):
    copy = page_texts.hosted_copy(language) if copy is None else copy
    title = copy["title"] if sign_in is None else copy["signin_title"]
    parts = _page_start(language, title, refresh, form_referrer=sign_in is not None)
    if message:
        parts.append(_status(copy[message]))
    if sign_in is not None:
        parts.append(f'<form method="post" action="{escape(sign_in)}">')
        parts.append(f'<input type="hidden" name="plan" value="{escape(plan_id)}">')
        parts.append(f'<input type="hidden" name="csrf" value="{escape(csrf)}">')
        for name, label, kind, autocomplete in fields:
            parts.append(f'<p><label>{_text(copy[label])} '
                         f'<input name="{name}" type="{kind}" autocomplete="{autocomplete}" '
                         'required></label></p>')
        parts.append(f'<button type="submit">{_text(copy["signin_submit"])}</button></form>')
    return "".join(parts) + "</body></html>"


def _queued(queued, copy):
    if not queued:
        return []
    parts = [f'<h2>{_text(copy["queued"])}</h2><ul>']
    for target, href in queued:
        label = _text(target)
        if href is not None:
            label = f'<a href="{escape(href)}">{label}</a>'
        parts.append(f"<li>{label}</li>")
    parts.append("</ul>")
    return parts


def _decline_all_form(action, csrf, copy):
    return (f'<form method="post" action="{escape(action)}">'
            f'<input type="hidden" name="csrf" value="{escape(csrf)}">'
            f'<div class="buttons"><button type="submit" class="decline-all">'
            f'{_text(copy["decline_all"])}</button></div></form>')


def render_list(queued, *, language="en", copy=None, decline_all=None):
    copy = page_texts.hosted_copy(language) if copy is None else copy
    parts = _page_start(language, copy["hosted_inbox"], form_referrer=decline_all is not None)
    parts.extend(_queued(queued, copy))
    if decline_all is not None:
        parts.append(_decline_all_form(*decline_all, copy))
    if not queued:
        parts.append(_status(copy["hosted_empty"]))
    return "".join(parts) + "</body></html>"


def render_plan(plan, path, *, language="en", copy=None, message=None, csrf=None, queued=(),
                refresh=None, who=(), blocked=None, decline_all=None, hosted=False, unfinished=None):
    copy = page_texts.TEXTS[language] if copy is None else copy
    check_unfinished = unfinished is not None and csrf is not None and blocked is None
    parts = _page_start(language, copy["title"], refresh, form_referrer=hosted and csrf is not None,
                        extra_style=_UNFINISHED_STYLE if check_unfinished else "")
    if message:
        parts.append(_status(copy[message]))
    if blocked is not None:
        parts.append(_status(blocked))
    if unfinished is not None:
        number = "one" if unfinished.count == 1 else "many"
        description = copy.get(f"unfinished_description_{unfinished.kind}_{number}",
                               copy["unfinished_description_unknown"])
        warning = copy["unfinished_write"].format(
            description=unfinished.description or description.format(count=unfinished.count),
            register=", ".join(unfinished.registers) or copy["unfinished_register_unknown"],
            time=unfinished.local_time or copy["unfinished_time_unknown"])
        parts.append(f'<section class="warning"><p>{_text(warning)}</p>')
        if check_unfinished:
            parts.append('<label><input type="checkbox" id="unfinished-checked" '
                         'form="approval-form" name="unfinished_checked" value="1"> '
                         f'{_text(copy["unfinished_checked"])}</label>')
        parts.append("</section>")
    envelope = plan.envelope
    parts.append("<dl>")
    for label in ("server", "company", "books_user", "operation", "target"):
        parts.append(f'<dt>{_text(copy[label])}</dt><dd>{_text(getattr(envelope, label))}</dd>')
    for label, value in who:
        parts.append(f'<dt>{_text(copy[label])}</dt><dd>{_text(value)}</dd>')
    parts.extend(["</dl>", f'<h2>{_text(copy["fields"])}</h2>'])
    # A private key can appear in an ordinary text field, too.
    parts.extend(_preview(privacy.mask_key_text(envelope.preview)[0], copy,
                          kind=envelope.kind, hide_secrets=hosted))
    if _changes_existing_record(envelope):
        parts.append(f'<p class="race">{_text(copy["race_gap"])}</p>')
    if plan.state == "done" and plan.outcome is not None:
        outcome = privacy.mask_private_keys(plan.outcome)[0]
        if hosted:
            outcome = _public_preview(outcome)
        parts.append(f'<h2>{_text(copy["result"])}</h2>{_value(outcome)}')
    if csrf is not None and plan.state == "pending":
        path = escape(path)
        show_ack = envelope.needs_ack and blocked is None
        form_class = ' class="needs-ack"' if show_ack else ""
        form_id = ' id="approval-form"' if check_unfinished else ""
        default_action = "approve" if blocked is None else "decline"
        parts.append(f'<form{form_class}{form_id} method="post" action="{path}/{default_action}">'
                     f'<input type="hidden" name="csrf" value="{escape(csrf)}">'
                     f'<input type="hidden" name="digest" value="{envelope.digest()}">')
        if check_unfinished:
            parts.append(f'<input type="hidden" name="unfinished_marker" '
                         f'value="{_text(unfinished.token)}">')
        if show_ack:
            kind = _ack_kind(envelope)
            parts.append(f'<fieldset><legend>{_text(copy["ledger" + kind])}</legend>'
                         f'<label><input type="checkbox" name="ack" value="1"> '
                         f'{_text(copy["ack" + kind])}</label></fieldset>')
        # CSS dims Approve until the tick. The server also requires the tick for keyboard submits.
        parts.append('<div class="buttons">')
        actions = [(default_action, default_action)]
        if blocked is None:
            actions.append(("decline", "decline"))
        if not hosted:
            actions.append(("decline-all", "decline_all"))
        for action, label in actions:
            button_class = action
            if action == "approve" and check_unfinished:
                parts.append(f'<button type="submit" class="approve-disabled" disabled>'
                             f'{_text(copy[label])}</button>')
                button_class += " approve-enabled"
            parts.append(f'<button type="submit" class="{button_class}" '
                         f'formaction="{path}/{action}">{_text(copy[label])}</button>')
        parts.append("</div></form>")
    if decline_all is not None:
        parts.append(_decline_all_form(*decline_all, copy))
    parts.extend(_queued(queued, copy))
    return "".join(parts) + "</body></html>"


def _render_consent(page_id, authority, enabled, message, language, copy, buttons=True):
    kind = authority.target.kind
    title = copy["consent_title_" + kind]
    parts = [f'<!doctype html><html lang="{_text(language)}"><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             f'<title>{_text(title)}</title><style>{_STYLE}</style>',
             f'<body><h1>{_text(title)}</h1>']
    if kind == "hr":
        parts.append(f"<p>{_text(copy['consent_hr_intro'])}</p><ol>")
        parts.extend(f"<li><p><strong>{_text(copy['consent_hr_%d_head' % n])}:</strong> "
                     f"{_text(copy['consent_hr_%d_body' % n])}</p></li>" for n in range(1, 5))
        parts.append("</ol>")
    else:
        # A text in another language than the page is marked so (Sol review of 849e1ca, MUST-FIX
        # 1); since Task 53 every page language has its own.
        text_lang = copy.get("consent_gdpr_lang", language)
        marked = f' lang="{_text(text_lang)}"' if text_lang != language else ""
        # One <p> per paragraph: the texts are three paragraphs joined by a blank line.
        parts.append(f"<div{marked}>" + "".join(
            f"<p>{_text(para)}</p>" for para in copy['consent_gdpr_text'].split("\n\n")
            if para.strip()) + "</div>")
    status = message or copy["consent_on" if enabled else "consent_off"]
    parts.append(f'<p role="status" class="status">{_text(status)}</p>')
    if buttons:
        # The 500 page draws none: after a failed save the state is unknown (review S4).
        path = f"/c/{page_id}"
        # The hash of the text drawn above: a yes records exactly that wording, whatever the
        # browser asks for by the time it posts (Sol review of 14fbad6, MUST-FIX).
        parts.append(f'<form method="post" action="{path}/off">'
                     f'<input type="hidden" name="csrf" value="{authority.csrf}">'
                     f'<input type="hidden" name="text" value="{consent.page_digest(copy, kind)}">'
                     '<div class="buttons">')
        if enabled:
            parts.append(f'<button type="submit" formaction="{path}/off">'
                         f'{_text(copy["consent_switch_off"])}</button>')
        else:
            parts.append(f'<button type="submit" formaction="{path}/on">'
                         f'{_text(copy["consent_switch_on"])}</button>'
                         f'<button type="submit" formaction="{path}/off" name="later" value="1">'
                         f'{_text(copy["consent_not_now"])}</button>')
        parts.append("</div></form>")
    parts.append("</body></html>")
    return "".join(parts)


# Preview keys shown in a block of their own; every key not drawn otherwise is in "details".
_WARNINGS = ("warning", "warnings")
_NOTES = ("confirm", "note")
# The person-facing form of a plan note on every approval page (approval.ITEMS_NOTE and its hosted
# variant speak of where to approve; on the page only the cost-account sentence matters).
_HOSTED_PAGE_NOTES = {
    "Nothing has been written. The person approves these item cards in the approval "
    "window; only then are they created. The group decides the cost account.":
        "Nothing has been written yet. The group decides the cost account.",
    "Nothing has been written. The person approves these item cards on the page at "
    "approve_url; only then are they created. The group decides the cost account.":
        "Nothing has been written yet. The group decides the cost account.",
}


_FOR_THE_AI = ("apply_approved", "approve_url", "plan_id", "approval page", "approval window")


# A warning keeps every sentence but the one telling the AI how to talk to the person (Sol
# re-check of 96a31ee: changes.APPROVE_WARNING and PAYMENT_END end with it).
_WARNING_FOR_THE_AI = ("Say this to the person",)


def _for_the_person(note, words=_FOR_THE_AI):
    """A plan note without its sentences for the AI (which tool to call, where the page is)."""
    if not isinstance(note, str):
        return note
    if note in _HOSTED_PAGE_NOTES:
        return _HOSTED_PAGE_NOTES[note]
    if not any(word in note for word in words):
        return note
    sentences = re.split(r"(?<=[.!?])\s+", note.strip())
    return " ".join(s for s in sentences if not any(word in s for word in words))


def _changes_existing_record(envelope):
    """The race gap exists wherever an existing record is changed, whatever the label:
    OK-ing a document is a PATCH with operation "approve" (review M2)."""
    return envelope.kind == "record_change" and (
        envelope.before != "" or any(write[0] == "PATCH" for write in envelope.writes))


def _scalar(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "✓" if value else "–"
    # The form sends `a  b` byte for byte; HTML would show it as `a b`. Keep and mark the run
    # (Task 19 re-check MUST 5, PARTLY: interior spaces collapsed in table cells).
    return _SPACES.sub(lambda m: f'<span class="spaces">{m.group(0)}</span>', _text(value))


_SPACES = re.compile(r" {2,}")


def _value(value, depth=0):
    """Any JSON value as escaped HTML: a dict as a two-column table, a list item after item."""
    if isinstance(value, dict):
        if not value:
            return ""
        if depth > 4:
            return f"<pre>{_text(json.dumps(value, ensure_ascii=False))}</pre>"
        rows = "".join(f"<tr><th>{_text(k)}</th><td>{_value(v, depth + 1)}</td></tr>"
                       for k, v in value.items())
        return f'<table class="pairs">{rows}</table>'
    if isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            return ", ".join(_scalar(v) for v in value)
        return "".join(_value(v, depth + 1) for v in value)
    return _scalar(value)


def _field_table(fields, copy):
    """Before and after per field, or the value a new record gets."""
    if not isinstance(fields, list) or not all(isinstance(f, dict) and "field" in f for f in fields):
        return _value(fields)
    changed = any("before" in f or "after" in f for f in fields)
    heads = ("field", "before", "after") if changed else ("field", "value")
    rows = []
    for f in fields:
        rows.append("<tr>" + "".join(f"<td>{_value(f.get(h, ''))}</td>" for h in heads) + "</tr>")
        rest = {k: v for k, v in f.items() if k not in heads}
        if rest:
            rows.append(f'<tr><td colspan="{len(heads)}">{_value(rest)}</td></tr>')
    head = "".join(f"<th>{_text(copy['col_' + h])}</th>" for h in heads)
    return f'<table class="fields"><tr>{head}</tr>{"".join(rows)}</table>'


def _lines(lines, copy):
    parts = []
    for number, line in enumerate(lines, 1):
        if not isinstance(line, dict):
            parts.append(f"<p>{_value(line)}</p>")
            continue
        title = f'{_text(copy["line"])} {_text(line.get("line", number))}'
        if line.get("new_line"):
            title += f' ({_text(copy["new_line"])})'
        parts.append(f"<h3>{title}</h3>")
        if "fields" in line:
            parts.append(_field_table(line["fields"], copy))
        parts.append(_value({k: v for k, v in line.items()
                             if k not in ("line", "new_line", "fields", "line_now")}))
        if isinstance(line.get("line_now"), dict) and line["line_now"]:
            parts.append(f'<details class="line-now"><summary>{_text(copy["line_now"])}</summary>'
                         f'{_value(line["line_now"])}</details>')
        elif "line_now" in line:
            parts.append(_value({"line_now": line["line_now"]}))
    return parts


def _document_now(document, copy):
    """The whole record as it is now (the plan's fingerprint covers all of it), folded: the header
    one field per row, the lines ONE table with a column per field (Task 33 run, 2026-11-23:
    tables in tables were unreadable). None when the shape is not the planner's."""
    if not isinstance(document, dict) or set(document) != {"header", "lines"}:
        return None
    header, lines = document["header"], document["lines"]
    if not isinstance(header, dict) or not isinstance(lines, dict) or not all(
            isinstance(line, dict) for line in lines.values()):
        return None
    parts = [f'<details class="document-now"><summary>{_text(copy["document_now"])}</summary>']
    if header:
        parts.append(_value(header))
    if lines:
        columns = list(dict.fromkeys(key for line in lines.values() for key in line))
        head = "".join(f"<th>{_text(c)}</th>" for c in [copy["line"], *columns])
        rows = "".join(
            f"<tr><td>{_text(number)}</td>"
            + "".join(f"<td>{_value(line.get(c, ''))}</td>" for c in columns) + "</tr>"
            for number, line in lines.items())
        parts.append(f'<div class="scroll"><table class="grid"><tr>{head}</tr>{rows}</table></div>')
    parts.append("</details>")
    return "".join(parts)


def _ack_kind(envelope) -> str:
    """"_payment" for a payment's approval (its tick names the payment, not the ledger), else
    "". Read from the preview's register; anything unreadable keeps the ledger text."""
    from .changes import PAYMENT_REGISTERS
    try:
        register = json.loads(envelope.preview).get("register", "")
    except (ValueError, AttributeError):
        return ""
    return "_payment" if str(register).casefold() in PAYMENT_REGISTERS else ""


def _public_preview(value):
    if isinstance(value, dict):
        return {key: _public_preview(item) for key, item in value.items()
                if not privacy.is_secret_field(key)}
    if isinstance(value, list):
        return [_public_preview(item) for item in value
                if not (isinstance(item, dict) and privacy.is_secret_field(item.get("field")))]
    return value


def _person_warnings(data, kind):
    for key in _WARNINGS:
        warning = data.get(key)
        # Receipt warnings are already person-facing and may contain invoice references.
        if kind != "goods_receipt":
            warning = _for_the_person(warning, _WARNING_FOR_THE_AI)
        if warning:
            yield warning


def _preview(text, copy, *, kind="", hide_secrets=False):
    """The stored preview as tables and blocks (design 3.4 step 4). Every key is shown, escaped:
    the person approves what they can read."""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return [f"<pre>{_text(text)}</pre>"]
    if hide_secrets:
        data = _public_preview(data)
    parts, details, document = [], {}, None
    for key, value in data.items():
        if key == "status" or key in _WARNINGS or key in _NOTES:
            continue
        if key == "fields":
            parts.append(_field_table(value, copy))
        elif key == "lines" and isinstance(value, list) and value:
            parts.append(f'<h2>{_text(copy["lines"])}</h2>')
            parts.extend(_lines(value, copy))
        elif key == "document_now" and (drawn := _document_now(value, copy)) is not None:
            document = drawn
        else:
            details[key] = value
    if document:
        parts.append(document)
    if details:
        parts.append(f'<h2>{_text(copy["details"])}</h2>{_value(details)}')
    warnings = list(_person_warnings(data, kind))
    if warnings:
        parts.append(f'<section class="warning" role="note"><h2>{_text(copy["warning"])}</h2>'
                     + "".join(f"<p>{_value(w)}</p>" for w in warnings) + "</section>")
    notes = [data[k] for k in _NOTES if data.get(k)]
    # A note telling the AI to call apply_approved or hand over approve_url is not for the person,
    # who is already on this page: hosted since the Sol re-check of 17277f4, local and Desktop
    # since the Task 33 run (2026-11-23). Item notes keep their one sentence for the person.
    # Sol review of 3b75f1f, MUST 1: only the AI's sentences go; the person's stay ("The receipt
    # is created already OK'd, so stock moves immediately.").
    notes = [_for_the_person(n) for n in notes]
    notes = [n for n in notes if n]
    if notes:
        parts.append('<section class="confirm">'
                     + "".join(f"<p>{_value(n)}</p>" for n in notes) + "</section>")
    return parts


_CHAT_ESCAPES = {
    ord(char): chr(92) + f"u{ord(char):04x}"
    for char in "<>\u0085\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
}


def _chat_value(value):
    # Keep a field on its own line even if its value contains markup or a line break. Text is
    # shown as written (opus review of d341919: no JSON escapes the person would misread);
    # only control and direction characters are made visible.
    if isinstance(value, str):
        # Every control and format character (C0, C1, zero-width, direction marks, BOM, soft
        # hyphen) is shown as its code (Sol recheck of ca80413).
        return "".join((chr(92) + f"u{ord(char):04x}" if ord(char) <= 0xFFFF
                        else chr(92) + f"U{ord(char):08x}")
                       if unicodedata.category(char) in ("Cc", "Cf") else char
                       for char in value).translate(_CHAT_ESCAPES)
    return json.dumps(value, ensure_ascii=False).translate(_CHAT_ESCAPES)


def _chat_fields(fields):
    for field in fields:
        name = _chat_value(field["field"])
        if "before" in field or "after" in field:
            before, after = (_chat_value(field.get(key, "")) for key in ("before", "after"))
            yield f"{name}: {before} → {after}"
        elif "value" in field:
            yield f"{name}: {_chat_value(field['value'])}"
        for key, value in field.items():
            if key not in ("field", "value", "before", "after", "personal"):
                yield f"  {name} ({key}): {_chat_value(value)}"


_CHAT_PARTY_FIELDS = ("CustCode", "CustName", "Addr0", "VECode", "VEName", "CUCode", "CUName")
_CHAT_DOCUMENT_FIELDS = (
    *_CHAT_PARTY_FIELDS, "Sum4", "PayVal", "CurPayVal", "RecVal", "BaseSum4",
    "CurncyCode", "InvDate", "OrdDate", "ShipDate", "TransDate", "PayDate",
)
_CHAT_PAYMENT_ROW_FIELDS = (
    *_CHAT_PARTY_FIELDS, "VISerNr", "InvoiceNr", "RecVal", "CurncyCode", "BankVal", "BankCurncy",
)


_CHAT_AMOUNT_FIELDS = ("Sum4", "PayVal", "CurPayVal", "RecVal", "BaseSum4", "BankVal")


def _chat_names(values: dict, shown: tuple) -> bool:
    """A party with a non-blank text value AND an amount that reads as a non-zero number, in this
    one dict and among the fields the summary SHOWS for it (Sol review of 14e0151: pooled names,
    "0" and blanks passed; Sol recheck of c2efbaa: a header BankVal or a row PayVal qualified
    without being shown)."""
    party = any(isinstance(values.get(key), str) and values[key].strip()
                for key in _CHAT_PARTY_FIELDS if key in shown)
    for key in _CHAT_AMOUNT_FIELDS:
        if key not in shown or not isinstance(values.get(key), (str, int, float)):
            continue
        try:
            amount = float(str(values.get(key) or "").strip().replace(",", "."))
        except ValueError:
            continue
        if amount == amount and amount not in (0.0, float("inf"), float("-inf")):
            return party
    return False


def _chat_document_now(document, register, copy):
    """Who and how much, for a chat yes to an approval on an existing record. None when the
    header does not name a party and an amount together, nor (payments) does EVERY payment row
    name its own: then only the browser page, which shows the whole record, may approve it
    (opus recheck of 0259f3f: a yes to "OKFlag: 0 -> 1" alone; Sol review of 14e0151)."""
    from .changes import PAYMENT_REGISTERS

    if not isinstance(document, dict) or set(document) != {"header", "lines"}:
        return None
    header, lines = document["header"], document["lines"]
    if not isinstance(header, dict) or not isinstance(lines, dict) or not all(
            isinstance(row, dict) for row in lines.values()):
        return None
    payment = register.casefold() in PAYMENT_REGISTERS
    if not (_chat_names(header, _CHAT_DOCUMENT_FIELDS) or (payment and lines and all(
            _chat_names(row, _CHAT_PAYMENT_ROW_FIELDS) for row in lines.values()))):
        return None
    parts = [f"{key}: {_chat_value(header[key])}" for key in _CHAT_DOCUMENT_FIELDS
             if str(header.get(key) or "").strip()]
    if payment:
        # OPVc can carry the supplier and bank amount only on the payment row.
        for number, row in lines.items():
            parts.append(f"{copy['line']} {_chat_value(number)}")
            parts.extend(f"{key}: {_chat_value(row[key])}" for key in _CHAT_PAYMENT_ROW_FIELDS
                         if str(row.get(key) or "").strip())
    return parts


def _pure_approval(envelope, data) -> bool:
    """An existing record whose only change is its approval field(s): no other header field and
    no line. A create that approves, or an edit made together with the approval, would be
    judged on values the write itself changes, so it is approved on the browser page only
    (Sol review of 14e0151, MUST 1 and 2)."""
    from .changes import approval_fields

    if not data.get("record_id") or data.get("lines"):
        return False
    fields = data.get("fields")
    if not isinstance(fields, list) or not fields:
        return False
    allowed = set(approval_fields(data.get("register")))
    return all(isinstance(field, dict) and str(field.get("field", "")).casefold() in allowed
               for field in fields)


def chat_confirmation(envelope, register, language):
    """Summarise the stored preview and identify the existing document being approved."""
    try:
        data = json.loads(envelope.preview)
    except ValueError:
        return None
    if not isinstance(data, dict) or not register:
        return None
    _, keys = privacy.mask_private_keys(data)
    if keys:
        return None

    copy = page_texts.TEXTS[language]
    parts = [f"{copy['chat_register']}: {_chat_value(register)}"]
    if envelope.kind in ("items", "contacts"):
        for record in data[envelope.kind]:
            parts.append(f"{copy['chat_record']}: {_chat_value(record['code'])}")
            if "fields" in record:
                # A role added to an existing contact names it (review S1 of contacts; opus
                # review of d341919, SHOULD 3).
                parts.extend(f"{key}: {_chat_value(value)}" for key, value in record.items()
                             if key not in ("code", "fields") and value != "")
                parts.extend(_chat_fields(record["fields"]))
            else:
                parts.extend(f"{key}: {_chat_value(value)}" for key, value in record.items()
                             if key != "code" and value != "")
    elif envelope.kind == "goods_receipt":
        # The lines give the quantities and any earlier receipts are named in the warning.
        parts.extend(f"{key}: {_chat_value(value)}" for key, value in data.items()
                     if key not in (*_WARNINGS, *_NOTES, "status", "lines", "already_received",
                                    "will_change_stock_by", "correlation", "vendor_matched_on")
                     and value != "")
    elif envelope.kind == "record_change":
        record = data.get("record_id") or copy["chat_new_record"]
        parts.append(f"{copy['chat_record']}: {_chat_value(record)}")
        parts.extend(_chat_fields(data.get("fields", ())))
        if envelope.operation == "approve" or envelope.needs_ack:
            # Only a plain approval of an existing record that names who and how much is
            # approved in the chat; the browser page shows the whole record for the rest.
            if not _pure_approval(envelope, data):
                return None
            digest = _chat_document_now(data.get("document_now"), register, copy)
            if digest is None:
                return None
            parts.extend(digest)
    else:
        return None

    if envelope.kind in ("record_change", "goods_receipt"):
        for number, line in enumerate(data.get("lines", ()), 1):
            title = f"{copy['line']} {_chat_value(line.get('line', number))}"
            if line.get("new_line"):
                title += f" ({copy['new_line']})"
            parts.append(title)
            parts.extend(_chat_fields(line.get("fields", ())))
            parts.extend(f"{key}: {_chat_value(value)}" for key, value in line.items()
                         if key not in ("line", "new_line", "fields", "line_now")
                         and (envelope.kind != "goods_receipt"
                              or (key != "matched_on" and value not in (None, ""))))
    if _changes_existing_record(envelope):
        parts.append(copy["race_gap"])
    parts.extend(f"{copy['warning']}: {_chat_value(warning)}"
                 for warning in _person_warnings(data, envelope.kind))
    if envelope.kind == "goods_receipt" and (note := _for_the_person(data.get("confirm"))):
        parts.append(f"{copy['warning']}: {_chat_value(note)}")
    if envelope.needs_ack:
        kind = _ack_kind(envelope)
        parts.append(f"{copy['ledger' + kind]}: {copy['ack' + kind]}")
    return "\n".join(parts)


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 closes each response, including refused bodies we deliberately do not read.
    def log_message(self, format, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def finish(self):
        """Close gently. A refusal answers before reading the body, and Windows resets a socket
        closed with unread bytes, so the client lost the answer (WinError 10053, about one run
        in five). Half-close, then read what is still coming, bounded in bytes and time."""
        super().finish()
        try:
            self.connection.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + _DRAIN_SECONDS
            drained = 0
            while drained < _DRAIN_BYTES:
                # Each receive waits only for what is left, so the whole drain ends on time
                # (Sol re-check NIT: a byte at 0.9 s allowed another full second).
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                self.connection.settimeout(left)
                chunk = self.connection.recv(16384)
                if not chunk:
                    break
                drained += len(chunk)
        except OSError:
            pass

    @property
    def owner(self):
        return self.server.owner

    def _language(self):
        """The browser's language for this answer (a request whose headers were never read: the
        default)."""
        headers = getattr(self, "headers", None)
        return page_texts.language_from_header(
            headers.get("Accept-Language", "") if headers is not None else "")

    def _respond(self, status, body=None, *, cookie=None, location=None, csp=None):
        body = (body if body is not None else self.owner._render(
            message="error", language=self._language())).encode("utf-8")
        self.send_response(status)
        # `csp`: the settings page's own policy (its one inline script, by hash).
        for name, value in {**HEADERS, "Referrer-Policy": _REFERRER_POLICY,
                            "Content-Security-Policy": csp or _CSP,
                            "Content-Length": str(len(body))}.items():
            self.send_header(name, value)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        self._respond(code)

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._method_not_allowed
        raise AttributeError(name)

    def _method_not_allowed(self):
        self._respond(405 if self._host_ok() else 403)

    def _host_ok(self):
        return self.headers.get_all("Host", []) == [f"127.0.0.1:{self.owner.port}"]

    @staticmethod
    def _cookie(route, page_id, value, clear=False):
        return (f"ebmcp_{page_id}={value}; HttpOnly; SameSite=Strict; Path=/{route}/{page_id}"
                + ("; Max-Age=0" if clear else ""))

    def _authority(self, route, page_id):
        authority = self.owner._pages.get(page_id)
        if authority is None or authority.route != route or not authority.active:
            return None
        if self.owner._consent_expired(authority):
            del self.owner._pages[page_id]
            return None
        # Split by hand: SimpleCookie drops the whole header on one illegal name, and another
        # program on 127.0.0.1 can set one (review NIT: that failed closed, but blocked us).
        name = "ebmcp_" + page_id
        for header in self.headers.get_all("Cookie", []):
            for pair in header.split(";"):
                key, sep, value = pair.strip().partition("=")
                if sep and key == name and _equal(value.strip(), authority.cookie):
                    return authority
        return None

    def _connection_changed(self, page_id, authority, state="pending"):
        """A plan of a connection the settings no longer name, in any state: no preview, no
        outcome, no buttons, and this page's authority ends (Astra recheck of the slice 2 fix,
        MUST 3; of 3485c9a, MUST 3). A pending plan stays pending, and the page no longer counts
        as loaded, so asking again once its connection is saved opens a fresh window."""
        authority.active = False
        authority.cookie = authority.csrf = ""
        self.owner._loaded.discard(authority.target)
        message = ("connection_changed_result" if state in ("executing", "done")
                   else "connection_changed")
        self._respond(409, self.owner._render(message=message, language=self._language()),
                      cookie=self._cookie("p", page_id, "", clear=True))

    def _withheld(self, page_id, authority, plan, message, code):
        """No preview and no outcome, and this page stays as it was: the settings could not be
        read just now, or the plan's consent is off (Astra recheck of ddce18b, regression and NEW
        MUST 1). An approved or executing plan still shows its true state and refreshes."""
        progress = plan.state in ("approved", "executing")
        if progress and message == "settings_unreadable":
            message, code = plan.state, 200
        if plan.state != "pending":
            authority.csrf = ""
        language = self.owner._language(self._language())
        self._respond(code, render_message(
            message, language=language, copy=self.owner.texts.TEXTS[language],
            refresh=f"1;url=/p/{page_id}" if progress else None))

    def _shown_now(self, page_id, authority, plan, consent_needed=True):
        """Whether `plan`'s preview or outcome may be served now; when not, the answer is sent."""
        owner = self.owner.store.owner_state(plan)
        if owner is False:
            self._connection_changed(page_id, authority, plan.state)
            return False
        if owner is None:
            self._withheld(page_id, authority, plan, "settings_unreadable", 503)
            return False
        consent_now = self.owner.store.consent_state(plan) if consent_needed else True
        if consent_now is not True:
            self._withheld(page_id, authority, plan, "settings_unreadable" if consent_now is None
                           else "consent_needed", 503 if consent_now is None else 403)
            return False
        return True

    def _result(self, page_id, authority, plan, status=None):
        if plan is not None and not self._shown_now(page_id, authority, plan):
            return
        state = plan.state if plan is not None else "error"
        if state != "pending":
            # Approval authority ends immediately; only read-only progress access survives.
            authority.csrf = ""
        if state not in ("pending", "approved", "executing"):
            authority.active = False
            # Drop the server-side secrets as well as deleting the browser cookie.
            authority.cookie = authority.csrf = ""
        code = status if status is not None else (410 if state == "expired" else 200)
        self._respond(code, self.owner._render(
            plan, page_id, authority, message=None if state == "pending" else state,
            language=self._language()),
            cookie=self._cookie("p", page_id, "", clear=True) if not authority.active else None)

    def _consent_result(self, page_id, authority, action=None, language=None):
        """`language`: for a GET the browser's; for a POST the language of the text the form
        names, so "on" records the wording that page drew."""
        target = authority.target
        authority.seen = (self.owner._clock(), self.owner._wall())
        language, copy = self.owner._consent_copy(language)
        try:
            if action == "on":
                # The hash of the text this page showed, in its language.
                consent.record(target.kind, target.connection_id, consent_text(copy, target.kind))
            elif action == "off":
                consent.withdraw(target.kind, target.connection_id)
            enabled = consent.given(target.kind, target.connection_id)
        except (OSError, ConfigError):
            self._respond(500, _render_consent(page_id, authority, False, copy["consent_error"],
                                               language, copy, buttons=False))
            return
        message = copy["consent_close"] if action == "later" else None
        self._respond(200, _render_consent(page_id, authority, enabled, message, language, copy))

    def do_GET(self):
        if not self._host_ok():
            self._respond(403)
            return
        with self.owner._lock:
            parts = self.path.split("/")
            if len(parts) == 3 and parts[1] == "a":
                bootstrap = self.owner._bootstraps.pop(parts[2], None)
                if bootstrap is None or not self.owner._bootstrap_alive(bootstrap):
                    self._respond(404)
                    return
                page_id, authority = self.owner._exchange(bootstrap)
                route = authority.route
                self._respond(303, self.owner._render(language=self._language()),
                              cookie=self._cookie(route, page_id, authority.cookie),
                              location=f"/{route}/{page_id}")
            elif len(parts) == 3 and parts[1] == "s":
                # The settings page: only ?lang=<code> may follow its id (the et/en switch).
                page_id, _, query = parts[2].partition("?")
                authority = self._authority("s", page_id)
                if authority is None:
                    self._respond(403)
                    return
                from . import settings_page
                settings_page.get(self, page_id, authority, query)
            elif len(parts) == 3 and parts[1] in _POST_ACTIONS:
                route, page_id = parts[1:]
                authority = self._authority(route, page_id)
                if authority is None:
                    self._respond(403)
                    return
                if route == "c":
                    self._consent_result(page_id, authority, language=self._language())
                else:
                    self._result(page_id, authority, self.owner.store.get(authority.target))
            else:
                self._respond(404)

    def do_POST(self):
        if (not self._host_ok() or self.headers.get_all("Origin", []) !=
                [f"http://127.0.0.1:{self.owner.port}"]):
            self._respond(403)
            return
        lengths = self.headers.get_all("Content-Length", [])
        try:
            length = int(lengths[0]) if len(lengths) == 1 else -1
        except ValueError:
            length = -1
        if length < 0 or self.headers.get("Transfer-Encoding") is not None:
            self._respond(400)
            return
        if length > _BODY_LIMIT:
            self._respond(413)
            return
        parts = self.path.split("/")
        if len(parts) != 4 or parts[3] not in _POST_ACTIONS.get(parts[1], ()):
            self._respond(404)
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                self._respond(400)
                return
            form = parse_qs(raw.decode("utf-8"), keep_blank_values=True,
                            errors="strict", max_num_fields=32)
        except (UnicodeError, ValueError):
            self._respond(400)
            return
        if parts[1] == "s":
            # The settings page takes the lock itself: its sign-in test runs outside it.
            from . import settings_page
            settings_page.post(self, parts[2], parts[3], form)
            return
        with self.owner._lock:
            route, page_id, action = parts[1:]
            authority = self._authority(route, page_id)
            csrf = form.get("csrf", [])
            # An emptied token (approval authority ended) matches nothing, not even "".
            if (authority is None or not authority.csrf or len(csrf) != 1
                    or not _equal(csrf[0], authority.csrf)):
                self._respond(403)
                return
            if route == "c":
                if action == "off" and form.get("later") == ["1"]:
                    action = "later"
                # The text the page drew, by its hash: "on" needs it, and a form naming a text no
                # page draws (or one not current) is refused. A switch-off needs no wording.
                shown = form.get("text")
                language = (consent.page_language(authority.target.kind, shown[0])
                            if shown is not None and len(shown) == 1 else None)
                if language is None and (action == "on" or shown is not None):
                    self._respond(400)
                    return
                self._consent_result(page_id, authority, action,
                                     language if language is not None else self._language())
                return
            plan = self.owner.store.get(authority.target)
            if plan is None or plan.state != "pending":
                # An unconsumed second page may still render expiry/done once. Approved and
                # executing pages are read-only, including the dangerous decline-all action.
                if plan is not None and plan.state in ("approved", "executing"):
                    authority.csrf = ""
                    self._respond(403)
                else:
                    self._result(page_id, authority, plan, status=404 if plan is None else None)
                return
            # Nothing new starts for another connection's plan or on an unreadable read; an
            # approval also needs the plan's consent on now. Declining needs neither consent.
            if not self._shown_now(page_id, authority, plan,
                                   consent_needed=action == "approve"):
                return
            acknowledged = form.get("ack") == ["1"]
            if action == "approve" and plan.envelope.needs_ack and not acknowledged:
                self._respond(400, self.owner._render(plan, page_id, authority,
                                                      "ack_required" + _ack_kind(plan.envelope),
                                                      language=self._language()))
                return
            try:
                if action == "approve":
                    # The digest of the page the person saw, not the store's own (review NIT).
                    digest = form.get("digest", [])
                    marker = form.get("unfinished_marker", [])
                    checked = form.get("unfinished_checked") == ["1"] and len(marker) == 1
                    self.owner.store.approve(plan.plan_id, digest[0] if len(digest) == 1 else "",
                                             acknowledged,
                                             unfinished_marker=marker[0] if checked else None)
                elif action == "decline":
                    self.owner.store.decline(plan.plan_id)
                else:
                    for pending in self.owner.store.pending():
                        if not (self.owner.store.same_owner(pending, plan)
                                and self.owner.store.belongs_now(pending)):
                            # Another connection's plan is neither shown nor declined from here,
                            # judged by the page plan's own connection, not only by the settings
                            # now (Astra recheck of 3485c9a and of ddce18b, MUST 3).
                            continue
                        try:
                            self.owner.store.decline(pending.plan_id)
                        except (Expired, Declined, Finished, InProgress, NotApproved):
                            # Another caller may have started/finished/evicted it since the snapshot.
                            continue
            except (Expired, Declined, Finished):
                self._result(page_id, authority, self.owner.store.get(plan.plan_id))
                return
            except ConnectionChanged:
                self._connection_changed(page_id, authority)
                return
            except OwnerUnknown:
                self._withheld(page_id, authority, plan, "settings_unreadable", 503)
                return
            except UnfinishedWriteCheckRequired:
                self._respond(400, self.owner._render(plan, page_id, authority,
                                                      "unfinished_required",
                                                      language=self._language()))
                return
            except UnfinishedWriteUnavailable:
                self._respond(409, self.owner._render(plan, page_id, authority,
                                                      "unfinished_unavailable",
                                                      language=self._language()))
                return
            except ApprovalError:
                self._respond(409, self.owner._render(plan, message="error",
                                                      language=self._language()))
                return
            self._result(page_id, authority, self.owner.store.get(plan.plan_id))
