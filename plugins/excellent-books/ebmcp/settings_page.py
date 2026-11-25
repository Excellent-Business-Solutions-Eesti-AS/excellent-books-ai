"""The ChatGPT/Codex plugin's Connect Excellent Books page (design 2026-11-23, slice 3).

Served by the loopback page server of the approval window (approval_page.PageServer, route "s"),
with its protections: a one-time secret address exchanged for a page-bound cookie, the exact Host
on GET and Origin on POST, no-store, frame denial. On top of those:

- Every drawn form carries its own token, bound to the settings revision (a counter kept in the
  settings file, never a content hash) and the consent text it drew (Astra review of slice 3,
  MUST 2 and 4, and its recheck). A POST spends its token under the page
  lock; each spent token keeps its own submission and answer, so a double submit of the same form
  waits for ITS answer and never signs in twice, and a different submission on a spent token is
  refused (recheck, NEW MUST 1).
- Save, options and Forget hold the settings lock (config.plugin_settings_locked) from the stale
  check through the test sign-in to the last write: a form drawn from an older revision is refused
  before any request, and no other save or Forget lands in between (MUST 2 and 3).
- The consent is the box ticked in THIS post, for the text this form drew, and it is for the
  connection named in this post (customer test 2026-11-24: one Save is enough). The page's script
  clears the box when a destination field changes, so the tick is given after the edit. Saving
  the saved connection again needs no tick while its consent is on record.
- Save records the consent FIRST, then the settings; a failed settings write takes a NEW consent
  back. Forget writes its tombstone first (one atomic write: the login is gone, the revision goes
  on), then writes the withdrawal for every id the old login had, without reading the consent
  store first (recheck, MUST 3 and NEW MUST 2).
- An empty password keeps the saved one ONLY while the server root, company and user are exactly
  the saved ones; otherwise nothing is sent anywhere (MUST 1: the stored root is the root that
  passed sign-in, compared without cleaning it again).
- The test sign-in is one Basic login (no redirect, HTTPS verified, https addresses only), then
  one read on its HSESSION cookie, also without redirects, both inside one total deadline. A
  failure saves nothing and is shown as a fixed text by category, never Books' words.
- The password is never drawn back into the page, logged or kept outside the settings file.
"""
from base64 import b64encode
from hashlib import sha256
import json
import re
import secrets
import threading
import time
import urllib.error
from urllib.parse import parse_qs, urlsplit

from . import config, consent, erp, page_texts
from .approval_page import _CSP, _STYLE, _equal, _text


SIGN_IN_TIMEOUT = 20.0        # one socket operation of the test sign-in
SIGN_IN_DEADLINE = 25.0       # the whole test sign-in, login and cookie read (recheck, point 8)
SAVE_WAIT_SECONDS = 60       # how long a double submit waits for the first Save's answer
LOCK_WAIT_SECONDS = 45       # how long a POST waits for another save's settings lock
FORMS_KEPT = 8               # drawn forms per page whose tokens still work
# The release scan reads a quoted password key followed by ":" as a hard-coded value.
_PASSWORD_KEY = config.PLUGIN_REQUIRED[-1]

# One inline script, allowed by its hash only: the copy buttons, the live destination line, and,
# when the destination changes, clearing the password (a browser may fill the saved one in) and
# the consent box (the yes was for the connection shown before), and showing the box where the
# consent on record was shown. An error message takes the focus. Without the script the page
# still works: the texts stay selectable, the saved destination is drawn, and a changed
# connection without a tick is answered with a page that shows the box.
SCRIPT = (
    "document.querySelectorAll('button[data-copy]').forEach(function(b){"
    "b.hidden=false;b.addEventListener('click',function(){"
    "var t=document.getElementById(b.getAttribute('data-copy'));"
    "var s=document.getElementById(b.getAttribute('data-copy')+'-done');"
    "function ok(){if(s){s.hidden=false;}}"
    "if(navigator.clipboard){navigator.clipboard.writeText(t.value).then(ok,function(){"
    "t.select();});}else{t.select();}});});"
    "var f=document.getElementById('server'),d=document.getElementById('dest-host'),"
    "p=document.getElementById('dest'),w=document.getElementById('password'),"
    "g=document.getElementById('gdpr');"
    "function host(v){v=v.trim();var i=v.indexOf('://');if(i>=0){v=v.slice(i+3);}"
    "v=v.split('/')[0].split('?')[0].split('#')[0];return v.slice(v.lastIndexOf('@')+1);}"
    "if(f&&d&&p){f.addEventListener('input',function(){var h=host(f.value);"
    "d.textContent=h;p.hidden=!h;});}"
    "var b=document.getElementById('gdpr-box'),c=document.getElementById('consent-given'),"
    "t=document.getElementById('consent-text');"
    "['server','company','user'].forEach(function(n){var e=document.getElementById(n);"
    "if(e){e.addEventListener('input',function(){"
    "if(w){w.value='';}if(g){g.checked=false;}"
    "if(b){b.hidden=false;}if(c){c.hidden=true;}if(t){t.open=true;}});}});"
    "var m=document.getElementById('msg');"
    "if(m&&m.getAttribute('role')==='alert'){m.focus();}")
_SCRIPT_HASH = b64encode(sha256(SCRIPT.encode("utf-8")).digest()).decode("ascii")
CSP = _CSP.replace("default-src 'none';",
                   "default-src 'none'; script-src 'sha256-%s';" % _SCRIPT_HASH)

_EXTRA_STYLE = (
    "input[type=text],input[type=password],textarea{width:100%;box-sizing:border-box;"
    "font:inherit;padding:.5rem;margin-top:.2rem}"
    "textarea{min-height:9rem}.hint{color:#333;font-size:.95rem;margin:.2rem 0}"
    "label.tick{display:flex;gap:.5rem;align-items:center;min-height:44px}"
    "label.tick input{flex:none;width:1.25rem;height:1.25rem;margin:0}"
    ".consent{border:1px solid #777;padding:.2rem .8rem;margin:1rem 0}"
    ".dest{overflow-wrap:anywhere}nav p{margin:0}"
    # Touch targets at least 44 px high at phone width (customer test 2026-11-24).
    "nav a{display:inline-block;min-height:44px;line-height:44px;padding:0 .5rem}"
    "input[type=text],input[type=password],button{min-height:44px}"
    "summary{min-height:44px;box-sizing:border-box;padding:.65rem 0}")

# What "Copy support details" may say: the version, the build, the last step and the failure
# category of this connector process. No host, user, password or Books text ever goes in. The
# build belongs to the connection that proved it and is shown only for that connection (recheck,
# NIT).
_SUPPORT = {"stage": "page_not_opened", "error": "none", "build": None, "build_for": None}
_SUPPORT_LOCK = threading.Lock()
_BUILD = re.compile(r"[0-9]+(?:\.[0-9]+){3}")


def _note(stage, error="none", build=None, *, connection=None, keep_build=False):
    """The last step for the support details. The build is the one this step proved for
    `connection` (None: not known), so a failed sign-in, a Forget or another server never shows
    an older build (Astra review of slice 3, NIT); only saving the choices keeps it."""
    with _SUPPORT_LOCK:
        _SUPPORT["stage"], _SUPPORT["error"] = stage, error
        if not keep_build:
            _SUPPORT["build"], _SUPPORT["build_for"] = build, connection


def support_details(values=None) -> str:
    """The support text (English, for Excellent's support): never a host, user or secret.
    `values`: the saved settings (None: read them now)."""
    from . import __version__

    values = config.read_plugin_settings() if values is None else values
    with _SUPPORT_LOCK:
        facts = dict(_SUPPORT)
    build = facts["build"]
    if build is not None and (facts["build_for"] is None
                              or facts["build_for"] != _connection(values)):
        build = None                      # proved for another connection than the saved one
    configured = all(values.get(key, "").strip() for key in config.PLUGIN_REQUIRED)
    approve = "chat" if config._is_chat(config._approval_word(
        values.get(config.APPROVE_IN_KEY, "")), "plugin") else "browser"
    return "\n".join((
        "Excellent Books plugin, support details",
        "Connector version: %s" % __version__,
        "Books build: %s" % (build or "unknown"),
        "Settings saved: %s" % ("yes" if configured else "no"),
        "Last step: %s" % facts["stage"],
        "Error category: %s" % facts["error"],
        "Saving changes: %s" % ("on" if config._said_yes(values.get(config.WRITES_KEY)) else "off"),
        "Approval: %s" % approve,
    ))


# -- the test sign-in ---------------------------------------------------------------------------

def _sign_in_guard():
    """The signed control file's stops apply to this login too (erp.Session.guard)."""
    from . import control
    return control.guard


def _category(status):
    """The fixed failure category of an HTTP status from either sign-in request."""
    if status in (401, 403):
        return "credentials"
    if status == 404:
        return "company_missing"
    return "unreachable" if status >= 500 else "not_books"


def _cookie_read(session, timeout):
    """The read on the HSESSION cookie: never redirected, never a second login. (status, body)."""
    in_login, session._in_login = session._in_login, True
    try:
        response = session.request(session.cfg.api_base + "/CUVc?fields=Code&limit=1",
                                   timeout=timeout, follow_redirects=False)
    finally:
        session._in_login = in_login
    return response.status, response.body


def sign_in_test(cfg, deadline=None):
    """One Basic login without redirects, then one read on its HSESSION cookie. Returns
    (category, build): category None when it worked, else one of credentials, company_missing,
    unreachable, not_books, rest_off, control_unreachable, unavailable. Never raises; never keeps
    the password.
    `deadline`: a time.monotonic() value both requests' timeouts stay inside."""
    from . import control

    def left():
        if deadline is None:
            return SIGN_IN_TIMEOUT
        return max(0.5, min(SIGN_IN_TIMEOUT, deadline - time.monotonic()))

    session = erp.Session(cfg, timeout=left())
    session.guard = _sign_in_guard()
    try:
        try:
            session._basic_login(follow_redirects=False)
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("the test sign-in ran out of time")
            status, body = _cookie_read(session, left())
        finally:
            session.cfg = cfg = None          # a failure's traceback keeps no password
    except erp.RestApiNotAllowed:
        return "rest_off", None
    except control.Stopped as exc:
        # The control file from knowledge.excellent.ee could not be confirmed: say so plainly.
        if exc.refusal.get("error") == "control_unavailable":
            return "control_unreachable", None
        return "unavailable", None
    except urllib.error.HTTPError as exc:
        return _category(exc.code), None
    except erp.SignInAgain:
        return "credentials", None
    except (erp.RedirectRefused, erp.ErpError):
        return "not_books", None
    except (urllib.error.URLError, OSError, TimeoutError):
        return "unreachable", None
    except Exception:
        return "unavailable", None
    if status != 200:
        return _category(status), None
    if not erp._answers_for_cuvc(body):       # a proxy's sign-in page can also answer 200
        return "not_books", None
    build = session.system_version
    return None, (build if isinstance(build, str) and _BUILD.fullmatch(build) else None)


def _sign_in_within_deadline(cfg):
    """sign_in_test with a total deadline (recheck, point 8): it runs in its own thread, and when
    the deadline passes the answer is "unreachable" and its late result is thrown away. The
    thread holds no lock and writes nothing, so the settings lock is released on this path too."""
    box = {}
    deadline = time.monotonic() + SIGN_IN_DEADLINE

    def run():
        box["result"] = sign_in_test(cfg, deadline)

    worker = threading.Thread(target=run, name="ebmcp-settings-sign-in", daemon=True)
    worker.start()
    worker.join(SIGN_IN_DEADLINE)
    return box.get("result", ("unreachable", None))


# -- drawing the page ---------------------------------------------------------------------------

_FORMS_LOCK = threading.Lock()


def _new_form(authority, version, digest):
    """A token for one drawn form, bound to the revision and the consent text it was drawn for."""
    token = secrets.token_urlsafe(32)
    with _FORMS_LOCK:
        authority.forms[token] = (version, digest)
        while len(authority.forms) > FORMS_KEPT:
            del authority.forms[next(iter(authority.forms))]
    return token


def _take_form(authority, token):
    """Spend a drawn form's token: (version, digest), or None when it is not one of ours."""
    with _FORMS_LOCK:
        for key in list(authority.forms):
            if _equal(token, key):
                return authority.forms.pop(key)
    return None


class _Result:
    """One spent token's submission (its fingerprint) and, once done, its own answer."""

    def __init__(self, fingerprint):
        self.fingerprint = fingerprint
        self.done = threading.Event()
        self.answer = None


def _fingerprint(action, form):
    """What a submission asked for: the action and every field but the token, the password only
    as typed or not (never kept)."""
    fields = sorted((key, values) for key, values in form.items()
                    if key not in ("csrf", "password"))
    typed = bool(form.get("password", [""])[0]) if form.get("password") else False
    return sha256(json.dumps([action, fields, typed]).encode("utf-8")).hexdigest()


def _spent(authority, token):
    with _FORMS_LOCK:
        for key, result in authority.results.items():
            if _equal(token, key):
                return result
    return None


def _keep_result(authority, token, result):
    with _FORMS_LOCK:
        authority.results[token] = result
        while len(authority.results) > FORMS_KEPT:
            del authority.results[next(iter(authority.results))]


def _copy(language):
    return page_texts.SETTINGS_TEXTS[language]


def _language(handler, authority, query=""):
    asked = parse_qs(query).get("lang", [""])[0] if query else ""
    if asked in page_texts.SETTINGS_TEXTS:
        authority.language = asked
    elif authority.language not in page_texts.SETTINGS_TEXTS:
        authority.language = page_texts.language_from_header(
            handler.headers.get("Accept-Language", ""))
        if authority.language not in page_texts.SETTINGS_TEXTS:
            authority.language = page_texts.DEFAULT_LANGUAGE
    return authority.language


def _host(address):
    try:
        return urlsplit(config.clean_server_url(address)).netloc
    except config.ConfigError:
        return ""


def _identity(server, company, user):
    """The connection a page shows, compared with the saved one: the server root, the company
    number and the user case-folded like config.connection_id (Books logins are
    case-insensitive). An address or company that does not parse is compared as typed. None when
    all three are empty."""
    server, company, user = server.strip(), company.strip(), user.strip()
    if not (server or company or user):
        return None
    try:
        root = config.plugin_server_root(server)
    except config.ConfigError:
        root = "typed:" + server
    try:
        number = str(config._company_number(company))
    except config.ConfigError:
        number = "typed:" + company
    return (root, number, user.casefold())


def _connection(values):
    """The saved connection's id, or None when the file names none."""
    try:
        return config.connection_id(config.Config(
            api_base=config.plugin_api_base(values), user=values["EBMCP_USER"], password=""))
    except (KeyError, config.ConfigError):
        return None


def _connections(values):
    """Every id the saved login's consent may have been recorded under (recheck, MUST 3): the
    current one, and for a root saved before the fix (ending in /api/<n>) the two ids the older
    code used: the stored root as it was, and that root cleaned once."""
    found = []
    try:
        server, user = values["EBMCP_SERVER_URL"].strip(), values["EBMCP_USER"]
        company = config._company_number(values["EBMCP_COMPANY"])
    except (KeyError, config.ConfigError):
        return found
    bases = []
    try:
        bases.append(config.plugin_api_base(values))
    except (KeyError, config.ConfigError):
        pass
    try:
        bases.append("%s/api/%d" % (config._validated_url(server).geturl().rstrip("/"), company))
    except config.ConfigError:
        pass
    try:
        bases.append(config.compose_api_base(server, company))
    except config.ConfigError:
        pass
    for base in bases:
        try:
            found.append(config.connection_id(config.Config(api_base=base, user=user,
                                                            password="")))
        except config.ConfigError:
            continue
    return list(dict.fromkeys(found))


def _invalid(name, faults, hint_id=None):
    """aria-invalid and aria-describedby for a field the message names (fix 6)."""
    described = " ".join(part for part in (hint_id, "msg" if name in faults else None) if part)
    return ((' aria-invalid="true"' if name in faults else "")
            + (f' aria-describedby="{described}"' if described else ""))


def _field(name, label, value, copy, *, kind="text", autocomplete="off", hint=None, faults=()):
    hint_id = f"{name}-hint"
    parts = [f'<p><label for="{name}">{_text(copy[label])}</label>'
             f'<input id="{name}" name="{name}" type="{kind}" value="{_text(value)}" '
             f'autocomplete="{autocomplete}" spellcheck="false"'
             + _invalid(name, faults, hint_id if hint else None) + ">"]
    if hint:
        parts.append(f'<span class="hint" id="{hint_id}">{_text(hint)}</span>')
    parts.append("</p>")
    return "".join(parts)


# The field a message is about (fix 6): it gets aria-invalid and points at the message.
_FAULTS = {"address_invalid": ("server",), "https_only": ("server",), "unreachable": ("server",),
           "not_books": ("server",), "company_invalid": ("company",),
           "company_missing": ("company",), "user_invalid": ("user",), "rest_off": ("user",),
           "credentials": ("user", "password"), "password_needed": ("password",),
           "password_invalid": ("password",), "gdpr_required": ("gdpr",)}
# Messages that report success; every other one is an alert that takes the focus.
_DONE = frozenset({"connected", "options_saved", "forgotten", "forgotten_login"})


def _message(copy, message):
    if message in _DONE:
        return f'<p id="msg" role="status" class="status">{_text(copy[message])}</p>'
    return f'<p id="msg" role="alert" tabindex="-1" class="status">{_text(copy[message])}</p>'


def render(page_id, authority, language, *, message=None, typed=None):
    """The whole page. Draws only saved or just-typed values, never a password, and never a
    ticked consent box; each drawn form gets a token bound to this read's revision and the
    consent text drawn."""
    copy = _copy(language)
    title = copy["title"]
    path = f"/s/{page_id}"
    parts = [f'<!doctype html><html lang="{_text(language)}"><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             f'<title>{_text(title)}</title><style>{_STYLE}{_EXTRA_STYLE}</style>',
             '<body><nav aria-label="%s"><p>' % _text(copy["language"])]
    parts.append(" | ".join(
        (f'<a href="{path}?lang={code}" lang="{code}" hreflang="{code}"'
         + (' aria-current="page"' if code == language else "") + f'>{_text(name)}</a>')
        for code, name in (("en", "English"), ("et", "Eesti"))))
    parts.append(f'</p></nav><h1>{_text(title)}</h1>')
    try:
        saved, version, _forgotten = config.read_plugin_state()
    except (config.ConfigError, OSError):
        parts.append(_message(copy, "unreadable"))
        return "".join(parts) + "</body></html>"
    configured = all(saved.get(key, "").strip() for key in config.PLUGIN_REQUIRED)
    shown = typed if typed is not None else {
        "server": saved.get("EBMCP_SERVER_URL", ""), "company": saved.get("EBMCP_COMPANY", ""),
        "user": saved.get("EBMCP_USER", "")}
    # The choices, Forget and the consent on record belong to the saved connection: a page that
    # shows another connection shows only that one (fix 3).
    own = configured and _identity(
        shown.get("server", ""), shown.get("company", ""), shown.get("user", "")) == _identity(
        saved["EBMCP_SERVER_URL"], saved["EBMCP_COMPANY"], saved["EBMCP_USER"])
    consented = own and consent.status("gdpr", _connection(saved)) == "given"
    if consented:
        parts.append('<p class="dest">%s</p>' % _text(copy["connected_to"].format(
            host=_host(saved["EBMCP_SERVER_URL"]), company=saved["EBMCP_COMPANY"],
            user=saved["EBMCP_USER"])))
    if message:
        parts.append(_message(copy, message))
    faults = _FAULTS.get(message, ())
    if message == "missing":
        faults = tuple(name for name in ("server", "company", "user")
                       if not shown.get(name, "").strip())
        if shown.get("password_missing"):
            faults += ("password",)
    text = consent.plugin_gdpr_texts()[language]
    digest = sha256(text.encode("utf-8")).hexdigest()
    token = _text(_new_form(authority, version, digest))
    parts.append(f"<p>{_text(copy['intro'])}</p>")
    parts.append(f'<form method="post" action="{path}/save">'
                 f'<input type="hidden" name="csrf" value="{token}">'
                 f'<input type="hidden" name="text" value="{digest}">')
    parts.append(_field("server", "server", shown.get("server", ""), copy,
                        hint=copy["server_hint"], faults=faults))
    parts.append(_field("company", "company", shown.get("company", ""), copy, faults=faults))
    parts.append(_field("user", "user", shown.get("user", ""), copy, autocomplete="username",
                        faults=faults))
    # new-password: a browser must not fill a remembered password in for a changed destination
    # (Astra review of slice 3, SHOULD); the script also clears it when the destination changes.
    parts.append(_field("password", "password", "", copy, kind="password",
                        autocomplete="new-password",
                        hint=copy["password_keep"] if configured else None, faults=faults))
    host = _host(shown.get("server", ""))
    parts.append(f'<p class="dest" id="dest"{"" if host else " hidden"}>'
                 f'{_text(copy["destination"])} <strong id="dest-host">{_text(host)}</strong></p>')
    parts.append(f'<section class="consent"><h2>{_text(copy["consent_heading"])}</h2>')
    paragraphs = "".join(f"<p>{_text(para)}</p>" for para in text.split("\n\n") if para.strip())
    # Never ticked in advance: a yes is given on this form, in this post.
    box = ('<label class="tick"><input type="checkbox" id="gdpr" name="gdpr" value="yes"'
           + _invalid("gdpr", faults) + f'> <span>{_text(copy["consent_yes"])}</span></label></p>')
    if consented:
        # The consent on record is shown as given; the box appears when a destination field
        # changes (the page's script) or on a page for another connection (fix 2).
        parts.append(f'<p id="consent-given">{_text(copy["consent_given"])}</p>'
                     f'<details id="consent-text"><summary>{_text(copy["consent_show"])}'
                     f'</summary>{paragraphs}</details><p id="gdpr-box" hidden>{box}')
    else:
        parts.append(f"{paragraphs}<p>{box}")
    parts.append("</section>")
    parts.append(f'<div class="buttons"><button type="submit">{_text(copy["save"])}</button>'
                 "</div></form>")
    parts.append(f'<details><summary>{_text(copy["dont_know"])}</summary>'
                 f'<p>{_text(copy["dont_know_help"])}</p>'
                 + _copy_area("request", copy["dont_know"], copy["request_text"],
                              copy["copy_request"], copy) + "</details>")
    if own:
        parts.extend(_more(path, token, saved, copy))
    parts.append(f'<script>{SCRIPT}</script></body></html>')
    return "".join(parts)


def _copy_area(name, label, text, button, copy):
    return (f'<textarea id="{name}" readonly aria-label="{_text(label)}">{_text(text)}</textarea>'
            f'<div class="buttons"><button type="button" data-copy="{name}" hidden>'
            f'{_text(button)}</button></div>'
            f'<p id="{name}-done" role="status" hidden>{_text(copy["copied"])}</p>')


def _more(path, token, saved, copy):
    writes = config._said_yes(saved.get(config.WRITES_KEY))
    chat = config._is_chat(config._approval_word(saved.get(config.APPROVE_IN_KEY, "")), "plugin")
    return [
        f'<h2>{_text(copy["more_heading"])}</h2>',
        f'<form method="post" action="{path}/options"><input type="hidden" name="csrf" '
        f'value="{token}">',
        '<p><label class="tick"><input type="checkbox" name="writes" value="yes"'
        + (" checked" if writes else "") + f'> <span>{_text(copy["writes"])}</span></label></p>',
        f'<p class="hint">{_text(copy["writes_help"])}</p>',
        '<p><label class="tick"><input type="checkbox" name="chat" value="yes"'
        + (" checked" if chat else "") + f'> <span>{_text(copy["chat"])}</span></label></p>',
        f'<p class="hint">{_text(copy["chat_help"])}</p>',
        f'<p class="hint">{_text(copy["restart_note"])}</p>',
        f'<div class="buttons"><button type="submit">{_text(copy["options_save"])}</button></div>'
        "</form>",
        f'<h2>{_text(copy["forget_heading"])}</h2><p>{_text(copy["forget_help"])}</p>',
        f'<form method="post" action="{path}/forget"><input type="hidden" name="csrf" '
        f'value="{token}"><p><label class="tick"><input type="checkbox" name="confirm" '
        f'value="yes"> <span>{_text(copy["forget_confirm"])}</span></label></p>'
        f'<div class="buttons"><button type="submit">{_text(copy["forget"])}</button></div></form>',
        f'<h2>{_text(copy["support_heading"])}</h2><p>{_text(copy["support_help"])}</p>',
        _copy_area("support", copy["support_heading"], support_details(saved),
                   copy["copy_support"], copy),
    ]


# -- requests -------------------------------------------------------------------------------------

def get(handler, page_id, authority, query):
    """GET /s/<page>[?lang=xx], under the page server's lock."""
    owner = handler.owner
    authority.seen = (owner._clock(), owner._wall())
    language = _language(handler, authority, query)
    with _SUPPORT_LOCK:
        if _SUPPORT["stage"] == "page_not_opened":
            _SUPPORT["stage"] = "page_opened"
    handler._respond(200, render(page_id, authority, language), csp=CSP)


def post(handler, page_id, action, form):
    """POST /s/<page>/<action>. The token is spent under the page lock; the work (a sign-in test,
    a file write) runs outside it, under the settings lock. A repeat of the same submission on a
    spent token gets that submission's own answer; a different one is refused."""
    owner = handler.owner
    fingerprint = _fingerprint(action, form)
    with owner._lock:
        authority = handler._authority("s", page_id)
        token = form.get("csrf", [])
        if authority is None or len(token) != 1:
            handler._respond(403)
            return
        result = _spent(authority, token[0])
        if result is None:
            bound = _take_form(authority, token[0])
            if bound is None:
                handler._respond(403)
                return
            version, digest = bound
            result, first = _Result(fingerprint), True
            _keep_result(authority, token[0], result)
        else:
            first = False
        authority.seen = (owner._clock(), owner._wall())
        language = _language(handler, authority)
    if not first:
        if not _equal(result.fingerprint, fingerprint):
            # Another submission on a spent token: never the first one's answer (NEW MUST 1).
            handler._respond(409, render(page_id, authority, language, message="error"), csp=CSP)
            return
        result.done.wait(SAVE_WAIT_SECONDS)
        answer = result.answer
        if answer is None:
            answer = (409, render(page_id, authority, language, message="in_progress"))
        handler._respond(*answer, csp=CSP)
        return
    answer = None
    try:
        work = {"save": _save, "options": _options, "forget": _forget}[action]
        try:
            with config.plugin_settings_locked(timeout=LOCK_WAIT_SECONDS):
                answer = work(page_id, authority, language, form, version, digest)
        except config.SettingsBusy:
            answer = (503, render(page_id, authority, language, message="save_failed"))
    except Exception:
        answer = (500, render(page_id, authority, language, message="error"))
    finally:
        form.pop("password", None)
        result.answer = answer
        result.done.set()
    handler._respond(*answer, csp=CSP)


def _one(form, name):
    values = form.get(name, [])
    return values[0] if len(values) == 1 else ""


def _current(page_id, authority, language, version):
    """Under the settings lock: (saved values, forgotten, None) when the file is still the
    revision the form was drawn from, else (None, None, the answer to send). Nothing is sent
    before this passes."""
    try:
        saved, now, forgotten = config.read_plugin_state()
    except (config.ConfigError, OSError):
        return None, None, (503, render(page_id, authority, language, message="unreadable"))
    if version is None or now != version:
        return None, None, (409, render(page_id, authority, language, message="stale"))
    return saved, forgotten, None


def _take_back(connection, before, previous):
    """A consent this Save recorded for a connection that did not have one: put back as it was
    (`previous`, from consent.snapshot) after the settings write failed, so the page's "nothing
    was changed" stays true (recheck, NEW MUST 2). A missing or stale consent stays missing or
    stale, never a withdrawal (Kaia's review of PR #4). True when nothing is left to take back."""
    if before == "given":
        return True                 # record() changed nothing
    try:
        consent.restore("gdpr", connection, previous)
    except (OSError, config.ConfigError):
        return False
    return consent.status("gdpr", connection) == before


def _save(page_id, authority, language, form, version, digest):
    """Test connection and save, under the settings lock. Every refusal before the sign-in sends
    nothing at all."""
    typed = {"server": _one(form, "server").strip(), "company": _one(form, "company").strip(),
             "user": _one(form, "user").strip()}
    if any(char in typed["server"] for char in "@?#"):
        # An address with a login, a query or a fragment in it is never drawn back: it may hold a
        # password or a token (Astra review of slice 3, SHOULD, and its recheck, SHOULD 2).
        typed["server"] = ""
        return 400, render(page_id, authority, language, message="address_invalid", typed=typed)

    def again(message, status=400):
        return status, render(page_id, authority, language, message=message, typed=typed)

    posted = _one(form, "text")
    shown = consent.plugin_text_language(digest)
    # The yes is for the text THIS form drew (MUST 4), not any current plugin wording.
    if shown is None or not posted or not _equal(posted, digest):
        return again("error")
    saved, forgotten, refused = _current(page_id, authority, language, version)
    if refused is not None:
        return refused
    password = _one(form, "password")
    if not (typed["server"] and typed["company"] and typed["user"]):
        typed["password_missing"] = not password   # a flag for aria-invalid, never the password
        return again("missing")
    raw = typed["server"]
    if "://" in raw and not raw.lower().startswith("https://"):
        return again("https_only")
    try:
        server = config.plugin_server_root(raw)
    except config.ConfigError:
        return again("address_invalid")
    if urlsplit(server).scheme != "https":
        return again("https_only")
    try:
        company = config._company_number(typed["company"])
    except config.ConfigError:
        return again("company_invalid")
    if not erp.login_user_ok(typed["user"]):
        return again("user_invalid")
    # The stored values are the root, company and user that passed the last sign-in: compared
    # as stored, never cleaned again (MUST 1). Forget's tombstone has no login: only a full Save
    # with a typed password and the consent replaces it (recheck, NEW MUST 2). The user is
    # case-folded like config.connection_id: "Mari" and "mari" are one Books login.
    same = (not forgotten and saved.get("EBMCP_SERVER_URL") == server
            and saved.get("EBMCP_COMPANY") == str(company)
            and saved.get("EBMCP_USER", "").casefold() == typed["user"].casefold())
    # The consent is the box ticked in this post, for this post's connection (fix 1). Saving the
    # saved connection again needs no tick while its consent is on record (fix 2).
    ticked = _one(form, "gdpr") == "yes"
    if not ticked and not (same and consent.status("gdpr", _connection(saved)) == "given"):
        return again("gdpr_required")
    if not password:
        # The saved password belongs to the saved connection only (Review change 1).
        if not same or not saved.get(_PASSWORD_KEY):
            return again("password_needed")
        password = saved[_PASSWORD_KEY]
    if any(char in password for char in "\r\n\x00"):
        return again("password_invalid")
    cfg = config.Config(api_base="%s/api/%d" % (server, company), user=typed["user"],
                        password=password)
    connection = config.connection_id(cfg)
    category, build = _sign_in_within_deadline(cfg)
    cfg = None
    if category is not None:
        password = None
        _note("sign_in_failed", category)
        return again(category, 401 if category == "credentials" else 502)
    values = {"EBMCP_SERVER_URL": server, "EBMCP_COMPANY": str(company),
              "EBMCP_USER": typed["user"], _PASSWORD_KEY: password,
              # A new connection starts with writing off and browser approval (Review change 6).
              config.WRITES_KEY: saved.get(config.WRITES_KEY, "no") if same else "no",
              config.APPROVE_IN_KEY: saved.get(config.APPROVE_IN_KEY, "browser") if same
              else "browser"}
    password = None
    before, previous = consent.status("gdpr", connection), None
    try:
        # The consent first: without it nothing is saved, so no login is ever usable with a
        # missing consent (MUST 3). Without a tick the consent on record stands.
        if ticked:
            previous = consent.snapshot("gdpr", connection)
            consent.record("gdpr", connection, consent.plugin_gdpr_texts()[shown])
    except (OSError, config.ConfigError):
        values = None
        _note("consent_failed", "consent_failed")
        return again("consent_failed", 500)
    try:
        config.save_plugin_settings(values, expected_version=version)
    except config.StaleSettings:
        # Only a hand edit gets past the settings lock; the sign-in was sent by then.
        _note("save_refused_stale", "stale")
        if not _take_back(connection, before, previous):
            return again("consent_kept", 500)
        return 409, render(page_id, authority, language, message="stale_after_test")
    except (config.ConfigError, OSError):
        _note("save_failed", "save_failed")
        if not _take_back(connection, before, previous):
            return again("consent_kept", 500)
        return again("save_failed", 500)
    finally:
        values = None
    _note("connected", "none", build, connection=connection)
    return 200, render(page_id, authority, language, message="connected")


def _options(page_id, authority, language, form, version, digest):
    """Saving changes and chat approval, under the settings lock: no sign-in (switching off must
    work while Books is down). Switching off takes effect at once; switching on after the host
    restarts the connector (config.plugin_switch_on)."""
    saved, _forgotten, refused = _current(page_id, authority, language, version)
    if refused is not None:
        return refused
    if not all(saved.get(key, "").strip() for key in config.PLUGIN_REQUIRED):
        return 409, render(page_id, authority, language, message="stale")
    values = dict(saved)
    values[config.WRITES_KEY] = "yes" if _one(form, "writes") == "yes" else "no"
    values[config.APPROVE_IN_KEY] = "chat" if _one(form, "chat") == "yes" else "browser"
    try:
        config.save_plugin_settings(values, expected_version=version)
    except config.StaleSettings:
        return 409, render(page_id, authority, language, message="stale")
    except (config.ConfigError, OSError):
        return 500, render(page_id, authority, language, message="save_failed")
    finally:
        values = saved = None
    _note("choices_saved", keep_build=True)
    return 200, render(page_id, authority, language, message="options_saved")


def _forget(page_id, authority, language, form, version, digest):
    """Under the settings lock: check the revision, write Forget's tombstone (one atomic write:
    the login is gone, the revision goes on), then write the GDPR withdrawal for every id the old
    login had, without reading the consent store first (recheck, MUST 3 and NEW MUST 2; customer
    test fix 4). A failed tombstone changes nothing; "withdrawn" is said only when a withdrawal
    was written. The HR decision stays its own (it is asked separately and stays per
    connection)."""
    if _one(form, "confirm") != "yes":
        return 400, render(page_id, authority, language, message="forget_needs_confirm")
    saved, _forgotten, refused = _current(page_id, authority, language, version)
    if refused is not None:
        return refused
    connections = _connections(saved)
    saved = None
    try:
        config.forget_plugin_settings(expected_version=version)
    except config.StaleSettings:
        return 409, render(page_id, authority, language, message="stale")
    except (config.ConfigError, OSError):
        _note("forget_failed", "forget_failed")
        return 500, render(page_id, authority, language, message="forget_failed")
    had = failed = False
    for connection in connections:
        try:
            had = consent.withdraw("gdpr", connection) or had
        except (OSError, config.ConfigError):
            failed = True
    if failed:
        _note("forget_consent_failed", "forget_failed")
        return 500, render(page_id, authority, language, message="forget_consent_failed")
    _note("forgotten")
    return 200, render(page_id, authority, language,
                       message="forgotten" if had else "forgotten_login")
