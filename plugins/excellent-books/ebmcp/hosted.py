"""Hosted startup policy, Books destinations and connections, and client registration."""
from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import weakref
from pathlib import Path
from collections import OrderedDict, deque
from collections.abc import Callable
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address
from math import ceil
from threading import Event, Lock
from time import monotonic, time
from typing import Iterator, Optional
from urllib.parse import urlsplit

from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.handlers.register import RegistrationHandler
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import ProviderTokenVerifier, RegistrationError
from mcp.server.auth.routes import build_metadata, cors_middleware
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared import session as mcp_session
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from . import approval, audit, auth, config, erp, page_texts, privacy, usage

RELEASED = False
PKOREA = "pkorea.excellent.ee:4455"
REGISTRATIONS_PER_HOUR = 10
MAX_CONNECTIONS = 500
IDLE_SECONDS = 3600
MAX_SECONDS = 12 * 3600
WAIT_TIMEOUT = 60.0
# Hosted writing (design 2026-11-17, section 11): per connection.
MAX_PLANS = 10
PLANS_PER_HOUR = 30
MAX_WAITING = 3
PREVIEW_BYTES = 256 * 1024
CLIENT_NAME_CHARS = 60
# apply_approved's wait for the click (design sections 2 and 11): up to OPEN_WAIT seconds for the
# approval page to be opened, then up to CLICK_WAIT for the click. Settings, each at most
# MAX_WAIT_SETTING: the tool-call time limit of claude.ai and ChatGPT is not verified (Task 45h).
OPEN_WAIT = 20
CLICK_WAIT = 50
MAX_WAIT_SETTING = 110
POLL_SECONDS = 0.5
PROGRESS_SECONDS = 10
_AUDIT_PRUNE_SECONDS = 24 * 3600
# A planned stop (design section 13): running writes get DRAIN_SECONDS from the SIGTERM; uvicorn's
# own wait for open requests is bounded by GRACEFUL_SHUTDOWN_SECONDS (an MCP stream left open would
# otherwise hold it forever). The compose service's stop_grace_period must stay above both
# (deploy/DEPLOY.md: 45 s), or Docker's SIGKILL lands inside the drain (opus review of 45f, M1).
DRAIN_SECONDS = 30.0
GRACEFUL_SHUTDOWN_SECONDS = 35


class _WriteDrain:
    def __init__(self):
        self.lock = Lock()
        self.stopping = False
        self.running = 0
        self.deadline = None            # monotonic; set by the first stop() or drain()

    def draining(self) -> bool:
        with self.lock:
            return self.stopping

    def stop(self, seconds: float = DRAIN_SECONDS) -> None:
        """Refuse approvals, begins and the next batch record from now on. Called from the
        SIGTERM handler, which can interrupt the main thread while it holds `lock` (a plain Lock):
        so no lock here, only two attribute stores, each atomic in CPython. A check that read
        `stopping` just before still finishes; `begin` reads it again under the plan store's lock,
        in the same step as the move to `executing`."""
        if self.deadline is None:
            self.deadline = monotonic() + seconds
        self.stopping = True

    async def drain(self, seconds: float) -> None:
        with self.lock:
            ends = monotonic() + seconds
            # The deadline the signal set holds: the lifespan's drain runs only after uvicorn's
            # own wait, and must not add a second 30 s on top of it.
            self.deadline = ends if self.deadline is None else min(self.deadline, ends)
            deadline = self.deadline
            self.stopping = True
        while True:
            with self.lock:
                if not self.running:
                    return
            remaining = deadline - monotonic()
            if remaining <= 0:
                return
            await asyncio.sleep(min(remaining, 0.05))


_active_writes = _WriteDrain()


def draining() -> bool:
    return _active_writes.draining()


async def drain(seconds: float = DRAIN_SECONDS) -> None:
    """Stop new approvals and starts, then let admitted workers finish up to the deadline."""
    await _active_writes.drain(seconds)


def draining_server(app, sessions, *, host: str, port: int):
    """The hosted uvicorn server. uvicorn 0.42's shutdown closes the socket, waits for every open
    request and only THEN runs the lifespan shutdown, where `drain()` was: too late to refuse a
    click that arrives during that wait (opus review of 45f, M1). So the drain starts in the
    signal handler itself, and uvicorn's wait is bounded. Local and Desktop do not use this."""
    import uvicorn

    class DrainingServer(uvicorn.Server):
        def handle_exit(self, sig, frame):
            sessions._write_drain.stop()
            super().handle_exit(sig, frame)

    return DrainingServer(uvicorn.Config(app, host=host, port=port,
                                         timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS))


USAGE_FLUSH_FLOOR_SECONDS = 1.0


async def _flush_usage(write_drain) -> None:
    """Write the queued usage lines before the process ends: after uvicorn's shutdown the default
    SIGTERM handler can end the process before Python joins the usage worker (Sol re-check of
    abed9f9). Bounded by what is left of the drain window, with a one-second floor so a drain
    that used the whole window still gets its last lines out; the compose stop_grace_period
    (45 s) is above both."""
    deadline = write_drain.deadline
    left = DRAIN_SECONDS if deadline is None else deadline - monotonic()
    await asyncio.to_thread(usage.flush, max(USAGE_FLUSH_FLOOR_SECONDS, min(left, DRAIN_SECONDS)))


def write_lifespan(app, sessions) -> None:
    """Wrap FastMCP's lifespan so its session manager stays up through draining."""
    original = app.router.lifespan_context

    def prune_both(now):
        # The write trail and, since Kaupo 2026-11-19 (45f review N5), the usage log: both keep
        # 90 days. Each prune swallows its own disk errors, so one never stops the other.
        audit.prune(now)
        usage.prune(now)

    async def prune_logs():
        await asyncio.to_thread(prune_both, datetime.now(timezone.utc))

    async def periodic_prune(stop):
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=_AUDIT_PRUNE_SECONDS)
            except TimeoutError:
                await prune_logs()

    @asynccontextmanager
    async def lifespan(app):
        global _active_writes
        async with original(app) as state:
            _active_writes = sessions._write_drain
            await prune_logs()
            stop = asyncio.Event()
            pruning = asyncio.create_task(periodic_prune(stop))
            try:
                yield state
            finally:
                stop.set()
                try:
                    if _active_writes is sessions._write_drain:
                        await drain()
                    else:
                        await sessions._write_drain.drain(DRAIN_SECONDS)
                finally:
                    try:
                        await pruning
                    finally:
                        await _flush_usage(sessions._write_drain)

    app.router.lifespan_context = lifespan

_DEFAULT_REDIRECTS = frozenset({
    # Verified 2026-11-19 in the Claude Help Center:
    # https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp
    "https://claude.ai/api/mcp/auth_callback",
    # Verified 2026-11-19 in OpenAI's OAuth docs (stable callback for eligible issuers):
    # https://developers.openai.com/plugins/build/auth#redirect-url
    "https://chatgpt.com/connector_platform_oauth_redirect",
})
_HOST_PORT = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
                        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?:([0-9]{1,5})")


def _entries(value: str) -> frozenset[str]:
    return frozenset(entry.strip() for entry in value.split(",") if entry.strip())


def log_servers(env) -> frozenset[str]:
    """Books servers proven to hold ONE company, whose own log the hosted connector may read
    (`EBMCP_HOSTED_LOG_SERVERS`, exact host:port, empty by default). The proof is written and part
    of the hosted security gate (Task 48); a malformed list proves nothing (Task 44)."""
    raw = _entries(env.get("EBMCP_HOSTED_LOG_SERVERS") or "")
    if not all(entry.isascii() for entry in raw):
        return frozenset()
    hosts = frozenset(h.lower() for h in raw)
    for host in hosts:
        match = _HOST_PORT.fullmatch(host)
        if not match or not 0 < int(match[1]) <= 65535:
            return frozenset()
    return hosts


def allowed_hosts(env) -> frozenset[str]:
    """Read exact host:port entries. A malformed entry invalidates the list."""
    # Lower-cased like the destinations it is compared with: an upper-case entry must not refuse
    # everything without a word (Task 38 review N4).
    raw = _entries(env.get("EBMCP_HOSTED_ALLOWED_HOSTS") or "")
    if not all(entry.isascii() for entry in raw):
        return frozenset()                  # a lookalike must not fold into a listed name (re-check)
    hosts = frozenset(h.lower() for h in raw)
    for host in hosts:
        match = _HOST_PORT.fullmatch(host)
        if not match or not 0 < int(match[1]) <= 65535:
            return frozenset()
    return hosts


def _wait_setting(env, key: str, default: float) -> float:
    raw = (env.get(key) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{key} must be a number of seconds.") from None
    if not 0 < value <= MAX_WAIT_SETTING:
        raise ValueError(f"{key} must be more than 0 and at most {MAX_WAIT_SETTING} seconds.")
    return value


def waits(env) -> tuple[float, float]:
    """(open wait, click wait) in seconds: EBMCP_HOSTED_OPEN_WAIT and EBMCP_HOSTED_CLICK_WAIT,
    else OPEN_WAIT and CLICK_WAIT. A setting that is not a number in (0, 110] raises ValueError;
    check_start refuses it, so a running server never meets one."""
    return (_wait_setting(env, "EBMCP_HOSTED_OPEN_WAIT", OPEN_WAIT),
            _wait_setting(env, "EBMCP_HOSTED_CLICK_WAIT", CLICK_WAIT))


def writes_enabled(env) -> bool:
    """The operator's switch for hosted writing: EBMCP_HOSTED_WRITES=yes on the container.
    EBMCP_WRITES is never read in hosted mode (check_start refuses it, Task 46)."""
    return (env.get("EBMCP_HOSTED_WRITES") or "").strip().lower() == "yes"


WRITING_OFF = (
    "Writing was not switched on when this connection signed in to Excellent Books, so nothing "
    "was prepared or written. To let the AI prepare changes, sign in again: the person "
    "disconnects and connects this connector again in their AI client and ticks the box that "
    "lets the AI prepare changes. Each change still waits for their approval on the Excellent "
    "Books site.")
SLOW_DOWN = (
    "Too many changes were prepared on this connection in the last hour, so this one was not "
    "prepared. Nothing was written. Wait a while and plan it again.")
PREVIEW_TOO_LARGE = (
    "This change is too large to show on one approval page, so it was not prepared and nothing "
    "was written. Split it into smaller changes and plan each one.")
TOO_MANY_PLANS = (
    "Ten changes are already waiting on this connection, so this one was not prepared and "
    "nothing was written. The person approves or declines the waiting ones on the Excellent "
    "Books site first; then plan this one again.")


class PreviewTooLarge(approval.ApprovalError):
    code = "preview_too_large"


class TooManyPlans(approval.ApprovalError):
    code = "too_many_plans"


class PlanRefused(approval.ApprovalError):
    """The connection may not issue a plan any more: its tick, a stop, or it ended. `refusal`
    is the tool answer."""

    def __init__(self, refusal: dict):
        super().__init__(refusal.get("why") or refusal.get("error"))
        self.refusal = refusal


class Draining(approval.ApprovalError):
    code = "draining"

    def __init__(self):
        super().__init__(page_texts.hosted_text("hosted_draining"))


def _signed_out() -> dict:
    return {"error": "sign_in_again", "why": SIGN_IN_AGAIN}


class ConnectionPlans(approval.PlanStore):
    """One connection's plans (design section 8): at most MAX_PLANS held, and no plan whose
    preview is over PREVIEW_BYTES (section 11) is ever issued.

    `may_issue(fetch)` is asked twice as a plan is issued, after the preview's last Books read:
    with `fetch=True` before the store's lock (the control file may be fetched, up to 5 s), then
    with `fetch=False` under it, at the moment the plan is added (in-memory facts only: never a
    network wait under the lock that a revoke's `close()` or a `get()` on the event loop would
    wait behind). A stop, an untick or an ended connection that came while the call waited, read,
    fetched or copied issues nothing (Sol review of 9c12e6c, MUST-FIX 2; re-checks of c9f0fc0
    and a90dac7). `issued()` is told once a plan is issued (the hourly count). `close()` (the
    connection was dropped) refuses every later plan."""

    def __init__(self, may_issue=None, issued=None):
        super().__init__(max_plans=MAX_PLANS)
        self._may_issue = may_issue
        self._issued = issued
        self._write_drain = _WriteDrain()
        self.closed = False

    def close(self) -> None:
        """No new plan from now on. A plan already executing still finishes in this store."""
        with self._changed:
            self.closed = True

    def issue(self, envelope, payload):
        if len(envelope.preview.encode("utf-8")) > PREVIEW_BYTES:
            raise PreviewTooLarge(PREVIEW_TOO_LARGE)
        refusal = self._may_issue(True) if self._may_issue is not None else None
        if refusal:                         # may fetch: outside the store's lock
            raise PlanRefused(refusal)
        plan_id = super().issue(envelope, payload)
        if self._issued is not None:
            self._issued()
        usage.hosted_plan("issued")
        return plan_id

    def _expire(self, plan):
        expired = super()._expire(plan)
        if expired is not plan:
            usage.hosted_plan("expired")
        return expired

    def approve(self, plan_id, digest, acknowledged, *, via=None) -> None:
        with self._write_drain.lock:
            if self._write_drain.stopping:
                raise Draining()
            super().approve(plan_id, digest, acknowledged, via=via)

    def draining(self) -> bool:
        return self._write_drain.draining()

    def _may_begin(self) -> None:
        # Read under the store's lock, in the same step as the move to `executing` (Sol re-check
        # of eadb7c1, MUST-FIX): a flag read before waiting for that lock let a plan start after
        # the SIGTERM. `stop()` takes no lock (it runs in the signal handler), so the read here is
        # the moment the plan starts: once the flag is set, no plan reaches `executing`.
        if self._write_drain.stopping:
            raise Draining()

    def begin(self, plan_id) -> approval.Approved:
        with self._write_drain.lock:
            return super().begin(plan_id)

    @contextmanager
    def execution(self, plan_id):
        with self._write_drain.lock:
            approved = super().begin(plan_id)
            self._write_drain.running += 1
        try:
            yield approved
        finally:
            with self._write_drain.lock:
                self._write_drain.running -= 1

    def state(self, plan_id) -> Optional[str]:
        """The plan's state, None when it is not held: polled on the event loop by a waiting
        apply_approved, so no preview is copied (Task 45e)."""
        with self._changed:
            plan = self._plans.get(plan_id)
            return self._expire(plan).state if plan is not None else None

    def count(self, plan_ids, states) -> int:
        """How many of `plan_ids` are held here in one of `states`, without copying a preview."""
        with self._changed:
            return sum(1 for plan_id in list(plan_ids)
                       if (plan := self._plans.get(plan_id)) is not None
                       and self._expire(plan).state in states)

    def _may_add(self) -> None:
        # With the store's lock held: in-memory facts only, no fetch. The control file's own lock
        # (never held across its network fetch) is taken after the store's.
        if self.closed:
            raise PlanRefused(_signed_out())
        refusal = self._may_issue(False) if self._may_issue is not None else None
        if refusal:
            raise PlanRefused(refusal)

    def _victim(self) -> str:
        """Design section 11: "the oldest finished or expired plan is evicted; never an executing
        one". Expired or declined first, then the oldest done one (approval.PlanStore's reason:
        a kept outcome answers a repeated apply). A waiting plan is a preview the person may have
        open, so it is never evicted: with only waiting, approved or executing plans left, the
        new plan is refused (Sol review of 9c12e6c)."""
        plans = [self._expire(self._plans[pid]) for pid in list(self._plans)]
        for states in (("expired", "declined"), ("done",)):
            victim = next((p.plan_id for p in plans if p.state in states), None)
            if victim is not None:
                return victim
        raise TooManyPlans(TOO_MANY_PLANS)


class PlanTurn:
    """One plan call's place in its connection's hourly limit (`may_plan` took it), given back
    exactly once: by the worker thread when its work ends, or, when the work never started, by
    the caller as it leaves. A cancelled caller does not stop a running worker, so the place stays
    taken until that worker ends; a worker that starts after its caller left does no work (Sol
    re-check of c9f0fc0)."""

    def __init__(self, conn: "BooksConnection"):
        self._conn = conn
        self._state = "held"
        self._lock = Lock()

    def start(self) -> bool:
        """In the worker thread, before the work: False when the caller already gave up."""
        with self._lock:
            if self._state != "held":
                return False
            self._state = "running"
            return True

    def end(self) -> None:
        """In the worker thread, after the work."""
        self._release(("running",))

    def give_up(self) -> None:
        """The caller, on every way out: a running worker keeps the place until it ends."""
        self._release(("held",))

    def _release(self, states) -> None:
        with self._lock:
            if self._state not in states:
                return
            self._state = "released"
        self._conn.plan_finished()


def _owned(owner, method):
    """`method` of the connection `owner` (a weak reference) points to; a connection that is
    gone answers "sign in again". Weak, so a store never keeps its connection alive."""
    def call(*args):
        conn = owner()
        return getattr(conn, method)(*args) if conn is not None else _signed_out()
    return call


class NotAllowed(ValueError):
    """The supplied Books address is not an allowed hosted destination."""


def check_destination(raw: str, env) -> str:
    """Return an allowlisted HTTPS origin without opening a connection.

    No address-range check is needed because the allowlist contains exact Excellent
    host names and the ERP opener's Task 2 redirect rule keeps requests on that origin.
    """
    refusal = "This server address is not on the hosted connector's list."
    if not isinstance(raw, str) or not raw.isascii():
        # Not text, or a host that only matches after Unicode case folding (a Kelvin sign for
        # "k"): refused like any other unlisted address (Task 38 review S1, N3).
        raise NotAllowed(refusal)
    try:
        parts = urlsplit(config.clean_server_url(raw))
    except config.ConfigError:
        raise NotAllowed(refusal) from None
    host_port = parts.netloc.lower()
    if parts.scheme != "https" or host_port not in allowed_hosts(env):
        raise NotAllowed(refusal)
    return f"https://{host_port}"


def _connection_label(session: erp.HostedSession) -> str:
    # An unresolved lookup falls back to the case-folded login (Task 39 review S3).
    code = session.usercode if getattr(session, "usercode_resolved", False) else None
    return config.connection_id(session.cfg, user_code=code)


@dataclass
class BooksConnection:
    """One OAuth grant's Books session and consent, held in memory."""

    grant_id: str
    session: erp.HostedSession
    gdpr: bool
    hr: bool
    writes: bool = False                    # the writing tick at sign-in (hosted writing, 45a)
    client: str = ""                        # the OAuth client's own name: shown, never compared
    created: float = field(default_factory=lambda: monotonic())
    signed_in_at: float = field(default_factory=time, init=False, compare=False)
    last_used: float = field(init=False)
    origin: str = field(init=False)
    company: int = field(init=False)
    user: str = field(init=False)
    label: str = field(init=False)
    # This connection's own plans: no tool reaches another connection's (design section 8),
    # and they go with the connection when it is dropped.
    plans: ConnectionPlans = field(init=False, repr=False, compare=False)
    # plan id -> monotonic time its page was first drawn (Sol re-check of 186d2fc, finding 3)
    opened: dict = field(init=False, repr=False, compare=False)
    asked: set = field(init=False, repr=False, compare=False)    # plan ids announced as awaiting
    waiting: set = field(init=False, repr=False, compare=False)  # plan ids a call waits for now
    _planned: deque = field(init=False, repr=False, compare=False)     # when each plan was issued
    _reserved: int = field(init=False, repr=False, compare=False)      # plan calls in flight
    _plan_lock: Lock = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        cfg = self.session.cfg
        self.origin = cfg.origin
        self.company = cfg.company
        self.user = cfg.user
        self.label = _connection_label(self.session)
        self.last_used = self.created
        owner = weakref.ref(self)
        self.plans = ConnectionPlans(may_issue=_owned(owner, "issue_refusal"),
                                     issued=_owned(owner, "_plan_issued"))
        self.opened = {}
        self.asked = set()
        self.waiting = set()
        self._planned = deque()
        self._reserved = 0
        self._plan_lock = Lock()
        # Asked by the session right before every send (erp.HostedSession._before_send).
        self.session.ended = self.ended
        self.session.grant_id = self.grant_id

    def ended(self) -> bool:
        """Idle for an hour or older than twelve: the same rule as BooksSessions.get."""
        return BooksSessions._expired(self, monotonic())

    def may_plan(self) -> Optional[dict]:
        """None when this connection may prepare one more plan now, else the refusal. Only
        ISSUED plans count towards PLANS_PER_HOUR, so busy answers and refusals never lock a
        person out; a call in flight holds a place until `plan_finished`, so the limit stays
        real (Sol review of 9c12e6c). After a None the caller gives the place back through one
        `PlanTurn` (server._plan)."""
        if not self.writes:
            return {"error": "writing_off", "why": WRITING_OFF}
        with self._plan_lock:
            now = monotonic()
            while self._planned and self._planned[0] <= now - 3600:
                self._planned.popleft()
            if len(self._planned) + self._reserved >= PLANS_PER_HOUR:
                return {"error": "slow_down", "why": SLOW_DOWN}
            self._reserved += 1
        return None

    def plan_finished(self) -> None:
        """The place `may_plan` held is given back; an issued plan is already counted."""
        with self._plan_lock:
            self._reserved = max(0, self._reserved - 1)

    def admit(self, plan_id: str, pending: bool) -> str:
        """apply_approved's admission to wait for this plan (design section 7), on the event loop
        before any worker hop (Sol review of 38865f6, MUST-FIX). In-memory only, no I/O.

        "duplicate": another call of this connection already waits for the plan; this one
        answers the plan's status at once. "too_many": a pending plan would be the fourth to
        hold a place. "wait": admitted; the caller calls `leave` when it stops waiting. A place
        is held while the plan is pending or approved, by a call waiting for it or once a call
        answered it as awaiting approval (`asked`); a plan already holding one keeps it. So at
        most MAX_WAITING calls of one connection wait for pending plans, one per plan."""
        with self._plan_lock:
            if plan_id in self.waiting:
                if pending:
                    # This duplicate answers awaiting approval with the link: the plan keeps its
                    # place after the primary call ends, cancelled or not (Sol re-check of
                    # 186d2fc).
                    self.asked.add(plan_id)
                return "duplicate"
            held = ("pending", "approved", "executing")
            self.asked = {pid for pid in self.asked if self.plans.count((pid,), held)}
            if pending and plan_id not in self.asked and self.plans.count(
                    self.asked | self.waiting, ("pending", "approved")) >= MAX_WAITING:
                return "too_many"
            self.waiting.add(plan_id)
            return "wait"

    def leave(self, plan_id: str, announced: bool) -> None:
        """The admitted call stopped waiting. `announced`: it answered awaiting approval, so the
        plan keeps its place; a cancelled or refused call gives the place back (Sol review of
        38865f6, SHOULD-FIX)."""
        with self._plan_lock:
            self.waiting.discard(plan_id)
            if announced:
                self.asked.add(plan_id)

    def _plan_issued(self) -> None:
        with self._plan_lock:
            self._planned.append(monotonic())

    def issue_refusal(self, fetch: bool = True) -> Optional[dict]:
        """Asked inside the Books turn before the preview reads anything, and twice as the plan
        is issued (ConnectionPlans; Sol review of 9c12e6c, MUST-FIX 2): the connection still
        live, its writing tick, then the control file's write stops, `stop.hosted_writes`
        included, and the version. `fetch=False` (under the store's lock): the held policy only.

        The lease is read first: its catch-up fetch may install a policy with a higher minimum,
        which the version read after it then sees (re-check of c9f0fc0), and the connection's
        liveness is read after the fetch, so a revoke during it counts (re-check of a90dac7)."""
        from . import __version__, control
        lease = control.may_write(hosted=True, fetch=fetch)
        if self.plans.closed or self.session.cookie is None or self.ended():
            return _signed_out()
        if not self.writes:
            return {"error": "writing_off", "why": WRITING_OFF}
        return control.version_refusal(__version__) or lease


class Full(Exception):
    """Every Books connection slot is occupied or reserved."""


class Busy(Exception):
    """The Books server's queue is full or the caller's wait has expired."""


@dataclass
class _OriginTurns:
    running: int = 0
    waiting: int = 0
    grants: OrderedDict[str, deque[asyncio.Future]] = field(default_factory=OrderedDict)
    last_grant: str | None = None

    def next_grant(self) -> str:
        first = next(iter(self.grants))
        if first == self.last_grant and len(self.grants) > 1:
            self.grants.move_to_end(first)
        return next(iter(self.grants))

    def remove(self, grant_id: str, ticket: asyncio.Future) -> None:
        queue = self.grants[grant_id]
        queue.remove(ticket)
        self.waiting -= 1
        if not queue:
            del self.grants[grant_id]


class ServerGate:
    """Bound Books work per HTTPS origin and alternate among queued grants on the event loop."""

    def __init__(self, max_running=1, max_waiting=8, max_waiting_per_grant=2):
        if max_running < 1 or min(max_waiting, max_waiting_per_grant) < 0:
            raise ValueError("The gate needs a running slot and non-negative queue limits.")
        self.max_running = max_running
        self.max_waiting = max_waiting
        self.max_waiting_per_grant = max_waiting_per_grant
        self._origins: dict[str, _OriginTurns] = {}

    async def run(self, origin: str, grant_id: str, work, *args, on_finished=lambda: None):
        """Run admitted work and settle the caller's reservation on the event loop."""
        try:
            await self._admit(origin, grant_id)
        except BaseException:
            on_finished()
            raise
        cancelled = Event()

        def run_if_needed():
            # An admitted call can still be waiting for an executor thread when it is cancelled.
            if not cancelled.is_set():
                return work(*args)

        def finished(task):
            self._release(origin)
            if not task.cancelled():
                task.exception()  # Retrieve errors even if the caller has gone away.
            on_finished()

        worker = asyncio.create_task(asyncio.to_thread(run_if_needed))
        worker.add_done_callback(finished)
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async def _admit(self, origin: str, grant_id: str) -> None:
        turns = self._origins.get(origin)
        if turns is None:
            turns = self._origins[origin] = _OriginTurns()
        if turns.running < self.max_running and not turns.waiting:
            turns.running += 1
            turns.last_grant = grant_id
            return
        queue = turns.grants.get(grant_id)
        if (turns.waiting >= self.max_waiting
                or len(queue or ()) >= self.max_waiting_per_grant):
            raise Busy("The Books server is busy. Try again later.")
        ticket = asyncio.get_running_loop().create_future()
        turns.grants.setdefault(grant_id, deque()).append(ticket)
        turns.waiting += 1
        try:
            async with asyncio.timeout(WAIT_TIMEOUT):
                await asyncio.shield(ticket)
        except (TimeoutError, asyncio.CancelledError) as exc:
            if ticket.done():
                self._release(origin)  # Admission raced with the timeout or cancellation.
            else:
                turns.remove(grant_id, ticket)
            if isinstance(exc, TimeoutError):
                raise Busy("The Books server is busy. Try again later.") from None
            raise

    def _release(self, origin: str) -> None:
        turns = self._origins[origin]
        turns.running -= 1
        if turns.waiting:
            grant_id = turns.next_grant()
            ticket = turns.grants[grant_id][0]
            turns.remove(grant_id, ticket)
            if grant_id in turns.grants:
                turns.grants.move_to_end(grant_id)
            turns.running += 1
            turns.last_grant = grant_id
            ticket.set_result(None)
        elif not turns.running:
            del self._origins[origin]


SERVER_GATE = ServerGate()


class Slot:
    """A single-use reservation belonging to one BooksSessions instance."""

    __slots__ = ("_grant_id",)

    def __init__(self) -> None:
        self._grant_id: str | None = None


class BooksSessions:
    """Thread-safe in-memory store for hosted Books grants and pending admissions."""

    def __init__(self) -> None:
        self._write_drain = _WriteDrain()
        self._connections: dict[str, BooksConnection] = {}
        self._slots: set[Slot] = set()
        self._lock = Lock()
        self._drop_listeners: list[Callable[[str], None]] = []

    def add_drop_listener(self, listener: Callable[[str], None]) -> None:
        """Register an in-memory listener that must not call back into this store."""
        with self._lock:
            self._drop_listeners.append(listener)

    @staticmethod
    def _expired(conn: BooksConnection, now: float) -> bool:
        return now - conn.last_used >= IDLE_SECONDS or now - conn.created >= MAX_SECONDS

    def _drop_locked(self, grant_id: str) -> None:
        conn = self._connections.pop(grant_id, None)
        if conn is not None:
            conn.session.cookie = None
            conn.plans.close()      # a call still holding the store issues nothing into it
            for listener in self._drop_listeners:
                listener(grant_id)

    def _expire_locked(self) -> None:
        now = monotonic()
        expired = [key for key, conn in self._connections.items() if self._expired(conn, now)]
        for key in expired:
            self._drop_locked(key)

    def reserve(self) -> Slot:
        with self._lock:
            self._expire_locked()
            for grant_id in [g for g, c in self._connections.items() if c.session.cookie is None]:
                self._drop_locked(grant_id)  # its Books session ended: it holds no slot (re-check)
            if len(self._connections) + len(self._slots) >= MAX_CONNECTIONS:
                raise Full("The hosted connector is busy. Try again later.")
            slot = Slot()
            self._slots.add(slot)
            return slot

    def release(self, slot: Slot) -> None:
        with self._lock:
            self._slots.discard(slot)

    @contextmanager
    def sign_in(self, cfg: config.Config, timeout: float = 20.0
                ) -> Iterator[tuple[erp.HostedSession, Slot]]:
        """Reserve before login. The caller publishes the connection by putting it in the slot."""
        try:
            slot = self.reserve()
        except BaseException:
            cfg = None                      # Full: this frame stays in the traceback (re-check)
            raise
        session = None
        published = False
        try:
            try:
                session = erp.HostedSession.sign_in(cfg, timeout)
            except BaseException as exc:
                cfg = None                  # this frame stays in the traceback (Task 39 review)
                erp.scrub_traceback(exc)
                raise
            cfg = None
            yield session, slot
            published = slot._grant_id is not None
        finally:
            try:
                if session is not None and not published:
                    try:
                        session.logout()
                    finally:
                        with self._lock:
                            conn = self._connections.get(slot._grant_id)
                            if conn is not None and conn.session is session:
                                self._drop_locked(conn.grant_id)
                            session.cookie = None
            finally:
                self.release(slot)

    def put(self, conn: BooksConnection, slot: Slot) -> None:
        with self._lock:
            if slot not in self._slots:
                raise ValueError("The Books connection slot is no longer reserved.")
            old = self._connections.get(conn.grant_id)
            if old is not None and old.session.cookie is not None:
                raise ValueError("A Books connection already holds this grant.")
            if old is not None:                 # its Books session ended (SignInAgain): replace it
                self._drop_locked(conn.grant_id)
            conn.plans._write_drain = self._write_drain
            self._connections[conn.grant_id] = conn
            slot._grant_id = conn.grant_id
            self._slots.remove(slot)

    def get(self, grant_id: str) -> BooksConnection | None:
        return self._live(grant_id, touch=True)

    def peek(self, grant_id: str) -> BooksConnection | None:
        """The live connection, without counting as a use: an open approval page must not keep
        a Books session (and one of the slots) alive when the AI client no longer uses it
        (opus review of 45b, NIT 3)."""
        return self._live(grant_id, touch=False)

    def matching(self, label: str) -> list[BooksConnection]:
        """Return live connections for a proved Books identity without extending their lifetime."""
        with self._lock:
            grants = [conn.grant_id for conn in self._connections.values() if conn.label == label]
            return [conn for grant in grants if (conn := self._live_locked(grant, touch=False))
                    is not None]

    def _live(self, grant_id: str, touch: bool) -> BooksConnection | None:
        with self._lock:
            return self._live_locked(grant_id, touch)

    def _live_locked(self, grant_id: str, touch: bool) -> BooksConnection | None:
        conn = self._connections.get(grant_id)
        if conn is None:
            return None
        now = monotonic()
        if self._expired(conn, now) or conn.session.cookie is None:
            self._drop_locked(grant_id)  # expired, or its Books session ended (re-check)
            return None
        if touch:
            conn.last_used = now
        return conn

    @contextmanager
    def hold_connection(self, conn: BooksConnection) -> Iterator[bool]:
        """Keep a revoke from racing a plan decision. Only in-memory work belongs here."""
        with self._lock:
            yield self._live_locked(conn.grant_id, touch=False) is conn

    def drop(self, grant_id: str) -> None:
        with self._lock:
            self._drop_locked(grant_id)

    def drop_all_grants(self) -> None:
        with self._lock:
            for grant_id in list(self._connections):
                self._drop_locked(grant_id)

    def holds(self, grant_id: str) -> bool:
        """Whether a live connection holds this grant, without counting as a use."""
        with self._lock:
            conn = self._connections.get(grant_id)
            return (conn is not None and conn.session.cookie is not None
                    and not self._expired(conn, monotonic()))

    def __len__(self) -> int:
        with self._lock:
            self._expire_locked()
            return len(self._connections)


SIGN_IN_AGAIN = "Sign in to Excellent Books again."


def caller_token():
    """The access token of the HTTP request that carried THIS tool call, or None.

    Only the MCP request context's own Starlette request counts: in a stateful MCP session every
    message is handled in the session's task, whose copy of the SDK's auth context variable was
    taken when the session started, so `get_access_token()` can answer with the token of the
    request that opened the session (mcp 1.26; Task 42). Without a request there is no caller:
    nothing falls back to that variable (Sol review of 59de990, SHOULD).
    """
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.lowlevel.server import request_ctx

    try:
        request = request_ctx.get().request
    except LookupError:
        return None
    user = getattr(request, "scope", {}).get("user") if request is not None else None
    return user.access_token if isinstance(user, AuthenticatedUser) else None


def caller_token_expired() -> bool:
    """Whether the access token this call came with has expired since it was admitted (the SDK's
    own rule: past `expires_at`). False without a hosted caller (a sign-in, a local session)."""
    expires_at = getattr(caller_token(), "expires_at", None)
    return isinstance(expires_at, (int, float)) and expires_at < time()


def caller_grant_id() -> str | None:
    grant_id = getattr(caller_token(), "grant_id", None)
    return grant_id if isinstance(grant_id, str) and grant_id else None


def current(sessions: BooksSessions | None) -> BooksConnection:
    """This request's own Books connection, from its access token's grant.

    Raises erp.SignInAgain when the call carries no hosted token, or its grant has no live
    connection (never made, expired, revoked, or its Books session ended: `get` has dropped it).
    The caller ends the grant in the OAuth database (server._sign_in_again); the next token load
    would also delete it (auth.HostedProvider._valid_session)."""
    grant_id = caller_grant_id()
    if sessions is None or grant_id is None:
        raise erp.SignInAgain(SIGN_IN_AGAIN)
    conn = sessions.get(grant_id)
    if conn is None:
        raise erp.SignInAgain(SIGN_IN_AGAIN)
    return conn


class McpSessionOwners:
    """Around the MCP endpoint: an MCP session id belongs to the grant whose request opened it.

    mcp 1.26 picks the transport by session id alone and sends a reply to the latest stream
    registered for its JSON-RPC id, so two grants on one session id could read each other's
    results (Sol review of 59de990, MUST 1). Another grant's request, or a session id this
    process never bound, is answered 404 "Session not found" before the transport sees it; the
    client then opens a session of its own. A request without a token passes to the SDK's own
    401. Bindings of grants that ended are pruned whenever a new session is bound."""

    HEADER = b"mcp-session-id"
    NOT_FOUND = {"jsonrpc": "2.0", "id": "server-error",
                 "error": {"code": -32600, "message": "Session not found"}}

    def __init__(self, app, sessions: BooksSessions):
        self.app, self.sessions = app, sessions
        self._owners: dict[str, str] = {}
        self._lock = Lock()

    @staticmethod
    def _grant(scope) -> str | None:
        from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
        user = scope.get("user")
        if not isinstance(user, AuthenticatedUser):
            return None
        grant_id = getattr(user.access_token, "grant_id", None)
        return grant_id if isinstance(grant_id, str) and grant_id else None

    def _bind(self, session_id: str, grant_id: str) -> None:
        with self._lock:
            for sid, owner in list(self._owners.items()):
                if not self.sessions.holds(owner):
                    del self._owners[sid]
            self._owners[session_id] = grant_id

    async def __call__(self, scope, receive, send):
        grant_id = self._grant(scope) if scope.get("type") == "http" else None
        if grant_id is None:
            return await self.app(scope, receive, send)
        session_ids = [value for name, value in scope.get("headers", [])
                       if name.lower() == self.HEADER]
        if session_ids:
            session_id = session_ids[0].decode("latin-1")
            with self._lock:
                owner = self._owners.get(session_id)
            if len(session_ids) != 1 or owner != grant_id:
                return await JSONResponse(self.NOT_FOUND, status_code=404)(scope, receive, send)
            if scope.get("method") != "DELETE":
                return await self.app(scope, receive, send)
            status = []

            async def answered(message):
                if message.get("type") == "http.response.start":
                    status.append(message.get("status"))
                await send(message)

            try:
                await self.app(scope, receive, answered)
            finally:
                # Unbound only once the SDK ended the session: a refused DELETE (400) leaves it
                # alive and still its owner's (Sol re-check of 6ff701b, SHOULD); a 2xx whose
                # sending failed still ended it (Sol re-check of b6967c4).
                if status and 200 <= status[0] < 300:
                    with self._lock:
                        self._owners.pop(session_id, None)
            return None

        async def bind(message):
            if message.get("type") == "http.response.start":
                for name, value in message.get("headers", []):
                    if name.lower() == self.HEADER:
                        self._bind(value.decode("latin-1"), grant_id)
            await send(message)

        return await self.app(scope, receive, bind)


def own_mcp_sessions(app, path: str, sessions: BooksSessions) -> None:
    """Wrap the built app's MCP route in McpSessionOwners. Exactly one route, or no start."""
    routes = [route for route in app.routes if isinstance(route, Route) and route.path == path]
    if len(routes) != 1:
        raise SystemExit("ERROR: the hosted MCP route %s was not found exactly once." % path)
    routes[0].app = McpSessionOwners(routes[0].app, sessions)


def _dev(env) -> bool:
    return (env.get("EBMCP_HOSTED_DEV") or "").strip().lower() == "yes"


def _http_url(uri: str) -> AnyHttpUrl | None:
    if "\\" in uri or any(ord(char) < 33 or ord(char) == 127 for char in uri):
        return None
    try:
        if not urlsplit(uri).netloc:
            return None
        url = AnyHttpUrl(uri)
    except ValueError:
        return None
    if url.username is not None or url.password is not None or url.fragment is not None:
        return None
    return url


def _is_loopback(host: str) -> bool:
    host = host.rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ip_address(host.strip("[]"))
    except ValueError:
        return False
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def _issuer(env) -> str:
    return (env.get("EBMCP_ISSUER_URL") or "").strip() or auth.DEFAULT_ISSUER


def check_start(env) -> None:
    if config._said_yes(env.get(config.WRITES_KEY)):
        sys.stderr.write("ERROR: Hosted mode is read-only. Disable EBMCP_WRITES.\n")
        raise SystemExit(2)
    # Hosted's OWN OAuth database, named explicitly: a default under the project root is not
    # writable in the container (uid 10001), and sharing the O365 door's file would let every
    # hosted start wipe colleagues' sign-ins (Sol re-check of 42c9120).
    hosted_db = (env.get("EBMCP_HOSTED_OAUTH_DB") or "").strip()
    if not hosted_db:
        sys.stderr.write("ERROR: Hosted mode needs EBMCP_HOSTED_OAUTH_DB, a writable file of its own "
                         "(e.g. /data/hosted-oauth.db).\n")
        raise SystemExit(2)
    o365_db = (env.get("OAUTH_DB_PATH") or "/data/oauth.db").strip()
    if Path(hosted_db).resolve() == Path(o365_db).resolve():
        sys.stderr.write("ERROR: EBMCP_HOSTED_OAUTH_DB must not be the O365 door's OAuth database.\n")
        raise SystemExit(2)
    # The catalogue and the control file come from https only: a file: source could point at a
    # checkout's .env (Sol re-check of 42c9120).
    if (env.get("EBMCP_CATALOG_LOCAL") or "").strip().lower() in ("1", "true", "yes"):
        sys.stderr.write("ERROR: Hosted mode cannot use a local catalogue (EBMCP_CATALOG_LOCAL).\n")
        raise SystemExit(2)
    for key in ("EBMCP_CONTROL_URL", "EBMCP_CATALOG_URL"):
        value = (env.get(key) or "").strip()
        if value and not value.lower().startswith("https://"):
            sys.stderr.write(f"ERROR: Hosted mode needs an https {key}.\n")
            raise SystemExit(2)
    if not allowed_hosts(env):
        # Empty or malformed: never start, released or not (Task 37 review N4).
        sys.stderr.write("ERROR: EBMCP_HOSTED_ALLOWED_HOSTS must list exact host:port entries.\n")
        raise SystemExit(2)
    if not RELEASED and allowed_hosts(env) != {PKOREA}:
        sys.stderr.write(f"ERROR: Unreleased hosted mode requires only {PKOREA} in "
                         "EBMCP_HOSTED_ALLOWED_HOSTS.\n")
        raise SystemExit(2)
    if RELEASED and not privacy.HOSTED_TEXT_SIGNED_OFF:
        sys.stderr.write("ERROR: Hosted privacy text requires sign-off before release.\n")
        raise SystemExit(2)
    try:
        waits(env)
    except ValueError as exc:
        sys.stderr.write("ERROR: %s\n" % exc)
        raise SystemExit(2)
    url = _http_url(_issuer(env))
    if url is None or url.query is not None or (
        url.scheme != "https" and not (_dev(env) and _is_loopback(url.host))
    ):
        sys.stderr.write("ERROR: EBMCP_ISSUER_URL must be a valid HTTPS issuer. "
                         "Loopback HTTP requires EBMCP_HOSTED_DEV=yes.\n")
        raise SystemExit(2)


def _redirect_entries(env) -> frozenset[str]:
    override = env.get("EBMCP_HOSTED_REDIRECTS")
    return _DEFAULT_REDIRECTS if override is None else _entries(override)


def _redirect_url(uri: str, env) -> AnyHttpUrl | None:
    url = _http_url(uri)
    # A callback host must be a literal CSP host source, with no wildcard or policy delimiter.
    if url is None or any(char in url.host for char in ";*"):
        return None
    if _is_loopback(url.host):
        return url if _dev(env) else None
    return url if url.scheme == "https" else None


def allowed_redirect(uri: str, env) -> bool:
    return uri in _redirect_entries(env) and _redirect_url(uri, env) is not None


def redirect_origins(env) -> frozenset[str]:
    """Return normalized origins for the same callback URLs accepted at registration."""
    origins = set()
    for uri in _redirect_entries(env):
        url = _redirect_url(uri, env)
        if url is not None:
            parts = urlsplit(str(url))
            origins.add(f"{parts.scheme}://{parts.netloc}")
    return frozenset(origins)


def validate_redirects(redirects, env) -> None:
    if not isinstance(redirects, list) or not redirects or any(
        not isinstance(uri, str) or not allowed_redirect(uri, env) for uri in redirects
    ):
        raise RegistrationError("invalid_redirect_uri", "Every redirect URI must be allowed.")


_MAX_TRACKED = 10_000


def _rate_key(address: str) -> str:
    try:
        parsed = ip_address(address)
    except ValueError:
        return address
    if isinstance(parsed, IPv6Address):
        if parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        return str(ip_address(int(parsed) >> 64 << 64)) + "/64"
    return str(parsed)


class _RegistrationLimit:
    def __init__(self):
        self._lock = Lock()
        self._by_address: dict[str, deque[float]] = {}
        self._requests: deque[tuple[float, str]] = deque()

    def retry_after(self, address: str) -> int:
        """Reserve a request slot, or return seconds until the next slot opens.

        An IPv6 client is counted by its /64 (one household or server can rotate inside it), and
        at most _MAX_TRACKED addresses are tracked: past that every new address waits, so the
        table cannot grow without bound (Task 37 review S2)."""
        address = _rate_key(address)
        with self._lock:
            now = monotonic()
            cutoff = now - 3600
            while self._requests and self._requests[0][0] <= cutoff:
                _, expired = self._requests.popleft()
                times = self._by_address[expired]
                times.popleft()
                if not times:
                    del self._by_address[expired]
            if address not in self._by_address and len(self._by_address) >= _MAX_TRACKED:
                return ceil(self._requests[0][0] - cutoff) if self._requests else 60
            times = self._by_address.setdefault(address, deque())
            if len(times) >= REGISTRATIONS_PER_HOUR:
                return ceil(times[0] - cutoff)
            times.append(now)
            self._requests.append((now, address))
            return 0


_LOWLEVEL_LOG = "mcp.server.lowlevel.server"
_PROTOCOL_LOGS = (_LOWLEVEL_LOG, "mcp.server.streamable_http", "mcp.server.streamable_http_manager",
                  "mcp.server.sse", "mcp.server.fastmcp.resources.resource_manager", "sse_starlette.sse",
                  mcp_session.__name__)
_stream_error_type = ContextVar("stream_error_type", default=None)


def _keep_protocol_log(record: logging.LogRecord) -> bool:
    # Desktop and the plugin too: their stderr lands in the AI client's log files (Astra review
    # of slice 2, MUST 5).
    if os.environ.get("EBMCP_MODE") not in ("hosted", "desktop", "plugin"):
        return True
    # mcp.shared.session calls the root logger directly in mcp 1.26.
    if record.name == "root" and record.pathname != mcp_session.__file__:
        return True
    if record.levelno <= logging.DEBUG:
        return False  # SDK debug traces can contain entire messages and change between versions.
    if record.name in ("root", mcp_session.__name__):
        msg = record.msg if isinstance(record.msg, str) else ""
        for kind in ("request", "notification"):
            if msg.startswith(f"Failed to validate {kind}:"):
                record.msg = f"Failed to validate MCP {kind}"
                break
        else:
            record.msg = "MCP session diagnostic"
    elif record.name != _LOWLEVEL_LOG or not isinstance(record.msg, str):
        return True
    elif record.msg.startswith("Warning:"):
        return False  # The SDK records Python warnings and logs their text at INFO.
    elif record.msg.startswith("Received exception from stream:"):
        error_type = _stream_error_type.get()
        if error_type is None and record.exc_info and record.exc_info[0] is not None:
            error_type = record.exc_info[0].__name__
        if error_type is None and isinstance(record.args, tuple) and record.args:
            if isinstance(record.args[0], BaseException):
                error_type = type(record.args[0]).__name__
        record.msg = "Received exception from stream: " + (error_type or "Exception")
    elif record.msg == "Tool '%s' not listed, no validation will be performed":
        record.msg = "Tool not listed, no validation will be performed"
    else:
        return True
    record.args = ()
    record.exc_info = record.exc_text = record.stack_info = None
    return True


def _protect_protocol_logs(server) -> None:
    logging.getLogger().addFilter(_keep_protocol_log)
    for name in _PROTOCOL_LOGS:
        logging.getLogger(name).addFilter(_keep_protocol_log)
    # mcp 1.26 logs a preformatted string. Keep the type while the SDK still has the exception,
    # so the filter can report it without parsing the error text.
    handle_message = server._handle_message

    async def handle(message, *args, **kwargs):
        if not isinstance(message, Exception):
            return await handle_message(message, *args, **kwargs)
        token = _stream_error_type.set(type(message).__name__)
        try:
            return await handle_message(message, *args, **kwargs)
        finally:
            _stream_error_type.reset(token)

    server._handle_message = handle


def configure_http(mcp_server, env) -> auth.HostedProvider:
    """Set up the hosted OAuth endpoints and protect the MCP resource."""
    _protect_protocol_logs(mcp_server._mcp_server)
    # Hosted has its OWN database: OAUTH_DB_PATH belongs to the live O365 door, and the
    # drop_all_grants() below would wipe every colleague's sign-in there (Task 41 review S2).
    db_path = (env.get("EBMCP_HOSTED_OAUTH_DB") or "").strip()   # check_start made it required
    store = auth.OAuthStore(db_path)
    store.drop_all_grants()  # The store's write transaction also prunes stale pending logins.
    issuer = AnyHttpUrl(_issuer(env))
    issuer_base = str(issuer).rstrip("/")
    resource = AnyHttpUrl(issuer_base + mcp_server.settings.streamable_http_path)
    redirects = frozenset(str(url) for uri in _redirect_entries(env)
                          if (url := _redirect_url(uri, env)) is not None)
    cfg = auth.HostedAuthConfig.from_env(env, issuer_base, str(resource), redirects)
    provider = auth.HostedProvider(cfg, store, BooksSessions())

    registration = ClientRegistrationOptions(enabled=False, valid_scopes=auth.DEFAULT_SCOPES,
                                              default_scopes=auth.DEFAULT_SCOPES)
    revocation = RevocationOptions(enabled=True)
    mcp_server.settings.auth = AuthSettings(
        issuer_url=issuer, resource_server_url=resource,
        client_registration_options=registration, revocation_options=revocation,
        required_scopes=auth.DEFAULT_SCOPES,
    )
    mcp_server._token_verifier = ProviderTokenVerifier(provider)

    # Add the SDK handlers explicitly so /token can validate the resource before the SDK
    # drops that field. Advertise our guarded /register without installing the SDK route.
    mcp_server._auth_server_provider = None
    metadata = build_metadata(issuer, None, registration, revocation)
    metadata.registration_endpoint = AnyHttpUrl(issuer_base + "/register")
    client_auth = ClientAuthenticator(provider)
    token_handler = TokenHandler(provider, client_auth)

    async def exchange(request: Request) -> Response:
        resources = (await request.form()).getlist("resource")
        if resources and resources != [cfg.resource_url]:
            return JSONResponse({"error": "invalid_target"}, status_code=400,
                                headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        return await token_handler.handle(request)

    mcp_server._custom_starlette_routes.extend([
        Route("/.well-known/oauth-authorization-server",
              cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"]),
              methods=["GET", "OPTIONS"]),
        Route("/authorize", AuthorizationHandler(provider).handle, methods=["GET", "POST"]),
        Route("/token", cors_middleware(exchange, ["POST", "OPTIONS"]),
              methods=["POST", "OPTIONS"]),
        Route("/revoke", cors_middleware(RevocationHandler(provider, client_auth).handle,
                                        ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"]),
    ])
    handler = RegistrationHandler(provider, registration)
    limit = _RegistrationLimit()

    @mcp_server.custom_route("/register", methods=["POST"])
    async def register(request: Request) -> Response:
        # Uvicorn supplies the client address, including forwarded data from trusted proxies.
        address = request.client.host if request.client else ""
        retry_after = limit.retry_after(address)
        if retry_after:
            return JSONResponse({"error": "too_many_requests"}, status_code=429,
                                headers={"Retry-After": str(retry_after)})
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
        try:
            # Compare the original strings before the SDK normalizes their URLs.
            validate_redirects(body.get("redirect_uris"), env)
        except RegistrationError as exc:
            return JSONResponse({"error": exc.error, "error_description": exc.error_description},
                                status_code=400)
        return await handler.handle(request)

    return provider
