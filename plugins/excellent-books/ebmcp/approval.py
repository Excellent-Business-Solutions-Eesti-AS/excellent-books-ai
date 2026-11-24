"""In-memory approval envelopes and their atomic, single-execution lifecycle.

Approval page handlers and the opt-in local chat branch in server.py call
``approve``. A restart forgets all plans.
"""
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from typing import Optional

from . import unfinished_write


MAX_WRITES = 50
# Measured on pkorea 2026-11-22: 50 items 9.0 s, 50 contacts 17.6 s (docs/reviews/2026-11-21-task30-opus.md).
DESKTOP_MAX_WRITES = MAX_WRITES
PLAN_SECONDS = 900
APPROVAL_SECONDS = 300
MAX_PLANS = 100
MAX_OPEN_WINDOWS = 3
LAUNCH_GAP_SECONDS = 10
CONSENT_GAP_SECONDS = 600
WAIT_SECONDS = 110
# Placeholder until Kaupo narrows the Desktop timeout (docs/probes/2026-11-P5-bundle.md, row 10).
DESKTOP_WAIT_SECONDS = 45
# Desktop kills a call before ~60 s, so a write must not start late in the call.
DESKTOP_WRITE_START_BUDGET_SECONDS = 10
DESKTOP_LOCK_WAIT_SECONDS = 10
# Desktop ends the call and restarts the extension before ~60 s (P5 bundle probe, row 10).
# Measured full batches took 9.0 s for items and 17.6 s for contacts on a near, idle server
# (docs/reviews/2026-11-21-task30-opus.md). Stop new writes at 45 s even on slower servers.
DESKTOP_CALL_BUDGET_SECONDS = 45
_WAIT_SLICE_SECONDS = 0.05
KINDS = frozenset({"record_change", "goods_receipt", "items", "contacts"})
OPERATIONS = frozenset({"create", "update", "approve", "batch"})

# A preview's note on how it is approved. Local and Desktop: apply_approved opens the window on
# the person's computer. Hosted (server._plan swaps them by HOSTED_NOTES): the person opens the
# preview's approve_url and presses Approve there (Task 51 review MUST 1).
APPLY_NOTE = ("Nothing is written yet. Show this preview to the person and call apply_approved "
              "with the plan_id to open the approval page.")
ITEMS_NOTE = ("Nothing has been written. The person approves these item cards in the approval "
              "window; only then are they created. The group decides the cost account.")
HOSTED_NOTES = {
    APPLY_NOTE: ("Nothing is written yet. Show this preview to the person and give them its "
                 "approve_url: they sign in if asked and press Approve on that page. Then call "
                 "apply_approved with the plan_id."),
    ITEMS_NOTE: ("Nothing has been written. The person approves these item cards on the page at "
                 "approve_url; only then are they created. The group decides the cost account."),
}


@dataclass(frozen=True)
class Envelope:
    kind: str
    server: str
    company: int
    books_user: str
    operation: str
    target: str
    writes: tuple
    before: str
    preview: str
    needs_ack: bool

    def __post_init__(self):
        if not self.writes:
            raise ValueError("An approval envelope must contain at least one write.")
        if len(self.writes) > MAX_WRITES:
            raise ValueError("An approval envelope may contain at most 50 writes.")
        if self.kind not in KINDS:
            raise ValueError(f"Unknown envelope kind {self.kind!r}.")
        if self.operation not in OPERATIONS:
            raise ValueError(f"Unknown envelope operation {self.operation!r}.")

    def digest(self) -> str:
        canonical = json.dumps(asdict(self), sort_keys=True, ensure_ascii=False,
                               separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalError(Exception):
    code = "refused"


class NotApproved(ApprovalError):
    code = "not_approved"


class ConnectionChanged(ApprovalError):
    """The plan belongs to another Books connection than the one saved now (Astra recheck of the
    slice 2 fix, MUST 3): neither shown nor approved until the settings name its connection."""
    code = "connection_changed"


class OwnerUnknown(ApprovalError):
    """The settings could not be read just now, so whose plan this is cannot be told: nothing new
    starts, and the plan stays as it was (Astra recheck of ddce18b, regression)."""
    code = "settings_unreadable"


class UnfinishedWriteCheckRequired(ApprovalError):
    pass


class UnfinishedWriteUnavailable(ApprovalError):
    pass


class Expired(ApprovalError):
    code = "expired"


class Declined(ApprovalError):
    code = "declined"


class InProgress(ApprovalError):
    code = "in_progress"


class Finished(ApprovalError):
    code = "finished"

    def __init__(self, outcome: dict):
        super().__init__("This plan has already finished.")
        self.outcome = deepcopy(outcome)


@dataclass(frozen=True)
class Plan:
    """A snapshot: changing a returned payload or outcome cannot change the store."""
    plan_id: str
    envelope: Envelope
    payload: dict
    state: str = "pending"
    outcome: Optional[dict] = None
    # Monotonic AND wall-clock times: either one passing a limit expires the plan.
    _created_at: float = field(default=0.0, repr=False)
    _created_wall: float = field(default=0.0, repr=False)
    _approved_at: Optional[float] = field(default=None, repr=False)
    _approved_wall: Optional[float] = field(default=None, repr=False)
    _approval_id: Optional[str] = field(default=None, repr=False)
    _via: Optional[str] = field(default=None, repr=False)
    _next_write: int = field(default=0, repr=False)


_APPROVED_KEY = object()


@dataclass(frozen=True, init=False)
class Approved:
    envelope: Envelope
    plan_id: str
    approval_id: str
    waited_s: float
    _store: "PlanStore" = field(repr=False, compare=False)

    def __init__(self, envelope, plan_id, approval_id, waited_s, *, _key=None, _store=None):
        if _key is not _APPROVED_KEY:
            raise TypeError("Only PlanStore.begin can create an Approved object.")
        object.__setattr__(self, "envelope", envelope)
        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "approval_id", approval_id)
        object.__setattr__(self, "waited_s", waited_s)
        object.__setattr__(self, "_store", _store)

    def live(self) -> bool:
        return self._store._live(self)

    def matches(self, origin: str, company: int, books_user: str) -> bool:
        # The store's own envelope too: this instance's can be changed with object.__setattr__
        # (Task 11 review NIT), the store's cannot.
        identity = (origin, company, books_user)
        return (identity == (self.envelope.server, self.envelope.company,
                             self.envelope.books_user)
                and self._store._identity_matches(self, identity))

    def peek_next(self, method: str, path: str, body: str) -> bool:
        """Is this the next approved write? Consumes nothing."""
        return self._store.peek_next(self, method, path, body)

    def take_next(self, method: str, path: str, body: str, *, cfg=None) -> bool:
        return self._store.take_next(self, method, path, body, cfg=cfg)

    def skip_next(self, method: str, path: str, body: str) -> bool:
        return self._store.skip_next(self, method, path, body)


class PlanStore:
    """``clock`` is monotonic, ``wall_clock`` the wall time. On macOS and Linux the
    monotonic clock stops while the PC sleeps; the person can set the wall clock back.
    A deadline passes when EITHER elapsed time passes it, so both errors fail closed.
    ``max_plans``: how many plans it holds before evicting one (hosted: per connection).
    """

    def __init__(self, clock=time.monotonic, wall_clock=time.time, max_plans=MAX_PLANS):
        self._clock = clock
        self._wall = wall_clock
        self._max_plans = max_plans
        self._plans: dict[str, Plan] = {}
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)
        # Desktop, the plugin and local (server.py): `plan -> bool`, does the plan belong to the
        # connection saved now; None from it: the settings could not be read. None: every plan
        # does (hosted stores are per connection).
        self.owner_check = None
        # The same stores: `plan -> bool | None`, are the personal data and (for an HR register)
        # the HR consent of the plan's connection on now (Astra recheck of ddce18b, NEW MUST 1).
        self.consent_check = None

    def owner_state(self, plan: Plan) -> Optional[bool]:
        """True: `plan` belongs to the connection saved now. False: a read that succeeded names
        another one. None: it cannot be told now (an unreadable read, a check that failed), which
        stops new work but changes nothing (Astra recheck of ddce18b, regression). Never called
        with the lock held (the check reads the settings)."""
        return self._ask(self.owner_check, plan)

    def consent_state(self, plan: Plan) -> Optional[bool]:
        """True: the plan's data may be shown now; False: its consent is off; None: unknown."""
        return self._ask(self.consent_check, plan)

    @staticmethod
    def _ask(check, plan) -> Optional[bool]:
        if check is None:
            return True
        try:
            answer = check(plan)
        except Exception:
            return None
        return None if answer is None else bool(answer)

    def belongs_now(self, plan: Plan) -> bool:
        """Whether `plan` may be shown, opened or approved now; anything but a yes says no."""
        return self.owner_state(plan) is True

    def same_owner(self, plan: Plan, other: Plan) -> bool:
        """Whether two plans belong to one connection, by what each plan was issued for, not by
        the settings now (Astra recheck of ddce18b, MUST 3): a page lists and declines only its
        own plan's connection's plans."""
        if self.owner_check is None:
            return True
        return (plan.payload.get("connection") == other.payload.get("connection")
                and (plan.envelope.server, plan.envelope.company)
                == (other.envelope.server, other.envelope.company))

    def _expire(self, plan: Plan) -> Plan:
        """Called with the lock held; execution must stay finishable after expiry."""
        if plan.state in ("pending", "approved") and self._seconds_left(plan) <= 0:
            plan = replace(plan, state="expired")
            self._plans[plan.plan_id] = plan
            self._changed.notify_all()
        return plan

    def _seconds_left(self, plan: Plan) -> float:
        """The least time left on either clock, for the plan and (once approved) the approval."""
        now, wall = self._clock(), self._wall()
        left = [plan._created_at + PLAN_SECONDS - now,
                plan._created_wall + PLAN_SECONDS - wall]
        if plan._approved_at is not None:
            left += [plan._approved_at + APPROVAL_SECONDS - now,
                     plan._approved_wall + APPROVAL_SECONDS - wall]
        return min(left)

    def _require(self, plan_id) -> Plan:
        plan = self._plans.get(plan_id)
        if plan is None:
            raise NotApproved("Unknown or evicted plan; make a new preview.")
        return self._expire(plan)

    @staticmethod
    def _raise_terminal(plan: Plan) -> None:
        if plan.state == "done":
            raise Finished(plan.outcome)
        if plan.state == "declined":
            raise Declined("This plan was declined.")
        if plan.state == "expired":
            raise Expired("This preview or approval expired; make a new preview.")

    def issue(self, envelope: Envelope, payload: dict) -> str:
        # Copy before eviction so a failed copy cannot remove an existing plan.
        envelope, payload = deepcopy(envelope), deepcopy(payload)
        with self._changed:
            self._may_add()
            if len(self._plans) >= self._max_plans:
                del self._plans[self._victim()]
            plan_id = "pl_" + secrets.token_urlsafe(12)
            while plan_id in self._plans:
                plan_id = "pl_" + secrets.token_urlsafe(12)
            self._plans[plan_id] = Plan(plan_id, envelope, payload, _created_at=self._clock(),
                                        _created_wall=self._wall())
            self._changed.notify_all()
            return plan_id

    def _may_add(self) -> None:
        """Called with the lock held, before a plan is added: a subclass may refuse it."""

    def _may_begin(self) -> None:
        """Called with the lock held, in the same step as the move to `executing`: a subclass
        may refuse it (hosted: a planned stop has begun)."""

    def _victim(self) -> str:
        """Called with the lock held. Expired or declined first, then the oldest pending, then
        the oldest done; never an approved or an executing plan. Pending before done: an evicted
        done plan would answer a duplicate apply with "make a new preview" (a double-write path),
        an evicted pending plan only costs a new preview (review 2026-11-17, Task 5)."""
        plans = [self._expire(self._plans[pid]) for pid in list(self._plans)]
        for states in (("expired", "declined"), ("pending",), ("done",)):
            victim = next((p.plan_id for p in plans if p.state in states), None)
            if victim is not None:
                return victim
        raise InProgress("Too many plans are approved or executing; finish or decline "
                         "one, then make the preview again.")

    def get(self, plan_id) -> Optional[Plan]:
        with self._changed:
            plan = self._plans.get(plan_id)
            return deepcopy(self._expire(plan)) if plan is not None else None

    def approve(self, plan_id, digest: str, acknowledged: bool, *, via: Optional[str] = None,
                unfinished_marker: str | None = None) -> None:
        current = self.get(plan_id)
        if current is not None and current.state == "pending":
            owner = self.owner_state(current)
            if owner is None:
                raise OwnerUnknown("The connector settings could not be read; nothing changed.")
            if owner is False:
                raise ConnectionChanged("This preview belongs to another Books connection.")
        with self._changed:
            plan = self._require(plan_id)
            self._raise_terminal(plan)
            if plan.state == "executing":
                raise InProgress("This plan is executing.")
            if digest != plan.envelope.digest():
                raise ApprovalError("The approval does not match the preview.")
            if plan.envelope.needs_ack and acknowledged is not True:
                raise ApprovalError("Acknowledge the ledger or stock warning first.")
            if plan.state == "approved":
                return  # A repeated click must not renew an approval's lifetime.
            approved = replace(
                plan, state="approved", _approved_at=self._clock(),
                _approved_wall=self._wall(), _approval_id="ap_" + secrets.token_urlsafe(12),
                _via=via)
            self._before_approval(plan, unfinished_marker)
            self._plans[plan_id] = approved
            self._changed.notify_all()

    def _before_approval(self, plan: Plan, unfinished_marker: str | None) -> None:
        """A local store may require an additional acknowledgement before approving."""

    def unfinished_marker(self, plan: Plan) -> unfinished_write.Marker | None:
        return None

    def decline(self, plan_id) -> None:
        with self._changed:
            plan = self._require(plan_id)
            if plan.state == "declined":
                return
            self._raise_terminal(plan)
            if plan.state == "executing":
                raise InProgress("This plan is executing; it cannot be cancelled.")
            self._plans[plan_id] = replace(plan, state="declined")
            self._changed.notify_all()

    def begin(self, plan_id) -> Approved:
        with self._changed:
            plan = self._require(plan_id)
            self._raise_terminal(plan)
            if plan.state == "executing":
                raise InProgress("This plan is already executing.")
            if plan.state != "approved":
                raise NotApproved("This plan has not been approved.")
            self._may_begin()
            approved = Approved(
                envelope=deepcopy(plan.envelope), plan_id=plan_id,
                approval_id=plan._approval_id, waited_s=plan._approved_at - plan._created_at,
                _key=_APPROVED_KEY, _store=self)
            self._plans[plan_id] = replace(plan, state="executing")
            self._changed.notify_all()
            return approved

    def finish(self, approved: Approved, outcome: dict) -> None:
        """Only the holder of the Approved that ``begin`` returned can finish the plan."""
        if not isinstance(approved, Approved) or approved._store is not self:
            raise NotApproved("Only the approval returned by begin can finish a plan.")
        with self._changed:
            plan = self._require(approved.plan_id)
            self._raise_terminal(plan)
            if plan.state != "executing":
                raise NotApproved("Only an executing plan can finish.")
            if plan._approval_id != approved.approval_id:
                raise NotApproved("This approval does not belong to the executing plan.")
            self._plans[plan.plan_id] = replace(plan, state="done", outcome=deepcopy(outcome))
            self._after_finish(plan, outcome)
            self._changed.notify_all()

    def _after_finish(self, plan: Plan, outcome: dict) -> None:
        """A local store may release write evidence after saving the outcome."""

    def wait(self, plan_id, seconds: float) -> str:
        # Waiting needs a real timeout even when tests hold the injected clock still.
        until = time.monotonic() + max(0, seconds)
        with self._changed:
            while True:
                plan = self._require(plan_id)
                if plan.state != "pending":
                    return plan.state
                remaining = until - time.monotonic()
                if remaining <= 0:
                    return "pending"
                self._changed.wait(timeout=max(0, min(remaining, self._seconds_left(plan))))

    def pending(self) -> list:
        with self._changed:
            return [deepcopy(plan) for pid in list(self._plans)
                    if (plan := self._require(pid)).state == "pending"]

    def active(self) -> list:
        """Snapshots that still need the approval server, including an in-flight write."""
        with self._changed:
            return [deepcopy(plan) for pid in list(self._plans)
                    if (plan := self._require(pid)).state in ("pending", "approved", "executing")]

    def _live(self, approved: Approved) -> bool:
        # The plan and approval deadlines were enforced at ``begin``. A timer that cut a
        # running batch would leave writes 1..k sent and k+1.. refused: a half-written batch,
        # worse than finishing it. No execution budget from ``begin`` either: the plan asks
        # for none, MAX_WRITES bounds the batch, and the executors re-check connection,
        # consent and Books build before every record (``server._execution_check``, Task 14).
        with self._changed:
            plan = self._plans.get(approved.plan_id)
            return (plan is not None and plan.state == "executing"
                    and plan._approval_id == approved.approval_id)

    def _identity_matches(self, approved: Approved, identity: tuple) -> bool:
        if not isinstance(approved, Approved) or approved._store is not self:
            return False
        with self._changed:
            plan = self._plans.get(approved.plan_id)
            return (plan is not None and plan._approval_id == approved.approval_id
                    and identity == (plan.envelope.server, plan.envelope.company,
                                     plan.envelope.books_user))

    def peek_next(self, approved: Approved, method: str, path: str, body: str) -> bool:
        if not isinstance(approved, Approved) or approved._store is not self:
            return False
        with self._changed:
            return self._is_next(self._plans.get(approved.plan_id), approved,
                                 (method, path, body))

    @staticmethod
    def _is_next(plan, approved: Approved, triple: tuple) -> bool:
        """Called with the lock held."""
        return (plan is not None and plan.state == "executing"
                and plan._approval_id == approved.approval_id
                and plan._next_write < len(plan.envelope.writes)
                and triple == plan.envelope.writes[plan._next_write])

    def take_next(self, approved: Approved, method: str, path: str, body: str, *, cfg=None) -> bool:
        return self._consume_next(approved, method, path, body, sending=True, cfg=cfg)

    def skip_next(self, approved: Approved, method: str, path: str, body: str) -> bool:
        # Skipping is terminal, exactly like sending: neither entry can be replayed.
        return self._consume_next(approved, method, path, body)

    def _consume_next(self, approved: Approved, method: str, path: str, body: str,
                      *, sending=False, cfg=None) -> bool:
        if not isinstance(approved, Approved) or approved._store is not self:
            return False
        with self._changed:
            plan = self._plans.get(approved.plan_id)
            if not self._is_next(plan, approved, (method, path, body)):
                return False
            if sending:
                self._before_send(plan, cfg)
            self._plans[plan.plan_id] = replace(plan, _next_write=plan._next_write + 1)
            return True

    def _before_send(self, plan: Plan, cfg) -> None:
        """A local store may record write evidence before handing out the first send."""


class LocalPlanStore(PlanStore):
    """The Desktop and ZIP store. Hosted plans keep their own write audit."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._writing = {}

    def unfinished_marker(self, plan: Plan) -> unfinished_write.Marker | None:
        return unfinished_write.read(plan.payload["connection"])

    def _before_approval(self, plan: Plan, unfinished_marker: str | None) -> None:
        try:
            if not unfinished_write.acknowledge(plan.payload["connection"], unfinished_marker):
                raise UnfinishedWriteCheckRequired()
        except (OSError, ValueError) as exc:
            raise UnfinishedWriteUnavailable() from exc

    def _before_send(self, plan: Plan, cfg) -> None:
        from .erp import WritePolicyRefused

        if plan.plan_id in self._writing:
            return
        try:
            self._writing[plan.plan_id] = unfinished_write.begin(plan, cfg)
        except unfinished_write.WriteInProgress as exc:
            raise WritePolicyRefused("Another write is in progress for this Books connection. "
                                     "Nothing was sent.") from exc
        except (OSError, ValueError) as exc:
            raise WritePolicyRefused("The unfinished-write marker could not be saved. "
                                     "Nothing was sent.") from exc

    def finish_unverified(self, approved: Approved, note: str) -> None:
        """Retire the approval after both outcome saves fail and keep its recovery marker."""
        with self._changed:
            plan = self._plans.get(approved.plan_id)
            if (approved._store is self and plan is not None and plan.state == "executing"
                    and plan._approval_id == approved.approval_id):
                outcome = {"status": "unverified", "note": note}
                if plan._via == "chat":
                    outcome["via"] = plan._via
                self._plans[plan.plan_id] = replace(plan, state="done", outcome=outcome)
                self._after_finish(plan, outcome)
                self._changed.notify_all()

    def _after_finish(self, plan: Plan, outcome: dict) -> None:
        writing = self._writing.pop(plan.plan_id, None)
        if writing is not None:
            path, lock = writing
            try:
                try:
                    if unfinished_write.verified(plan, outcome):
                        path.unlink(missing_ok=True)
                finally:
                    unfinished_write.release_lock(lock)
            except (OSError, TypeError):
                # Keeping the marker is safe. The plan has already reached its stored outcome.
                pass


def open_in_browser(url: str) -> bool:
    """Start the platform browser. Never echo the bootstrap capability or use a shell.

    No standard stream is shared with the browser: a stdio connector speaks on stdin/stdout, and
    a console browser that inherited them (Python's webbrowser can pick lynx or w3m on a Linux
    terminal) would corrupt it while the caller holds the dispatch lock (review Task 13 NIT 7).
    Use only desktop session settings in the child environment to keep connector credentials
    out of the launcher and any browser it starts."""
    desktop_keys = (
        "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "TMP", "TEMP",
        "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR", "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "DESKTOP_SESSION",
        "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_HOME", "XDG_DATA_DIRS",
        "SYSTEMROOT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    )
    env = {name: os.environ[name] for name in desktop_keys if name in os.environ}
    quiet = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
             "stderr": subprocess.DEVNULL}
    try:
        if sys.platform == "win32":
            # ShellExecute sees the environment of this child, which contains no Books login.
            command = [sys.executable, "-IS", "-c", "import os, sys\nos.startfile(sys.argv[1])", url]
            quiet["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            command = ["/usr/bin/open" if sys.platform == "darwin" else "xdg-open", url]
        child = subprocess.Popen(command, env=env, start_new_session=sys.platform != "win32", **quiet)
        if sys.platform == "win32":
            # The helper exits as soon as ShellExecute returns; a nonzero code is a launch that
            # failed (no default browser): say no_browser, not opened (Task 34 review SHOULD 1).
            try:
                return child.wait(timeout=LAUNCH_WAIT_SECONDS) == 0
            except subprocess.TimeoutExpired:
                return True
        return True
    except OSError:
        return False


LAUNCH_WAIT_SECONDS = 5
CONNECTION_CHANGED = "connection_changed"      # an Approvals request state


class Approvals:
    """Serialize browser dispatch, reserving at most three pending windows INCLUDING queued ones.

    There is no approval route here. Only the injected launcher sees a bootstrap URL;
    return values carry states only. Unknown/evicted ids raise NotApproved, like PlanStore.wait.
    """

    def __init__(self, store, page, launch=open_in_browser, clock=time.monotonic):
        self.store = store
        self.page = page
        self._launch = launch
        self._clock = clock
        self._lock = threading.Lock()
        # Insertion order is the dispatch queue; failed launches do not reserve a window.
        self._requests = {}
        self._last_launch = None
        self._consent_launches = {}     # (kind, connection_id) -> clock of the last window
        self._settings_launch = None    # clock of the last settings window (plugin)

    def ask_consent(self, kind: str, connection_id: str, explicit: bool = False) -> str:
        """Open the local consent window without returning its address to the caller.

        `explicit`: the person asked for the window (HR switch-off, Task 27 M1 road b). It opens
        at once even while an earlier page is still loaded (a closed tab looks loaded for up to
        CONSENT_PAGE_SECONDS), keeping only the short launch gap against a calling loop."""
        with self._lock:
            now = self._clock()
            # Per kind and connection. Inside the ten minutes a new window waits only while the
            # last one can still be used (its link alive or its page loaded); a window that never
            # loaded or has expired is reopened after the short launch gap (Task 27 review S2).
            last = self._consent_launches.get((kind, connection_id))
            if last is not None and (now - last < LAUNCH_GAP_SECONDS or (
                    not explicit and now - last < CONSENT_GAP_SECONDS
                    and self.page.consent_waiting(kind, connection_id))):
                return "recently_asked"
            url = None
            try:
                url = self.page.consent_bootstrap_url(kind, connection_id)
                if self._launch(url):
                    self._consent_launches[(kind, connection_id)] = max(now, self._clock())
                    return "opened"
            except Exception:
                # The launcher may put the secret URL in an exception.
                pass
            if url is not None:
                self.page.discard_consent_bootstrap(url)
            return "no_browser"

    def ask_settings(self) -> str:
        """Open the plugin's Connect Excellent Books page in the person's own browser; return a
        status word only ("opened", "already_open", "no_browser"), never its address (design
        2026-11-23, Review change 2). Every call is an intentional request (open_settings, or the
        first Books call while unconfigured), so it opens again even while an earlier page may be
        loaded (its tab may be closed); only the short launch gap coalesces parallel calls."""
        with self._lock:
            now = self._clock()
            last = self._settings_launch
            if last is not None and now - last < LAUNCH_GAP_SECONDS:
                return "already_open"
            url = None
            try:
                url = self.page.settings_bootstrap_url()
                if self._launch(url):
                    self._settings_launch = max(now, self._clock())
                    return "opened"
            except Exception:
                # The launcher may put the secret URL in an exception.
                pass
            if url is not None:
                self.page.discard_settings_bootstrap(url)
            return "no_browser"

    def _plan(self, plan_id):
        plan = self.store.get(plan_id)
        if plan is None:
            raise NotApproved("Unknown or evicted plan; make a new preview.")
        return plan

    def _prune(self):
        # Called with our lock held; never retain evicted or terminal requests indefinitely.
        for pid in list(self._requests):
            plan = self.store.get(pid)
            if plan is None or plan.state != "pending":
                del self._requests[pid]

    def _requeue_unseen(self):
        # Called with our lock held. A window that was closed, or opened behind others and never
        # seen, would answer already_open until its plan expired and keep a slot (review Task 13
        # S2): once its bootstrap expired unused it goes back in the queue, keeping its place and
        # its slot, and _dispatch relaunches it (at most one window per LAUNCH_GAP_SECONDS).
        for pid, state in self._requests.items():
            if state == "opened" and self.page.unopened(pid):
                self._requests[pid] = "queued"

    def _dispatch(self):
        # Called with our lock held, including through launch, so worker threads cannot race.
        self._requeue_unseen()
        now = self._clock()
        if self._last_launch is not None and now - self._last_launch < LAUNCH_GAP_SECONDS:
            return
        # The first queued plan that may still open; one dropped on the way does not cost the
        # next one a wait slice (blind judge of 3485c9a, NIT).
        for pid in [pid for pid, state in self._requests.items() if state == "queued"]:
            # Recheck after queueing: an expired/declined/evicted preview must never be launched.
            plan = self.store.get(pid)
            if plan is None or plan.state != "pending":
                del self._requests[pid]
                continue
            owner = self.store.owner_state(plan)
            if owner is None:
                # The settings could not be read just now: not opened yet, still queued (Astra
                # recheck of ddce18b, regression).
                continue
            if owner is False:
                # Queued for a connection the settings no longer name: never opened (Astra
                # recheck of the slice 2 fix, MUST 3). Asking again after a switch back queues it
                # again.
                self._requests[pid] = CONNECTION_CHANGED
                continue
            break
        else:
            return
        try:
            started = bool(self._launch(self.page.bootstrap_url(pid)))
        except Exception:
            # An OS/custom launcher exception may include the capability. Never expose it.
            started = False
        # Measure from dispatch completion as well, so a slow launcher cannot bunch windows.
        self._last_launch = max(now, self._clock())
        self._requests[pid] = "opened" if started else "no_browser"

    def request(self, plan_id) -> str:
        with self._lock:
            plan = self._plan(plan_id)
            self._prune()
            self._requeue_unseen()
            before = self._requests.get(plan_id)
            used = sum(s in ("opened", "queued") for s in self._requests.values())
            if plan.state != "pending":
                result = plan.state
            elif before == "opened":
                result = "already_open"
            elif before in (None, "no_browser", CONNECTION_CHANGED) and used >= MAX_OPEN_WINDOWS:
                # A plan asked again after its connection came back takes a window like a new
                # one (blind judge of 3485c9a, NIT).
                result = "too_many"
            else:
                # New, still queued, or asked again after no browser started: try (again).
                self._requests[plan_id] = "queued"
                self._dispatch()
                result = self._requests.get(plan_id, self._plan(plan_id).state)
        if result not in ("opened", "already_open", "queued", "too_many"):
            self.page.stop_if_idle()
        return result

    def wait(self, plan_id, seconds=WAIT_SECONDS) -> str:
        # A frozen injected launch clock must never extend the worker's real-time budget.
        until = time.monotonic() + max(0, seconds)
        while True:
            with self._lock:
                plan = self._plan(plan_id)
                self._prune()
                if plan.state != "pending":
                    result = plan.state
                elif plan_id not in self._requests:
                    # Never requested (or refused as too_many): no window will come, so do not
                    # hold a worker thread for the whole wait (review Task 13 S4).
                    result = "pending"
                else:
                    self._dispatch()
                    result = self._requests.get(plan_id)
                    if result not in ("no_browser", CONNECTION_CHANGED):
                        result = None
            if result is not None:
                self.page.stop_if_idle()
                return result
            remaining = until - time.monotonic()
            if remaining <= 0:
                self.page.stop_if_idle()
                return self._plan(plan_id).state
            # Reuse the store's condition and dual-clock expiry; never hold our lock waiting.
            self.store.wait(plan_id, min(remaining, _WAIT_SLICE_SECONDS))
