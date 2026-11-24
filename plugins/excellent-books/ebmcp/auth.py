"""Microsoft 365 (Entra) sign-in for the Excellent Books MCP.

Ported from `estonian_mcp_build/o365_auth.py`, which was itself ported from hal-rag. The MCP
server is its own OAuth 2.1 Authorization Server and delegates the login to Entra:

    client 401 -> /.well-known/oauth-* -> DCR /register -> /authorize
      -> login.microsoftonline.com -> /auth/o365/callback (validate id_token)
      -> our own auth code -> /token -> our own access token

Divergence from the reference, and the reason for it: the reference's caller treats "no config"
as open unless a flag forbids it. Here `decide_startup` is default-deny — running open requires
EBMCP_ALLOW_OPEN, which a consultant's local .env sets and the hosted instance never does. A
secret that fails to load therefore stops the server instead of opening it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import httpx
import jwt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

if TYPE_CHECKING:
    from .hosted import BooksConnection, BooksSessions

logger = logging.getLogger("ebmcp.auth")

DEFAULT_ISSUER = "https://booksmcp.excellent.ee"
DEFAULT_SCOPES = ["user"]          # used by the provider in Task 5; matches the siblings
OIDC_KEYS = ("OIDC_TENANT_ID", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET")
TOKEN_PREFIX = "ebmcp_"


def loopback_bind(host) -> str | None:
    """The literal loopback address open mode binds, or None when `host` is not one.

    Open mode (EBMCP_ALLOW_OPEN) is served only on this computer (Sol re-check 2026-11-20,
    MUST-FIX 1). `localhost` is turned into 127.0.0.1 HERE, never left to the system resolver,
    which can map it to a network address (Sol re-check of abed9f9, MUST-FIX 1). Surrounding
    spaces and the brackets of `[::1]` are removed, so the value accepted is exactly the value
    uvicorn binds (the same re-check's NIT). Accepted: 127.0.0.0/8 and ::1, written as addresses.
    """
    value = str(host or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if value.lower() == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version == 4:
        return str(address) if address.is_loopback else None
    if address == ipaddress.IPv6Address("::1") and not address.scope_id:
        return "::1"
    return None


def is_loopback_host(host: str) -> bool:
    """True for a bind only this computer can reach (see `loopback_bind`)."""
    return loopback_bind(host) is not None


def loopback_peer(address) -> bool:
    """True when an ASGI `client` or `server` pair names this computer: 127.0.0.0/8, ::1, or
    127.x as a dual-stack socket reports it (::ffff:127.0.0.1). A missing address, a name or a
    socket path is not loopback: open mode then answers nothing."""
    try:
        ip = ipaddress.ip_address(str(address[0]))
    except (TypeError, IndexError, ValueError):
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return ip in ipaddress.IPv4Network("127.0.0.0/8")
    return ip == ipaddress.IPv6Address("::1") and not ip.scope_id


class LoopbackOnly:
    """ASGI guard for open mode: answers 403 unless both ends of the connection are this computer.

    The bind check covers only the built-in launcher. Anyone can also serve the app with their
    own launcher (`uvicorn ebmcp.server:app --host 0.0.0.0`), so the open app itself refuses
    another computer (Sol re-check of abed9f9, MUST-FIX 2). Lifespan events pass through."""

    _BODY = (b"This connector runs without a sign-in and answers only on this computer "
             b"(127.0.0.1).")

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        kind = scope.get("type")
        if kind in ("http", "websocket") and not (loopback_peer(scope.get("client"))
                                                  and loopback_peer(scope.get("server"))):
            if kind == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                    (b"content-length", str(len(self._BODY)).encode("ascii"))]})
            await send({"type": "http.response.body", "body": self._BODY})
            return
        await self.app(scope, receive, send)


OPEN_BIND_REFUSAL = ("EBMCP_ALLOW_OPEN runs the connector without a sign-in, so it may listen only "
                     "on this computer (127.0.0.1, ::1 or localhost); the configured bind (EBMCP_HOST) "
                     "is not one of those. Remove EBMCP_HOST or set it to 127.0.0.1.")


def _positive(value: int, name: str) -> int:
    """0 or less would end every session at login and lock the door without a word (review N4)."""
    if value < 1:
        raise ValueError("%s must be at least 1, got %d" % (name, value))
    return value


def _int_env(env: dict, name: str, default: int) -> int:
    """The default when unset; the value when set; a NAMED error when set to nonsense.

    Never silently defaults a malformed value. `OAUTH_REFRESH_TOKEN_TTL=30d` meaning thirty days
    would otherwise become 2592000 seconds by coincidence and hide the typo; a TTL the admin
    cannot see is a TTL the admin cannot shorten. Raising stops the server, which is the
    fail-closed direction, and the message names the variable so the fix is one line.
    """
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(
            "%s must be a whole number, got %r" % (name, raw)) from None


def _text_env(env: dict, name: str, default: str) -> str:
    """A stripped override, or the default when it is unset or only whitespace.

    An env value carrying a trailing space or newline — routine from a .env file or a
    docker --env-file — must not reach the issuer URL or the redirect URI, where it becomes a
    redirect_uri mismatch at Entra rather than a visible configuration error.
    """
    return (env.get(name) or "").strip() or default


@dataclass(frozen=True)
class AuthConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    redirect_uri: str
    issuer_url: str
    oauth_db_path: str
    access_ttl: int
    refresh_ttl: int
    max_session_days: int = 30


def load_auth_config(env: dict | None = None) -> AuthConfig | None:
    """`AuthConfig` when all three OIDC values are present, else None.

    Partial configuration is None, not a half-authenticated server. `decide_startup` is what
    turns that None into a refusal rather than an open port.
    """
    env = os.environ if env is None else env
    tenant = (env.get("OIDC_TENANT_ID") or "").strip()
    client_id = (env.get("OIDC_CLIENT_ID") or "").strip()
    secret = (env.get("OIDC_CLIENT_SECRET") or "").strip()
    if not (tenant and client_id and secret):
        return None
    issuer = _text_env(env, "EBMCP_ISSUER_URL", DEFAULT_ISSUER).rstrip("/") or DEFAULT_ISSUER
    return AuthConfig(
        tenant_id=tenant,
        client_id=client_id,
        client_secret=secret,
        redirect_uri=_text_env(env, "OIDC_REDIRECT_URI", f"{issuer}/auth/o365/callback"),
        issuer_url=issuer,
        oauth_db_path=_text_env(env, "OAUTH_DB_PATH", "/data/oauth.db"),
        access_ttl=_int_env(env, "OAUTH_ACCESS_TOKEN_TTL", 3600),
        refresh_ttl=_int_env(env, "OAUTH_REFRESH_TOKEN_TTL", 2592000),
        max_session_days=_positive(_int_env(env, "OAUTH_MAX_SESSION_DAYS", 30),
                                   "OAUTH_MAX_SESSION_DAYS"),
    )


def decide_startup(env: dict | None = None) -> tuple[str, str]:
    """Return the startup mode and reason. HTTP defaults to deny.

    Desktop uses stdio. Hosted has its own HTTP startup policy. Local HTTP never returns
    "open" by omission.

    The HTTP branch order is the security control. `allow_open and any_oidc` is tested
    first because a PARTIAL OIDC config makes `load_auth_config` return None: test `cfg` first and
    a host with a secret that failed to load, plus a stray EBMCP_ALLOW_OPEN, falls through to
    "open". Pinned by `test_allow_open_beside_partial_oidc_config_still_refuses`.

    `load_auth_config` is called only AFTER that first guard, so a malformed OAUTH_*_TTL — which
    raises — cannot pre-empt the one refusal that matters most.
    """
    env = os.environ if env is None else env
    open_setting = (env.get("EBMCP_ALLOW_OPEN") or "").strip()
    any_oidc = any((env.get(k) or "").strip() for k in OIDC_KEYS)

    if env.get("EBMCP_MODE") == "hosted":
        if open_setting or any(key.startswith("OIDC_") and (value or "").strip()
                               for key, value in env.items()):
            return ("refuse", "Hosted mode cannot be combined with EBMCP_ALLOW_OPEN or "
                              "OIDC_* settings. Unset those settings to start in hosted mode.")
        return ("hosted", "Hosted mode selected.")

    if env.get("EBMCP_MODE") in ("desktop", "plugin"):
        # The ChatGPT/Codex plugin is stdio too, with the same refusals (Review change 5).
        name = "Desktop" if env.get("EBMCP_MODE") == "desktop" else "Plugin"
        if name == "Plugin":
            # Any OIDC_* setting at all, as hosted (Astra review of slice 2, SHOULD 1); Desktop
            # keeps its three-key rule.
            any_oidc = any_oidc or any(key.startswith("OIDC_") and (value or "").strip()
                                       for key, value in env.items())
        if open_setting or any_oidc:
            return ("refuse", "%s mode cannot be combined with EBMCP_ALLOW_OPEN or "
                              "OIDC settings. Unset those settings to start over stdio." % name)
        return ("stdio", "%s mode uses stdio without an HTTP listener." % name)

    allow_open = open_setting.lower() in ("1", "true", "yes")
    if allow_open and any_oidc:
        return ("refuse", "EBMCP_ALLOW_OPEN is set alongside OIDC_* values. That combination is "
                          "always a mistake: it would serve an unauthenticated server on a host "
                          "someone meant to protect. Unset one of them.")
    if load_auth_config(env) is not None:
        return ("authenticated", "O365 sign-in enabled")
    if allow_open:
        if "EBMCP_HOST" in env and loopback_bind(env.get("EBMCP_HOST")) is None:
            return ("refuse", OPEN_BIND_REFUSAL)
        return ("open", "EBMCP_ALLOW_OPEN is set — server is OPEN, on this computer only")
    return ("refuse", "OAuth is not configured (OIDC_TENANT_ID, OIDC_CLIENT_ID and "
                      "OIDC_CLIENT_SECRET must all be set). Refusing to start an unauthenticated "
                      "server. Set EBMCP_ALLOW_OPEN=1 only for a local copy.")


# --------------------------------------------------------------------------
# store
# --------------------------------------------------------------------------

def _h(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class BooksAccessToken(AccessToken):
    grant_id: str
    login_at: int
    connection: str = ""


class BooksRefreshToken(RefreshToken):
    grant_id: str
    login_at: int
    connection: str = ""


class BooksAuthCode(AuthorizationCode):
    grant_id: str
    login_at: int
    connection: str = ""


_GRANT_ROWS = (("auth_codes", "ac_json"), ("access_tokens", "at_json"),
               ("refresh_tokens", "rt_json"))
_PENDING_TTL = 600
_MAX_CLIENTS = 200


class ClientCapacityError(ValueError):
    pass


class OAuthStore:
    """SQLite-backed OAuth state keyed by hashes of user tokens and codes."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._init_db()

    @contextmanager
    def _conn(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(self._db_path)
        c.row_factory = sqlite3.Row
        try:
            with c:
                if write:
                    c.execute("BEGIN IMMEDIATE")
                    self._prune(c)
                yield c
        finally:
            c.close()

    def _init_db(self) -> None:
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL").fetchone()
            c.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS clients(
                    client_id TEXT PRIMARY KEY, info_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS pending(
                    entra_state TEXT PRIMARY KEY, data_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS auth_codes(
                    code TEXT PRIMARY KEY, ac_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS access_tokens(
                    token_hash TEXT PRIMARY KEY, at_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS refresh_tokens(
                    token_hash TEXT PRIMARY KEY, rt_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS api_tokens(
                    token_hash TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER);
                """
            )
            c.execute("PRAGMA secure_delete=ON")
            scrub = c.execute("PRAGMA user_version").fetchone()[0] == 0
            for table, payload in _GRANT_ROWS:
                deleted = c.execute(f"DELETE FROM {table} WHERE CASE WHEN json_valid({payload}) "
                                    f"THEN COALESCE(json_extract({payload}, '$.grant_id'), '') = '' "
                                    "ELSE 1 END")
                scrub = scrub or deleted.rowcount > 0
            if scrub:
                c.execute("PRAGMA user_version=0")
            self._prune(c)
            c.commit()
            if scrub:
                # Rebuild pages that held previously deleted secrets, then discard old WAL frames.
                c.execute("VACUUM")
                if c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]:
                    raise sqlite3.OperationalError("Could not checkpoint the OAuth database migration")
                c.execute("PRAGMA user_version=1")

    @staticmethod
    def _prune(c: sqlite3.Connection) -> None:
        now = int(time.time())
        c.execute("DELETE FROM pending WHERE created_at <= ?", (now - _PENDING_TTL,))
        for table, payload in _GRANT_ROWS:
            c.execute(f"DELETE FROM {table} WHERE "
                      f"COALESCE(json_extract({payload}, '$.expires_at'), 0) <= ?", (now,))

    @staticmethod
    def _cap_clients(c: sqlite3.Connection, keep: str) -> None:
        """Past _MAX_CLIENTS: evict idle clients first, then clients with only an unfinished
        sign-in, oldest first. A client holding a code or a token (a real Entra sign-in) is never
        evicted; registration is refused only when every other client holds one. An unfinished
        sign-in costs an attacker no login, so it must not protect a client (opus review of
        16ae919: 200 of them locked registration and pushed colleagues' clients out)."""
        excess = c.execute("SELECT COUNT(*) FROM clients").fetchone()[0] - _MAX_CLIENTS
        if excess <= 0:
            return
        granted = " UNION ALL ".join(
            f"SELECT json_extract({payload}, '$.client_id') AS id FROM {table}"
            for table, payload in _GRANT_ROWS)
        pending = "SELECT json_extract(data_json, '$.client_id') FROM pending"
        deleted = c.execute(f"""
            DELETE FROM clients WHERE client_id IN (
                SELECT client_id FROM clients WHERE client_id != ?
                AND client_id NOT IN (SELECT id FROM ({granted}) AS g WHERE id IS NOT NULL)
                ORDER BY (client_id IN ({pending})) ASC, rowid
                LIMIT ?
            )
        """, (keep, excess))
        if deleted.rowcount != excess:
            raise ClientCapacityError("Client registration capacity reached.")
        c.execute("DELETE FROM pending WHERE json_extract(data_json, '$.client_id') "
                  "NOT IN (SELECT client_id FROM clients)")

    # --- clients (DCR) ---
    def save_client(self, info: OAuthClientInformationFull) -> None:
        # The DCR-issued client_secret is stored in plaintext by design: the MCP
        # SDK token endpoint needs it for compare_digest client auth. It is a
        # CLIENT credential (the MCP client app), not a user token.
        with self._conn(write=True) as c:
            c.execute(
                "INSERT OR REPLACE INTO clients(client_id, info_json) VALUES(?,?)",
                (info.client_id, info.model_dump_json()))
            self._cap_clients(c, info.client_id)

    def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT info_json FROM clients WHERE client_id=?",
                (client_id,)).fetchone()
        return (OAuthClientInformationFull.model_validate_json(row["info_json"])
                if row else None)

    # --- pending Entra logins (one-shot, TTL) ---
    def save_pending(self, entra_state: str, data: dict, created_at: int | None = None) -> None:
        ts = int(time.time()) if created_at is None else created_at
        with self._conn(write=True) as c:
            c.execute(
                "INSERT OR REPLACE INTO pending(entra_state, data_json, created_at) "
                "VALUES(?,?,?)",
                (entra_state, json.dumps(data), ts))

    def get_pending(self, state: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT data_json FROM pending WHERE entra_state=? AND created_at>?",
                            (state, int(time.time()) - _PENDING_TTL)).fetchone()
        return json.loads(row["data_json"]) if row else None

    def pop_pending(self, entra_state: str, max_age: int = _PENDING_TTL) -> dict | None:
        with self._conn(write=True) as c:
            row = c.execute(
                "SELECT data_json, created_at FROM pending WHERE entra_state=?",
                (entra_state,)).fetchone()
            c.execute("DELETE FROM pending WHERE entra_state=?", (entra_state,))
        if not row:
            return None
        if int(time.time()) - row["created_at"] >= max_age:
            return None
        return json.loads(row["data_json"])

    # --- authorization codes (one-shot) ---
    def save_auth_code(self, ac: BooksAuthCode) -> None:
        with self._conn(write=True) as c:
            c.execute(
                "INSERT OR REPLACE INTO auth_codes(code, ac_json) VALUES(?,?)",
                (_h(ac.code), ac.model_dump_json(exclude={"code"})))

    def get_auth_code(self, code: str) -> BooksAuthCode | None:
        with self._conn() as c:
            return self._read_auth_code(c, code)

    @staticmethod
    def _read_auth_code(c: sqlite3.Connection, code: str) -> BooksAuthCode | None:
        row = c.execute("SELECT ac_json FROM auth_codes WHERE code=?", (_h(code),)).fetchone()
        return BooksAuthCode.model_validate(dict(json.loads(row["ac_json"]), code=code)) if row else None

    def pop_auth_code(self, code: str) -> BooksAuthCode | None:
        with self._conn(write=True) as c:
            return self._pop_auth_code(c, code)

    def _pop_auth_code(self, c: sqlite3.Connection, code: str) -> BooksAuthCode | None:
        ac = self._read_auth_code(c, code)
        c.execute("DELETE FROM auth_codes WHERE code=?", (_h(code),))
        return ac

    # --- access tokens ---
    def save_access(self, at: BooksAccessToken) -> None:
        with self._conn(write=True) as c:
            self._insert_access(c, at)

    @staticmethod
    def _insert_access(c: sqlite3.Connection, at: BooksAccessToken) -> None:
        c.execute(
            "INSERT OR REPLACE INTO access_tokens(token_hash, at_json) VALUES(?,?)",
            (_h(at.token), at.model_dump_json(exclude={"token"})))

    def get_access(self, token: str) -> BooksAccessToken | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT at_json FROM access_tokens WHERE token_hash=?",
                (_h(token),)).fetchone()
        return BooksAccessToken.model_validate(dict(json.loads(row["at_json"]), token=token)) if row else None

    def delete_access(self, token: str) -> None:
        with self._conn(write=True) as c:
            c.execute("DELETE FROM access_tokens WHERE token_hash=?", (_h(token),))

    # --- refresh tokens ---
    def save_refresh(self, rt: BooksRefreshToken) -> None:
        with self._conn(write=True) as c:
            self._insert_refresh(c, rt)

    @staticmethod
    def _insert_refresh(c: sqlite3.Connection, rt: BooksRefreshToken) -> None:
        c.execute(
            "INSERT OR REPLACE INTO refresh_tokens(token_hash, rt_json) VALUES(?,?)",
            (_h(rt.token), rt.model_dump_json(exclude={"token"})))

    def get_refresh(self, token: str) -> BooksRefreshToken | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT rt_json FROM refresh_tokens WHERE token_hash=?",
                (_h(token),)).fetchone()
        return BooksRefreshToken.model_validate(dict(json.loads(row["rt_json"]), token=token)) if row else None

    def delete_refresh(self, token: str) -> bool:
        with self._conn(write=True) as c:
            return self._delete_refresh(c, token)

    @staticmethod
    def _delete_refresh(c: sqlite3.Connection, token: str) -> bool:
        return c.execute("DELETE FROM refresh_tokens WHERE token_hash=?", (_h(token),)).rowcount == 1

    def exchange_tokens(self, previous: BooksAuthCode | BooksRefreshToken,
                        at: BooksAccessToken, rt: BooksRefreshToken) -> bool:
        """Consume the credential and create its replacements in the same transaction."""
        with self._conn(write=True) as c:
            if isinstance(previous, BooksAuthCode):
                consumed = self._pop_auth_code(c, previous.code) is not None
            else:
                consumed = self._delete_refresh(c, previous.token)
            if not consumed:
                return False
            self._insert_access(c, at)
            self._insert_refresh(c, rt)
            return True

    def delete_grant(self, grant_id: str) -> None:
        with self._conn(write=True) as c:
            for table, payload in _GRANT_ROWS:
                c.execute(f"DELETE FROM {table} WHERE json_extract({payload}, '$.grant_id') = ?",
                          (grant_id,))

    def drop_all_grants(self) -> None:
        with self._conn(write=True) as c:
            for table, _ in _GRANT_ROWS:
                c.execute(f"DELETE FROM {table}")

    def purge_expired(self) -> None:
        """Drop expired OAuth credentials and stale pending logins."""
        with self._conn(write=True):
            pass

    # --- API tokens (personal tokens for clients) ---
    def mint_api_token(self, subject: str, label: str = "", days: int = 90) -> str:
        """Return the RAW token. It is shown once and never recoverable: only its hash is kept.

        The token is 256 bits from `secrets`, so the stored digest is a plain SHA-256 and
        deliberately not a slow KDF: there is no guessable secret behind it to brute-force, and
        `verify_api_token` runs on every single request.

        An empty subject is refused here rather than downstream. `verify_api_token` returns the
        subject and its caller tests `is None`, so a token minted `--for ""` would authenticate
        as a principal that is falsy but not None — a session belonging to nobody.
        """
        subject = (subject or "").strip()
        if not subject:
            raise ValueError("an API token needs a subject: who the token authenticates as")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = int(time.time())
        with self._conn(write=True) as c:
            c.execute("INSERT INTO api_tokens (token_hash, subject, label, created_at, expires_at)"
                      " VALUES (?,?,?,?,?)",
                      (_h(token), subject, label, now, now + days * 86400))
        return token

    def verify_api_token(self, token: str) -> str | None:
        """Subject, or None if unknown, expired or revoked. Read every time — never cached, so a
        revocation takes effect on the next request rather than at some TTL.

        Columns are read BY NAME. Positional access here means the revocation check silently
        becomes the expiry check the day someone reorders the SELECT, and a revoked token would
        keep working with every test still green.

        A token is expired at its expiry timestamp.
        """
        with self._conn() as c:
            row = c.execute("SELECT subject, expires_at, revoked_at FROM api_tokens"
                            " WHERE token_hash=?", (_h(token),)).fetchone()
        if row is None or row["revoked_at"] is not None:
            return None
        if row["expires_at"] is None or row["expires_at"] <= int(time.time()):
            return None
        return row["subject"]

    def revoke_api_token(self, token_hash_prefix: str) -> bool:
        """Revoke every LIVE token whose hash starts with this prefix. True if anything changed.

        Matched with `substr`, never `LIKE`. `LIKE` reads `%` and `_` in the pattern as
        wildcards, and this value arrives straight from an admin's argv: `revoke '%%%%'` is four
        characters, clears the length guard below, and revoked EVERY live token in the company —
        measured, not theorised. `substr` has no pattern language, so a prefix is only ever
        itself. Hashes are lowercase hex, so the prefix is lowered to keep the case-insensitive
        matching `LIKE` gave for free.

        The length guard stays as the second line of defence: a stray short prefix still names
        far more tokens than an admin meant to name.
        """
        prefix = (token_hash_prefix or "").strip().lower()
        if len(prefix) < 4:
            return False
        with self._conn(write=True) as c:
            cur = c.execute("UPDATE api_tokens SET revoked_at=?"
                            " WHERE substr(token_hash,1,?)=? AND revoked_at IS NULL",
                            (int(time.time()), len(prefix), prefix))
            return cur.rowcount > 0

    def list_api_tokens(self) -> list[dict]:
        """Every token, newest first. Rows carry the HASH; the raw token is not recoverable.

        `dict(row)` takes its keys from the cursor rather than from a hand-written tuple zipped
        against the SELECT by position — a pairing that mislabels silently when a column moves.
        `rowid` breaks the tie for tokens minted within the same second, so the order a listing
        shows and the order a script indexes are the same order.
        """
        with self._conn() as c:
            rows = c.execute("SELECT token_hash, subject, label, created_at, expires_at,"
                             " revoked_at FROM api_tokens"
                             " ORDER BY created_at DESC, rowid DESC").fetchall()
        return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# Entra
# --------------------------------------------------------------------------

class EntraOIDC:
    def __init__(self, cfg: AuthConfig):
        self.cfg = cfg
        self._authority = f"https://login.microsoftonline.com/{cfg.tenant_id}"
        self._issuer = f"{self._authority}/v2.0"
        self._jwks_uri = f"{self._authority}/discovery/v2.0/keys"
        self._jwk_client = jwt.PyJWKClient(self._jwks_uri)

    def build_authorize_url(self, state: str, nonce: str) -> str:
        q = urlencode({
            "client_id": self.cfg.client_id,
            "response_type": "code",
            "redirect_uri": self.cfg.redirect_uri,
            "response_mode": "query",
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
        })
        return f"{self._authority}/oauth2/v2.0/authorize?{q}"

    async def exchange_code(self, code: str) -> dict:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.cfg.redirect_uri,
            "client_id": self.cfg.client_id,
            "client_secret": self.cfg.client_secret,
            "scope": "openid email profile",
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self._authority}/oauth2/v2.0/token", data=data)
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(
                f"Entra token request failed: HTTP {e.response.status_code}") from e
        except httpx.HTTPError as e:
            raise ValueError(f"Entra token request failed: {e}") from e
        if "error" in body:
            raise ValueError(
                f"Entra token error: {body.get('error')} "
                f"{body.get('error_description', '')}")
        return body

    def validate_id_token(self, id_token: str, expected_nonce: str) -> str:
        """Verify signature/issuer/audience/nonce; return the user's email."""
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(
                id_token, signing_key.key, algorithms=["RS256"],
                audience=self.cfg.client_id, issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except (jwt.PyJWTError, jwt.exceptions.PyJWKClientError) as e:
            raise ValueError(f"id_token validation failed: {e}") from e
        if claims.get("nonce") != expected_nonce:
            raise ValueError("id_token nonce mismatch")
        email = (claims.get("email") or claims.get("preferred_username")
                 or claims.get("upn") or "").strip().lower()
        if not email:
            raise ValueError("Entra released no email claim")
        return email


# --------------------------------------------------------------------------
# provider
# --------------------------------------------------------------------------

class ClientRegistry:
    def __init__(self, store: OAuthStore):
        self.store = store

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.store.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        try:
            self.store.save_client(client_info)
        except ClientCapacityError as exc:
            raise RegistrationError("invalid_client_metadata", str(exc)) from None


class BooksOAuthProvider(
    ClientRegistry, OAuthAuthorizationServerProvider[BooksAuthCode, BooksRefreshToken, AccessToken]
):
    def __init__(self, cfg: AuthConfig, store: OAuthStore, entra: EntraOIDC):
        super().__init__(store)
        self.cfg = cfg
        self.entra = entra

    def _valid_session(self, credential: BooksAuthCode | BooksRefreshToken | BooksAccessToken) -> bool:
        now = time.time()
        return (credential.expires_at is not None and now < credential.expires_at
                and credential.login_at <= now < self._session_end(credential.login_at))

    def _session_end(self, login_at: int) -> int:
        return login_at + self.cfg.max_session_days * 86400

    # --- /authorize: stash the pending request, send the user to Entra ---
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        entra_state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        self.store.save_pending(entra_state, {
            "nonce": nonce,
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "claude_state": params.state,
            "scopes": params.scopes or DEFAULT_SCOPES,
        })
        return self.entra.build_authorize_url(entra_state, nonce)

    # --- Entra return leg (called by the /auth/o365/callback route) ---
    async def complete_entra_login(self, entra_state: str, code: str) -> str:
        pending = self.store.pop_pending(entra_state)
        if pending is None:
            raise ValueError("unknown or expired state")
        token_resp = await self.entra.exchange_code(code)
        id_token = token_resp.get("id_token")
        if not id_token:
            raise ValueError("Entra returned no id_token")
        # Tenant-wide: a valid id_token for our single-tenant app == authorized. The e-mail this
        # returns IS that decision, so it is checked and then dropped: container logs are read by
        # more people than the database is, and no personal data goes into them. The DCR client
        # id below is what makes a log line useful without naming anybody.
        self.entra.validate_id_token(id_token, pending["nonce"])
        logger.info("O365 sign-in completed for client %s", pending["client_id"])
        auth_code = secrets.token_urlsafe(32)
        login_at = int(time.time())
        self.store.save_auth_code(BooksAuthCode(
            code=auth_code,
            grant_id=secrets.token_urlsafe(32),
            login_at=login_at,
            scopes=pending["scopes"],
            expires_at=min(login_at + _PENDING_TTL, self._session_end(login_at)),
            client_id=pending["client_id"],
            code_challenge=pending["code_challenge"],
            redirect_uri=pending["redirect_uri"],
            redirect_uri_provided_explicitly=pending[
                "redirect_uri_provided_explicitly"],
        ))
        return construct_redirect_uri(
            pending["redirect_uri"], code=auth_code, state=pending["claude_state"])

    # --- code -> token ---
    async def load_authorization_code(
        self, client, authorization_code: str
    ) -> BooksAuthCode | None:
        # The SDK validates the redirect and PKCE proof before calling the exchange.
        ac = self.store.get_auth_code(authorization_code)
        if ac is None or ac.client_id != client.client_id or not self._valid_session(ac):
            return None
        return ac

    async def exchange_authorization_code(
        self, client, authorization_code: BooksAuthCode
    ) -> OAuthToken:
        if authorization_code.client_id != client.client_id or not self._valid_session(authorization_code):
            raise TokenError("invalid_grant", "Sign in again.")
        return self._issue(authorization_code, authorization_code.scopes)

    # --- refresh ---
    async def load_refresh_token(self, client, refresh_token: str) -> BooksRefreshToken | None:
        rt = self.store.get_refresh(refresh_token)
        if rt is None or rt.client_id != client.client_id or not self._valid_session(rt):
            return None
        return rt

    async def exchange_refresh_token(
        self, client, refresh_token: BooksRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        if refresh_token.client_id != client.client_id or not self._valid_session(refresh_token):
            raise TokenError("invalid_grant", "Sign in again.")
        use_scopes = scopes or refresh_token.scopes
        if not set(use_scopes).issubset(refresh_token.scopes):
            raise TokenError("invalid_scope", "Requested scopes were not granted.")
        return self._issue(refresh_token, use_scopes)

    # --- bearer validation ---
    async def load_access_token(self, token: str) -> AccessToken | None:
        """The one place both doors meet: an OAuth access token and a personal API token are
        equally valid here, and nothing downstream needs to know which was used. Both branches
        check expiry here (the OAuth one also the session's maximum age), so neither door leans
        on the SDK's later re-check and the two cannot drift apart. Adding a token branch anywhere
        else would mean re-implementing expiry and revocation a second time."""
        at = self.store.get_access(token)
        if at is not None and self._valid_session(at):
            return at
        subject = self.store.verify_api_token(token)
        if subject is None:
            return None
        return AccessToken(token=token, client_id=subject, scopes=DEFAULT_SCOPES,
                           expires_at=None)

    async def revoke_token(self, token: AccessToken | BooksRefreshToken) -> None:
        if isinstance(token, (BooksAccessToken, BooksRefreshToken)):
            self.store.delete_grant(token.grant_id)

    # --- helper ---
    def _issue(self, previous: BooksAuthCode | BooksRefreshToken, scopes: list[str]) -> OAuthToken:
        now = int(time.time())
        cap = self._session_end(previous.login_at)
        metadata = dict(client_id=previous.client_id, scopes=scopes,
                        grant_id=previous.grant_id, login_at=previous.login_at,
                        connection=previous.connection)
        access = BooksAccessToken(token=secrets.token_urlsafe(32),
                                  expires_at=min(now + self.cfg.access_ttl, cap), **metadata)
        refresh = BooksRefreshToken(token=secrets.token_urlsafe(32),
                                    expires_at=min(now + self.cfg.refresh_ttl, cap), **metadata)
        if not self.store.exchange_tokens(previous, access, refresh):
            raise TokenError("invalid_grant", "Sign in again.")
        return OAuthToken(
            access_token=access.token, token_type="Bearer",
            expires_in=access.expires_at - now, scope=" ".join(scopes),
            refresh_token=refresh.token)


@dataclass(frozen=True)
class HostedAuthConfig:
    issuer_url: str
    resource_url: str
    redirect_uris: frozenset[str]
    access_ttl: int
    refresh_ttl: int
    max_session_days: int

    @classmethod
    def from_env(cls, env, issuer_url: str, resource_url: str,
                 redirect_uris: frozenset[str]) -> HostedAuthConfig:
        return cls(
            issuer_url, resource_url, redirect_uris,
            access_ttl=_int_env(env, "OAUTH_ACCESS_TOKEN_TTL", 3600),
            refresh_ttl=_int_env(env, "OAUTH_REFRESH_TOKEN_TTL", 2592000),
            max_session_days=_positive(_int_env(env, "OAUTH_MAX_SESSION_DAYS", 30),
                                       "OAUTH_MAX_SESSION_DAYS"),
        )


class HostedProvider(BooksOAuthProvider):
    """OAuth grants backed by this process's live Books connections."""

    def __init__(self, cfg: HostedAuthConfig, store: OAuthStore, sessions: BooksSessions):
        ClientRegistry.__init__(self, store)
        self.cfg = cfg
        self.sessions = sessions

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource is not None and params.resource != self.cfg.resource_url:
            raise AuthorizeError("invalid_request", "The requested resource is not this server.")
        redirect_uri = str(params.redirect_uri)
        if redirect_uri not in self.cfg.redirect_uris:
            raise AuthorizeError("invalid_request", "The redirect URI is no longer allowed.")
        state = secrets.token_urlsafe(32)
        self.store.save_pending(state, {
            "client_id": client.client_id,
            "redirect_uri": redirect_uri,
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "client_state": params.state,
            "scopes": params.scopes or DEFAULT_SCOPES,
            "resource": self.cfg.resource_url,
        })
        return f"{self.cfg.issuer_url}/auth/books?{urlencode({'state': state})}"

    def has_pending_books_login(self, state: str) -> bool:
        pending = self.store.get_pending(state)
        return pending is not None and pending.get("resource") == self.cfg.resource_url

    def complete_books_login(self, state: str, connection: BooksConnection) -> str:
        pending = self.store.pop_pending(state)
        if pending is None or pending.get("resource") != self.cfg.resource_url:
            raise ValueError("Unknown or expired Books sign-in state.")
        if self.sessions.get(connection.grant_id) is not connection:
            raise ValueError("The Books connection is no longer active.")
        # The AI app as it registered itself: shown on the approval page, never compared.
        from .hosted import CLIENT_NAME_CHARS
        client = self.store.get_client(pending["client_id"])
        name = getattr(client, "client_name", None)
        connection.client = name[:CLIENT_NAME_CHARS] if isinstance(name, str) else ""
        code = secrets.token_urlsafe(32)
        login_at = int(time.time())
        self.store.save_auth_code(BooksAuthCode(
            code=code,
            grant_id=connection.grant_id,
            login_at=login_at,
            connection=connection.label,
            scopes=pending["scopes"],
            expires_at=min(login_at + _PENDING_TTL, self._session_end(login_at)),
            client_id=pending["client_id"],
            code_challenge=pending["code_challenge"],
            redirect_uri=pending["redirect_uri"],
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            resource=pending["resource"],
        ))
        return construct_redirect_uri(pending["redirect_uri"], code=code, state=pending["client_state"])

    def _valid_session(self, credential: BooksAuthCode | BooksRefreshToken | BooksAccessToken) -> bool:
        # Inherited code and refresh paths check here both before and during exchange.
        if not super()._valid_session(credential):
            return False
        if self.sessions.get(credential.grant_id) is None:
            self.store.delete_grant(credential.grant_id)
            return False
        return not isinstance(credential, BooksAuthCode) or credential.resource == self.cfg.resource_url

    async def load_access_token(self, token: str) -> BooksAccessToken | None:
        at = self.store.get_access(token)
        return at if at is not None and self._valid_session(at) else None

    async def revoke_token(self, token: AccessToken | BooksRefreshToken) -> None:
        if isinstance(token, (BooksAccessToken, BooksRefreshToken)):
            self.sessions.drop(token.grant_id)
        await super().revoke_token(token)
