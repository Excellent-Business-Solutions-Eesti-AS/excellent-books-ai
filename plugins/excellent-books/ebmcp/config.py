"""Runtime configuration, read from `.env` by this module itself.

Why not `source .env` and read the environment: Git Bash (MSYS2) rewrites POSIX-looking values
on the way into a native Windows python — `/Servers/x` became `C:/Program Files/Git/Servers/x`
in the HUGE database project, and the failure read as a zero, not an error. Reading the file
here sidesteps that. Values already present in the environment still win, so a container can
inject them without a file.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from hashlib import sha256
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / ".env"

REQUIRED = ("EBMCP_API_BASE or EBMCP_SERVER_URL", "EBMCP_USER", "EBMCP_PASSWORD")


class ConfigError(ValueError):
    """Configuration was provided but cannot be used safely."""


MODES = ("local", "desktop", "hosted", "plugin")


def mode() -> str:
    value = os.environ.get("EBMCP_MODE", "local")
    if value not in MODES:
        raise ConfigError("EBMCP_MODE must be local, desktop, hosted or plugin.")
    return value


def stdio_mode() -> bool:
    """Desktop and the ChatGPT/Codex plugin: one person's connector over stdio, its state in a
    per-user data folder, its consent and approval pages in that person's browser."""
    return mode() in ("desktop", "plugin")


# The ChatGPT/Codex plugin (design 2026-11-23, Review changes 5 and 6): its own data folder, so a
# Desktop install and a plugin install never share settings or consent, and its settings only in
# <data>/settings.env, written by the settings page (save_plugin_settings), never the environment.
PLUGIN_FOLDER = "ExcellentBooksMCP-Plugin"
PLUGIN_SETTINGS_NAME = "settings.env"
PLUGIN_REQUIRED = ("EBMCP_SERVER_URL", "EBMCP_COMPANY", "EBMCP_USER", "EBMCP_PASSWORD")
PLUGIN_KEYS = PLUGIN_REQUIRED + ("EBMCP_WRITES", "EBMCP_APPROVE_IN")


def data_dir() -> Path:
    """The runtime data folder. Keep the existing ZIP and container roots."""
    run_mode = mode()
    folder = PLUGIN_FOLDER if run_mode == "plugin" else "ExcellentBooksMCP"
    override = os.environ.get("EBMCP_DATA_DIR")
    if override:
        try:
            path = Path(override).expanduser()
        except RuntimeError:        # "~someone" with no such home folder
            raise ConfigError("EBMCP_DATA_DIR names a home folder that does not exist.") from None
        if not path.is_absolute():
            # Relative to whatever folder the host started us in: no stable place for state.
            raise ConfigError("EBMCP_DATA_DIR must be an absolute folder path.")
    elif run_mode not in ("desktop", "plugin"):
        return PROJECT_ROOT
    elif sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) if local else Path.home() / "AppData" / "Local"
        path = base / folder
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / folder
    else:
        path = Path.home() / ".local" / "state" / folder
    posix = os.name == "posix"
    # Never raises (Task 24 review S2): a folder that cannot be made or made private leaves the
    # callers' own reads and writes to fail softly, as they do on a read-only install. The home
    # folder itself (EBMCP_DATA_DIR=~) is never chmod-ed.
    try:
        path.mkdir(mode=0o700 if posix else 0o777, parents=True, exist_ok=True)
        if posix and path.resolve() != Path.home().resolve() \
                and stat.S_IMODE(path.stat().st_mode) != 0o700:
            path.chmod(0o700)
    except OSError:
        pass
    return path


_HTTP_NETWORKS = tuple(ip_network(cidr) for cidr in (
    "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))


def _validated_url(raw: str):
    address = raw.strip()
    if not address or any(char.isspace() for char in address):
        raise ConfigError("Server address must have a host without whitespace.")
    if "://" not in address:
        address = "https://" + address
    try:
        parts = urlsplit(address)
        host = parts.hostname
        parts.port  # Validate port syntax and range as well as the host.
    except ValueError:
        raise ConfigError("Server address has an invalid host or port.") from None
    if parts.scheme not in ("http", "https"):
        raise ConfigError("Server address must use https:// or private-network http://.")
    if not host or any(char.isspace() for char in host):
        raise ConfigError("Server address must have a host without whitespace.")
    if "@" in parts.netloc or "?" in address or "#" in address:
        raise ConfigError("Server address must not contain userinfo, a query or a fragment.")
    if parts.scheme == "http" and host != "localhost":
        # Only literal IPs are classified. Names are never resolved to grant HTTP access.
        private = False
        if ":" in host or re.fullmatch(r"[0-9.]+", host):
            try:
                ip = ip_address(host)
                private = any(ip in network for network in _HTTP_NETWORKS)
            except ValueError:
                pass
        if not private:
            raise ConfigError("This server address needs https://. Plain http:// works only with "
                              "this computer or an office-network IP address (for example "
                              "http://192.168.1.10:8080); a server name is not enough: use its "
                              "IP address, or https.")
    return parts


def clean_server_url(raw: str) -> str:
    """Validate a Books address and remove a trailing REST company path."""
    parts = _validated_url(raw)
    path = re.sub(r"/api/[0-9]+$", "", parts.path.rstrip("/"))
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def plugin_server_root(raw: str) -> str:
    """The plugin's ONE server root: the root the settings page signs in to, stores, compares and
    the connector later uses (Astra review of slice 3, MUST 1). clean_server_url removes one
    trailing /api/<n>; an address that still ends in one after that would name a different root
    each time it was cleaned again, so it is refused."""
    root = clean_server_url(raw)
    if clean_server_url(root) != root:
        raise ConfigError("Server address must not end in /api/<number> twice; enter the server "
                          "address without the REST path.")
    return root


def plugin_api_base(values: dict) -> str:
    """The REST base the plugin settings `values` name (KeyError when a key is missing). The
    stored root is used as it is: one that still ends in /api/<n> was not written by the
    settings page (it stores the root it signed in to) and is refused, never cleaned into
    another root."""
    raw = values["EBMCP_SERVER_URL"]
    if re.search(r"/api/[0-9]+$", _validated_url(raw).path.rstrip("/")):
        raise ConfigError("The saved server address ends in /api/<number>: save the connection "
                          "again on the settings page.")
    return "%s/api/%d" % (plugin_server_root(raw), _company_number(values["EBMCP_COMPANY"]))


def _company_number(company) -> int:
    # "2.0" is accepted: Claude Desktop may hand its number setting over that way (P5 row 15).
    match = re.fullmatch(r"([0-9]+)(?:\.0+)?", str(company))
    if not match or isinstance(company, bool) or int(match.group(1)) < 1:
        raise ConfigError("EBMCP_COMPANY must be a positive integer.")
    return int(match.group(1))


def compose_api_base(server_url: str, company) -> str:
    return "%s/api/%s" % (clean_server_url(server_url), _company_number(company))


def read_env_file(path: Path = ENV_FILE) -> dict:
    """KEY=value lines; `#` comments and blank lines skipped; surrounding quotes stripped.
    `utf-8-sig`: Notepad can save the file with a byte order mark, which hid the first key
    (opus review 2026-10-04, M7).

    Plugin mode reads its own settings file whatever `path` says, and only the plugin keys: a
    line such as EBMCP_ALLOW_OPEN or a catalogue address there is ignored."""
    run_mode = mode()
    if run_mode == "plugin":
        return read_plugin_settings()
    if run_mode == "desktop" or not path.exists():
        return {}
    values = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def plugin_settings_file() -> Path:
    return data_dir() / PLUGIN_SETTINGS_NAME


def _plugin_value(raw: str) -> str:
    """A value the writer wrote is a JSON string, so any password round-trips; a value typed by
    hand is read like a `.env` value."""
    value = raw.strip()
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except ValueError:
            decoded = None
        if isinstance(decoded, str):
            return decoded
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


class SettingsUnreadable(ConfigError):
    """The settings file exists but could not be read or decoded just now."""


# The settings file's own bookkeeping, written only by save_plugin_settings and
# forget_plugin_settings (Astra recheck of the settings page, MUST 2, 3 and 5):
# - EBMCP_REVISION: a counter, one higher on every save or Forget, never a content hash. A form
#   drawn at revision N may save only while the file is still at N.
# - EBMCP_WRITES_SINCE / EBMCP_CHAT_SINCE: the revision at which that switch was last turned on.
#   A connector counts a switch as on only while it carries the same SINCE as at its start, so an
#   off -> on after the start (by any process) stays off until the next start. One file, one
#   atomic write: no second file that can disagree with it.
# - EBMCP_FORGOTTEN: Forget's tombstone. The file then holds only the revision and this mark: no
#   login, and the next revision is still higher than every form drawn before.
REVISION_KEY = "EBMCP_REVISION"
WRITES_SINCE_KEY = "EBMCP_WRITES_SINCE"
CHAT_SINCE_KEY = "EBMCP_CHAT_SINCE"
FORGOTTEN_KEY = "EBMCP_FORGOTTEN"
_META_KEYS = (REVISION_KEY, WRITES_SINCE_KEY, CHAT_SINCE_KEY, FORGOTTEN_KEY)


def _plugin_file(*, strict: bool = False) -> tuple:
    """(exists, every plugin and bookkeeping key) from ONE read of <data>/settings.env. A missing
    file is (False, {}); an unreadable one raises SettingsUnreadable when `strict`, else is
    (True, {})."""
    try:
        text = plugin_settings_file().read_bytes().decode("utf-8-sig")
    except FileNotFoundError:
        return False, {}
    except (OSError, ConfigError, UnicodeDecodeError):
        if strict:
            raise SettingsUnreadable("The plugin settings could not be read.") from None
        return True, {}
    values = {}
    # Split on line feeds only: str.splitlines also breaks at characters a password may hold.
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in PLUGIN_KEYS or key in _META_KEYS:
            values[key] = _plugin_value(value)
    return True, values


def _settings_only(values: dict) -> dict:
    return {key: value for key, value in values.items() if key in PLUGIN_KEYS}


def read_plugin_settings(*, strict: bool = False, meta: bool = False) -> dict:
    """The plugin keys of <data>/settings.env. A missing or unreadable file is no settings: the
    tools then answer settings_needed. `strict`: an unreadable file raises SettingsUnreadable
    instead, so a snapshot says "unreadable", never "switched off" (Astra recheck of ddce18b).
    `meta`: the file's bookkeeping too (the switch rule reads it, plugin_switch_on)."""
    values = _plugin_file(strict=strict)[1]
    return values if meta else _settings_only(values)


def plugin_configured() -> bool:
    """Every required plugin setting is in the file and not blank."""
    values = read_plugin_settings()
    return all(values.get(key, "").strip() for key in PLUGIN_REQUIRED)


_PLUGIN_SAVE_LOCK = threading.Lock()
_PLUGIN_LOCK_HELD = threading.local()
_PLUGIN_HEADER = ("# Written by the Excellent Books plugin settings page. Keep this file on this "
                  "computer only.\n")
NO_SETTINGS_VERSION = "0"
_LEGACY_VERSION = "legacy"              # a file written before the counter (or by hand)
_MALFORMED_VERSION = "malformed"        # a counter that is not a number


class StaleSettings(ConfigError):
    """The settings changed after the form that tries to save was loaded."""


class SettingsBusy(ConfigError):
    """Another save of the plugin settings held the lock too long."""


def _revision(values: dict, exists: bool):
    """The file's counter: 0 for no file or a file without one (written before the counter),
    None for a counter that is not a number."""
    if not exists or REVISION_KEY not in values:
        return 0
    raw = values[REVISION_KEY].strip()
    return int(raw) if re.fullmatch(r"[0-9]{1,18}", raw) else None


def _version_of(values: dict, exists: bool) -> str:
    if not exists:
        return NO_SETTINGS_VERSION
    if REVISION_KEY not in values:
        return _LEGACY_VERSION
    revision = _revision(values, exists)
    return _MALFORMED_VERSION if revision is None else str(revision)


def _next_revision(values: dict, exists: bool) -> int:
    revision = _revision(values, exists)
    return (revision if revision is not None else 0) + 1


def plugin_settings_version() -> str:
    """The revision a settings form loads with and hands back to save_plugin_settings: the file's
    counter, NO_SETTINGS_VERSION when there is no file (Astra review of slice 2, MUST 8). Never a
    content hash: a hash repeats when the content does (the same "none" after every Forget, Astra
    recheck of the settings page, MUST 2); the counter only grows, and Forget keeps it."""
    exists, values = _plugin_file(strict=True)
    return _version_of(values, exists)


def read_plugin_state() -> tuple:
    """(settings, revision, forgotten) from ONE strict read: what the settings page draws, the
    revision its form is bound to, and whether the file is Forget's tombstone."""
    exists, values = _plugin_file(strict=True)
    return (_settings_only(values), _version_of(values, exists),
            exists and _said_yes(values.get(FORGOTTEN_KEY)))


@contextmanager
def plugin_settings_locked(*, timeout: float | None = None):
    """Hold the settings lock for the whole block: the lock of this process and the lock file
    the other connector processes share. Re-entrant in one thread, so save_plugin_settings and
    forget_plugin_settings inside the block keep it. The settings page holds it from its stale
    check through the test sign-in and the consent record to the settings write, so no other
    save, Forget or options change lands in between (Astra review of slice 3, MUST 2 and 3).
    `timeout`: seconds to wait for the lock file (None: control's default); SettingsBusy after."""
    from . import control

    if getattr(_PLUGIN_LOCK_HELD, "depth", 0):
        _PLUGIN_LOCK_HELD.depth += 1
        try:
            yield
        finally:
            _PLUGIN_LOCK_HELD.depth -= 1
        return
    target = plugin_settings_file()
    target.parent.mkdir(parents=True, exist_ok=True)
    if not _PLUGIN_SAVE_LOCK.acquire(timeout=-1 if timeout is None else timeout):
        raise SettingsBusy("Another save of the plugin settings is still running.")
    try:
        with target.with_name("settings.lock").open("a+b") as lock:
            if os.fstat(lock.fileno()).st_size == 0:
                lock.write(b"\0")
                lock.flush()
            try:
                control._take_lock(lock, timeout=timeout)
            except OSError:
                raise SettingsBusy("Another save of the plugin settings is still running.") \
                    from None
            _PLUGIN_LOCK_HELD.depth = 1
            try:
                yield
            finally:
                _PLUGIN_LOCK_HELD.depth = 0
                control._release_lock(lock)
    finally:
        _PLUGIN_SAVE_LOCK.release()


# -- the restart boundary of the two switches (Astra review of slice 3, MUST 5; recheck MUST 5) -----
# Writing and chat approval switched OFF count at once; switched ON they count only after the host
# restarts the connector. Both rules read the ONE settings file: at its start a connector keeps,
# from one read, the SINCE revision of every switch that was on. Later a switch counts as on only
# while the file says on with that same SINCE: any off -> on after the start (from any process, seen
# here or not) wrote a newer SINCE, so it stays off until the next start. A start read that failed
# or found a counter that is not a number leaves both switches off for this process only; the next
# start reads the file again. An off this process saw also stays off (the latch below), which
# covers a hand edit that kept the SINCE.
_SWITCHED_OFF_SEEN: dict = {}
_PLUGIN_START: dict = {}
_SINCE_KEYS = {"writes": WRITES_SINCE_KEY, "chat": CHAT_SINCE_KEY}


def _switches_on(values: dict) -> set:
    on = set()
    if _said_yes(values.get(WRITES_KEY, "")):
        on.add("writes")
    if _is_chat(_approval_word(values.get(APPROVE_IN_KEY, "")), "plugin"):
        on.add("chat")
    return on


def _since(values: dict, kind: str, revision):
    """The revision `kind` was turned on at, None when it is off. A file without the SINCE line
    (written before it, or by hand) counts from its own revision. Anything unreadable is a fresh
    object, equal to nothing: off (fail closed)."""
    if kind not in _switches_on(values):
        return None
    raw = values.get(_SINCE_KEYS[kind])
    if raw is None:
        return revision if revision is not None else object()
    raw = raw.strip()
    return int(raw) if re.fullmatch(r"[0-9]{1,18}", raw) else object()


def _start_key():
    try:
        return _approve_in_key()
    except ConfigError:
        return "plugin settings"


def _plugin_start() -> dict:
    """What this connector process read at its start, from ONE read of the settings file: the
    SINCE of each switch, the approval word and the connection. Taken by the first caller (the
    server takes it while it starts: server.WRITES_ON) and kept for the process."""
    key = _start_key()
    start = _PLUGIN_START.get(key)
    if start is None:
        try:
            values = read_plugin_settings(strict=True, meta=True)
        except SettingsUnreadable:
            start = {"valid": False, "writes": None, "chat": None, "word": "", "connection": None}
        else:
            revision = _revision(values, True)
            start = {"valid": revision is not None,
                     "writes": _since(values, "writes", revision),
                     "chat": _since(values, "chat", revision),
                     "word": values.get(APPROVE_IN_KEY, ""),
                     "connection": _plugin_connection(_settings_only(values))}
        _PLUGIN_START[key] = start
    return start


def plugin_switch_on(kind: str, values: dict) -> bool:
    """Whether the plugin's `kind` switch ("writes" or "chat") counts as on in this process, given
    `values`: one read of the settings file with its bookkeeping (_plugin_file)."""
    start = _plugin_start()
    seen = _SWITCHED_OFF_SEEN.setdefault(_start_key(), set())
    if kind in seen:
        return False
    now = _since(values, kind, _revision(values, True))
    if now is None:
        seen.add(kind)
        return False
    begun = start[kind]
    return bool(start["valid"]) and begun is not None and now == begun


def _write_plugin_file(values: dict) -> None:
    """Under the settings lock: the whole file, private from the first byte, then one atomic
    replace. Values are JSON-quoted, so any password round-trips."""
    from uuid import uuid4

    from . import control, setup

    text = _PLUGIN_HEADER + "".join(
        "%s=%s\n" % (key, json.dumps(values[key], ensure_ascii=True))
        for key in PLUGIN_KEYS + _META_KEYS if key in values)
    target = plugin_settings_file()
    temporary = target.with_name(".settings-%s.tmp" % uuid4().hex)
    try:
        fd = setup._open_private(temporary)
        with os.fdopen(fd, "wb") as stream:
            stream.write(text.encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        control._replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def save_plugin_settings(values: dict, *, expected_version: str) -> None:
    """Write <data>/settings.env with exactly these settings (slice 3's settings page calls this).

    Private from the first byte (setup._open_private: owner-only ACL or 0600 on the temporary
    copy, then an atomic replace), one save at a time (plugin_settings_locked), values
    JSON-quoted so any password round-trips. A value with CR, LF or NUL is refused: it could
    start another setting. Refusals never repeat a value. The writer owns the bookkeeping: the
    revision one higher, and each switch that is on keeps its SINCE when it was on before, else
    gets this revision (plugin_switch_on).

    `expected_version` is plugin_settings_version() as the form was loaded. It is compared under
    the lock: when another save came in between, nothing is written (StaleSettings), so an older
    form cannot restore a password or switch writing back on (Astra review of slice 2, MUST 8)."""
    if mode() != "plugin":
        raise ConfigError("Plugin settings are written only in plugin mode.")
    clean = {}
    for key, value in values.items():
        if key not in PLUGIN_KEYS:
            raise ConfigError("That is not a plugin setting.")
        if not isinstance(value, str):
            raise ConfigError("A plugin setting must be text.")
        if any(char in value for char in "\r\n\x00"):
            raise ConfigError("A setting cannot contain a line break or a NUL character.")
        clean[key] = value
    with plugin_settings_locked():
        exists, old = _plugin_file(strict=True)
        if _version_of(old, exists) != expected_version:
            raise StaleSettings("The settings changed since this page was loaded, so nothing "
                                "was saved. Load the page again and repeat the change.")
        revision = _next_revision(old, exists)
        before = _revision(old, exists)
        for kind in _switches_on(clean):
            was = _since(old, kind, before)
            clean[_SINCE_KEYS[kind]] = str(was if isinstance(was, int) else revision)
        clean[REVISION_KEY] = str(revision)
        _write_plugin_file(clean)


def forget_plugin_settings(*, expected_version: str) -> None:
    """Forget the saved login ("Forget saved login" on the settings page): ONE atomic write of a
    tombstone that holds the next revision and the forgotten mark, nothing else (Astra recheck of
    the settings page, MUST 2 and NEW MUST 2). Under the same lock as save_plugin_settings and
    refused the same way (StaleSettings) when the file changed after the page was loaded. Only a
    full new save (typed password, consent) replaces the tombstone."""
    if mode() != "plugin":
        raise ConfigError("Plugin settings are written only in plugin mode.")
    with plugin_settings_locked():
        exists, old = _plugin_file(strict=True)
        if _version_of(old, exists) != expected_version:
            raise StaleSettings("The settings changed since this page was loaded, so nothing "
                                "was removed. Load the page again.")
        _write_plugin_file({REVISION_KEY: str(_next_revision(old, exists)),
                            FORGOTTEN_KEY: "yes"})


# Consent needs an explicit yes, in the org's languages, or the date setup may write. Anything
# else is no: the first rule counted every word but five as yes, "ei" (Estonian no) among them
# (opus review 2026-10-04, I1). A trailing "# comment" is ignored.
CONSENT_YES = frozenset({"yes", "y", "true", "1", "on", "jah", "ja", "kyllä", "jā", "taip"})


def _said_yes(value) -> bool:
    return str(value or "").split("#", 1)[0].strip().lower() in CONSENT_YES


def consent_given(value) -> bool:
    word = str(value or "").split("#", 1)[0].strip().lower()
    return _said_yes(word) or bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", word))


WRITES_KEY = "EBMCP_WRITES"
APPROVE_IN_KEY = "EBMCP_APPROVE_IN"


def writes_enabled(env_file: Path | None = None, *, strict: bool = False) -> bool:
    """The four write tools exist only when this says an explicit yes (Astra's review rec 1,
    Kaupo 2026-10-05: the package ships with writes off). The environment wins, as for every
    other key; a date is not a yes here. `env_file` None is this module's ENV_FILE, read at call
    time, so a test or a moved install can point it elsewhere.

    Hosted mode answers its own switch, EBMCP_HOSTED_WRITES, and never reads EBMCP_WRITES or a
    settings file (hosted writing design, section 9)."""
    if mode() == "hosted":
        from . import hosted
        return hosted.writes_enabled(os.environ)
    if mode() == "plugin":
        # The settings file only (Review change 5): no environment override. An off counts at
        # once, an on only after a restart (plugin_switch_on); a failed read latches nothing. The
        # start read comes first, so a file unreadable at the start is off for this process.
        _plugin_start()
        try:
            values = read_plugin_settings(strict=True, meta=True)
        except SettingsUnreadable:
            if strict:
                raise
            return False
        return plugin_switch_on("writes", values)
    path = ENV_FILE if env_file is None else env_file
    value = os.environ.get(WRITES_KEY) or read_env_file(path).get(WRITES_KEY, "")
    return _said_yes(value)


_APPROVE_IN_FROM_FILE: dict = {}


def remember_approve_in() -> None:
    """Read the settings file's approval setting once, when the server starts (Sol recheck of
    ca80413: a lazy first read let an edit made before the first plan switch chat on)."""
    if mode() == "hosted":
        return                  # hosted reads no settings file and always uses its own page
    key = _approve_in_key()
    if key not in _APPROVE_IN_FROM_FILE:
        if mode() == "plugin":
            # The plugin's one settings file holds every company in turn: the start's choice
            # belongs to the connection saved then (Astra review of slice 2, MUST 3), both from
            # ONE read of the file (Astra recheck, MUST 3): the start read the switches keep too
            # (_plugin_start; Astra recheck of the settings page, MUST 5).
            start = _plugin_start()
            _APPROVE_IN_FROM_FILE[key] = start["word"]
            _APPROVE_IN_CONNECTION[key] = start["connection"]
        else:
            _APPROVE_IN_FROM_FILE[key] = read_env_file(ENV_FILE).get(APPROVE_IN_KEY, "")


_APPROVE_IN_CONNECTION: dict = {}


def _plugin_connection(values: dict | None = None) -> Optional[str]:
    """The connection the plugin settings file names now (or `values`, one read of it), or None
    when it names none. Read without the consent record: only the login identity counts here."""
    values = read_plugin_settings() if values is None else values
    try:
        return connection_id(Config(api_base=plugin_api_base(values),
                                    user=values["EBMCP_USER"], password=""))
    except (KeyError, ConfigError):
        return None


def _approval_word(value) -> str:
    return str(value or "").split("#", 1)[0].strip().lower()


def _approve_in_key():
    """Where the remembered approval setting came from: `.env`, or the plugin settings file."""
    if mode() != "plugin":
        return ENV_FILE
    try:
        return plugin_settings_file()
    except ConfigError:
        return "plugin settings"


def approve_in(env_file: Path | None = None, *, snapshot: "Snapshot | None" = None) -> str:
    """The local approval setting. Desktop's manifest boolean arrives as a string; the plugin's
    settings page may write the same. Plugin mode reads only its settings file. `snapshot`: the
    plugin's word and connection from that one read instead of another (Astra recheck of
    3485c9a, MUST 3); a snapshot that failed or names no connection means browser."""
    run_mode = mode()
    # Hosted ignores the local setting and always uses its own approval page.
    if run_mode == "hosted":
        return "browser"
    value = None if run_mode == "plugin" else os.environ.get(APPROVE_IN_KEY)
    if value is None and env_file is not None:
        value = read_env_file(env_file).get(APPROVE_IN_KEY, "")
    elif value is None:
        # Read once per process (opus review of d341919, SHOULD 2): an AI that can write files
        # but not restart the connector must not switch chat approval on in a running one.
        remember_approve_in()
        key = _approve_in_key()
        value = _APPROVE_IN_FROM_FILE[key]
        if run_mode == "plugin" and _is_chat(_approval_word(value), run_mode):
            # Chat stays on only while the file still says chat for the connection the process
            # started with: switching it off, or to another company, counts at once; switching it
            # on still needs a restart (Astra review of slice 2, MUST 3).
            if snapshot is not None:
                if snapshot.error is not None or snapshot.cfg is None:
                    return "browser"
                chat_on = snapshot.chat_on
                connection = connection_id(snapshot.cfg)
            else:
                current = read_plugin_settings(meta=True)    # one read: switch and connection
                chat_on = plugin_switch_on("chat", current)
                connection = _plugin_connection(_settings_only(current))
            started_with = _APPROVE_IN_CONNECTION.get(key)
            # Off at once; on again only after a restart (plugin_switch_on; Astra review of
            # slice 3, MUST 5, and its recheck).
            if not chat_on or started_with is None or started_with != connection:
                return "browser"
    return "chat" if _is_chat(_approval_word(value), run_mode) else "browser"


def _is_chat(word: str, run_mode: str) -> bool:
    return word == "chat" or (run_mode in ("desktop", "plugin") and word == "true")


GDPR_KEY = "EBMCP_GDPR_CONSENT"
HR_KEY = "EBMCP_HR_CONSENT"
# A missing text ID means the wording in force before text IDs shipped. Keep these fixed.
LEGACY_GDPR_TEXT_ID = "5a5e1185f1088e83"
LEGACY_HR_TEXT_ID = "ea0d9f2ba45ce97b"


def consent_text_id(kind: str) -> str:
    # Imported here: privacy builds its GDPR texts from claims, and claims -> erp_fields -> config
    # would otherwise be a cycle (Task 50).
    from . import privacy

    text = privacy.GDPR_TEXT if kind == "gdpr" else privacy.HR_CONSENT_TEXT
    return sha256(text.encode("utf-8")).hexdigest()[:16]


def local_consent_state(kind: str, values: dict) -> str:
    key, text_key, legacy, accepted = (
        (GDPR_KEY, "EBMCP_GDPR_TEXT", LEGACY_GDPR_TEXT_ID, consent_given)
        if kind == "gdpr" else (HR_KEY, "EBMCP_HR_TEXT", LEGACY_HR_TEXT_ID, _said_yes)
    )
    # A blank decision in the environment falls back to the file, as for every other key (reask
    # review S3); a text id set in the environment wins even when blank (it then proves nothing).
    if not accepted(os.environ.get(key) or values.get(key)):
        return "off"
    text_id = os.environ.get(text_key, values.get(text_key, legacy))
    text_id = str(text_id or "").split("#", 1)[0].strip()   # a hand-added comment (review N1)
    return "given" if text_id == consent_text_id(kind) else "stale"


def local_hr_consent_state(env_file: Path | None = None) -> str:
    path = ENV_FILE if env_file is None else env_file
    return local_consent_state("hr", read_env_file(path))


def hr_enabled(env_file: Path | None = None, *, connection: str | None = None) -> bool:
    """Read the user's HR decision on every call. Desktop records it per Books connection."""
    if mode() == "hosted":
        # Never the process's settings (Task 41 review M1): the person's own tick at sign-in,
        # read from their connection by server._hr_gate (Task 42).
        return False
    if stdio_mode():
        from . import consent

        try:
            if connection is None:
                connection = connection_id(Config.from_env(None))
            return consent.given("hr", connection)
        except (ConfigError, KeyError):
            return False
    return local_hr_consent_state(env_file) == "given"


# Where the report catalogue comes from (ebmcp/remote_catalog.py). Only https:// is fetched; a
# file:// copy is read only with EBMCP_CATALOG_LOCAL=yes, a developer's switch, like EBMCP_WRITES
# an explicit yes (opus review, 2026-10-14). Both read at call time, the environment first.
CATALOG_URL_KEY = "EBMCP_CATALOG_URL"
CATALOG_LOCAL_KEY = "EBMCP_CATALOG_LOCAL"
DEFAULT_CATALOG_URL = "https://knowledge.excellent.ee/books/catalog.json"
CONTROL_URL_KEY = "EBMCP_CONTROL_URL"
DEFAULT_CONTROL_URL = "https://knowledge.excellent.ee/books/control.json"


def _setting(key: str, env_file: Path | None) -> str:
    # Plugin as Desktop: these developer settings come from the environment, never a file.
    if mode() in ("desktop", "hosted", "plugin"):
        return os.environ.get(key, "").strip()
    path = ENV_FILE if env_file is None else env_file
    return (os.environ.get(key) or read_env_file(path).get(key, "")).strip()


def catalog_url(env_file: Path | None = None) -> str:
    return _setting(CATALOG_URL_KEY, env_file) or DEFAULT_CATALOG_URL


def control_url(env_file: Path | None = None) -> str:
    return _setting(CONTROL_URL_KEY, env_file) or DEFAULT_CONTROL_URL


def catalog_local_allowed(env_file: Path | None = None) -> bool:
    return _said_yes(_setting(CATALOG_LOCAL_KEY, env_file))


@dataclass(frozen=True)
class Config:
    api_base: str      # e.g. http://host:port/api/1  — REST base for company 1
    user: str          # what REST authenticates with: a login e-mail on many servers
    password: str = field(repr=False)
    # The UserVc `Code` the report endpoint wants. NOT the same identifier as `user` — see
    # `erp.Session.resolve_usercode`, which looks it up at login. Set EBMCP_USERCODE only to
    # override that lookup; leaving it empty is the normal case.
    usercode: str = ""
    # The customer's GDPR decision (Kaupo, 2026-10-04): personal data reaches their AI only
    # after they accepted the current wording, or ticked the box in Desktop settings.
    gdpr_consent: bool = False
    gdpr_consent_stale: bool = False

    @property
    def company(self) -> int:
        match = re.search(r"/api/([0-9]+)$", urlsplit(self.api_base).path.rstrip("/"))
        if not match:
            raise ConfigError("EBMCP_API_BASE must end with /api/<company>.")
        return _company_number(match.group(1))

    @property
    def origin(self) -> str:
        parts = urlsplit(self.api_base)
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    @property
    def server_root(self) -> str:
        """The ERP's web root, where /WebExcellentAPI.hal lives: api_base without /api/N."""
        return self.api_base.rsplit("/api/", 1)[0]

    @classmethod
    def from_env(cls, env_file: Path | None = ENV_FILE, *,
                 file_values: dict | None = None) -> "Config":
        # Desktop and hosted read the process environment only: a hosted run must never pick up
        # a checkout's .env login (Task 41 review M1). `file_values`: one read of `env_file`
        # already made (read_snapshot), used instead of reading it again.
        run_mode = mode()
        if run_mode == "plugin":
            return cls._from_plugin_settings()
        desktop = run_mode in ("desktop", "hosted")
        if not env_file or desktop:
            from_file = {}
        else:
            from_file = read_env_file(env_file) if file_values is None else file_values

        def setting(name):
            return os.environ.get(name) or from_file.get(name, "")

        values = {name: setting(name) for name in REQUIRED[1:]}
        # Whitespace only is missing too: a blank login would fail much later, inside a plan.
        missing = [name for name, value in values.items() if not value.strip()]
        api_base = "" if run_mode == "desktop" else setting("EBMCP_API_BASE")
        server_url = setting("EBMCP_SERVER_URL")
        if not api_base and not server_url:
            missing.insert(0, "EBMCP_SERVER_URL" if run_mode == "desktop" else REQUIRED[0])
        if missing:
            raise KeyError("missing configuration: %s (looked in the environment and %s)"
                           % (", ".join(missing), env_file))
        if api_base:
            try:
                api_base = _validated_url(api_base).geturl().rstrip("/")
            except ConfigError as exc:
                raise ConfigError("EBMCP_API_BASE: %s" % exc) from None
        else:
            api_base = compose_api_base(server_url, setting("EBMCP_COMPANY") or "1")
        optional = setting("EBMCP_USERCODE")
        if desktop:
            gdpr_consent = _said_yes(setting(GDPR_KEY))
            gdpr_consent_stale = False
        else:
            gdpr_state = local_consent_state("gdpr", from_file)
            gdpr_consent = gdpr_state == "given"
            gdpr_consent_stale = gdpr_state == "stale"
        return cls(api_base=api_base,
                   user=values["EBMCP_USER"], password=values["EBMCP_PASSWORD"],
                   usercode=optional.strip(),
                   gdpr_consent=gdpr_consent, gdpr_consent_stale=gdpr_consent_stale)

    @classmethod
    def _from_plugin_settings(cls, values: dict | None = None) -> "Config":
        """Plugin mode: the settings file only, never the environment (Review change 5). The
        company has no default, the address must be https (Review change 1), and the GDPR
        decision is the record the settings page made for this connection (consent.py).
        `values`: one read of the file already made (read_snapshot)."""
        values = read_plugin_settings() if values is None else values
        missing = [key for key in PLUGIN_REQUIRED if not values.get(key, "").strip()]
        if missing:
            raise KeyError("missing configuration: %s (looked in the plugin settings file)"
                           % ", ".join(missing))
        if _validated_url(values["EBMCP_SERVER_URL"]).scheme != "https":
            raise ConfigError("Server address must use https:// in the Excellent Books plugin.")
        cfg = cls(api_base=plugin_api_base(values),
                  user=values["EBMCP_USER"], password=values["EBMCP_PASSWORD"])
        from . import consent

        state = consent.status("gdpr", connection_id(cfg))
        return replace(cfg, gdpr_consent=state == "given", gdpr_consent_stale=state == "stale")


@dataclass(frozen=True)
class Snapshot:
    """The settings one tool call or one write step decides by, from ONE read (Astra recheck of
    the slice 2 fix, MUST 1 and 2): the connection and the write switch. A read that failed is
    kept as `error`; every reader of this snapshot then refuses, nobody reads again."""
    cfg: Optional[Config]
    writes: bool
    error: Optional[BaseException] = None
    # The plugin's EBMCP_APPROVE_IN word from the same read, and whether chat approval counts as
    # on in this process from that read (plugin_switch_on; approve_in(snapshot=...)).
    approve_word: str = ""
    chat_on: bool = False
    # False when the read failed before the switch was known: "unreadable", not "switched off".
    writes_known: bool = True
    # Local (ZIP) only: the HR decision from the same `.env` read, local_consent_state's word
    # (Astra recheck of ddce18b, MUST 1). "" where the mode keeps it elsewhere.
    hr_state: str = ""


def read_snapshot() -> Snapshot:
    """One read of the settings. The plugin: its file once, for the login, the consent record,
    the write switch and the approval word. Desktop and local: `.env` once for the switch and
    Config.from_env (Desktop's values come from the process, local's from `.env`; Astra recheck
    of 3485c9a, MUST 2). Hosted: as before."""
    # Every reader refuses on a kept failure: never a second read. The switch is kept apart from
    # an incomplete connection, so "writing is off" still answers first where it did before.
    try:
        run_mode = mode()
        plugin = run_mode == "plugin"
        hr_state = ""
        chat_on = False
        if plugin:
            _plugin_start()
            values = read_plugin_settings(strict=True, meta=True)
            writes = plugin_switch_on("writes", values)
            chat_on = plugin_switch_on("chat", values)
            values = _settings_only(values)
        elif run_mode == "hosted":
            values, writes = None, writes_enabled()
        else:
            values = read_env_file(ENV_FILE)
            writes = _said_yes(os.environ.get(WRITES_KEY) or values.get(WRITES_KEY, ""))
            if run_mode == "local":
                hr_state = local_consent_state("hr", values)
    except Exception as exc:
        return Snapshot(None, False, exc, writes_known=False)
    word = values.get(APPROVE_IN_KEY, "") if plugin else ""
    try:
        cfg = (Config._from_plugin_settings(values) if plugin
               else Config.from_env(ENV_FILE, file_values=values))
    except Exception as exc:
        return Snapshot(None, writes, exc, approve_word=word, hr_state=hr_state, chat_on=chat_on)
    return Snapshot(cfg, writes, approve_word=word, hr_state=hr_state, chat_on=chat_on)


def connection_id(cfg: Config, user_code: Optional[str] = None) -> str:
    """Hash the configured login (case-folded: Books logins are case-insensitive, probe S1), or
    the exact Books code a caller resolved. A blank one is refused: it would give every login on
    the company one id (Task 24 review S3)."""
    user = cfg.user.casefold() if user_code is None else user_code
    if not str(user or "").strip():
        raise ConfigError("A connection needs a Books user; none was given.")
    # The server ROOT, path prefix included: two Books servers behind one host are two
    # connections (Sol re-check of c89ea64). Without a prefix it equals the origin, which is
    # also what a configuration object without a server root (a test stand-in) is hashed by.
    # A JSON list, not a joined string: a "|" inside a path prefix or a login cannot move the
    # field boundaries and make two connections hash alike (Sol re-check of a63f0d4).
    identity = json.dumps([getattr(cfg, "server_root", cfg.origin), cfg.company, user],
                          ensure_ascii=False, separators=(",", ":"))
    return sha256(identity.encode("utf-8")).hexdigest()[:16]


def session_connection_id(session) -> str:
    if hasattr(session.cfg, "user"):
        return connection_id(session.cfg)
    # Retain the case-folded fallback for session adapters without a configured login.
    return connection_id(session.cfg, user_code=session.usercode.casefold())
