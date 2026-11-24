"""Local recovery evidence for a plan that may have reached Books."""

from dataclasses import dataclass
from datetime import datetime, timezone
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

from . import config


CHECK_IN_BOOKS = ("Tell the person that an earlier write may not have finished and they must "
                  "check it in Excellent Books before approving another change.")


@dataclass(frozen=True)
class Marker:
    token: str
    description: str = ""
    registers: tuple[str, ...] = ()
    local_time: str = ""
    kind: str = ""
    count: int = 0


class WriteInProgress(OSError):
    """The connection lock is held by another writer."""


def _path(connection: str) -> Path:
    return config.data_dir() / f"unfinished-write-{connection}.json"


def _read(path: Path, connection: str) -> Marker | None:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        return Marker("unreadable")
    token = sha256(raw).hexdigest()
    try:
        data = json.loads(raw)
        stamp = datetime.fromisoformat(data["started_at"])
        registers = data["registers"]
        description, kind, count = "", "", 0
        if "description" in data:
            description = data["description"]
            if not (isinstance(description, str) and description and description.isprintable()):
                return Marker(token)
        else:
            kind, count = data["kind"], data["count"]
            if not (isinstance(kind, str) and type(count) is int and count > 0):
                return Marker(token)
        if (data["connection"] == connection and stamp.utcoffset() is not None
                and isinstance(registers, list) and registers
                and all(isinstance(register, str) and register and register.isprintable()
                        for register in registers)):
            return Marker(token, description, tuple(registers),
                          stamp.astimezone().isoformat(sep=" ", timespec="minutes"), kind, count)
    except (ValueError, TypeError, KeyError, OverflowError, OSError, RecursionError):
        pass
    return Marker(token)


def read(connection: str) -> Marker | None:
    try:
        return _read(_path(connection), connection)
    except (OSError, config.ConfigError):
        return Marker("unreadable")


def _lock(path: Path):
    from . import control

    # Keep the lock file in place so both processes lock the same file.
    stream = path.with_suffix(".lock").open("a+b")
    try:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(bytes(1))
            stream.flush()
        # Never wait for a writer while the caller holds the approval store lock.
        try:
            control._take_lock(stream, timeout=0)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                raise WriteInProgress() from exc
            raise
    except BaseException:
        stream.close()
        raise
    return stream


def release_lock(stream):
    from . import control

    try:
        control._release_lock(stream)
    finally:
        stream.close()


def acknowledge(connection: str, token: str | None) -> bool:
    """Clear only the marker shown on that page, and only once the earlier writer is done."""
    marker = read(connection)
    if marker is None:
        return True
    if token != marker.token:
        return False
    path = _path(connection)
    lock = _lock(path)
    try:
        marker = _read(path, connection)
        if marker is None:
            return True
        if token != marker.token:
            return False
        path.unlink()
    finally:
        release_lock(lock)
    return True


def _save(path: Path, data: dict) -> None:
    from . import control

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".unfinished-write-",
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(data).encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        control._replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def begin(plan, cfg):
    """Persist before dispatch and hold the connection lock through the plan's read-back."""
    from .erp import WritePolicyRefused, rest_register

    connection = plan.payload["connection"]
    if cfg is None or config.connection_id(cfg) != connection:
        raise WritePolicyRefused("The Books connection changed before dispatch. Nothing was sent.")
    path = _path(connection)
    lock = _lock(path)
    try:
        if _read(path, connection) is not None:
            raise WritePolicyRefused("An earlier write may not have finished. Check it in "
                                     "Excellent Books before approving another change.")
        registers = sorted({rest_register(write[1], cfg.api_base) for write in plan.envelope.writes}
                           - {None})
        envelope = plan.envelope
        count = len(plan.payload["lines"]) if envelope.kind == "goods_receipt" else len(envelope.writes)
        _save(path, {"connection": connection, "registers": registers,
                     "server": envelope.server, "company": envelope.company,
                     "books_user": envelope.books_user, "kind": envelope.kind, "count": count,
                     "started_at": datetime.now(timezone.utc).isoformat()})
    except BaseException:
        release_lock(lock)
        raise
    return path, lock


def verified(plan, outcome: dict) -> bool:
    if (outcome.get("write_suspension_reason") or outcome.get("unverified")
            or outcome.get("not_found_after_create") or outcome.get("posted") == "unverified"):
        return False
    status = outcome.get("status")
    if status is not None:
        # A record-change refusal returned after take_next is not a pre-dispatch refusal.
        return status in ("created", "updated", "not_saved", "not_attempted")
    if plan.envelope.kind == "goods_receipt":
        return bool(outcome.get("document")) and isinstance(outcome.get("posted"), bool)
    # These are read-back buckets (including roles and partially saved contact fields),
    # or records refused before dispatch. Subtract the preview's own refusals.
    if plan.envelope.kind in ("items", "contacts"):
        buckets = ("created", "refused", "not_attempted", "roles_added", "flags_not_set")
        accounted = sum(len(outcome.get(bucket, ())) for bucket in buckets)
        return accounted == len(plan.envelope.writes) + len(plan.payload.get("refused", ()))
    return False
