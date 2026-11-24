"""Create and verify the signed digests of downloadable release artifacts."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from . import control

SIGNED_PREFIX = b"excellent-books-release/1:"


def _file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(version: str, built_from: str, files: dict) -> dict:
    """Hash paths keyed by artifact name, e.g. 'mcpb' and 'zip' for the control file."""
    body = {"version": version, "built_from": built_from,
            "files": {name: _file_hash(Path(path)) for name, path in files.items()}}
    _validate_record(body)
    return body


def _validate_record(body: dict) -> None:
    if not isinstance(body, dict):
        raise ValueError("expected a release record")
    if not (control._sentence(body.get("version")) and control._sentence(body.get("built_from"))):
        raise ValueError("expected a release version and build commit")
    files = body.get("files")
    if not isinstance(files, dict) or not files or not all(
            control._sentence(name) and control._sha(digest) for name, digest in files.items()):
        raise ValueError("expected artifact names and SHA-256 digests")


def sign(body: dict, private_key, key_id: str) -> dict:
    """Return a signed copy of the release record."""
    _validate_record(body)
    return control.sign(body, private_key, key_id, prefix=SIGNED_PREFIX)


def verify(body: dict) -> dict:
    """Return the authenticated record or raise ValueError."""
    _validate_record(body)
    try:
        content = control.canonical(body)
    except (ValueError, TypeError, RecursionError):
        raise ValueError("invalid release JSON") from None
    control._check_signature(body, content, prefix=SIGNED_PREFIX)
    return body


def agrees_with_control(record: dict, policy) -> None:
    """Raise ValueError unless the SIGNED record and the control file agree: the control file
    lists this version, and every digest it lists is in the record with the same value (the
    publish step's machine check; review S2, Sol re-check of 3e20ca0)."""
    record = verify(record)
    listed = getattr(policy, "releases", {}).get(record["version"])
    if not listed:
        raise ValueError("the control file does not list release %s" % record["version"])
    if any(record["files"].get(name) != digest for name, digest in listed.items()):
        raise ValueError("the control file and the release record disagree")


def read_record(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=control._unique_pairs)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check"])
    parser.add_argument("file", type=Path)
    parser.add_argument("record", type=Path)
    parser.add_argument("--version", help="fail unless the record is this release")
    args = parser.parse_args(argv)
    try:
        verified = verify(read_record(args.record))
        if args.version is not None and verified["version"] != args.version:
            raise ValueError("the record is release %s, not %s" % (verified["version"], args.version))
        files = verified["files"]
        expected = files.get(args.file.name, files.get(args.file.suffix[1:].lower()))
        if expected is None:
            raise ValueError("the artifact is missing from the release record")
        if expected != _file_hash(args.file):
            raise ValueError("SHA-256 does not match the release record")
    except (OSError, ValueError, RecursionError) as error:
        print(f"Release check failed: {error}", file=sys.stderr)
        return 1
    # Name the release: an old, validly signed record must not pass as the current one (S1).
    print("OK: %s matches release %s (built from %s)"
          % (args.file.name, verified["version"], verified["built_from"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
