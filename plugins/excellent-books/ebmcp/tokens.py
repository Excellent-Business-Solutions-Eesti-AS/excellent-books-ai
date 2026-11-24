"""Admin CLI for personal API tokens.

    py -m ebmcp.tokens mint --for someone@excellent.ee [--label laptop] [--days 90]
    py -m ebmcp.tokens list
    py -m ebmcp.tokens revoke <token-hash-prefix>

Tokens are for clients that cannot do the OAuth flow. They are minted by an admin on the
server, never self-service, and the raw value is printed once because only its hash is stored.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys

from .auth import OAuthStore

DEFAULT_DB = "/data/oauth.db"


def _when(ts) -> str:
    """A date, or the raw stamp when it is not one. `list` is the tool an admin reaches for when
    something is already wrong; it must not be the thing that crashes. A far-future `expires_at`
    (`--days 400000`) is outside what `localtime` accepts on Windows."""
    if not ts:
        return "-"
    try:
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return str(ts)


def main(argv: list | None = None) -> int:
    # Resolved per call, not at import: a module-level os.environ read freezes the path at the
    # first import and makes the CLI ignore an OAUTH_DB_PATH exported after it.
    default_db = os.environ.get("OAUTH_DB_PATH") or DEFAULT_DB

    parser = argparse.ArgumentParser(prog="ebmcp.tokens")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # --db is declared on EACH subparser, never on the parent: argparse only accepts a parent
    # option BEFORE the subcommand, and every caller writes `... revoke <prefix> --db <path>`.
    m = sub.add_parser("mint")
    m.add_argument("--for", dest="subject", required=True)
    m.add_argument("--label", default="")
    m.add_argument("--days", type=int, default=90)
    m.add_argument("--db", default=default_db)

    ls = sub.add_parser("list")
    ls.add_argument("--db", default=default_db)

    r = sub.add_parser("revoke")
    r.add_argument("prefix")
    r.add_argument("--db", default=default_db)

    args = parser.parse_args(argv)
    store = OAuthStore(args.db)

    if args.cmd == "mint":
        token = store.mint_api_token(args.subject, args.label, args.days)
        print("Token for %s (valid %d days). It is shown ONCE and cannot be recovered:\n\n  %s\n"
              % (args.subject, args.days, token))
        return 0

    if args.cmd == "list":
        rows = store.list_api_tokens()
        if not rows:
            print("no tokens")
            return 0
        print("%-10s %-32s %-12s %-10s %-10s" % ("HASH", "SUBJECT", "LABEL", "EXPIRES", "REVOKED"))
        for row in rows:
            print("%-10s %-32s %-12s %-10s %-10s"
                  % (row["token_hash"][:8], row["subject"], row["label"] or "-",
                     _when(row["expires_at"]), _when(row["revoked_at"])))
        return 0

    # A prefix under 4 characters is refused by the store itself, before any SQL runs. It
    # surfaces here through this same path: nothing was revoked, so it is the same answer.
    if store.revoke_api_token(args.prefix):
        print("revoked")
        return 0
    print("no live token with hash prefix %r" % args.prefix, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
