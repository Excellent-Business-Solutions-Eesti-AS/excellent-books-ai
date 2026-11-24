"""Serve the connector over MCP stdio for the ChatGPT / Codex plugin (EBMCP_MODE=plugin).

Design: docs/superpowers/specs/2026-11-23-chatgpt-codex-plugin-design.md (Review change 5). The
plugin's launcher runs `plugin_main.py` from the plugin folder with stdio inherited. Like Desktop:
stdout carries only the protocol, no HTTP listener. Unlike Desktop: login, company, consent,
writes and the approval choice come only from the plugin's settings file (config.py), never from
the environment.
"""

from contextlib import redirect_stdout
import logging
import os
import sys


# Settings the plugin reads only from its settings file. Dropped from the process too, so no code
# path (or child process) can pick one up from the environment by accident.
_FROM_THE_FILE_ONLY = (
    # EBMCP_PASSWORD ends its line: the release scan reads `"NAME", "x"` as a hard-coded value.
    "EBMCP_SERVER_URL", "EBMCP_COMPANY", "EBMCP_USER", "EBMCP_WRITES", "EBMCP_PASSWORD",
    "EBMCP_APPROVE_IN", "EBMCP_API_BASE", "EBMCP_USERCODE", "EBMCP_GDPR_CONSENT",
    "EBMCP_GDPR_TEXT", "EBMCP_HR_CONSENT", "EBMCP_HR_TEXT",
)


def open_settings_page() -> str:
    """Open the Connect Excellent Books page in the person's own browser and return a status
    word only: "opened", "already_open", "no_browser" or "unavailable". Never a URL, cookie,
    token or form value: those must not enter MCP (Review change 2). The page is served by the
    same loopback page server as the approval window (settings_page.py)."""
    from . import server

    return server._approvals.ask_settings()


def main() -> None:
    # Plugin mode is set before anything imports ebmcp.server, which decides its tools at import.
    os.environ["EBMCP_MODE"] = "plugin"
    for key in _FROM_THE_FILE_ONLY:
        os.environ.pop(key, None)
    from . import auth

    decision, reason = auth.decide_startup(os.environ)
    if decision != "stdio":
        sys.stderr.write("ERROR: %s\n" % reason)
        raise SystemExit(2)
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, force=True)
    from .desktop import _ProtocolStdout

    with redirect_stdout(_ProtocolStdout(sys.stdout, sys.stderr)):
        from . import server

        server.check_unfinished_write_at_startup()
        server.control.load()
        server.control.start_refresh()
        server.remote_catalog.warm()
        server.warm_fields()
        server.warm_register_fields()
        server.mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
