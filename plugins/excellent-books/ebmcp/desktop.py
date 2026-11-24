"""Serve the connector over MCP stdio for a desktop client."""

from contextlib import redirect_stdout
import logging
import os
import sys


# The settings defined by tools/bundle/manifest.template.json. The bundle test checks parity.
MANIFEST_ENV_KEYS = frozenset({
    "EBMCP_MODE", "EBMCP_SERVER_URL", "EBMCP_COMPANY", "EBMCP_USER", "EBMCP_PASSWORD",
    "EBMCP_GDPR_CONSENT", "EBMCP_WRITES", "EBMCP_APPROVE_IN",
})


class _ProtocolStdout:
    """FastMCP uses stdout.buffer for JSON-RPC. Send text diagnostics to stderr."""

    def __init__(self, protocol, diagnostics):
        self.buffer = protocol.buffer
        self._diagnostics = diagnostics

    def __getattr__(self, name):
        return getattr(self._diagnostics, name)


def main() -> None:
    # Claude Desktop leaves an empty setting as its literal ${...} placeholder (P5 row 2).
    for key in MANIFEST_ENV_KEYS:
        value = os.environ.get(key, "")
        if value.startswith("${") and value.endswith("}"):
            del os.environ[key]
    os.environ["EBMCP_MODE"] = "desktop"
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, force=True)
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
