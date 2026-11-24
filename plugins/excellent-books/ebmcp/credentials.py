"""Refusing an argument that carries this connector's own configuration.

The threat is not an attacker. It is a helpful exchange: a person cannot get the connector
working, pastes their `.env` into the chat to ask what is wrong, and the model — being helpful —
forwards it into a tool argument. The value then lands somewhere permanent: the audit log, an
Item's Name, a Contact's comment field, where it is shared with everyone who can read that
record and survives long after the conversation is closed.

**This does not prevent the leak, and saying otherwise would be dishonest.** By the time a tool
argument carries a password, that password is already in the model's context and has already
been sent to the API. The correct response to that is to ROTATE the credential. What this guard
prevents is the second copy, the durable one.

**Scope, deliberately narrow.** It matches values that NAME this connector's configuration keys.
It is not a general password detector. A detector for "a string that looks secret" would refuse
legitimate item names and would still miss any password that looks like an ordinary word, and
this project has already had one control whose written justification outran the data it was
justified by — `vendor` in `audit.FIELDS`, where "a code is not personal data" turned out to be
false against the actual contact codes. A guard that claims less and is true is worth more than
one that claims more and is not.

Same shape as `privacy.is_blocked`: a plain predicate a tool calls before it does anything,
with a refusal that explains itself. Adding a tool that takes free text from the model means
calling `contains_config` in it. That is the whole control; there is no second net.
"""
from __future__ import annotations

import re

# This connector's own configuration keys, including hosted process settings.
# A value naming any of them is configuration, whatever follows the `=`.
CONFIG_KEYS = (
    "EBMCP_API_BASE",
    "EBMCP_SERVER_URL",
    "EBMCP_COMPANY",
    "EBMCP_USER",
    "EBMCP_PASSWORD",
    "EBMCP_PORT",
    "EBMCP_HOST",
    "EBMCP_ALLOW_OPEN",
    "EBMCP_AUDIT_LOG",
    "EBMCP_USAGE_LOG",
    "EBMCP_GDPR_CONSENT",
    "EBMCP_GDPR_TEXT",
    "EBMCP_HR_CONSENT",
    "EBMCP_HR_TEXT",
    "EBMCP_WRITES",
    "EBMCP_APPROVE_IN",
    "EBMCP_USERCODE",
    "EBMCP_CATALOG_URL",
    "EBMCP_CATALOG_LOCAL",
    "EBMCP_MODE",
    "EBMCP_DATA_DIR",
    "EBMCP_CONTROL_URL",
    "EBMCP_ISSUER_URL",
    "EBMCP_HOSTED_ALLOWED_HOSTS",
    "EBMCP_HOSTED_OAUTH_DB",
    "EBMCP_HOSTED_REDIRECTS",
    "EBMCP_HOSTED_LOG_SERVERS",
    "EBMCP_HOSTED_DEV",
    "OIDC_TENANT_ID",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "OIDC_REDIRECT_URI",
    "OAUTH_DB_PATH",
    "OAUTH_ACCESS_TOKEN_TTL",
    "OAUTH_REFRESH_TOKEN_TTL",
    "OAUTH_MAX_SESSION_DAYS",
)

# `KEY` followed by `=`, with whatever spacing a paste happens to carry. The `=` is what makes
# it an assignment rather than a mention: "EBMCP_PASSWORD" written in a sentence asking how to
# set it is not a credential, and refusing that would make the connector useless for support.
_ASSIGNMENT = re.compile(r"\b(%s)\s*=" % "|".join(CONFIG_KEYS), re.IGNORECASE)


def looks_like_config(value) -> bool:
    """Does this string assign one of this connector's configuration keys?"""
    if not isinstance(value, str) or not value:
        return False
    return bool(_ASSIGNMENT.search(value))


def contains_config(payload) -> bool:
    """The same question of a whole argument — a list of rows, a dict of fields, nested.

    Tools here take shapes, not strings: `create_items` takes a list of dicts, and
    `plan_goods_receipt` takes rows with a description each. A guard reading only top-level
    strings would miss every realistic paste.
    """
    if isinstance(payload, str):
        return looks_like_config(payload)
    if isinstance(payload, dict):
        return any(contains_config(k) or contains_config(v) for k, v in payload.items())
    if isinstance(payload, (list, tuple, set)):
        return any(contains_config(item) for item in payload)
    return False


_REFUSED = ("%s was given a value that assigns one of this connector's configuration keys, so it "
            "was refused before anything was written. ")
# Per package (Task 51): a Desktop user has no `.env` or terminal; a hosted user signs in on the
# connector's own page and has neither.
_WHERE = {
    "local": ("Configuration belongs only in the `.env` file beside the connector, never in a "
              "tool argument and never in the conversation. If a password has been pasted into "
              "this chat, deleting the message is not enough — rotate it. To set the connector up "
              "without typing a password into a chat window at all, the person can run "
              "`python -m ebmcp.setup` in their own terminal."),
    "desktop": ("Configuration belongs only in Claude Desktop > Settings > Extensions > Excellent "
                "Books, never in a tool argument and never in the conversation. If a password has "
                "been pasted into this chat, deleting the message is not enough — rotate it in "
                "Excellent Books and enter the new one in those settings."),
    "plugin": ("The connection settings belong only on this connector's Connect Excellent Books "
               "page on the person's computer (they ask for Excellent Books settings, or you call "
               "open_settings), never in a tool argument and never in the conversation. If a "
               "password has been pasted into this chat, deleting the message is not enough — "
               "rotate it in Excellent Books and enter the new one on that page."),
    "hosted": ("The Books user and password are typed only on this connector's Excellent Books "
               "sign-in page, never in a tool argument and never in the conversation; never ask "
               "for the password in the chat. If a password has been pasted into this chat, "
               "deleting the message is not enough — rotate it in Excellent Books, then sign in "
               "again with the new one: disconnect and connect this connector again in the AI "
               "client."),
}
# No package's steps when the mode cannot be told (Task 51 review SHOULD 3).
_NEUTRAL = ("Keep connector credentials out of tool arguments and chat. Rotate any password "
            "already pasted into chat.")


def refusal(tool: str, mode: str | None = None) -> dict:
    """Why it was refused, without repeating what was refused.

    The refusal is read by a model that will relay it to a person. Echoing the argument back
    would copy the credential into the answer — the exact thing being prevented — and from
    there into whatever the person forwards next. `mode` None is the process's run mode; an
    unknown or unreadable mode gets the neutral copy.
    """
    if mode is None:
        from . import config
        try:
            mode = config.mode()
        except config.ConfigError:
            mode = None
    return {"error": "looks_like_configuration",
            "why": _REFUSED % tool + _WHERE.get(mode, _NEUTRAL)}
