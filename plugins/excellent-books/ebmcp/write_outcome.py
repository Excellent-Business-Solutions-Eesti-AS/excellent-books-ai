"""What a write's outcome is: one set of rules under every executor (changes.py, receipts.py for
receipts and items, contacts.py).

Settled in the Task 6-9 reviews and their re-check (2026-11-17):

- A write stopped before any HTTP (`erp.NotSent`: the gate refused it, or the login before it
  failed) is `not_attempted`. Any other failure while sending is a lost reply, `unverified`: it
  may have landed, so it is never "not created".
- A read whose answer cannot be trusted - no reply, an HTTP error, or an HTTP 200 with an error
  or an empty result outside a Books data document - is `ReadFailed`. It cannot establish absence,
  a free code or zero stock. An unread read-back makes its writes `unverified`.
- A create is ours only when the read-back shows its code AND its name. Books answers HTTP 200
  "Already registered" for a code that exists, stores nothing and echoes the rejected values
  (measured on CUVc), so neither the reply nor the code alone proves it.
- Every planned write ends in exactly one bucket (`Outcomes`), keyed by its place in the
  approved envelope, so two roles on one contact never merge into one result.
"""
from __future__ import annotations

import re
from typing import Optional
from xml.etree import ElementTree

from . import erp

NOT_ATTEMPTED = "not_attempted"
UNVERIFIED = "unverified"
CREATED = "created"
ABSENT = "absent"
# Books refused the write and said so, saving nothing (changes.py: a create whose every bound
# variant was refused on the same field, write_outcome.refused_on).
REFUSED = "refused"

NOT_SENT = "The approval did not cover this write, so nothing was sent. Plan it again."
NOT_LOGGED_IN = ("Excellent Books could not be logged in to before this write, so nothing was "
                 "sent. Try again.")

# Meanings and next steps from docs/2026-11-16-write-recipes.md. Several codes are Books' general
# messages (1053 "Enter date", 1142 "wrong date", 1010 "Account missing"), so the measured
# meaning is keyed by (code, field) and any other field gets the code's general sentence, with
# the field named when Books names one (Task 22 gate, opus C SF3 and N6). 1120 ("code not in
# use") stays unlisted: Kaupo 2026-11-18, not measured as a write refusal sentence.
# 1985 (Task 22 gate, opus C SF5): an OK posts stock value and cannot be undone here, and the
# earlier receipts may wait for someone else's prices; the count of them is left out on purpose.
# Sol re-check (SF5 PARTLY): OKing them through the connector is not offered at all; they can be
# someone else's receipts waiting for prices.
_CHRONOLOGY = ("Books keeps stock in date order: earlier goods receipts are waiting for OK. "
               "Check and confirm them in Excellent Books: they may be waiting for prices or an "
               "invoice, and an OK cannot be undone through this connector.")
BOOKS_REFUSALS = {
    "1985": _CHRONOLOGY,
    "1256": "Books needs a payment term. Choose one for this document.",
    "1125": "Books needs a customer code. Choose the customer for this document.",
    "1010": "Books says an account is missing. Enter the account it asks for.",
    "1053": "Books needs a date that is missing. Enter the date Books asks for.",
    "1557": ("Books needs a document number from a series that covers this date. Check the "
             "series in Books and choose a number from it."),
    "1142": "Books did not accept a date. Check the dates of this document.",
    "1202": "Books needs the payment ordered before it can be reconciled. Order it first.",
    "1102": "Books refused this change to a confirmed record. Check in Books how to correct it.",
}
# With the field Books names: the measured meaning on its own field, else the general one.
FIELD_REFUSALS = {
    ("1010", "AccNumber"): "A line is missing an account. Enter the account on that line.",
    ("1053", "PayDate"): "Books needs the payment date. Enter the date of the payment.",
    ("1142", "ValidUntilDate"): ("Books did not accept the valid-until date. Set the date on the "
                                 "quotation in Books."),
    ("1102", "OKFlag"): ("Books refused to undo the confirmation. Check in Books how to correct "
                         "the record."),
}
# A line's meaning only when Books names the row (Sol re-check, SF3 PARTLY; measured:
# `<error code='1010' row='0' field='AccNumber'/>`); without one the field is named instead.
LINE_REFUSALS = {("1010", "AccNumber")}
NAMED_FIELD = {"1010": "Books needs an account in %s. Enter that account.",
               "1053": "Books needs a date in %s. Enter that date.",
               "1142": "Books did not accept the date in %s. Check that date."}
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,40}$")


# A write the user's access rights refuse (Task 21; docs/probes/2026-11-P1-P2.md). Measured on
# pkorea 2026-11-18: a purchase invoice POSTed by a user whose access group has that module off
# answered HTTP 401 with an EMPTY body, again after a fresh login, and the server log shows it
# was never processed; a read refused by rights answers 405 with one `<error description=...>`
# element and nothing else.
# Decided (Kaupo 2026-11-18, Task 22 gate, Sol MUST and SHOULD): an empty 401 cannot prove that
# nothing was saved (an expired session or a proxy answers the same), so it stays `unverified`
# with ACCESS_UNCLEAR. Only a 403/405 whose whole body is one <error> whose description says "not
# allowed" (any case, at most ACCESS_TEXT_MAX characters) is `refused`, and only that description
# is passed on: no other error text is copied into the result.
ACCESS_REFUSED = ("Excellent Books refused this: your user's access rights do not allow it. "
                  "Nothing was saved.")
ACCESS_UNCLEAR = ("Excellent Books answered with an access error (HTTP 401, no text), so usually "
                  "your user's rights do not allow this. Whether anything was saved is not "
                  "known: check in Excellent Books before trying again.")
ACCESS_TEXT_MAX = 200
_ACCESS_ERROR = re.compile(r"\s*<error description='([^'<>]+)'>\s*</error>\s*")


def _text(body) -> str:
    return body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else (body or "")


# Books' measured denials are a few plain words ("the resource api is not allowed"). Anything
# else in the description (a digit, `=`, `-`, `/`, a word long enough to be a token) could be an
# echoed secret, and the outcome is stored for the approval page: the refusal then stands in our
# fixed words only (Phase 0 gate, parked privacy SHOULD 2).
_PLAIN_WORDS = re.compile(r"[^\W\d_]{1,12}(?:[ ,.:;']+[^\W\d_]{1,12})*[.!]?")


def access_refusal(status: int, body) -> Optional[list]:
    """Books' words (`erp_said`) when the reply is the allowlisted access refusal, else None.
    An empty list: the refusal, with words that are not passed on."""
    found = _ACCESS_ERROR.fullmatch(_text(body)) if status in (403, 405) else None
    if not found:
        return None
    description = erp.unescape(found.group(1))
    if "not allowed" not in description.casefold() or len(description) > ACCESS_TEXT_MAX:
        return None
    if erp.withholds_books_wording():
        # Hosted, Desktop and the plugin: the same code/field/row-only rule as every other Books reply (Sol re-check of
        # eadb7c1, B3); plain words can still name a user or echo a session.
        return erp.reply_problems(body)
    if not _PLAIN_WORDS.fullmatch(description.strip()):
        return []
    return [{"description": description}]


def access_unclear(status: int, body) -> bool:
    """An empty HTTP 401 on a write: usually the user's rights, never proof of nothing saved."""
    return status == 401 and not _text(body).strip()


class ReadFailed(erp.ErpError):
    """A read whose answer cannot be trusted; its text says why (HTTP status or the ERP error)."""


def send_failure(exc: BaseException) -> str:
    """The outcome of an exception raised while sending one approved write."""
    return NOT_ATTEMPTED if isinstance(exc, erp.NotSent) else UNVERIFIED


def connection_loss(exc: erp.WriteConnectionLost) -> dict:
    return {"why": str(exc), "books_answering": exc.books_answering}


# Per record: in a batch an earlier record may have been sent (Sol review of 0ab49a7, MUST).
REST_API_OFF = erp.REST_API_NOT_ALLOWED + " This was not sent."


def before_write_why(exc: BaseException, default: str) -> str:
    """What to say when a read BEFORE a write failed: the user's missing REST API right in its
    own words (a cached session logged in again; Phase 0 gate item 4), else `default`."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, erp.RestApiNotAllowed):
            return REST_API_OFF
        seen.add(id(exc))
        exc = exc.__cause__        # explicit chains only: never an unrelated earlier error
    return default


def not_sent_why(exc: BaseException) -> str:
    """What to tell the person about a write that was `not_attempted`."""
    if isinstance(exc, erp.UnapprovedWrite):
        return NOT_SENT
    if isinstance(exc, erp.WritePolicyRefused):
        return str(exc)
    if isinstance(exc.__cause__, erp.RestApiNotAllowed):
        return str(exc)            # the REST API is off for this user (Task 22 gate round 2)
    return NOT_LOGGED_IN


HOSTED_SAID = ("erp_said holds only Books' error codes and field names, not its wording: open "
               "the record in Excellent Books, or enter it there, to read Books' own message.")


def said_note(local: str, hosted_extra: str = "") -> str:
    """A note's sentence about erp_said. Hosted withholds Books' wording (erp.WITHHELD), so it
    must not claim erp_said explains what to fill in (Sol re-check of eadb7c1, SHOULD)."""
    return HOSTED_SAID + hosted_extra if erp.withholds_books_wording() else local


def refusal_explanations(problems: list) -> dict:
    """Optional result field to show beside the original Books reply."""
    explanations = {}
    for problem in problems:
        code = problem.get("error")
        if code not in BOOKS_REFUSALS:
            continue
        field = str(problem.get("field") or "")
        field = field if _FIELD_NAME.match(field) else ""
        measured = FIELD_REFUSALS.get((code, field))
        if (code, field) in LINE_REFUSALS and not str(problem.get("row") or "").strip():
            measured = None
        sentence = measured or (
            NAMED_FIELD[code] % field if field and code in NAMED_FIELD else BOOKS_REFUSALS[code])
        if sentence not in explanations.get(code, ""):
            explanations[code] = ("%s %s" % (explanations[code], sentence)
                                  if code in explanations else sentence)
    return {"erp_explanations": explanations} if explanations else {}


def has_data_root(body) -> bool:
    """Only a complete Books data document can establish absence on a read."""
    try:
        return ElementTree.fromstring(body).tag == "data"
    except (ElementTree.ParseError, LookupError, ValueError):
        return False


def checked_records(response, register: str, lines: bool = False) -> list:
    """The records of a REST read, or ReadFailed.

    `lines=False`: `erp.list_records` (header fields); `lines=True`: `erp.records_with_lines`.
    An HTTP 200 whose body says `<error>` or `<message>` and holds no record of `register` is an
    ERP refusal, not an empty answer (changes._read_whole measured the shape first).
    """
    if response is None:
        raise ReadFailed("no reply")
    status = getattr(response, "status", 200)
    if status != 200:
        raise ReadFailed("HTTP %s" % status)
    body = getattr(response, "body", b"") or b""
    records = (erp.records_with_lines(body, register) if lines
               else erp.list_records(body, register))
    if not records:
        problems = erp.reply_problems(body)
        if problems:
            raise ReadFailed("Excellent Books answered with an error: %s" % problems)
        if not has_data_root(body):
            raise ReadFailed("Excellent Books did not return a data document.")
    return records


# The measured refusal, as an ALLOWLIST (Sol re-check 2026-11-18: a deny-list missed a record url
# on a message, a "saved" text, a url in the declaration). Anything outside it is no refusal.
_DECLARATIONS = ("<?xml version='1.0' encoding='UTF-8' standalone='yes'?>", "<?xml version='1.0'?>")
_ATTRIBUTES = r"""(?:\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:'[^'<>&]*'|"[^"<>&]*"))*"""
# One refusal element, complete: <message .../> or <message ...></message> with nothing inside.
_REFUSAL = re.compile(r"\s*<(message|error)(%s)\s*(?:/>|>\s*</\1\s*>)" % _ATTRIBUTES)
_WRAPPER = re.compile(r"\s*<data\s*>")
_WRAPPER_END = re.compile(r"\s*</data\s*>")
_ATTRIBUTE = re.compile(r"""([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^']*)'|"([^"]*)")""")
# The texts Books gives with this refusal, by the API user's language (measured: en, et). Another
# language is no refusal: the chain stops at the first form, never guesses.
REFUSAL_TEXTS = {"Erroneous date", "Vale kuupäev"}


def refused_on(status, reply, code: str, field: str, update: bool = False) -> bool:
    """True only for the measured refusal of `field` with error `code`, nothing saved: HTTP status
    exactly 200, a strict UTF-8 reply that is one of the measured XML declarations (or none), then
    at most one <message> whose only attribute is `description` with a known refusal text, then
    one or more <error> elements whose attributes are only `code` = code, `field` = field and an
    empty `description`, and nothing else: no record, no url, no entity, no namespace, no text.
    `update`: a PATCH answers the same inside a bare <data> (QTVc 83, 2026-11-18); a create never.
    Decides whether a create's next bound variant may be sent (changes.py, QTVc ValidUntilDate
    1142; write recipes section 1, decided 2026-11-18; Sol review and re-check 2026-11-18)."""
    if status != 200:
        return False
    if isinstance(reply, (bytes, bytearray)):
        try:
            text = bytes(reply).decode("utf-8")
        except UnicodeDecodeError:
            return False
    else:
        text = str(reply or "")
    position = 0
    stripped = text.lstrip()
    for declaration in _DECLARATIONS:
        if stripped.startswith(declaration):
            position = len(text) - len(stripped) + len(declaration)
            break
    else:
        if stripped.startswith("<?"):
            return False
    wrapper = _WRAPPER.match(text, position) if update else None
    if wrapper:
        position = wrapper.end()
    messages = errors = 0
    while True:
        element = _REFUSAL.match(text, position)
        if not element:
            break
        found = _ATTRIBUTE.findall(element.group(2))
        attributes = {name: single or double for name, single, double in found}
        if len(attributes) != len(found):
            return False                                 # a repeated attribute
        if element.group(1) == "message":
            if (errors or messages or set(attributes) != {"description"}
                    or attributes["description"] not in REFUSAL_TEXTS):
                return False
            messages += 1
        else:
            if (not {"code", "field"} <= set(attributes) <= {"code", "field", "description"}
                    or attributes.get("description", "") != ""
                    or (attributes["code"], attributes["field"]) != (code, field)):
                return False
            errors += 1
        position = element.end()
    if wrapper:
        closing = _WRAPPER_END.match(text, position)
        if not closing:
            return False
        position = closing.end()
    return errors > 0 and not text[position:].strip()


def _clean(value) -> str:
    return str(value or "").strip()


def judge_create(stored: Optional[dict], code: str, name: Optional[str],
                 code_field: str = "Code", name_field: str = "Name") -> tuple:
    """(CREATED | ABSENT | UNVERIFIED, the name stored under that code or None).

    `stored` is the record the read-back found for `code`, or None when a read that worked found
    nothing. `name=None` means the create named no name (a register without one): the code alone
    decides. A different stored code or name is UNVERIFIED: another user's record, or ours
    renamed, cannot be told apart, and calling it created invites nobody to look."""
    if stored is None:
        return ABSENT, None
    if _clean(stored.get(code_field)) != _clean(code):
        return UNVERIFIED, _clean(stored.get(name_field)) or None
    if name is not None and _clean(stored.get(name_field)) != _clean(name):
        return UNVERIFIED, _clean(stored.get(name_field))
    return CREATED, None


class Outcomes:
    """Each planned write in exactly one bucket.

    `put(key, bucket, entry)` places it; a second `put` for the same key MOVES it (a lost reply
    first held as unverified, then decided by the read-back). Keys are the write's place in the
    envelope, or ("plan", n) for what was refused before the plan was issued; the lists keep the
    order of each key's first `put`."""

    def __init__(self, buckets):
        self.buckets = tuple(buckets)
        self._at = {}

    def put(self, key, bucket: str, entry: dict) -> None:
        if bucket not in self.buckets:
            raise ValueError("unknown bucket %r" % bucket)
        self._at[key] = (bucket, entry)

    def bucket(self, key) -> Optional[str]:
        found = self._at.get(key)
        return found[0] if found else None

    def keys(self, bucket: str) -> list:
        return [key for key, (where, _) in self._at.items() if where == bucket]

    def lists(self) -> dict:
        out = {bucket: [] for bucket in self.buckets}
        for where, entry in self._at.values():
            out[where].append(entry)
        return out


def batch_audit_outcome(lists: dict, sent: bool, ok=(CREATED,),
                        failed=("not_found_after_create",)) -> str:
    """One audit word for a batch: `unverified` before anything else; nothing sent is `stopped`
    (something left unattempted) or `refused`; then `failed` when a bucket in `failed` holds
    anything, `ok` when one in `ok` does."""
    if lists.get(UNVERIFIED):
        return UNVERIFIED
    if not sent:
        return "stopped" if lists.get(NOT_ATTEMPTED) else "refused"
    if any(lists.get(bucket) for bucket in failed):
        return "failed"
    return "ok" if any(lists.get(bucket) for bucket in ok) else "failed"
