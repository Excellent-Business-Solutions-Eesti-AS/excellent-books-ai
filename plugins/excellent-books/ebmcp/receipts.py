"""Taking goods into stock — a Goods Receipt (`PUVc`), created already OK'd.

This is the first thing this server writes, and the rules below are not style choices. Each one
is a create that failed on `pkorea:4455` on 2026-09-16, or — worse — one that succeeded while
telling us it had failed. The design is in
`docs/superpowers/specs/2026-09-16-goods-receipt-write-design.md`.

**The reply body is a running commentary, not a verdict.** The ERP applies `set_field.`
parameters in the order they arrive and emits a message for each intermediate invalid state, so
a create can come back carrying `May not be blank`, `This item code is not registered` and
`error code=1058 field='Location'` and still have produced a correct record that moved stock by
exactly the quantity sent. That is measured, not theorised. Nothing in this module reads success
out of a response body; `execute_receipt` finds the correlated receipt and checks its lines.
`ItemStatusVc` before and after is supporting evidence only.

**`POST /<register>/<SerNr>` does not update that record — it creates another one.** Measured:
posting `OKFlag=1` to `/PUVc/544118975` created `544118976`, an empty OK'd receipt that is still
on the demo database. So the receipt is built complete and created OK'd in a single call.

**`PATCH` is the update verb** (Kaupo's suggestion, verified 2026-09-16): `PATCH /INVc/9906` with
`set_field.Name` renamed that record in place — 161 items before and 161 after, the reply's own
`url` still `/api/1/INVc/9906`. An earlier version of this docstring said there was no way to
update, which was wrong; only POST had been tried. Nothing in this module uses PATCH yet, because
a goods receipt is created complete and correcting a posted one is a business decision rather
than a field edit, but it exists and it is how a mistake gets repaired.

**`PONr=0` is mandatory.** Omitted, or sent as `-1` the way `PUVcRecordDuplicate` does
internally, the create is refused with `Erroneous date. Check Order Date.`
(`error code=20855 field='PONr'`). Only `0` creates. The refusal names a date and the cause is a
purchase-order number, which is the sort of thing that costs an afternoon if it is not written
down.

**Field order is significant**, because the ERP validates after each parameter rather than at
the end. A field a calculation depends on must be sent before the field that triggers the
calculation. That is the same mechanism that makes a `VIVc` create fatal: there the due-date
calculation runs when `InvDate` is applied, and whenever it succeeds the process dies.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import secrets
import threading
import time
import urllib.parse
import weakref
from decimal import Decimal, InvalidOperation
from typing import Callable, Optional

from . import approval, audit, changes, contacts, control, dates, erp, privacy, write_outcome
from .config import session_connection_id
from .erp import FORM_CONTENT_TYPE, reply_problems

# A spreadsheet longer than this is a bulk import, not a conversation. Refused, never truncated:
# a silently shortened goods receipt is a stock discrepancy nobody goes looking for.
MAX_LINES = 200
MAX_BATCH = 50
# What `plan_items` may set on a new item, as (preview key, INVc field, length). The lengths are
# the register definition's (Code M4Code 20, Name M4Str 100, Unittext M4Str 10, Group M4Code 5,
# BarCode M4Code 20, AlternativeCode M4Str 40; checked 2026-11-17). REST stores an over-length string whole (PUVc `Comment`, measured
# 2026-11-17), so the plan refuses one by name instead of letting the window cut it later
# (Task 8 review S4). `vendor_item_code` lands in AlternativeCode and is often a product name.
# One table with the generic path (changes.FIELD_LIMITS, Sol re-check 2026-11-17 MUST 6).
ITEM_FIELD_LIMITS = tuple((key, field, changes.FIELD_LIMITS["invc"][field]) for key, field in (
    ("code", "Code"), ("name", "Name"), ("unit", "Unittext"), ("group", "Group"),
    ("barcode", "BarCode"), ("alternative_code", "AlternativeCode")))
# A blank unit or group is not sent; the approval page says who fills it (Task 8 review L4).
SET_BY_BOOKS = "set by Excellent Books"

# `Comment` and `EXCVEInvoiceNr` are 60 characters in the register dictionary (M4Str 60).
# Measured 2026-11-17 on pkorea:4455 (1370): REST stored 70, 100 and 300 characters whole in
# both, neither cut nor refused (docs/erp-register-access.md). The limit is kept anyway (review
# 2026-11-17 M2): the window shows 60, a receipt saved again in Books may keep only that, and
# the correlation mark must survive it. The mark also goes FIRST in the comment.
TEXT_LIMIT = 60
# The mark that finds the receipt again after the POST when there is no supplier invoice number.
# A Books user sees it in the receipt's Comment, so it is plain: "AI-" and 8 hex characters.
TOKEN_PREFIX = "AI-"
# How far back the plan looks for an earlier receipt with the same supplier invoice number. One
# indexed TransDate read of four header fields: 678 receipts in 0.13 s on the demo.
DUPLICATE_DAYS = 365
DESKTOP_UNVERIFIED_NOTE = ("Excellent Books did not fully confirm this receipt. It may have been "
                           "posted: do not post or plan this delivery again. Check the receipt in "
                           "Excellent Books. Stock is supporting evidence only.")
UNVERIFIED_NOTE = (DESKTOP_UNVERIFIED_NOTE.removesuffix(".") + "; erp_messages are progress "
                   "messages, not a verdict.")
_ISO_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Registers this module touches. Named so the privacy gate has something to check against.
REGISTERS = ("PUVc", "INVc", "ItemStatusVc")

# ItemStatusVc carries one row per location PLUS a total row whose Location is this literal.
# Summing every row double-counts; measured 38.00 for the total against P1 1.00 and PL 37.00.
TOTAL_ROW = ";;;"


def _mode() -> str:
    from . import config
    try:
        return config.mode()
    except config.ConfigError:
        return "local"


class PlanError(Exception):
    """A refusal the customer should see. Never repeats the ERP's own wording."""


class PlanReadFailed(PlanError):
    """Books could not be read for the preview: not the caller's mistake, and its text can carry
    Books' own diagnostics (hosted answers it without them)."""


class InvalidBatch(PlanError):
    """The batch itself is wrong: empty, or over the limit (hosted: `invalid_arguments`)."""


def _check_lines(lines) -> None:
    """A goods receipt's batch itself, asked before any read or match (Sol re-check of a90dac7):
    an empty or oversized delivery is the caller's argument mistake, not a missing contact or
    item."""
    if not lines:
        raise InvalidBatch("A goods receipt with no lines would take nothing into stock.")
    if len(lines) > MAX_LINES:
        raise InvalidBatch("%d lines is more than this tool will post in one document (limit %d). "
                           "Split the delivery." % (len(lines), MAX_LINES))


class NoMatch(PlanError):
    """Nothing in the register answers to this. It may be something that should be created."""


def _records(response, register: str, what: str, lines: bool = False) -> list:
    """The records of a read, or PlanError: an HTTP error or an HTTP 200 error body is never an
    empty register, a free code or zero stock (write_outcome.checked_records)."""
    try:
        return write_outcome.checked_records(response, register, lines=lines)
    except write_outcome.ReadFailed as exc:
        raise PlanReadFailed("%s could not be read (%s)." % (what, exc)) from None


class Ambiguous(PlanError):
    """Several records answer to this — so the thing almost certainly already exists.

    Kept separate from NoMatch on purpose: an ambiguous line must never become a NEW item.
    That is how a catalogue grows a second copy of a product it already sells.
    """


def check_register(register: str) -> None:
    """The secret-register gate (privacy.is_blocked), on the write path as well as the read
    paths.

    The standing rule is that a new register-reading tool adds this check and that there is no
    second net. A tool that WRITES has the same obligation and a worse failure mode.
    """
    if privacy.is_blocked(register):
        raise PlanError(privacy.refusal(register)["why"])


def _clean(value) -> str:
    return str(value or "").strip()


def _is_closed(item) -> bool:
    """`Terminated` is what the item card's Closed tick writes.

    A closed item still MATCHES (Kaupo, 2026-09-16: "match them, but say so"). Hiding it would
    make a line naming a genuinely closed product look like a new product and invite a
    duplicate — which is the mess this rule exists because of. So it resolves, and the preview
    says so; the person decides whether receiving stock against a closed item is what they meant.
    """
    return _clean(item.get("Terminated")) == "1"


def resolve_item(items: list, token) -> dict:
    """One spreadsheet cell to exactly one item, or a refusal that names the problem.

    Order is Books `Code`, then `BarCode`, then `AlternativeCode` / `EUCodex`, then `Name`
    (Kaupo, 2026-09-16: "when Books item codes are not provided, mostly code lookup does EAN or
    Barcodes, or in rare cases name lookup"). Only one of the three sample items carries a
    barcode at all, so a real spreadsheet resolves on a mixture of these, and the lines that do
    not resolve have to be visible rather than dropped.

    Zero matches and several matches are both refusals. A resolver that guesses turns a typo
    into stock that was never delivered.
    """
    needle = _clean(token)
    if not needle:
        raise PlanError("A line has no item reference at all.")
    folded = needle.casefold()

    for field, label in (("Code", "code"), ("BarCode", "barcode"),
                         ("AlternativeCode", "alternative_code"), ("EUCodex", "eu_code")):
        hits = [it for it in items if _clean(it.get(field)) and _clean(it.get(field)) == needle]
        if len(hits) == 1:
            return {"code": _clean(hits[0].get("Code")), "name": _clean(hits[0].get("Name")),
                    "matched_on": label, "closed": _is_closed(hits[0])}
        if len(hits) > 1:
            raise Ambiguous("%r matches %d items by %s: %s. Give the Books item code."
                            % (needle, len(hits), label,
                               ", ".join(_clean(h.get("Code")) for h in hits)))

    hits = [it for it in items if _clean(it.get("Name")).casefold() == folded]
    if len(hits) == 1:
        return {"code": _clean(hits[0].get("Code")), "name": _clean(hits[0].get("Name")),
                "matched_on": "name", "closed": _is_closed(hits[0])}
    if len(hits) > 1:
        raise Ambiguous("%r matches %d items by name: %s. Give the Books item code."
                        % (needle, len(hits), ", ".join(_clean(h.get("Code")) for h in hits)))
    raise NoMatch("%r matches no item by code, barcode, alternative code or name." % needle)


def build_body(vendor: str, location: str, trans_date: str, lines: list,
               comment: str = "", ok: bool = True,
               supplier_invoice_nr: str = "") -> bytes:
    """The urlencoded body, in the order the ERP needs to read it.

    `quote_via=quote` is not decoration: `urlencode` writes a space as `+` by default and the
    ERP stores that `+` literally — a comment sent as "MCP write probe" came back as
    `MCP+write+probe` and is still on the demo database saying so.

    `stp` is never emitted. The ERP sets it (observed on read-back) and it is not the caller's.
    """
    _check_lines(lines)
    if not _clean(vendor):
        raise PlanError("A goods receipt needs the vendor it came from.")
    if not _clean(location):
        raise PlanError("A goods receipt needs the location the goods go into.")

    fields = [("set_field.PONr", "0"),          # mandatory; -1 and absent are both refused
              ("set_field.TransDate", _clean(trans_date)),
              ("set_field.VECode", _clean(vendor)),
              ("set_field.Location", _clean(location))]
    if _clean(comment):
        fields.append(("set_field.Comment", _clean(comment)))
    if _clean(supplier_invoice_nr):
        fields.append(("set_field.EXCVEInvoiceNr", _clean(supplier_invoice_nr)))

    for index, line in enumerate(lines):
        quantity = line.get("quantity")
        numeric = _decimal(quantity)
        if numeric is None:
            raise PlanError("Line %d has a quantity that is not a number: %r"
                            % (index + 1, quantity))
        if numeric <= 0:
            raise PlanError("Line %d has quantity %s. A goods receipt takes goods IN; use a "
                            "return for goods going out." % (index + 1, quantity))
        price = line.get("unit_price")
        has_price = price is not None and str(price).strip() != ""
        unit_price = _decimal(price) if has_price else None
        if has_price and (unit_price is None or unit_price < 0):
            raise PlanError("Line %d has a unit price that is not a price: %r. Give a number, "
                            "0 or more, or leave it out for Excellent Books to set."
                            % (index + 1, price))
        fields.append(("set_row_field.%d.ArtCode" % index, _clean(line.get("code"))))
        # A decimal point on the wire, whatever the spreadsheet used ("1,5" -> "1.5").
        fields.append(("set_row_field.%d.Quant" % index, format(numeric, "f")))
        # The row does not inherit the header location: a row read back after a create that
        # omitted it carried an empty Location.
        fields.append(("set_row_field.%d.Location" % index, _clean(location)))
        if unit_price is not None:
            fields.append(("set_row_field.%d.UPrice" % index, format(unit_price, "f")))
        if _clean(line.get("vendor_item_code")):
            fields.append(("set_row_field.%d.VEItemCode" % index,
                           _clean(line.get("vendor_item_code"))))

    # Last, deliberately: everything the posting depends on is in place by the time it is set.
    if ok:
        fields.append(("set_field.OKFlag", "1"))

    # Every value, not only the comment: the page shows a zero-width space (U+200B) as nothing
    # (Sol re-check of dcd94b9, medium: VEItemCode went out unchecked). Runs at plan; post sends
    # the approved bytes unchanged.
    for name, value in fields:
        if changes.has_control(value):
            raise PlanError(changes.CONTROL_REFUSAL % name.rsplit(".", 1)[-1])
    return urllib.parse.urlencode(fields, quote_via=urllib.parse.quote).encode("ascii")


def _decimal(value) -> Optional[Decimal]:
    """A finite number from a cell, decimal comma or point; None when it is not one."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = Decimal(str(value).strip().replace(",", "."))
    except InvalidOperation:
        return None
    return number if number.is_finite() else None


def _number(value) -> float:
    text = _clean(value).replace(" ", "").replace(",", ".")
    try:
        return float(text)
    except ValueError:
        return 0.0


def stock_delta(before: dict, after: dict, expected: Optional[dict] = None) -> dict:
    """What actually moved, per item and per location.

    The delta is evidence, including concurrent movements; the correlated receipt decides
    whether this write was verified.
    """
    by_item = {}
    moved = False
    for code in sorted(set(before) | set(after)):
        was, now = before.get(code, {}), after.get(code, {})
        locations = {}
        for location in sorted(set(was) | set(now)):
            if location == TOTAL_ROW:
                continue
            change = _number(now.get(location)) - _number(was.get(location))
            if change:
                locations[location] = change
        total = _number(now.get(TOTAL_ROW)) - _number(was.get(TOTAL_ROW))
        if total or locations:
            moved = True
        by_item[code] = {"total": total, "by_location": locations,
                         "before_total": _number(was.get(TOTAL_ROW)),
                         "after_total": _number(now.get(TOTAL_ROW))}

    result = {"moved": moved, "by_item": by_item, "warning": ""}
    if not moved:
        result["warning"] = ("Stock did NOT change. The document may exist without having "
                             "posted; read it back in Books before sending the goods on.")
    if expected is not None:
        mismatches = {}
        for code, quantity in expected.items():
            measured = by_item.get(code, {}).get("total", 0.0)
            if abs(measured - _number(quantity)) > 1e-6:
                mismatches[code] = {"expected": _number(quantity), "measured": measured}
        result["matches_expected"] = not mismatches
        if mismatches:
            result["mismatches"] = mismatches
            result["warning"] = ("Stock moved by a different amount than this receipt asked "
                                 "for. Check the document in Books before acting on it.")
    return result


ITEM_FIELDS = "Code,Name,BarCode,AlternativeCode,EUCodex,ItemType,Terminated"
# The reference demo answers the trimmed item list in 0.10 s for 121 items / 27 kB. A real
# catalogue is bigger; past this the resolver stops being the cheap thing it is here and the
# caller is told to give Books item codes instead of guessing from a spreadsheet.
MAX_ITEMS = 20000
# Every register read carries one, for the reason the read path already documents: a `sort` on
# a field a register carries but is not indexed on does not fail, it hangs.
TIMEOUT = 60.0


def fetch_items(session, timeout: float = TIMEOUT) -> list:
    """The item list, trimmed to the columns the resolver actually matches on.

    **No `range`, deliberately, and this is not a style choice.** Measured 2026-09-16 over three
    repeats of each read on `pkorea:4455`:

        range=0:zzzzzzzz   ->  157, 121, 157 items   NON-DETERMINISTIC
        range=0:\\uffff     ->  157, 157, 157 items   stable, still short
        no range           ->  158, 158, 158 items   correct

    The same call returned a different record count on repeated identical requests, and every
    ranged read dropped items — the codes on this database include non-ASCII (`SÕIDUREM_50`),
    which sorts past `z`. A resolver reading a short list refuses a line for an item that
    exists, which is the one failure this tool must not have, so the whole register is read.
    `sort` without `range` is fine; it is `range` without `sort` that fails.
    """
    check_register("INVc")
    response = session.rest_get("/INVc", timeout=timeout, sort="Code", fields=ITEM_FIELDS)
    items = _records(response, "INVc", "The item list")
    if len(items) > MAX_ITEMS:
        raise PlanError("This company has %d items, too many to match a spreadsheet against by "
                        "name. Supply Books item codes." % len(items))
    return items


def fetch_stock(session, codes, timeout: float = TIMEOUT) -> dict:
    """Current stock per item, per location — the before and after of the delta check."""
    check_register("ItemStatusVc")
    stock = {}
    for code in sorted({_clean(c) for c in codes if _clean(c)}):
        response = session.rest_get("/ItemStatusVc", timeout=timeout, sort="Code",
                                    range="%s:%s" % (code, code))
        # A failed read is not zero stock (review 2026-11-17 S7), nor is an HTTP 200 error
        # body (Sol re-check MUST 3); an item with no rows is.
        rows = _records(response, "ItemStatusVc", "Stock of %s" % code)
        stock[code] = {_clean(r.get("Location")): r.get("Instock") for r in rows}
    return stock


VENDOR_FIELDS = "Code,Name,VATNr,RegNr1,RegNr2,CUType"
# The columns a vendor can be recognised by, in the order they are tried. A registration or VAT
# number is what a vendor's own paperwork carries; the Books code usually is not on it at all.
VENDOR_KEYS = (("Code", "code"), ("VATNr", "vat_number"),
               ("RegNr1", "registration_number"), ("RegNr2", "registration_number"))


def fetch_vendors(session, timeout: float = TIMEOUT) -> list:
    """The contact list, trimmed. No `range`, for the reason `fetch_items` documents."""
    check_register("CUVc")
    response = session.rest_get("/CUVc", timeout=timeout, sort="Code", fields=VENDOR_FIELDS)
    return _records(response, "CUVc", "The contact list")


def resolve_vendor(vendors: list, token) -> dict:
    """A vendor's code, VAT number, registration number or name to exactly one contact.

    Same rule as items: zero and several are both refusals. Receiving a delivery against the
    wrong supplier puts the goods on the wrong account and is invisible until somebody
    reconciles the purchase ledger.
    """
    needle = _clean(token)
    if not needle:
        raise PlanError("No vendor was given.")
    squashed = needle.replace(" ", "").casefold()

    for field, label in VENDOR_KEYS:
        hits = [v for v in vendors
                if _clean(v.get(field)) and _clean(v.get(field)).replace(" ", "").casefold() == squashed]
        if len(hits) == 1:
            return {"code": _clean(hits[0].get("Code")), "name": _clean(hits[0].get("Name")),
                    "matched_on": label, "closed": _is_closed(hits[0])}
        if len(hits) > 1:
            raise Ambiguous("%r matches %d contacts by %s: %s. Give the Books contact code."
                            % (needle, len(hits), label,
                               ", ".join(_clean(h.get("Code")) for h in hits)))

    hits = [v for v in vendors if _clean(v.get("Name")).casefold() == needle.casefold()]
    if len(hits) == 1:
        return {"code": _clean(hits[0].get("Code")), "name": _clean(hits[0].get("Name")),
                "matched_on": "name"}
    if len(hits) > 1:
        raise Ambiguous("%r matches %d contacts by name: %s. Give the Books contact code."
                        % (needle, len(hits), ", ".join(_clean(h.get("Code")) for h in hits)))
    raise NoMatch("%r matches no contact by code, VAT number, registration number or name."
                  % needle)


def propose_item_code(items: list) -> str:
    """A free item code to suggest for something new.

    Suggested, never imposed — Kaupo, 2026-09-16: the AI proposes and the human confirms, so
    this only has to be sensible and genuinely free. It continues the band most of the
    catalogue lives in rather than the single highest code, because one stray 800003 would
    otherwise drag every new item into a range nothing else uses.
    """
    taken = {_clean(i.get("Code")) for i in items}
    numeric = sorted(int(c) for c in taken if c.isdigit())
    band = [n for n in numeric if 1000 <= n <= 9999] or numeric
    candidate = (max(band) + 1) if band else 1000
    while str(candidate) in taken:
        candidate += 1
    return str(candidate)


def propose_items(items: list, unmatched: list) -> list:
    """For each line nobody could match, what creating it would look like.

    The proposal is the thing the person reads and corrects. It is deliberately explicit about
    the fields that decide accounting behaviour — a wrong `group` posts the cost to the wrong
    account, and that is not visible in the stock figures at all.
    """
    proposals, taken = [], {_clean(i.get("Code")) for i in items}
    for entry in unmatched:
        code = propose_item_code([{"Code": c} for c in taken])
        taken.add(code)
        proposals.append({
            "proposed_code": code,
            "name": _clean(entry.get("name")) or _clean(entry.get("item")),
            "barcode": _clean(entry.get("barcode")),
            "unit": _clean(entry.get("unit")) or "TK",
            "group": _clean(entry.get("group")),
            "vendor_item_code": _clean(entry.get("item")),
            "from_line": entry.get("line"),
            "needs_a_decision": "group — it decides which cost account the purchase posts to",
        })
    return proposals


def _books_user(session) -> str:
    """The Books user an item plan is bound to: the plan's `usercode or cfg.user` (review L6),
    the form Task 11's gate compares."""
    return session.usercode or session.cfg.user


NOT_SKIPPED = "The approval could not pass over a refused item, so nothing after it was sent."


def plan_items(session, store: approval.PlanStore, items: list, *, max_writes: int = MAX_BATCH) -> dict:
    """Preview a bounded batch of stocked item cards without writing anything."""
    check_register("INVc")
    stopped = control.register_refusal("INVc", write=True)   # the signed control file's stop
    if stopped:
        return stopped
    if not items:
        raise InvalidBatch("No items to create.")
    if len(items) > max_writes:
        raise InvalidBatch("%d items is more than this tool will create at once (limit %d)."
                        % (len(items), max_writes))

    rows = fetch_items(session)
    existing = {_clean(i.get("Code")) for i in rows}
    # Review L5: who already carries each barcode / alternative code. A second item with the
    # same value makes the next plan_goods_receipt refuse that line as ambiguous.
    carried = {"BarCode": {}, "AlternativeCode": {}}
    for row in rows:
        for field, owners in carried.items():
            if _clean(row.get(field)):
                owners.setdefault(_clean(row.get(field)), []).append(_clean(row.get("Code")))
    previews, refused, writes, warnings, planned = [], [], [], [], set()
    path = urllib.parse.urlsplit(session.cfg.api_base).path.rstrip("/") + "/INVc"
    for proposal in items:
        values = {"code": _clean(proposal.get("code")) or _clean(proposal.get("proposed_code")),
                  "name": _clean(proposal.get("name")),
                  "unit": _clean(proposal.get("unit")), "group": _clean(proposal.get("group")),
                  "barcode": _clean(proposal.get("barcode")),
                  "alternative_code": (_clean(proposal.get("alternative_code")) or
                                       _clean(proposal.get("vendor_item_code")))}
        code, name = values["code"], values["name"]
        controlled = [key for key, value in values.items() if changes.has_control(value)]
        if controlled:
            refused.append({"code": code, "why": changes.CONTROL_REFUSAL % ", ".join(controlled)})
            continue
        too_long = ["%s (%s) is %d characters; an item's %s in Excellent Books holds %d"
                    % (key, field, len(values[key]), field, limit)
                    for key, field, limit in ITEM_FIELD_LIMITS if len(values[key]) > limit]
        if not code or not name:
            refused.append({"code": code, "why": "an item needs both a code and a name"})
            continue
        if too_long:
            refused.append({"code": code, "why": "; ".join(too_long) + ". Shorten it and plan again."})
            continue
        if code in planned:
            refused.append({"code": code, "why": "this code is listed twice in this batch; "
                                                 "only the first is planned"})
            continue
        if code in existing:
            refused.append({"code": code, "why": "an item with this code already exists"})
            continue
        for key, field in (("barcode", "BarCode"), ("alternative_code", "AlternativeCode")):
            owners = carried[field].setdefault(values[key], []) if values[key] else None
            if owners:
                warnings.append({"code": code, "field": key, "value": values[key],
                                 "also_on": list(owners),
                                 "why": "another item already carries this %s, so a receipt "
                                        "line giving it will match both and be refused as "
                                        "ambiguous" % key.replace("_", " ")})
            if owners is not None:
                owners.append(code)
        preview = dict(values, item_type="stocked")
        fields = [("set_field.Code", code), ("set_field.Name", name), ("set_field.ItemType", "1")]
        for key, field in (("unit", "Unittext"), ("group", "Group"),
                           ("barcode", "BarCode"), ("alternative_code", "AlternativeCode")):
            if values[key]:
                fields.append(("set_field.%s" % field, values[key]))
            elif key in ("unit", "group"):
                preview[key] = SET_BY_BOOKS
        body = urllib.parse.urlencode(fields, quote_via=urllib.parse.quote)
        writes.append(("POST", path, body))
        previews.append(preview)
        planned.add(code)

    out = {"status": "planned" if writes else "refused", "items": previews, "refused": refused,
           "warnings": warnings,
           "note": (approval.ITEMS_NOTE if writes else
                    "Nothing has been written and there is nothing to approve: every item was "
                    "refused (see refused).")}
    if writes:
        envelope = approval.Envelope(
            kind="items", server=session.cfg.origin, company=session.cfg.company,
            books_user=_books_user(session), operation="batch", target="INVc x%d" % len(writes),
            writes=tuple(writes), before="",
            preview=json.dumps(out, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
            needs_ack=False)  # Creating item cards neither posts to the ledger nor moves stock.
        out["plan_id"] = store.issue(envelope, {"items": previews, "refused": refused,
            "system_version": getattr(session, "system_version", None),
            "connection": session_connection_id(session)})
    return out


def execute_items(session, approved: approval.Approved, plan: approval.Plan,
                  still_allowed: Callable[[], bool]) -> dict:
    """Send stored writes in order; the caller owns finishing the plan, even on a stop."""
    if (not isinstance(approved, approval.Approved) or not approved.live()
            or not isinstance(plan, approval.Plan) or plan.plan_id != approved.plan_id
            or plan.envelope != approved.envelope
            or not approved.matches(session.cfg.origin, session.cfg.company, _books_user(session))
            or approved.envelope.kind != "items"):
        return {"error": "refused", "why": "A live approval for this plan and connection is required."}

    check_register("INVc")
    envelope = approved.envelope
    # Identify the records from the same immutable bytes being dispatched, never a caller's
    # proposals or a mutable payload. Refusals belong to the approved preview as well.
    records = []
    for method, path, body in envelope.writes:
        fields = dict(urllib.parse.parse_qsl(body))
        records.append({"code": fields["set_field.Code"], "name": fields["set_field.Name"]})
    # Every planned write ends in exactly one bucket, keyed by its place in the envelope; the
    # plan-time refusals come first in `refused` (write_outcome.Outcomes).
    out = write_outcome.Outcomes(ITEM_BUCKETS)
    for n, entry in enumerate(json.loads(envelope.preview)["refused"]):
        out.put(("plan", n), "refused", entry)
    sent, said = [], {}       # sent: indexes whose request went out (reply or not)
    unclear = set()           # indexes answered by an empty 401 (round 4)
    connection_lost = False

    def stop(index, why=None):
        for later in range(index, len(records)):
            out.put(later, write_outcome.NOT_ATTEMPTED,
                    dict(records[later], why=why) if why else records[later])

    for index, (method, path, body) in enumerate(envelope.writes):
        record = records[index]
        try:
            allowed = still_allowed()
        except Exception as exc:
            # Review S3: a permission check that cannot answer is a stop, never a crash that
            # loses the per-item lists of what was already sent.
            stop(index, write_outcome.before_write_why(
                exc, "Whether writing may go on could not be checked, so this was not sent."))
            break
        if not allowed:
            stop(index)
            break
        try:
            # A failed existence check, an HTTP 200 error body included, is never a free code.
            response = session.rest_get("/INVc", timeout=TIMEOUT, sort="Code",
                                        range="%s:%s" % (record["code"], record["code"]))
            taken = any(_clean(row.get("Code")) == record["code"]
                        for row in _records(response, "INVc", "The item code"))
        except Exception as exc:
            # Checking the code cannot dispatch a write. Leave this record retryable too.
            stop(index, write_outcome.before_write_why(
                exc, "The item code could not be checked before writing, so this was not sent."))
            break
        if taken:
            out.put(index, "refused", {"code": record["code"],
                                       "why": "an item with this code already exists"})
            try:
                skipped = contacts._skip(approved, (method, path, body))
            except Exception:
                # Sol re-check SHOULD 1: a raising skip is a stop, never a lost batch.
                skipped = False
            if not skipped:
                stop(index + 1, NOT_SKIPPED)
                break
            continue
        try:
            erp.check_desktop_write_budget()
            reply = session.request(session.cfg.origin + path, body.encode("ascii"),
                                    {"Content-Type": FORM_CONTENT_TYPE}, timeout=TIMEOUT,
                                    method=method, approved=approved)
            if reply is None:
                raise PlanError("No reply to the item create.")
        except erp.WriteConnectionLost as exc:
            # The single liveness read has already run. Earlier writes still awaiting
            # read-back also need checking in Books.
            for earlier in sent:
                out.put(earlier, write_outcome.UNVERIFIED, records[earlier])
            out.put(index, write_outcome.UNVERIFIED,
                    dict(record, **write_outcome.connection_loss(exc)))
            connection_lost = True
            stop(index + 1, exc.suspension_reason)
            break
        except erp.DesktopWriteTimeout as exc:
            out.put(index, write_outcome.UNVERIFIED, dict(record, why=str(exc)))
            stop(index + 1)
            break
        except Exception as exc:
            if write_outcome.send_failure(exc) == write_outcome.NOT_ATTEMPTED:
                # Review S1: stopped BEFORE any HTTP. Nothing was sent, so this is not "may
                # have been created"; the batch stops here.
                stop(index, write_outcome.not_sent_why(exc))
                break
            # The write might have landed. A later read must not invite a retry of this record.
            sent.append(index)
            out.put(index, write_outcome.UNVERIFIED, records[index])
            stop(index + 1)
            break
        said[record["code"]] = reply_problems(getattr(reply, "body", b""))
        if write_outcome.access_unclear(getattr(reply, "status", 200),
                                        getattr(reply, "body", b"")):
            unclear.add(index)
        sent.append(index)
        out.put(index, "created", record)      # until the read-back decides

    if sent and not connection_lost:
        try:
            # Exactly one batch read-back, separate from each pre-write code check.
            with erp.desktop_batch_read_back():
                after = {_clean(item.get("Code")): item for item in fetch_items(session)}
        except Exception:
            # An unread read-back is unverified, and nothing more (review M1).
            for index in sent:
                out.put(index, write_outcome.UNVERIFIED, records[index])
        else:
            for index in out.keys("created"):
                item = records[index]
                verdict, theirs = write_outcome.judge_create(after.get(item["code"]),
                                                             item["code"], item["name"])
                if verdict == write_outcome.ABSENT and index in unclear:
                    # Task 22 gate round 4 (Sol MUST): an empty 401 after a sent write is never
                    # "not found after create"; it stays unverified with the access note. A
                    # read-back that shows the item still decides it was created.
                    out.put(index, write_outcome.UNVERIFIED, dict(
                        item, http_status=401, why=write_outcome.ACCESS_UNCLEAR))
                elif verdict == write_outcome.ABSENT:
                    problems = said[item["code"]]
                    out.put(index, "not_found_after_create",
                            dict(item, erp_said=problems,
                                 **write_outcome.refusal_explanations(problems))
                            if problems else item)
                elif verdict == write_outcome.UNVERIFIED:
                    # Review S2: Books answers a POST for a code that exists with HTTP 200
                    # "Already registered" and stores nothing (CUVc, measured 2026-11-17), so
                    # the code alone does not prove the item is ours.
                    out.put(index, write_outcome.UNVERIFIED, dict(item, why=(
                        "The code is now used by another item (%s); this one may not have "
                        "been created. Check it in Excellent Books." % theirs)))
    lists = out.lists()
    outcome = write_outcome.batch_audit_outcome(lists, sent=bool(sent))
    audit.record("create_items", register="INVc", outcome=outcome,
                 reason="not_found_after_create" if lists["not_found_after_create"] else None,
                 created=len(lists["created"]), lines=len(records),
                 **audit.approval_facts(approved))
    return dict(lists, note=(
        "Created items were read back from Excellent Books. not_found_after_create lists items "
        "absent on read-back; " + write_outcome.said_note("erp_said explains what to fill in.")
        + " Unverified items may have been created: check them in Excellent Books before "
        "retrying. not_attempted items were not sent."))


ITEM_BUCKETS = ("created", "refused", "not_found_after_create", "not_attempted",
                write_outcome.UNVERIFIED)



def _exists(session, register: str, key: str, value: str, timeout: float = 20.0) -> bool:
    """Is there a record with this key? Status is checked BEFORE the body, always."""
    value = _clean(value)
    if not value:
        return False
    response = session.rest_get("/%s" % register, timeout=timeout, sort=key,
                                range="%s:%s" % (value, value))
    if response.status != 200:
        return False
    from .erp import list_records
    return any(_clean(r.get(key)) == value for r in list_records(response.body, register))


def _reference_fingerprint(vendors, items, vendor_code, item_codes) -> str:
    """Fingerprint all fetched fields of the selected vendor and items, including Closed."""
    codes = set(item_codes)
    selected = ([v for v in vendors if _clean(v.get("Code")) == vendor_code],
                [i for i in items if _clean(i.get("Code")) in codes])
    canonical = json.dumps([sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))
                            for rows in selected], sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _iso_date(session, given) -> str:
    """The receipt date as YYYY-MM-DD, the form `TransDate` is written and read back in.

    Review 2026-11-17 S6: "17.11.2026" went out as typed, never matched the ISO read-back, and a
    span Books cannot read is substituted at HTTP 200. `TransDate` ends in "Date", so dates.py
    sends it ISO; a date in the ERP's own format is read with the customer's SysFormatBlock.
    """
    text = _clean(given)
    if not text:
        return datetime.date.today().isoformat()
    try:
        value = dates.to_wire("TransDate", text, lambda: dates.erp_format(session))
    except ValueError as exc:
        raise PlanError(str(exc)) from None
    if not isinstance(value, str) or not _ISO_DAY.match(value):
        raise PlanError("TransDate: %s is not a date. Write it as YYYY-MM-DD." % text)
    return value


def _check_text_limits(comment: str, stored_comment: str, supplier_invoice_nr: str) -> None:
    """Refuse at plan time what Books keeps only 60 characters of (TEXT_LIMIT), and a control
    character (Task 22 gate, A NIT-1: the page shows it as a space)."""
    for name, value in (("comment", comment), ("supplier_invoice_nr", supplier_invoice_nr)):
        if changes.has_control(value):
            raise PlanError(changes.CONTROL_REFUSAL % name)
    if len(stored_comment) > TEXT_LIMIT:
        extra = len(stored_comment) - len(comment)
        raise PlanError(
            "The comment is too long: a goods receipt's comment in Excellent Books holds %d "
            "characters%s. Shorten it to %d characters." % (
                TEXT_LIMIT, (", and %d of them are the mark that finds the receipt again after "
                             "posting" % extra) if extra else "", TEXT_LIMIT - extra))
    if len(supplier_invoice_nr) > TEXT_LIMIT:
        raise PlanError("The supplier invoice number is %d characters; a goods receipt in "
                        "Excellent Books holds %d." % (len(supplier_invoice_nr), TEXT_LIMIT))


def _already_received(session, vendor: str, invoice_nr: str, trans_date: str) -> list:
    """Earlier receipts from this vendor with this supplier invoice number, newest window only.

    One indexed read (`sort=TransDate`, open end, DUPLICATE_DAYS back) of four header fields;
    the vendor and the number are compared here, never with `filter.` (it reads every record).
    Raises when Books cannot be read: the caller says the check was not made.
    """
    start = datetime.date.fromisoformat(trans_date) - datetime.timedelta(days=DUPLICATE_DAYS)
    response = session.rest_get("/PUVc", timeout=TIMEOUT, sort="TransDate",
                                range="%s:" % start.isoformat(),
                                fields="SerNr,VECode,TransDate,EXCVEInvoiceNr,Invalid")
    wanted = invoice_nr.casefold()
    return [{"document": _clean(h.get("SerNr")), "date": _clean(h.get("TransDate"))}
            for h, _ in _records(response, "PUVc", "Goods receipts", lines=True)
            if _clean(h.get("VECode")) == vendor and _clean(h.get("Invalid")) != "1"
            and _clean(h.get("EXCVEInvoiceNr")).casefold() == wanted]


def _same_day(session, planned) -> list:
    """Every receipt on the plan's TransDate, with lines: the indexed one-day read."""
    response = session.rest_get("/PUVc", timeout=TIMEOUT, sort="TransDate",
                                range="%s:%s" % (planned["trans_date"], planned["trans_date"]))
    return _records(response, "PUVc", "Goods receipts on this date", lines=True)


# Weak store references keep correlation lookup subject to the shared store's eviction and
# restart lifetime, without a second unbounded cache of plan IDs or receipt data.
_receipt_stores = weakref.WeakSet()
_receipt_stores_lock = threading.Lock()


def correlation(plan_id: str) -> str:
    """Return the plan-time value; PlanStore issues the ID only after the body is frozen."""
    with _receipt_stores_lock:
        stores = list(_receipt_stores)
    for store in stores:
        planned = store.get(plan_id)
        if planned is not None and planned.envelope.kind == "goods_receipt":
            return planned.payload["correlation"]
    raise PlanError("Unknown or evicted receipt plan; make a new preview.")


def plan(session, store: approval.PlanStore, vendor: str, location: str, lines: list,
         trans_date: str = "", comment: str = "", supplier_invoice_nr: str = "") -> dict:
    """Resolve and validate everything, write nothing, and hand back something to confirm.

    Every line must resolve to exactly one item or the WHOLE plan is refused. A spreadsheet
    that is 90% resolvable produces no document at all, on purpose: a goods receipt missing
    the lines nobody could match is a stock discrepancy that surfaces weeks later.
    """
    check_register("PUVc")
    stopped = control.register_refusal("PUVc", write=True)   # the signed control file's stop
    if stopped:
        return stopped
    _check_lines(lines)
    trans_date = _iso_date(session, trans_date)
    # The correlation value and the texts as Books will store them, checked before any read.
    comment, supplier_invoice_nr = _clean(comment), _clean(supplier_invoice_nr)
    mark = supplier_invoice_nr or TOKEN_PREFIX + secrets.token_hex(4)
    stored_comment = comment if supplier_invoice_nr else (mark + " " + comment).strip()
    _check_text_limits(comment, stored_comment, supplier_invoice_nr)

    known = fetch_vendors(session)
    try:
        vendor_match = resolve_vendor(known, vendor)
    except NoMatch:
        # Not a dead end any more: the supplier may simply be new. Same shape as needs_items —
        # a separate decision from receiving the goods, so nothing is planned until it exists.
        # The next free code in the band the catalogue actually lives in — NOT the global
        # maximum. Measured 2026-09-16: the five highest numeric contact codes on the
        # reference demo are 11 digits beginning 1-6, i.e. isikukood-shaped, because
        # private-person contacts are coded by their personal ID. max()+1 proposed
        # 48702124717, which is both absurd and shaped like personal data.
        numeric = sorted(int(c) for c in (_clean(v.get("Code")) for v in known) if c.isdigit())
        band = [n for n in numeric if 10000 <= n <= 99999] or [n for n in numeric if n < 10000]
        free = str((max(band) + 1) if band else 1000)
        while free in {_clean(v.get("Code")) for v in known}:
            free = str(int(free) + 1)
        return {"status": "needs_contact",
                "unmatched_vendor": _clean(vendor),
                "proposed_code": free,
                "confirm": ("Nothing was planned and nothing was written. No contact matches "
                            "%r by code, VAT number, registration number or name. If this is a "
                            "new supplier, take its company name, registration number, VAT "
                            "number and address from the delivery paperwork, show them to the "
                            "person, and call plan_contacts: it only plans the contact. Then call "
                            "apply_approved; the person approves it themselves, and "
                            "only then is it created. Run plan_goods_receipt again once the contact exists."
                            % _clean(vendor))}

    items = fetch_items(session)
    resolved, ambiguous, unmatched = [], [], []
    for index, line in enumerate(lines or []):
        line = line or {}
        token = line.get("item") if _clean(line.get("item")) else line.get("code")
        description = _clean(line.get("name")) or _clean(line.get("description"))
        try:
            match = resolve_item(items, token)
        except Ambiguous as failure:
            ambiguous.append("line %d: %s" % (index + 1, failure))
            continue
        except NoMatch:
            # The vendor's own code matched nothing — but a delivery line almost always carries
            # a DESCRIPTION too, and on this data that description is often the exact item name.
            # Measured 2026-09-16: a line reading `MG-2005 | JVC videomakk 2000` proposed a NEW
            # item, and item 2005 is called exactly "JVC videomakk 2000". Without this fallback
            # the tool creates a second copy of a product the company already sells, which is
            # the failure `Ambiguous` exists to prevent, reached by a path that skipped it.
            try:
                match = resolve_item(items, description) if description else None
            except Ambiguous as failure:
                ambiguous.append("line %d: %s" % (index + 1, failure))
                continue
            except NoMatch:
                match = None
        if match is None:
            unmatched.append({"line": index + 1, "item": _clean(token),
                              "name": _clean(line.get("name")) or _clean(line.get("description")),
                              "barcode": _clean(line.get("barcode")),
                              "unit": _clean(line.get("unit")),
                              "group": _clean(line.get("group")),
                              "quantity": line.get("quantity")})
            continue
        price = line.get("unit_price")
        if price is not None and not str(price).strip():
            price = None
        resolved.append({"code": match["code"], "name": match["name"],
                         "matched_on": match["matched_on"],
                         "closed": bool(match.get("closed")),
                         "quantity": line.get("quantity"),
                         "unit_price": price,
                         "vendor_item_code": line.get("vendor_item_code") or
                                            (_clean(token) if match["matched_on"] != "code" else "")})

    if ambiguous:
        raise Ambiguous("These lines match MORE than one item, so they were not planned and "
                        "must not be created as new items — the product is already in the "
                        "catalogue:\n  " + "\n  ".join(ambiguous))

    if unmatched:
        # Not an error: a first delivery of something new is ordinary. But it is a SEPARATE
        # decision from receiving the goods, so nothing is planned until the items exist.
        return {"status": "needs_items",
                "vendor": vendor_match["code"], "vendor_name": vendor_match["name"],
                "matched_lines": len(resolved),
                "unmatched_lines": [u["line"] for u in unmatched],
                "proposed_items": propose_items(items, unmatched),
                "confirm": ("Nothing was planned and nothing was written. These lines name "
                            "products this company has no item for. Show the proposals to the "
                            "person, let them correct the code, name, unit and especially the "
                            "GROUP, then call plan_items with what they settle on: it only "
                            "plans the items. Then call apply_approved; the person approves them "
                            "themselves, and only then are they created. Run plan_goods_receipt again once "
                            "the items exist.")}

    # build_body is the validator for quantities, prices, the line cap and the required header
    # fields; calling it here means `post` cannot meet a problem `plan` did not already show.
    body = build_body(vendor=vendor_match["code"], location=location, trans_date=trans_date,
                      lines=resolved, comment=stored_comment, ok=True,
                      supplier_invoice_nr=supplier_invoice_nr)

    expected = {}
    for line in resolved:
        expected[line["code"]] = expected.get(line["code"], 0.0) + _number(line["quantity"])

    warnings = []
    if any(l.get("closed") for l in resolved):
        warnings.append(
            "Closed in Books: %s. These items are marked Closed on their item card and this "
            "receipt would still take stock in against them. Check that is intended before "
            "confirming." % ", ".join(l["code"] for l in resolved if l.get("closed")))
    already = None
    if supplier_invoice_nr:
        # Review 2026-11-17 M1: the same supplier invoice received before is a double receipt,
        # or the delivery this plan repeats. A warning, not a refusal: a vendor can reuse a
        # number, and the person decides.
        try:
            already = _already_received(session, vendor_match["code"], supplier_invoice_nr,
                                        trans_date)
        except Exception:
            warnings.append(
                "This connector could not check Excellent Books for an earlier goods receipt "
                "with supplier invoice number %s from this vendor. Check in Books that this "
                "delivery has not been received already." % supplier_invoice_nr)
        if already:
            warnings.append(
                "Excellent Books already has a goods receipt from this vendor with supplier "
                "invoice number %s: %s. Check this is not the same delivery before approving; "
                "approving takes the goods in again." % (supplier_invoice_nr, ", ".join(
                    "%s (%s)" % (a["document"], a["date"]) for a in already)))

    preview = {
        "status": "ready_to_post",
        "vendor": vendor_match["code"],
        "vendor_name": vendor_match["name"],
        "vendor_matched_on": vendor_match["matched_on"],
        "location": _clean(location),
        "date": trans_date,
        "comment": comment,
        # What the receipt's Comment will say in Books, mark included (review 2026-11-17 S8).
        "comment_in_books": stored_comment,
        "supplier_invoice_nr": supplier_invoice_nr,
        "correlation": mark,
        "lines": [{"item": line["code"], "name": line["name"], "quantity": line["quantity"],
                   "unit_price": line["unit_price"],
                   **({"price_set_by": "Excellent Books"} if line["unit_price"] is None else {}),
                   "vendor_item_code": line["vendor_item_code"],
                   "matched_on": line["matched_on"],
                   **({"closed_in_books": True} if line.get("closed") else {})}
                  for line in resolved],
        "will_change_stock_by": {code: quantity for code, quantity in sorted(expected.items())},
        **({"already_received": already} if already else {}),
        **({"warning": " ".join(warnings)} if warnings else {}),
        "confirm": ("Nothing has been written. The person must approve these exact lines "
                    "before apply_approved can execute this plan. "
                    "The receipt is created already OK'd, so stock moves immediately."),
    }
    if all(line["unit_price"] is not None for line in resolved):
        preview["total"] = sum(_number(line["quantity"]) * _number(line["unit_price"])
                               for line in resolved)
    else:
        preview["total_set_by"] = "Excellent Books"
    payload = {"vendor": vendor_match["code"], "location": _clean(location),
               "trans_date": trans_date, "comment": comment,
               "supplier_invoice_nr": supplier_invoice_nr, "correlation": mark,
               # What the preview warned about (Task 22 gate, opus A SHOULD-2).
               "already_received": tuple(a["document"] for a in already or ()),
               "expected": tuple(sorted(expected.items())), "lines": resolved,
               "system_version": getattr(session, "system_version", None),
               "connection": session_connection_id(session)}
    path = urllib.parse.urlsplit(session.cfg.api_base).path.rstrip("/") + "/PUVc"
    envelope = approval.Envelope(
        kind="goods_receipt", server=session.cfg.origin, company=session.cfg.company,
        books_user=session.usercode or session.cfg.user, operation="create", target="PUVc (new)",
        writes=(("POST", path, body.decode("ascii")),),
        before=_reference_fingerprint(known, items, vendor_match["code"], expected),
        preview=json.dumps(preview, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
        needs_ack=True)
    preview["plan_id"] = store.issue(envelope, payload)
    with _receipt_stores_lock:
        _receipt_stores.add(store)
    return preview


def highest_sernr(session, register: str = "PUVc", timeout: float = TIMEOUT) -> int:
    """The largest serial in a register right now.

    Retained for live probes; receipt execution uses correlation instead of this maximum.
    **The reply cannot tell us the document number.**
    Measured 2026-09-16: when the ERP emits its progress messages the reply contains ONLY those
    messages and no record element at all, so the document number is simply absent on the common
    path — a first attempt to parse `<SerNr>` out of it logged an empty document every time.

    Serials here are not small: the live band is around 544118956+, so nothing may assume a
    number fits a human-sized range.
    """
    from .erp import list_records
    response = session.rest_get("/%s" % register, timeout=timeout, sort="SerNr", fields="SerNr")
    if response.status != 200:
        return 0
    numbers = [int(r.get("SerNr")) for r in list_records(response.body, register)
               if str(r.get("SerNr") or "").isdigit()]
    return max(numbers) if numbers else 0


def _row_count(body: str) -> int:
    return len({part.split(".")[1] for part in (body or "").split("&")
                if part.startswith("set_row_field.")})


def _measure_stock(session, expected):
    """A failed supporting read cannot change a document's verification result."""
    try:
        # An item with no ItemStatusVc rows yet (its first receipt) has zero stock, and
        # fetch_stock gives it {}; only a failed read is "not measured" (review 2026-11-17 S7).
        return fetch_stock(session, expected)
    except Exception:
        return None


def _receipt_matches(header, planned) -> bool:
    if (header.get("VECode") != planned["vendor"]
            or header.get("TransDate") != planned["trans_date"]):
        return False
    if planned["supplier_invoice_nr"]:
        # Preserve the measured PUVc field used by build_body, not VIVc's InvoiceNr.
        return header.get("EXCVEInvoiceNr") == planned["correlation"]
    # The mark is the comment's first word (review 2026-11-17 M2).
    return (header.get("Comment") or "").split()[:1] == [planned["correlation"]]


def _receipt_not_saved(header, lines, body) -> list:
    """Check the saved header and ordered lines against every field actually sent."""
    not_saved, sent_rows = [], set()
    for key, wanted in urllib.parse.parse_qsl(body, keep_blank_values=True):
        number = None
        if key.startswith("set_field."):
            field = key.split(".", 1)[1]
            stored = header.get(field, "")
        else:
            _, index, field = key.split(".", 2)
            number = int(index) + 1
            sent_rows.add(number)
            stored = lines.get(number, {}).get(field, "")
        same = wanted == stored
        if not same and field in {"Quant", "UPrice", "OKFlag", "PONr"}:
            try:
                same = float(wanted.replace(",", ".")) == float(str(stored).replace(",", "."))
            except ValueError:
                pass
        if not same:
            difference = {"field": field, "wanted": wanted, "stored": stored}
            if number is not None:
                difference["line"] = number
            not_saved.append(difference)
    if set(lines) != sent_rows:
        not_saved.append({"field": "lines", "wanted": len(sent_rows), "stored": len(lines)})
    return not_saved


def execute_receipt(session, approved: approval.Approved, plan: approval.Plan) -> dict:
    """Dispatch the approved bytes once. The caller finishes the plan with this outcome."""
    started = time.monotonic()

    def refused(why, reason):
        audit.record("post_goods_receipt", register="PUVc", outcome="failed", reason=reason,
                     ms=int((time.monotonic() - started) * 1000),
                     **({} if reason == "not_approved" else audit.approval_facts(approved)))
        return {"error": "refused", "why": why}

    if (not isinstance(approved, approval.Approved) or not approved.live()
            or not isinstance(plan, approval.Plan) or plan.plan_id != approved.plan_id
            or plan.envelope != approved.envelope
            or not approved.matches(session.cfg.origin, session.cfg.company, session.usercode or session.cfg.user)
            or approved.envelope.kind != "goods_receipt"):
        return refused("A live approval for this plan and connection is required.", "not_approved")

    planned, envelope = plan.payload, approved.envelope
    expected = dict(planned["expected"])
    try:
        check_register("PUVc")
        vendors, items = fetch_vendors(session), fetch_items(session)
        current = _reference_fingerprint(vendors, items, planned["vendor"], expected)
    except Exception as exc:
        return refused(write_outcome.before_write_why(
            exc, "Excellent Books could not be reached to check the vendor and items. "
                 "Nothing was written. Make a new preview."), "reference_read_failed")
    if current != envelope.before:
        return refused("The vendor or an item changed since the preview. Nothing was written. "
                       "Make a new preview so the person sees the current details.", "references_changed")

    # Review 2026-11-17 M1: a receipt that ALREADY answers to this plan's vendor, date and
    # correlation value (the same supplier invoice typed by hand, an earlier run) is not ours.
    # Without this read, a POST that does not land reads the old receipt back as "posted".
    try:
        existing = {_clean(h.get("SerNr")) for h, _ in _same_day(session, planned)
                    if _receipt_matches(h, planned)}
    except Exception as exc:
        return refused(write_outcome.before_write_why(
            exc, "Excellent Books could not be read to check the receipts already on this "
                 "date. Nothing was written. Make a new preview."), "pre_read_failed")
    # Task 22 gate (opus A SHOULD-2): a receipt for the same supplier invoice that the preview did
    # not show (a second preview of one delivery, both approved) is refused, not taken in twice.
    if planned["supplier_invoice_nr"]:
        unseen = sorted(existing - set(planned.get("already_received") or ()) - {""})
        if unseen:
            # The check reads the receipts of the plan's own date only (round 4, Sol SHOULD).
            return refused("Excellent Books got a goods receipt from this vendor with supplier "
                           "invoice number %s dated %s after this preview: %s. Nothing was "
                           "written. This check looks at receipts with the same date only. "
                           "Check in Excellent Books that it is not the same delivery; to take "
                           "the goods in again anyway, make a new preview." % (
                               planned["supplier_invoice_nr"], planned["trans_date"],
                               ", ".join(unseen)),
                           "received_after_preview")

    before = _measure_stock(session, expected)
    method, path, body = envelope.writes[0]
    mode = _mode()
    stdio = mode in ("desktop", "plugin")      # the plugin keeps Desktop's structured replies
    unverified_note = DESKTOP_UNVERIFIED_NOTE if stdio else UNVERIFIED_NOTE
    reply, reason = b"", None
    try:
        erp.check_desktop_write_budget()
        response = session.request(session.cfg.origin + path, body.encode("ascii"),
                                   {"Content-Type": FORM_CONTENT_TYPE}, timeout=TIMEOUT,
                                   method=method, approved=approved)
        if response is None:
            reason = "no_reply"
        else:
            reply = response.body or b""
    except erp.WriteConnectionLost as exc:
        audit.record("post_goods_receipt", register="PUVc", outcome="unverified",
                     reason="write_connection_lost", lines=_row_count(body),
                     ms=int((time.monotonic() - started) * 1000),
                     **audit.approval_facts(approved))
        return {"status": write_outcome.UNVERIFIED, "posted": "unverified",
                "note": exc.suspension_reason,
                **write_outcome.connection_loss(exc)}
    except erp.DesktopWriteTimeout:
        audit.record("post_goods_receipt", register="PUVc", outcome="unverified",
                     reason="no_reply", lines=_row_count(body), **audit.approval_facts(approved))
        return {"status": write_outcome.UNVERIFIED, "posted": "unverified", "note": unverified_note}
    except Exception as exc:
        if write_outcome.send_failure(exc) == write_outcome.NOT_ATTEMPTED:
            audit.record("post_goods_receipt", register="PUVc", outcome="failed",
                         reason="not_attempted", ms=int((time.monotonic() - started) * 1000),
                         **audit.approval_facts(approved))
            return {"status": write_outcome.NOT_ATTEMPTED, "posted": False,
                    "note": write_outcome.not_sent_why(exc)}
        # The request may have landed: every outcome from here is terminal, never False.
        reason = "no_reply"

    # Exactly one NEW match is the document, as Task 6 calls a read-back create "created" (review
    # 2026-11-17 S5): it exists, so it is named, with any field Books did not keep listed. Zero or
    # several new matches, or a failed read, stay "unverified" (terminal).
    document, not_saved, ok_saved = "", [], False
    try:
        matches = [(h, rows) for h, rows in _same_day(session, planned)
                   if _receipt_matches(h, planned) and _clean(h.get("SerNr")) not in existing]
        if len(matches) == 1:
            header, rows = matches[0]
            document = _clean(header.get("SerNr"))
            not_saved = _receipt_not_saved(header, rows, body)
            ok_saved = _clean(header.get("OKFlag")) == "1"
            if not document:
                reason = reason or "missing_document_number"
        else:
            reason = reason or "correlation_not_unique"
    except Exception:
        reason = reason or "read_back_failed"
    posted = (ok_saved if document else "unverified")
    if posted is True:
        reason = "fields_changed_by_erp" if not_saved else reason
    elif posted is False:
        reason = "not_ok"

    after = _measure_stock(session, expected)
    delta = (stock_delta(before, after, expected=expected)
             if before is not None and after is not None else
             {"verified": False, "moved": None, "by_item": {},
              "warning": "Stock evidence could not be measured; check stock in Excellent Books."})
    audit.record("post_goods_receipt", register="PUVc",
                 outcome="ok" if posted is True else "failed" if posted is False else "unverified",
                 reason=reason, document=document if re.fullmatch(r"[0-9]+", document) else "",   # a SerNr only (Sol 03ad0bf)
                 lines=_row_count(body),
                 location=planned["location"], stock_moved=bool(delta["moved"]),
                 ms=int((time.monotonic() - started) * 1000),
                 **audit.approval_facts(approved))
    result = {"document": document, "posted": posted, "stock": delta,
              "vendor": planned["vendor"], "location": planned["location"],
              "date": planned["trans_date"],
              "note": ("The correlated receipt and its lines were read back from Excellent Books. "
                       "Stock is supporting evidence only. ERP progress messages can read like "
                       "errors even when the write succeeded.")}
    if mode == "local":
        # Masked whole, then cut: a cut first could leave a key's body without its BEGIN.
        result["erp_messages"] = privacy.mask_key_text(reply.decode("utf-8", "replace"))[0][:400]
    if posted is False:
        result["note"] = ("Excellent Books created goods receipt %s but did not OK it, so it took "
                          "no stock in. Tell the person to open it in Excellent Books and OK it "
                          "there; do not post or plan this delivery again." % document)
    elif posted is True and not_saved:
        result["note"] = ("Excellent Books created and OK'd goods receipt %s, but the fields in "
                          "not_saved are not what was approved. Tell the person to check and "
                          "correct the receipt in Excellent Books; do not post or plan this "
                          "delivery again." % document)
    elif posted == "unverified":
        result["note"] = unverified_note
    if stdio or posted is not True:
        said = reply_problems(reply, structured=stdio)
        if stdio:
            # A Books diagnostic can echo the session cookie. Keep structured codes and fields.
            said = [problem for problem in said if "field" in problem or "error" in problem]
            if said:
                result["erp_said"] = said
        if posted is not True:
            explanations = write_outcome.refusal_explanations(said)
            if explanations:
                result.update(erp_said=said, **explanations)
    if not_saved:
        result["not_saved"] = not_saved
    return result
