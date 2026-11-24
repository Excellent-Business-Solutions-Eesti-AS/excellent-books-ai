"""A report date goes out in the form the ERP reads for that FIELD.

The report action (`ExcellentAPI.hal`, `ParseReportSpecValues`) decides by the spec field's
NAME: one ending in "Date" (`sStartDate`, `sEndDate`, `RegDate`) is parsed as YYYY-MM-DD, a
format hard-coded there, so ISO is right on every customer's ERP. Every other field (`d1`, `d2`)
is handed over as text and read in the system date format, `SysFormatBlock`, which the customer
sets. Measured 2026-10-02 on the demo (`docs/erp-report-api.md` section 2): a wrong form is read
as another date at HTTP 200 with a plausible report. The Stock List "on 2025-12-31" was the
stock of 20.12.1931; `RegDate` given as 01.03.2026 was read as 26.02.1900.

So the model may write a date either as ISO or the way the ERP prints it, and this module sends
each field the form its own branch reads. The system format is read from `SysFormatBlock` (two
named fields, over REST) only when a value needs it, and kept for the session. Text with digits
that is not a date is refused, never sent: sent raw, it is read as some other date. Without the
format, a value that needs it is refused rather than guessed, and the refusal never suggests
leaving the field out — blank is today, so "the stock on 31.12.2025" would get today's.

The day and month are always two digits and the year four, the shape the API itself states
(`GetDateFormat`, printed by its login action), whatever the block's leading-zero settings say.
Only `dateOrder` and `dateSep` are read; the demo's settings are the only ones measured.
"""
from __future__ import annotations

import datetime
import re
from typing import Callable, Optional, Union

FIELDS = ("dateOrder", "dateSep")
ORDERS = {0: "mdy", 1: "dmy", 2: "ymd"}       # SysFormatBlock.dateOrder

# An ISO date, optionally with a time after it (the time is not the ERP's to read here).
_ISO = re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ]\S.*)?$")
_ISO_DAY = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_LEAF = re.compile(r"<(dateOrder|dateSep)>([^<]*)</\1>")

Format = Optional[dict]
FormatSource = Union[Format, Callable[[], Format]]


def is_iso_field(name: str) -> bool:
    """The report action's own test: `right(spec,4)=="Date"`."""
    return name.endswith("Date")


def erp_format(session) -> Format:
    """`{"order": 0|1|2, "sep": "."}` from the ERP's `SysFormatBlock`, or None when its answer
    carries no usable format.

    Any answer is kept on the session, a format or "none": a 401 here costs a Basic re-login,
    and asking on every report would repeat it each time. A failure to REACH the ERP (OSError,
    ErpError) is not an answer — it propagates, so the caller says the ERP was unreachable, and
    the next report asks again: the server's session lives as long as the process."""
    cached = getattr(session, "_erp_date_format", None)
    if cached is not None:
        return cached or None
    if not hasattr(session, "rest_get"):
        return None
    response = session.rest_get("/SysFormatBlock", timeout=20, fields=",".join(FIELDS))
    found = False
    if response.status == 200:
        leaves = dict(_LEAF.findall(response.text))
        try:
            order = int(leaves.get("dateOrder", ""))
        except ValueError:
            order = None
        sep = leaves.get("dateSep", "")
        if order in ORDERS and len(sep) == 1:
            found = {"order": order, "sep": sep}
    try:
        session._erp_date_format = found
    except AttributeError:
        pass
    return found or None


def _resolve(fmt: FormatSource) -> Format:
    return fmt() if callable(fmt) else fmt


def _parse_erp(text: str, fmt: dict) -> Optional[tuple]:
    """(year, month, day) from the ERP's own format; None when the text is not in it."""
    parts = text.split(fmt["sep"])
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    by = dict(zip(ORDERS[fmt["order"]], (int(p) for p in parts)))
    if by["y"] < 1000:
        return None                      # a two-digit year: which century is a guess
    return by["y"], by["m"], by["d"]


def is_iso_day(value: str) -> bool:
    """Whether the text has the YYYY-MM-DD shape."""
    return _ISO_DAY.fullmatch(value) is not None


def to_wire(name: str, value, fmt: FormatSource, local: Optional[bool] = None,
            *, date_only: bool = False):
    """The value as field `name` must be sent. `fmt` is the ERP's format, or a function that
    reads it — called only when this value needs it. Raises ValueError, naming the field, for
    text that is not a date and for a value that needs the format when it is unknown.

    `local` overrides the name: True sends the ERP's own format (a register field Books stores
    as TEXT and reads as a date, QTVc `ValidUntilDate`, in a form that flips at runtime), False
    sends ISO (a register field typed M4Date whose name does not end in "Date", `UserDate1`).
    None, the report path, decides by the name. `date_only` requires YYYY-MM-DD for ISO input."""
    iso_field = is_iso_field(name) if local is None else not local
    if not isinstance(value, str) or not value.strip():
        return value
    text = value.strip()
    if not any(c.isdigit() for c in text):
        return value                     # a word, not a date: the ERP's to read
    iso = _ISO_DAY.fullmatch(text) if date_only else _ISO.match(text)
    known = None if (iso and iso_field) else _resolve(fmt)
    if iso:
        parsed = int(iso.group(1)), int(iso.group(2)), int(iso.group(3))
    elif known:
        parsed = _parse_erp(text, known)
    elif iso_field:
        raise ValueError("%s: %s cannot be read without the ERP's date format, which this "
                         "connector could not read. Write it as YYYY-MM-DD." % (name, value))
    else:
        raise _no_format(name)
    if parsed is None:
        raise ValueError("%s: %s is not a date this connector can send. Write it as YYYY-MM-DD."
                         % (name, value))
    try:
        day = datetime.date(*parsed)
    except (ValueError, OverflowError):
        raise ValueError("%s: %s is not a date" % (name, value)) from None
    if iso_field:
        return day.isoformat()
    if not known:
        raise _no_format(name)
    parts = {"d": "%02d" % day.day, "m": "%02d" % day.month, "y": "%04d" % day.year}
    return known["sep"].join(parts[c] for c in ORDERS[known["order"]])


def _no_format(name: str) -> ValueError:
    return ValueError(
        "%s: the report was not run. This field is read in the ERP's own date format, not as "
        "YYYY-MM-DD, and this connector could not read that format (SysFormatBlock), so the "
        "date cannot be sent reliably. Tell the person so; a run without the date would show "
        "today instead." % name)
