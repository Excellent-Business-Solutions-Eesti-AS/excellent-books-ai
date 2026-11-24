"""Parse what `action=report` returns.

The ERP answers with the report's own screen HTML wrapped as `<report><lang>…</lang><table>…
</table></report>` — and with `<report><lang></lang></report>`, no table at all, when there is
nothing to show. Measured layouts on the demo DB (2026-09-14):

- flat        Trial Balance: meta rows, one header row, data rows, `Group` subtotals, `Total`.
- sectioned   Balance Sheet, P&L: one-cell rows are section headings ("AKTIVA", "1. Raha ja
              pangakontod"); the header can be NARROWER than the data (P&L labels only the two
              amount columns: "Period | Accumulated").
- multiline   Transaction Journal: one record is two <tr> — a 7-cell line, then a 3-cell
              amounts line.
- blocks      Nominal Ledger: a one-cell "ACCOUNT nnnn name" row opens a block of 4/5/6-cell
              sub-rows.

Labels follow the API user's language, so nothing keys on a word except the footer labels,
and those are a list. The header is found positionally: the first row of the data width if it
carries no digits, else the last digit-free row of two or more cells before it. The catalogue's
per-report `output.layout` is the final authority; this module is the guess it starts from.

An error comes back as `<data><res errstr="…" newdata=''></res></data>` — "Access denied" for
both a rights problem and a repname the server cannot find.
"""
from __future__ import annotations

import html
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Optional

FOOTER_LABELS = {
    "total", "group", "sum", "subtotal",              # en
    "kokku", "grupp", "vahesumma", "kogukäive",       # et (Trial Balance grand total, 1370)
    "kopā", "kopa", "grupa",                          # lv
    "iš viso", "is viso", "grupė", "grupe",           # lt
    "yhteensä", "yhteensa", "ryhmä", "ryhma",         # fi
    "totalt", "gruppe",                               # no / sv
    "итого", "всего", "группа",                       # ru
}
SECTION_SEP = " › "

_DATE_LIKE = re.compile(r"^\d{1,2}[./-]\d{1,2}[./-]\d{2,4}$")
_HAS_DIGIT = re.compile(r"\d")
# an amount ends in a decimal separator plus one or two digits; an id never does
_DECIMAL_TAIL = re.compile(r"[.,]\d{1,2}$")


class ReportError(Exception):
    """A report did not come back.

    `errstr` is the ERP's own message when the failure was its error envelope
    (`<data><res errstr="..."></res></data>`), and None when it was anything else — an HTTP
    status, a body that would not parse. The DISTINCTION is what callers branch on, because the
    words are in the server's own language: an English server says "Access denied" and a Latvian
    one says "Piekluve liegta". Matching the English cost a Latvian consultant the explanation
    of what to check, and a list of translations would always be one locale behind.
    """

    def __init__(self, message, errstr=None):
        super().__init__(message)
        self.errstr = errstr


@dataclass
class Report:
    title: str
    lang: str
    meta: list
    header: list
    rows: list
    footer: list
    width: int
    sections: list = field(default_factory=list)   # one section path per data row ("" when none)
    layout: str = "flat"                            # flat | sectioned | multiline | blocks | empty
    empty: bool = False
    raw_row_count: int = 0

    def keys(self) -> list:
        """Header labels as record keys; unlabeled leading columns are named c1, c2, … because a
        narrow header labels the RIGHTMOST columns (P&L: "Period | Accumulated" over 4 cells)."""
        labels = list(self.header)
        if len(labels) < self.width:
            labels = ["c%d" % (i + 1) for i in range(self.width - len(labels))] + labels
        return _unique(labels)

    def records(self, rows: Optional[Iterable] = None, numeric: Optional[set] = None) -> list:
        """Rows as dicts. Cells that parse as numbers become floats; pass `numeric` (column
        labels) to restrict that to known amount columns."""
        keys = self.keys()
        out = []
        for row in (self.rows if rows is None else rows):
            cells = list(row) + [""] * (len(keys) - len(row))
            rec = {}
            for key, cell in zip(keys, cells):
                if numeric is not None:
                    value = to_number(cell) if key in numeric else None
                else:
                    value = to_amount(cell)
                rec[key] = cell if value is None else value
            out.append(rec)
        return out


def decode_checked(source) -> str:
    """The reply as text, or `ReportError` with `errstr` set when it is the ERP's error
    envelope. Detected by SHAPE, never by the words, which are in the server's language."""
    text = _decode(source)
    # A private key is withheld from the raw text before parsing splits it over rows, sections
    # and headings, where no masker can join its pieces again (Sol review of 03ad0bf, MUST 2).
    # Every report and the server log come through here, the log's cached read too.
    if "-----" in text:
        from . import privacy
        text = privacy.mask_key_text(text)[0]
    err = re.search(r"<res\b[^>]*\berrstr=(\"([^\"]*)\"|'([^']*)')", text)
    if err:
        found = err.group(2) if err.group(2) is not None else err.group(3)
        raise ReportError(found, errstr=found)
    return text


def parse_report(source) -> Report:
    text = decode_checked(source)

    lang_match = re.search(r"<lang>(.*?)</lang>", text, flags=re.S)
    lang = _clean(lang_match.group(1)) if lang_match else ""

    raw_rows = [_cells(tr) for tr in re.findall(r"<tr\b[^>]*>(.*?)</tr>", text, flags=re.S | re.I)]
    rows = [r for r in raw_rows if any(c for c in r)]
    if not rows:
        return Report("", lang, [], [], [], [], 0, layout="empty", empty=True, raw_row_count=len(raw_rows))

    width = _modal_width(rows)
    first_modal = next(i for i, r in enumerate(rows) if len(r) == width)
    if _looks_like_header(rows[first_modal]):
        header_at: Optional[int] = first_modal
    else:
        header_at = next((i for i in range(first_modal - 1, -1, -1)
                          if len(rows[i]) >= 2 and _looks_like_header(rows[i])), None)

    if header_at is None:
        header, meta, body = [], rows[:first_modal], rows[first_modal:]
    else:
        header, meta, body = rows[header_at], rows[:header_at], rows[header_at + 1:]

    data, sections, footer = [], [], []
    path: list = []
    previous_was_heading = False
    for r in body:
        if len(r) == 1:
            path = path + [r[0]] if previous_was_heading else [r[0]]
            previous_was_heading = True
            continue
        previous_was_heading = False
        if _is_footer(r):
            footer.append(r)
            continue
        data.append(r)
        sections.append(SECTION_SEP.join(path))

    title = meta[0][0] if meta and meta[0] and meta[0][0] else ""
    return Report(title, lang, meta, header, data, footer, width, sections,
                  _layout(data, sections), False, len(raw_rows))


def to_amount(text) -> Optional[float]:
    """`to_number`, but only for cells that are actually amounts.

    Customer 10000000 reached the model as `10000000.0`, which is not a customer number and
    would not match one if echoed into a lookup. This ERP prints money with a decimal
    separator and always two decimals ("1 549 400,00", "-6 114 199,03") and identifiers
    without one, so a cell carrying no decimal separator stays text. Arithmetic is unaffected:
    `reports.postprocess` re-parses strings whenever it totals or compares.
    """
    if text is None:
        return None
    s = str(text).replace(" ", "").replace(" ", "").strip()
    if not _DECIMAL_TAIL.search(s):
        return None
    return to_number(text)


def to_number(text) -> Optional[float]:
    """'1 234,56' → 1234.56; '1,234.56' → 1234.56; '-0,00' → 0.0; dates and words → None."""
    if text is None:
        return None
    s = str(text).replace("\xa0", "").replace(" ", "").replace(" ", "").strip()
    if not s or _DATE_LIKE.match(s):
        return None
    negative = s.startswith("-") or (s.startswith("(") and s.endswith(")"))
    s = s.strip("()-+")
    if not s or not re.fullmatch(r"[0-9.,]+", s) or not any(ch.isdigit() for ch in s):
        return None
    if "," in s and "." in s:
        decimal = "," if s.rfind(",") > s.rfind(".") else "."
        s = s.replace("." if decimal == "," else ",", "").replace(decimal, ".")
    elif "," in s:
        parts = s.split(",")
        s = parts[0] + "." + parts[1] if len(parts) == 2 else s.replace(",", "")
    elif s.count(".") > 1:
        s = s.replace(".", "")
    try:
        value = float(s)
    except ValueError:
        return None
    return -value if negative else value


# ----------------------------------------------------------------------------- helpers


def _decode(source) -> str:
    if isinstance(source, str):
        return source
    try:
        return source.decode("utf-8")
    except UnicodeDecodeError:
        return source.decode("cp1252", "replace")


def _clean(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", fragment))).strip()


def _cells(tr: str) -> list:
    return [_clean(td) for td in re.findall(r"<t[dh]\b[^>]*>(.*?)(?=<t[dh]\b|</tr>|$)", tr, flags=re.S | re.I)]


def _modal_width(rows: list) -> int:
    counts = Counter(len(r) for r in rows if len(r) >= 2)
    if not counts:
        return max(len(r) for r in rows)
    best = max(counts.values())
    return max(w for w, n in counts.items() if n == best)


def _looks_like_header(row: list) -> bool:
    """Column labels carry no digits; data lines nearly always do (a code, a date, an amount)."""
    return any(c for c in row) and not any(_HAS_DIGIT.search(c) for c in row)


def _is_footer(row: list) -> bool:
    # NFC: a decomposed "a" plus diaeresis is the same label; strip again after the colon, so
    # "Kogukäive :" is the label too (review 2026-11-17).
    first = unicodedata.normalize("NFC", row[0] if row else "")
    first = first.strip().rstrip(":").strip().lower()
    return first in FOOTER_LABELS


def _layout(data: list, sections: list) -> str:
    if not data:
        return "empty"
    widths = Counter(len(r) for r in data)
    has_sections = any(sections)
    if len(widths) >= 2:
        (w1, n1), (w2, n2) = widths.most_common(2)
        share = min(n1, n2) / len(data)
        alternates = all(len(data[i]) != len(data[i + 1]) for i in range(min(6, len(data) - 1)))
        if share >= 0.3 and alternates and not has_sections:
            return "multiline"
    if has_sections and len(widths) >= 3:
        return "blocks"
    if has_sections:
        return "sectioned"
    return "flat"


def _unique(labels: list) -> list:
    seen: Counter = Counter()
    out = []
    for label in labels:
        seen[label] += 1
        out.append(label if seen[label] == 1 else "%s (%d)" % (label, seen[label]))
    return out
