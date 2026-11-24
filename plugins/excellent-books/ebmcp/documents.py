"""One template for every Excellent Books document.

Quotations, orders, invoices, purchase invoices, goods receipts, deliveries, transactions.
Not a list of special cases: the page is built from what the register actually carries, so a
register nobody listed still renders, named by its own code.

Six were measured on the demo database and they differ in exactly three ways:

- **the key.** `SerNr` everywhere except `TRVc`, which carries `Number`. Asking `TRVc` for a
  `SerNr` returns one empty element per record rather than an error, so it counts correctly by
  accident and transfers nothing.
- **the other party.** `CustCode`/`Addr0` on the sales side, `VECode`/`VEName` on the purchase
  side, neither on a transaction.
- **the line.** An item line (`ArtCode`, `Quant`, `Price`) on invoices, orders, receipts and
  deliveries; an account line (`AccNumber`, `Comment`) on purchase invoices and transactions.
  Printing empty Kogus and Ühikuhind headings on an account document would tell the reader the
  data is missing rather than absent, so a column appears only when a line fills it.

The layout follows the Books invoice window rather than a printed invoice. Consultants already
read that window, and a printout implies a document fit to send a customer — which this is not,
having no logo, terms or bank details. The window also shows what a printout hides: payment
terms, salesman, objects, the OK flag.

The HTML is self-contained, with no fonts, scripts or images to fetch, because it is handed to
a client to display and nothing can be assumed about where it ends up.
"""
from __future__ import annotations

import re
from typing import Optional

from . import control, privacy
from .erp import unescape as _unescape

MAX_DOCUMENTS = 3
# A 199-line order renders 45 KB of HTML and carries 199 rows into the model's context. The
# document stays whole: `line_count` is the true figure, `lines_omitted` says what was cut, and
# `max_lines` raises the cap for the caller who genuinely wants every line.
MAX_LINES = 50
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,31}$")
_FIELD = re.compile(r"<([A-Za-z0-9_]+)>([^<]*)</\1>")

KINDS = {
    "IVVc": ("Arve", "Sales invoice"),
    "ORVc": ("Tellimus", "Sales order"),
    "QTVc": ("Pakkumine", "Quotation"),
    "VIVc": ("Ostuarve", "Purchase invoice"),
    "PUVc": ("Laosissetulek", "Goods receipt"),
    "SHVc": ("Lähetus", "Delivery"),
    "TRVc": ("Kanne", "Transaction"),
    "IPVc": ("Laekumine", "Receipt"),
    "PPVc": ("Väljamakse", "Personnel payment"),   # Expenses module: advances and expense refunds
}

# SerNr unless the register says otherwise.
KEYS = {"TRVc": "Number"}

# A key that restarts in every sub-system does not name a record on its own. TRVc's Number
# series begins at 1 again for each register that posts into it, so "transaction 1000" is
# several different transactions and `IntYc` says which one. Addressed as "IVVc:1000" or
# "201:1000"; a bare number is answered only when exactly one sub-system carries it.
SUB_KEYS = {"TRVc": "IntYc"}
# TRVc cannot be ranged on its own number: `sort=Number` is HTTP 422. It is reachable two ways
# and they are 120x apart, measured on the demo database looking up Number 2161:
#   sort=IntYc&range=<sub>:<sub>&filter.Number=N      30.07 s  — needs the sub-system
#   sort=TransDate&range=<day>:<day>&filter.Number=N   0.25 s  — needs the date, and finds
#                                                               every sub-system at once
# Over the whole IntYc span (200:299) it does not finish at all. So a transaction is asked for
# by sub-system or by date, and a bare number is refused with both ways out.
RANGE_KEY = {"TRVc": "TransDate"}
# research/excellent-api-and-sources.md, from Confluence ERA/3739713637. A value under 200 is a
# transaction somebody entered by hand, which belongs to no register — hence no entry here.
SUB_SYSTEMS = {"IVVc": "201", "VIVc": "203", "PUVc": "205", "SHVc": "206"}

# Whose document is it. First pair present wins.
PARTIES = [("CustCode", "Addr0", "Klient"), ("VECode", "VEName", "Tarnija"),
           ("CUCode", "CUName", "Klient")]

# The Books window's own wording, for the fields worth showing above the grid.
HEADER_LABELS = {
    "IntYc": "Alamsüsteem",
    "InvDate": "Arve kp.", "OrdDate": "Tellimuse kp.", "TransDate": "Kande kp.",
    "RegDate": "Kirjendatud", "PayDate": "Laekumistähtaeg", "DueDate": "Tähtaeg",
    "PayDeal": "Tasumistingimus", "CurncyCode": "Valuuta", "Rate": "Kurss",
    "SalesMan": "Müügimees", "OurContact": "Meie esindaja", "CustContact": "Nende esindaja",
    "RefStr": "Viitenumber", "Objects": "Objektid", "ObjStr": "Objektid",
    "Location": "Ladu", "ProjNr": "Projekt", "InvoiceNr": "Tarnija arve nr",
    "OfficialSerNr": "Amet. ser.nr.", "CustOrdNr": "Kliendi tell. nr.",
    "Comment": "Kommentaar", "OKFlag": "Kinnitatud", "ShipDate": "Lähetuse kp.",
}
HEADER_ORDER = ["IntYc", "InvDate", "OrdDate", "TransDate", "RegDate", "ShipDate", "PayDeal",
                "PayDate", "DueDate", "CurncyCode", "Rate", "SalesMan", "OurContact",
                "CustContact", "RefStr", "CustOrdNr", "InvoiceNr", "OfficialSerNr",
                "Objects", "ObjStr", "Location", "ProjNr", "OKFlag", "Comment"]

# The grid, in the Books column order: Artikkel | Kogus | Nimetus | Ühikuhind | % | Summa.
ROW_COLUMNS = [
    ("ArtCode", "Artikkel", "code"), ("Quant", "Kogus", "qty"), ("Spec", "Nimetus", "text"),
    ("UnitCode", "Ühik", "text"), ("Price", "Ühikuhind", "money"), ("vRebate", "%", "qty"),
    ("AccNumber", "Konto", "code"), ("Comment", "Selgitus", "text"),
    ("Objects", "Objekt", "text"), ("VATCode", "KM", "text"), ("Sum", "Summa", "money"),
]

# Totals along the bottom, in the order Books prints them.
TOTALS = [("Sum1", "Vahesumma"), ("DiscSum", "Allahindlus"), ("Sum3", "KM"),
          ("Sum4", "KOKKU"), ("PayVal", "KOKKU"), ("RecVal", "Kokku")]

_OK = {"1": "Jah", "0": "Ei"}
# The grand total, as opposed to a subtotal. Sum1 is Vahesumma and must never be reported as
# the document's total — it is the figure before VAT.
GRAND_TOTALS = ("Sum4", "PayVal", "RecVal")


# -- the tool ---------------------------------------------------------------------------------

def show(session, register: str, numbers: list, max_lines: int = MAX_LINES,
         date: str = "") -> dict:
    """Fetch up to three documents and return both a summary to reason about and a page to read."""
    if privacy.is_blocked(register):                      # see ebmcp/privacy.py
        return privacy.refusal(register)
    if not _IDENTIFIER.match(str(register or "")):
        return {"error": "bad_register",
                "why": "%r is not a register name. Give a plain code such as IVVc or ORVc."
                       % register}
    stopped = control.register_refusal(register)          # the signed control file's stop
    if stopped:
        return stopped
    if str(register).casefold() == "cuvc":
        # A contact has no document number (SerNr), so a lookup here is a 422 from the ERP.
        return {"error": "not_a_document",
                "why": ("%s is the contact register, not a document. Read a contact with "
                        "find_records on CUVc, sort=\"Code\" and range=\"<code>:<code>\", "
                        "naming the fields you need." % register)}

    numbers = [str(n).strip() for n in (numbers or []) if str(n).strip()]
    if not numbers:
        return {"error": "no_numbers", "why": "give at least one document number"}
    if len(numbers) > MAX_DOCUMENTS:
        return {"error": "too_many",
                "why": "asked for %d documents; this renders at most %d."
                       % (len(numbers), MAX_DOCUMENTS),
                "advice": ("Rendering is for reading one document at a time. For a list, a "
                           "total, or anything across many documents, use run_report or read "
                           "the register directly with sort and range.")}

    key = KEYS.get(register, "SerNr")
    sub_key = SUB_KEYS.get(register)
    if sub_key and not date and any(_address(n)[0] in (None, _BAD) for n in numbers):
        if any(_address(n)[0] is None for n in numbers):
            return {"error": "need_sub_system_or_date",
                    "why": ("a %s number does not name a transaction on its own — the number "
                            "series starts again in every sub-system, and the register cannot "
                            "be ranged on it. Either name the register that made it "
                            "(\"IVVc:%s\"), which takes about 30 seconds, or pass the "
                            "transaction's date, which takes under a second and finds every "
                            "sub-system at once."
                            % (register, _address(numbers[0])[1]))}

    addresses = []
    for number in numbers:
        wanted, plain = _address(number) if sub_key else (None, number)
        if wanted is _BAD:
            return {"error": "bad_sub_system",
                    "why": ("%r does not name a sub-system of %s. Write the register that made "
                            "the transaction, %s, or its own code — %s:%s."
                            % (number.split(":", 1)[0], register,
                               " / ".join(sorted(SUB_SYSTEMS)), "IVVc", plain))}
        addresses.append((wanted, plain))

    found, missing, ambiguous = [], [], {}
    for wanted, plain in addresses:
        matches = _fetch(session, register, key, plain, wanted, date)
        if isinstance(matches, dict):          # the ERP refused; say that, not "not found"
            return matches
        if sub_key and wanted:
            matches = [d for d in matches if d["header"].get(sub_key) == wanted]
        if not matches:
            missing.append(plain)
        elif sub_key and len(matches) > 1:
            ambiguous[plain] = [d["header"].get(sub_key, "") for d in matches]
        else:
            found.append(matches[0])

    if ambiguous:
        # Serving the first of several is a wrong document served silently, which is worse than
        # a question. The choices are written the way they must be sent back.
        choices = ["%s:%s" % (_register_of(sub) or sub, plain)
                   for plain, subs in sorted(ambiguous.items()) for sub in subs]
        return {"error": "ambiguous", "choices": choices,
                "why": ("%s %s belongs to more than one sub-system — its Number series starts "
                        "again in each. Ask for one of the choices."
                        % (register, ", ".join(sorted(ambiguous))))}

    if not found:
        return {"error": "not_found",
                "why": "no %s document numbered %s" % (register, ", ".join(missing))}

    for doc in found:
        doc["line_count"] = len(doc["rows"])
        doc["rows"] = doc["rows"][:max(0, max_lines)]

    result = {"register": register,
              "documents": [_summary(register, key, d) for d in found],
              "html": render(register, found)}
    if missing:
        result["not_found"] = missing
    return result


_BAD = object()


def _address(number: str) -> tuple:
    """Split "IVVc:1000" or "201:1000" into the sub-system and the number itself.

    Only a register with a composite key is read this way: `range` takes `a:b` everywhere
    else, so splitting on a colon in general would turn a range into a prefix.
    """
    prefix, separator, rest = number.partition(":")
    if not separator:
        return None, number
    prefix, rest = prefix.strip(), rest.strip()
    if prefix in SUB_SYSTEMS:
        return SUB_SYSTEMS[prefix], rest
    return (prefix, rest) if prefix.isdigit() else (_BAD, rest)


def _register_of(sub_system: str) -> Optional[str]:
    return next((r for r, code in SUB_SYSTEMS.items() if code == sub_system), None)


def _fetch(session, register: str, key: str, number: str, sub: Optional[str] = None,
           date: str = ""):
    """Every record the key matches, or an error dict when the ERP refused the call.

    More than one record means the key does not identify one on its own, which is the caller's
    problem to resolve and not ours to guess at. The error dict matters as much: reading a
    non-200 as "no such document" told the user a document did not exist when the truth was
    that the ERP had rejected the key — `sort=Number` on TRVc is 422, and every lookup of a
    transaction reported not_found because of it.
    """
    range_key = RANGE_KEY.get(register)
    if range_key and date:
        params = {"sort": range_key, "range": "%s:%s" % (date, date),
                  "filter.%s" % key: number}
        timeout = 60.0
    elif range_key:
        params = {"sort": SUB_KEYS[register], "range": "%s:%s" % (sub, sub),
                  "filter.%s" % key: number}
        timeout = 120.0                        # measured at 30 s; the span is a whole sub-system
    else:
        params, timeout = {"sort": key, "range": number}, 60.0

    response = session.rest_get("/%s" % register, timeout=timeout, **params)
    status = getattr(response, "status", 200)
    if status >= 400:
        return {"error": "erp_refused", "status": status,
                "why": ("the ERP answered %s reading %s. That is the register refusing the "
                        "lookup, not a document that does not exist." % (status, register))}
    body = response.body
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
    docs = []
    for inner in re.findall(r"<%s\b[^>]*>(.*?)</%s>" % (register, register), text, re.S):
        header = {k: _unescape(v.strip()) for k, v in _FIELD.findall(inner.split("<rows", 1)[0])
                  if v.strip()}
        rows = []
        for place, (attrs, chunk) in enumerate(
                re.findall(r"<row\b([^>]*)>(.*?)</row>", inner, re.S)):
            row = {k: _unescape(v.strip()) for k, v in _FIELD.findall(chunk)
                   if v.strip() and any(k == f for f, _l, _t in ROW_COLUMNS)}
            if row:
                # The line number plan_record_change takes: the row's own rownumber + 1, so a
                # blank row skipped here does not shift the numbers after it.
                number = re.search(r"""rownumber=['"](\d+)['"]""", attrs)
                row["line"] = (int(number.group(1)) if number else place) + 1
                rows.append(row)
        docs.append({"header": header, "rows": rows})
    return docs


def _party(header: dict) -> tuple:
    for code_field, name_field, label in PARTIES:
        if header.get(code_field) or header.get(name_field):
            return header.get(code_field, ""), header.get(name_field, ""), label
    return "", "", ""


def _summary(register: str, key: str, doc: dict) -> dict:
    """What the model reads; the page is for the person."""
    header = doc["header"]
    code, name, _label = _party(header)
    total = next((_number(header[f]) for f in GRAND_TOTALS if header.get(f)), None)
    line_count = doc.get("line_count", len(doc["rows"]))
    summary = {"register": register, "number": header.get(key), "party_code": code, "party": name,
               "date": header.get("InvDate") or header.get("OrdDate") or header.get("TransDate"),
               "total": total, "line_count": line_count,
               "header": {k: v for k, v in header.items()
                          if k in HEADER_LABELS or k == key
                          or k in dict((f, l) for f, l in TOTALS)},
               "rows": doc["rows"]}
    sub_key = SUB_KEYS.get(register)
    if sub_key:
        summary["sub_system"] = header.get(sub_key)
    if line_count > len(doc["rows"]):
        summary["lines_omitted"] = line_count - len(doc["rows"])
    return summary


# -- formatting --------------------------------------------------------------------------------

def eur(value) -> str:
    """Estonian money: space thousands, decimal comma, always two decimals."""
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return "" if value is None else str(value)
    whole, _, frac = ("%.2f" % abs(amount)).partition(".")
    grouped = ""
    while len(whole) > 3:
        grouped = " " + whole[-3:] + grouped
        whole = whole[:-3]
    return ("-" if amount < 0 else "") + whole + grouped + "," + frac


def _number(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _qty(value) -> str:
    number = _number(value)
    if number is None:
        return "" if value is None else str(value)
    return str(int(number)) if number == int(number) else ("%g" % number)


def _escape(text) -> str:
    return (str("" if text is None else text).replace("&", "&amp;")
            .replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


# -- the page ----------------------------------------------------------------------------------

_CSS = """
:root{--paper:#eef1f4;--sheet:#fff;--ink:#15191f;--soft:#4d5765;--faint:#7a8490;--rule:#dbe0e7;
--strong:#aeb7c2;--accent:#14556e;--tint:#eaf1f5;--head:#f3f6f8}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--paper:#0d1115;--sheet:#151b21;
--ink:#e8edf2;--soft:#9fabb8;--faint:#76828f;--rule:#27313a;--strong:#3c4956;--accent:#6fb6d2;
--tint:#16303b;--head:#1b232b}}
:root[data-theme=dark]{--paper:#0d1115;--sheet:#151b21;--ink:#e8edf2;--soft:#9fabb8;
--faint:#76828f;--rule:#27313a;--strong:#3c4956;--accent:#6fb6d2;--tint:#16303b;--head:#1b232b}
.ebdoc-page,.ebdoc-page *{box-sizing:border-box}
.ebdoc-page{background:var(--paper);color:var(--ink);padding:16px;display:flex;
flex-direction:column;gap:18px;font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
.ebdoc{background:var(--sheet);border:1px solid var(--strong);max-width:60rem;width:100%;
margin:0 auto;display:flex;flex-direction:column}
.ebdoc-bar{display:flex;flex-wrap:wrap;gap:8px 20px;align-items:baseline;
padding:12px 16px;border-bottom:1px solid var(--strong);background:var(--head)}
.ebdoc-bar .kind{font-size:.68rem;letter-spacing:.14em;text-transform:uppercase;
color:var(--accent);font-weight:700}
.ebdoc-bar .nr{font-size:1.5rem;font-weight:600;font-variant-numeric:tabular-nums}
.ebdoc-bar .who{margin-left:auto;text-align:right;color:var(--soft);font-size:.9rem}
.ebdoc-bar .who b{color:var(--ink);font-weight:600}
.ebdoc-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));
gap:2px 18px;padding:12px 16px;border-bottom:1px solid var(--rule)}
.ebdoc-fields div{display:flex;gap:10px;align-items:baseline;
border-bottom:1px dotted var(--rule);padding:3px 0}
.ebdoc-fields dt{color:var(--soft);font-size:.82rem;min-width:8.5rem}
.ebdoc-fields dd{margin:0;font-variant-numeric:tabular-nums}
.ebdoc-grid{overflow-x:auto}
.ebdoc table{border-collapse:collapse;width:100%;min-width:34rem}
.ebdoc thead th{background:var(--tint);font-size:.68rem;letter-spacing:.08em;
text-transform:uppercase;color:var(--soft);font-weight:700;text-align:left;padding:7px 10px;
border-bottom:1px solid var(--strong);white-space:nowrap}
.ebdoc td{padding:5px 10px;border-bottom:1px solid var(--rule);vertical-align:top}
.ebdoc th.r,.ebdoc td.r{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.ebdoc td.rownr{color:var(--faint);text-align:right;width:2.4rem;
font-variant-numeric:tabular-nums}
.ebdoc td.more{color:var(--faint);font-style:italic}
.ebdoc th.rownr{width:2.4rem}
.ebdoc td.code{color:var(--accent);font-weight:500;white-space:nowrap;
font-variant-numeric:tabular-nums}
.ebdoc-sums{display:flex;justify-content:flex-end;padding:12px 16px;
border-top:1px solid var(--strong)}
.ebdoc-sums dl{display:grid;grid-template-columns:auto auto;gap:4px 24px;margin:0;
min-width:16rem}
.ebdoc-sums dt{color:var(--soft);font-size:.86rem}
.ebdoc-sums dd{margin:0;text-align:right;font-variant-numeric:tabular-nums}
.ebdoc-sums .grand dt,.ebdoc-sums .grand dd{font-weight:700;font-size:1.05rem;
border-top:1px solid var(--strong);padding-top:5px;margin-top:2px}
.ebdoc-sums .grand{display:contents}
.ebdoc-foot{padding:8px 16px;color:var(--faint);font-size:.76rem;
border-top:1px solid var(--rule)}
"""


def render(register: str, docs: list) -> str:
    return "\n".join(["<style>%s</style>" % _CSS, '<div class="ebdoc-page">']
                     + [_one(register, d) for d in docs] + ["</div>"])


def _one(register: str, doc: dict) -> str:
    header, rows = doc["header"], doc["rows"]
    line_count = doc.get("line_count", len(rows))
    key = KEYS.get(register, "SerNr")
    kind_et, kind_en = KINDS.get(register, (register, register))
    code, name, party_label = _party(header)

    out = ['<article class="ebdoc">']
    out.append('<div class="ebdoc-bar"><span class="kind">%s</span>'
               '<span class="nr">%s</span>%s</div>'
               % (_escape(kind_et), _escape(header.get(key, "")),
                  ('<span class="who">%s<br><b>%s</b> %s</span>'
                   % (_escape(party_label), _escape(name), _escape(code))) if (name or code) else ""))

    fields = []
    for field in HEADER_ORDER:
        value = header.get(field)
        if not value:
            continue
        if field == "OKFlag":
            value = _OK.get(value, value)
        elif field == "IntYc":
            register_of = _register_of(value)
            value = "%s (%s)" % (value, register_of) if register_of else value
        fields.append("<div><dt>%s</dt><dd>%s</dd></div>"
                      % (_escape(HEADER_LABELS[field]), _escape(value)))
    if fields:
        out.append('<dl class="ebdoc-fields">%s</dl>' % "".join(fields))

    columns = [c for c in ROW_COLUMNS if any(r.get(c[0]) for r in rows)]
    if columns:
        head = "".join('<th class="%s">%s</th>' % ("r" if kind in ("money", "qty") else "",
                                                   _escape(label))
                       for _f, label, kind in columns)
        body = []
        for index, row in enumerate(rows, 1):
            cells = ['<td class="rownr">%d</td>' % row.get("line", index)]
            for field, _label, kind in columns:
                value = row.get(field, "")
                if kind == "money":
                    cells.append('<td class="r">%s</td>' % _escape(eur(value)))
                elif kind == "qty":
                    cells.append('<td class="r">%s</td>' % _escape(_qty(value)))
                elif kind == "code":
                    cells.append('<td class="code">%s</td>' % _escape(value))
                else:
                    cells.append("<td>%s</td>" % _escape(value))
            body.append("<tr>%s</tr>" % "".join(cells))
        omitted = line_count - len(rows)
        if omitted > 0:
            body.append('<tr><td class="rownr"></td><td class="more" colspan="%d">'
                        "… ja veel %d rida</td></tr>" % (len(columns), omitted))
        out.append('<div class="ebdoc-grid"><table><thead><tr><th class="rownr"></th>%s</tr>'
                   "</thead><tbody>%s</tbody></table></div>" % (head, "".join(body)))

    sums, seen_grand = [], False
    for field, label in TOTALS:
        if not header.get(field) or (label == "KOKKU" and seen_grand):
            continue
        grand = label == "KOKKU"
        seen_grand = seen_grand or grand
        sums.append('<div class="%s"><dt>%s</dt><dd>%s</dd></div>'
                    % ("grand" if grand else "", _escape(label), _escape(eur(header[field]))))
    if sums:
        out.append('<div class="ebdoc-sums"><dl>%s</dl></div>' % "".join(sums))

    out.append('<div class="ebdoc-foot">%s · %s · %d rida · Excellent Books</div>'
               % (_escape(register), _escape(kind_en), line_count))
    out.append("</article>")
    return "".join(out)
