"""Reading a register directly — the fast path for a question about current state.

`sort` names the key and `range` filters on it. They are one mechanism, not two: the ERP echoes
`sort`, `key` and `range` back in the response's own `<data …>` attributes, so a call can be
checked against what the server thought it was asked. Measured on the 40 GB demo database,
`ARVc` sorted by `DueDate` over December 2025 returns all 5,611 open invoices in 0.57 s, where
`ARRn` — the report that answers the same question — times out at 90 s and does not even parse
as a table. Reports exist to compute, group and format; a support register already holds the
answer, and the ERP indexes it.

**Three narrowing parameters, and the ERP treats each one differently when it is wrong.** This
is the whole reason this module has gates rather than passing arguments through:

- **`sort` fails two different ways, and only one of them is cheap.** A name the register does
  not carry at all is HTTP 422 in 0.02 s. A field it *does* carry but is not indexed on — the
  realistic mistake, `CustName` rather than `CustCode` — **hangs**: it did not answer in 120 s
  on the demo database. So a catalogued register's key list is enforced, and every call carries
  a timeout, because "it will error quickly" turned out to be true only of the wrong half.
- **`fields` is silently lenient.** Ask for `InvoiceNr,NoSuchField,RVal` and two columns come
  back, no error. Harmless in its rows, but a column missing for that reason reads as a field
  that is empty, so an unknown name is refused rather than dropped.
- **`filter.` is silently WRONG.** `filter.NoSuchField=X` returns every row in the range as
  though it had filtered, and `filter` is NOT echoed in the response attributes, so nothing in
  the answer reveals it. That is why a server-side filter is only offered against a field list
  somebody checked — `match` needs the register catalogue, and `where` (which filters here,
  after the rows arrive) is always available instead.

A register nobody catalogued still answers, the same decision as the document template: the
tool would otherwise be useless the first time somebody asks about a register we did not think
of. What it cannot do for such a register is `match`, and it says which checks it skipped.
"""
from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Optional

import yaml

from . import control, privacy, register_fields, remote_catalog, reports
from .erp import data_attrs, list_lines, list_records

MAX_ROWS = 200
# The page when nothing was filtered, summed or grouped (project review 2026-10-04, Kaupo: yes).
# The overdue question read 200 rows of ARVc, 44,985 chars, and took 12-15 s against 4-6 s for
# answers of 2k chars; a page of 50 with the count, and a hint to sum or group, answers it.
PAGE_ROWS = 50
PAGE_HINT = ("Showing %d of %d rows. Do not page through them: sum=[...] totals every row, and "
             "group_by=<field> answers \"by customer\" or \"by supplier\" in one call. Pass "
             "max_rows only when the person asked to see the rows themselves.")
# Past this the call has stopped being the cheap one this module is for. The rows are already
# in memory, so the totals stay true; the note is what changes.
CEILING = 20000
# A floor under the hang above. Long enough for the slowest measured good call (1.82 s
# untrimmed over 5,611 records) with room to spare, short enough to be an answer.
TIMEOUT = 60.0

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,31}$")
_cache: dict = {}

# A register a model reaches for that answers with nothing, and where the answer lives instead.
# VEVc answers HTTP 200 and no records on the demo (a made-up register answers 404), and a
# supplier lookup spent up to five of its eight calls there (speed repeat runs, 2026-09-30).
# Said only when it came back empty, so a database that does use it is not contradicted.
# Pointed at the purchase registers, where `VEName` finds a supplier and its VECode in one call.
EMPTY_HERE = {
    "VEVc": ("VEVc returned no records. Suppliers are contacts, and the purchase registers carry "
             "the supplier's name: find_records on APVc (open purchase invoices) or VIVc (all "
             "purchase invoices) with where={\"VEName\": \"contains:<part of the name>\"} gives "
             "its VECode in one call."),
}


# -- the span, and the two different ways it loses records -------------------------------------
#
# Measured on the demo 2026-09-16, three repeats of every call. A `range` costs records in two
# unrelated ways, and only one of them leaves a trace in the response:
#
#   A. THE ERP SUBSTITUTES A SPAN IT CAN READ. `range` is parsed in the key's own type, and a
#      span that does not parse is replaced rather than refused — HTTP 200 throughout:
#
#        sort=DueDate    range=0:zzzzzzzz  -> echoed 2026-09-01:2026-09-16     0 of 2210
#        sort=DueDate    range=abc:def     -> echoed 2026-09-16:2026-09-16     0 of 2210
#        sort=SerNr      range=0:zzzzzzzz  -> echoed 0:0                       0 of 200
#        sort=SerNr      range=2020-01-01:2030-12-31 -> echoed 2020:2030       0 of 200
#        sort=TransDate  range=0:zzzzzzzz  -> echoed 2026-09-01:2026-09-16    72 of 200
#
#      The last is the dangerous one: 72 is a plausible answer, and it answers a question
#      nobody asked. The substitute is visible in the `<data …>` echo, so it is checkable.
#
#   B. THE SPAN IS HONOURED AND RECORDS STILL FALL OUTSIDE IT. Echoed verbatim, and short:
#
#        ARVc sort=CustCode      range=0:zzzzzzzz  ->  2197 of 2210  (3,761.28 of receivables)
#        ItemStatusVc sort=Code  range=0:zzzzzzzz  ->   125 of 130
#
#      No endpoint pair fixes this. A span ending at U+FFFF loses the same 13,
#      one starting at '!' loses 2, and 0x01 to U+10FFFF returns exactly those 2
#      and loses the other 2,208. The ERP's collation is not code-point order and cannot be
#      reasoned about from here.
#
# So B is answered before the call rather than after it: a span that MEANS "everything" is a
# model writing "no filter", not a customer band, and it is dropped. An unranged read is
# complete, and measured it is not slower — ARVc unranged 0.09 s against 0.10 s for the span.
# A deliberate narrowing is still sent, because a person who asks for C000001:C000050 wants
# C000001:C000050. A is answered by reading the echo and refusing rows from the wrong question.

_OPEN_LOW = re.compile(r"^0*1?$")           # "", "0", "1", "00000000" — a model writing "from
                                            # the beginning". A real code never looks like this.


def _open_high(bound: str) -> bool:
    """An upper bound that means "to the end": empty, a run of z/Z/9, or a top code point."""
    if bound == "":
        return True
    if len(bound) >= 4 and (set(bound) <= set("z") or set(bound) <= set("Z")
                            or set(bound) <= set("9")):
        return True
    return len(bound) == 1 and ord(bound) >= 0xFFF0


def is_catch_all(span: str) -> bool:
    """Does this span mean "the whole register"? Then it is not a span.

    Deliberately asymmetric: a false positive costs one unranged read, which is complete and
    measured no slower. A false negative leaves the caller the narrowing they asked for. Being
    wrong here can make the answer slower; it cannot make it short.
    """
    if not span or ":" not in span:
        return False                        # a bare value is an exact match — the ERP expands
    low, _, high = span.partition(":")
    return bool(_OPEN_LOW.match(low.strip())) and _open_high(high.strip())


# A start date no business record needs: a model writing "from the beginning" as a date.
# Measured 2026-10-04 (the bench's correctness check): e01 sent DueDate 2000-01-01:<yesterday>
# and lost 3 of 2,212 overdue invoices, the three with no due date, which sort before every date.
_GUESSED_START = re.compile(r"^([01]\d\d\d|2000)-\d\d-\d\d$")


# Where a blank date belongs in an open-start answer: the due date of an OPEN invoice (an
# invoice with no due date is still owed; the documented overdue rule is range=":<yesterday>").
# Nowhere else: on ORVc PlanShipDate 152 of 171 orders have no planned date, and dropping a
# guessed start there ADDED them to "planned before X" (the SVOVc/ORVc agent, 2026-10-04).
BLANK_DATES_BELONG = {("ARVc", "DueDate"), ("APVc", "DueDate")}
# Where a blank date means "not set" and must NOT come with an open start: the planned date of an
# order. ":X" on ORVc PlanShipDate returned 173 orders, 154 of them with no planned date; with a
# real lower bound (1900-01-01:X) the ERP returned the 19 that have one (measured 2026-10-04,
# order-register review M1). An open start there is rewritten to that bound, and said.
BLANK_MEANS_UNSET = {("ORVc", "PlanShipDate"), ("SVOVc", "PlanShipDate")}
LOWEST_DATE = "1900-01-01"
CURRENCY_NOUNS = {"ORVc": "orders", "SVOVc": "service orders"}


def guessed_start(sort: str, span: str, register: str = "") -> bool:
    """Does this span start on a date that only means "from the start"? Then the start goes.
    Only on the keys of BLANK_DATES_BELONG, and only when the span reaches past 2000:
    "2000-01-01:2000-12-31" is a question about 2000 (re-review 04.10, S4)."""
    if (str(register or ""), str(sort or "")) not in BLANK_DATES_BELONG:
        return False
    low, sep, high = str(span or "").partition(":")
    low, high = low.strip(), high.strip()
    return bool(sep) and bool(_GUESSED_START.match(low)) and (not high or high[:4] > "2000")


def _same_span(asked: str, echoed: str) -> bool:
    """`range=9906` comes back as `9906:9906` — the ERP's own expansion, not a substitution.
    Reading that as one would refuse every exact-value lookup."""
    expand = lambda s: s if ":" in s else "%s:%s" % (s, s)
    return expand(asked.strip()) == expand(echoed.strip())


def _rule_fields(rule: dict) -> set:
    return set(rule.get("keep") or {}) | set(rule.get("drop") or {}) | \
        set(rule.get("negative_when") or {}) | ({rule["serial"]} if rule.get("serial") else set())


# The OK box: OKFlag on invoices, DoneFlag on payments (Kaupo, 2026-10-01).
CONFIRMED_BY = {"OKFlag", "DoneFlag"}
# A note names what it left out by number up to this many; past it, a count only.
NAMED_UP_TO = 5


_LAST_WORD = re.compile(r"[A-Z][a-z0-9]*$")


def _missing_why(register: str, entry: dict, missing: list, allowed: set) -> str:
    """Why a where, sum or group on `missing` was refused, and where to look instead: the
    register file's own pointer (`elsewhere`), else its fields ending in the same word —
    `CustName` on APVc is `VEName` there."""
    hints = []
    for name in missing:
        pointer = (entry.get("elsewhere") or {}).get(name)
        tail = _LAST_WORD.search(str(name))
        alike = sorted(f for f in allowed if tail and f != name and f.endswith(tail.group(0)))
        if pointer:
            hints.append(pointer)
        elif alike:
            hints.append("For %s, the nearest here: %s." % (name, ", ".join(alike)))
    # "Catalogued": the ERP may have the field (SVOVc TotCost does), this connector does not read
    # it, and "has no field" told the model it does not exist (order-register review N6).
    return ("%s has no catalogued field %s, so the register was not read: a where, sum or group "
            "on it could match nothing. %s" % (register, ", ".join(missing), " ".join(hints))).strip()


def _clear(names) -> list:
    """Names that may be shown in an error or a note: never a secret-named one."""
    return [n for n in names if not privacy.is_secret_field(n)]


def _not_declared(register: str, declared: dict, asked: list,
                  entry: Optional[dict] = None, known: Optional[set] = None) -> Optional[dict]:
    """The refusal for a name this customer's ERP does not declare (register_fields.py), or
    None. Uncatalogued: the nearest declared names and how many there are, never the whole list
    (IVVc declares over 400). Catalogued: the catalogued fields this ERP does declare."""
    have = register_fields.names(declared)
    missing = [n for n in dict.fromkeys(asked) if n and n not in have]
    if not missing:
        return None
    answer = {"error": "unknown_field", "register": register, "unknown": missing}
    if entry is None:
        close = register_fields.closest(missing, declared)
        answer.update(did_you_mean=close, declared_fields=len(have), why=(
            "%s has no field %s on this ERP: its own Export/Import Format listing declares %d "
            "fields for %s, none by that name. The ERP drops an unknown name from `fields` without "
            "saying so and ignores a filter on one, returning everything, so the register was not "
            "read.%s" % (register, ", ".join(missing), len(have), register,
                         " did_you_mean lists the nearest names it does declare." if close else "")))
        return answer
    usable = sorted(set(known or ()) & have)
    answer.update(fields=_clear(usable),
                  did_you_mean=register_fields.closest(missing, {"header": usable}), why=(
                      "%s is in this connector's catalogue of %s, but this ERP's own Export/Import "
                      "Format listing does not declare it (another Books version): the ERP would "
                      "drop it from `fields` without a word and ignore a filter on it, so the "
                      "register was not read." % (", ".join(missing), register)))
    return answer


def _left_out(rows: list, what: str, serial: str = "SerNr") -> str:
    """How many records `rows` are — a record read by line is several rows — and which, when
    few: "1 unconfirmed (702)", "7 unconfirmed"."""
    numbers = list(dict.fromkeys(str(r.get(serial) or "") for r in rows))
    if not all(numbers):
        return "%d %s" % (len(rows), what)
    if len(numbers) <= NAMED_UP_TO:
        return "%d %s (%s)" % (len(numbers), what, ", ".join(numbers))
    return "%d %s" % (len(numbers), what)


def apply_count_rule(rows: list, rule: dict, callers: set) -> tuple:
    """Rows as the ERP counts them, plus a note saying what that took.

    `rule` comes from the register's YAML (`count_rule`). A field the caller filters on
    themselves (a `where`, or the key of a span) is left alone, so "which invoices are not
    confirmed" still has an answer. Stored-positive amounts are turned negative here, rows and
    totals alike, so a total over the result is a total the reader can use.
    """
    keep = {f: set(v) for f, v in (rule.get("keep") or {}).items() if f not in callers}
    drop = {f: set(v) for f, v in (rule.get("drop") or {}).items() if f not in callers}
    negative = {f: set(v) for f, v in (rule.get("negative_when") or {}).items()}
    left_out = {"unconfirmed": [], "invalidated": [], "of another kind": []}
    kept = []
    for row in rows:
        if any(str(row.get(f) or "") in values for f, values in drop.items()):
            left_out["invalidated"].append(row)
            continue
        missing = [f for f, values in keep.items() if str(row.get(f) or "") not in values]
        if missing:
            left_out["unconfirmed" if CONFIRMED_BY & set(missing) else "of another kind"] \
                .append(row)
            continue
        if any(str(row.get(f) or "") in values for f, values in negative.items()):
            row = dict(row)
            for field in rule.get("negative_fields") or []:
                number = reports._as_number(row.get(field))
                if number:
                    row[field] = "%.2f" % -number
        kept.append(row)
    said = [str(rule.get("says") or "").strip()]
    gone = ", ".join(_left_out(gone_rows, what, rule.get("serial") or "SerNr")
                     for what, gone_rows in left_out.items() if gone_rows)
    if gone:
        said.append("Left out: %s." % gone)
    return kept, " ".join(s for s in said if s)


# -- a settings block: the payment modes and their balances (Kaupo, 2026-10-01, Q4) ----------

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _balance_date(span: str):
    """The date the balances are taken at: the END of `range` ("2026-09-30", ":2026-09-30" or
    "2026-09-01:2026-09-30"), today when there is none. None when it is not a date."""
    import datetime
    end = str(span or "").split(":")[-1].strip()
    if not end:
        return datetime.date.today().isoformat()
    return end if _DATE.match(end) else None


def _balance_report(report_id: str) -> dict:
    """The catalogue entry of the report a block's balances come from, or the refusal: the same
    gate as run_report, because a fetched catalogue decides what the entry says."""
    doc = remote_catalog.report(report_id)
    if doc is None:
        return {"error": "unknown_report", "id": report_id,
                "why": "the catalogue has no %s, so the balances cannot be read." % report_id}
    return reports.gate(doc) or doc


def read_block(session, register: str, entry: dict, span: str = "",
               timeout: Optional[float] = None) -> dict:
    """A settings block read three fields wide, with each row's account balance attached.

    PMBlock: the payment modes. Kaupo, 2026-10-01: "money in the bank" is every payment-mode
    account with its balance, and one total. The balance is the last column of the Trial
    Balance at the date and the account its first — by POSITION, because the column labels
    follow the API user's language. Accounts are counted once, however many modes share one.
    """
    stopped = control.register_refusal(register)
    if stopped:
        return stopped
    date = _balance_date(span)
    if date is None:
        return {"error": "bad_date", "register": register,
                "why": ("`range` on %s is the date the balances are taken at, written "
                        "YYYY-MM-DD (e.g. \":2026-09-30\"), not %r. Leave it out for today."
                        % (register, span))}
    wanted = list(entry.get("default_fields") or [])
    response = session.rest_get("/%s" % register, timeout=timeout or TIMEOUT,
                                fields=",".join(wanted))
    if getattr(response, "status", 200) >= 400:
        return {"error": "erp_refused", "status": response.status,
                "why": "the ERP answered %s for the %s setting." % (response.status, register)}
    modes = [{f: row[f] for f in wanted if row.get(f)}
             for row in list_lines(response.body, register) if row.get("Code")]
    modes, _hidden = privacy.strip_secret_fields(modes)
    answer = {"register": register, "date": date, "modes": modes, "notes": []}
    balances = entry.get("balances") or {}
    if not balances.get("report"):
        return answer

    accounts: dict = {}
    for mode in modes:
        if mode.get("AccNr"):
            accounts.setdefault(mode["AccNr"], []).append(mode)
    doc = _balance_report(balances["report"])
    got = doc if "error" in doc else reports.run(
        doc, session, {"sStartDate": date, "sEndDate": date}, raw=True, timeout=timeout or 60.0)
    if "error" in got:
        answer.update(error=got["error"], why=got.get("why"))
        return answer
    found = {}
    for record in got["records"]:
        cells = list(record.values())
        if len(cells) >= 2:
            found[str(cells[0]).strip()] = reports._as_number(cells[-1])
    lines = [{"account": account, "payment_modes": [m["Code"] for m in group],
              "names": list(dict.fromkeys(m.get("Comment") or m["Code"] for m in group)),
              "balance": found.get(account)}
             for account, group in accounts.items()]
    unknown = [line["account"] for line in lines if line["balance"] is None]
    answer.pop("modes")                     # every mode is named in `accounts`
    answer.update(accounts=lines,
                  total=round(sum(l["balance"] for l in lines if l["balance"] is not None), 2),
                  seconds=round((getattr(response, "seconds", 0) or 0) + (got["seconds"] or 0),
                                2))
    answer["notes"].append("Every payment mode's account, each once, with its balance in %s at "
                           "%s; the total covers all of them." % (balances["report"], date))
    if unknown:
        answer["notes"].append("Not in the Trial Balance at that date, so no balance is given: "
                               "%s — nothing posted to it, or no such account." % ", ".join(unknown))
    answer["notes"].extend(entry.get("always_say") or [])
    return answer


# -- an invoice in another currency (Kaupo, 2026-10-01, Q2) ----------------------------------

SERIALS = 20            # invoice numbers named in a currency split; the count covers them all


def _currency_fields(rule: dict) -> set:
    return {rule.get("amount"), rule.get("base"), rule.get("serial"), rule.get("field")} - {None}


def _other_currency(row: dict, rule: dict) -> bool:
    """True when the record's base-currency total is not its own total, past rounding."""
    amount = reports._as_number(row.get(rule["amount"]))
    base = reports._as_number(row.get(rule["base"]))
    if base is None:
        return False            # blank only on zero-value drafts (3 of 3,803 on :4455)
    if amount is None:
        # A blank own total gives no rate: two demo orders carry BaseSum4 with Sum4 blank, and
        # converting at rate 0 zeroed their Sum1 (order-register review N3). Left as they are.
        return False
    if not amount:
        return bool(base)
    return abs(base / amount - 1) > float(rule.get("tolerance", 0.001))


def _in_base_currency(row: dict, rule: dict) -> dict:
    """The record with its amounts in the base currency: `amount` becomes `base`, every other
    converted field scales by the record's own rate, base / amount."""
    amount = reports._as_number(row.get(rule["amount"]))
    base = reports._as_number(row.get(rule["base"])) or 0.0
    ratio = base / amount if amount else 0.0
    out = dict(row)
    for field in rule.get("converts") or []:
        number = reports._as_number(row.get(field))
        if number is not None:
            out[field] = "%.2f" % (base if field == rule["amount"] else number * ratio)
    return out


def _per_currency(matched: list, field: str, sums: Optional[list], group_by: Optional[str],
                  max_rows: int, say: str = "") -> Optional[dict]:
    """For a register whose records NAME their currency and carry no base-currency amount
    (Payments: B1BankVal is blank on every demo line). There is no rate to convert at, so the
    amounts are never added across currencies: totals and groups are given per currency."""
    by: dict = {}
    for row in matched:
        by.setdefault(row.get(field) or "", []).append(row)
    if len(by) <= 1:
        return None
    totals = {code or "(blank)": reports.postprocess(part, None, None, sums, None, 1)["totals"]
              for code, part in by.items()}
    groups = []
    if group_by:
        for code, part in by.items():
            for group in reports.postprocess(part, None, None, sums, group_by, max_rows)["groups"]:
                groups.append(dict(group, currency=code or "(blank)"))
    note = ("These rows are in %d currencies (%s), and amounts in different currencies are never "
            "added together: totals_by_currency has one total per currency, and each group is "
            "one %s in one currency. Say each currency's figure separately.%s"
            % (len(by), ", ".join(sorted(code or "(blank)" for code in by)), group_by or "group",
               # The register's own word on what "(blank)" is (order-register review N4).
               (" " + " ".join(str(say).split())) if say else ""))
    return {"totals": {}, "groups": groups, "totals_by_currency": totals,
            "currency_split": {code or "(blank)": {"rows": len(part)} for code, part in by.items()},
            "note": note}


def apply_currency_rule(rows: list, rule: dict, where: Optional[dict], sums: Optional[list],
                        group_by: Optional[str], max_rows: int) -> Optional[dict]:
    """Totals and groups in ONE currency when some records are in another; None when none are.

    `rule` comes from the register's YAML (`currency_rule`). A sum over invoices in EUR, GBP
    and USD is no number at all, and nothing in it shows that it is mixed - so the records in
    another currency are converted at their own rate for the totals and groups, and the split
    says how much of the answer that was. The rows themselves are not touched.
    """
    matched = reports.postprocess(rows, None, where, None, None, len(rows) or 1)["rows"]
    if rule.get("field"):
        return _per_currency(matched, rule["field"], sums, group_by, max_rows, rule.get("say"))
    other = [r for r in matched if _other_currency(r, rule)]
    if not other:
        return None
    home = [r for r in matched if not _other_currency(r, rule)]
    converted = [_in_base_currency(r, rule) for r in other]
    whole = reports.postprocess(home + converted, None, None, sums, group_by, max_rows)
    present = [f for f in rule.get("converts") or [] if any(f in r for r in matched)]
    serial = rule.get("serial")
    noun = rule.get("noun") or "invoices"
    # Records, not lines: a by-line read carries each record once per line (review S7).
    count = (lambda rs: len({r.get(serial) for r in rs})) if serial and all(
        r.get(serial) for r in matched) else len
    split = {           # keyed by the register's own noun and counted in records, like the note
        "base_currency": {noun: count(home),
                          "totals": {f: reports._total(home, f) for f in present}},
        "other_currencies": {noun: count(other),
                             "serials": [r[serial] for r in other if r.get(serial)][:SERIALS],
                             "totals_in_base_currency": {f: reports._total(converted, f)
                                                         for f in present}},
    }
    note = ("%d of %d %s are in another currency than the base one (their %s differs "
            "from %s). Every total and group here is in the base currency: those %s were "
            "converted at their own rate, %s to %s and the other amounts in proportion. The rows "
            "show each one in its own currency, and currency_split shows the two parts.%s"
            % (count(other), count(matched), noun, rule["base"], rule["amount"], noun,
               rule["amount"],
               rule["base"], (" " + " ".join(str(rule["say"]).split())) if rule.get("say") else ""))
    return {"totals": whole["totals"], "groups": whole["groups"], "currency_split": split,
            "note": note}


def rule_of(entry: Optional[dict]) -> Optional[dict]:
    """The register's count rule, if its file declares one."""
    return (entry or {}).get("count_rule")


def _exact_value(span: str) -> str:
    """The value of a one-value span ("X" or "X:X"), or "" for a real span."""
    span = str(span or "").strip()
    if not span:
        return ""
    if ":" not in span:
        return span
    low, _, high = span.partition(":")
    return low.strip() if low.strip() and low.strip() == high.strip() else ""


def load(register: str, root: Optional[Path] = None) -> Optional[dict]:
    """The catalogue entry for a register, or None when nobody has written one. From the fetched
    catalogue (remote_catalog); `root` reads `<root>/<register>.yaml` instead (tests)."""
    if not _IDENTIFIER.match(str(register or "")):
        return None
    if root is None:
        return remote_catalog.register(register)
    key = (str(root), register)
    if key not in _cache:
        path = Path(root) / ("%s.yaml" % register)
        _cache[key] = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None
    return _cache[key]


# Open invoices sorted by due date: a span with a START (a model's guessed "from" date) leaves out
# everything due before it. One extra INDEXED read (`range=:<start-1>`, about 0.3 s; never a
# filter, which reads every record) counts what lies before, so the answer says so (bench e01).
EARLIER_NOTE_REGISTERS = {"ARVc", "APVc"}
EARLIER_TIMEOUT = 10.0
_ISO_DATE = re.compile(r"^\d{4}-\d\d-\d\d$")


def _earlier_count(session, register: str, sort: str, span: str,
                   timeout: Optional[float] = None, filtered: bool = False) -> Optional[dict]:
    """How many open invoices fall due before the span's start, or None: not applicable, or the
    extra read did not answer. It never raises: the main answer stands without it.

    Task 22 gate (Sol SHOULD): a filtered question (match, where) gets no count, because this
    read is register-wide; the count stands only when Books echoes the range and sort sent; an
    invoice with no due date (it sorts first, so the open start holds it) is counted apart."""
    if (register not in EARLIER_NOTE_REGISTERS or sort != "DueDate" or ":" not in span
            or filtered):
        return None
    start = span.partition(":")[0].strip()
    if not _ISO_DATE.match(start):
        return None                         # an open start (nothing before it) or not a date
    try:
        before = (datetime.date.fromisoformat(start) - datetime.timedelta(days=1)).isoformat()
        asked = ":" + before
        response = session.rest_get("/%s" % register,
                                    timeout=min(timeout or EARLIER_TIMEOUT, EARLIER_TIMEOUT),
                                    sort="DueDate", range=asked, fields="SerNr,DueDate")
        if getattr(response, "status", 200) >= 400:         # the status before the body
            return None
        echo = data_attrs(response.body)
        if (not echo.get("range") or not _same_span(asked, echo["range"])
                or echo.get("sort") != "DueDate"):
            # No echo or another span or key: not our count. Books 1370 echoes the sort on
            # ARVc and APVc (pkorea 2026-11-18), so a missing one is no count either.
            return None
        found = list_records(response.body, register)
    except Exception:                       # noqa: BLE001 - a timeout or a parse: say nothing
        return None
    undated = sum(1 for r in found if not str(r.get("DueDate") or "").strip())
    count = len(found) - undated
    if not count and not undated:
        return None
    note = "%d more open invoices fall due before %s" % (count, start)
    if undated:
        note += ", and %d have no due date" % undated
    out = {"count": count, "before": start, "note": note}
    if undated:
        out["undated"] = undated
    return out


def find(session, register: str, sort: str, range: str = "", fields: Optional[list] = None,
         match: Optional[dict] = None, where: Optional[dict] = None,
         sums: Optional[list] = None, max_rows: Optional[int] = None,
         root: Optional[Path] = None, timeout: Optional[float] = None,
         group_by: Optional[str] = None) -> dict:
    """One register, one key, one span — filtered, totalled, grouped and truncated here.

    `group_by` exists because of the first speed baseline (2026-09-30): "group those by
    customer and show the three largest" took 110 s and 37 turns, the model reading each
    customer's invoices with a call of its own. Grouped, the rows themselves are left out —
    the model asked for the groups, and reading 200 rows it did not ask for is time too.
    """
    # Before argument validation and before any call: a blocked register is refused for the
    # reason it is blocked, not sent back for a missing `sort`. See ebmcp/privacy.py.
    if privacy.is_blocked(register):
        return privacy.refusal(register)
    stopped = control.register_refusal(register)          # the signed control file's stop
    if stopped:
        return stopped
    # A secret-named field is neither read nor used to narrow: a `where` or a `sort` on it would
    # recover it by bisection (Kaupo, 2026-10-04: secrets are not report material).
    secret = privacy.secret_fields(list(fields or []) + list(where or {}) + list(match or {}) +
                                   list(sums or []) + [group_by]) + \
        privacy.secret_fields([sort], as_sort=True)
    if secret:
        return {"error": "secret_field", "register": str(register or ""), "fields": secret,
                "why": privacy.SECRET_FIELD_REFUSAL % ", ".join(secret)}
    if not _IDENTIFIER.match(str(register or "")):
        return {"error": "bad_register",
                "why": "%r is not a register name. Give a plain code such as ARVc or APVc."
                       % register}
    if (load(register, root) or {}).get("kind") == "block":
        # A settings block has one record and no key; its own reader, below.
        return read_block(session, register, load(register, root), range, timeout)
    if not sort or not _IDENTIFIER.match(str(sort)):
        return {"error": "no_sort",
                "why": ("`sort` names the key the ERP ranges over and there is no default. "
                        "Without it `range` fails, and a call carrying only a filter did not "
                        "answer in 120 seconds on the demo database.")}

    if fields is not None and not list(fields):
        fields = None                   # `fields=[]` is no list at all: the defaults, not every field

    entry = load(register, root)
    notes = []
    # A register file may declare `line_fields`: then a read that names one is read one row per
    # line (Payments, Q3). Both lists are the allowlist of names a caller may use.
    line_fields = dict((entry or {}).get("line_fields") or {})
    known = set((entry or {}).get("fields") or {}) | set(line_fields)
    # The fields this customer's OWN ERP declares for the register (register_fields.py, Kaupo
    # 2026-10-05), or None: cannot tell, and then everything below is as it was before it. A
    # register the listing lacks is None too: absence proves nothing, and nothing is refused for it.
    declared = register_fields.declared(session, register)
    explicit = list(fields or []) + list(where or {}) + list(sums or []) + \
        ([group_by] if group_by else []) + list(match or {})
    if entry is None and declared is not None:
        notes.append("%s is not in the register catalogue: its field names were checked against "
                     "this ERP's own Export/Import Format listing, but the key and the meaning of "
                     "each column were taken on trust." % register)
        refused = _not_declared(register, declared, explicit)
        if refused:
            return refused
        # A server-side filter on a LINE field was never measured: refused, not guessed at. Nor
        # on a packed matrix, a base64 blob (release review 10-05, M9).
        types = declared.get("types") or {}
        on_lines = [f for f in (match or {}) if f not in set(declared.get("header") or [])
                    or register_fields.PACKED in str(types.get(f) or "")]
        if on_lines:
            return {"error": "cannot_filter", "register": register, "fields": on_lines,
                    "why": ("%s is a line field of %s on this ERP, and a server-side filter on a "
                            "line field was never measured, so it is not sent. Use `where` "
                            "instead: it filters here, after the rows arrive."
                            % (", ".join(on_lines), register))}
    elif entry is None:
        notes.append("%s is not in the register catalogue, so the key, the field names and the "
                     "meaning of each column were taken on trust rather than checked." % register)

    if match:
        if entry is None and declared is None:
            return {"error": "cannot_filter",
                    "why": ("a server-side filter on %s cannot be checked against anything, and "
                            "the ERP IGNORES a filter naming a field the register does not have "
                            "— it returns every row as though it had filtered, and says nothing. "
                            "Use `where` instead: it filters here, after the rows arrive."
                            % register)}
    if match and entry is not None:
        unknown = [f for f in match if f not in entry["fields"]]
        # A server-side filter on a LINE field was never measured: refused, not guessed at.
        unknown += [f for f in match if f in line_fields and f not in unknown]
        if unknown:
            return {"error": "unknown_field", "fields": sorted(entry["fields"]),
                    "why": ("%s has no field %s. A filter on a field a register does not have is "
                            "ignored by the ERP and returns everything, so it is refused here."
                            % (register, ", ".join(sorted(unknown))))}

    # A where, sum or group on a name the catalogued register does not have read the whole
    # register only to fail afterwards — ItemStatusVc `Name` in 9 stored benchmark runs, APVc
    # `CustName` in one. Refused before the read, with where to look instead.
    if entry is not None:
        allowed = known | (_rule_fields(entry["count_rule"]) if entry.get("count_rule") else set()) \
            | (_currency_fields(entry["currency_rule"]) if entry.get("currency_rule") else set())
        asked = list(where or {}) + list(sums or []) + ([group_by] if group_by else [])
        missing = [f for f in dict.fromkeys(asked) if f not in allowed]
        if missing:
            return {"error": "unknown_field", "fields": sorted(entry["fields"]),
                    "why": _missing_why(register, entry, missing, allowed)}

    # A grouped answer leaves every row out, so only what the groups are built from is fetched
    # (the count rule adds its own below). k08 read a year of IVVc for 4.3-5.4 s with the full
    # default list, 2026-09-30. A name the register does not have keeps the old path, so it is
    # still refused as an unknown column by name. Only for a catalogued register: on any other,
    # a name only the LINES carry, or no field at all, comes back as records with no header
    # field (ORVc, fields=ArtCode,Quant, 2026-10-01), which grouped into one group "" with a
    # total of 0 instead of an error (opus review). The full read's columns refuse the name.
    grouped = list(dict.fromkeys([group_by] + list(sums or []) + list(where or {}))) \
        if group_by else []
    if fields is None and grouped and entry is not None and set(grouped) <= known:
        fields = grouped
    elif fields is None and entry:
        fields = list(entry.get("default_fields") or [])
        # What the caller filters or totals on is fetched too. Without it a `where` on a
        # catalogued field outside the defaults was refused as an unknown column, a lost turn.
        fields += [f for f in list(where or {}) + list(sums or [])
                   if f in known and f not in fields]
    elif fields and entry:
        # Named fields too: a where, sum or group on a field left out of them is fetched with
        # them, not refused as an unknown column after the read (7 stored benchmark runs).
        fields = list(fields) + [f for f in dict.fromkeys(list(where or {}) + list(sums or []) +
                                                          [group_by])
                                 if f and f in known and f not in fields]
    if fields and entry:
        unknown = [f for f in fields if f not in known]
        if unknown:
            return {"error": "unknown_field", "fields": sorted(entry["fields"]),
                    "why": ("%s has no field %s. The ERP drops an unknown name from `fields` "
                            "without saying so, which reads afterwards as a field that is empty."
                            % (register, ", ".join(sorted(unknown))))}
    if entry is not None and declared is not None:
        # The catalogue was read on the demo's build; this customer's may lack a field. One the
        # caller named is refused; a default nobody named is left out, and said.
        refused = _not_declared(register, declared, explicit, entry, known)
        if refused:
            return refused
        have = register_fields.names(declared)
        gone = [f for f in fields or [] if f not in have]
        if gone:
            fields = [f for f in fields if f in have]
            shown = _clear(gone)
            notes.append("Left out of the default fields: %s. This ERP's own Export/Import Format "
                         "listing does not declare %s (another Books version), so the ERP would "
                         "have returned %s empty." % (", ".join(shown) or "%d field(s)" % len(gone),
                                                      "it" if len(gone) == 1 else "them",
                                                      "it" if len(gone) == 1 else "them"))
    if not fields:
        notes.append("Every field of every record was transferred because no `fields` were "
                     "given: the same 5,611 records cost 1.82 s untrimmed against 0.57 s "
                     "trimmed, so the transfer is a large part of the cost.")

    if entry and sort not in (entry.get("keys") or {}):
        return {"error": "not_a_key", "keys": sorted(entry.get("keys") or {}),
                "why": ("%s is not a key %s is indexed on. Sorting on a field the register "
                        "carries but is not indexed on does not fail — it HANGS; %s did not "
                        "answer in 120 seconds. Use one of the keys listed."
                        % (sort, register, "sort=CustName on ARVc"))}
    if entry is None:
        notes.append("Nothing checked the key: sorting on a field a register carries but is "
                     "not indexed on hangs rather than failing, so this call was given a "
                     "%.0f-second timeout." % (timeout or TIMEOUT))

    span = str(range or "").strip()
    if is_catch_all(span):
        notes.append("The span %r means the whole register, so it was not sent: the ERP applies "
                     "one in the key's own type and a catch-all loses records silently — 13 of "
                     "2,210 open invoices on a code key, and all 2,210 on a date key. This read "
                     "is unranged and complete." % span)
        span = ""
    elif guessed_start(sort, span, register):
        notes.append("The start %s was dropped: it means \"from the start\", and a start date loses "
                     "the records with no date at all, which sort before every date (3 of 2,212 open "
                     "invoices on the demo). This read is from the start."
                     % span.partition(":")[0].strip())
        span = ":" + span.partition(":")[2].strip()
        if is_catch_all(span):          # "2000-01-01:" was the whole register: read unranged
            span = ""
    elif (register, sort) in BLANK_MEANS_UNSET and span.startswith(":"):
        span = LOWEST_DATE + span
        notes.append("Records with no %s are left out: an open start would bring every one of them "
                     "(154 of 173 orders on the demo have none). To see those, read without a range "
                     "and where={\"%s\": \"\"}." % (sort, sort))
    # An open invoice with no due date is in an open-start answer and counts as overdue; the answer
    # names it apart (Kaupo, 2026-10-04). The due date is fetched so a grouped read can count it.
    undated = (register, sort) in BLANK_DATES_BELONG and span.startswith(":")

    rule = (entry or {}).get("count_rule")
    crule = (entry or {}).get("currency_rule")
    if crule and register in CURRENCY_NOUNS and not crule.get("noun"):
        crule = dict(crule, noun=CURRENCY_NOUNS[register])
    by_line = bool(line_fields) and (not fields or bool(set(fields) & set(line_fields)))
    # A header amount repeats on every line: summed over a by-line read it counts each record once
    # per line (one order of 100.00 with two lines summed to 200.00; order-register review M3).
    header_sums = [f for f in (sums or []) if by_line and f not in line_fields]
    if header_sums:
        return {"error": "header_sum_on_lines",
                "why": ("%s is each %s record's own total, repeated on every line of it, so summed "
                        "over lines it would count a record once per line. Sum it without line "
                        "fields (one row per record), or sum a line field (%s)."
                        % (", ".join(header_sums), register,
                           ", ".join(sorted(line_fields)) or "none"))}
    serial = (rule_of(entry) or {}).get("serial") or "SerNr"
    exact = _exact_value(span)
    if crule and crule.get("field") and not by_line:
        # Read by header: the record's own currency, so the check never pulls the lines.
        crule = dict(crule, field=crule["header_field"]) if crule.get("header_field") else None
    count_fields = _rule_fields(rule) if rule else set()
    currency_fields = _currency_fields(crule) if crule else set()
    if declared is not None and (count_fields or currency_fields):
        have = register_fields.names(declared)
        missing = [f for f in sorted(count_fields | currency_fields) if f not in have]
        if missing:
            # Not the caller's field, so no `fields` to retry with: a retry would meet the same
            # refusal (Task 22 gate, opus C SF6; memory "instruction rules need a stop condition").
            return {"error": "rule_field_missing", "register": register, "unknown": missing,
                    "why": ("%s's counting or currency rule needs %s, which this ERP's own "
                            "Export/Import Format listing does not declare (another Books "
                            "version), so %s cannot be counted or totalled correctly here. Do "
                            "not retry with other fields: use a report for this question."
                            % (register, ", ".join(missing), register))}
    params = {"sort": sort}
    if span:
        params["range"] = span
    if fields:
        # The rule needs its own fields whatever the caller asked to see.
        sent = list(fields) + sorted(count_fields - set(fields))
        # And the currency check's own (header-only) fields, whatever was asked.
        sent += sorted(currency_fields - set(sent))
        # The key itself on an exact-value read (to check the rows) or an undated count, and the
        # serial on a grouped by-line read (to count records, not lines).
        sent += [f for f in ([sort] if exact or undated else []) +
                 ([serial] if by_line and group_by else [])
                 if f and f not in sent and f in known]
        params["fields"] = ",".join(sent)
    for field, value in (match or {}).items():
        params["filter.%s" % field] = value

    response = session.rest_get("/%s" % register, timeout=timeout or TIMEOUT, **params)
    if getattr(response, "status", 200) == 422:
        return {"error": "bad_key", "keys": sorted((entry or {}).get("keys") or {}),
                "why": ("the ERP refused %r as a key for %s. `sort` must name a field the "
                        "register is indexed on, not any field it carries."
                        % (sort, register))}
    if getattr(response, "status", 200) >= 400:
        return {"error": "erp_refused", "status": response.status,
                "why": "the ERP answered %s for this register read." % response.status}

    # What the server thought it was asked. A substituted span or key answers a different
    # question with an HTTP 200, and the rows look like an answer — so they are not returned.
    echo = data_attrs(response.body)
    if echo.get("sort") and echo["sort"] != sort:
        return {"error": "sort_replaced", "asked": sort, "used": echo["sort"],
                "why": ("the ERP sorted %s on %r, not the %r that was asked for. A different key "
                        "is a different order, and with a span a different set of records."
                        % (register, echo["sort"], sort))}
    if span and "range" not in echo:
        notes.append("The ERP did not say which span it used. It normally echoes `range` back, "
                     "and a span it cannot read in the key's own type is SUBSTITUTED rather "
                     "than refused — so this count could not be verified against the request.")
    elif span and not _same_span(span, echo["range"]):
        return {"error": "range_replaced", "asked": span, "used": echo["range"],
                "why": ("the ERP could not read %r as a span over %s and used %r instead — it "
                        "substitutes rather than refusing, and answers HTTP 200. The records it "
                        "returned are the answer to a different question, so they are not shown. "
                        "Give the span in the key's own type (a date key wants dates, a serial "
                        "key wants numbers), or leave `range` out to read the whole register."
                        % (span, sort, echo["range"]))}
    elif not span and echo.get("range"):
        return {"error": "range_replaced", "asked": "", "used": echo["range"],
                "why": ("no span was sent and the ERP narrowed to %r on its own. The count would "
                        "read as the whole register and is not." % echo["range"])}

    rows = list_lines(response.body, register) if by_line else \
        list_records(response.body, register)
    rows, hidden = privacy.strip_secret_fields(rows)
    if hidden:
        notes.append("%d stored secret%s (password, token or key fields) left out: they are not "
                     "report material." % (hidden, "s" if hidden != 1 else ""))
    if by_line:
        notes.append("One row per line of each %s record, its own fields repeated on every line "
                     "— count the records by their number, not by rows." % register)
    if not rows and register in EMPTY_HERE:
        notes.append(EMPTY_HERE[register])
    # An exact value the ERP could not match is answered with its nearest records: ORVc
    # CustOrdNr "ZZPROBE-OR1" returned the order whose number is "test123" (review S5).
    if exact and rows and any(sort in r for r in rows):
        wanted = exact.strip().casefold()
        kept = [r for r in rows if str(r.get(sort, "")).strip().casefold() == wanted]
        if len(kept) != len(rows):
            notes.append("%d record(s) the ERP returned for %s=%s carry another value and are left "
                          "out: it answers a value it cannot match with its nearest records."
                          % (len(rows) - len(kept), sort, exact))
        rows = kept
    # A catalogued field no record carries is blank on all of them, not a missing column: an
    # undelivered order has no Shipd2 on any line (review S1).
    if entry and rows:
        asked = list(dict.fromkeys(list(sums or []) + list(where or {}) +
                                   ([group_by] if group_by else [])))
        absent = [f for f in asked if f in known and not any(f in r for r in rows)]
        if absent:
            for r in rows:
                for f in absent:
                    r.setdefault(f, "")
            notes.append("No record here carries %s: it counts as blank, and sums to 0."
                         % ", ".join(absent))
    if rule:
        # A span on a rule field (sort=DoneFlag&range=0:0) is the caller's own choice too.
        rows, said = apply_count_rule(rows, rule, set(where or {}) | set(match or {}) |
                                      ({sort} if span else set()))
        notes.append(said)
    if len(rows) >= CEILING:
        notes.append("The span matched %d records, at or past the %d this tool is shaped for. "
                     "The totals below cover all of them, but narrow the range before asking "
                     "again." % (len(rows), CEILING))
    # `where` is applied here, to the values the ERP holds.
    read_any = bool(rows)
    if where and rows:
        try:            # sums and group_by checked over the rows READ, not the matched ones (MF1)
            rows = reports.postprocess(rows, None, where, sums, group_by or None, len(rows))["rows"]
        except reports.SpecError as bad:
            return {"error": "unknown_column", "why": str(bad)}
        # The parser keeps only filled values: a field every matched row leaves blank (nothing of
        # this customer's delivered: Shipd2) is blank, and sums to 0 (re-review MF1).
        for f in list(sums or []) + ([group_by] if group_by else []):
            if rows and not any(f in r for r in rows):
                for r in rows:
                    r.setdefault(f, "")
    no_due_date = 0
    if undated and rows:
        no_due_date = sum(1 for r in rows if not str(r.get(sort) or "").strip())
        if no_due_date:
            verb = "has" if no_due_date == 1 else "have"
            lead = ("The 1 invoice here has" if no_due_date == len(rows) == 1 else
                    "All %d invoices here have" % no_due_date if no_due_date == len(rows) else
                    "%d of the %d invoices here %s" % (no_due_date, len(rows), verb))
            notes.append("%s no due date. They are in this answer: an open invoice with no due date "
                         "is still owed and counts as overdue. Name them apart (\"%d of these %s no "
                         "due date\"); where={\"%s\": \"\"} lists them."
                         % (lead, no_due_date, verb, sort))

    asked_rows = max_rows
    if max_rows is None:
        max_rows = MAX_ROWS if (where or sums or group_by or match) else PAGE_ROWS
    currency = None
    try:
        shaped = reports.postprocess(rows, None, None, sums, group_by or None, max_rows) \
            if read_any else {"rows": [], "row_count_total": 0, "truncated": False, "totals": {},
                          "groups": []}
        if crule and rows:
            currency = apply_currency_rule(rows, crule, None, sums, group_by or None, max_rows)
    except reports.SpecError as bad:
        return {"error": "unknown_column", "why": str(bad)}
    if currency:
        shaped["totals"], shaped["groups"] = currency["totals"], currency["groups"]
        notes.append(currency["note"])
    if currency and "totals_by_currency" in currency:
        shaped["totals_by_currency"] = currency["totals_by_currency"]

    if not group_by:                # a grouped answer carries no rows to budget (re-review N9)
        shaped = reports.fit_budget(shaped, narrow="where, fields, sum or group_by")
    if "budget_note" in shaped:
        notes.append(shaped.pop("budget_note"))
    elif shaped["truncated"] and asked_rows is None and not group_by:
        notes.append(PAGE_HINT % (len(shaped["rows"]), shaped["row_count_total"]))
    notes.extend((entry or {}).get("always_say") or [])
    earlier = _earlier_count(session, register, sort, span, timeout,
                             filtered=bool(match or where))
    answer = {"register": register, "sort": sort, "range": span,
              "seconds": getattr(response, "seconds", None),
              "fields": fields or [],
              "rows": shaped["rows"], "row_count_total": shaped["row_count_total"],
              "truncated": shaped["truncated"], "totals": shaped["totals"],
              "notes": notes}
    if no_due_date:
        answer["no_due_date"] = no_due_date
    if earlier:
        answer["earlier"] = earlier
    if currency:
        answer["currency_split"] = currency["currency_split"]
        if "totals_by_currency" in shaped:
            answer["totals_by_currency"] = shaped["totals_by_currency"]
    if group_by:
        # Largest first by the first summed field, so "the three largest" is the first three.
        first = (sums or [None])[0]
        groups = sorted(shaped["groups"], key=lambda g: (-(g["sums"].get(first) or 0.0)
                                                          if first else -g["count"], str(g["key"])))
        if by_line:
            # A group's count is lines; `records` is how many distinct records they belong to.
            serials: dict = {}
            for r in rows:                  # the rows `where` matched, above
                key = r.get(group_by)
                serials.setdefault("" if key is None else key, set()).add(r.get(serial))
            for g in groups:
                g["records"] = len(serials.get(g["key"], ()))
            notes.append("On a by-line read a group's count is its lines; `records` is how many "
                         "%s records they belong to." % register)
        answer.update(rows=[], groups=groups[:max_rows], groups_total=len(groups),
                      truncated=len(groups) > max_rows)
        notes.append("Grouped by %s, largest first%s; the rows themselves are left out. Call "
                     "again without group_by to see them." % (group_by, " by %s" % first if first
                                                              else " by count"))
    return answer
