"""Reading the ERP server's own log, `hansa.log`, through `TC/inspect-hansa-log` (S8).

The report is the one place a connector can see WHY something happened on the server: the
restart at 15:38:54 on 2026-09-30 is the line `Field name not found in F4FieldNumber 1
sflags0`, followed five seconds later by `Server process running`; a create that the REST reply
half-reported is a `RecordCheckError` line naming register, field, record, error code and text.

**The reply's shape, measured on `:4455` (8.5.56.1369):** a title block, an <hr>, then one
single-cell <table> per log line, NEWEST FIRST, each line `YYYY-MM-DD HH:MM:SS (thread) text`.
The generic report parser reads that as two rows, so this entry names `reader: server_log` and
`reports.run` hands the reply here instead. `long1` is the number of kilobytes read from the
END of the file: 64 KB was the last 30 minutes, 1 MB the last 6.7 hours (10,760 lines, 4.2 s),
2 MB the last 7.4 hours on a busier evening (21,292 lines, 14.9 s);
about 45% of lines are background-thread noise (KPI recalculation, auto tasks, memory).

E-mail and IP addresses come back as the server wrote them: until 2026-10-04 they were masked;
since then personal data is the customer's own GDPR decision (Kaupo; ebmcp/privacy.py).
"""
from __future__ import annotations

import html
import re
import time
from dataclasses import dataclass
from typing import Optional

from . import control, report_html

# Every answer from the log says what it holds (Task 21 step 3). Measured 2026-11-16 (P2): a
# personal REST user without Technics reads the whole log, so Books lets anyone who may run this
# report see other people's logins. Kaupo decided: no gate, a disclosure.
LOGINS_NOTICE = ("This is the Books server's own log: it shows other users' logins, IP addresses "
                 "and some usage statistics, not only this user's. Books lets every user who may "
                 "run this report read it.")

# What an empty `long1` makes the ERP read is unmeasured, and the whole file is hundreds of
# thousands of tokens — so the connector always sends a size, and never a huge one.
DEFAULT_KB = 256
MAX_KB = 2048
# A follow-up within this long is served from the last read instead of the ERP: measured
# 2026-09-30, four follow-up calls re-read the same 2 MB at 15 s each. The log only grows at
# the top, so a read this recent still holds everything a follow-up filters for.
REUSE_SECONDS = 120
# When a time filter asks for more than the read holds, every line passes it, and the newest
# page of them is the part furthest from what was asked (300 rows, 46,858 chars, measured).
UNREACHED_ROWS = 20

HEADER = ["Time", "Thread", "Message"]
_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+\((-?\d+)\)\s?(.*)$", re.S)
_CELL = re.compile(r'<td width="100%">(.*?)</td>', re.S | re.I)


class LogReport(report_html.Report):
    """Cells stay text: `(-1)` is a thread, not a negative amount, and a pid is not a sum."""

    def records(self, rows=None, numeric=None) -> list:
        keys = self.keys()
        return [dict(zip(keys, row)) for row in (self.rows if rows is None else rows)]


def _text(cell: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", cell)).strip()


def parse(source) -> "LogReport":
    """The log as a report. Raises `report_html.ReportError` on the ERP's error envelope."""
    text = report_html.decode_checked(source)
    head, _, body = text.partition("<hr>")
    titles = [_text(s) for s in re.findall(r"<strong>(.*?)</strong>", head, re.S | re.I)]
    titles = [t for t in titles if t]

    rows = []
    for cell in _CELL.findall(body):
        line = _text(cell)
        if not line:
            continue
        m = _LINE.match(line)
        rows.append([m.group(1), m.group(2), m.group(3).strip()] if m else ["", "", line])

    report = LogReport(title=titles[0] if titles else "", lang="", meta=titles[1:],
                       header=list(HEADER), rows=rows, footer=[], width=len(HEADER),
                       layout="log", empty=not rows, raw_row_count=len(rows))
    return report


def _now() -> float:
    return time.monotonic()


@dataclass
class LogRead:
    report: LogReport
    seconds: float
    kb: int                          # what the lines cover: the reused read may be bigger
    reused_age: Optional[float]      # seconds since the reused read, None for a fresh one


def read(session, doc: dict, spec: dict, timeout: float) -> LogRead:
    """The log, from the ERP or from this connector's read of the last two minutes when that
    covered at least as much. Raises `report_html.ReportError` as `parse` does."""
    # The report's stops before every read, a reused one too (review 2026-11-18, MUST 2).
    stopped = control.report_dispatch(doc)
    if stopped:
        try:
            del session._server_log_read
        except AttributeError:
            pass
        raise control.Stopped(stopped)
    kb = spec.get("long1", SERVER_DEFAULT_KB)
    cached = getattr(session, "_server_log_read", None)
    if cached and cached["kb"] >= kb and _now() - cached["at"] <= REUSE_SECONDS:
        return LogRead(cached["report"], 0.0, cached["kb"],
                       _now() - cached["at"])
    response = session.run_report(doc["window_class"], doc["repname"], spec, timeout=timeout)
    if getattr(response, "status", 200) != 200:
        raise report_html.ReportError("the ERP answered HTTP %d" % response.status)
    report = parse(response.body)
    try:
        session._server_log_read = {"kb": kb, "at": _now(), "report": report}
    except AttributeError:           # a session that takes no attributes simply never reuses
        pass
    return LogRead(report, getattr(response, "seconds", 0.0), kb, None)


def reuse_note(got: LogRead) -> str:
    if got.reused_age is None:
        return ""
    return ("reused this connector's read of the log from %d s ago (%d KB) instead of reading it "
            "again; lines logged since then appear after two minutes." % (got.reused_age, got.kb))


def unreached_note(bound: str, shown: int) -> str:
    return ("showing only the %d oldest lines read, the ones nearest %s, oldest first, because "
            "every line read is later than that." % (shown, bound))


def forward_note(bound: str) -> str:
    return ("rows run forward from %s, oldest first, because the Time filter starts there; "
            "without a lower Time bound the newest lines come first." % bound)


# One answer's worth of log lines. A line is ~150 chars, so 300 is ~45,000 characters.
MAX_ROWS = 300


def cap_rows(max_rows: int) -> tuple:
    if max_rows > MAX_ROWS:
        return MAX_ROWS, ("returned at most %d log lines per call (asked for %d); narrow with "
                          "where to see others." % (MAX_ROWS, max_rows))
    return max_rows, ""


# Without `long1` the server reads its own default: 194,698 bytes and 1,122 lines on :4455,
# against 199,450 and 1,150 with long1=100 (2026-10-04) - about 100 KB.
SERVER_DEFAULT_KB = 100
UNSIZED_NOTE = ("read the server's own default, about the last 100 KB of the log: this connector "
                "could not confirm the size field on this ERP's version, so it did not send one "
                "and cannot read further back.")


def size(spec: dict) -> tuple:
    """The spec with `long1` bounded, and a note when the connector changed it."""
    sent = dict(spec)
    asked = sent.get("long1")
    if not asked or asked <= 0:
        sent["long1"] = DEFAULT_KB
        return sent, ("read the last %d KB of the log (no size was given). On the demo server "
                      "that is about the last hour and a half; ask for more to reach further "
                      "back." % DEFAULT_KB)
    if asked > MAX_KB:
        sent["long1"] = MAX_KB
        return sent, ("asked for %d KB; read %d KB, the most this connector reads at once "
                      "(on 2026-09-30 that was 7.4 hours of the demo server's log, read in 15 s)." % (asked, MAX_KB))
    return sent, ""


_LOWER = (">=", ">", "=", "contains:")
_TEMPLATE = "0000-01-01 00:00:00"


def lower_bound(condition) -> str | None:
    """The earliest time a `where` on Time asks for, as the text it was given, or None when the
    filter sets no lower bound (`<=`, a word search). A list takes its earliest bound."""
    if isinstance(condition, (list, tuple)):
        found = [b for b in (lower_bound(c) for c in condition) if b]
        return min(found) if found else None
    if not isinstance(condition, str):
        return None
    text = condition.strip()
    for prefix in _LOWER:
        if text.lower().startswith(prefix):
            text = text[len(prefix):].strip()
            break
    else:
        if text[:1] in "<!":
            return None
    return text if re.match(r"^\d{4}-\d\d", text) else None


def _when(text: str):
    import datetime
    full = text + _TEMPLATE[len(text):] if len(text) < len(_TEMPLATE) else text[:len(_TEMPLATE)]
    try:
        return datetime.datetime.strptime(full, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def reached(report: LogReport, bound: str | None) -> bool:
    times = [row[0] for row in report.rows if row[0]]
    return bound is None or not times or min(times)[:len(bound)] <= bound


def reread_size(kb: int, report: LogReport, bound: str | None) -> int | None:
    """A bigger read that should reach `bound`, estimated from how much time `kb` covered, or
    None when the first read reached it or is already the most this connector reads.

    Measured 2026-09-30: a model asked `Time >= 15:20` with 512 KB, which reached back only to
    the evening, so every line passed the filter and 300 rows of the wrong hours went to it.
    One more ERP read of a few seconds is cheaper than that turn."""
    if reached(report, bound) or kb >= MAX_KB:
        return None
    times = [row[0] for row in report.rows if row[0]]
    oldest, newest, target = _when(min(times)), _when(max(times)), _when(bound)
    if not (oldest and newest and target) or newest <= oldest:
        return MAX_KB
    factor = (newest - target).total_seconds() / (newest - oldest).total_seconds()
    return min(MAX_KB, max(kb * 2, int(kb * factor * 1.25) + 1))


def reach_note(report: LogReport, bound: str | None, kb: int, first_kb: int | None) -> str:
    notes = []
    if first_kb:
        notes.append("the first read (%d KB) did not reach back to %s, so the log was read again "
                     "at %d KB." % (first_kb, bound, kb))
    if not reached(report, bound):
        oldest = min(row[0] for row in report.rows if row[0])
        notes.append("the %d KB read did not reach back to %s: its oldest line is %s, so the "
                     "rows are only what happened after that. %s"
                     % (kb, bound, oldest, "That is the most this connector reads at once; the "
                        "earlier part of the log is not reachable here." if kb >= MAX_KB else
                        "Ask for a bigger long1 (at most %d)." % MAX_KB))
    return " ".join(notes)
