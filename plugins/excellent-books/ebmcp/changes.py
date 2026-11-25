"""Creating and changing any record the connector's ERP user may change, the way the Books AI
Chat does: `plan` writes nothing and returns a preview plus a single-use `plan_id`; `execute`
requires an Approved object, writes exactly that envelope and reads the record back.

Whose rights apply: the ERP user in `.env`. Books checks them on every call. What this module
adds is what no ERP right covers:

- registers that run the system are never written: every settings block (`*Block`), access and
  API registers, timed jobs and server control (a PATCH there can restart the server), job
  queues, logins and licences, histories, prepayments, and the registers Books keeps itself from
  the documents (`CLOSED` by name, `CLOSED_PATTERNS` by name pattern, `closed_reason`); nor a
  register that holds credentials (`privacy.is_blocked`);
- a posting or state tick other than the register's approval (SentOKFlag, FinnishedFlag,
  UpdStockFlag, ClosedFlag, PrelBook...: `POSTING_TICK`) is refused in any value until measured;
- field names are checked against the customer's own field listing (`register_fields`), because
  Books silently ignores a name it does not know. No listing, no plan. Secret-named fields,
  system fields (UUID, ServerSequence, SyncFlags), packed matrices and the record's own key on
  an update are refused;
- the approval is never taken off a document (its register's approval fields, `approval_fields`:
  OKFlag on most documents, OrderedFlag and DoneFlag on a supplier payment, set away from 1), and
  a document is never marked invalid; setting the approval is allowed, with a warning in the
  preview (a payment's says what that step closes, `payment_warning`); a quotation has no
  approval; OKFlag, DoneFlag and OrderedFlag are refused where they do not approve the register
  (`RESERVED_APPROVALS`), and on every line (no approval on a line is measured);
- a payment (IPVc, OPVc) is written only with the fields measured on pkorea (`PAYMENT_FIELDS`);
- a value holding a control character (a line break, a tab) is refused: the approval page could
  not show it apart from a space;
- a create without the field Books refuses it for (`REQUIRED_ON_CREATE`, a purchase-invoice line
  without its account: `REQUIRED_ON_LINE`) is refused at plan with Books' own error code, and a
  field Books drops silently (`FIELD_HINTS`, IVVc Comment) is refused with the field to use;
- nothing is deleted: there is no delete here;
- an invoice goes only to a contact marked as a customer, checked at plan and before writing,
  on an update too (the record's own contact when the change does not name one);
- a create never lands on an existing code: checked at plan and again before writing;
- an update is refused when the record changed after the preview;
- `PUVc` is closed here because a goods receipt has its own measured rules
  (plan_goods_receipt). Purchase invoice (VIVc) writes require a measured Books build at
  preview and dispatch. Payment recipes are separate (docs/2026-11-16-write-recipes.md);
- at most `MAX_ROWS` lines, refused above that rather than cut.

Lines are numbered from 1, as show_documents numbers them; the wire's row index is that minus
one. Fields go out in the previewed order, lines after the header, the approval last: field
order changes the result in Books (docs/corrections-for-other-repos.md item 7).

Measured on the demo: a successful create answers with the whole new record, `url` and number
included. A reply without the record does NOT prove a refusal: receipts.py measured a create
that answered with progress messages only and still made a correct record. So a create is
"created" only when the new record is read back, and "unverified" otherwise. A PATCH answers
with an empty document, so an update is proved only by reading the record back.
`POST /<register>/<id>` creates ANOTHER record (receipts.py): updates go out as PATCH.
`session.request` returns a 4xx/5xx as a response, so every status is checked here.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import urllib.parse
from decimal import Decimal
from typing import Optional

from . import approval, audit, control, dates, erp, privacy, register_fields, report_html, write_outcome
from .config import session_connection_id

MAX_ROWS = 200
# Header lengths from the register definition, refused at plan time on every path that writes
# the register (create_items and this module). REST stores an over-length string whole, so the
# window would cut it later (Task 8 review S4; Sol re-check 2026-11-17 MUST 6). INVc: Code M4Code
# 20, Name M4Str 100, Unittext M4Str 10, Group M4Code 5, BarCode M4Code 20, AlternativeCode
# M4Str 40 (checked 2026-11-17).
FIELD_LIMITS = {"invc": {"Code": 20, "Name": 100, "Unittext": 10, "Group": 5, "BarCode": 20,
                         "AlternativeCode": 40}}
# The fields that approve a document, per register, in wire order (Books' spelling). Measured on
# pkorea 1370 (docs/2026-11-16-write-recipes.md): a quotation has no approval; a supplier payment
# is ordered, then done (DoneFlag first is refused with 1202). A register not listed here keeps
# the global DEFAULT_APPROVAL_FIELDS: only an explicit entry narrows the checks (review M8).
APPROVAL_FIELDS = {
    "ivvc": ("OKFlag",), "orvc": ("OKFlag",), "shvc": ("OKFlag",), "povc": ("OKFlag",),
    "puvc": ("OKFlag",), "vivc": ("OKFlag",), "ipvc": ("OKFlag",),
    "opvc": ("OrderedFlag", "DoneFlag"),
    "qtvc": (),
}
DEFAULT_APPROVAL_FIELDS = ("okflag", "doneflag")      # casefolded
# Every name that approves some register. Each is refused where it does not approve the register
# and on every line: no approval on a line is measured (Sol review 2026-11-18, MUST 1 and 2).
RESERVED_APPROVALS = ("okflag", "doneflag", "orderedflag")
# Posting and state ticks that are not a register's approval (Task 22 gate, A MUST-3; Kaupo
# 2026-11-18): StockMovVc SentOKFlag sends stock out of the from-location, ProdVc FinnishedFlag
# finishes a production, UpdStockFlag moves stock on returns and cash invoices, ClosedFlag and
# PrelBook change what a document books. None was measured through REST, so each is refused in
# any value, on the header and on lines, until it is measured and added to MEASURED_TICKS as
# (register, field), casefolded. `(?<!o)ok` keeps "Book" out. The names this refuses on pkorea
# 1370 are pinned by tests/test_changes.py::test_the_posting_ticks_refused_on_1370_are_pinned.
POSTING_TICK = re.compile(r"(?<!o)ok(flag|status)?$|done(flag)?$|finn?ish(ed)?(flag)?$|updstock"
                          r"|sent(ok)?flag$|closedflag$|prelbook$|stockedflag$|transferflag$"
                          r"|confirmedflag$|approvalstatus|unok", re.I)
MEASURED_TICKS = frozenset()
# Round 2 (Kaupo 2026-11-18): on a register with a measured approval table (APPROVAL_FIELDS),
# EVERY field ending in "Flag" is refused unless it approves that register: the write recipes
# measured no other Flag as safe to send. On the other registers these state flags are refused
# too (judged from the pkorea 1370 listing: a document made from this one, a step done, sent,
# exported, received, paid, locked): InvFlag InvdFlag IVFlag ORFlag POFlag PUFlag QTFlag VIFlag
# PIFlag ShipFlag *MadeFlag ExportedFlag RejectedFlag ReceivedFlag TreatedFlag SubmittedFlag
# DeliveredFlag PaidFlag NotPaidFlag UpdatedFlag MovedFlag DeletedFlag LockedFlag StockMovFlag.
# Master-data flags (CUVc blockedFlag, OnHoldFlag; INVc Terminated) stay writable: a person
# sees them in the preview and sets them back the same way.
STATE_FLAG = re.compile(r"^(inv|invd|iv|or|po|pu|qt|vi|pi|ship)flag$|madeflag$|exportedflag$"
                        r"|rejectedflag$|receivedflag$|treatedflag$|submittedflag$"
                        r"|deliveredflag$|(not)?paidflag$|updatedflag$|movedflag$"
                        r"|deletedflag$|^lockedflag$|stockmovflag$", re.I)
# Why a register in APPROVAL_FIELDS with no approval refuses OKFlag and DoneFlag.
NO_APPROVAL = {"qtvc": "a quotation is not approved in Books: it has no OK. It is accepted or "
                       "turned into an order in Excellent Books itself."}
# Approval steps Books takes only in order: (register, field) -> (the field set first, its code).
APPROVAL_NEEDS = {("opvc", "doneflag"): ("OrderedFlag", "1202")}
PAYMENT_REGISTERS = ("ipvc", "opvc")
# The only fields a payment is written with: the draft recipes and approval steps measured on
# pkorea 1370 (write recipes sections 8 and 8b). Its other status fields (SentFlag, ExportedFlag,
# RejectedFlag, AcceptanceStatus...) were never measured and may send or change the payment.
PAYMENT_FIELDS = {
    "ipvc": {"header": ("PayMode", "Comment", "OKFlag"), "lines": ("InvoiceNr", "RecVal")},
    "opvc": {"header": ("PayMode", "PayDate", "OrderedFlag", "DoneFlag"),
             "lines": ("VISerNr", "RecVal", "Comment")},
}
# A create Books refuses without these fields, saving nothing (measured on pkorea 1370,
# docs/2026-11-16-write-recipes.md); checked at plan so the person approves nothing doomed.
REQUIRED_ON_CREATE = {"qtvc": ("CustCode",), "ivvc": ("CustCode",), "povc": ("PayDeal",),
                      "vivc": ("PayDeal",), "shvc": ("SerNr",), "opvc": ("PayDate",)}
REQUIRED_ON_LINE = {"vivc": ("AccNumber",)}       # 1010 even when the line names an item
# Books' error code and message for each missing field above.
REQUIRED_CODES = {"custcode": ("1125", "Enter Customer Code"),
                  "paydeal": ("1256", "Enter payment term"),
                  "sernr": ("1557", "Not in any defined series"),
                  "paydate": ("1053", "Enter date"),
                  "accnumber": ("1010", "Account missing")}
# A field Books accepts and silently drops on that register: refused, with the one to use.
FIELD_HINTS = {("ivvc", "Comment"): "InvComment"}
INVALID_FIELDS = ("invalid",)                  # annuls an approved document without un-OK
# Header totals Books computes from the lines: sent before the rows they lose the last row's VAT
# (PayVal/VATVal, measured on pkorea), so they go after the lines, the approval after them.
AFTER_LINES = re.compile(r"^(sum\d|basesum\d|vatval|payval)$", re.I)
SYSTEM_FIELDS = ("uuid", "serversequence", "syncflags")
KEY_FIELDS = ("sernr", "code")
# A register field Books stores as TEXT and reads as a date in a form that flips at runtime
# (docs/2026-11-16-write-recipes.md section 1, measured 2026-11-17 and 11-18 on pkorea): QTVc
# ValidUntilDate took the company form one day and ISO the next, inside one server process; a
# refused form answers 1142 and saves nothing; "" saves on every day measured; an UPDATE of it
# was refused in every form on 11-18. Decided (Kaupo, 2026-11-18, final): a create carries up to
# three bound variants of the same body, the next sent only after FALLBACK_ERROR on this field
# with no record saved: the person's date in the company form (or, with none given, the field
# left out, so Books fills its own default), the date in ISO, then the field empty. A change of
# the field on an existing record is refused.
TEXT_DATES = {"QTVc": "ValidUntilDate"}
FALLBACK_ERROR = "1142"
DEFAULT_SHOWN = "Use Books' default"     # the preview's value when the field is left out
BLANK_SHOWN = "Leave blank"              # ... and when the person gave it empty
DEFAULT_NOTE = ("left out: Excellent Books fills its own default from the quotation settings "
                "(Kehtiv kuni vaikimisi)")
BLANK_RESULT = ("The quotation was saved with a blank valid-until date: Excellent Books refused "
                "the date in every form this connector may send. Set the valid-until date in "
                "Excellent Books itself.")
# The blank variant went out but the read-back shows a date (Sol review 2026-11-18, SHOULD).
BLANK_NOT_STORED = ("The last step sent the valid-until date blank, and Excellent Books stored "
                    "%r there (as read back). Check the valid-until date in Excellent Books.")


def fallback_steps(values, company=None) -> str:
    """What the preview says about the bound variants, made from the variants themselves (Sol
    review 2026-11-18, SHOULD): None = left out, "" = blank, else the date as sent."""
    def step(value):
        if value is None:
            return "with the valid-until date left out, so Excellent Books fills its own default"
        if value == "":
            return "with the valid-until date blank"
        return "with the date as %s%s" % (value, " (the company's own way of writing dates)"
                                          if value == company else "")
    words = [step(v) for v in values]
    text = "Sent first %s." % words[0]
    for word in words[1:]:
        text += (" If Excellent Books refuses that (its error %s, which saves nothing), then %s."
                 % (FALLBACK_ERROR, word))
    return text
UPDATE_REFUSED = ("%s of an existing %s is not changed through this connector: Excellent Books "
                  "refuses that change through its API in every date form (measured 2026-11-18). "
                  "Set it in Excellent Books itself. Nothing was planned.")
DATE_TYPE = "M4Date"            # register_fields type of a real date field (sent as ISO)
# What Books itself sets on a PATCH, so the read-back after an approval does not name it as
# changed. Measured on pkorea:4455, build 8.5.56.1370, 2026-11-17 (docs/erp-register-access.md):
# OK (OKFlag 1) on an un-OK'd invoice; a line Quant change; a line added with ArtCode + Quant
# (with and without OK in the same PATCH). Only measured fields belong here. `approve_if_blank`:
# OK fills these only when they were blank at plan time (RefStr), so a filled one that changed
# is still named. `new_line`: on a line the plan adds, compared with an empty line, Books' own
# fill is left out; the plan's own fields there are checked as `not_saved`.
DERIVED = {
    "ivvc": {
        "approve": ("OKBy", "Prntdf", "RegTime"),
        "approve_if_blank": ("RefStr",),
        "line_change": {"when": ("Quant",),
                        "header": ("BaseSum4", "CalcFinRef", "RetValue", "RetnValue", "Sum1",
                                   "Sum3", "Sum4", "SumIncCom", "TotGP", "TotQty", "TransTime"),
                        "line": ("Sum", "rowGP")},
        "new_line": {"header": ("BaseSum4", "CalcFinRef", "GPProc", "RetValue", "RetnValue",
                                "Sum1", "Sum3", "Sum4", "SumIncCom", "TotGP", "TotQty",
                                "TransTime"),
                     "line": ("BasePrice", "Price", "SalesAcc", "Spec", "Sum", "UnitCode",
                              "UnitComment", "VATCode", "rowGP", "stp")},
    },
}
LINE_ONLY_REFUSED = ("stp",)                   # a line's type: Books sets it

_SETTINGS = ("{name} is a settings block. Settings, number series and access rules change how "
             "the whole company's Excellent Books works, so a person changes them in Excellent "
             "Books itself.")
_ACCESS = ("{name} holds access rights or API settings. An administrator changes them in "
           "Excellent Books itself.")
_TIMED = ("{name} holds timed jobs that run maintenance or imports on the server. They are set "
          "up in Excellent Books itself.")
_SERVER = ("{name} controls a server: a change there can restart it. It is not changed through "
           "this connector.")
_LEDGER = ("{name} is kept by Excellent Books itself from the documents (transactions, open "
           "invoices, stock status). Change the document instead, and Books updates it.")
_QUEUE = ("{name} is a queue of jobs Excellent Books carries out itself (e-mails, payments, bank "
          "requests, exports): a change there can send something out of Books. It is not changed "
          "through this connector.")
_LOGIN = ("{name} holds logins or licences. An administrator changes them in Excellent Books "
          "itself.")
_HISTORY = ("{name} is a history Excellent Books keeps itself. It is not changed through this "
            "connector.")
_SECRET = ("{name} holds credentials, keys, tokens, certificates or API settings. It is not "
           "changed through this connector; an administrator changes it in Excellent Books.")
_PREPAYMENT = ("{name} holds prepayments, which Excellent Books keeps itself from the payments. "
               "Change the payment instead, in Excellent Books.")
CLOSED = {
    "puvc": "Goods receipts go through plan_goods_receipt, which knows their own rules.",
    "accessvc": _ACCESS, "apiinterfacevc": _ACCESS,
    "timedmaintvc": _TIMED, "timedimportvc": _TIMED,
    "remotecloudservervc": _SERVER,
    "trvc": _LEDGER, "arvc": _LEDGER, "apvc": _LEDGER, "itemstatusvc": _LEDGER,
    "arpayvc": _PREPAYMENT, "appayvc": _PREPAYMENT,
    # Round 4 (Sol re-check section 3), by name where no family pattern fits safely.
    "visitedurlvc": _HISTORY,
    "acmeworkspacevc": _SECRET, "authcustvc": _SECRET, "fingerprintregvc": _SECRET,
    "x509attributesvc": _SECRET,
    "epprivvc": _ACCESS, "htsrestaccvc": _ACCESS, "acceptgroupvc": _ACCESS,
    "acceptancerulesvc": _ACCESS,
    "connectiondetailsvc": _SERVER, "dnsrecordvc": _SERVER, "fedservvc": _SERVER,
    "pop3servvc": _SERVER, "noderebuildvc": _SERVER,
    "asyncstatusvc": _TIMED, "epaymentstatusvc": _QUEUE, "excidletaskplanvc": _TIMED,
    "htsprogramrunsvc": _TIMED, "stoppedmailsvc": _QUEUE, "txservicereplyvc": _QUEUE,
    "instockvc": _LEDGER, "plannedpaymentvc": _LEDGER, "plannedpaymentsvc": _LEDGER,
    "purgetrvc": _LEDGER,
}
# The owner's W1 categories by NAME PATTERN as well (Task 22 gate, A MUST-1; Kaupo 2026-11-18):
# a hand list missed 40 such registers on pkorea 1370. Whether REST accepts a write on them is
# unmeasured, which is the reason to fail closed. `que(?!st)` is a queue (QueVc, QueueVc,
# QueuedLogActionVc), not a Request or Quest. The registers still writable on 1370 are pinned by
# tests/test_changes.py::test_the_registers_still_writable_on_1370_are_pinned.
CLOSED_PATTERNS = (
    (re.compile(r"que(?!st)", re.I), _QUEUE),
    (re.compile(r"server", re.I), _SERVER),
    (re.compile(r"^http\w*redirectvc$", re.I), _SERVER),
    (re.compile(r"^backup", re.I), _SERVER),
    (re.compile(r"login", re.I), _LOGIN),
    (re.compile(r"licen[cs]", re.I), _LOGIN),
    (re.compile(r"hist", re.I), _HISTORY),
    # Credentials (Task 22 gate round 2, Kaupo 2026-11-18): tokens, passwords, certificates,
    # keys, OAuth, secrets, credentials, two-factor, and API registers. `API(?![a-z])` is
    # case-sensitive so APInstallVc (purchase-ledger installments) stays a business register.
    # On pkorea 1370 these close (all unmeasured, none a write recipe's register):
    # token: ExcTokenVc OAuthAccessTokenVc OAuthRefreshTokenVc SingleTokenVc; passw/pwd:
    # PartnerPasswdSettingsVc PassWordVc; cert: AvalaraCertificateVc CertificateVc
    # ClientCertificateVc EPCertTypeVc EPCertVc NotificationCertificateVc WHCertificateVc; key:
    # IntEnabKeyReqVc PlKeyVc VYKeyVc; API: APIInterfaceTaskVc APIRecordTaskVc APIRecordVc API_PMVc
    # LAPITransPackageRelVc LogisticsAPITransVc LogisticsAPIVc; oauth: + OAuthClientContextVc
    # OAuthCodeVc; credential: CredentialRequestV1Vc CredentialVc CredentialsCacheV2Vc
    # CredentialsCacheVc DevCredentialVc; 2fa: Code2FAVc Congifure2FAVc Method2FAVc.
    (re.compile(r"token|passw|pwd|cert|key|oauth|secret|credential|2fa", re.I), _SECRET),
    (re.compile(r"API(?![a-z])"), _SECRET),
    # Users and access rights (Task 22 gate round 3; the owner's W1 decision 2026-11-11 closes
    # access/user/API). `User` is case-sensitive so the customer-service registers (CUService*,
    # "USer" only by case) stay open. On 1370 this closes 31 *User* and 6 *Access* registers.
    (re.compile(r"User"), _ACCESS),
    (re.compile(r"access", re.I), _ACCESS),
    # Round 4 (Sol re-check section 3; Kaupo 2026-11-18: keep the deny-list). On 1370:
    # Sess: EXCSignSessVc HWIDSessionsVc ProdPlanSessionVc WebNGPaySessionVc WebNGQSessionVc;
    # Log (not Logistics): ASPActionLogVc ChatLogVc CloudRecordLogVc DBLogVc LogActionV1Vc
    # PBXCallLogVc PerfLogVc SiteMinderUUIDLogVc UsageLogVc; His<n>Vc: ROHisVc ROHis2Vc;
    # <x>Archive: ASPArchiveVc RegArchiveVc RegArchiveDetailVc (ArchiveVc stays open); Sign/SigC:
    # BiometricSignVc ConfSignVc EXCExternalSignersVc HobSigCacheVc HobSignaturesVc (+EXCSignSess);
    # Whitelist: PBXIPWhitelistVc; AutoTask: EXCAutoTaskVc; Dated..Action: EPDatedActionsVc;
    # Web..Request: WebRequestVc; WebService: CustWebServiceVc WebServiceStatusVc WebServiceVc;
    # Cloud: CloudMachineStatsVc CloudMigrationVc CloudNodeVc CloudWatchpointVc (+CloudRecordLog);
    # Hosting: HostingCenterVc HostingConfigurationVc; LocalMachine: LocalMachineVc,
    # LocalMachineSetVc, LocalMachineIBVc, LocalMachineITLVc, LocalMachineSPVc; ^HAL: HALRecordDefVc
    # HALRulesVc; Stats: CloudMachineStatsVc SystemPressureStatsVc. The rest by name (CLOSED).
    (re.compile(r"Sess|Sig[nC]|Whitelist"), _SECRET),
    (re.compile(r"AutoTask|Dated\w*Action|Web\w*Request"), _TIMED),
    (re.compile(r"WebService|Hosting|LocalMachine|^HAL|Stats|Cloud"), _SERVER),
    (re.compile(r"Log(?!ist)|His\d*Vc$|\wArchive"), _HISTORY),
)
# An invoice needs a contact marked for that side; Books refuses it otherwise, after the person
# has already approved the preview.
CONTACT_SIDE = {"ivvc": ("custcode", "CUType", "a customer")}

# Not every OK is a ledger posting (Sol re-check 2026-11-20, SHOULD 5; write recipes sections 4
# and 5): an order's OK changes the quantities on order, a delivery's moves stock out.
APPROVE_WARNING = ("This approves the document (OK). That does what approving it in Excellent "
                   "Books does: an invoice is posted to the ledger, a delivery moves stock out, "
                   "and an order changes the quantities on order. It cannot be undone through "
                   "this connector: only a person in Excellent Books can correct it. Say this to "
                   "the person in plain words and apply only if they confirm the approval itself.")
# Measured 2026-11-17 (write recipes section 8b): an incoming payment's OK closes the customer
# invoice's open amount; ordering a supplier payment closes the supplier invoice in payables at
# once. Nothing went to a bank on pkorea, which has no bank integration.
# One sentence per approval step, in the table's order (Sol review 2026-11-18, SHOULD 1).
PAYMENT_STEPS = {
    ("ipvc", "okflag"): "This confirms an incoming payment: the customer invoice's open amount "
                        "goes down by the amount paid at once.",
    ("opvc", "orderedflag"): "This orders a supplier payment: the supplier invoice's open amount "
                             "in payables goes down at once by this payment's amount, whether "
                             "that pays it in full or in part. Where the company's bank "
                             "integration sends payments on "
                             "ordering, this may also send it to the bank.",
    ("opvc", "doneflag"): "This marks an already ordered supplier payment as done (reconciled).",
}
PAYMENT_END = ("It cannot be undone through this connector: only a person in Excellent Books can "
               "correct it. Say this to the person in plain words and apply only if they confirm "
               "this payment step itself.")


def payment_warning(register: str, header: dict) -> str:
    """The warning for the payment steps this change sets, in order."""
    setting = {k.casefold() for k, v in header.items() if v == "1"}
    steps = [PAYMENT_STEPS[(register.casefold(), f)] for f in approval_fields(register)
             if f in setting and (register.casefold(), f) in PAYMENT_STEPS]
    return " ".join(steps + [PAYMENT_END])

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,40}$")
_URL = re.compile(r"""\burl=['"]/api/[^/'"]+/([^/'"]+)/([^'"]+)['"]""")


class ChangeError(Exception):
    """A refusal the person should see; nothing was written."""
    code = "refused"


class ErpRefused(ChangeError):
    """Excellent Books answered a read with an HTTP error; nothing was written."""
    code = "erp_refused"


class VivcBuildUnverified(ChangeError):
    code = "vivc_build_unverified"


VIVC_VERIFIED_BUILDS = ("8.5.56.1370",)


def vivc_build_reason(register: Optional[str], build: Optional[str]) -> Optional[str]:
    if (register or "").casefold() == "vivc" and build not in VIVC_VERIFIED_BUILDS:
        # Only the version number of Books' own text (Astra recheck of ddce18b, NEW MUST 2).
        shown = erp.version_text(build)
        shown = shown if shown[:1].isdigit() else "unknown"
        return (f"Purchase invoice writing is unverified for Books build {shown}. "
                "Please enter the invoice in Excellent Books.")
    return None


def approval_fields(register) -> tuple:
    """The casefolded fields that approve a document of `register`, in wire order. A register
    not in APPROVAL_FIELDS keeps DEFAULT_APPROVAL_FIELDS (review 2026-11-17 M8)."""
    found = APPROVAL_FIELDS.get(str(register or "").strip().casefold())
    return DEFAULT_APPROVAL_FIELDS if found is None else tuple(f.casefold() for f in found)


def closed_reason(register) -> Optional[str]:
    """Why `register` is never written here, or None. Pinned by a test."""
    name = str(register or "").strip()
    folded = name.casefold()
    if folded.endswith("block"):
        return _SETTINGS.format(name=name)
    reason = CLOSED.get(folded) or next(
        (why for pattern, why in CLOSED_PATTERNS if pattern.search(name)), None)
    # A register name privacy reads as a secret, with or without its "Vc" (round 2).
    if not reason and (privacy.is_secret_field(name)
                       or privacy.is_secret_field(re.sub(r"Vc$", "", name))):
        reason = _SECRET
    return reason.format(name=name) if reason else None


def _flag(name: str, value: str) -> str:
    """An approval value as Books stores it, "1" or "0": 1.0, 01 and true must not post a
    document without the preview's warning."""
    word = value.strip().casefold()
    if word in ("1", "true", "yes", "on"):
        return "1"
    if word in ("", "0", "false", "no", "off"):
        return "0"
    try:
        number = float(word)
    except ValueError:
        number = None
    if number in (0.0, 1.0):
        return "1" if number else "0"
    raise ChangeError("%s is a tick box: 1 or 0, not %r." % (name, value))


def _value(value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float, str)):
        text = str(value).strip()
        if isinstance(value, float) and "e" in text:
            return format(Decimal(text), "f")
        return text
    raise ChangeError("Field values must be text or numbers.")


def _get(session, path: str, **params):
    """A REST read whose HTTP status is checked. None for 404 (no such record)."""
    response = session.rest_get(path, **params)
    status = getattr(response, "status", 200)
    if status == 404:
        return None
    if status >= 400:
        raise ErpRefused("Excellent Books answered HTTP %d when this connector read %s. Nothing "
                         "was written. %s" % (status, path.split("?")[0],
                                              "It said: %s" % erp.reply_problems(response.text)
                                              if erp.reply_problems(response.text) else ""))
    return response


def _listing(session, register: str):
    """(canonical register name, its field listing) or (register, None). Case-insensitive: the
    listing is keyed by Books' own spelling, and "ivvc" must not skip the field check."""
    entry = register_fields.declared(session, register)
    if entry:
        return register, entry
    try:
        every = register_fields.customer_registers(session) or {}
    except Exception:
        every = {}
    for name in every:
        if name.casefold() == register.casefold():
            return name, register_fields.declared(session, name)
    return register, None


def _register(register) -> str:
    name = str(register or "").strip()
    if not _NAME.match(name):
        raise ChangeError("%r is not a register name." % name)
    if privacy.is_blocked(name):
        raise ChangeError(privacy.refusal(name)["why"])
    reason = closed_reason(name)
    if reason:
        raise ChangeError(reason)
    return name


def _record_id(record_id) -> str:
    rid = str(record_id or "").strip()
    if rid and (len(rid) > 60 or any(c in rid for c in "/?#\\") or not rid.isprintable()
                or has_control(rid) or set(rid) == {"."}):
        raise ChangeError("%r is not a record number or code." % rid)
    return rid


def _lines(rows, update: bool) -> list:
    """[{"line": n from 1, field: value, ...}] in the order given."""
    out = []
    for place, row in enumerate(rows or [], 1):
        if not isinstance(row, dict):
            raise ChangeError("Each line must be a set of field names and values.")
        if "index" in row or "row" in row:
            raise ChangeError("Give the line number as \"line\", from 1, as show_documents "
                              "numbers the lines.")
        if update and "line" not in row:
            # Numbered by position they would overwrite the record's own first lines.
            raise ChangeError("To change lines of an existing record, give each line its "
                              "\"line\" number, from 1, as show_documents shows them. To add a "
                              "line, give the next free number.")
        fields = row.get("fields") if isinstance(row.get("fields"), dict) else row
        number = _value(row.get("line", place))
        if not number.isdigit() or int(number) < 1:
            raise ChangeError("A line number is a whole number from 1.")
        values = {str(k): _value(v) for k, v in fields.items() if k not in ("line", "fields")}
        out.append(dict({"line": int(number)}, **values))
    numbers = [line["line"] for line in out]
    if len(set(numbers)) != len(numbers):
        raise ChangeError("Each line number may appear once.")
    return out


def _check_names(entry, register: str, header: dict, lines: list) -> tuple:
    """Refuses what is not written here. Returns (header, lines) in Books' own spelling."""
    names = list(header) + [k for line in lines for k in line if k != "line"]
    for name in names:
        if not _NAME.match(str(name)):
            raise ChangeError("%r is not a field name." % name)
    secret = privacy.secret_fields(names)
    if secret:
        raise ChangeError("%s is a stored secret (a password, token or key) and this connector "
                          "does not write it. Change it in Excellent Books itself."
                          % ", ".join(secret))
    if not entry:
        raise ChangeError("This Excellent Books did not list the fields of %s, so the field "
                          "names cannot be checked, and Books ignores a name it does not know. "
                          "Nothing was planned. Make the change in Excellent Books itself."
                          % register)
    heads = {n.casefold(): n for n in entry.get("header") or []}
    rows = {n.casefold(): n for n in entry.get("lines") or []}
    unknown = [n for n in header if n.casefold() not in heads]
    unknown += [n for line in lines for n in line if n != "line" and n.casefold() not in rows]
    if unknown:
        near = register_fields.closest(unknown, entry)
        raise ChangeError("%s has no field %s.%s" % (
            register, ", ".join(sorted(set(unknown))),
            " Nearest names: %s." % ", ".join(near) if near else ""))
    header = {heads[k.casefold()]: v for k, v in header.items()}
    lines = [{(k if k == "line" else rows[k.casefold()]): v for k, v in line.items()}
             for line in lines]
    types = entry.get("types") or {}
    system = [n for n in list(header) + [k for line in lines for k in line if k != "line"]
              if n.casefold() in SYSTEM_FIELDS or types.get(n) == register_fields.PACKED]
    system += [k for line in lines for k in line if k.casefold() in LINE_ONLY_REFUSED]
    if system:
        raise ChangeError("%s is kept by Excellent Books itself and is not written through this "
                          "connector." % ", ".join(sorted(set(system))))
    return header, lines


def too_long(register: str, fields: dict) -> list:
    """[(field, length, limit)] for each value longer than `FIELD_LIMITS` allows, in order."""
    limits = {k.casefold(): (k, n) for k, n in FIELD_LIMITS.get(register.casefold(), {}).items()}
    return [(limits[k.casefold()][0], len(v), limits[k.casefold()][1])
            for k, v in fields.items()
            if k.casefold() in limits and len(v) > limits[k.casefold()][1]]


def _check_lengths(register: str, header: dict) -> None:
    over = too_long(register, header)
    if over:
        raise ChangeError("%s. Shorten it and plan again." % "; ".join(
            "%s is %d characters; %s holds %d" % (field, length, field, limit)
            for field, length, limit in over))


def _normalise_flags(register: str, header: dict, lines: list) -> None:
    """Approval and invalid flags become "1" or "0" in place, before any rule reads them."""
    flags = set(approval_fields(register)) | set(DEFAULT_APPROVAL_FIELDS) | set(INVALID_FIELDS)
    for fields in [header] + lines:
        for name in list(fields):
            if str(name).casefold() in flags:
                fields[name] = _flag(name, fields[name])


def _check_reserved(register: str, header: dict, lines: list) -> None:
    """Refuses an approval name where it does not approve the register, and on any line. Runs
    before the field listing, so the reason is the approval's, not "no such field"."""
    fields = approval_fields(register)
    for line in lines:
        for name in line:
            if str(name).casefold() in RESERVED_APPROVALS:
                raise ChangeError("An approval (%s) on a line is not written through this "
                                  "connector: approving a document on its lines was never "
                                  "measured. Approve the document itself. Nothing was planned."
                                  % name)
    for name in header:
        folded = str(name).casefold()
        if folded in RESERVED_APPROVALS and folded not in fields:
            listed = APPROVAL_FIELDS.get(register.casefold())
            why = NO_APPROVAL.get(register.casefold()) or (
                "%s is approved with %s, not %s." % (register, " then ".join(listed), name)
                if listed else "%s approves only a supplier payment (OPVc)." % name)
            raise ChangeError("%s is not an approval of %s: %s Nothing was planned."
                              % (name, register, why))


def posting_tick(register: str, name) -> bool:
    """True for a posting or state tick that is refused in any value (POSTING_TICK). The
    approval names are RESERVED_APPROVALS' business, checked before this."""
    folded = str(name).casefold()
    reg = str(register).casefold()
    if folded in RESERVED_APPROVALS or (reg, folded) in MEASURED_TICKS:
        return False
    # Round 4 (Sol re-check MUST): a document state without a Flag suffix (QTVc
    # AcceptanceStatus, ORVc OrderStatus, IVVc Status...) is refused there too: none is measured.
    if reg in APPROVAL_FIELDS and folded.endswith(("flag", "status")):
        return True
    return bool(POSTING_TICK.search(folded) or STATE_FLAG.search(folded))


def _check_posting_ticks(register: str, header: dict, lines: list) -> None:
    for fields in [header] + lines:
        for name in fields:
            if name != "line" and posting_tick(register, name):
                raise ChangeError(
                    "%s on %s is a posting or status tick this connector has not measured: "
                    "setting or clearing it may post the document, move stock, send or close "
                    "it, or mark a step done that was not. "
                    "Change it in Excellent Books itself. Nothing was planned." % (name, register))


def _check_payment_fields(register: str, header: dict, lines: list) -> None:
    """A payment carries only its measured fields (PAYMENT_FIELDS); names in Books' spelling."""
    allowed = PAYMENT_FIELDS.get(register.casefold())
    if not allowed:
        return
    # By name, not by capitals: the lookup gives the listing's spelling, which may be PAYMODE.
    head = {f.casefold() for f in allowed["header"]}
    rows = {f.casefold() for f in allowed["lines"]}
    other = [k for k in header if str(k).casefold() not in head]
    other += [k for line in lines for k in line
              if k != "line" and str(k).casefold() not in rows]
    if other:
        raise ChangeError(
            "%s is not written on a payment (%s) through this connector: only the fields "
            "measured on a test server are (%s; on its lines %s). A payment's other status "
            "fields may send or change it in ways not checked. Change it in Excellent Books "
            "itself. Nothing was planned." % (
                ", ".join(sorted(set(other))), register, ", ".join(allowed["header"]),
                ", ".join(allowed["lines"])))


CONTROL_REFUSAL = ("%s holds a line break, tab, invisible character, special space or other "
                   "control character. The approval page cannot show it apart from a space or "
                   "from nothing, so it is not written. Write the value on one line with plain "
                   "spaces. Nothing was planned.")
# Cc controls; Cf invisible format marks (zero-width space and joiner, BOM, soft hyphen, text
# direction overrides); Zl/Zp line and paragraph separators; any space but the plain one
# (a no-break or figure space looks like a space). Sol review of 41d7c81, MUST.
# Co private use has no agreed look. Letters that render blank: braille blank and the Hangul
# fillers (re-check of dcd94b9).
# Cn unassigned and Cs lone surrogates: no agreed look either, and a surrogate cannot even be
# encoded (Sol re-check of dcd94b9). U+034F, the combining grapheme joiner, shows as nothing.
_UNSEEN = {"Cc", "Cf", "Cn", "Co", "Cs", "Zl", "Zp"}
_BLANK_LETTERS = {"\u2800", "\u3164", "\u115f", "\u1160", "\uffa0", "\u034f"}


def has_control(value) -> bool:
    """A character the approval page cannot show as what it is, anywhere in the value. The one
    rule for every write tool: record changes, items, contacts and receipts (Task 22 gate, A
    NIT-1)."""
    return any(unicodedata.category(c) in _UNSEEN or c in _BLANK_LETTERS
               or (unicodedata.category(c) == "Zs" and c != " ")
               for c in str(value if value is not None else ""))


def _check_controls(header: dict, lines: list) -> None:
    """Refuses a value with a control character: the approval page shows a line break or a tab
    like a space, so the person could not see what is sent (Sol review 2026-11-18, MUST 5)."""
    for fields in [header] + lines:
        for name, value in fields.items():
            if name != "line" and has_control(value):
                raise ChangeError(CONTROL_REFUSAL % name)


def _check_approval(register: str, header: dict, lines: list, record_id: str) -> bool:
    """Refuses un-OK and Invalid. True when the change sets an approval."""
    _normalise_flags(register, header, lines)
    fields = approval_fields(register)
    approving = False
    for name, value in list(header.items()) + [(k, v) for r in lines for k, v in r.items()]:
        folded = str(name).casefold()
        off = record_id and folded in fields and value != "1"
        if off or (folded in INVALID_FIELDS and value not in ("", "0")):
            raise ChangeError("Taking the approval (%s) off a document or marking it invalid is "
                              "not done through this connector. A person does it in Excellent "
                              "Books, where the correction is visible." % name)
        approving = approving or (folded in fields and value == "1")
    return approving


def _check_approval_order(register: str, header: dict, current) -> None:
    """Refuses an approval step Books takes only after another (OPVc: ordered, then done)."""
    for name, value in header.items():
        need = APPROVAL_NEEDS.get((register.casefold(), name.casefold()))
        if not need or value != "1":
            continue
        first, code = need
        mine = next((v for k, v in header.items() if k.casefold() == first.casefold()), None)
        theirs = next((v for k, v in (current or {}).items()
                       if k.casefold() == first.casefold()), None)
        if mine != "1" and theirs != "1":
            raise ChangeError("%s needs %s first: Excellent Books refuses it with %s (\"Payment "
                              "must be ordered before it can be reconciled\"). Nothing was "
                              "planned. Set %s in the same change, or first on its own."
                              % (name, first, code, first))


def _check_required(register: str, header: dict, lines: list, record_id: str,
                    current_lines=None) -> None:
    """Refuses a create (and a line it adds) Books would refuse for a missing field, naming
    Books' own error code. Nothing is sent: Books saves nothing then either."""
    folded = register.casefold()

    def refuse(field, where=""):
        code, said = REQUIRED_CODES.get(field.casefold(), ("", ""))
        raise ChangeError("Excellent Books refuses a %s without %s%s (its error %s, \"%s\"). "
                          "Nothing was planned. Give %s and plan again."
                          % (register, field, where, code, said, field))

    if not record_id:
        for field in REQUIRED_ON_CREATE.get(folded, ()):
            given = next((v for k, v in header.items() if k.casefold() == field.casefold()), "")
            if not str(given).strip():
                refuse(field)
    for line in lines:
        existing = record_id and line["line"] in (current_lines or {})
        for field in REQUIRED_ON_LINE.get(folded, ()):
            key = next((k for k in line if k.casefold() == field.casefold()), None)
            if existing and key is None:
                continue                   # an existing line keeps the value it has
            if not str(line.get(key, "") if key else "").strip():
                refuse(field, " on line %d" % line["line"])


def _check_hints(register: str, header: dict) -> None:
    for name in header:
        for (reg, field), better in FIELD_HINTS.items():
            if reg == register.casefold() and field.casefold() == str(name).casefold():
                raise ChangeError("%s has no %s field: Excellent Books drops it without saying "
                                  "so. Its free-text field is %s. Nothing was planned; plan "
                                  "again with %s." % (register, name, better, better))


def _read_whole(session, register: str, record_id: str) -> tuple:
    """(the record's header, {line: fields}, its raw XML) or (None, {}, ""). A record that is
    not the one asked for is None too: a path the ERP read as the whole register must not stand
    in for it.

    The raw XML is the record element's content: what the parser leaves out (empty values,
    attributes, fields after </rows>, a repeated tag) still counts in the fingerprint. Its own
    opening tag is left out: measured 2026-11-17, a single-record read carries the server's
    newest `sequence` there, which moves when anything on the server is written."""
    response = _get(session, "/%s/%s" % (register, urllib.parse.quote(record_id, safe="")))
    if response is None:
        return None, {}, ""
    for raw, (header, lines) in zip(erp._elements(response.body, register),
                                    erp.records_with_lines(response.body, register)):
        if record_id in (header.get("SerNr"), header.get("Code")):
            return header, lines, raw
    problems = erp.reply_problems(response.text)
    if problems:
        # An HTTP 200 carrying an error is not "no such record".
        raise ErpRefused("Excellent Books answered with an error when this connector read %s %s: "
                         "%s. Nothing was written." % (register, record_id, problems))
    if not write_outcome.has_data_root(response.body):
        raise ErpRefused("Excellent Books did not return a data document for %s %s." %
                         (register, record_id))
    return None, {}, ""


def _read(session, register: str, record_id: str) -> tuple:
    """(the record's header, {line: fields}) or (None, {})."""
    header, lines, _ = _read_whole(session, register, record_id)
    return header, lines


def _check_contact(session, register: str, header: dict, current=None) -> None:
    side = CONTACT_SIDE.get(register.casefold())
    if not side:
        return
    field, flag, word = side
    code = next((v for k, v in header.items() if k.casefold() == field), "")
    if not code and current:
        # An update that does not name the contact still goes to the record's own one.
        code = next((v for k, v in current.items() if k.casefold() == field), "")
    if not code:
        return
    # One key value is a range on the index, never a filter (CLAUDE.md, measured up to 100x).
    response = _get(session, "/CUVc", fields="Code,%s" % flag, sort="Code",
                    range="%s:%s" % (code, code))
    found = [r for r in erp.list_records(response.body if response else b"", "CUVc")
             if r.get("Code") == code]
    if not found:
        raise ChangeError("There is no contact with the code %s." % code)
    if str(found[0].get(flag) or "") != "1":
        raise ChangeError("The contact %s is not marked as %s, so Excellent Books would refuse "
                          "this invoice. Tick it on the contact card first (or ask to change "
                          "the contact), then plan the invoice again." % (code, word))


def _code_key(header: dict) -> Optional[str]:
    """The record key a create names itself (Code or SerNr), or None."""
    return next((k for k in header if k.casefold() in KEY_FIELDS), None)


def _refuse_existing_code(session, register: str, header: dict) -> None:
    for key in [k for k in header if k.casefold() in KEY_FIELDS]:
        if _read(session, register, header[key])[0] is not None:
            raise ChangeError("A %s record with the %s %s exists already. Nothing was planned: "
                              "to change it, plan an update with record_id %s." % (
                                  register, "code" if key.casefold() == "code" else "number",
                                  header[key], header[key]))


def fingerprint(header: dict, lines: dict, raw: str = "") -> str:
    """Hash everything read, including secret-named fields and each line's number, and the
    record's raw XML (`_read_whole`) for what the parser does not see.

    The parsed header and lines are order-independent; values, field presence and row numbers
    are not. The raw XML is hashed as Books sent it, so a reordered or respelled record counts
    as a change: deliberately conservative (a refused write, never a missed change; two reads
    of an unchanged record were byte-identical, measured 2026-11-17).
    The input is the parsed document from _read_whole, not its filtered public preview.
    """
    canonical = json.dumps((header, lines, raw), sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _public_fields(fields: dict) -> dict:
    hidden = set(privacy.secret_fields(list(fields)))
    return {k: v for k, v in fields.items() if k not in hidden}


def _fields_of(line: dict) -> dict:
    return {k: v for k, v in line.items() if k != "line"}


def plan(session, store: approval.PlanStore, register, fields=None, rows=None,
         record_id=None) -> dict:
    """Checks the change and returns its preview and plan_id. Writes nothing."""
    stopped = control.register_refusal(register, write=True)   # before the listing is read
    if stopped:
        return stopped
    register, entry = _listing(session, _register(register))
    # Again on Books' own spelling: the listing may resolve "excautotaskvc" to a name a
    # case-sensitive W1 pattern closes (Task 22 gate round 4, Sol MUST).
    _register(register)
    if reason := vivc_build_reason(register, getattr(session, "system_version", None)):
        raise VivcBuildUnverified(reason)
    record_id = _record_id(record_id)
    if fields is not None and not isinstance(fields, dict):
        raise ChangeError("fields is a set of field names and values.")
    header = {str(k): _value(v) for k, v in (fields or {}).items()}
    lines = _lines(rows, update=bool(record_id))
    if len(lines) > MAX_ROWS:
        raise ChangeError("%d lines is more than this connector writes at once (%d). Import a "
                          "file in Excellent Books instead." % (len(lines), MAX_ROWS))
    if not header and not lines:
        raise ChangeError("There is nothing to write: give at least one field.")
    if privacy.is_hr(register=register) and len(lines) > privacy.PAYROLL_MAX_ROWS:
        # The preview shows each line as it is now: more than the HR cap would be an export.
        raise ChangeError("An HR or payroll change covers at most %d lines at once."
                          % privacy.PAYROLL_MAX_ROWS)
    _check_controls(header, lines)
    _check_hints(register, header)
    _check_reserved(register, header, lines)
    _check_posting_ticks(register, header, lines)
    header, lines = _check_names(entry, register, header, lines)
    _check_payment_fields(register, header, lines)
    _check_lengths(register, header)
    if not record_id:
        _check_required(register, header, lines, record_id)
    header, lines, shown, date_format, variants, date_checks = _dates(
        session, entry, register, header, lines, record_id)
    key = [k for k in header if k.casefold() in KEY_FIELDS]
    if record_id and key:
        raise ChangeError("%s is the record's own number or code and is not changed through "
                          "this connector." % ", ".join(key))
    approving = _check_approval(register, header, lines, record_id)

    preview = {"status": "planned", "register": register,
               "action": "update" if record_id else "create"}
    before, line_before = {}, {}
    current, current_lines, current_raw = None, {}, ""
    if record_id:
        current, current_lines, current_raw = _read_whole(session, register, record_id)
        if current is None:
            raise ChangeError("No %s record %s was found." % (register, record_id))
        _check_required(register, header, lines, record_id, current_lines)
        if privacy.is_hr(register=register) and len(current_lines) > privacy.PAYROLL_MAX_ROWS:
            raise ChangeError("An HR or payroll preview covers at most %d lines at once. "
                              "Make this change in Excellent Books itself."
                              % privacy.PAYROLL_MAX_ROWS)
        before = {k: current.get(k, "") for k in header}
        preview["record_id"] = record_id
        preview["document_now"] = {
            "header": _public_fields(current),
            "lines": {n: _public_fields(v) for n, v in current_lines.items()}}
        preview["fields"] = [{"field": k, "before": before[k], "after": v}
                             for k, v in header.items()]
        shown = []
        for line in lines:
            now = current_lines.get(line["line"])
            if now is None:
                line_before[line["line"]] = None          # must still be absent at apply
                shown.append(dict({"line": line["line"], "new_line": True}, **_fields_of(line)))
                continue
            secret = set(privacy.secret_fields(list(now)))
            now = {k: v for k, v in now.items() if k not in secret}
            line_before[line["line"]] = {k: now.get(k, "") for k in _fields_of(line)}
            shown.append({"line": line["line"],
                          "fields": [{"field": k, "before": now.get(k, ""), "after": v}
                                     for k, v in _fields_of(line).items()],
                          "line_now": now})
        if lines:
            preview["lines"] = shown
    else:
        _refuse_existing_code(session, register, header)
        preview["fields"] = [dict({"field": k, "value": v}, **shown.get(k, {}))
                             for k, v in header.items()]
        # A field the create leaves to Books (QTVc ValidUntilDate with no date given).
        preview["fields"] += [dict({"field": k}, **extra) for k, extra in shown.items()
                              if k not in header]
        if lines:
            # "lines", not "rows": the payroll limit empties a "rows" list, and a person must
            # see every line they approve.
            preview["lines"] = lines
    _check_approval_order(register, header, current)
    _check_contact(session, register, header, current)
    build = getattr(session, "system_version", None)
    if reason := vivc_build_reason(register, build):
        raise VivcBuildUnverified(reason)
    if approving:
        preview["warning"] = (payment_warning(register, header)
                              if register.casefold() in PAYMENT_REGISTERS else APPROVE_WARNING)
    preview["note"] = approval.APPLY_NOTE
    payload = {
        "register": register, "record_id": record_id,
        "header": tuple(header.items()),
        # What each bound write sends in the header, in envelope order (TEXT_DATES fallbacks).
        "variants": tuple(tuple(v.items()) for v in variants),
        "lines": tuple((line["line"], tuple(_fields_of(line).items())) for line in lines),
        "before": tuple(before.items()),
        "line_before": tuple((n, None if v is None else tuple(v.items()))
                             for n, v in sorted(line_before.items())),
        "document_header": current, "document_lines": current_lines,
        "system_version": build,
        "date_format": date_format,
        "date_checks": date_checks,
        "connection": session_connection_id(session)}
    path = urllib.parse.urlsplit(session.cfg.api_base).path.rstrip("/") + "/" + register
    if record_id:
        path += "/" + urllib.parse.quote(record_id, safe="")
    envelope = approval.Envelope(
        kind="record_change", server=session.cfg.origin, company=session.cfg.company,
        books_user=session.usercode or session.cfg.user,
        operation="approve" if approving else "update" if record_id else "create",
        target="%s %s" % (register, record_id or "(new)"),
        writes=tuple(("PATCH" if record_id else "POST", path,
                      _form(variant, [(r["line"], _fields_of(r)) for r in lines],
                            approval_fields(register),
                            register.casefold() in APPROVAL_FIELDS).decode("ascii"))
                     for variant in variants),
        before=fingerprint(current, current_lines, current_raw) if record_id else "",
        preview=json.dumps(preview, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
        needs_ack=approving)
    preview["plan_id"] = store.issue(envelope, payload)
    return preview


def _fresh_date_format(session):
    """The company's date format read now, not the session's cached copy: a plan binds the
    format its bytes were written in (review 2026-11-17 M2), and execution checks it again."""
    kept = getattr(session, "_erp_date_format", None)
    try:
        session._erp_date_format = None
    except AttributeError:
        return dates.erp_format(session)
    try:
        found = dates.erp_format(session)
    except Exception:
        session._erp_date_format = kept
        raise
    if found is None and kept:
        # A failed fresh read refuses this plan; it must not replace the copy reports still
        # use, which erp_format would then never read again (re-check 2026-11-17).
        session._erp_date_format = kept
    return found


def _delivery_type(session) -> Optional[str]:
    """Read the company's current PlanDeliveryBlock.FieldType, if available."""
    block = "PlanDeliveryBlock"
    try:
        response = session.rest_get("/" + block, fields="FieldType", timeout=20)
    except erp.SignInAgain:
        raise
    except (OSError, erp.HTTPException, erp.ErpError):
        return None
    if (response.status != 200 or not write_outcome.has_data_root(response.body)
            or erp.reply_problems(response.body)):
        return None
    entries = erp.list_records(response.body, block)
    value = entries[0].get("FieldType", "") if len(entries) == 1 else ""
    return value if value.isdecimal() else None


# Planned-ship text fields Books reads by PlanDeliveryBlock.FieldType even with no M4Date
# companion (opus review of the Task 33 fix, SHOULD 3: POVc line PlanShipRow is converted by
# Books' own field code; QTVc line PlanShip, SVOVc/WOVc PlanShiprw are the same family).
PLAN_SHIP_NAMES = frozenset({"PlanShip", "PlanShipRow", "PlanShiprw"})
# PlanDeliveryBlock.FieldType, from Books' own paste code: 1 date, 2 week (nn), 3 week (yynn);
# anything else is free text.
WEEK_FORMS = {"2": "nn, for example 49", "3": "yynn, for example 2649"}


def _is_week(text: str, kind: str) -> bool:
    """A week number in the form FieldType asks for: nn (2) or yynn (3), week 1 to 53."""
    if not text.isascii() or not text.isdecimal() or len(text) not in ((1, 2) if kind == "2" else (4,)):
        return False
    return 1 <= int(text[-2:] if kind == "3" else text) <= 53


def _date_text_fields(types, fields) -> set:
    """An M4Str with an M4Date companion on the same side of the record, or a planned-ship
    field by name."""
    names = set(fields)
    return {name for name in names if types.get(name) == "M4Str" and (
        name in PLAN_SHIP_NAMES
        or (name + "Date" in names and types.get(name + "Date") == DATE_TYPE))}


_DATE_LOOKING = re.compile(
    r"^[0-9]{6}(?:[0-9]{2})?$|^[0-9]{1,4}[./-][0-9]{1,4}\.?$|"
    r"\b[0-9]{1,4}[^\w]+[0-9]{1,2}[^\w]+[0-9]{1,4}|"
    r"\b[0-9]{1,2}[^\w]+[^\W\d_]+[^\w]+[0-9]{2,4}\b|"
    r"\b[^\W\d_]+[^\w]+[0-9]{1,2}[^\w]+[0-9]{2,4}\b")


def _dates(session, entry, register: str, header: dict, lines: list, record_id) -> tuple:
    """(header, lines, shown, date_format, variants, date_checks).

    A date field (M4Date in the listing, or a name ending in "Date" the listing gives no type)
    goes out as ISO: measured 2026-11-17, QTVc QTDate sent as 01.12.2026 was stored as 1912-12-26
    at HTTP 200. A value in the company's own format is converted, text that is not a date is
    refused. A date-text field in date mode uses the same ISO wire form (Task 33).

    A TEXT_DATES field is the exception (QTVc ValidUntilDate): `variants` are the headers of the
    bound writes of one create, in the order they may be sent: the person's date in the company
    form, then in ISO, then empty; with no date given, the field left out, then empty; given
    empty, that one write. `header` is what the person sees (the date as ISO), `shown` adds what
    the preview says about it. A change of it on an existing record is refused.
    `date_format` is the company format the bytes depend on, or None when none was needed."""
    text_field = TEXT_DATES.get(register)
    header, shown, known = dict(header), {}, []
    header_types = entry.get("types") or {}
    # Line fields have their own types (520 names are on both sides on pkorea 1370); a listing
    # cached before line_types existed gives none, and the name rule applies to its lines.
    line_types = entry.get("line_types") or {}
    header_names = entry.get("header") or []
    header_text = _date_text_fields(header_types, header_names)
    # Old listings put line types in "types". A name shared by both sides lost its line type.
    line_names = entry.get("lines") or []
    line_text = (_date_text_fields(line_types, line_names) if "line_types" in entry else
                 _date_text_fields(header_types, (set(line_names) - set(header_names))
                                   | (set(line_names) & PLAN_SHIP_NAMES)))
    date_checks = {}
    date_header, date_lines = set(), set()

    def is_date(name, types):
        # The customer's own listing decides: M4Date is a date, whatever its name (315 on pkorea
        # 1370 do not end in "Date"); an M4Int or M4Str field named "...Date" is not (33 and 17).
        # Only a field the listing gives no type falls back to the name (re-checks 2026-11-17).
        kind = types.get(name)
        return kind == DATE_TYPE if kind else dates.is_iso_field(name)

    def fmt():
        if not known:
            known.append(_fresh_date_format(session))
        return known[0]

    def no_format(name):
        return ChangeError(
            "%s is read by Excellent Books in the company's own date format, and this connector "
            "could not read that format (SysFormatBlock), so the date cannot be sent reliably. "
            "Nothing was planned. Leave %s out (Excellent Books fills its default), or set it in "
            "Excellent Books." % (name, name))

    def convert(name, value, local, *, date_only=False):
        value = str(value).strip()
        if not value:
            return value
        if not any(c.isdigit() for c in value):
            raise ChangeError("%s: %r is not a date. Write it as YYYY-MM-DD%s." % (
                name, value, ', or empty ("") to leave it blank' if local else ""))
        if local and not fmt():
            raise no_format(name)
        try:
            return dates.to_wire(name, value, fmt, local=local, date_only=date_only)
        except (OSError, erp.HTTPException, erp.ErpError) as exc:
            if not date_only or isinstance(exc, erp.SignInAgain):
                raise
            raise ChangeError("%s: the company's date format could not be read. "
                              "Write it as YYYY-MM-DD." % name) from None
        except ValueError as exc:
            if date_only:
                raise ChangeError("%s: write a valid date as YYYY-MM-DD." % name) from None
            raise ChangeError(str(exc)) from None

    def convert_field(name, value, types, date_text, checked):
        if name in date_text:
            if not str(value).strip():
                return value                    # clearing it is the same in every mode
            if "delivery_type" not in date_checks:
                date_checks["delivery_type"] = _delivery_type(session)
            kind = date_checks["delivery_type"]
            text = str(value).strip()
            looks_like_date = _DATE_LOOKING.search(text) or dates.is_iso_day(text)
            if kind is None:
                # Opus review MUST 2: unread, "next week" was sent raw and Books stored today.
                raise ChangeError(
                    "%s: the company's planned delivery setting in Excellent Books (date, week "
                    "number or text) could not be read, so no value can be sent to it safely. "
                    "Nothing was planned. Set it in Excellent Books itself." % name)
            if kind == "1":
                checked.add(name)
                return convert(name, value, False, date_only=True)
            if kind in WEEK_FORMS:
                # Opus review MUST 1: a week-mode company reads "2026-12-03" as week numbers;
                # Sol re-check of 016c4ff: only a real week number goes ("Dec 3", "99" did not).
                if not _is_week(text, kind):
                    raise ChangeError(
                        "%s: this company keeps the planned delivery as a week number (%s), "
                        "not a date. Nothing was planned. Give the week number." % (
                            name, WEEK_FORMS[kind]))
                return text
            if looks_like_date and not dates.is_iso_day(text):
                raise ChangeError("%s: write a date as YYYY-MM-DD." % name)
        elif is_date(name, types):
            checked.add(name)
            return convert(name, value, False)
        return value

    # Opus review NIT 7: Books fills the date from the text field; both in one plan disagree.
    for names, fields in [(header_text, header)] + [(line_text, line) for line in lines]:
        both = sorted(n for n in names if n in fields and n + "Date" in fields)
        if both:
            raise ChangeError("Give %s only: Excellent Books fills %sDate from it. Nothing was "
                              "planned." % (both[0], both[0]))
    for name in list(header):
        if name == text_field:
            if record_id:
                raise ChangeError(UPDATE_REFUSED % (name, register))
        else:
            header[name] = convert_field(name, header[name], header_types, header_text, date_header)
    lines = [{k: (convert_field(k, v, line_types, line_text, date_lines) if k != "line" else v)
              for k, v in line.items()} for line in lines]

    variants = [header]
    if text_field and not record_id and text_field in (entry.get("header") or []):
        date_header.add(text_field)
        given = header.get(text_field)
        if given is None:
            variants = [dict(header), dict(header, **{text_field: ""})]
            shown[text_field] = {"value": DEFAULT_SHOWN, "set_by": DEFAULT_NOTE,
                                 "fallback": fallback_steps([None, ""])}
        elif str(given).strip():
            company = convert(text_field, given, True)
            header[text_field] = convert(text_field, given, False)     # ISO: what is shown
            forms = []
            for value in (company, header[text_field], ""):
                if value not in forms:
                    forms.append(value)
            variants = [dict(header, **{text_field: value}) for value in forms]
            shown[text_field] = {"fallback": fallback_steps(
                forms, company if company != header[text_field] else None)}
        else:
            header[text_field] = ""
            variants = [header]
            shown[text_field] = {"set_by": BLANK_SHOWN}
    date_checks.update(header=tuple(sorted(date_header)), lines=tuple(sorted(date_lines)))
    return header, lines, shown, (known[0] if known else None), variants, date_checks


def _form(header: dict, lines: list, approving=DEFAULT_APPROVAL_FIELDS,
          ordered=False) -> bytes:
    """The previewed order: header fields, then the lines, then the header totals, then the
    approval fields last: in `approving`'s order when the register's order is measured
    (`ordered`), else in the order given, as before Task 19a."""
    approval = [(k, v) for k, v in header.items() if k.casefold() in approving]
    if ordered:
        approval.sort(key=lambda pair: approving.index(pair[0].casefold()))
    totals = [(k, v) for k, v in header.items()
              if AFTER_LINES.match(k) and k.casefold() not in approving]
    pairs = [("set_field.%s" % k, v) for k, v in header.items()
             if k.casefold() not in approving and not AFTER_LINES.match(k)]
    for number, fields in lines:
        pairs += [("set_row_field.%d.%s" % (number - 1, k), v) for k, v in fields.items()]
    pairs += [("set_field.%s" % k, v) for k, v in totals + approval]
    # Spaces as %20: Books stores a '+' literally (receipts.py).
    return urllib.parse.urlencode(pairs, quote_via=urllib.parse.quote).encode("ascii")


_PLAIN_DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)")


def _plain_number(text: str) -> bool:
    if not _PLAIN_DECIMAL.fullmatch(text) or report_html.has_leading_zero(text):
        return False
    whole, _, fraction = text.lstrip("+-").partition(".")
    digits = (whole + fraction.rstrip("0")).lstrip("0")
    return len(digits) <= 15


def _same(wanted: str, stored) -> bool:
    stored = "" if stored is None else str(stored)
    if wanted == stored:
        return True
    return (_plain_number(wanted) and _plain_number(stored)
            and float(wanted) == float(stored))


UNVERIFIED = ("Excellent Books did not confirm this write, and that does not prove it failed: "
              "a create can answer with messages only and still make the record. Do NOT plan "
              "the same change again. Read the register first (find_records, newest records, "
              "or the record itself) and tell the person what you find.")


def _unverified(register: str, reply: str, why: str, lines: int,
                explain: Optional[str] = None, approved=None) -> dict:
    # Audited as returned (Sol re-check 2026-11-17, SHOULD 3): "failed" here told the log the
    # write did not happen, when nobody knows.
    audit.record("apply_record_change", register=register, outcome=write_outcome.UNVERIFIED,
                 reason=why, lines=lines, **audit.approval_facts(approved))
    said = erp.reply_problems(reply)
    result = {"status": write_outcome.UNVERIFIED, "register": register,
              "erp_said": said, **write_outcome.refusal_explanations(said), "note": UNVERIFIED}
    if explain:
        result["why"] = explain
    return result


def _changed_since(planned: dict, current: dict, current_lines: dict) -> list:
    changed = [k for k, v in planned["before"] if not _same(v, current.get(k))]
    for number, fields in planned["line_before"]:
        if fields is None:
            if number in current_lines:
                changed.append("line %d was added" % number)
            continue
        now = current_lines.get(number) or {}
        changed += ["line %d %s" % (number, k) for k, v in fields if not _same(v, now.get(k))]
    return changed


def _before_writing(session, planned: dict, envelope: approval.Envelope,
                    register: str, record_id: str, header: dict):
    """The checks just before the write; anything refused here wrote nothing."""
    if planned.get("date_format") and _fresh_date_format(session) != planned["date_format"]:
        # The approved bytes carry dates written in that format; resent now, Books would read
        # them as other dates at HTTP 200 (review 2026-11-17 M2).
        raise ChangeError("The company's date format in Excellent Books changed since the "
                          "preview. Nothing was written. Plan the change again.")
    date_checks = planned.get("date_checks", {})
    if ("delivery_type" in date_checks
            and _delivery_type(session) != date_checks["delivery_type"]):
        raise ChangeError("The company's planned delivery field setting changed or could not be "
                          "confirmed. Nothing was written. Plan the change again.")
    # Check the plan's contact first. The full fingerprint then proves the document still
    # names that contact, with no further ERP read between the document check and dispatch.
    _check_contact(session, register, header, planned["document_header"])
    if record_id:
        current, current_lines, raw = _read_whole(session, register, record_id)
        if current is None:
            raise ChangeError("%s record %s is no longer there. Nothing was written."
                              % (register, record_id))
        if fingerprint(current, current_lines, raw) != envelope.before:
            changed = _changed_since(planned, current, current_lines)
            raise ChangeError("The record changed since the preview (%s). Nothing was written. "
                              "Plan the change again, so the person sees what it is now."
                              % (", ".join(changed) or "another field of the record"))
    else:
        _refuse_existing_code(session, register, header)


def execute(session, approved: approval.Approved, plan: approval.Plan, *, still_allowed=None) -> dict:
    """Send the approved bytes, then read back. The caller finishes the plan with this outcome."""
    if (not isinstance(approved, approval.Approved) or not approved.live()
            or not isinstance(plan, approval.Plan) or plan.plan_id != approved.plan_id
            or plan.envelope != approved.envelope
            or not approved.matches(session.cfg.origin, session.cfg.company, session.usercode or session.cfg.user)
            or approved.envelope.kind != "record_change"):
        return {"error": "refused", "why": "A live approval for this plan and connection is required."}
    try:
        return _execute(session, approved, plan, still_allowed)
    except ChangeError as exc:
        return {"error": exc.code, "why": str(exc)}


def _execute(session, approved: approval.Approved, plan: approval.Plan, still_allowed) -> dict:
    planned, envelope = plan.payload, approved.envelope
    register, record_id = planned["register"], planned["record_id"]
    header = dict(planned["header"])
    lines = [(number, dict(fields)) for number, fields in planned["lines"]]
    headers = {"Content-Type": erp.FORM_CONTENT_TYPE}
    # One record, up to three bound variants of its create (TEXT_DATES): the next is sent only
    # when Books refused the previous one unambiguously on that field and saved nothing
    # (write_outcome.refused_on); the rest are passed over on the approval's counter, so none
    # can be sent later, also when the checks before writing refuse (Sol review 2026-11-18).
    variants = [dict(v) for v in planned.get("variants") or (planned["header"],)]
    text_field = TEXT_DATES.get(register)
    index = 0
    try:
        try:
            _before_writing(session, planned, envelope, register, record_id, header)
        except ChangeError:
            raise
        except Exception as exc:
            raise ErpRefused(write_outcome.before_write_why(
                exc, "Excellent Books could not be reached to check the record before "
                     "writing. Nothing was written. Plan the change again."))
        if reason := vivc_build_reason(register, getattr(session, "system_version", None)):
            raise VivcBuildUnverified(reason)
        for index, (method, path, form_body) in enumerate(envelope.writes):
            try:
                erp.check_desktop_write_budget()
                if index and still_allowed is not None and not still_allowed():
                    raise erp.WritePolicyRefused(write_outcome.NOT_SENT)
                response = session.request(session.cfg.origin + path,
                                           form_body.encode("ascii"), headers,
                                           method=method, approved=approved)
            except erp.WriteConnectionLost as exc:
                return dict(_unverified(register, "", "write_connection_lost", len(lines),
                                        approved=approved), note=exc.suspension_reason,
                            **write_outcome.connection_loss(exc))
            except erp.VersionChanged:
                reason = vivc_build_reason(register, getattr(session, "system_version", None))
                return _unverified(register, "", "version_changed", len(lines), reason,
                                   approved=approved)
            except Exception as exc:
                if write_outcome.send_failure(exc) == write_outcome.NOT_ATTEMPTED:
                    # Before it, only refused variants were sent: nothing was saved.
                    audit.record("apply_record_change", register=register, outcome="failed",
                                 reason="not_attempted", lines=len(lines),
                                 **audit.approval_facts(approved))
                    return {"status": write_outcome.NOT_ATTEMPTED, "register": register,
                            "note": write_outcome.not_sent_why(exc)}
                # A timeout after the request left: it may have been written.
                return _unverified(register, "", "no_reply", len(lines), approved=approved)
            reply = response.text
            status = getattr(response, "status", 200)
            if status >= 400:
                said = write_outcome.access_refusal(status, response.body)
                if said is not None:     # the allowlisted access-rights refusal: nothing saved
                    audit.record("apply_record_change", register=register, outcome="failed",
                                 reason="access_refused_http_%d" % status, lines=len(lines),
                                 **audit.approval_facts(approved))
                    return {"status": write_outcome.REFUSED, "register": register,
                            "erp_said": said, "http_status": status,
                            "note": write_outcome.ACCESS_REFUSED}
                if write_outcome.access_unclear(status, response.body):
                    return dict(_unverified(register, reply, "http_401_empty", len(lines),
                                            approved=approved),
                                http_status=status, note=write_outcome.ACCESS_UNCLEAR)
                return _unverified(register, reply, "http_%d" % status, len(lines),
                                   approved=approved)
            refused = bool(text_field) and write_outcome.refused_on(
                status, reply, FALLBACK_ERROR, text_field, update=bool(record_id))
            if not (refused and index + 1 < len(envelope.writes)):
                break
    finally:
        for later in envelope.writes[index:]:
            if approved.peek_next(*later):
                approved.skip_next(*later)
    if refused:
        audit.record("apply_record_change", register=register, outcome="failed",
                     reason="refused_%s_every_form" % FALLBACK_ERROR, lines=len(lines),
                     **audit.approval_facts(approved))
        if record_id:
            # An update carries no variants: Books re-reads the date the record already holds
            # and refuses the whole change (measured 2026-11-18, QTVc 70 and 74).
            note = ("Excellent Books refused this change with its error %s on the %s the %s "
                    "already holds (Books reads that date in a form that changes from day to "
                    "day), so nothing was saved. Tell the person; the change is made in "
                    "Excellent Books itself." % (FALLBACK_ERROR, text_field, register))
        else:
            note = ("Excellent Books refused the %s %s in every form this connector may send "
                    "(its error %s), so nothing was saved. Tell the person; the %s is created "
                    "in Excellent Books itself." % (register, text_field, FALLBACK_ERROR,
                                                   register))
        said = erp.reply_problems(reply)
        return {"status": write_outcome.REFUSED, "register": register, "erp_said": said,
                **write_outcome.refusal_explanations(said), "note": note}
    header = variants[index] if index < len(variants) else header
    blank = bool(text_field) and len(variants) > 1 and header.get(text_field) == ""

    code_key = _code_key(header)
    made = None
    if not record_id:
        made = _URL.search(reply)
        if made and made.group(1).casefold() == register.casefold():
            record_id = urllib.parse.unquote(made.group(2))
        elif code_key:
            record_id = header[code_key]          # a code-keyed register: look for that code
        else:
            return _unverified(register, reply, "no_record_in_reply", len(lines), approved=approved)

    try:
        stored, stored_lines = _read(session, register, record_id)
    except Exception:
        # Not knowing is not "not there": a failed read never says nothing was made.
        return _unverified(register, reply, "read_back_failed", len(lines), approved=approved)
    created = not planned["record_id"]
    if stored is None and created and code_key and record_id == header[code_key] and not made:
        # The code was absent just before the write and is absent after it: not made.
        audit.record("apply_record_change", register=register, outcome="failed",
                     reason="not_created", lines=len(lines),
                     **audit.approval_facts(approved))
        said = erp.reply_problems(reply)
        return {"status": "not_created", "register": register, "erp_said": said,
                **write_outcome.refusal_explanations(said),
                "note": "Excellent Books did not create it: no record with this code exists "
                        "after the write. " + write_outcome.said_note(
                            "Tell the person what Books asked for (erp_said) and plan it again "
                            "with that.", " Then plan it again.")}
    if stored is None:
        return _unverified(register, reply, "not_read_back", len(lines), approved=approved)
    if created and code_key:
        # Books answers HTTP 200 "Already registered" for a code another user made in between,
        # stores nothing and echoes our values: the record read back must carry our code AND
        # our name to be ours (Sol re-check 2026-11-17, MUST 1).
        name_key = next((k for k in header if k.casefold() == "name"), None)
        verdict, theirs = write_outcome.judge_create(
            stored, header[code_key], header[name_key] if name_key else None,
            code_field=code_key, name_field=name_key or "Name")
        if verdict != write_outcome.CREATED:
            return _unverified(register, reply, "identity_not_confirmed", len(lines),
                               "A %s record with this %s is there%s; it may not be the one "
                               "approved. Check it in Excellent Books." % (
                                   register, "code" if code_key.casefold() == "code" else
                                   "number", " under another name (%s)" % theirs if theirs
                                   else ", but not as approved"), approved=approved)
    date_checks = planned.get("date_checks", {})
    known_format = [planned["date_format"]] if planned.get("date_format") else []

    def readback_format():
        if not known_format:
            try:
                known_format.append(_fresh_date_format(session))
            except (OSError, erp.HTTPException, erp.ErpError):
                known_format.append(None)
        return known_format[0]

    def field_saved(field, wanted, kept, side):
        if field not in date_checks.get(side, ()):
            return _same(wanted, kept)
        if wanted == (kept or ""):
            return True
        if not wanted or not kept or not any(c.isdigit() for c in kept):
            return False
        try:
            return (dates.to_wire(field, wanted, readback_format, local=False, date_only=True)
                    == dates.to_wire(field, kept, readback_format, local=False, date_only=True))
        except ValueError:
            return False

    not_saved = [{"field": k, "wanted": v, "stored": stored.get(k, "")}
                 for k, v in header.items() if not field_saved(k, v, stored.get(k), "header")]
    for number, fields in lines:
        now = stored_lines.get(number)
        if now is None:
            not_saved.append({"line": number, "field": "(the whole line)", "wanted": "a line",
                              "stored": ""})
            continue
        not_saved += [{"line": number, "field": k, "wanted": v, "stored": now.get(k, "")}
                      for k, v in fields.items() if not field_saved(k, v, now.get(k), "lines")]
    # A create that happened is "created" even when Books changed a value: the record exists,
    # and calling it anything else invites a second create.
    status = "created" if created else "not_saved" if not_saved else "updated"
    approving = approval_fields(register)
    approval_saved = any(k.casefold() in approving and v == "1"
                         and _same(v, stored.get(k)) for k, v in header.items())
    approval_saved = approval_saved or any(
        k.casefold() in approving and v == "1"
        and _same(v, stored_lines.get(number, {}).get(k))
        for number, fields in lines for k, v in fields.items())
    # After a saved approval, the rest of the document is compared with the plan-time read. A
    # difference is reported, never a failure: Books saved what the person approved (review
    # 2026-11-17 M1), and the read-back cannot tell Books' own work from another user's.
    changed_after = (_changed_after_write(register, planned["document_header"],
                                          planned["document_lines"], stored, stored_lines,
                                          header, lines)
                     if not created and envelope.needs_ack and approval_saved else [])
    # A code can be a personal ID. Only a serial number confirmed by the read-back is
    # eligible for the hosted write trail.
    document = None
    if (isinstance(session, erp.HostedSession) and stored.get("SerNr") == record_id
            and stored.get("Code") != record_id):
        document = record_id
    audit.record("apply_record_change", register=register,
                 outcome="ok" if created or not not_saved else "failed",
                 reason=("fields_changed_by_erp" if created and not_saved else
                         "fields_not_saved" if not_saved else
                         "changed_after_write" if changed_after else None), lines=len(lines),
                 document=document,
                 **audit.approval_facts(approved))
    result = {"status": status, "register": register, "record_id": record_id,
              "not_saved": not_saved,
              "note": "The record and its lines were read back from Excellent Books after "
                      "writing."}
    if blank and created:
        # Said from the read-back, not from what was sent (Sol review 2026-11-18, SHOULD).
        kept = str(stored.get(text_field) or "").strip()
        result["valid_until"] = BLANK_NOT_STORED % kept if kept else BLANK_RESULT
        result["note"] += " " + result["valid_until"]
    said = erp.reply_problems(reply)
    if said:
        result["erp_said"] = said
        if status == "not_saved":
            result.update(write_outcome.refusal_explanations(said))
        result["note"] += (" Books also sent the messages in erp_said; on a write that was "
                           "read back they are usually progress, not failure.")
    if not_saved:
        result["note"] += (" The fields in not_saved did not take the value asked for: Books "
                           "refused or recalculated them. Tell the person; do not apply again.")
    if changed_after:
        result["changed_after_write"] = changed_after
        result["note"] += (" Books or another user changed these fields after the write: %s; "
                           "check them in Books." % ", ".join(changed_after))
    return result


def _changed_after_write(register: str, before: dict, before_lines: dict, after: dict,
                         after_lines: dict, set_header: dict, set_lines: list) -> list:
    """The fields of the document that differ from the plan-time read, other than the ones the
    plan set, the approval fields and what Books is measured to derive on this write (DERIVED).
    Header names first, then "line N field"; "line N" for a line that appeared or went; a
    secret-named field only as "a field that is not shown". A line the plan added is compared
    with an empty line, leaving out its own fields (checked as `not_saved`) and Books' measured
    fill of a new line."""
    derived = DERIVED.get(register.casefold(), {})
    own = approval_fields(register)
    approving = any(k.casefold() in own for k in set_header) or any(
        k.casefold() in own for _, fields in set_lines for k in fields)
    change = derived.get("line_change") or {}
    when = {f.casefold() for f in change.get("when", ())}
    recalculated = {n for n, fields in set_lines if when & {k.casefold() for k in fields}}
    added = {n for n, _ in set_lines if n not in (before_lines or {})}
    new_line = derived.get("new_line") or {}
    skip = {k.casefold() for k in set_header} | set(own)
    if approving:
        skip |= {f.casefold() for f in derived.get("approve", ())}
        filled = {k.casefold() for k, v in (before or {}).items() if v not in ("", None)}
        skip |= {f.casefold() for f in derived.get("approve_if_blank", ())
                 if f.casefold() not in filled}
    if recalculated:
        skip |= {f.casefold() for f in change.get("header", ())}
    if added:
        skip |= {f.casefold() for f in new_line.get("header", ())}
    names, hidden = [], False

    def differ(old: dict, new: dict, skipped: set, label: str) -> None:
        nonlocal hidden
        for k in sorted(set(old) | set(new)):
            if k.casefold() in skipped or old.get(k) == new.get(k):
                continue
            if privacy.secret_fields([k]):
                hidden = True
            else:
                names.append(label + k)

    differ(before or {}, after or {}, skip, "")
    written = {n: {k.casefold() for k in fields} for n, fields in set_lines}
    line_derived = {f.casefold() for f in change.get("line", ())}
    for number in sorted(set(before_lines) | set(after_lines)):
        old, new = before_lines.get(number), after_lines.get(number)
        if number in added and new is not None:
            differ({}, {k: v for k, v in new.items() if v not in ("", None)},
                   set(own) | written[number]
                   | {f.casefold() for f in new_line.get("line", ())}, "line %d " % number)
            continue
        if old is None or new is None:
            names.append("line %d" % number)
            continue
        skipped = set(own) | written.get(number, set())
        if number in recalculated:
            skipped |= line_derived
        differ(old, new, skipped, "line %d " % number)
    if hidden:
        names.append("a field that is not shown")
    return names
