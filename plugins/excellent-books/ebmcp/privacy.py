"""What this MCP will not read, and what it says about everything else.

**Secrets are never read** (Kaupo, 2026-10-04: "tokens, passwords etc - mask them. hide them.
they are not report material"). The registers that hand out password material or an
integration's credentials are refused at every door (`is_blocked`); a field NAMED like a secret
is dropped from every register row and refused as a filter or sort (`is_secret_field`); a PEM
private key is masked in every result (`mask_private_keys`); a report that prints one is not in
the catalogue (`SECRET_REPORTS`).

**Personal data is the customer's decision** (Kaupo, 2026-10-04). Until that day payroll, HR and
people's communications were refused as whole modules, and personal fields and codes were
refused or masked. The connector runs on the customer's own computer with their own ERP login,
into the AI they chose: they accept the current wording at install, nothing is read
before they have (`server.session`), and a result that names people carries `NOTICE`.

Adding any register-reading or register-writing tool means adding the `is_blocked` and
`secret_fields` checks to it; there is no second net.
"""
from __future__ import annotations

import re

from . import claims

# The hosted GDPR text (gdpr_text("hosted")) is a draft until Kaupo signs it off in Task 48.
HOSTED_TEXT_SIGNED_OFF = False

# The user registers.
#
# Measured on the reference demo 2026-09-16, after Sven hit it on a Latvian server: a plain
# `GET /UserVc?limit=1` as an ordinary API user returns, among 41 fields, `NewPassWord`,
# `DiscPassword`, `PassWordAlgorithm`, `PassWordLinkf`, `SidCNewPassWord`,
# `SidCPassWordAlgorithm`, `TwoFAStatus` and `TwoFAMethod`. `GlobalUserVc` returns the same
# among 31. So any API user with REST access can read every user's password material and
# two-factor state — including users far more privileged than itself.
#
# `erp.list_records` drops empty fields, so a name missing from a one-record sample is not
# evidence the field does not exist. What is present is evidence enough.
#
# This does not fix the ERP, and it is not meant to: the server-side configuration is filed for
# the HAL developers. It stops this connector being the thing that reads it.
USER_REGISTERS = frozenset({
    "UserVc",             # per-company users
    "GlobalUserVc",       # users defined across companies on the same server
    # Each user's password hash (Password, M4NLong) and its only key runs over it (the opus
    # re-check of 2026-10-05, from the datadefs). Kaupo 10-04: lose what exposes passwords.
    "UserPasswdVc",
    "GlobalUserPasswdVc",
    # Hardware-key users: password hash, salt and algorithm, recovery e-mail and phone (release
    # review 10-05, I4; Kaupo: refuse whole).
    "HWIDUserVc",
})

CREDENTIAL_REFUSAL = (
    "This MCP does not read the user register. It carries password material — password hashes "
    "and algorithms, the SidC set, and two-factor state — for every user on the server, and a "
    "connector an AI client drives is not a place that belongs. This is a scope decision, not "
    "a permissions error: different fields or a narrower range will not help. If you need to "
    "know who a user is, look in Excellent Books itself."
)


def _normalise(register) -> str:
    return str(register or "").strip().casefold()


# A settings block that hands out an integration's own credentials over REST. Measured on the
# reference demo 2026-10-01: `GET /EInvoiceBlock` returns a filled `APIServiceToken` and
# `PrivateKey` to an ordinary API user (only the field names were read). Filed for the HAL
# developers too. Any other block's secret-named fields are dropped by `strip_secret_fields`.
# EInvoiceCertVc holds the e-invoice certificate's private key file (opus review 10-04, C2):
# a register whose whole purpose is the key, refused whole like the block.
CREDENTIAL_BLOCKS = frozenset({"EInvoiceBlock", "EInvoiceCertVc"})

BLOCK_REFUSAL = (
    "This MCP does not read the e-invoice settings or certificates. They carry the e-invoice "
    "service's own API token and private key, and a connector an AI client drives is not a "
    "place for them. This is a scope decision, not a permissions error, so retrying will not "
    "help. Look at the e-invoice settings in Excellent Books itself."
)

# App tokens per user: its Token column was already dropped by name, but two of its keys end in
# the token and nobody needs an AI to list API tokens (Kaupo, 2026-10-05: refused whole, like
# the password registers).
TOKEN_REGISTERS = frozenset({"HAppTokenVc", "LoginTokenVc", "ClientLoginTokenBlock"})

TOKEN_REFUSAL = (
    "This MCP does not read the token registers. They hold users' API and login tokens, and a "
    "connector an AI client drives is not a place for them. This is a scope decision, not a "
    "permissions error, so retrying will not help. Manage tokens in Excellent Books itself."
)

_CREDENTIAL_BLOCKED = {name.casefold() for name in USER_REGISTERS}
_SECRET_BLOCKS = {name.casefold() for name in CREDENTIAL_BLOCKS}
_TOKEN_BLOCKED = {name.casefold() for name in TOKEN_REGISTERS}
_BLOCKED = _CREDENTIAL_BLOCKED | _SECRET_BLOCKS | _TOKEN_BLOCKED


def is_blocked(register) -> bool:
    """True for a register this MCP refuses to read at all."""
    return _normalise(register) in _BLOCKED


def refusal(register) -> dict:
    """The error body both register tools return, shaped like their other errors, with the
    register's own reason: a refusal that gives the wrong one sends somebody to the wrong fix."""
    name = _normalise(register)
    why = (CREDENTIAL_REFUSAL if name in _CREDENTIAL_BLOCKED
           else TOKEN_REFUSAL if name in _TOKEN_BLOCKED else BLOCK_REFUSAL)
    return {"error": "register_not_available",
            "register": str(register or ""),
            "why": why}


# Reports whose output carries a stored credential. 2026-10-01: Data Check XML Invoice ends every
# run by printing the e-invoice private key when it contains a space, which a PEM key always does
# — the secret EInvoiceBlock is refused for (correction 15), leaving by the report door.
# Not in the catalogue at all (Kaupo, 2026-10-04: "lose those kind of reports altogether"):
# the generator (knowledge repo, books/tools/gen_catalog.py) skips the window. Keyed by WINDOW, because a customer's disk may hold an
# older catalogue under another id. {window class: (catalogue id, what it prints)}.
SECRET_REPORTS = {
    "FindMisMatchRClass": ("DBMain/data-check-xml-invoice",
                           "its closing check prints the stored e-invoice private key"),
}
# The same reports by RUN NAME (opus review, 2026-10-14): the catalogue comes from another repo,
# and a window class it leaves out or renames must not let the program run. {run name: as above}
SECRET_RUN_NAMES = {
    "FindMisMatchRn": SECRET_REPORTS["FindMisMatchRClass"],
}
SECRET_REPORT_REFUSAL = (
    "%s is not run by this connector: %s, a credential that must not reach a chat. "
    "Run it in Excellent Books itself.")


# -- personal data: the customer's decision, taken once (Kaupo, 2026-10-04) --------------------
#
# "Customer uses his/her own AI - it might be European AI, local AI or whatever. Lets just warn
# about personal data and GDPR... move responsibility to user." The connector runs on the
# customer's own computer with their own ERP login; what reaches their AI is theirs to decide.
# They decide at install (`python -m ebmcp.setup`), nothing is read before they have, and a
# result that names people says so (server._finish, `names_people` below).
#
# One text per package (Task 50; spec 2026-11-16 sections 2.5 and 6): the developer ZIP
# (`local`, setup), Claude Desktop (`desktop`, the dialog tick and the consent page) and the hosted
# connector (`hosted`, the sign-in page). Each holds `claims.what_leaves(mode)` as a paragraph of
# its own, word for word (tests/test_claims.py). No text says Excellent "does not see" the data:
# Excellent hosts many customers' Books servers, and hosted answers pass through its server.
# Changing a wording asks everyone who accepted it again (config.consent_text_id, consent.py).
_PERSONAL_DATA = (
    "Answers from this connector can contain personal data from your Excellent Books - names, "
    "personal ID codes, e-mail addresses, phone numbers, salaries, absences (which can be health "
    "data) and messages. ")
_DECISION = (
    "You, as the controller of that data, decide whether %s may receive it under the GDPR and "
    "your own agreements with it; Excellent cannot take that decision for you.")
# Kaupo 2026-11-16: the log reader stays open in local and Desktop use, with this disclosure
# (server_log.LOGINS_NOTICE says the same on every answer from the log). Sol review of 849e1ca,
# SHOULD 5: not "every connected user". Books rights decide who may run the report; the connector
# adds only the stops of the catalogue and the control file (reports.py, control.py).
_SERVER_LOG = (
    "Excellent Books has a report that reads the Books server's own log. Through this connector, "
    "users whose Books account may run that report can read that log: the connector adds no check "
    "of its own beyond Excellent Books rights and any report stop Excellent publishes. The log "
    "shows other users' logins (names, and e-mail and IP addresses as Books writes them) and some "
    "usage statistics.")
# What Excellent's Knowledge server keeps is said in claims.what_leaves (its citation is there).
# Hosted design 2026-11-17 sections 10, 12 and 16, as the code does it (Sol review of 849e1ca,
# MUST-FIX 3): the plan tools return the preview to the AI (changes.py, `return preview`) and the
# approval page shows it (hosted_approve.py); plans live on the in-memory BooksConnection, and a
# restart ends every grant (tests/test_hosted_provider.py). server.py apply_approved: a required
# begin line (audit.require) and a best-effort end line (audit.record) with the same facts plus the
# end line's own; audit.record keeps a document number only when it is all digits. audit.prune at
# start and every _AUDIT_PRUNE_SECONDS (hosted.py) drops lines older than RETENTION_DAYS; size
# rotation (MAX_BYTES, BACKUP_COUNT) can drop them sooner. tests/test_gdpr_consent.py ties each
# audit field to its words.
_HOSTED_HELD = (
    "A change the AI prepares is shown to you on the approval page, and its preview is also "
    "returned to the AI. The hosted connector keeps each change waiting for approval only in its "
    "memory, until it is approved, declined or expires. A restart of the service ends every sign-in and clears the changes still "
    "waiting for approval; it never undoes a write already saved in Excellent Books. When an "
    "approved change is carried out (one record, or a batch of several), Excellent's audit trail "
    "gets a begin line, which must be written before anything is sent, and an end line, written "
    "when possible; an approval that expires before it is carried out leaves only a count in the "
    "usage log. Both hold the time, a connection label, the "
    "register, the operation, a short approval reference, how long the approval waited and how "
    "the approver signed in. The end line can add the outcome, a short reason code, counts of "
    "records and lines, how long the write took, whether stock moved, and the document number "
    "when Excellent Books confirmed a numeric one. The lines hold no field values, names or previews. Lines older "
    "than 90 days are deleted when the service starts and once a day; when the trail reaches its "
    "size limit, older lines can be removed sooner. Excellent Books records the write under your "
    "own user. ")
# Sol review of 849e1ca, SHOULD 4: usage.py (FIELDS; `actor` is the connection label, hosted only),
# auth.py (the OAuth store: registered clients, and hashed codes and tokens with the connection
# label, deleted at expiry and by a restart), deploy/booksmcp.conf (Apache's combined access log).
# Usage retention, Kaupo 2026-11-19 (45f review N5): hosted usage lines are kept 90 days like the
# write trail; usage.prune (usage.RETENTION_DAYS) runs in the same start and daily job as
# audit.prune (hosted.py), and the size rotation of usage.py can remove lines sooner. The text
# promises the cleanup RUN, not its result: a failed rewrite (logged for operators) and an
# unreadable line are kept (Sol review 2026-11-20, A). The access
# log's retention is the server's logrotate setting, not verified from this repo, so no figure is
# given.
_HOSTED_RECORDS = (
    "Excellent's server also keeps a usage line for each tool call, with the time, the tool, the "
    "outcome, how long it took, the connector version, the kind of AI app and the connection "
    "label, and a line without connection details when a change is prepared, approved, declined "
    "or expires. A cleanup of usage lines older than 90 days runs when the service starts and "
    "about every 24 hours; the log's size limit can remove lines sooner. To keep you signed "
    "in, it stores the AI apps registered with it (their names and return addresses) and, for each "
    "sign-in, the sign-in time, the connection label and fingerprints of its authorization codes "
    "and its access and refresh tokens, not the codes or tokens themselves. Sign-in records are "
    "deleted when the service restarts, and expired ones as new records are written; the "
    "registered apps are kept across restarts; when the list is full, apps without a live sign-in "
    "can be removed. "
    "Excellent's web server logs each request to the hosted connector with its time, network "
    "address and the address requested, and for most requests the browser or app name; for the "
    "one-time approval hand-off it logs the path only. ")
# Hosted reads the server log only on a Books server Excellent listed (EBMCP_HOSTED_LOG_SERVERS,
# hosted.log_servers, empty by default; reports.log_refusal refuses every other server).
_HOSTED_SERVER_LOG = (
    "Only if Excellent has listed your Books server for the server-log reader can users whose "
    "Books account may run the server-log report read that server's own log through this "
    "connector. The log shows other users' logins (names, "
    "and e-mail and IP addresses as Books writes them) and some usage statistics.")


def _gdpr_texts() -> dict:
    return {
        "local": "\n\n".join((
            _PERSONAL_DATA + "They are sent to the AI service you connected this connector to. "
            + _DECISION % "that service",
            claims.what_leaves("local"),
            _SERVER_LOG,
            claims.CHAT_APPROVAL)),
        "desktop": "\n\n".join((
            _PERSONAL_DATA + "They are sent to Claude, the AI service of Anthropic, through the "
            "Claude Desktop app on this computer. " + _DECISION % "Anthropic",
            claims.what_leaves("desktop"),
            _SERVER_LOG,
            claims.CHAT_APPROVAL)),
        # The ChatGPT/Codex plugin (design 2026-11-23, Review change 6): the Desktop text with
        # OpenAI as the recipient and the decision party. Recorded per connection with its hash.
        "plugin": "\n\n".join((
            _PERSONAL_DATA + "They are sent to OpenAI's Codex / ChatGPT, through the Codex app on "
            "this computer. " + _DECISION % "OpenAI",
            claims.what_leaves("plugin"),
            _SERVER_LOG,
            claims.CHAT_APPROVAL)),
        # DRAFT until Task 48: the hosted gate refuses a release while HOSTED_TEXT_SIGNED_OFF is
        # False (hosted.py). Kaupo signs the wording off there, not here.
        "hosted": "\n\n".join((
            _PERSONAL_DATA + "They are sent to your connected AI provider. "
            + _DECISION % "that provider",
            claims.what_leaves("hosted"),
            _HOSTED_HELD + _HOSTED_RECORDS + _HOSTED_SERVER_LOG,
            "The hosted connector always uses browser approval. The ZIP and Desktop connectors "
            "also offer chat approval. " + claims.CHAT_APPROVAL)),
    }


# Task 53: the Desktop text in Estonian for the Estonian consent page, paragraph for paragraph
# the English "desktop" text above: the same data, the controller sentence, what leaves the
# computer (claims.what_leaves("desktop", "et")), the server-log disclosure and chat approval.
# A yes on that page
# records the hash of THIS text (consent.current_hashes covers every page language). Kaupo reads it
# before release; changing it asks everyone who accepted it again.
_PERSONAL_DATA_ET = (
    "Selle ühenduse vastustes võib olla isikuandmeid Teie Excellent Booksist: nimed, "
    "isikukoodid, e-posti aadressid, telefoninumbrid, töötasud, puudumised (need võivad olla "
    "terviseandmed) ja sõnumid. ")
_DESKTOP_DECISION_ET = (
    "Need saadetakse selles arvutis oleva Claude Desktopi rakenduse kaudu Claude'ile, mis on "
    "Anthropicu tehisintellekti teenus. Nende andmete vastutav töötleja olete Teie. Teie "
    "otsustate, kas Anthropic tohib neid saada isikuandmete kaitse üldmääruse ning Teie ja "
    "Anthropicu vaheliste lepingute alusel. Excellent ei saa seda otsust Teie eest teha.")
_SERVER_LOG_ET = (
    "Excellent Booksis on aruanne, mis loeb Booksi serveri enda logi. Selle ühenduse kaudu "
    "saavad seda logi lugeda kasutajad, kelle Booksi kasutajakontol on õigus see aruanne "
    "käivitada. Ühendus kontrollib ainult Excellent Booksi õigusi ja seda, kas Excellent on "
    "aruande kasutamise peatanud; muud kontrolli see omalt poolt ei lisa. Logis on näha teiste "
    "kasutajate sisselogimised (nimed ning e-posti ja IP-aadressid nii, nagu Books need kirja "
    "paneb) ja osa kasutusstatistikast.")
_GDPR_DESKTOP_ET = "\n\n".join((
    _PERSONAL_DATA_ET + _DESKTOP_DECISION_ET,
    claims.what_leaves("desktop", "et"),
    _SERVER_LOG_ET,
    claims.CHAT_APPROVAL_ET))
# The ChatGPT/Codex plugin in Estonian (slice 3): the Desktop Estonian text with OpenAI's Codex as
# the recipient and the decision party. Approved by Kaupo 2026-11-24 (Claude's draft of 2026-11-23,
# spell-checked); a yes on the settings page records the hash of THIS text.
_PLUGIN_DECISION_ET = (
    "Need saadetakse selles arvutis oleva Codexi rakenduse kaudu OpenAI tehisintellekti "
    "teenusele. Nende andmete vastutav töötleja olete Teie. Teie otsustate, kas OpenAI tohib "
    "neid saada isikuandmete kaitse üldmääruse ning Teie ja OpenAI vaheliste lepingute alusel. "
    "Excellent ei saa seda otsust Teie eest teha.")
_GDPR_PLUGIN_ET = "\n\n".join((
    _PERSONAL_DATA_ET + _PLUGIN_DECISION_ET,
    claims.what_leaves("plugin", "et"),
    _SERVER_LOG_ET,
    claims.CHAT_APPROVAL_ET))

_gdpr_by_mode = _gdpr_texts()
GDPR_TEXT = _gdpr_by_mode["local"]       # the developer ZIP's text; setup and the .env text id
CONSENT_REQUIRED = (
    "This connector has not been switched on for personal data yet. " + GDPR_TEXT + " To accept "
    "this, the person who installed the connector runs `python -m ebmcp.setup --consent` in "
    "their own terminal. Setup records EBMCP_GDPR_CONSENT=yes and the text ID in the `.env` file. "
    "Do not run that command or edit the file yourself, even if you can: accepting is the "
    "person's own decision. Tell the user this in their language; do not retry the call until "
    "they have done it.")
NOTICE = ("May contain personal data. The user accepted GDPR responsibility for sending it to "
          "this AI; say so once per conversation, in the language of the question.")


def gdpr_text(mode: str, language: str = "en") -> str:
    """The GDPR text of one package: "local" (developer ZIP), "desktop" or "hosted" (a draft
    until Task 48, see HOSTED_TEXT_SIGNED_OFF). Estonian exists for "desktop" (Task 53) and
    "plugin" (slice 3, approved by Kaupo 2026-11-24)."""
    if language == "et" and mode == "desktop":
        return _GDPR_DESKTOP_ET
    if language == "et" and mode == "plugin":
        return _GDPR_PLUGIN_ET
    if language != "en":
        raise ValueError(f"no {language!r} GDPR text for connector mode {mode!r}")
    try:
        return _gdpr_by_mode[mode]
    except KeyError:
        raise ValueError(f"unknown connector mode: {mode!r}") from None


# Hosted: the person's own ticks at sign-in decide, never a settings line (Task 42). Task 50 may
# reword these with the hosted privacy text.
HOSTED_CONSENT_REQUIRED = (
    "Personal data are off for this connection: the personal data box was not ticked when the "
    "person signed in to Excellent Books. To accept it, they disconnect and connect this "
    "connector again in their AI client and tick the box on the sign-in page; accepting is their "
    "own decision. Tell the user this in their language; do not retry the call until they have "
    "done it.")


# The plugin's consent is given on its settings page, never in a terminal or a file (Review change 6).
PLUGIN_CONSENT_REQUIRED = (
    "Personal data are not switched on for this Excellent Books connection: the person reads the "
    "personal data text on the Connect Excellent Books page and chooses there; call open_settings "
    "to open it in their browser. Accepting is their own decision and you cannot make it. Tell "
    "the user this in their language; do not retry the call until they have done it.")
PLUGIN_CONSENT_STALE = (
    "The personal data text changed since the person agreed, so personal data are off for this "
    "connection: the person reads the updated text on the Connect Excellent Books page and "
    "chooses there; call open_settings to open it in their browser. Accepting is their own "
    "decision and you cannot make it. Tell the user this in their language.")


def consent_required(mode: str, *, stale: bool = False) -> str:
    if mode == "hosted":
        return HOSTED_CONSENT_REQUIRED
    if mode == "plugin":
        return PLUGIN_CONSENT_STALE if stale else PLUGIN_CONSENT_REQUIRED
    if mode == "desktop":
        return (
            "Open Claude Desktop > Settings > Extensions > Excellent Books and tick the "
            "personal data box. Accepting is your own decision. The AI cannot do this for "
            "you. Restart Claude Desktop after changing the setting."
        )
    if stale:
        return ("The personal data text changed since you agreed. Ask the person who installed "
                "the connector to run `python -m ebmcp.setup --consent` in their own terminal "
                "and read the updated text. Accepting is their own decision.")
    return CONSENT_REQUIRED


# -- where the notice goes: only an answer that names people (Kaupo, 2026-10-05) ---------------
#
# Measured 05.10: with the notice on every data result, every bench answer carried the sentence
# and the fastest question went 4.4 -> 6.0 s. A total, a balance or a stock count names nobody.
# Over-noticing is the cheap direction: a sentence too many costs a second; none at all on a
# payroll answer misleads the person who accepted the responsibility.
#
# Registers about people, whatever fields were asked: contacts, Estonian payroll (from
# PayRollDataEn.hal), Human Resources, activities, employees, and people's communications (mail,
# chat, calls; the release review of 10-05, I2, from the demo's own listing).
PEOPLE_REGISTERS = frozenset({
    "CUVc", "ActVc",
    "EmplVc", "ContractVc", "CalcPayrollVc", "PaymPayrollVc", "WorkedHoursVc", "SummedHoursVc",
    "AbsenceVc", "PlanAbsenceVc", "VacBalanceVc", "VacReservVc", "VacDaysFBVc", "DPDVacBalanceVc",
    "SalaryFBVc", "AbsenceFBVc", "PieceWorkVc", "ProgTaxVc", "EPShiftSheetVc",
    "HRMCOVc", "HRMCOChangeVc", "HRMPAVc", "HRMSEVc", "HRMSkillVc", "HRMCheckListVc",
    "LeaveApplicationVc", "LeaveTransferVc", "EmplPSVc", "TrainingPlanVc",
    "EmployeeVc", "EmplContractVc", "MissedDaysVc", "StdIDLoginVc", "HWIDUserVc",
    "ChatLogVc", "CallHistoryVc", "TelCallsVc", "MailVc", "ChatVc", "ChatMessageVc", "ConfVc",
    "PBXCallLogVc",
})
# Report modules about people: Human Resources (payroll too, in Books), CRM (contacts and
# activities), telephony, e-mail.
PEOPLE_MODULES = frozenset({"modHRM", "modCRM", "modTel", "modEmail"})
# Reports elsewhere that print people: the ones the policing rules of 10-01..10-04 named for the
# personal data they print, the contact lists, and the server log (logins, e-mails, addresses).
PEOPLE_REPORTS = frozenset({
    "SL/contact-list", "SY/person-list", "SY/user-login-history", "Hotel/guest-book",
    "Hotel/rooming-list", "DBMain/message-history", "DBMain/global-message-history",
    "DBMain/skype-call-history", "DBMain/skype-message-count", "DBMain/my-meets",
    "Exp/personnel-payment-journal", "Exp/periodic-personnel-statement",
    "Exp/periodic-personnel-statement-unpaid-expenses", "Courses/test-results", "BA/sms-status",
    "TC/inspect-hansa-log", "SY/user-activities", "SY/mail-list", "Courses/participant-list",
    "Timekeeper/hours-worked-analysis",
})
# A filled one of these in any row or document of any other result names a person. Register rows
# only in practice: a report's columns are labels in the API user's language, so reports are
# known by module and id above.
PEOPLE_FIELDS = frozenset(name.casefold() for name in (
    "Person", "ClientContact", "ContactPerson", "eMail", "Phone", "PhoneNo", "Mobile", "BirthDate",
    "Birthday", "BirthPlace", "BirthCountry", "Ethnicity", "IDCode", "FirstName", "LastName",
    "Participant"))
_PEOPLE_REGISTERS = {name.casefold() for name in PEOPLE_REGISTERS}


def _has_person_field(value, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.casefold() in PEOPLE_FIELDS and \
                    not isinstance(item, (dict, list)) and str(item or "").strip():
                return True
            if isinstance(item, (dict, list)) and _has_person_field(item, depth + 1):
                return True
    elif isinstance(value, list):
        return any(_has_person_field(item, depth + 1) for item in value)
    return False


def names_people(result, register=None, doc=None) -> bool:
    """True when `result` is about people: a register or report about them, or a filled person
    field in any row or document of it."""
    if register is not None and _normalise(register) in _PEOPLE_REGISTERS:
        return True
    if doc and (doc.get("module") in PEOPLE_MODULES or doc.get("id") in PEOPLE_REPORTS):
        return True
    return _has_person_field(result)


# -- HR and payroll: warned about, not forbidden ---------------------------------------------------
#
# The connector warns about HR and payroll rather than forbidding them, but reads them only after
# the user's own yes (config.hr_enabled), asked in setup after HR_CONSENT_TEXT; a missing key is
# not a yes. Every HR answer carries HR_WARNING, and no answer exports HR in bulk. What counts as HR is the Books AI Chat's own list, so both treat the same data
# as HR: the registers and report windows of the Latvian payroll (every EP... code), the
# Estonian payroll and the HR module, named one by one because the ERP files customers, items
# and invoices under the payroll and HR modules too.
HR_REGISTERS = frozenset({
    "EmployeeVc", "EmplGroupVc", "DeductionVc", "EmplContractVc", "PayTypeVc", "PayTypeGroupVc",
    "MissedDaysVc", "MissedDaysTypeVc", "SalaryTimeTableVc", "STT2TotalVc", "SalaryCalcVc",
    "Calc2PaymentVc", "SalaryPaymentVc", "EmplRSVc", "EmplVc", "PositionVc", "AccGroupVc",
    "ContractVc", "PaymTypeVc", "AbsenceVc", "AbsTypeVc", "VacBalanceVc", "ExceptDatesVc",
    "OpenTransVc", "PieceWorkVc", "PieceWorkTypeVc", "ISCOCodeVc", "WorkHourTypeVc",
    "WorkedHoursVc", "CalcPayrollVc", "CPUnpaidVc", "PaymPayrollVc", "TaxVc", "SalaryFBVc",
    "AbsenceFBVc", "VacDaysFBVc", "ITFMUsedVc", "DPDUsedVc", "CPWHVc", "CPPWVc", "CPOTVc",
    "CPAbsVc", "BailiffVc", "CPPPHistVc", "ProgTaxVc", "PlanAbsenceVc", "PlanAbsenceRowVc",
    "VacReservVc", "DPDVacBalanceVc", "SalarySlipHeaderVc", "SummedHoursVc", "SickDaysVc",
    "HRMCOVc", "HRMCOChangeVc", "HRMCheckListVc", "HRMJPVc", "HRMPAVc", "HRMSEVc",
    "LeaveApplicationVc", "SoftFactorVc", "TrainingPackVc", "TrainingPlanVc",
})
HR_REPORT_WINDOWS = frozenset({
    "AbsencesRClass", "AvarageSalaryRClass", "CalcPayrollRClass", "ContrListRClass",
    "CPayrollRClass", "CPForecastRClass", "EmplHistRClass", "EmplListRClass", "IllCalcRClass",
    "NewTSDRClass", "PaymPayrollRClass", "PlanAbsencesRClass", "PPayrollRClass",
    "SalarySlipRClass", "SalaryStatisticsRClass", "SalSlipRClass", "SeveranceRClass",
    "TSDRClass", "VacBalanceRClass", "VacBalToUseRClass", "VacCalcRClass", "WorkedHoursRClass",
    "WorkExperienceRClass", "PayTypesRClass", "BankTSDStatRClass", "ChecklistPointsRClass",
    "EmployeeStatRClass", "EmployeeTrainingRClass", "HeadCountRClass", "HRMCOListRClass",
    "HRMCORClass", "HRMSkillRClass", "LeaveBalanceRClass", "PayrollSummaryRClass",
    "PayspacePayslipsRClass", "SoftFactAnalysisRClass", "TrainingPlanRClass",
})
# Beyond the AI Chat's list: the HR module's registers and windows all start with HRM (its
# HRMPayrollVc holds pay per employee and is not on that list), and two leave registers.
# The Estonian bailiff withholdings (BailiffNewVc, BailiffNetoVc, HistBailiffVc; BailiffVc is on
# the AI Chat's list) and employee deductions (DeductVc) are payroll too: found by sweeping the
# customer's own register listing for payroll titles. PPVc ("Väljamaksed, kulutused") is not:
# it is the Expenses module's advances and expense refunds to accountable persons, like a
# supplier payment, and stays under the GDPR consent.
EXTRA_HR_REGISTERS = frozenset({"LeaveTransferVc", "LeaveSchemeVc", "BailiffNewVc",
                                "BailiffNetoVc", "HistBailiffVc", "DeductVc"})
_HR_NAMES = {name.casefold() for name in HR_REGISTERS | HR_REPORT_WINDOWS | EXTRA_HR_REGISTERS}
# Latvian payroll is every EP... code - except the supplier e-payment registers and windows
# (EPaymentQueVc, EPayStatRClass), which are purchase ledger.
_HR_PREFIX = re.compile(r"^(ep(?!ay)[a-z]|hrm)", re.I)


def _hr_name(name) -> bool:
    name = _normalise(name)
    return bool(name) and (name in _HR_NAMES or bool(_HR_PREFIX.match(name)))


def is_hr(register=None, doc=None) -> bool:
    """True for an HR or payroll register, or a report whose window or run name is one."""
    if register is not None and _hr_name(register):
        return True
    if not doc:
        return False
    return _hr_name(doc.get("window_class")) or _hr_name(doc.get("repname"))


# The four warnings, one source for the install question, the refusal, every HR answer and the
# customer guide (ebmcp/guide.md).
HR_POINTS = (
    ("Data protection", "HR and payroll answers contain employees' personal data - names, "
     "personal ID codes, salaries, bank accounts and absences. Sick leave and other absences can "
     "be health data, a special category of personal data under GDPR Article 9."),
    ("GDPR", "this data is sent to the AI service you connected. Your company is the controller: "
     "it needs a legal basis for this - for health data also an exception under Article 9(2) - "
     "and an agreement with that service. Check where the service processes the data, and send "
     "only what the question needs."),
    ("EU AI Act", "using AI to make or support decisions on hiring, promotion, dismissal, pay or "
     "other terms of work, on allocating tasks by behaviour or personal traits, or on "
     "evaluating employees' performance can be a high-risk use under the EU AI Act (Annex III), "
     "with obligations for your company. Do not base such a decision on these answers without "
     "a human reviewing it."),
    ("Accuracy", "the AI can be wrong. Check figures in Excellent Books before acting on them."),
)
_HR_POINTS = " ".join("%d. %s: %s" % (n, head, body)
                      for n, (head, body) in enumerate(HR_POINTS, 1))
HR_WARNING = ("HR and payroll data - read before using this answer. " + _HR_POINTS +
              " Pass these four points on to the user in their language, briefly, before the "
              "data itself, every time HR or payroll data is shown.")
# Desktop only (Task 27 review M1, road b, Kaupo 2026-11-19): every HR answer says how to switch
# HR off again, so withdrawing is as easy as giving consent.
HR_SWITCH_OFF = ('The user can switch HR and payroll data off at any time by saying "Switch HR data '
                 'off": then call hr_data_consent, and they click Switch off in the window it opens. '
                 'Mention this briefly with the four points.')
HR_CONSENT_INTRO = ("The connector reads HR and payroll data only if you answer yes here. "
                    "Read these four points first.")
HR_CONSENT_TEXT = HR_CONSENT_INTRO + " " + _HR_POINTS
HR_CONSENT_REQUIRED = (
    "HR and payroll data are off in this connector: nobody has said yes to them. " + _HR_POINTS +
    " To switch them on, the person who installed the connector runs `python -m ebmcp.setup "
    "--hr-consent` in their own terminal and reads the warnings. Setup records "
    "EBMCP_HR_CONSENT=yes and the text ID in the `.env` file. Do not run that command or edit the file yourself, even if you can: "
    "it is the company's own decision. Questions about how the HR module works can still be "
    "answered from Excellent Knowledge. Tell the user this in their language.")


HOSTED_HR_CONSENT_REQUIRED = (
    "HR and payroll data are off for this connection: the HR and payroll box was not ticked when "
    "the person signed in to Excellent Books. " + _HR_POINTS + " To switch them on, they "
    "disconnect and connect this connector again in their AI client and tick that box on the "
    "sign-in page; it is their own decision. Questions about how the HR module works can still be "
    "answered from Excellent Knowledge. Tell the user this in their language.")


# Desktop's HR road is the hr_data_consent tool (Kaupo 2026-11-19): no setup, file or terminal.
# The live Desktop gate (server._hr_gate) answers with these too (Task 51 review MUST 3).
_DESKTOP_HR_ROAD = (
    " " + _HR_POINTS + " If the person wants to review the warnings and choose, call "
    "hr_data_consent. They make the choice in their browser, in a window on their own computer; "
    "only their click there switches HR on, and it is their own decision. Questions about how "
    "the HR module works can still be answered from Excellent Knowledge. Tell the user this in "
    "their language.")
DESKTOP_HR_CONSENT_REQUIRED = ("HR and payroll data are off in this connector: nobody has said yes "
                               "to them." + _DESKTOP_HR_ROAD)
DESKTOP_HR_CONSENT_STALE = ("HR and payroll data are off in this connector: the warnings changed "
                            "since the person agreed." + _DESKTOP_HR_ROAD)
# consent.status "off": switched off on the consent page, or a saved choice that cannot be read.
DESKTOP_HR_CONSENT_OFF = ("HR and payroll data are off in this connector: they were switched off, "
                          "or the saved choice could not be read." + _DESKTOP_HR_ROAD)


def hr_refusal(mode: str | None = None, *, stale: bool = False, off: bool = False) -> dict:
    """The HR refusal of the run mode (`mode` None: the process's own, Task 51). `off` (Desktop):
    the choice was withdrawn or cannot be read, not never made."""
    if mode is None:
        from . import config
        try:
            mode = config.mode()
        except config.ConfigError:
            mode = "local"
    if mode == "hosted":
        return {"error": "hr_not_enabled", "why": HOSTED_HR_CONSENT_REQUIRED}
    if mode in ("desktop", "plugin"):      # the plugin lists hr_data_consent too
        why = (DESKTOP_HR_CONSENT_STALE if stale else
               DESKTOP_HR_CONSENT_OFF if off else DESKTOP_HR_CONSENT_REQUIRED)
        return {"error": "hr_not_enabled", "why": why}
    if stale:
        return {"error": "hr_not_enabled", "why": (
            "The HR and payroll warnings changed since you agreed. Ask the person who installed "
            "the connector to run `python -m ebmcp.setup --hr-consent` in their own terminal "
            "and read the updated warnings. Accepting is their own decision.")}
    return {"error": "hr_not_enabled", "why": HR_CONSENT_REQUIRED}


# -- no bulk HR or payroll export ------------------------------------------------------------------
#
# HR and payroll stay readable behind the consents above. What they may not become is an export:
# "every employee's salary" in one answer. An HR answer over many rows, groups or document lines
# keeps its count and totals and loses the rest; a narrow question (one employee, a department
# total, a year of one person's payslips) is answered as before. The test is the MATCHED count,
# not the page: max_rows=5 over 400 employees is the first page of an export. Every HR register
# and report is covered (`is_hr`), so there is no second list to fall behind.
#
# One employee's monthly payslips for a year fit; a department of thirteen does not.
PAYROLL_MAX_ROWS = 12
PAYROLL_LIMIT = (
    "Bulk export of HR and payroll data is not available through this connector: this answer "
    "covered more than %d rows, so only its count and totals are shown. Ask about one employee, "
    "or for a total or a total by department. Do not work round this with one call per "
    "employee in a loop; the person can export payroll in Excellent Books itself."
    % PAYROLL_MAX_ROWS)


def _limit_documents(result) -> bool:
    """show_documents: a payroll run is one document with a line per employee. The cap is on
    the whole answer: three documents of twelve lines are 36 lines in one answer."""
    docs = [d for d in result.get("documents") or [] if isinstance(d, dict)]
    lines = sum(d.get("line_count", len(d.get("rows") or [])) or 0 for d in docs)
    if lines <= PAYROLL_MAX_ROWS:
        return False
    for doc in docs:
        doc["rows"], doc["lines_omitted"] = [], doc.get("line_count", len(doc.get("rows") or []))
    result["html"] = ""              # the page renders every line the summary just lost
    return True


def limit_payroll(result, register=None, doc=None):
    """Withhold the rows, groups and document lines of an HR or payroll answer that covers more
    than PAYROLL_MAX_ROWS; the count and totals stay. Anything else passes untouched."""
    if not isinstance(result, dict) or "error" in result or not is_hr(register, doc):
        return result
    withheld = _limit_documents(result)
    rows = result.get("rows")
    if result.get("row_count_total", len(rows or [])) > PAYROLL_MAX_ROWS:
        if rows:
            result["rows"], result["truncated"], withheld = [], True, True
    # A report's section headings name employees and its footer holds their subtotals, for the
    # WHOLE report: a `where` narrows the rows, not them. Kept only when the report itself, before
    # any `where`, is within the cap.
    whole = result.get("row_count_before_where", result.get("row_count_total", len(rows or [])))
    if whole > PAYROLL_MAX_ROWS or whole != result.get("row_count_total", whole):
        for key in ("sections", "footer"):
            if result.get(key):
                result[key], withheld = [], True
    records = result.get("records")
    if records and len(records) > PAYROLL_MAX_ROWS:
        result["records"], withheld = [], True
    groups = result.get("groups")
    if groups and result.get("groups_total", len(groups)) > PAYROLL_MAX_ROWS:
        result["groups"], result["truncated"], withheld = [], True, True
    if withheld:
        result["payroll_limit"] = PAYROLL_LIMIT
    return result


# -- secrets, by name and by value (Kaupo, 2026-10-04: "tokens, passwords etc - mask them. hide
# them. they are not report material") -------------------------------------------------------
#
# The block list above names the registers known to carry secrets. This is the net for the ones
# nobody has measured: a field whose NAME says it is a secret is dropped from every register row
# and document this connector returns, and refused as a filter, sort or sum (a `where` on it
# would let a caller recover it by bisection). Over-hiding is the cheap direction: a field named
# like a token that is not one costs a column; a password that leaves costs a breach.
# Widened after the opus review (10-04, C2), which read every field name of the Books datadefs:
# EPKey ("API Password"), HWCustPassw ("Parole"), EInvKey, PrivKeyFile, EBAuthCode, EBSessionId
# all passed the first pattern. The "...Key" ending also catches AccessKey, MerchantKEY,
# EncryptionKey, WebServiceKey in the core ERP datadefs; the business fields it would hide there
# are exempt by name (NOT_SECRET), and the catalogued register fields are pinned clear by a test.
# `^pin(code|nr)?$|^code2fa$`: app PINs and two-factor codes (release review 10-05, I4), whole
# names only, from the demo's own listing of 13,793 field names: settings like UserPinField,
# Use2FA or Period2FA stay readable.
_SECRET_NAME = re.compile(r"passw|passphrase|pass$|pwd|token|secret|priv(ate)?_?key|api_?key|"
                          r"(?<=[a-z])key$|auth_?code|session_?id|credential|"
                          r"^pin(code|nr)?$|^code2fa$", re.I)
# The same without the "...Key" ending, for a SORT key: HansaWorld names its indexes that way
# (CDKey, MainKey; 45 registers have no other, exchange rates among them), and refusing them left
# the register unreadable (re-review of 54a8586, N1). An index is an order, not a value.
_SECRET_SORT = re.compile(r"passw|passphrase|pass$|pwd|token|secret|priv(ate)?_?key|api_?key|"
                          r"auth_?code|session_?id|credential|^pin(code|nr)?$|^code2fa$", re.I)
# Business fields in the core ERP datadefs that end in "Key" (re-review N1).
NOT_SECRET = frozenset(n.casefold() for n in ("SearchKey", "CusDecKey", "VYKey", "CheckDosageKey",
                                              "IdKey", "startKey", "xKey", "RecordKey"))
SECRET_FIELD_REFUSAL = (
    "%s is a stored secret (a password, token or key) and this connector does not read, filter "
    "or sort by it. It is not report material: look in Excellent Books itself if it must be seen.")


def is_secret_field(name, as_sort: bool = False) -> bool:
    if not name or str(name).casefold() in NOT_SECRET:
        return False
    return bool((_SECRET_SORT if as_sort else _SECRET_NAME).search(str(name)))


def secret_fields(names, as_sort: bool = False) -> list:
    return sorted({str(n) for n in names if is_secret_field(n, as_sort)})


def strip_secret_fields(rows: list) -> tuple:
    """(rows without any secret-named field, how many fields were dropped)."""
    dropped, out = 0, []
    for row in rows:
        secret = [k for k in row if is_secret_field(k)]
        dropped += len(secret)
        out.append({k: v for k, v in row.items() if k not in secret} if secret else row)
    return out, dropped


PRIVATE_KEY_WITHHELD = "[private key withheld]"
# One line of a key's body: base64, a PEM or OpenPGP armor header, or an OpenPGP checksum.
# Several base64 lines in one cell too, joined by line breaks only (re-review 10-05, N3): a
# cell of words with spaces between them is still not key material.
# The report parser turns a cell's line breaks into spaces, so a parsed cell of two key lines
# reads "line1 line2": whitespace is accepted after a long run only (a PEM line is 64 characters),
# so "Server process running" beside a key still stops the run (N1-N3 re-check 10-05).
_KEY_LINE = re.compile(r"[A-Za-z0-9+/]+={0,2}(?:\r?\n[A-Za-z0-9+/]+={0,2})*|"
                       r"(?:[A-Za-z0-9+/]{40,}={0,2}\s+)+[A-Za-z0-9+/]+={0,2}|"
                       r"=[A-Za-z0-9+/]{4}|"
                       r"(?:Proc-Type|DEK-Info|Version|Comment|MessageID|Hash|Charset):.*", re.S)


def _key_edges(text) -> tuple:
    """(an END line with no BEGIN before it, a BEGIN line with no END after it) in one value."""
    if not isinstance(text, str) or "-----" not in text:
        return False, False
    begins, ends = [], []
    for kind, start, _ in _edges(text):
        (begins if kind == "BEGIN" else ends).append(start)
    return (bool(ends) and (not begins or ends[0] < begins[0]),
            bool(begins) and (not ends or ends[-1] < begins[-1]))


def _key_shaped(value) -> bool:
    """A cell that can be a line of a key's body; a blank one continues the run."""
    if value is None:
        return True
    return isinstance(value, str) and (not value.strip() or bool(_KEY_LINE.fullmatch(value.strip())))


def _split_key_cells(cells: list) -> tuple:
    """A key printed one line per row (a report table, the server log: opus review 10-04, M1).
    Returns (the indexes of the cells that are lines of a key whose BEGIN or END line is in
    another cell, how many keys were counted twice: once at the BEGIN and once at the END).
    The rows can run either way - the server log arrives newest first - so the key-shaped cells
    on BOTH sides of a BEGIN or END cell are hidden, up to the first cell that cannot be part of
    a key. Over-hiding is the cheap direction."""
    edges = [_key_edges(cell) for cell in cells]
    hide = set()
    for i, (closes, opens) in enumerate(edges):
        if not (closes or opens):
            continue
        for step in (-1, 1):
            j = i + step
            while 0 <= j < len(cells) and not any(edges[j]) and _key_shaped(cells[j]):
                hide.add(j)
                j += step
    twice = min(sum(1 for c, _o in edges if c), sum(1 for _c, o in edges if o))
    return hide, twice


_NO_CELL = object()


# A whole reply (HTML or XML) before any parser splits it. Edges are paired by ORDER, not by one
# regex (Sol re-checks of d39c6da and 5021ed0): in reading order every BEGIN takes the next END
# (inner BEGINs swallowed); in a newest-first log every END takes the next BEGIN. Both are tried
# on the whole text and the one leaving fewer lone edges is used (forward on a tie), so two
# newest-first keys never pair across each other. Unbounded and linear. A lone edge (a key cut
# short) stays for mask_private_keys' per-column run. Spaces may arrive escaped.
_SP = r"(?:\s|&#0*32;|&#x0*20;|&nbsp;|&#0*160;|&#xa0;)+"
_DOC_EDGE = re.compile(
    rf"-----(BEGIN|END){_SP}(?:(?:[A-Z]+{_SP})*?PRIVATE{_SP}KEY|"
    rf"PGP{_SP}PRIVATE{_SP}KEY{_SP}BLOCK)-----", re.I)


def _edges(text: str) -> list:
    return [(m.group(1).upper(), m.start(), m.end()) for m in _DOC_EDGE.finditer(text)]


def _pair(edges: list, first: str) -> tuple:
    """(spans, lone edge count): each `first` edge takes the next edge of the other kind."""
    spans, open_at, lone = [], None, 0
    for kind, start, end in edges:
        if kind == first:
            if open_at is None:
                open_at = start
        elif open_at is not None:
            spans.append((open_at, end))
            open_at = None
        else:
            lone += 1
    return spans, lone + (open_at is not None)


def _replace(text: str, spans: list) -> str:
    out, at = [], 0
    for start, end in spans:
        out += [text[at:start], PRIVATE_KEY_WITHHELD]
        at = end
    out.append(text[at:])
    return "".join(out)


def mask_key_text(text: str) -> tuple:
    """(a whole reply's text with every paired private key withheld, how many)."""
    if not isinstance(text, str) or "-----" not in text:
        return text, 0
    edges = _edges(text)
    forward, forward_lone = _pair(edges, "BEGIN")
    backward, backward_lone = _pair(edges, "END")
    spans = backward if backward_lone < forward_lone else forward
    return (_replace(text, spans), len(spans)) if spans else (text, 0)


def _mask_value(value: str) -> tuple:
    """(one cell or field with every key withheld, how many). Forward pairs first; then lone
    ENDs mask from the start (the rest of a key begun in another cell), lone BEGINs to the end,
    and a value holding both is withheld whole: it is a newest-first key or the tail of one key
    and the head of the next, and nothing in it can be told apart."""
    edges = _edges(value)
    if not edges:
        return value, 0
    spans, _lone = _pair(edges, "BEGIN")
    inside = [any(s <= e[1] < t for s, t in spans) for e in edges]
    lone_end = [e for e, i in zip(edges, inside) if not i and e[0] == "END"]
    lone_begin = [e for e, i in zip(edges, inside) if not i and e[0] == "BEGIN"]
    if lone_end and lone_begin:
        return PRIVATE_KEY_WITHHELD, 1
    if lone_end:
        spans = [(0, lone_end[-1][2])] + [s for s in spans if s[0] >= lone_end[-1][2]]
    if lone_begin:
        spans = [s for s in spans if s[1] <= lone_begin[0][1]] + [(lone_begin[0][1], len(value))]
    return _replace(value, spans), len(spans)


def mask_private_keys(obj) -> tuple:
    """(obj with every PEM or OpenPGP private key replaced, how many). Walks containers and strings.
    A key split across the rows of a list is hidden in every row (`_split_key_cells`): per
    column of a list of dicts or of lists, or along a list of strings."""
    count, placed = 0, False

    def mask_text(value: str) -> str:
        nonlocal count, placed
        new, n = _mask_value(value)
        count += n
        placed = placed or bool(n)
        return new

    def split_rows(items: list) -> list:
        nonlocal count, placed
        if not any("-----" in cell for item in items
                   for cell in (item.values() if isinstance(item, dict) else
                                item if isinstance(item, (list, tuple)) else (item,))
                   if isinstance(cell, str)):
            return items
        columns = [(None, list(items))]
        for key in dict.fromkeys(k for item in items if isinstance(item, dict) for k in item):
            columns.append((("k", key), [item.get(key) if isinstance(item, dict) else _NO_CELL
                                         for item in items]))
        width = max((len(item) for item in items if isinstance(item, (list, tuple))), default=0)
        for j in range(width):
            columns.append((("i", j), [item[j] if isinstance(item, (list, tuple)) and j < len(item)
                                       else _NO_CELL for item in items]))
        out = list(items)
        for column, cells in columns:
            hide, twice = _split_key_cells(cells)
            count -= twice
            placed = placed or bool(hide)
            for i in hide:
                if not isinstance(cells[i], str) or not cells[i].strip():
                    continue
                if column is None:
                    out[i] = PRIVATE_KEY_WITHHELD
                elif column[0] == "k":
                    out[i] = {**out[i], column[1]: PRIVATE_KEY_WITHHELD}
                else:
                    row = list(out[i])
                    row[column[1]] = PRIVATE_KEY_WITHHELD
                    out[i] = row if isinstance(items[i], list) else tuple(row)
        return out

    def walk(value):
        if isinstance(value, str):
            return mask_text(value)
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(walk(v) for v in split_rows(list(value)))
        return value
    masked = walk(obj)
    # Something was withheld: the answer says so even when BEGIN/END double counting nets to 0.
    return masked, max(count, 1) if placed else max(count, 0)
