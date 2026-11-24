"""Shared customer claims for the three ways to use Excellent Books MCP."""

from .erp_fields import PROBED_VERSION as SUPPORTED_BUILD

TOOLS_READ = 3
TOOLS_WRITE = 5
TOOLS_DESKTOP_EXTRA = 1  # hr_data_consent opens the local consent window.
TOOLS_PLUGIN_EXTRA = 2  # hr_data_consent and open_settings (the Connect Excellent Books page).
TESTED_CLIENT = {
    "desktop": "Claude Desktop on Windows",
    "local": "Claude Code",
    "hosted": "claude.ai",
    "plugin": "Codex desktop app on Windows",
}
WHOSE_RIGHTS = "your own Excellent Books user"

# Task 52 review fixes (Sol part B and Astra's blind read, 2026-11-20): one wording per promise,
# in every customer text that describes it (tests/test_claims.py checks where each must appear).
# The approval promise carries its condition in the same sentence (approval design section 3.5).
# Sol re-check 2026-11-20, MUST-FIX 2: the window is bound to a browser profile (the local page's
# cookie, the hosted approver cookies), not to a person, so whoever uses that profile can approve.
APPROVAL_PROMISE = (
    "With browser approval, nothing is saved until Approve is pressed in the approval window. "
    "Anyone using the browser profile that holds the approval window can press it, so approve "
    "only in a profile of your "
    "own. A chat-only AI client, with no tool that controls your browser, your screen or a "
    "command line on this computer, cannot press it."
)
CHAT_APPROVAL = (
    "If you switch on approval in the chat, a change is saved after you say yes in the chat. "
    "A change that posts to the ledger, moves stock or changes a payment says so before you "
    "answer. Your AI passes that yes on, and the connector cannot check that it came from you."
)
CHAT_APPROVAL_ET = (  # Kaupo approved this wording on 2026-11-23
    "Kui lülitate sisse vestluses kinnitamise, salvestatakse muudatus pärast seda, kui ütlete "
    "vestluses „jah“. Kui muudatus mõjutab pearaamatut, laoseisu või makset, on see kokkuvõttes "
    "kirjas enne, kui vastate. Teie tehisintellekt edastab selle vastuse ja ühendus ei saa "
    "kontrollida, kas vastus tuli Teilt."
)
AI_WITH_CONTROL = (
    "An AI with such a tool (a browser extension, computer use, or a command line as in Claude "
    "Code) acts as you and could press Approve too; the connector cannot tell its click from yours."
)
CLAUDE_CODE_WRITES = (
    "Claude Code can run commands on this computer, so with Claude Code, leave writing off."
)
# What approving does (changes.APPROVE_WARNING, changes.PAYMENT_STEPS, receipts: created OK'd).
# Not every OK is a ledger posting (Sol re-check 2026-11-20, SHOULD 5; write recipes 4 and 5).
APPROVAL_EFFECTS = (
    "Approving can do more than save a record. Approving (OK) a document does what approving it "
    "in Excellent Books does: an invoice is posted to the ledger, a delivery moves stock out, and "
    "an order changes the quantities on order. A goods receipt is saved already approved, so stock "
    "moves in at once. Confirming an incoming payment lowers the customer invoice's open amount. "
    "Ordering a supplier payment lowers the supplier invoice's open amount at once and, where your "
    "bank integration sends payments on ordering, may also send it to the bank; one approval may "
    "order a payment and mark it done. The preview warns about each of these, and none can be "
    "undone through the connector."
)
# Astra's second blind read, 2: said wherever writing is switched on (changes.PAYMENT_STEPS).
ONE_SWITCH = (
    "One switch covers every kind of write, supplier payments included: with writing on, the AI "
    "can also prepare a supplier payment order, and where your bank integration sends payments on "
    "ordering, approving it may send the money."
)
# Scope of writing: changes.closed_reason, the field listings and Books' own rights decide.
WRITE_SCOPE = "supported registers and fields, within your Excellent Books rights"
CUSTOMER_CONTACT = "A sales invoice goes only to a contact marked as a customer."
# Privacy boundaries as the code draws them (privacy.is_hr, limit_payroll, is_blocked,
# is_secret_field, the private-key mask in server._finish).
# Sol re-check 2026-11-20, SHOULD 8: the gate is the connector's own list (privacy.HR_REGISTERS,
# HR_REPORT_WINDOWS, the EP/HRM prefixes), not Books' module assignment.
HR_SCOPE = (
    "The HR yes covers the employee, payroll, absence and HR registers and reports on the "
    "connector's own list. Contacts, items and invoices that Excellent Books files under the "
    "payroll or HR modules, salary postings in the general ledger, and personal data in other "
    "registers and reports are readable without it."
)
# SHOULD 9: limit_payroll keeps up to 12 groups, and a limited document keeps its header and party.
ROW_LIMIT = (
    "A single tool result never shows more than 12 HR or payroll rows, so in a company of 12 "
    "employees or fewer one result can show every one of them. A result covering more withholds "
    "its rows but still shows its count and totals, up to 12 named group totals (for example per "
    "department or per employee) and each document's header with its party. This does not limit "
    "what the AI puts together from several narrower questions, and a total over one or two "
    "people can still show their pay."
)
SECRETS_SCOPE = (
    "Passwords, API tokens and private keys are hidden where Excellent Books keeps them: the "
    "registers that hold them are refused, fields named like a password, token or key are "
    "dropped, and recognisable private-key text is masked in every answer. A password typed into "
    "an ordinary note, comment or message is not recognised and can be shown."
)


def tool_count(mode: str, writes: bool) -> int:
    """Count the tools listed for the mode and its write switch."""
    if mode not in TESTED_CLIENT:
        raise ValueError(f"unknown connector mode: {mode!r}")
    extra = {"desktop": TOOLS_DESKTOP_EXTRA, "plugin": TOOLS_PLUGIN_EXTRA}.get(mode, 0)
    return TOOLS_READ + (TOOLS_WRITE if writes else 0) + extra


_CATALOGUE_AND_CONTROL = (
    "The connector asks Excellent's server for its report catalogue and a small control file. "
    "Those requests carry no data from your Excellent Books; Excellent's server sees the usual "
    "request details, such as the network address they came from. "
)
_LOCAL_USAGE = (
    "The connector's own usage log (which tool ran, when, how long it took, whether it worked, "
    "the connector and Books versions and the kind of AI app) stays on this computer. "
)
# Checked in c:\klientideandmed\excellent-knowledge-mcp-server at e111af6 (2026-11-19):
# server.py:3444-3454 `_record_search` keeps each search_knowledge phrase with its time, source,
# result count and caller IP in the in-memory list `_search_queries` (server.py:73-74, the last
# 1,000), called at server.py:3931 and :3934; /api/stats shows them only to an API-key holder
# (server.py:3736-3737). The request log line (server.py:3609) holds method, path, IP and status,
# not the phrase. books_find_report (server.py:4167) takes the person's whole question and records
# none of it. Nothing writes the phrases to disk, so a restart clears them. Sol review of 849e1ca,
# MUST-FIX 2: the AI can send Knowledge the whole question, which can hold Books data.
_KNOWLEDGE = (
    "If you also add the Excellent Knowledge connector, %s can send it search words or your whole "
    "question, which can contain data from your Excellent Books, and these reach Excellent. Its "
    "knowledge search keeps the last 1,000 search phrases in memory, with the time and the network "
    "address they came from, for usage statistics; they are gone after that server restarts. Its "
    "report search keeps none of the question. Its web log records each request's network "
    "address, not the words."
)
_WHAT_LEAVES = {
    "desktop": (
        "Answers from your Excellent Books go to Claude (Anthropic) through Claude Desktop. The "
        "connector itself exchanges data from your Excellent Books only with Claude and with your "
        "own Excellent Books server (run by Excellent if Excellent hosts it). "
        + _CATALOGUE_AND_CONTROL + _LOCAL_USAGE + _KNOWLEDGE % "Claude"
    ),
    "local": (
        "Answers from your Excellent Books go to the AI service you connected. The connector "
        "itself exchanges data from your Excellent Books only with that service and with your own "
        "Excellent Books server (run by Excellent if Excellent hosts it). "
        + _CATALOGUE_AND_CONTROL + _LOCAL_USAGE + _KNOWLEDGE % "your AI"
    ),
    # The ChatGPT/Codex plugin (design 2026-11-23, Review change 6): the Desktop paragraph with
    # OpenAI's Codex / ChatGPT as the recipient.
    "plugin": (
        "Answers from your Excellent Books go to OpenAI's Codex / ChatGPT through the Codex app on "
        "this computer. The connector itself exchanges data from your Excellent Books only with "
        "OpenAI's Codex / ChatGPT and with your own Excellent Books server (run by Excellent if "
        "Excellent hosts it). "
        + _CATALOGUE_AND_CONTROL + _LOCAL_USAGE + _KNOWLEDGE % "Codex"
    ),
    "hosted": (
        "Your sign-in details go to Excellent's hosted connector, which uses them to sign in to "
        "Excellent Books. Your password is used for that sign-in only and is not stored by the "
        "hosted connector. Tool requests from your connected AI provider and answers from your "
        "Excellent Books pass through the hosted connector; Claude at claude.ai is the AI client "
        "it is tested with. " + _KNOWLEDGE % "your AI"
    ),
}


# Task 53: the Desktop paragraph in Estonian, the same promises as the English one above, nothing
# added or softened (the Estonian consent page shows it; Kaupo reads it before release). Only Desktop
# has an Estonian page text: the developer ZIP's setup is English, hosted is a draft (Task 48).
# "1000" is how Estonian writes 1,000. Checked with the Estonian NLP tools 2026-11-19.
_WHAT_LEAVES_ET = {
    "desktop": (
        "Vastused Teie Excellent Booksist liiguvad Claude Desktopi kaudu Claude'ile (Anthropic). "
        "Ühendus ise vahetab Teie Excellent Booksi andmeid ainult Claude'iga ja Teie enda "
        "Excellent Booksi serveriga (mida haldab Excellent, kui Excellent seda majutab). "
        "Ühendus küsib Excellenti serverist aruannete kataloogi ja väikest kontrollfaili. Nendes "
        "päringutes ei ole Teie Excellent Booksi andmeid; Excellenti server näeb päringu tavalisi "
        "üksikasju, näiteks võrguaadressi, kust päring tuli. "
        "Ühenduse enda kasutuslogi jääb sellesse arvutisse. Selles on kirjas, milline tööriist "
        "käivitati, millal, kui kaua see kestis, kas see õnnestus, ühenduse ja Booksi versioonid "
        "ning tehisintellekti rakenduse liik. "
        "Kui lisate ka Excellent Knowledge'i ühenduse, võib Claude saata sellele otsingusõnu või "
        "kogu Teie küsimuse. Küsimuses võib olla Teie Excellent Booksi andmeid. Otsingusõnad ja "
        "küsimus jõuavad Excellentini. Selle teadmistebaasi otsing hoiab kasutusstatistika jaoks "
        "mälus viimast 1000 otsingufraasi koos aja ja võrguaadressiga, kust need tulid; selle "
        "serveri taaskäivitamisel need kaovad. Selle aruannete otsing ei säilita küsimusest "
        "midagi. Selle veebiserveri logi salvestab iga päringu võrguaadressi, mitte sõnu."
    ),
}


def _plugin_et() -> str:
    """The ChatGPT/Codex plugin's Estonian paragraph: the Desktop one with OpenAI's Codex as the
    recipient, three replacements and nothing else (slice 3). Approved by Kaupo 2026-11-24."""
    text = _WHAT_LEAVES_ET["desktop"]
    for old, new in (("liiguvad Claude Desktopi kaudu Claude'ile (Anthropic)",
                      "liiguvad Codexi rakenduse kaudu OpenAI-le"),
                     ("ainult Claude'iga", "ainult OpenAI-ga"),
                     ("võib Claude saata", "võib Codex saata")):
        if text.count(old) != 1:
            raise RuntimeError("the Desktop Estonian paragraph changed: redo the plugin text")
        text = text.replace(old, new)
    return text


_WHAT_LEAVES_ET["plugin"] = _plugin_et()


def what_leaves(mode: str, language: str = "en") -> str:
    """Return the data disclosure paragraph for the selected mode (and language)."""
    texts = _WHAT_LEAVES if language == "en" else _WHAT_LEAVES_ET if language == "et" else {}
    try:
        return texts[mode]
    except KeyError:
        raise ValueError(f"unknown connector mode or language: {mode!r}, {language!r}") from None
