"""The customer guide: what the connector does, whose rights apply, the rules, personal data and
that HR and payroll data are restricted. One source, `guide.md` beside this file, served three ways: a web
page at /guide, the MCP resource `URI` and the MCP prompt `books_guide`.

The four HR warnings are not repeated here: the setup screen and every HR answer carry them.
"""
from __future__ import annotations

import html as _html
import re
from pathlib import Path


SOURCE = Path(__file__).with_name("guide.md")
URI = "guide://excellent-books-mcp"
WEB_URL = "https://booksmcp.excellent.ee/guide"
TITLE = "Excellent Books MCP guide"


def text(mode: str | None = None) -> str:
    """The guide. `mode` "plugin": the ChatGPT/Codex plugin's own text (PLUGIN_TEXT), which names
    no other AI vendor (Astra recheck of the slice 2 fix); every other mode reads `guide.md`."""
    if mode == "plugin":
        return PLUGIN_TEXT
    return SOURCE.read_text(encoding="utf-8")


# The plugin's guide: the same rules as guide.md, in the plugin's own words. Kept here, not in a
# second .md file, so the shipped file list stays as it is. Change both when a rule changes.
PLUGIN_TEXT = """# Excellent Books plugin: guide for users

Ask questions about your own Excellent Books data in plain language. The plugin runs the connector on your own computer, signs in to Excellent Books as your own Excellent Books user, and passes the answers to your AI service.

## What you can ask

Examples:

- How much do our customers owe us right now?
- Which purchase invoices are unpaid?
- Show me the trial balance for last month.
- What is our stock worth?
- How much did we sell to this customer in September?

Ask in any language. The AI finds the right report or register itself, through the free Excellent Knowledge connector (https://knowledge.excellent.ee/mcp): add it too, or the AI can read your registers but cannot look a report up. If an answer looks like it came from the wrong report, ask again and name what you want.

## Whose rights apply

The connector works as the Excellent Books user saved on its Connect Excellent Books page. It sees and changes only what that user may see and change, and Excellent Books checks those rights on every call.

- Each person uses their own Excellent Books user. Do not share one login between people.
- What your user cannot open in Excellent Books, the connector cannot open either.
- To see which server address, company and user it uses, ask the AI to open the Excellent Books settings. The approval window also names the server, company and Books user a change goes to.

## What leaves your computer

Answers from your Excellent Books go to the AI service you use. The connector itself exchanges data from your Excellent Books only with that service and with your own Excellent Books server (run by Excellent if Excellent hosts it). The connector asks Excellent's server for its report catalogue and a small control file. Those requests carry no data from your Excellent Books; Excellent's server sees the usual request details, such as the network address they came from. The connector's own usage log (which tool ran, when, how long it took, whether it worked, the connector and Books versions and the kind of AI app) stays on this computer. If you also add the Excellent Knowledge connector, your AI can send it search words or your whole question, which can contain data from your Excellent Books, and these reach Excellent. Its knowledge search keeps the last 1,000 search phrases in memory, with the time and the network address they came from, for usage statistics; they are gone after that server restarts. Its report search keeps none of the question. Its web log records each request's network address, not the words.

You cannot see which of the two searches the AI used. If a question must not reach Excellent, switch the Excellent Knowledge connector off in your AI app before you ask it; the AI can then still read your registers, but cannot look a report up. A file you attach to the chat, such as a supplier's delivery note, goes to your AI service whether writing is on or off.

## Writing to Excellent Books

Writing is a setting: **Allow saving changes** on the Connect Excellent Books page. Switching it off counts at once. When writing is off, the connector only reads.

When writing is on:

- The AI can prepare new records and changes in the supported registers and fields, within your Excellent Books rights: quotations, orders, sales invoices, deliveries, purchase orders, purchase invoices, payments, contacts, items and more. One switch covers every kind of write, supplier payments included: with writing on, the AI can also prepare a supplier payment order, and where your bank integration sends payments on ordering, approving it may send the money.
- By default, the connector opens an approval window in your browser on this computer. The window shows what will be saved. Decline throws that preview away. Anything approved before it, such as a new supplier or item made for a delivery, stays in Excellent Books.
- With browser approval, nothing is saved until Approve is pressed in the approval window. Anyone using the browser profile that holds the approval window can press it, so approve only in a profile of your own. A chat-only AI client, with no tool that controls your browser, your screen or a command line on this computer, cannot press it.
- If you switch on approval in the chat, a change is saved after you say yes in the chat. A change that posts to the ledger, moves stock or changes a payment says so before you answer. Your AI passes that yes on, and the connector cannot check that it came from you. Switch on **Approve in chat** on the Connect Excellent Books page and restart your AI app; switching it off counts at once. Long previews and changes that need a check for an unfinished write still open the approval window.
- An AI with such a tool (a browser extension, computer use, or a command line as in Codex) acts as you and could press Approve too; the connector cannot tell its click from yours. Do not let such an AI work with Excellent Books while writing is on.
- Codex can run commands on this computer, so with Codex, leave writing off.
- Approving can do more than save a record. Approving (OK) a document does what approving it in Excellent Books does: an invoice is posted to the ledger, a delivery moves stock out, and an order changes the quantities on order. A goods receipt is saved already approved, so stock moves in at once. Confirming an incoming payment lowers the customer invoice's open amount. Ordering a supplier payment lowers the supplier invoice's open amount at once and, where your bank integration sends payments on ordering, may also send it to the bank; one approval may order a payment and mark it done. The preview warns about each of these, and none can be undone through the connector.
- An approval (OK), a payment step or a goods receipt does not go through until you confirm that you understand: by the tick in the approval window or, with chat approval on, by your yes to the preview that shows the warning. The connector does not take the approval off a document or mark one invalid.
- A preview stays open for 15 minutes. If you have not pressed Approve after about two minutes, the AI is told the window is still waiting. Once you have pressed it, ask the AI to continue. If saving has not started within five minutes of your approval, and within those 15 minutes, the approval lapses and nothing is saved. A save that has started is finished.
- A preview belongs to the Books connection it was made for. If the settings name another server, company or user before you approve, the preview is neither shown nor saved: ask the AI to prepare it again.
- If you are not sure a change was saved, check in Excellent Books before you ask again. If the connection dropped during the write, check the result first. Then restart your AI app.
- If your AI app asks you to confirm a tool call before it runs, keep that confirmation on for the connector's write tool. It is a second check, not the one the connector relies on.
- It does not delete anything. Delete in Excellent Books.
- It does not change settings blocks, access rights, logins, licences, timed jobs, queues, server registers, histories, or the registers Books keeps itself (transactions, open invoices, prepayments, stock status).
- It does not set or clear posting and status ticks other than the approval, such as a stock movement's sent tick or a production's finished tick. Set those in Excellent Books.
- Another user can change a document between the final check and saving its approval. The connector checks it again after saving; if it reports a change, open the document in Excellent Books and correct it there.
- On a payment it writes only the fields tested on a demo server (payment mode, date, comment, the invoice paid and the amount); other payment statuses are changed in Excellent Books.
- A sales invoice goes only to a contact marked as a customer.
- Purchase invoice writes require a verified Books build. If the connector cannot verify the build, enter the invoice in Excellent Books.

## What it does not do, whoever asks

- It does not run reports that could change data or restart the server.
- Passwords, API tokens and private keys are hidden where Excellent Books keeps them: the registers that hold them are refused, fields named like a password, token or key are dropped, and recognisable private-key text is masked in every answer. A password typed into an ordinary note, comment or message is not recognised and can be shown.
- A single tool result never shows more than 12 HR or payroll rows, so in a company of 12 employees or fewer one result can show every one of them. A result covering more withholds its rows but still shows its count and totals, up to 12 named group totals (for example per department or per employee) and each document's header with its party. This does not limit what the AI puts together from several narrower questions, and a total over one or two people can still show their pay. Export payroll in Excellent Books itself.

## Personal data and the GDPR

Answers can contain personal data, such as names, personal ID codes, e-mail addresses, phone numbers and messages. Your company is the controller of that data and decides whether the provider of your AI service may receive it, under the GDPR and your agreements with that provider. If you do not know whether your company has decided this, ask whoever handles data protection there before you accept.

The connector reads Excellent Books only after you accept the current personal data text on the Connect Excellent Books page. If the wording you accepted changes, the page asks you again. To withdraw, use **Remove saved login** on that page: it removes the saved login from this computer and withdraws the consent; answers already sent stay with your AI service under your agreements with its provider.

## HR and payroll data

HR and payroll data can be read once you say yes to them after four warnings: data protection, the GDPR, the EU AI Act and accuracy. To choose, ask the AI to switch HR data on: the connector opens a window on this computer with the four warnings and **Switch on** and **Not now**. Only a click there switches HR data on. Anyone using that browser profile can click it; a chat-only AI client, with no tool that controls your browser, your screen or a command line on this computer, cannot.

The HR yes covers the employee, payroll, absence and HR registers and reports on the connector's own list. Contacts, items and invoices that Excellent Books files under the payroll or HR modules, salary postings in the general ledger, and personal data in other registers and reports are readable without it.

Every HR or payroll answer repeats the four warnings. A single tool result never shows more than 12 HR or payroll rows, so in a company of 12 employees or fewer one result can show every one of them. A result covering more withholds its rows but still shows its count and totals, up to 12 named group totals (for example per department or per employee) and each document's header with its party. This does not limit what the AI puts together from several narrower questions, and a total over one or two people can still show their pay.

Say "Switch HR data off" at any time. In the window that opens, click **Switch off** and check that it says **Consent is off.**

If the warnings you accepted change, HR and payroll data are off again until you read the new warnings in that window and choose again.

## The AI can be wrong

Like every language model, the AI can misread a question or a report. Ask it which report or register an answer came from, and check important figures in Excellent Books before you act on them, send them on or decide anything based on them.

## Never paste a password into the chat

The connector reads your login from its own settings, saved on the Connect Excellent Books page. The AI never needs it. If a password reaches a chat, deleting the message is not enough: change the password in Excellent Books.

## Help

- How Excellent Books works: add the free Excellent Knowledge connector, https://knowledge.excellent.ee/mcp
- Questions and problems: excellentinfo@excellent.ee
"""


# No quote, apostrophe or angle bracket in a URL: it goes into an href attribute.
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s\"'<>]+)\)|(https?://[^\s<>\"')]+)")


def _inline(raw: str) -> str:
    """Escape first, then the few marks the guide uses: `code`, **bold**, links."""
    out = _html.escape(raw, quote=False)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)

    def link(m):
        label, url = (m.group(1), m.group(2)) if m.group(2) else (m.group(3), m.group(3))
        return '<a href="%s">%s</a>' % (url, label)
    return _LINK.sub(link, out)


def render(markdown: str) -> str:
    """The guide's own subset of Markdown: headings, bullets, numbered lists, paragraphs."""
    parts, list_tag, para = [], None, []

    def flush():
        nonlocal list_tag
        if para:
            parts.append("<p>%s</p>" % _inline(" ".join(para)))
            para.clear()
        if list_tag:
            parts.append("</%s>" % list_tag)
            list_tag = None

    for line in markdown.splitlines():
        stripped = line.strip()
        heading = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        item = re.match(r"^(?:[-*]|(\d+)\.)\s+(.*)$", stripped)
        if not stripped:
            flush()
        elif heading:
            flush()
            level = len(heading.group(1))
            parts.append("<h%d>%s</h%d>" % (level, _inline(heading.group(2)), level))
        elif item:
            if para:
                parts.append("<p>%s</p>" % _inline(" ".join(para)))
                para.clear()
            tag = "ol" if item.group(1) else "ul"
            if list_tag != tag:
                if list_tag:
                    parts.append("</%s>" % list_tag)
                parts.append("<%s>" % tag)
                list_tag = tag
            parts.append("<li>%s</li>" % _inline(item.group(2)))
        else:
            para.append(stripped)
    flush()
    return "\n".join(parts)


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<style>
:root { --bg: #ffffff; --fg: #1d1d1f; --muted: #5f6368; --rule: #e3e3e6; --code: #f2f2f4;
        --link: #0b57d0; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #161618; --fg: #ececee; --muted: #a3a3a8; --rule: #2e2e33; --code: #26262b;
          --link: #8ab4f8; }
}
body { margin: 0; background: var(--bg); color: var(--fg);
       font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 720px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 1.8rem; line-height: 1.25; margin: 0 0 16px; }
h2 { font-size: 1.25rem; margin: 40px 0 8px; padding-top: 16px; border-top: 1px solid var(--rule); }
p, li { color: var(--fg); }
ol li { margin-bottom: 8px; }
code { background: var(--code); padding: 1px 5px; border-radius: 4px; font-size: 0.92em;
       overflow-wrap: anywhere; }
a { color: var(--link); overflow-wrap: anywhere; }
</style>
</head>
<body><main>
%(body)s
</main></body>
</html>
"""


def html() -> str:
    return _PAGE % {"title": _html.escape(TITLE), "body": render(text())}
