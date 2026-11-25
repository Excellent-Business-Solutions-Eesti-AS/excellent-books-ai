# Excellent Books MCP: guide for users

Ask questions about your own Excellent Books data in plain language. The connector is tested with Claude Desktop on Windows. It runs on your own computer, signs in to Excellent Books as your own Excellent Books user, and passes the answers to Claude.

## What you can ask

Examples:

- How much do our customers owe us right now?
- Which purchase invoices are unpaid?
- Show me the trial balance for last month.
- What is our stock worth?
- How much did we sell to this customer in September?

Ask in any language. The AI finds the right report or register itself, through the free Excellent Knowledge connector (https://knowledge.excellent.ee/mcp): add it too, or the AI can read your registers but cannot look a report up. If an answer looks like it came from the wrong report, ask again and name what you want.

## Whose rights apply

The connector works as the Excellent Books user entered in its settings. It sees and changes only what that user may see and change, and Excellent Books checks those rights on every call.

- Each person uses their own Excellent Books user. Do not share one login between people.
- What your user cannot open in Excellent Books, the connector cannot open either.
- If someone else set the connector up for you, check in Claude Desktop > Settings > Extensions > Excellent Books which server address, company and user it uses. The approval window also names the server, company and Books user a change goes to.

## What leaves your computer

Answers from your Excellent Books go to Claude (Anthropic) through Claude Desktop. The connector itself exchanges data from your Excellent Books only with Claude and with your own Excellent Books server (run by Excellent if Excellent hosts it). The connector asks Excellent's server for its report catalogue and a small control file. Those requests carry no data from your Excellent Books; Excellent's server sees the usual request details, such as the network address they came from. The connector's own usage log (which tool ran, when, how long it took, whether it worked, the connector and Books versions and the kind of AI app) stays on this computer. If you also add the Excellent Knowledge connector, Claude can send it search words or your whole question, which can contain data from your Excellent Books, and these reach Excellent. Its knowledge search keeps the last 1,000 search phrases in memory, with the time and the network address they came from, for usage statistics; they are gone after that server restarts. Its report search keeps none of the question. Its web log records each request's network address, not the words.

You cannot see which of the two searches the AI used. If a question must not reach Excellent, switch the Excellent Knowledge connector off in Claude before you ask it; the AI can then still read your registers, but cannot look a report up. A file you attach to the chat, such as a supplier's delivery note, goes to Claude whether writing is on or off.

## Writing to Excellent Books

Writing is a setting: Claude Desktop > Settings > Extensions > Excellent Books. Restart Claude Desktop after you change it. When writing is off, the connector only reads.

When writing is on:

- The AI can prepare new records and changes in the supported registers and fields, within your Excellent Books rights: quotations, orders, sales invoices, deliveries, purchase orders, purchase invoices, payments, contacts, items and more. One switch covers every kind of write, supplier payments included: with writing on, the AI can also prepare a supplier payment order, and where your bank integration sends payments on ordering, approving it may send the money.
- By default, the connector opens an approval window in your browser on this computer. The window shows what will be saved. Decline throws that preview away. Anything approved before it, such as a new supplier or item made for a delivery, stays in Excellent Books.
- With browser approval, nothing is saved until Approve is pressed in the approval window. Anyone using the browser profile that holds the approval window can press it, so approve only in a profile of your own. A chat-only AI client, with no tool that controls your browser, your screen or a command line on this computer, cannot press it.
- If you switch on approval in the chat, a change is saved after you say yes in the chat. A change that posts to the ledger, moves stock or changes a payment says so before you answer. Your AI passes that yes on, and the connector cannot check that it came from you. Enable **Approve changes in the chat** in the extension settings. Long previews and changes that need a check for an unfinished write still open the approval window.
- An AI with such a tool (a browser extension, computer use, or a command line as in Claude Code) acts as you and could press Approve too; the connector cannot tell its click from yours. Do not let such an AI work with Excellent Books while writing is on.
- Claude Code can run commands on this computer, so with Claude Code, leave writing off.
- Approving can do more than save a record. Approving (OK) a document does what approving it in Excellent Books does: an invoice is posted to the ledger, a delivery moves stock out, and an order changes the quantities on order. A goods receipt is saved already approved, so stock moves in at once. Confirming an incoming payment lowers the customer invoice's open amount. Ordering a supplier payment lowers the supplier invoice's open amount at once and, where your bank integration sends payments on ordering, may also send it to the bank; one approval may order a payment and mark it done. The preview warns about each of these, and none can be undone through the connector.
- An approval (OK), a payment step or a goods receipt does not go through until you confirm that you understand: by the tick in the approval window or, with chat approval on, by your yes to the preview that shows the warning. The connector does not take the approval off a document or mark one invalid.
- A preview stays open for 15 minutes. If you have not pressed Approve after about two minutes, the AI is told the window is still waiting. Once you have pressed it, ask the AI to continue. If saving has not started within five minutes of your approval, and within those 15 minutes, the approval lapses and nothing is saved. A save that has started is finished.
- If you are not sure a change was saved, check in Excellent Books before you ask again. If the connection dropped during the write, check the result first. Then restart the connector if it runs on your computer, or sign out and back in if you use the hosted connector.
- Keep Claude Desktop's own confirmation for the connector's write tool switched on. It is a second check, not the one the connector relies on.
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

Answers can contain personal data, such as names, personal ID codes, e-mail addresses, phone numbers and messages. Your company is the controller of that data and decides whether Anthropic may receive it, under the GDPR and your agreements with Anthropic. If you do not know whether your company has decided this, ask whoever handles data protection there before you accept.

The connector reads Excellent Books only after you accept the current personal data text. In Claude Desktop, tick the personal data box in Settings > Extensions > Excellent Books and restart Claude Desktop. If the wording you accepted changes, the connector opens a consent window. To withdraw, untick the box and restart Claude Desktop; answers already sent stay with Claude under your agreements with Anthropic.

## HR and payroll data

HR and payroll data can be read once you say yes to them after four warnings: data protection, the GDPR, the EU AI Act and accuracy. To choose, ask the AI to switch HR data on: the connector opens a window on this computer with the four warnings and **Switch on** and **Not now**. Only a click there switches HR data on. Anyone using that browser profile can click it; a chat-only AI client, with no tool that controls your browser, your screen or a command line on this computer, cannot.

The HR yes covers the employee, payroll, absence and HR registers and reports on the connector's own list. Contacts, items and invoices that Excellent Books files under the payroll or HR modules, salary postings in the general ledger, and personal data in other registers and reports are readable without it.

Every HR or payroll answer repeats the four warnings. A single tool result never shows more than 12 HR or payroll rows, so in a company of 12 employees or fewer one result can show every one of them. A result covering more withholds its rows but still shows its count and totals, up to 12 named group totals (for example per department or per employee) and each document's header with its party. This does not limit what the AI puts together from several narrower questions, and a total over one or two people can still show their pay.

In Claude Desktop, say "Switch HR data off" at any time. In the window that opens, click **Switch off** and check that it says **Consent is off.**

If the warnings you accepted change, HR and payroll data are off again until you read the new warnings in that window and choose again.

## The AI can be wrong

Like every language model, the AI can misread a question or a report. Ask it which report or register an answer came from, and check important figures in Excellent Books before you act on them, send them on or decide anything based on them.

## Never paste a password into the chat

The connector reads your login from its own settings. The AI never needs it. If a password reaches a chat, deleting the message is not enough: change the password in Excellent Books.

## Developer ZIP and Claude Code

The ZIP from https://booksmcp.excellent.ee/download is the developer route: Python on your own computer and Claude Code. INSTALL.md in the ZIP has every step and a table of error messages.

1. Install Python 3.11 or newer from https://www.python.org/downloads/. On Windows, tick "Add python.exe to PATH" on the first screen.
2. Unzip the download to a folder that OneDrive or Dropbox does not sync.
3. Open a terminal in that folder and run `pip install -r requirements.txt`.
4. Run `python -m ebmcp.setup`. It asks for the server address with its port and company number, your own Excellent Books user code and its password, without showing the password. It writes `.env`, then asks you to accept the personal data text and, separately, the four HR warnings.
5. Start the connector with `python -m ebmcp.server` and leave that window open. It should say `Uvicorn running on http://127.0.0.1:8005`: the connector has started. Once the personal data text is accepted, it signs in to Excellent Books right away to read which report and register fields your Books has; a sign-in problem shows at your first question. `Refusing to start an unauthenticated server` means `.env` is missing (run step 4) or its line `EBMCP_ALLOW_OPEN=1` was deleted. That line runs the connector without a sign-in of its own, so it starts only on this computer's own address: it refuses to start if `EBMCP_HOST` names a network address.
6. In Claude Code, in another terminal: `claude mcp add --transport http excellent-books http://127.0.0.1:8005/mcp`
7. Add the free Excellent Knowledge connector too: `claude mcp add --transport http excellent-knowledge https://knowledge.excellent.ee/mcp`

### What leaves your computer

Answers from your Excellent Books go to the AI service you connected. The connector itself exchanges data from your Excellent Books only with that service and with your own Excellent Books server (run by Excellent if Excellent hosts it). The connector asks Excellent's server for its report catalogue and a small control file. Those requests carry no data from your Excellent Books; Excellent's server sees the usual request details, such as the network address they came from. The connector's own usage log (which tool ran, when, how long it took, whether it worked, the connector and Books versions and the kind of AI app) stays on this computer. If you also add the Excellent Knowledge connector, your AI can send it search words or your whole question, which can contain data from your Excellent Books, and these reach Excellent. Its knowledge search keeps the last 1,000 search phrases in memory, with the time and the network address they came from, for usage statistics; they are gone after that server restarts. Its report search keeps none of the question. Its web log records each request's network address, not the words.

### Settings in the ZIP

- Writing: `EBMCP_WRITES=yes` in `.env` and a restart switch it on. The approval window opens in your browser by default. Set `EBMCP_APPROVE_IN=chat` to approve changes in the chat. Claude Code can run commands on this computer, so with Claude Code, leave writing off.
- Personal data: to accept later or review changed wording, run `python -m ebmcp.setup --consent`. To withdraw, set `EBMCP_GDPR_CONSENT=no` in `.env`; if your AI app's connector settings also set `EBMCP_GDPR_CONSENT` as an environment variable, that value wins, so change it there too.
- HR and payroll: run `python -m ebmcp.setup --hr-consent` to review the warnings or change your answer, or set `EBMCP_HR_CONSENT=no` in `.env` to turn access off.

## Help

- How Excellent Books works: add the free Excellent Knowledge connector, https://knowledge.excellent.ee/mcp
- Questions and problems: excellentinfo@excellent.ee
