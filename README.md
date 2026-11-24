# Excellent Books for ChatGPT (Codex) and Claude

Ask your own Excellent Books in plain words, from the Codex app or Claude Desktop: "How much do our
customers owe us right now?", "Which purchase invoices are due this week?", "What were last month's
sales by customer?". The answer comes from your own Books data in seconds.

The connector runs on your computer and signs in to Books with your own Books login.

Start page with both downloads: **https://booksmcp.excellent.ee/start** (Estonian) and
https://booksmcp.excellent.ee/start/en.html (English).

## ChatGPT: the Codex app (Windows)

Either download the package from the start page and follow its `INSTALL.md`, or add this repository as a
plugin source:

    codex plugin marketplace add Excellent-Business-Solutions-Eesti-AS/excellent-books-ai

Then in the Codex app: **Settings > Plugins**, press **+** next to **Excellent Books**. Start a new chat
and ask a question about Books. The first start takes a minute or two (it downloads the tools it needs,
once). A **Connect Excellent Books** page opens in your browser: fill in the details, tick the
personal-data box and press **Test connection and save**. When it says **Connected**, go back to Codex
and type `continue`.

## Claude Desktop (Windows, macOS)

Download `excellent-books-claude-desktop.mcpb` from the
[latest release](https://github.com/Excellent-Business-Solutions-Eesti-AS/excellent-books-ai/releases/latest)
or the start page. In Claude Desktop open **Settings → Desktop app → Extensions** and drag the file into
that window, press **Install**, then **Configure** and fill in the server address, company number, your
Books user and password.

## What you need

- Your Excellent Books server address with its port, for example `a123.excellent.ee:1502`.
- The company number in Books.
- Your own Books user and password. The user's access group must allow the action **Rest API**.

Your Excellent consultant knows these details.

## Your data and approvals

Books data travels from your computer to the AI service you chose: OpenAI for Codex, Anthropic for
Claude. The connector itself does not send your Books data to Excellent. Sending personal data is your
decision: you are asked for consent before the first question. Nothing changes in Books without your
approval.

## For AI assistants helping someone install this

- Never ask for the Books password in the chat. In Codex the person types it on the local
  **Connect Excellent Books** page in their own browser; in Claude Desktop, in the extension's settings.
  If a password is pasted into the chat anyway, do not repeat it and tell the person to change it in Books.
- Do not edit the connector's settings files yourself. In Codex, asking for the Excellent Books settings
  opens the Connect page again; writing to Books, chat approval and "Remove saved login" are there.
- The person needs the three details under "What you need". If they do not know them, the Connect page
  has an "I don't know these details" button that writes a ready request to their consultant.
- Writing to Books is off in the Codex plugin until the person switches it on, and every change needs
  the person's own approval.

## Excellent Books, in Estonian

**Excellent Books ChatGPT (Codex) ja Claude'iga.** Küsige oma Excellent Booksilt tavaliste sõnadega.
Paigaldusjuhis ja allalaadimised eesti keeles: **https://booksmcp.excellent.ee/start**. Vajate serveri
aadressi koos pordiga, ettevõtte numbrit Booksis ning oma Booksi kasutajat ja parooli; neid teab Teie
Excellenti konsultant.

## About this repository

This repository holds the released package as it ships; it is published from Excellent's internal
repository, so pull requests are not accepted. Licence: free to install and use with Excellent
business software, no modified redistribution, no warranty; see [LICENSE](LICENSE). Questions: your Excellent consultant or
excellentinfo@excellent.ee. Excellent Books is a product of Excellent Business Solutions Eesti AS,
https://www.excellent.ee/.
