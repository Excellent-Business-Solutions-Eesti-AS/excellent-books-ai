# Excellent Books for Codex

Ask questions about your own Excellent Books data in plain language. The connector finds the right
report or register, runs it in your Excellent Books and passes the answer to the AI. It signs in as
your own Excellent Books user, so it sees only what your user may see. INSTALL.md, one folder up,
has the install steps.

**Add the free Excellent Knowledge connector alongside it:** `https://knowledge.excellent.ee/mcp`.
The AI finds reports there; without it, the AI can read your registers but cannot look a report up.
What you ask can reach Excellent through it, with data from your Excellent Books: see "What leaves
your computer" before you add it.

## What leaves your computer

Answers from your Excellent Books go to OpenAI's Codex / ChatGPT through the Codex app on this computer. The connector itself exchanges data from your Excellent Books only with OpenAI's Codex / ChatGPT and with your own Excellent Books server (run by Excellent if Excellent hosts it). The connector asks Excellent's server for its report catalogue and a small control file. Those requests carry no data from your Excellent Books; Excellent's server sees the usual request details, such as the network address they came from. The connector's own usage log (which tool ran, when, how long it took, whether it worked, the connector and Books versions and the kind of AI app) stays on this computer. If you also add the Excellent Knowledge connector, Codex can send it search words or your whole question, which can contain data from your Excellent Books, and these reach Excellent. Its knowledge search keeps the last 1,000 search phrases in memory, with the time and the network address they came from, for usage statistics; they are gone after that server restarts. Its report search keeps none of the question. Its web log records each request's network address, not the words.

You cannot see which of the two searches the AI used. If a question must not reach Excellent,
switch the Excellent Knowledge connector off in Codex before you ask it.

On its first start the plugin downloads the uv program from GitHub (Astral's official release,
checked against a fixed SHA-256) and a Python runtime through it, into
`%LOCALAPPDATA%\ExcellentBooksMCP-Plugin`. Your Books login is saved in the same folder.

## Writing

Writing is a setting, off as installed. Approving a change in Excellent Books does what approving
it there does: an invoice is posted to the ledger, a delivery moves stock. Codex can run commands
on this computer, and an AI that can run commands or control your browser acts as you and could
approve too; the connector cannot tell its click from yours.

**The AI can be wrong.** Ask it which report or register an answer came from, and check important
figures in Excellent Books before you act on them.

**excellentinfo@excellent.ee**
