# Install Excellent Books for Codex on Windows

Excellent Books for Codex lets you ask about your own Excellent Books data in plain words. It runs
on your computer and signs in to Books with your own Books login.

You need the Codex app for Windows and an internet connection.

## Install

1. Unzip this package into a folder you keep, for example `Documents\Excellent Books for Codex`.
   Right-click the ZIP file, choose **Extract All...**, type that folder and press **Extract**.
   Keep the folder: Codex reads the plugin from it.
2. Open Codex and go to **Settings > Plugins**.
3. Press **Add** and choose the folder from step 1 (the one that holds this INSTALL.md).
4. **Excellent** now shows as its own group. Press **+** next to **Excellent Books**.

## First question

1. Start a new chat and ask a Books question, for example "How much do our customers owe us right now?"
2. The first start takes a minute or two: it downloads the tools it needs, once.
3. A **Connect Excellent Books** page opens in your browser. Fill in your Books server address,
   company number, Books user and password, read the personal-data text and tick the box. Press
   **Test connection and save**. Your consultant can give you the server address and the company
   number.
4. When the page says **Connected**, go back to Codex and type `continue` (in Estonian: `jätka`).
   Nothing is saved in Books unless you switch writing on and approve each change.

Writing, chat approval and **Remove saved login** are on the same Connect page. To open it again,
ask Codex to open the Excellent Books settings.

If the first answer is an error, ask again once: Codex sometimes needs a second try right after
installing a plugin.

## Remove it

1. In Codex, go to **Settings > Plugins**, open **Excellent Books** and remove it.
2. Remove the **Excellent** folder from the plugin list in the same place, then delete the folder
   from step 1.
3. To remove your saved Books login too, delete the folder `ExcellentBooksMCP-Plugin` in
   `%LOCALAPPDATA%` (type `%LOCALAPPDATA%` in the File Explorer address bar).
