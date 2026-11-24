"""`python -m ebmcp.setup` — write `.env` without a password ever passing through a chat.

This exists because of a real exchange, 2026-09-16. A person could not get the connector
working, and the natural next move is to paste `.env` into the chat and ask what is wrong. At
that moment the password has been sent to a model API, and the only honest remedy is to rotate
it. Instructions in the prompt help; a route that never needs the value help more.

So: the person runs this in their own terminal. `getpass` reads the password without echoing it
to the screen, nothing is passed as a command-line argument (which would be visible in the
process list and in shell history), and the file is written with owner-only permissions. A
model can say "run this command" and be genuinely useful without ever being near the value.

It refuses to clobber an existing `.env` unless asked, because the failure it would otherwise
cause — a working install silently replaced by a half-typed one — is worse than the nuisance of
a second run.
"""
from __future__ import annotations

from codecs import BOM_UTF8
import getpass
import os
import stat
import sys
import textwrap
from pathlib import Path
from uuid import uuid4

from . import privacy
from .config import (GDPR_KEY, HR_KEY, PROJECT_ROOT, _said_yes, consent_given,
                     consent_text_id, local_consent_state, read_env_file)

TEMPLATE = """# Written by `python -m ebmcp.setup`. Keep this file on your own computer.
# Do not e-mail it, do not put it in Git, and do not paste it into a chat window —
# a password that reaches a chat has to be rotated, not deleted.
# Do not keep it in a synced folder (OneDrive, Dropbox, synced Documents): that is how a
# credentials file quietly ends up in a cloud account and in a backup.

EBMCP_API_BASE={api_base}
EBMCP_USER={user}
EBMCP_PASSWORD={password}

# The connector has no sign-in of its own, so it listens only on this computer (127.0.0.1) and
# refuses to start if EBMCP_HOST names a network address. Every program running on this computer
# can reach it and read Excellent Books as the user above.
EBMCP_ALLOW_OPEN=1

# Writing starts off. With writing on, the AI can prepare changes in supported registers,
# including invoices and supplier payment orders, which your bank integration may send to the
# bank. Applying a preview requires your approval.
# Restart to list the write tools. Claude Code can run commands on this computer, so with
# Claude Code, leave writing off.
EBMCP_WRITES=no

# Use chat to approve previews by saying yes. Long previews and unfinished writes use the browser.
EBMCP_APPROVE_IN=browser
{consent}"""

# The customer's GDPR decision (Kaupo, 2026-10-04), with when and where it was taken. The
# connector reads nothing from the ERP until the line says yes (server.session).
CONSENT = """
# GDPR: {verdict} in setup on {date} - answers may carry personal data to the AI you connect.
EBMCP_GDPR_CONSENT={word}
EBMCP_GDPR_TEXT={text_id}
"""

# HR and payroll: the person answers yes or no after reading the warnings; only yes opens them.
HR_CONSENT = """
# HR and payroll data: {verdict} in setup on {date}, after the data protection, GDPR and
# EU AI Act warnings. Only yes switches them on.
EBMCP_HR_CONSENT={word}
EBMCP_HR_TEXT={text_id}
"""


def _ask(prompt: str, example: str) -> str:
    while True:
        value = input("%s\n  (e.g. %s)\n> " % (prompt, example)).strip()
        if value:
            return value
        print("  That cannot be empty.\n")


def _lock_down(path: Path) -> str:
    """Owner-only, on both families. Returns what was done, for the closing message."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)          # 600
    except OSError:
        return "could not set file permissions — check them yourself"
    if os.name != "nt":
        return "permissions set to 600 (owner only)"
    # chmod on Windows only flips the read-only bit; the ACL is what actually governs access,
    # and a file in a user folder inherits permissions that let anything running as that user
    # read it. icacls is the real control, so it is run and its success reported honestly.
    # Read AND write for the owner: until 2026-10-04 this granted read only, and the owner could
    # no longer add the GDPR consent line, by --consent or by Notepad (opus review, C1).
    # The account is the one running setup, by its SID (Sol re-check of abed9f9): USERNAME is a
    # bare name that can name another account. The whole ACL is replaced in ONE call, so a failure
    # leaves the ACL that was there; /reset then /grant left inherited access behind when the
    # grant failed. Explicit grants for other accounts go too (Sol re-check 2026-11-20, SHOULD 13).
    account = _current_account()
    if account is None:
        return ("could not restrict permissions automatically: your Windows account could not be "
                "read. Run:\n"
                "    icacls \"%s\" /reset\n"
                "    icacls \"%s\" /inheritance:r /grant:r \"<COMPUTER or DOMAIN>\\<your user name>:(R,W)\""
                % (path, path))
    sid, name = account
    if _owner_only(path, sid):
        return "permissions restricted to %s only" % name
    # The grant is quoted whole: PowerShell, the default Windows 11 terminal, cannot parse an
    # unquoted user:(R,W) (re-review of 54a8586).
    return ("could not restrict permissions automatically — run:\n"
            "    icacls \"%s\" /reset\n"
            "    icacls \"%s\" /inheritance:r /grant:r \"%s:(R,W)\"" % (path, path, name))


def _current_account() -> tuple[str, str] | None:
    """(SID, COMPUTER-or-DOMAIN\\user) of the account running this process, from `whoami`; None
    when it cannot be read. Output not decoded as text: whoami writes OEM bytes, and a name like
    "Jüri" printed a decode traceback (re-review of 54a8586)."""
    import re
    import subprocess
    try:
        run = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True)
    except OSError:
        return None
    raw = getattr(run, "stdout", b"") or b""
    if run.returncode != 0:
        return None
    try:
        text = raw.decode("oem", "replace")
    except LookupError:                      # no "oem" codec off Windows (tests)
        text = raw.decode("utf-8", "replace")
    match = re.fullmatch(r'\s*"([^"]+)","(S-1-[0-9]+(?:-[0-9]+)+)"\s*', text)
    if not match or "\\" not in match[1]:
        return None
    return match[2], match[1]


def _owner_only(path: Path, sid: str) -> bool:
    """Replace the file's whole ACL with one entry, read and write for `sid`, inheritance off.
    One SetNamedSecurityInfoW call: it applies completely or not at all. The owner keeps the
    right to change the ACL."""
    try:
        import ctypes
        from ctypes import wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32")
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(wintypes.DWORD)]
        convert.restype = wintypes.BOOL
        get_dacl = advapi.GetSecurityDescriptorDacl
        get_dacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        get_dacl.restype = wintypes.BOOL
        set_named = advapi.SetNamedSecurityInfoW
        set_named.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                              ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        set_named.restype = wintypes.DWORD
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        descriptor = ctypes.c_void_p()
        # D:P = protected (no inherited entries); FR and FW = icacls (R,W).
        if not convert("D:P(A;;FRFW;;;%s)" % sid, 1, ctypes.byref(descriptor), None):
            return False
        try:
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            dacl = ctypes.c_void_p()
            if not get_dacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                            ctypes.byref(defaulted)) or not present or not dacl:
                return False
            se_file_object = 1
            dacl_info = 0x00000004
            protected_dacl_info = 0x80000000
            return set_named(str(path), se_file_object, dacl_info | protected_dacl_info,
                             None, None, dacl, None) == 0
        finally:
            kernel.LocalFree(descriptor)
    except (OSError, AttributeError, ValueError):
        return False


def _writable(path: Path) -> None:
    """Give the owner write access back to a `.env` an older setup locked read-only (`<user>:R`);
    the owner keeps the right to change the ACL. A no-op off Windows or when it cannot be done:
    the write that follows says so."""
    if os.name != "nt" or not path.exists():
        return
    import subprocess
    account = _current_account()
    if account:
        subprocess.run(["icacls", str(path), "/grant:r", "*%s:(R,W)" % account[0]],
                       capture_output=True)


def _open_private(path: Path) -> int:
    """Create a new file with owner-only access from its first open."""
    if os.name != "nt":
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    import ctypes
    from ctypes import wintypes
    import msvcrt

    account = _current_account()
    if account is None:
        raise PermissionError("Could not identify your Windows account.")

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                    ("inherit_handle", wintypes.BOOL)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                        ctypes.POINTER(wintypes.DWORD)]
    convert.restype = wintypes.BOOL
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD,
                       wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    volume_info = kernel.GetVolumeInformationByHandleW
    volume_info.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD,
                            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                            ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
    volume_info.restype = wintypes.BOOL

    descriptor = ctypes.c_void_p()
    # Protected DACL, one full-access entry for the current account, no inherited handles.
    if not convert(f"D:P(A;;FA;;;{account[0]})", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        security = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        generic_write, create_new, normal = 0x40000000, 1, 0x80
        handle = create(str(path), generic_write, 0, ctypes.byref(security), create_new, normal, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)

    try:
        flags = wintypes.DWORD()
        persistent_acls = 0x00000008
        if not volume_info(handle, None, 0, None, None, ctypes.byref(flags), None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        if not flags.value & persistent_acls:
            raise PermissionError("The drive does not support Windows file permissions.")
        return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
    except OSError:
        kernel.CloseHandle(handle)
        path.unlink(missing_ok=True)
        raise


def _save_settings(target: Path, text: str, *, force: bool) -> None:
    path = target.with_name(f"{target.name}.{uuid4().hex}.tmp") if force else target
    fd = _open_private(path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        if force:
            os.replace(path, target)
    except OSError:
        path.unlink(missing_ok=True)
        raise


WIDTH = 72


def _bold(text: str) -> str:
    """Bold in a real terminal; plain when piped, captured or NO_COLOR is set, and on the old
    Windows console, which prints the codes instead (Windows Terminal sets WT_SESSION)."""
    if os.name == "nt" and not os.environ.get("WT_SESSION"):
        return text
    if sys.stdout.isatty() and not os.environ.get("NO_COLOR"):
        return "\033[1m%s\033[0m" % text
    return text


def _show(title: str, intro: str, points=()) -> None:
    """A consent text as a person reads it: a title, wrapped paragraphs, one warning per block."""
    print("\n" + _bold(title))
    print("-" * len(title) + "\n")
    for paragraph in intro.split("\n\n"):    # the GDPR text has paragraphs (Task 50)
        print(textwrap.fill(paragraph, WIDTH, initial_indent="  ", subsequent_indent="  ") + "\n")
    for n, (head, body) in enumerate(points, 1):
        print("  " + _bold("%d. %s" % (n, head)))
        print(textwrap.fill(body[:1].upper() + body[1:], WIDTH,
                            initial_indent="     ", subsequent_indent="     ") + "\n")


def _consent() -> str:
    """Shows the GDPR text, asks, and returns the `.env` lines that record the answer."""
    import datetime
    _show("Personal data and the GDPR", privacy.GDPR_TEXT)
    yes = consent_given(input("Do you accept this? (yes/no)\n> "))
    return CONSENT.format(verdict="accepted" if yes else "declined",
                          date=datetime.date.today().isoformat(), word="yes" if yes else "no",
                          text_id=consent_text_id("gdpr"))


def _hr_consent(gdpr_lines: str = "EBMCP_GDPR_CONSENT=yes") -> str:
    """Shows the HR and payroll warnings, asks, and returns the `.env` lines. Not asked when the
    GDPR consent was declined: nothing is read then, HR included, and no line is written, which
    leaves HR off. No default: the question repeats until the answer is yes or no."""
    import datetime
    if "EBMCP_GDPR_CONSENT=yes" not in gdpr_lines:
        return ""
    _show("HR and payroll data", privacy.HR_CONSENT_INTRO, privacy.HR_POINTS)
    try:
        answer = input("Switch on HR and payroll data? Type yes or no.\n> ").strip()
        while not answer:
            answer = input("Type yes or no.\n> ").strip()
    except (KeyboardInterrupt, EOFError):
        # Ctrl+C here must not lose the answers given before it: HR simply stays off.
        print("\nNo answer: HR and payroll data stay off. Switch them on later with:"
              "  python -m ebmcp.setup --hr-consent")
        answer = "no"
    yes = _said_yes(answer)
    return HR_CONSENT.format(verdict="switched on" if yes else "switched off",
                             date=datetime.date.today().isoformat(), word="yes" if yes else "no",
                             text_id=consent_text_id("hr"))


def _replace_consent(raw: bytes, key: str, lines: str) -> bytes:
    """Replace the consent assignments, preserving unrelated bytes and the file's line endings."""
    bom = BOM_UTF8 if raw.startswith(BOM_UTF8) else b""
    raw = raw[len(bom):]
    newline = b"\r\n" if raw.partition(b"\n")[0].endswith(b"\r") else b"\n"
    block = lines.lstrip("\n").encode("utf-8").replace(b"\n", newline)
    keys = {key, key.removesuffix("_CONSENT") + "_TEXT"}
    kept = []
    inserted = False
    for line in raw.splitlines(keepends=True):
        name, equals, _ = line.partition(b"=")
        if not equals or name.decode("utf-8").strip() not in keys:
            kept.append(line)
        elif not inserted:
            kept.append(block)
            inserted = True
    if not inserted:
        if raw and not raw.endswith(b"\n"):
            kept.append(newline)
        kept.append(block)
    return bom + b"".join(kept)


def _add_consent(target: Path, key: str = GDPR_KEY) -> int:
    """`--consent` / `--hr-consent`: record the decision in an existing `.env`, nothing else
    rewritten."""
    is_gdpr = key == GDPR_KEY
    flag = "--consent" if is_gdpr else "--hr-consent"
    if not target.exists():
        print("%s does not exist yet. Run this command without %s first." % (target, flag))
        return 1
    try:
        gdpr = local_consent_state("gdpr", read_env_file(target)) == "given"
    except OSError:                 # unreadable: the write below says what to do
        gdpr = False
    if not is_gdpr and not gdpr:
        print("Accept the GDPR text first, with:  python -m ebmcp.setup --consent\n"
              "HR and payroll data come after it. Nothing was changed.")
        return 1
    if is_gdpr and gdpr:
        print("GDPR is already accepted for %s. Nothing was changed." % target)
        return 0
    # HR is a switch both ways: the answer is recorded whichever it is.
    lines = _consent() if is_gdpr else _hr_consent()
    if is_gdpr and "%s=yes" % key not in lines:
        print("Nothing was changed. The connector refuses to read the ERP until this is accepted.")
        return 1
    _writable(target)
    try:
        target.write_bytes(_replace_consent(target.read_bytes(), key, lines))
    except PermissionError:
        print("%s could not be written. Give your own account write access and run this again:\n"
              "    icacls \"%s\" /grant:r \"%s:(R,W)\""
              % (target, target, (_current_account() or ("", "<your user name>"))[1]))
        return 1
    note = _lock_down(target)
    print("\nRecorded in %s. No restart is needed." % target)
    # The decision is recorded either way; a lock-down that failed is said, never dropped
    # (Sol re-check of abed9f9).
    print("  %s" % note)
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    force = "--force" in argv
    target = PROJECT_ROOT / ".env"
    if "--consent" in argv:
        return _add_consent(target)
    if "--hr-consent" in argv:
        return _add_consent(target, HR_KEY)

    if target.exists() and not force:
        print("%s already exists.\n" % target)
        print("Nothing was changed. Re-run with --force to replace it, or edit the file"
              " directly.")
        return 1

    print("Excellent Books MCP — connection settings.\n")
    print("These three values are saved on this computer, in %s." % target)
    print("The password is used only to sign in to your Excellent Books server. Type it"
          " here, never into a chat; it is not shown as you type it.\n")

    api_base = _ask("Your Excellent Books server, with its port and company number:",
                    "https://your-server.excellent.ee:4455/api/1")
    user = _ask("Your own Excellent Books user code:", "YOURCODE")
    password = getpass.getpass("That user's password (not shown as you type)\n> ")
    while not password:
        print("  That cannot be empty.\n")
        password = getpass.getpass("That user's password (not shown as you type)\n> ")

    consent = _consent()
    consent += _hr_consent(consent)
    try:
        _save_settings(target, TEMPLATE.format(api_base=api_base.rstrip("/"), user=user,
                                               password=password, consent=consent), force=force)
    except OSError:
        print("Could not save the settings with private permissions. Check the folder's "
              "permissions and try again.")
        return 1

    print("\nWritten: %s" % target)
    print("  File permissions restricted to your account.")
    if "EBMCP_GDPR_CONSENT=yes" not in consent:
        print("\nGDPR not accepted: the connector will refuse to read the ERP until it is.")
        print("Accept later with:  python -m ebmcp.setup --consent")
    print("\nStart the connector with:  py -m ebmcp.server")
    print("A printed port means the connector started on this computer. Once the personal")
    print("data text is accepted, it signs in to Excellent Books right away to read which")
    print("report fields your Books has; a sign-in problem shows at your first question.")
    print("If Excellent Books refuses the sign-in,")
    print("check the server address and company number; if your user may not use the REST")
    print("API, ask your Excellent Books administrator to allow the action Rest API. To")
    print("change the settings, edit the file or re-run this command with --force. Do not")
    print("paste the file into a chat to have it checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
