"""Creating a contact — a supplier a delivery arrived from, or a customer, that Books does not
have yet.

**`CUVc` is not `INVc`.** The contact register carries `BirthDate`, `BirthPlace`, `Birthday`,
`BirthCountry`, `Person` and `Ethnicity`, and on an Estonian private person `RegNr1` is where the
**isikukood** goes. Until 2026-10-04 this tool created companies only (Kaupo, 2026-09-16); since
then a private person too — personal data is the customer's own GDPR decision, taken at install
(ebmcp/privacy.py). What stays, in `build_fields` so there is one place to read:

1. `CustType` says the kind: 0 a company (the default), 1 a private person when `type` asks for
   one; anything else is refused. (Until 2026-10-01 this pinned `CUType` to 1, believing it meant
   "company". CUType is the Customer checkbox and VEType the Supplier one — Kaupo, and the ERP's
   own code agrees.)
2. Fields are an **allowlist**. Anything not on it is refused BY NAME — never silently dropped,
   because silence looks like acceptance and nobody would find out until they opened Books.

The mechanics are the goods receipt's: form-urlencoded `set_field.`, spaces as `%20` not `+`,
and the result verified by reading the record back rather than by trusting the reply.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import urllib.parse
from typing import Optional

from . import approval, audit, changes, control, erp, privacy, write_outcome
from .config import session_connection_id

# What a caller may set, and the ERP field each one reaches. A private person's own fields since
# 2026-10-04 (each set on :4455 and read back that day; BirthDate takes ISO).
ALLOWED = {
    "code": "Code",
    "name": "Name",
    "vat_number": "VATNr",
    "registration_number": "RegNr1",
    "personal_code": "RegNr1",
    "address": "InvAddr0",
    "address2": "InvAddr1",
    "city": "InvAddr2",
    "postcode": "InvAddr3",
    "region": "Region",
    "country": "CountryCode",
    "email": "eMail",
    "phone": "Phone",
    "mobile": "Mobile",
    "website": "wwwAddr",
    "comment": "Comment",
    "contact_person": "Person",
    "birth_date": "BirthDate",
    "birthday": "Birthday",
    "birth_place": "BirthPlace",
    "birth_country": "BirthCountry",
    "ethnicity": "Ethnicity",
}

# The role follows the use case (Kaupo, 2026-10-01): the purchase side — a goods receipt, a
# purchase invoice — creates a supplier, the sales side a customer. Each is its own checkbox,
# and one contact can be both. A new contact gets its role and NOT the other: the ERP ticks
# Customer on every new contact by default, so the other flag is sent as 0 (measured to stick on
# :4455). An existing contact, company or person, that needs the other role — an entry with only
# its code and the role — has that one flag PATCHed to 1 (`PATCH /CUVc/<Code>`, measured: the
# other flag stays).
# A role is added, never removed.
ROLES = {"supplier": "VEType", "customer": "CUType"}
KINDS = {"": "0", "company": "0", "0": "0", "person": "1", "1": "1"}    # CustType

TIMEOUT = 60.0
MAX_CONTACTS = 50


class ContactError(Exception):
    """A refusal the customer should see."""


class InvalidBatch(ContactError):
    """The batch itself is wrong: empty, or over the limit (hosted: `invalid_arguments`)."""


class ContactReadFailed(ContactError):
    """Books could not be read for the preview: not the caller's mistake, and its text can carry
    Books' own diagnostics (hosted answers it without them)."""


def check_register(register: str) -> None:
    """The secret-register gate, on this write path too. There is no second net."""
    if privacy.is_blocked(register):
        raise ContactError(privacy.refusal(register)["why"])


def _clean(value) -> str:
    return str(value or "").strip()


def build_fields(contact: dict) -> list:
    """The `set_field.` pairs, in order, or a refusal naming what was wrong.

    `Code` goes first deliberately: the ERP validates after each parameter, so the record's
    identity is established before anything is hung off it.
    """
    contact = dict(contact or {})

    wanted_type = _clean(contact.pop("type", "")).casefold()
    if wanted_type not in KINDS:
        raise ContactError("A contact's type is company or person, not %r." % wanted_type)
    kind = KINDS[wanted_type]

    role = _role(contact.pop("role", ""))

    unknown = [key for key in contact if key not in ALLOWED]
    if unknown:
        raise ContactError(
            "This connector does not set %s on a contact. It writes only: %s. Anything else is "
            "set in Excellent Books, where somebody can see what they are agreeing to."
            % (", ".join(repr(u) for u in sorted(unknown)), ", ".join(sorted(ALLOWED))))
    for key, value in contact.items():
        if changes.has_control(value):
            raise ContactError(changes.CONTROL_REFUSAL % key)

    if _clean(contact.get("registration_number")) and _clean(contact.get("personal_code")):
        raise ContactError("registration_number and personal_code are the same field (RegNr1): "
                           "give the one that fits the contact.")

    code, name = _clean(contact.get("code")), _clean(contact.get("name"))
    if not code:
        raise ContactError("A contact needs a code. Propose one and let the person confirm it.")
    if not name:
        raise ContactError("A contact needs a name.")
    _check_birth_dates(contact)

    fields = [("set_field.Code", code), ("set_field.Name", name),
              ("set_field.CustType", kind),
              ("set_field.%s" % ROLES[role], "1")]
    fields += [("set_field.%s" % flag, "0") for other, flag in sorted(ROLES.items())
               if other != role]
    for key in sorted(contact):
        if key in ("code", "name"):
            continue
        value = _clean(contact.get(key))
        if value:
            fields.append(("set_field.%s" % ALLOWED[key], value))
    return fields


_ISO_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_MONTH_DAY = re.compile(r"(\d{2})/(\d{2})")


def _real_date(year: int, month: int, day: int) -> bool:
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False
    return True


def _check_birth_dates(contact: dict) -> None:
    """Opus review 10-04, M4: a wrongly formed date can be stored as ANOTHER date at HTTP 200
    (measured on report specs; CLAUDE.md), so the form is checked before anything is sent.
    BirthDate takes ISO (measured on :4455, 10-04); Birthday is the month and day, MM/DD."""
    birth_date, birthday = _clean(contact.get("birth_date")), _clean(contact.get("birthday"))
    found = _ISO_DATE.fullmatch(birth_date)
    if birth_date and not (found and _real_date(*map(int, found.groups()))):
        raise ContactError("birth_date is a date as YYYY-MM-DD (1976-05-03 for 3 May 1976), not "
                           "%r. Ask the person rather than guessing the order." % birth_date)
    found = _MONTH_DAY.fullmatch(birthday)
    # 2000 is a leap year, so 02/29 is a birthday.
    if birthday and not (found and _real_date(2000, *map(int, found.groups()))):
        raise ContactError("birthday is the month and day as MM/DD (05/03 for 3 May), not %r. "
                           "Ask the person rather than guessing the order." % birthday)


# What the read-back compares besides the kind and the role (review M4).
BIRTH_FIELDS = ("BirthDate", "Birthday")


def _role(value) -> str:
    role = _clean(value).casefold() or "supplier"
    if role not in ROLES:
        raise ContactError("A contact's role is %s, not %r: a supplier for the purchase side, a "
                           "customer for the sales side." % (" or ".join(sorted(ROLES)), role))
    return role


def role_only(contact: dict) -> Optional[str]:
    """The role, when an entry names nothing but a code and a role: a role to add to an
    existing contact. None for anything else."""
    given = {key for key, value in (contact or {}).items() if _clean(value)}
    return _role(contact.get("role")) if given == {"code", "role"} else None


def build_body(contact: dict) -> bytes:
    """`quote_via=quote` so a space is `%20`: the ERP stores urlencode's default `+` literally."""
    return urllib.parse.urlencode(build_fields(contact),
                                  quote_via=urllib.parse.quote).encode("ascii")


FIELDS = ("Code", "Name", "VATNr", "RegNr1", "RegNr2", "CUType", "VEType", "CustType")


def fetch(session, timeout: float = TIMEOUT, extra: tuple = ()) -> list:
    """The contact list, trimmed. No `range` — a WIDE ranged read of a register on this ERP has
    been measured returning a different count on identical calls. `extra`: more fields to
    read, for a read-back that compares them."""
    check_register("CUVc")
    if privacy.secret_fields(extra):
        raise ContactError("Secret fields cannot be read on a contact.")
    response = session.rest_get("/CUVc", timeout=timeout, sort="Code",
                                fields=",".join(FIELDS + tuple(extra)))
    return _records(response, "The contact list")


def _records(response, what: str) -> list:
    """The contacts a read returned, or ContactError: an HTTP error or an HTTP 200 error body is
    never "no such contact" (write_outcome.checked_records; Sol re-check 2026-11-17, MUST 3)."""
    try:
        return write_outcome.checked_records(response, "CUVc")
    except write_outcome.ReadFailed as exc:
        raise ContactReadFailed("%s could not be read (%s)." % (what, exc)) from None


def fetch_one(session, code: str, timeout: float = TIMEOUT) -> Optional[dict]:
    """One contact as `fetch` reads it, or None. Review S2: the check before each write reads
    that record on the Code index (`sort=Code&range=X:X`, the single-key read
    `receipts._exists` and `changes._check_contact` use; the losses measured in
    docs/erp-register-access.md are wide and date spans, not one key value). Rows are matched on
    the exact code, since the ERP's collation is not code-point order. A code holding `:` cannot
    be one span, so that one is checked against the whole list."""
    check_register("CUVc")
    if ":" in code:
        return next((c for c in fetch(session, timeout) if _clean(c.get("Code")) == code), None)
    response = session.rest_get("/CUVc", timeout=timeout, sort="Code",
                                range="%s:%s" % (code, code), fields=",".join(FIELDS))
    return next((c for c in _records(response, "The contact")
                 if _clean(c.get("Code")) == code), None)


def _fingerprint(value) -> str:
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _preview_fields(contact, pairs):
    # Include defaults and the explicitly cleared opposite role, not just supplied values.
    names = {v: k for k, v in ALLOWED.items() if k != "personal_code"}
    if _clean(contact.get("personal_code")):
        names["RegNr1"] = "personal_code"
    names.update({"CustType": "type", **{v: k for k, v in ROLES.items()}})
    # Review L5: a private person's name and registration number are personal data too.
    person = ("set_field.CustType", "1") in pairs
    shown = []
    for field, value in pairs:
        field = field.split(".", 1)[1]
        key = names[field]
        personal = (key == "personal_code" or field.casefold() in privacy.PEOPLE_FIELDS
                    or (person and key in ("name", "registration_number")))
        if field == "CustType":
            value = "person" if value == "1" else "company"
        shown.append({"field": key, "value": value, "personal": personal})
    return shown


def plan(session, store: approval.PlanStore, new_contacts: list,
         timeout: float = TIMEOUT, *, max_writes: int = MAX_CONTACTS) -> dict:
    """Read and validate a bounded batch. Issue exact bytes for approval; never write."""
    check_register("CUVc")
    stopped = control.register_refusal("CUVc", write=True)   # the signed control file's stop
    if stopped:
        return stopped
    if not new_contacts:
        raise InvalidBatch("No contacts to create.")
    if len(new_contacts) > max_writes:
        raise InvalidBatch("%d contacts is more than this tool will create at once."
                           % len(new_contacts))

    existing = {_clean(c.get("Code")): c for c in fetch(session, timeout)}
    # Validate the entire batch before issuing any plan.
    entries, shown, writes, refused, already, before = [], [], [], [], [], {}
    reserved, roles_planned = set(existing), set()
    base_path = urllib.parse.urlsplit(session.cfg.api_base).path.rstrip("/") + "/CUVc"
    for contact in new_contacts:
        contact = dict(contact or {})
        unknown = sorted(set(contact) - set(ALLOWED) - {"type", "role"})
        if unknown:
            raise ContactError("This connector does not set %s on a contact." %
                               ", ".join(repr(key) for key in unknown))
        code, role = _clean(contact.get("code")), role_only(contact)
        if changes.has_control(code):     # role-only codes skipped the field check (Sol, dcd94b9)
            raise ContactError(changes.CONTROL_REFUSAL % "code")
        if role and code not in existing:
            raise ContactError("No contact has the code %r. To create it, give its name and "
                               "details too; to add a role, give the code of one that exists."
                               % code)
        if role:
            flag, record = ROLES[role], existing[code]
            if str(record.get(flag) or "") == "1":
                already.append({"code": code, "role": role})
                continue
            if (code, role) in roles_planned:
                continue                       # review L6: the same role twice is one write
            roles_planned.add((code, role))
            pairs = [("set_field.%s" % flag, "1")]
            write = ("PATCH", base_path + "/" + urllib.parse.quote(code, safe=""),
                     "set_field.%s=1" % flag)
            before[code] = record
            # Review S1: the approval page names the contact; the name is in the digest, and
            # the before-state fingerprint refuses the write if it changed.
            summary = {"code": code, "role": role, "name": _clean(record.get("Name"))}
            wanted = {flag: "1"}
        else:
            pairs = build_fields(contact)
            if code in reserved:
                refused.append({"code": code, "why": "a contact with this code already exists"})
                continue
            reserved.add(code)
            write = ("POST", base_path, urllib.parse.urlencode(
                pairs, quote_via=urllib.parse.quote))
            summary = {"code": code, "name": _clean(contact.get("name"))}
            wanted = {f.split(".", 1)[1]: v for f, v in pairs
                      if f.split(".", 1)[1] in ("CustType", "VEType", "CUType") + BIRTH_FIELDS}
            wanted["Name"] = summary["name"]       # review L2: read back by name, not code alone
        if privacy.secret_fields(f.split(".", 1)[1] for f, _ in pairs):
            raise ContactError("Secret fields cannot be set on a contact.")
        writes.append(write)
        entries.append({"summary": summary, "role": role, "wanted": wanted})
        shown.append(dict(summary, fields=_preview_fields(contact, pairs)))

    preview = {"status": "planned" if writes else "nothing_to_plan", "contacts": shown,
               "refused": refused, "already": already,
               "note": approval.APPLY_NOTE}
    if not writes:
        preview["note"] = ("Nothing to plan or write. All requested roles are already ticked."
                           if already and not refused else
                           "Nothing to plan or write; see refused and already.")
        return preview
    envelope = approval.Envelope(
        kind="contacts", server=session.cfg.origin, company=session.cfg.company,
        books_user=session.usercode or session.cfg.user, operation="batch", target="CUVc x%d" % len(writes),
        writes=tuple(writes), before=_fingerprint(before) if before else "",
        preview=json.dumps(preview, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
        needs_ack=False)
    preview["plan_id"] = store.issue(envelope, {
        "entries": entries, "before": before, "refused": refused, "already": already,
        "count": len(new_contacts), "timeout": timeout,
        "system_version": getattr(session, "system_version", None),
        "connection": session_connection_id(session)})
    return preview


def _skip(approved, w) -> bool:
    """Pass over a refused entry on the approval's counter. Review S3: False means the counter
    did not move, so the gate would refuse every later write; the caller stops."""
    return approved.skip_next(*w)


NOT_SKIPPED = "The approval could not pass over a refused contact, so nothing after it was sent."


def execute(session, approved: approval.Approved, plan: approval.Plan, still_allowed) -> dict:
    """Send stored bytes in order, then read back once. The caller finishes the plan."""
    if (not isinstance(approved, approval.Approved) or not approved.live()
            or not isinstance(plan, approval.Plan) or plan.plan_id != approved.plan_id
            or plan.envelope != approved.envelope
            or not approved.matches(session.cfg.origin, session.cfg.company, session.usercode or session.cfg.user)
            or approved.envelope.kind != "contacts"):
        return {"error": "refused", "why": "A live approval for this plan and connection is required."}
    planned = plan.payload
    entries, timeout = planned["entries"], planned["timeout"]
    already = list(planned["already"])
    # Every planned write ends in exactly one bucket, keyed by its place in the envelope, so two
    # roles on one contact stay two results (write_outcome.Outcomes; Sol re-check MUST 4, 5).
    out = write_outcome.Outcomes(CONTACT_BUCKETS)
    unclear = set()                     # indexes answered by an empty 401 (round 4)
    for n, entry in enumerate(planned["refused"]):
        out.put(("plan", n), "refused", entry)
    sent, lost, said = [], set(), {}     # write indexes: sent (reply or not), reply lost
    connection_lost = False

    def stop(index, why=None):
        for later in range(index, len(entries)):
            summary = entries[later]["summary"]
            out.put(later, write_outcome.NOT_ATTEMPTED,
                    dict(summary, why=why) if why else summary)

    # Our preceding PATCH may add the other role to this same contact. Only that exact
    # expected change is allowed when comparing the next read with the preview snapshot.
    own_roles = {}
    for i, (entry, w) in enumerate(zip(entries, approved.envelope.writes)):
        summary, role = entry["summary"], entry["role"]
        code = summary["code"]
        try:
            if not still_allowed():
                stop(i)
                break
            current = fetch_one(session, code, timeout)
        except Exception as exc:
            stop(i, write_outcome.before_write_why(
                exc, "Could not check permission or the contact before writing."))
            break
        why = None
        if role:
            before = planned["before"][code]
            expected = dict(before, **own_roles.get(code, {}))
            if _fingerprint(current) != _fingerprint(expected):
                # Review L3: our own earlier role that did not land is not "changed".
                why = ("The role added just before on this contact did not show on it, so this "
                       "one was not sent. Check the contact in Excellent Books."
                       if own_roles.get(code) and _fingerprint(current) == _fingerprint(before)
                       else "The contact changed since the preview. Plan its role again.")
        elif current is not None:
            why = "a contact with this code already exists"
        if why:
            out.put(i, "refused", dict(summary, why=why))
            try:
                skipped = _skip(approved, w)
            except Exception:
                # Sol re-check SHOULD 1: a raising skip is a stop, never a lost batch.
                skipped = False
            if not skipped:
                stop(i + 1, NOT_SKIPPED)
                break
            continue
        method, path, body = w
        try:
            erp.check_desktop_write_budget()
            reply = session.request(session.cfg.origin + path, body.encode("ascii"),
                                    {"Content-Type": erp.FORM_CONTENT_TYPE}, timeout=timeout,
                                    method=method, approved=approved)
        except erp.WriteConnectionLost as exc:
            # The single liveness read has already run. Earlier writes still awaiting
            # read-back also need checking in Books.
            for earlier in sent:
                out.put(earlier, write_outcome.UNVERIFIED, entries[earlier]["summary"])
            out.put(i, write_outcome.UNVERIFIED,
                    dict(summary, **write_outcome.connection_loss(exc)))
            connection_lost = True
            stop(i + 1, exc.suspension_reason)
            break
        except erp.DesktopWriteTimeout as exc:
            out.put(i, write_outcome.UNVERIFIED, dict(summary, why=str(exc)))
            stop(i + 1)
            break
        except Exception as exc:
            if write_outcome.send_failure(exc) == write_outcome.NOT_ATTEMPTED:
                # Review S3: stopped before any HTTP. Not a lost reply; the batch stops.
                stop(i, write_outcome.not_sent_why(exc))
                break
            # A lost reply may hide a successful write. Stop, keep this attempt; the read-back
            # decides it.
            sent.append(i)
            lost.add(i)
            out.put(i, write_outcome.UNVERIFIED, summary)
            stop(i + 1)
            break
        sent.append(i)
        said[i] = erp.reply_problems(getattr(reply, "body", b""))
        if write_outcome.access_unclear(getattr(reply, "status", 200),
                                        getattr(reply, "body", b"")):
            unclear.add(i)
        out.put(i, "roles_added" if role else "created", summary)   # until the read-back
        if role:
            own_roles.setdefault(code, {}).update(entry["wanted"])

    if sent and not connection_lost:
        extra = tuple(f for f in BIRTH_FIELDS if any(f in entries[i]["wanted"] for i in sent))
        try:
            with erp.desktop_batch_read_back():
                after = {_clean(c.get("Code")): c for c in fetch(session, timeout, extra)}
        except Exception:
            # Review M1: an unread result is unverified and nothing more.
            for i in sent:
                out.put(i, write_outcome.UNVERIFIED, dict(
                    entries[i]["summary"],
                    why="The read-back failed; check Excellent Books before retrying."))
        else:
            for i in sent:
                _judge(out, i, entries[i], after, i in lost, said.get(i))
                # Task 22 gate round 4 (Sol MUST): an empty 401 after a sent write is never
                # "not found after create"; it stays unverified with the access note. A
                # read-back that shows the contact still decides it was created.
                if i in unclear and out.bucket(i) in ("not_found_after_create",
                                                      write_outcome.UNVERIFIED):
                    out.put(i, write_outcome.UNVERIFIED, dict(
                        entries[i]["summary"], http_status=401,
                        why=write_outcome.ACCESS_UNCLEAR))
    lists = out.lists()
    audit.record("create_contacts", register="CUVc",
                 outcome=write_outcome.batch_audit_outcome(
                     lists, sent=bool(sent), ok=("created", "roles_added"),
                     failed=("not_found_after_create", "flags_not_set")),
                 reason=("not_found_after_create" if lists["not_found_after_create"] else
                         "flags_not_set" if lists["flags_not_set"] else None),
                 created=len(lists["created"]), updated=len(lists["roles_added"]),
                 lines=planned["count"], **audit.approval_facts(approved))
    landed, unflagged = lists["roles_added"], lists["flags_not_set"]
    result = dict(lists, already=already,
                  note=("Created contacts and added roles were read back from Excellent Books. "
                        "not_found_after_create was read back and is not there: it was not "
                        "created; " + write_outcome.said_note(
                            "erp_said explains missing details.")
                        + " Anything unverified may have been written: check it in Excellent "
                        "Books before retrying. not_attempted was not sent."))
    if landed:
        result["note"] += (" Those in roles_added already existed and now have that role ticked "
                           "as well; nothing else on them was changed.")
    if already:
        result["note"] += " Those in already had the role; nothing was written to them."
    if unflagged:
        result["note"] += (" Those in flags_not_set exist but were stored without the kind, "
                           "role or birth date asked for; set it in Excellent Books before using "
                           "them.")
    return result


CONTACT_BUCKETS = ("created", "refused", "not_found_after_create", "roles_added",
                   "flags_not_set", write_outcome.NOT_ATTEMPTED, write_outcome.UNVERIFIED)


def _judge(out, index: int, entry: dict, after: dict, lost: bool, said) -> None:
    """The one bucket of a write whose read-back worked. A create must show its code AND name
    (review L2, write_outcome.judge_create), then the kind, the role and a birth date: a
    supplier stored without its Supplier flag, or a person with another birth date, is not the
    contact the person approved. A role checks only its own flag (Sol re-check MUST 5)."""
    summary, role = entry["summary"], entry["role"]
    stored = after.get(summary["code"])
    if not role:
        verdict, theirs = write_outcome.judge_create(stored, summary["code"],
                                                     entry["wanted"]["Name"])
        if verdict == write_outcome.ABSENT:
            if lost:
                out.put(index, write_outcome.UNVERIFIED, dict(
                    summary, why="The write reply was lost and the contact was not there when "
                                 "read back; check Excellent Books before retrying."))
            else:
                # The reply only explains a contact that is not there (erp.reply_problems).
                out.put(index, "not_found_after_create",
                        dict(summary, erp_said=said, **write_outcome.refusal_explanations(said))
                        if said else summary)
            return
        if verdict == write_outcome.UNVERIFIED:
            # Review L2: the same code under another name may be another user's contact.
            out.put(index, write_outcome.UNVERIFIED, dict(
                summary, why="A contact with this code is there under another name (%s); it "
                             "may not be the one approved. Check it in Excellent Books." % theirs))
            return
    stored = stored or {}
    checked = {f: v for f, v in entry["wanted"].items() if f != "Name"}
    if all(_clean(stored.get(f)) == v for f, v in checked.items()):
        out.put(index, "roles_added" if role else "created", summary)
    elif role and lost:
        out.put(index, write_outcome.UNVERIFIED, dict(
            summary, why="The write reply was lost and the role was not there when read back; "
                         "check Excellent Books before retrying."))
    else:
        # Only here, never also in created (Sol re-check MUST 4).
        out.put(index, "flags_not_set", dict(summary, expected=checked,
                                             stored={f: stored.get(f, "") for f in checked}))
