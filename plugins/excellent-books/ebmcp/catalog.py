"""The report catalogue: one YAML per report window, generated skeleton + hand-written meaning.

Two ERP endpoints feed the skeleton, joined on `window_class`:
- `getreportfilters` — title, module, typed spec fields. Carries NO repname.
- `getstartupitems` — `reports[].report_function`, which IS the repname. The RClass->Rn naming
  convention fails for 10 % of reports and a wrong repname answers "Access denied", so the
  repname is never derived, only looked up here.

Both lists repeat a window once per language source file; `join_reports` dedupes, keeping the
copy that actually carries filters. `merge` lets the skeleton be regenerated from a newer ERP
build without losing what consultants wrote: generated facts (repname, types, required flags)
refresh; meaning, answers, pitfalls, translations, verification stay.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

import yaml

GENERATED_STATUSES = ("skeleton", "no-spec-window", "no-repname")
# Per spec field: what the ERP says (refreshed); every other subkey a person adds is kept.
SPEC_GENERATED = ("type", "label", "required", "options", "interface", "client_default")
# Per document: the keys the generator owns. Everything else — answers, answers_et, pitfalls,
# verified, last_run, crashes_server, whatever the next agent or tool adds — survives a
# regeneration. An allowlist of hand keys was tried first and dropped `answers_et` the day
# the first description landed; the generator's own keys are the finite list.
DOC_GENERATED = ("id", "module", "window_class", "repname", "repnames_all", "title", "status",
                 "spec", "api_note", "spec_source")


# ----------------------------------------------------------------------------- joining


def load_branches(path) -> dict:
    """tools/books_branches.yaml: {window class: {field: {"keep": 0 | 1 | "both", "why": ...}}}."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def books_branch(window_class: str, filters: list, branches: dict) -> tuple:
    """(filters, undecided): each field once, as Excellent Books shows it.

    The endpoint lists both sides of a window's if/else, so a field can come twice with two
    labels or two kinds (Ordered Items' Print: a three-way choice on Books, a tick box elsewhere).
    `branches` says which: the first, the second, or both (one setting behind two widgets on
    Books, the labels joined) — or none: the endpoint also lists fields inside a block comment,
    which no Books user can set (Kaupo, 2026-10-03: dropped). A field listed twice with no
    decision keeps the endpoint's last copy, as before, and is named in `undecided`."""
    seen: dict = {}
    for f in filters:
        seen.setdefault(f.get("field"), []).append(f)
    out, undecided = [], []
    for field, copies in seen.items():
        keep = ((branches or {}).get(window_class) or {}).get(field, {}).get("keep")
        if keep == "none":
            continue
        if len(copies) == 1:
            out.append(copies[0])
        elif keep == "both":
            labels = list(dict.fromkeys(c.get("label") for c in copies if c.get("label")))
            out.append(dict(copies[0], label=" / ".join(labels)))
        elif keep in (0, 1) and keep < len(copies):
            out.append(copies[keep])
        else:
            undecided.append(field)
            out.append(copies[-1])
    return out, undecided


def join_reports(filters_json: dict, startup_json: dict, books_windows: Optional[dict] = None,
                 branches: Optional[dict] = None, defaults: Optional[dict] = None) -> list:
    """One entry per distinct window_class, in first-seen order of `getreportfilters`.

    `books_windows` ({window_class: filters}) fills a window the endpoint returned without filters:
    it reads only productwindows.hal (correction 16), so 74 Books windows came back empty. Those
    fields are parsed from the Books source and probed on the ERP first (tools/window_fields.py,
    tools/probe_window_fields.py); the endpoint's own filters always win where it has any.
    `branches` (load_branches) picks the Books widget of a field listed twice (books_branch).
    `defaults` ({window_class: {field: value}}, tools/window_defaults.py) are what the window's
    defaults hook sets when the client opens it; skeleton keeps those on declared fields."""
    repnames: dict = {}
    for r in startup_json.get("reports", []):
        repnames.setdefault(r["window_class"], set()).add(r["report_function"])

    entries: dict = {}
    for r in filters_json.get("reports", []):
        wc = r["window_class"]
        current = entries.get(wc)
        if current is None:
            entries[wc] = {"title": r["title"], "window_class": wc, "module": r["module"],
                           "filters": list(r.get("filters") or []), "note": r.get("note"),
                           "repnames": sorted(repnames.get(wc, ()))}
            continue
        # a later duplicate wins only where it carries more than the first copy did
        if len(r.get("filters") or []) > len(current["filters"]):
            current["filters"] = list(r["filters"])
        if r.get("note") and not current["note"]:
            current["note"] = r["note"]
    for wc, entry in entries.items():
        if not entry["filters"] and (books_windows or {}).get(wc):
            entry["filters"] = list(books_windows[wc])
            entry["spec_source"] = "books-window"
        entry["filters"], undecided = books_branch(wc, entry["filters"], branches)
        if (defaults or {}).get(wc):
            entry["defaults"] = dict(defaults[wc])
        if undecided:
            entry["undecided"] = undecided
    return list(entries.values())


# ----------------------------------------------------------------------------- naming


def module_short(module: str) -> str:
    return module[3:] if module.startswith("mod") else module


def slug_for(entry: dict, taken: set) -> str:
    """kebab-case of the English title; on collision the window class disambiguates, so the
    name is stable across regenerations (a counter would depend on order)."""
    base = re.sub(r"[^a-z0-9]+", "-", entry["title"].lower()).strip("-") or entry["window_class"].lower()
    slug = base
    if slug in taken:
        tail = re.sub(r"rclass$", "", entry["window_class"].lower()) or entry["window_class"].lower()
        slug = "%s-%s" % (base, tail)
    taken.add(slug)
    return slug


# ----------------------------------------------------------------------------- skeleton


def _options(raw) -> dict | None:
    if not raw:
        return None
    if isinstance(raw, dict):
        return dict(raw)
    out = {}
    for o in raw:
        if isinstance(o, dict):
            out[o.get("value")] = o.get("label", o.get("value"))
        else:
            out[o] = o
    return out


def skeleton(entry: dict, slug: str) -> dict:
    spec = {}
    for f in entry.get("filters") or []:
        field = {"type": f.get("datatype"), "label": f.get("label"), "required": bool(f.get("required")),
                 "meaning": None}
        if f.get("interfacetype") and f["interfacetype"] not in ("EditField", "EditFieldTL", "DateField", "CheckBox"):
            field["interface"] = f["interfacetype"]
        opts = _options(f.get("options"))
        if opts:
            field["options"] = opts
        # What the client's window ticks on opening; run_report sends it unless told otherwise.
        if (entry.get("defaults") or {}).get(f["field"]):
            field["client_default"] = entry["defaults"][f["field"]]
        spec[f["field"]] = field

    if entry.get("note") and "not found" in entry["note"].lower() and not entry.get("spec_source"):
        status = "no-spec-window"
    elif not entry.get("repnames"):
        status = "no-repname"
    else:
        status = "skeleton"

    doc = {
        "id": "%s/%s" % (module_short(entry["module"]), slug),
        "module": entry["module"],
        "window_class": entry["window_class"],
        "repname": entry["repnames"][0] if entry.get("repnames") else None,
        "title": {"en": entry["title"]},
        "status": status,
        "answers": [],
        "not_for": [],
        "spec": spec,
        "output": {"columns": [], "footer": []},
        "pitfalls": [],
        "sources": [],
        "verified": None,
    }
    if len(entry.get("repnames") or []) > 1:
        doc["repnames_all"] = list(entry["repnames"])
    if entry.get("note"):
        doc["api_note"] = entry["note"]
    if entry.get("spec_source"):
        doc["spec_source"] = entry["spec_source"]
    return doc


# ----------------------------------------------------------------------------- merge


def merge(existing: dict, fresh: dict) -> dict:
    """Fresh skeleton + everything a person wrote into `existing`."""
    merged = dict(fresh)
    # status: a hand-set status survives; a generated one is recomputed
    if existing.get("status") not in GENERATED_STATUSES and existing.get("status"):
        merged["status"] = existing["status"]
    # repname: generated — unless the verifier switched to another of the window's run names
    # because the ERP denied this one, and the ERP still offers the switched-to name
    if (existing.get("repname_denied") == fresh.get("repname")
            and existing.get("repname") in (fresh.get("repnames_all") or [])):
        merged["repname"] = existing["repname"]
    # titles: English is generated, every other language is hand-written
    title = dict(fresh.get("title") or {})
    for lang, text in (existing.get("title") or {}).items():
        if lang != "en":
            title[lang] = text
    merged["title"] = title
    # every key the generator does not own is a person's or a tool's: keep it
    for key, value in existing.items():
        if key not in DOC_GENERATED and key != "removed_spec" and value not in (None, [], {}):
            merged[key] = value
    # spec fields: generated facts from fresh, every other subkey from existing
    spec = {}
    old_spec = existing.get("spec") or {}
    # An earlier regeneration's record of dropped fields stays, and a field that comes back
    # takes its meaning from it.
    kept = dict(existing.get("removed_spec") or {})
    for name, fresh_field in (fresh.get("spec") or {}).items():
        field = dict(fresh_field)
        old = old_spec.get(name) or kept.get(name) or {}
        for key, value in old.items():
            if key not in SPEC_GENERATED and value is not None:
                field[key] = value
        spec[name] = field
    merged["spec"] = spec
    removed = {name: value for name, value in kept.items() if name not in spec}
    removed.update({name: old_spec[name] for name in old_spec if name not in spec})
    if removed:
        merged["removed_spec"] = removed
    return merged


# ----------------------------------------------------------------------------- files


class _Dumper(yaml.SafeDumper):
    pass


def _str_presenter(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _str_presenter)


def dump_yaml(doc: dict) -> str:
    return yaml.dump(doc, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=100)


# libyaml's loader when the PyYAML install has it (the wheels bundle it): 0.23 s for the 873
# catalogue files against 2.07 s pure-Python, identical data (tests/test_catalog.py). The index
# is built on the first find_report, so this was 4.5 s on the first question of every session.
YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def load_yaml(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=YAML_LOADER) or {}


def path_for(root: Path, doc: dict) -> Path:
    module, slug = doc["id"].split("/", 1)
    return root / module / ("%s.yaml" % slug)


def write_catalog(entries: Iterable[dict], root: Path, *, preserve_books_windows: bool = False) -> dict:
    """Write or refresh one YAML per entry. Returns counts: written, refreshed, by status."""
    root.mkdir(parents=True, exist_ok=True)
    taken_by_module: dict = {}
    stats = {"written": 0, "refreshed": 0, "status": {}}
    for entry in entries:
        taken = taken_by_module.setdefault(entry["module"], set())
        doc = skeleton(entry, slug_for(entry, taken))
        path = path_for(root, doc)
        if path.exists():
            existing = load_yaml(path)
            if preserve_books_windows and existing.get("spec_source") == "books-window":
                status = existing["status"]
                stats["status"][status] = stats["status"].get(status, 0) + 1
                continue
            doc = merge(existing, doc)
            stats["refreshed"] += 1
        else:
            stats["written"] += 1
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dump_yaml(doc), encoding="utf-8", newline="\n")
        stats["status"][doc["status"]] = stats["status"].get(doc["status"], 0) + 1
    return stats


def _timed_out_at(doc: dict) -> Optional[float]:
    """The limit a run gave up at, when the last one did. The matcher shows it so a model does
    not spend 90 seconds discovering what the catalogue already knows."""
    last = doc.get("last_run") or {}
    if last.get("ok") is False and "timeouterror" in str(last.get("error", "")).lower():
        return last.get("timeout")
    return None


def build_index(root: Path) -> list:
    """A flat list the tools load at start.

    Carries `answers_et` and `not_for` as well as `answers`, because the matcher needs both:
    without the Estonian an Estonian question matches nothing, and without the cross-references
    it cannot route a question away from the report that explicitly disclaims it.
    """
    index = []
    for path in sorted(root.glob("*/*.yaml")):
        doc = load_yaml(path)
        index.append({k: doc.get(k) for k in ("id", "module", "window_class", "repname", "title", "status")}
                     | {"answers": doc.get("answers") or [],
                        "answers_et": doc.get("answers_et") or [],
                        "not_for": doc.get("not_for") or [],
                        "replaced_by": doc.get("replaced_by"),
                        "seconds": (doc.get("verified") or {}).get("seconds"),
                        "timed_out_at": _timed_out_at(doc),
                        "file": path.relative_to(root).as_posix()})
    return index
