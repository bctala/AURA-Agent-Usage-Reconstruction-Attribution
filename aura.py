#!/usr/bin/env python3
"""
aura.py  --  AURA: Agent Usage Reconstruction & Attribution

A four-step command-line framework for investigating incidents involving
LLM agents. It reconstructs what an agent did, detects prompt-injection,
and produces a court-defensible report where every finding cites the exact
evidence it rests on.

  STEP 1  collect    normalize heterogeneous logs into one evidence store
  STEP 2  timeline   rebuild the ordered cause-and-effect chain per session
  STEP 3  scan       detect injection in untrusted content + link to actions
  STEP 4  report     produce an HTML report + integrity verification

Zero third-party dependencies. Python 3.8+.  Tested on Kali / Debian.

Usage:
  python3 aura.py run      --agent trace.jsonl --mail mail.json \
                           --identity signin.json --out case/
  # or one step at a time:
  python3 aura.py collect  --agent trace.jsonl --mail mail.json --out case/
  python3 aura.py timeline --case case/
  python3 aura.py scan     --case case/
  python3 aura.py report   --case case/ --html case/report.html

by Tala Almulla
"""

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
import uuid
from datetime import datetime, timezone, timedelta

VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
TOOL_NAME = "AURA"
TAGLINE = "Agent Usage Reconstruction & Attribution By Tala Almulla"

# --------------------------------------------------------------------------
# Terminal colour + progress helpers (auto-disabled when piped / NO_COLOR)
# --------------------------------------------------------------------------
_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(code):
    return code if _COLOR else ""


class C:
    RESET = _c("\033[0m"); BOLD = _c("\033[1m"); DIM = _c("\033[2m")
    RED = _c("\033[91m"); GREEN = _c("\033[92m"); YELLOW = _c("\033[93m")
    BLUE = _c("\033[94m"); MAGENTA = _c("\033[95m"); CYAN = _c("\033[96m")


BANNER = r"""
   █████╗ ██╗   ██╗██████╗  █████╗
  ██╔══██╗██║   ██║██╔══██╗██╔══██╗
  ███████║██║   ██║██████╔╝███████║
  ██╔══██║██║   ██║██╔══██╗██╔══██║
  ██║  ██║╚██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"""

EMBLEM = r"""
              _________
           .-'         '-.
         .'    _______    '.
        /    .'       '.    \
       |    |  A I      |    |
       |    |  AGENT    |    |
        \    '.  4N6  .'    /
         '.    '-----'    .'
           '-._______.-'\
                         '\.
                           '\.  """


def print_banner():
    print(C.CYAN + C.BOLD + BANNER + C.RESET)
    print(f"  {C.MAGENTA}{C.BOLD}{TOOL_NAME}{C.RESET}"
          f"{C.DIM} — {TAGLINE}  v{VERSION}{C.RESET}\n")


def step_start(n, name, sentence):
    print(f"{C.CYAN}{C.BOLD}[{n}/4] {name:8s}{C.RESET} {sentence} "
          f"{C.YELLOW}… IN PROGRESS{C.RESET}")


def step_done(n, name, result):
    print(f"{C.CYAN}{C.BOLD}[{n}/4] {name:8s}{C.RESET} "
          f"{C.GREEN}✔ DONE{C.RESET} — {result}\n")


def print_signoff():
    print(C.MAGENTA + C.BOLD + EMBLEM + C.RESET)
    print(f"                {C.BOLD}by Tala Almulla{C.RESET}\n")

# ==========================================================================
# SECTION 0 -- Shared evidence schema + helpers
# --------------------------------------------------------------------------
# Every collector writes events in ONE normalized shape. This is what turns
# four scattered log types into a single correlatable store. Each event also
# carries a pointer back to its raw source (file + hash + line), which is the
# chain-of-custody backbone the report later verifies.
# ==========================================================================

CANONICAL_FIELDS = [
    "event_id",        # stable unique id, e.g. ev-ab12cd34
    "timestamp",       # ISO-8601 UTC
    "source",          # agent_trace | mail_audit | identity | ...
    "source_file",     # originating file (basename)
    "source_sha256",   # hash of that whole file (custody)
    "raw_ref",         # line/record number inside the source
    "session_id",      # ties events from different sources together
    "actor",           # agent id / service principal / account
    "event_type",      # user_message|model_response|tool_call|tool_result|action|auth|downstream
    "tool_name",       # for tool_call/tool_result/action
    "trust",           # trusted | untrusted  (untrusted = ingested external data)
    "content",         # free text (message body, retrieved text, ...)
    "tool_input",      # dict, for tool_call
    "tool_output",     # str/dict, for tool_result
]

# Tools that change state in the outside world. An injection that leads to
# one of these is what turns "weird output" into "actual damage".
ACTION_TOOLS = {
    "send_email", "forward_email", "http_request", "http_post", "curl",
    "write_file", "delete_file", "transfer_funds", "wire", "post_message",
    "upload", "create_user", "run_command", "exec",
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def new_event(**kw):
    ev = {k: None for k in CANONICAL_FIELDS}
    ev["event_id"] = kw.pop("event_id", None) or "ev-" + uuid.uuid4().hex[:8]
    ev["schema_version"] = SCHEMA_VERSION
    ev["trust"] = "trusted"
    for k, v in kw.items():
        if k in ev or k == "schema_version":
            ev[k] = v
    return ev


def parse_ts(s):
    """Parse an ISO-8601 string into an aware UTC datetime. Naive -> assume UTC."""
    if s is None:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # last resort: common formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                dt = None
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def load_jsonl(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line:
                out.append((i, json.loads(line)))
    return out


def write_jsonl(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")


def case_path(case, name):
    return os.path.join(case, name)


def load_events(case):
    p = case_path(case, "events.jsonl")
    if not os.path.exists(p):
        sys.exit(f"[!] {p} not found. Run 'collect' first.")
    return [obj for _, obj in load_jsonl(p)]


# ==========================================================================
# SECTION 1 -- STEP 1: collect
# --------------------------------------------------------------------------
# One collector per log type. Each reads a vendor/format-specific file and
# emits normalized events. Adding a new evidence source = adding one function
# here; nothing downstream changes. Untrusted sources (data the agent
# ingested, e.g. an incoming email body or a fetched web page) are tagged
# trust="untrusted" -- Step 3 only scans those.
# ==========================================================================

def collect_agent_trace(path):
    """Agent framework export (JSONL). One record per step."""
    src = os.path.basename(path)
    digest = sha256_file(path)
    events = []
    for lineno, rec in load_jsonl(path):
        etype = rec.get("type")
        ev = new_event(
            timestamp=iso(parse_ts(rec.get("ts"))),
            source="agent_trace", source_file=src, source_sha256=digest,
            raw_ref=f"line:{lineno}",
            session_id=rec.get("session_id"),
            actor=rec.get("agent_id") or rec.get("actor"),
            event_type=etype,
            tool_name=rec.get("tool"),
            content=rec.get("content"),
            tool_input=rec.get("input"),
            tool_output=rec.get("output"),
        )
        # Content the agent PULLED IN from outside is untrusted.
        if etype == "tool_result" and rec.get("tool") in {
            "read_email", "read_webpage", "read_file", "search", "fetch_url",
            "read_document", "rag_lookup",
        }:
            ev["trust"] = "untrusted"
        events.append(ev)
    return events


def collect_mail_audit(path):
    """Downstream mail server audit log (JSON list)."""
    src = os.path.basename(path)
    digest = sha256_file(path)
    data = json.load(open(path, encoding="utf-8"))
    events = []
    for i, rec in enumerate(data):
        events.append(new_event(
            timestamp=iso(parse_ts(rec.get("time"))),
            source="mail_audit", source_file=src, source_sha256=digest,
            raw_ref=f"record:{i}",
            session_id=rec.get("session_id"),
            actor=rec.get("app_id") or rec.get("sender"),
            event_type="downstream",
            tool_name="send_email",
            content=f"to={rec.get('to')} subject={rec.get('subject')}",
            tool_input={"to": rec.get("to"), "subject": rec.get("subject")},
        ))
    return events


def collect_identity(path):
    """Identity provider sign-in log (JSON list)."""
    src = os.path.basename(path)
    digest = sha256_file(path)
    data = json.load(open(path, encoding="utf-8"))
    events = []
    for i, rec in enumerate(data):
        events.append(new_event(
            timestamp=iso(parse_ts(rec.get("time"))),
            source="identity", source_file=src, source_sha256=digest,
            raw_ref=f"record:{i}",
            session_id=rec.get("session_id"),
            actor=rec.get("principal") or rec.get("app_id"),
            event_type="auth",
            content=f"signin status={rec.get('status')} ip={rec.get('ip')}",
        ))
    return events


def cmd_collect(args):
    quiet = getattr(args, "quiet", False)
    os.makedirs(args.out, exist_ok=True)
    all_events, manifest = [], []
    plan = [(args.agent, collect_agent_trace, "agent_trace"),
            (args.mail, collect_mail_audit, "mail_audit"),
            (args.identity, collect_identity, "identity")]
    for path, fn, label in plan:
        if not path:
            continue
        if not os.path.exists(path):
            sys.exit(f"[!] input not found: {path}")
        evs = fn(path)
        all_events.extend(evs)
        digest = sha256_file(path)
        manifest.append({"source": label, "file": os.path.basename(path),
                         "path": os.path.abspath(path), "sha256": digest,
                         "events": len(evs)})
        if not quiet:
            print(f"[+] {label:12s} {len(evs):4d} events   sha256={digest[:16]}...  ({path})")

    write_jsonl(case_path(args.out, "events.jsonl"), all_events)
    json.dump({"tool": "aura", "version": VERSION,
               "collected_utc": iso(datetime.now(timezone.utc)),
               "sources": manifest, "total_events": len(all_events)},
              open(case_path(args.out, "manifest.json"), "w"), indent=2)
    if not quiet:
        print(f"[=] wrote {len(all_events)} normalized events -> {case_path(args.out,'events.jsonl')}")
        print(f"[=] custody manifest             -> {case_path(args.out,'manifest.json')}")
    return f"{len(all_events)} events from {len(manifest)} source(s)"


# ==========================================================================
# SECTION 2 -- STEP 2: timeline
# --------------------------------------------------------------------------
# Merge every source onto one clock, group by session, and rebuild the
# cause-and-effect chain. Two forensic problems handled here:
#   (a) clock skew between systems -- estimated by matching the same real
#       action seen in two sources (agent's send_email tool_call vs the mail
#       server's downstream record).
#   (b) orphan events -- a tool_call with no tool_result, or a session that
#       appears in identity/mail logs but has no agent trace at all.
# ==========================================================================

def estimate_clock_offset(events):
    """Match agent send_email tool_calls to mail_audit records by recipient."""
    agent_sends, mail_sends = [], []
    for e in events:
        if e["source"] == "agent_trace" and e["event_type"] == "tool_call" \
                and e["tool_name"] in {"send_email", "forward_email"}:
            agent_sends.append(e)
        if e["source"] == "mail_audit":
            mail_sends.append(e)
    offsets = []
    for a in agent_sends:
        a_to = (a.get("tool_input") or {}).get("to")
        for m in mail_sends:
            m_to = (m.get("tool_input") or {}).get("to")
            if a_to and m_to and a_to == m_to:
                ta, tm = parse_ts(a["timestamp"]), parse_ts(m["timestamp"])
                if ta and tm:
                    offsets.append((tm - ta).total_seconds())
    if not offsets:
        return None
    offsets.sort()
    return offsets[len(offsets) // 2]  # median


def cmd_timeline(args):
    quiet = getattr(args, "quiet", False)
    events = load_events(args.case)
    offset = estimate_clock_offset(events)

    # sort chronologically; keep original order stable for identical ts
    events.sort(key=lambda e: (parse_ts(e["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc)))

    # group by session
    sessions = {}
    for e in events:
        sessions.setdefault(e["session_id"] or "(no-session)", []).append(e)

    # detect orphans / gaps
    gaps = []
    trace_sessions = {e["session_id"] for e in events if e["source"] == "agent_trace"}
    for e in events:
        if e["source"] in {"mail_audit", "identity"} and e["session_id"] \
                and e["session_id"] not in trace_sessions:
            gaps.append({"type": "no_agent_trace", "session_id": e["session_id"],
                         "detail": f"{e['source']} event exists but no agent trace for this session",
                         "event_id": e["event_id"]})
    # dedupe gap sessions
    seen = set(); gaps = [g for g in gaps if not (g["session_id"] in seen or seen.add(g["session_id"]))]

    # tool_call without a following tool_result in same session
    for sid, evs in sessions.items():
        for i, e in enumerate(evs):
            if e["source"] == "agent_trace" and e["event_type"] == "tool_call":
                has_result = any(n["event_type"] == "tool_result" and n["tool_name"] == e["tool_name"]
                                 for n in evs[i + 1:i + 4])
                if not has_result:
                    gaps.append({"type": "missing_tool_result", "session_id": sid,
                                 "detail": f"tool_call '{e['tool_name']}' has no tool_result "
                                           f"(possible content-logging gap)",
                                 "event_id": e["event_id"]})

    out = {"tool": "aura", "version": VERSION,
           "clock_offset_mail_minus_agent_s": offset,
           "sessions": list(sessions.keys()),
           "gaps": gaps,
           "timeline": events}
    json.dump(out, open(case_path(args.case, "timeline.json"), "w"), indent=2, ensure_ascii=False)

    # human-readable print
    if not quiet:
        print(f"\n=== TIMELINE ({len(events)} events, {len(sessions)} sessions) ===")
        if offset is not None:
            print(f"[clock] mail server is {offset:+.0f}s vs agent host "
                  f"(matched on recipient). Align before trusting cross-source order.\n")
        for sid, evs in sessions.items():
            print(f"--- session {sid} ---")
            for e in evs:
                tag = "UNTRUSTED" if e["trust"] == "untrusted" else ""
                label = e["event_type"] + (f":{e['tool_name']}" if e["tool_name"] else "")
                desc = (e["content"] or "")[:70].replace("\n", " ")
                print(f"  {e['timestamp']}  [{e['source']:11s}] {label:22s} {tag:9s} {desc}")
            print()
        if gaps:
            print("=== GAPS / MISSING EVIDENCE ===")
            for g in gaps:
                print(f"  [{g['type']}] session={g['session_id']}: {g['detail']}")
        print(f"\n[=] wrote {case_path(args.case,'timeline.json')}")

    off_txt = f"{offset:+.0f}s" if offset is not None else "n/a"
    return f"{len(sessions)} session(s) · clock skew {off_txt} · {len(gaps)} gap(s)"


# ==========================================================================
# SECTION 3 -- STEP 3: scan
# --------------------------------------------------------------------------
# Look ONLY at untrusted content (data the agent ingested) for prompt
# injection, then link each hit to the state-changing actions that followed
# it in the same session. Two detector families:
#   (a) hidden characters -- zero-width, bidi overrides, unicode "tag" chars,
#       and other invisible format controls used to smuggle instructions.
#   (b) instruction patterns -- imperative phrases typical of injection.
# Linkage + confidence is what makes this forensic rather than a lint check.
# ==========================================================================

HIDDEN_RANGES = [
    (0x200B, 0x200F),   # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),   # bidi embeddings/overrides
    (0x2060, 0x2064),   # word joiner / invisible operators
    (0x2066, 0x2069),   # bidi isolates
    (0xFEFF, 0xFEFF),   # BOM / zero-width no-break space
    (0xE0000, 0xE007F), # unicode tag characters
]

INJECTION_PATTERNS = [
    (r"ignore (all |the )?(previous|prior|above) (instructions|prompts?)", "override", 3),
    (r"disregard (the |all )?(previous|above|prior)", "override", 3),
    (r"forget (your |the |all )?(previous |prior )?(instructions|rules)", "override", 3),
    (r"new instructions?:", "override", 2),
    (r"you are now", "roleplay", 2),
    (r"act as (an?|the)", "roleplay", 1),
    (r"system prompt", "system_ref", 2),
    (r"do ?n['o]?t (tell|inform|mention|alert)", "stealth", 3),
    (r"without (telling|informing|notifying)", "stealth", 3),
    (r"keep this (secret|confidential|between us)", "stealth", 2),
    (r"(forward|send|email|cc|bcc) .{0,40}@", "exfiltration", 3),
    (r"(transfer|wire|send) .{0,20}(funds|money|payment|invoice)", "exfiltration", 3),
    (r"(delete|wipe|remove) (all |the )?(logs|files|emails|records)", "destruction", 3),
    (r"(curl|wget|fetch|http[s]?://)", "network", 2),
    (r"(reveal|print|output|repeat|show) (your |the )?(system |initial )?(prompt|instructions|api[_ ]?key|token)", "disclosure", 3),
    (r"run the following", "exec", 2),
]


def find_hidden(text):
    hits = []
    for ch in text or "":
        cp = ord(ch)
        for lo, hi in HIDDEN_RANGES:
            if lo <= cp <= hi:
                hits.append((cp, unicodedata.name(ch, "UNKNOWN")))
                break
    return hits


def visible_of(text):
    """Strip hidden chars so instruction matching sees the smuggled text."""
    return "".join(c for c in (text or "")
                   if not any(lo <= ord(c) <= hi for lo, hi in HIDDEN_RANGES))


def scan_text(text):
    clean = visible_of(text)
    patt = []
    for rx, cat, weight in INJECTION_PATTERNS:
        m = re.search(rx, clean, re.IGNORECASE)
        if m:
            patt.append({"category": cat, "match": m.group(0)[:80], "weight": weight})
    hidden = find_hidden(text)
    score = sum(p["weight"] for p in patt) + (2 if hidden else 0)
    return patt, hidden, score


def cmd_scan(args):
    quiet = getattr(args, "quiet", False)
    events = load_events(args.case)
    # index by session preserving chronological order
    events.sort(key=lambda e: (parse_ts(e["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc)))
    findings = []

    for i, e in enumerate(events):
        if e["trust"] != "untrusted":
            continue
        blob = " ".join(str(x) for x in [e.get("content"), e.get("tool_output")] if x)
        patt, hidden, score = scan_text(blob)
        if score == 0:
            continue

        # link to state-changing actions that follow, same session
        linked = []
        inj_kw = " ".join(p["match"] for p in patt).lower()
        for n in events[i + 1:]:
            if n["session_id"] != e["session_id"]:
                continue
            if n["event_type"] in {"tool_call", "action"} and n["tool_name"] in ACTION_TOOLS:
                steps = 0
                # count intervening agent events in the session
                idx_e = events.index(e); idx_n = events.index(n)
                steps = sum(1 for m in events[idx_e:idx_n]
                            if m["session_id"] == e["session_id"]
                            and m["source"] == "agent_trace")
                # does the action match the injected intent?
                tgt = str(n.get("tool_input") or "").lower()
                match_bonus = 2 if (n["tool_name"] in {"send_email", "forward_email"}
                                    and "@" in inj_kw) else 0
                linked.append({"event_id": n["event_id"], "tool": n["tool_name"],
                               "timestamp": n["timestamp"], "steps_after": steps,
                               "tool_input": n.get("tool_input"),
                               "match_bonus": match_bonus})

        # confidence
        conf_score = score + sum(l["match_bonus"] for l in linked) + (2 if linked else 0)
        conf = "HIGH" if conf_score >= 7 else "MEDIUM" if conf_score >= 4 else "LOW"

        findings.append({
            "finding_id": "f-" + uuid.uuid4().hex[:8],
            "type": "prompt_injection",
            "confidence": conf,
            "score": conf_score,
            "source_event": e["event_id"],
            "session_id": e["session_id"],
            "source_ref": {"file": e["source_file"], "sha256": e["source_sha256"],
                           "raw_ref": e["raw_ref"]},
            "patterns": patt,
            "hidden_chars": [{"codepoint": f"U+{cp:04X}", "name": nm} for cp, nm in hidden],
            "linked_actions": linked,
            "explanation": _explain(patt, hidden, linked),
        })

    json.dump({"tool": "aura", "version": VERSION,
               "findings": findings, "count": len(findings)},
              open(case_path(args.case, "findings.json"), "w"), indent=2, ensure_ascii=False)

    if not quiet:
        print(f"\n=== SCAN: {len(findings)} finding(s) ===")
        for f in findings:
            print(f"\n[{f['confidence']}] {f['finding_id']}  session={f['session_id']}")
            print(f"   source event : {f['source_event']}  ({f['source_ref']['file']} {f['source_ref']['raw_ref']})")
            if f["hidden_chars"]:
                print(f"   hidden chars : " + ", ".join(h["name"] for h in f["hidden_chars"][:6]))
            for p in f["patterns"]:
                print(f"   pattern      : [{p['category']}] \"{p['match']}\"")
            for l in f["linked_actions"]:
                print(f"   -> ACTION    : {l['tool']} at {l['timestamp']} "
                      f"({l['steps_after']} steps later) -> {l['event_id']}")
            print(f"   assessment   : {f['explanation']}")
        print(f"\n[=] wrote {case_path(args.case,'findings.json')}")

    highs = sum(1 for f in findings if f["confidence"] == "HIGH")
    return f"{len(findings)} finding(s) ({highs} HIGH)"


def _explain(patt, hidden, linked):
    bits = []
    if hidden:
        bits.append(f"{len(hidden)} invisible/control character(s) used to smuggle text")
    if patt:
        cats = sorted({p['category'] for p in patt})
        bits.append("instruction-like content (" + ", ".join(cats) + ")")
    if linked:
        a = linked[0]
        bits.append(f"followed by a state-changing '{a['tool']}' action {a['steps_after']} steps later")
    else:
        bits.append("no state-changing action was linked (possible failed/blocked attempt)")
    return "; ".join(bits) + "."


# ==========================================================================
# SECTION 4 -- STEP 4: report
# --------------------------------------------------------------------------
# Assemble a single HTML report. Two things make it defensible:
#   (1) VERIFY -- every event_id cited by a finding is confirmed to exist in
#       the evidence store, and every source file hash is recorded. If a
#       citation can't be resolved, the report says so instead of hiding it.
#   (2) GAPS -- what's missing is stated explicitly, so a reader never
#       mistakes "we couldn't see it" for "it didn't happen".
# ==========================================================================

def verify(events, findings):
    ids = {e["event_id"] for e in events}
    results = []
    for f in findings:
        cited = [f["source_event"]] + [l["event_id"] for l in f["linked_actions"]]
        missing = [c for c in cited if c not in ids]
        results.append({"finding_id": f["finding_id"],
                        "cited": cited, "missing": missing,
                        "ok": not missing})
    return results


def cmd_report(args):
    quiet = getattr(args, "quiet", False)
    events = load_events(args.case)
    manifest = json.load(open(case_path(args.case, "manifest.json")))
    timeline = json.load(open(case_path(args.case, "timeline.json"))) \
        if os.path.exists(case_path(args.case, "timeline.json")) else {"gaps": [], "clock_offset_mail_minus_agent_s": None}
    findings_doc = json.load(open(case_path(args.case, "findings.json"))) \
        if os.path.exists(case_path(args.case, "findings.json")) else {"findings": []}
    findings = findings_doc["findings"]

    ver = verify(events, findings)
    verified_ok = all(v["ok"] for v in ver)

    # overall assessment (qualitative, not fake-precise)
    highs = [f for f in findings if f["confidence"] == "HIGH"]
    overall = "HIGH concern" if highs else ("MEDIUM concern" if findings else "No injection detected")

    html = _html_report(manifest, timeline, findings, ver, verified_ok, overall)
    open(args.html, "w", encoding="utf-8").write(html)
    if not quiet:
        print(f"[=] report written -> {args.html}")
        print(f"[=] findings: {len(findings)}  |  citation integrity: "
              f"{'PASS' if verified_ok else 'FAIL'}  |  overall: {overall}")
        print_signoff()
    return f"citations {'PASS' if verified_ok else 'FAIL'} · {overall}"


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;")) if s is not None else ""


def _html_report(manifest, timeline, findings, ver, verified_ok, overall):
    rows = ""
    for e in timeline.get("timeline", []):
        cls = ' class="untrusted"' if e["trust"] == "untrusted" else ""
        rows += (f"<tr{cls}><td>{_esc(e['timestamp'])}</td><td>{_esc(e['source'])}</td>"
                 f"<td>{_esc(e['event_type'])}{(':'+_esc(e['tool_name'])) if e['tool_name'] else ''}</td>"
                 f"<td>{_esc((e.get('content') or '')[:80])}</td>"
                 f"<td class='mono'>{_esc(e['event_id'])}</td></tr>")

    fcards = ""
    for f in findings:
        links = "".join(
            f"<li>action <b>{_esc(l['tool'])}</b> at {_esc(l['timestamp'])} "
            f"({l['steps_after']} steps later) &rarr; <span class='mono'>{_esc(l['event_id'])}</span></li>"
            for l in f["linked_actions"]) or "<li>none</li>"
        pats = "".join(f"<li>[{_esc(p['category'])}] <code>{_esc(p['match'])}</code></li>"
                       for p in f["patterns"]) or "<li>none</li>"
        hid = ", ".join(f"{_esc(h['codepoint'])} {_esc(h['name'])}" for h in f["hidden_chars"]) or "none"
        badge = {"HIGH": "badge-high", "MEDIUM": "badge-med", "LOW": "badge-low"}[f["confidence"]]
        fcards += f"""
        <div class="card">
          <h3><span class="badge {badge}">{f['confidence']}</span> {_esc(f['finding_id'])}
              &mdash; prompt injection (session {_esc(f['session_id'])})</h3>
          <p>{_esc(f['explanation'])}</p>
          <p><b>Source evidence:</b> <span class="mono">{_esc(f['source_event'])}</span>
             from <span class="mono">{_esc(f['source_ref']['file'])}</span>
             {_esc(f['source_ref']['raw_ref'])} &middot;
             sha256 <span class="mono">{_esc(f['source_ref']['sha256'][:24])}...</span></p>
          <p><b>Hidden characters:</b> {hid}</p>
          <p><b>Instruction patterns:</b></p><ul>{pats}</ul>
          <p><b>Linked actions:</b></p><ul>{links}</ul>
        </div>"""

    src_rows = "".join(
        f"<tr><td>{_esc(s['source'])}</td><td class='mono'>{_esc(s['file'])}</td>"
        f"<td class='mono'>{_esc(s['sha256'])}</td><td>{s['events']}</td></tr>"
        for s in manifest["sources"])

    gap_rows = "".join(
        f"<li>[{_esc(g['type'])}] session <b>{_esc(g['session_id'])}</b>: {_esc(g['detail'])}</li>"
        for g in timeline.get("gaps", [])) or "<li>No gaps detected.</li>"

    ver_rows = "".join(
        f"<tr><td class='mono'>{_esc(v['finding_id'])}</td>"
        f"<td>{'&#10003; all citations resolve' if v['ok'] else '&#10007; MISSING: '+_esc(v['missing'])}</td></tr>"
        for v in ver) or "<tr><td colspan=2>No findings to verify.</td></tr>"

    off = timeline.get("clock_offset_mail_minus_agent_s")
    off_txt = (f"Mail server clock is {off:+.0f}s relative to the agent host "
               f"(measured by matching the same send on both sides).") if off is not None \
        else "Not enough cross-source matches to estimate clock skew."

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>AI Agent Forensics Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;line-height:1.5}}
 h1{{border-bottom:3px solid #333;padding-bottom:.3rem}}
 h2{{margin-top:2rem;border-bottom:1px solid #ccc;padding-bottom:.2rem}}
 .mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85em}}
 table{{border-collapse:collapse;width:100%;font-size:.9em}}
 td,th{{border:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}}
 th{{background:#f4f4f4}}
 tr.untrusted td{{background:#fff6f6}}
 .card{{border:1px solid #ddd;border-left:5px solid #888;border-radius:6px;padding:1rem;margin:1rem 0;background:#fafafa}}
 .badge{{padding:.1rem .5rem;border-radius:4px;color:#fff;font-size:.8em;font-weight:bold}}
 .badge-high{{background:#c0392b}} .badge-med{{background:#e67e22}} .badge-low{{background:#7f8c8d}}
 .summary{{padding:1rem;border-radius:6px;background:#eef;border:1px solid #99c}}
 code{{background:#eee;padding:.05rem .3rem;border-radius:3px}}
 .pass{{color:#27ae60;font-weight:bold}} .fail{{color:#c0392b;font-weight:bold}}
 footer{{margin-top:3rem;font-size:.8em;color:#777}}
</style></head><body>
<h1>AURA &mdash; AI Agent Forensics Report</h1>
<div class="summary">
  <b>Overall assessment:</b> {overall}<br>
  <b>Findings:</b> {len(findings)} &middot;
  <b>Citation integrity:</b> <span class="{'pass' if verified_ok else 'fail'}">
     {'PASS - every cited event resolves to collected evidence' if verified_ok else 'FAIL - see verification section'}</span><br>
  <b>Generated:</b> {iso(datetime.now(timezone.utc))} by {TOOL_NAME} {VERSION} &middot; author: Tala Almulla
</div>

<h2>1. Evidence sources (chain of custody)</h2>
<table><tr><th>Source</th><th>File</th><th>SHA-256</th><th>Events</th></tr>{src_rows}</table>

<h2>2. Findings</h2>
{fcards or "<p>No prompt-injection indicators found in untrusted content.</p>"}

<h2>3. What we could NOT establish (gaps)</h2>
<p>{off_txt}</p>
<ul>{gap_rows}</ul>
<p class="mono">Absence of evidence here is reported explicitly; it must not be read as proof that nothing happened.</p>

<h2>4. Citation verification</h2>
<table><tr><th>Finding</th><th>Result</th></tr>{ver_rows}</table>

<h2>5. Full timeline</h2>
<table><tr><th>Timestamp (UTC)</th><th>Source</th><th>Event</th><th>Content</th><th>Event ID</th></tr>{rows}</table>
<p><span style="background:#fff6f6;border:1px solid #ddd;padding:0 .4rem">pink rows</span> = untrusted content ingested by the agent (the only rows scanned for injection).</p>

<footer>Reproducible: rerun the four steps on the same inputs (same hashes) to regenerate this report.
Model behaviour is non-deterministic; this report analyses the recorded trace, not a re-execution.</footer>
</body></html>"""


# ==========================================================================
# RUN -- all four steps in sequence with a live progress tracker
# ==========================================================================

def cmd_run(args):
    from argparse import Namespace
    print_banner()
    print(f"  {C.DIM}case: {args.out}{C.RESET}\n")

    step_start(1, "Collect", "normalizing heterogeneous evidence into one store")
    s1 = cmd_collect(Namespace(agent=args.agent, mail=args.mail,
                               identity=args.identity, out=args.out, quiet=True))
    step_done(1, "Collect", s1)

    step_start(2, "Timeline", "rebuilding the per-session cause-and-effect chain")
    s2 = cmd_timeline(Namespace(case=args.out, quiet=True))
    step_done(2, "Timeline", s2)

    step_start(3, "Scan", "hunting prompt injection in untrusted content")
    s3 = cmd_scan(Namespace(case=args.out, quiet=True))
    step_done(3, "Scan", s3)

    html = args.html or case_path(args.out, "report.html")
    step_start(4, "Report", "writing the citation-verified report")
    s4 = cmd_report(Namespace(case=args.out, html=html, quiet=True))
    step_done(4, "Report", s4)

    print(f"  {C.BOLD}report:{C.RESET} {html}")
    print_signoff()


# ==========================================================================
# CLI dispatch
# ==========================================================================

def main():
    p = argparse.ArgumentParser(
        prog="aura",
        description="AURA - Agent Usage Reconstruction & Attribution (AI agent forensics).")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r0 = sub.add_parser("run", help="run all four steps with a progress tracker")
    r0.add_argument("--agent", help="agent trace (JSONL)")
    r0.add_argument("--mail", help="mail audit log (JSON)")
    r0.add_argument("--identity", help="identity sign-in log (JSON)")
    r0.add_argument("--out", default="case", help="case output directory (default: case)")
    r0.add_argument("--html", default=None, help="report path (default: <case>/report.html)")
    r0.set_defaults(func=cmd_run)

    c = sub.add_parser("collect", help="STEP 1: normalize logs into an evidence store")
    c.add_argument("--agent", help="agent trace (JSONL)")
    c.add_argument("--mail", help="mail audit log (JSON)")
    c.add_argument("--identity", help="identity sign-in log (JSON)")
    c.add_argument("--out", required=True, help="case output directory")
    c.add_argument("--quiet", action="store_true", help="suppress verbose output")
    c.set_defaults(func=cmd_collect)

    t = sub.add_parser("timeline", help="STEP 2: rebuild ordered cause-and-effect chain")
    t.add_argument("--case", required=True)
    t.add_argument("--quiet", action="store_true")
    t.set_defaults(func=cmd_timeline)

    s = sub.add_parser("scan", help="STEP 3: detect injection + link to actions")
    s.add_argument("--case", required=True)
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="STEP 4: HTML report + citation verification")
    r.add_argument("--case", required=True)
    r.add_argument("--html", default=None)
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(func=cmd_report)

    args = p.parse_args()
    if args.cmd == "report" and not args.html:
        args.html = case_path(args.case, "report.html")
    args.func(args)


if __name__ == "__main__":
    main()
