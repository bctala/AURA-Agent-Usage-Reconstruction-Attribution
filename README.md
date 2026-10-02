# AURA: Agent Usage Reconstruction & Attribution

> A command-line **digital-forensics toolkit for AI-agent incidents**. AURA reconstructs what an LLM agent did, detects prompt-injection in the data the agent ingested, links each injection to the real-world action it triggered, and produces a court-defensible report where **every finding cites the exact evidence it rests on**.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Linux%20%7C%20-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-prototype-orange)

---

## Why AURA

LLM agents now take real actions (sending email, editing files, calling APIs, moving data) on behalf of an identity. When one is abused, investigators have to prove **what** the agent did, **why**, and **under whose authority**, from evidence scattered across the agent framework, the tools it called, the systems it touched, and the identity provider that authenticated it. There is almost no open tooling for that.

These are not hypothetical problems. Real 2025–2026 incidents motivate AURA directly:

---

## What it does

AURA is one CLI with **four steps**. Each step is useful alone; together they form the pipeline.

| Step | Command | What it does |
|------|---------|--------------|
| 1 | `collect`  | Normalizes heterogeneous logs (agent trace, mail audit, identity) into **one evidence store**, hashing every source file for chain of custody. Tags content the agent ingested as `untrusted`. |
| 2 | `timeline` | Merges sources onto one clock, groups by session, rebuilds the **cause-and-effect chain**, estimates cross-source **clock skew**, and flags **gaps / orphans**. |
| 3 | `scan`     | Scans **only untrusted content** for prompt injection — hidden Unicode + instruction patterns — and **links each hit to the state-changing action** that followed, with a confidence score. |
| 4 | `report`   | Builds an HTML report, **verifies every cited event** resolves to collected evidence, and states explicitly what could **not** be established. |

---

## Requirements

- **Python 3.8+**
- **No third-party packages** — standard library only.

The architecture diagram was rendered with `matplotlib` (dev-only, not needed to run AURA).

---

## Installation

```bash
git clone https://github.com/<your-username>/aura.git
cd aura
python3 aura.py --version
```
---

## Quick start

```bash
# 1. generate the bundled sample incident (clean + injected sessions, a gap, a clock skew)
python3 samples/generate_samples.py

# 2. run the whole pipeline with a live progress tracker
python3 aura.py run \
    --agent    samples/agent_trace.jsonl \
    --mail     samples/mail_audit.json \
    --identity samples/identity_signin.json \
    --out case

# 3. open the report
xdg-open case/report.html
```

---

## Usage

**All-in-one** (recommended):

```bash
python3 aura.py run --agent samples/agent_trace.jsonl \
                    --mail samples/mail_audit.json \
                    --identity samples/identity_signin.json --out case
```

**Step by step** (more verbose output per step):

```bash
python3 aura.py collect  --agent samples/agent_trace.jsonl \
                         --mail samples/mail_audit.json \
                         --identity samples/identity_signin.json --out case
python3 aura.py timeline --case case
python3 aura.py scan     --case case
python3 aura.py report   --case case --html case/report.html
```

**`--out` vs `--case`.** `case` is just the name of the investigation folder — call it anything. `--out case` means *create/write the case here* (Step 1 produces it). `--case case` means *read the existing case here* (Steps 2–4 consume it).

**Options:** `--agent`, `--mail`, `--identity` are each optional — drop any you don't have (an agent trace alone works). `--quiet` suppresses verbose output on the individual steps. `--html` sets the report path (defaults to `<case>/report.html`).

**Note on paths:** the sample paths are relative, so run from the folder containing `aura.py` and `samples/`, or pass absolute paths (e.g. `--agent ~/Desktop/aura/samples/agent_trace.jsonl`).

---

## Input formats

- **Agent trace** (`.jsonl`, one step per line):
  `{"ts","session_id","agent_id","type","tool","content","input","output"}`
  where `type` ∈ `user_message | model_response | tool_call | tool_result`.
- **Mail audit** (`.json` list): `{"time","session_id","app_id","to","subject"}`.
- **Identity sign-in** (`.json` list): `{"time","session_id","principal","status","ip"}`.

To add a new source (MCP server log, cloud trail, Slack audit), write one collector function in Section 1 of `aura.py` that emits the shared event schema.

---

## Output

```
case/
  events.jsonl     normalized evidence store (the shared schema)
  manifest.json    source files + SHA-256 hashes + event counts (chain of custody)
  timeline.json    ordered timeline, clock offset, detected gaps
  findings.json    injection findings with linked actions + confidence
  report.html      human-readable, citation-verified report
```

---

## How it works

**Step 1 — collect.** One collector per log type maps a vendor-specific format into a single canonical event (`timestamp, source, session_id, actor, event_type, tool_name, content, trust, raw_ref, source_sha256`). Every event keeps a pointer back to its raw source file, hash, and line — the chain-of-custody backbone. Content the agent *pulled in from outside* (an email body, a fetched page) is tagged `untrusted`; only those are scanned later.

**Step 2 — timeline.** Merges all sources, sorts on one clock, and groups by session. It estimates **clock skew** between systems by matching the *same* action seen on two sides (the agent's `forward_email` call vs. the mail server's record) and flags **gaps**: a `tool_call` with no `tool_result` (possible content-logging gap) and sessions that appear in mail/identity logs but have **no agent trace at all**.

**Step 3 — scan.** On untrusted content only, it detects invisible/control characters (zero-width, bidi overrides, Unicode tag chars) and instruction patterns (override, stealth, exfiltration, …), then **links** each injection to the state-changing actions that follow it in the same session, scoring confidence higher when the action matches the injected intent.

**Step 4 — report.** Assembles the HTML report, **verifies** that every event ID cited by a finding exists in the evidence store (prints PASS/FAIL), and dedicates a section to what could **not** be established — so a reader never mistakes "we couldn't see it" for "it didn't happen."

---

## Testing & sample scenarios

`samples/generate_samples.py` builds a synthetic incident with **known ground truth**, so results can be graded:

| Session / signal | What it represents | Expected result |
|---|---|---|
| `S-CLEAN` | benign task, no injection, no action | **no finding** (false-positive test) |
| `S-EVIL` | hidden injection in an ingested email → forwards invoices externally | **HIGH** finding, action linked |
| `S-ORPHAN` | exists in mail + identity logs, no agent trace | reported as a **gap** |
| Clock skew | mail log +420s vs agent host | **detected** and reported |

Metrics worth reporting in a write-up: injection precision/recall, false-positive rate on benign sessions, clock-offset error, and citation-integrity pass rate.

---

## Limitations

- **Synthetic test data.** There is no industry-standard agent-trace format yet, so the bundled data is constructed. Real-data validation is on the roadmap.
- **Heuristic detection.** Injection detection uses patterns + hidden characters. A legitimate message containing an external address and an imperative can score LOW/MEDIUM — by design, it surfaces for a human to judge rather than asserting intent.
- **Analyses the recorded trace, not a re-execution.** Agent behaviour is non-deterministic, so re-running the agent is not a valid check; re-running these four steps on the same inputs is (same inputs → same hashes → same report).
- **Trust boundary only (for now).** AURA currently models injection-driven tool misuse. Sandbox/containment escapes need the collectors and detector on the roadmap.

---

## Roadmap / future improvements

#### 1. Validation on real data

#### 2. More agent scenarios (beyond the inbox agent)

#### 3. More evidence collectors

#### 4. Containment-boundary / sandbox-escape support

#### 5. Detection improvements
- [ ] Semantic / LLM-assisted injection detection beyond regex, with reproducibility guardrails (pinned model, hashed inputs, cited evidence).
- [ ] **Multilingual injection patterns (Arabic + others)** — most open-source filters are English-only, a real blind spot for Gulf organizations.
- [ ] Confidence calibration from labeled data.
- [ ] Detect ANSI/OSC escape-sequence smuggling and injection hidden in image metadata.

#### 6. Timeline & correlation
- [ ] **Apply** clock-offset alignment, not just report it; handle multiple/mixed time sources.
- [ ] Entity resolution: map app-id ↔ agent ↔ human operator across systems.

#### 7. Output & interoperability
- [ ] Normalize events to **OCSF / ECS** for SIEM ingestion.
- [ ] Export findings & IOCs as **STIX 2.1 / MISP**.
- [ ] Stronger custody: signed, write-once evidence store and a hash-chained manifest.
- [ ] PDF report export.

---

## Contributing

Contributions are welcome — new collectors, detectors, and test scenarios especially. Please open an issue to discuss substantial changes first. New evidence sources should emit the shared event schema (see Section 1 of `aura.py`); new detectors should attach cited evidence IDs and a confidence level so the report's verification stays meaningful.

---

## Author & references

**Author:** Tala Almulla — a digital-forensics project exploring forensics for AI-agent incidents.

**Reference incidents**
- EchoLeak — CVE-2025-32711, Microsoft 365 Copilot zero-click prompt injection (Aim Security, June 2025).
- *Disrupting the first reported AI-orchestrated cyber espionage campaign* — Anthropic Threat Intelligence, November 2025.
- OpenAI o1 System Card (2024) — Docker-daemon misconfiguration during CTF evaluation.
- OpenAI → Hugging Face sandbox-escape incident, July 2026.

> **Disclaimer:** AURA is a research/educational prototype. Test injection scenarios only in your own sandbox with fake data and accounts, and follow the law and your organization's rules when handling real evidence.
