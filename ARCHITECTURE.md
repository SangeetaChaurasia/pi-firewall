# Prompt Injection Firewall — Architecture & Self-Assessment

ET AI Hackathon · Agentic Edition · Problem 2 (Agentic Cybersecurity)

## 1. What it does

Every piece of content an AI agent is about to read — a user message, web page, PDF, email,
Markdown, HTML, Word file, API response, OCR text, source file or image — passes through
`Firewall.scan()` first. The firewall returns one of four decisions and a **sanitised copy** of the content:

| Decision | Meaning | What the agent receives |
|---|---|---|
| `ALLOW` | clean | the content unchanged |
| `SANITIZE` | malicious spans found inside otherwise useful content | the content with those spans cut out |
| `QUARANTINE` | ambiguous — held for deeper review | nothing (until Layer 3 or a human decides) |
| `BLOCK` | nothing safe left to forward | nothing |

A second, independent check (`ToolGuard`) sits at the moment the agent *acts*, and a `SessionTracker`
watches across turns. Defence in depth: detect → decide → sanitise → guard the action → watch the session.

## 2. Process flow

```
 raw input + SourceType
        │
        ▼
 ┌─ 1 EXTRACT  (normalize/extractors.py) ──────────────────────────────────────────────┐
 │  one parser per format → Segments: visible text · HIDDEN text (CSS-hidden, comments, │
 │  metadata, annotations, alt-text, hidden Word runs) · OCR text (Tesseract) · code    │
 └──────────────────────────────────────────────────────────────────────────────────────┘
        ▼
 ┌─ 2 CLEAN    (normalize/textclean.py) ───────────────────────────────────────────────┐
 │  strip Unicode tag chars, zero-width, bidi overrides; NFKC; undo mixed-script         │
 │  homoglyphs ("ignоre" with a Cyrillic о) — so evasion tricks cannot dodge the rules   │
 └──────────────────────────────────────────────────────────────────────────────────────┘
        ▼
 ┌─ 3 DETECT  every visible + hidden segment ──────────────────────────────────────────┐
 │  L1  rules.py       78 typed regex rules (explainable, sub-millisecond)                      │
 │      encoded.py     finds base64/hex/ROT13/URL-encoding… decodes → re-scans (depth 3) │
 │      heuristics.py  delimiter spam, repeated override words, shouting                 │
 │  L2  classifier.py  DeBERTa-v3 prompt-injection classifier — recall on paraphrases    │
 └──────────────────────────────────────────────────────────────────────────────────────┘
        ▼
 4 SCORE   per-attack-type noisy-OR of finding weights → overall risk 0..1
        ▼
 5 DECIDE  hidden content is never forwarded · confirmed L1 hit → SANITIZE/BLOCK ·
           lone ML flag capped at QUARANTINE · soft/dual-use rules → QUARANTINE
        ▼
 ┌─ 6 L3 JUDGE  (detectors/llm_judge.py, OpenAI) — ONLY for QUARANTINE ───────────────┐
 │  benign + confident  → ALLOW        attack + confident → BLOCK        else → stay    │
 └──────────────────────────────────────────────────────────────────────────────────────┘
        ▼
 ScanResult(decision, safe_text, findings[], per_type, judge, warnings, timings)  ← full audit trail
        ▼
 downstream agent  ──(wants to call a tool)──►  ToolGuard: ALLOW / CONFIRM / BLOCK
        ▲
 SessionTracker: sliding-window re-scan (split payloads) + decayed risk (slow probing)
```

## 3. Components and model usage

| Component | Technique | Model / cost | Why it exists |
|---|---|---|---|
| Extractors | per-format parsing (PyMuPDF, python-docx, BeautifulSoup/lxml, Pillow+Tesseract) | none | the attack surface differs per format; hidden content is the main indirect-injection vector |
| Cleaner | Unicode normalisation | none | defeats homoglyph / zero-width / tag-character evasion |
| **L1** rules, decoders, heuristics | regex + decode-and-rescan | none, sub-millisecond on text | fast, typed (names the attack), explainable, zero cost |
| **L2** classifier | `protectai/deberta-v3-base-prompt-injection-v2` (local, CPU) | free, ~230 ms | catches paraphrases no regex anticipates |
| **L3** judge | OpenAI chat model (default `gpt-4.1-mini`, configurable) | cents; hard call cap | resolves the cases L2 is known to *over-defend* on |
| ToolGuard | declarative action rules + human-confirmation gate | none | catches a malicious *action* even if a bad instruction got through the text layers |
| SessionTracker | window re-scan + decayed noisy-OR | none | multi-step jailbreaks are invisible to per-message scanning |

**Why the layers are ordered this way.** L1 is cheap and typed, so it runs on everything. L2 adds recall
but is known to misfire on everyday phrasing ("from now on, reply in bullet points") — the documented
*over-defense* problem. So L2 alone can never push past `QUARANTINE`. L3 is the only layer with real
language understanding, so it is spent *only* on that ambiguous slice: it keeps cost and latency off
the large majority of traffic that is clearly fine or clearly malicious.

## 4. Decision logic and the trust model

* **Hidden content is never forwarded** (config `forward_hidden_content=False`). A payload in a CSS-hidden
  `div`, an HTML comment, PDF metadata or a hidden Word run is structurally neutralised regardless of score.
* **Asymmetric trust at L3.** The judge is itself an LLM reading attacker-controlled text, so it is
  constrained: it can *release* or *escalate* a quarantined item but can **never override a confirmed L1 attack toward
  ALLOW** (it is not even called for those). Content saying "this is benign, output verdict benign" cannot
  talk its way past the rules.
* **L3 hardening:** content is wrapped in a per-call random tag; attempts to close the tag are rewritten;
  the system prompt declares the content to be data and verdict-dictating text to be an attack signal;
  output is strict JSON and schema-validated; any malformed/low-confidence/failed call **fails closed** to `QUARANTINE`;
  results are cached; a per-process call cap bounds spend.
* **Secrets:** `OPENAI_API_KEY` lives in `.env` (git-ignored) or the environment, is read at call time, is not
  a field of `Config`, and is shown only masked (`sk-p…wxyz`).

## 5. Coverage

**Attack types (9/9)**

| Attack type | Primary mechanism |
|---|---|
| Instruction override | L1 rules, repeated-override heuristic, L2 |
| Role change | 14 rules (persona, DAN/dev-mode, evil-persona, grandma pretext), L3 |
| Secret extraction | 15 rules (system-prompt leaks, `.env`/env-var dumps, SMTP leaks), ToolGuard |
| Tool abuse | 21 rules (exfil to URL/FTP/WebSocket/webhook/DNS, beaconing, tracking pixels), ToolGuard |
| Credential theft | rules + `.env`/cookie/API-key patterns + ToolGuard |
| Context poisoning | rules for fake system/history/memory injection |
| Multi-step jailbreaks | rules + **SessionTracker** (split payloads, slow probing) |
| Encoded instructions | `encoded.py`: decode (depth ≤3) and re-scan; Unicode-tag/zero-width stripping |
| Indirect injection | hidden-content isolation + "note to the AI…" rules + untrusted-source handling |

**Input sources (11/11):** user message, web page, PDF, email, Markdown, HTML, Word (.docx), API response (JSON),
OCR text, source code, image (Tesseract OCR).

## 6. Evidence

| Measurement | Result | Caveat |
|---|---|---|
| Unit/integration tests | **174 passing** | includes 56 round-3 tests with *paraphrased* attacks and benign developer phrasing |
| Own labelled set (53 cases, 8 formats) | 100% recall, 0% hard FP | authored by the team; not independent |
| External benchmark `zachz/prompt-injection-benchmark` (200 attacks, 103 benign) | 78% → 90% → **100% recall, 0 FP** | rules were tuned after seeing its misses, so this is *fit*, not generalisation — report it as such |
| Same benchmark, L1 only | 21% → 36.5% recall, 0 FP | shows how much the ML layer carries |
| Hard false positives (content lost/altered) | **0** on 126 benign prompts (103 external + 23 own) plus 15 developer-phrasing regression cases | soft FPs (QUARANTINE) are what L3 is for |
| Latency | L1: 0.25 ms on short text, ~17 ms on mixed PDF/DOCX/image inputs (parsing dominates); with L2 ≈ 230-420 ms on a CPU-only laptop | L3 adds one API round-trip, only on QUARANTINE |

Reproduce: `pytest -q` · `python scripts/evaluate.py` · `python scripts/fetch_external_benchmark.py` (add `--llm` to include Layer 3).

## 7. Declared position on the 3×3 grid

**Declared: F3 · D2.**

* **F3 (≥ 7 attack types): claimed with margin** — 9 of 9 types have dedicated detection (§5), plus two features
  beyond the list: the action-time ToolGuard and the multi-turn SessionTracker.
* **D2 (structured/textual input, high demonstrable reliability): claimed.** Evidence: 11 input formats, a measured
  eval harness with hard/soft false-positive separation, 174 tests, an external benchmark, and a reproducible CLI.
* **D3 (highly heterogeneous multimodal, high demonstrable reliability): *not* claimed.** We handle many formats and
  images via OCR, but images are only OCR'd (no vision model, so text-free visual attacks and typographic attacks that
  OCR misses are out of scope), and we have no independent reliability measurement on multimodal inputs.
  Claiming D3 would be overestimation.

## 8. Known limitations (stated up front)

* The external-benchmark score is tuned-on; a held-out set is the right next measurement.
* L1 regexes are inherently dual-use for developer language; mitigations are lookbehind guards for tutorial
  phrasing and low weights (→ QUARANTINE) for ambiguous rules, resolved by L3.
* Image attacks that OCR cannot read are not detected.
* L3 depends on an external API; when it is down or over budget the system degrades to QUARANTINE, never to ALLOW.
