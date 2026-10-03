# What We Used, and Why

Prompt Injection Firewall — ET AI Hackathon: Agentic Edition, Problem 2.
Companion to [`ARCHITECTURE.md`](../ARCHITECTURE.md) (design) and [`command.md`](../command.md) (how to run it).

---

## 1. At a glance

| Concern | What we used | Why this and not something else |
|---|---|---|
| Language | **Python** (developed/tested on 3.12; 3.10+ recommended) | Every library we needed (PDF, DOCX, OCR, ML, LLM SDK, UI) has first-class Python support; one language across detectors, scripts, tests and UI |
| Fast, explainable detection | **Regex rules + decoders + heuristics** (Layer 1) | Sub-millisecond, zero cost, and every flag names its rule and attack type — judges and security teams can *audit* a decision |
| Paraphrase recall | **DeBERTa-v3 prompt-injection classifier** (Layer 2, local) | Regexes cannot anticipate paraphrases; a local model adds recall with no per-call cost and no data leaving the machine |
| Ambiguity resolution | **OpenAI chat model** (Layer 3, default `gpt-4.1-mini`) | The only layer with real language understanding, so it is spent *only* on the ambiguous slice Layer 2 over-defends on |
| Document parsing | **PyMuPDF, python-docx, BeautifulSoup + lxml, Pillow + Tesseract** | Each gives access to *hidden* content (see §2), which is the main indirect-injection vector |
| Demo UI | **Streamlit** | A working interactive demo in one file, no front-end build step |
| Testing | **pytest** | Table-driven attack/benign cases; the suite doubles as the regression harness for every rule change |
| Secrets/config | **Own tiny `.env` loader** | No extra dependency to fail on a judge's machine; the key is never stored on a config object |

---

## 2. Libraries

| Package | Role in the project | Why chosen |
|---|---|---|
| `pymupdf` | PDF text, white-on-white text, tiny-font text, annotations, metadata | Exposes per-span colour and font size, which is what lets us detect *invisible* text; fast, no system dependency |
| `python-docx` | Word text, **hidden runs**, comments, document properties | Direct access to run formatting (`font.hidden`) and core properties where injections hide |
| `beautifulsoup4` + `lxml` | HTML/web pages, e-mail HTML parts | Robust on messy real-world HTML; lets us find `display:none`, zero-size and off-screen text, comments, meta tags, alt text |
| `pillow` + `pytesseract` (+ the **Tesseract OCR** program) | Image and OCR input; two OCR passes (plain and contrast-boosted) | Satisfies "images via OCR" from the brief; no paid vision API required |
| `torch` (CPU build) + `transformers` | Runs the Layer-2 classifier locally | CPU-only wheels run on an ordinary laptop; no GPU needed |
| `datasets` | Downloads the external benchmark from Hugging Face | Reproducible external validation; an offline CSV copy ships in `data/external/` |
| `openai` | Layer-3 judge and the real-LLM victim agent in the demo | Official SDK; timeouts and retries built in |
| `streamlit` | Four-tab demo (Try it, Agent demo, Tool-call guard, Multi-turn session) | Fastest route to a demonstrable, intuitive prototype |
| `pytest` | 172 automated tests | Standard; parametrised cases keep attack/benign lists readable |
| Python stdlib (`re`, `unicodedata`, `base64`, `binascii`, `codecs`, `hashlib`, `secrets`, `email`, `dataclasses`, `argparse`, `csv`) | Detection engine, decoding, hashing/caching, e-mail parsing, CLI | Keeps the core dependency-light and easy to audit |

**Deliberately not used:** `python-dotenv` (a 40-line loader avoids one more dependency), LangChain/LlamaIndex
(the firewall is a library that sits *in front of* any agent framework; coupling it to one would limit it),
a vector database (nothing to retrieve — this is classification, not RAG).

---

## 3. Models

| Layer | Model | Runs | Cost | Role |
|---|---|---|---|---|
| L2 | `protectai/deberta-v3-base-prompt-injection-v2` (Hugging Face) | locally, CPU | free; ~230–420 ms per scan on a laptop CPU | Paraphrase recall. Capped at QUARANTINE on its own, because on its own it over-defends ("from now on, reply in bullet points") |
| L3 | OpenAI `gpt-4.1-mini` by default (`OPENAI_MODEL` to change; `gpt-5.4-nano` is a cheaper option) | OpenAI API | cents per hundred calls; hard cap `PIF_LLM_MAX_CALLS` | Judges only QUARANTINE cases; can release a benign one or escalate an attack; fails closed |
| Demo agent | same OpenAI model | OpenAI API | negligible | A *real* victim agent holding a canary secret, so the before/after demo is objective (substring check) |

Why a two-model ladder instead of one: Layer 2 is free but blunt; Layer 3 is smart but costs money and time.
Putting the expensive model behind the cheap one means almost every request is handled at no cost, and the
LLM only sees the small ambiguous remainder.

> Before submitting, open each model card/licence page (the DeBERTa model and the benchmark dataset) and confirm
> the terms allow your use and what attribution they require.

---

## 4. Data and evaluation

| Asset | What it is | Use |
|---|---|---|
| `data/eval/cases.py` | 53 hand-built cases across 8 input formats (PDF, DOCX, HTML, e-mail, Markdown, JSON, code, image), attacks and benign | Format-level reliability; hard vs. soft false-positive split |
| `zachz/prompt-injection-benchmark` (Hugging Face; copy at `data/external/zachz_pib.csv`) | 303 rows: 200 injections, 103 benign | Independent-ish check; **our rules were tuned after seeing its misses, so report it as tuned-on** |
| `tests/` | 172 pytest cases incl. paraphrased attacks and benign developer phrasing | Regression safety net |
| `demo_assets/` (`scripts/make_demo_assets.py`) | 9 attack files + 3 clean controls, regenerated on demand | The video demo and a quick end-to-end smoke test |

Metrics we report: recall, precision, false-positive rate split into **hard** (content altered or lost) and
**soft** (held for review, nothing lost), attack-type accuracy, and scan latency.

---

## 5. Key design decisions (and the alternatives we rejected)

| Decision | Rejected alternative | Reason |
|---|---|---|
| Layered pipeline: rules → ML → LLM | LLM on every input | An LLM per request is slow and costly, and is itself injectable. We use it narrowly and constrain it |
| Hidden content is never forwarded | Score it like visible text | A CSS-hidden or white-on-white instruction has no legitimate reader; removing it is safer than judging it |
| Per-format extractors | Flatten everything to text first | Flattening destroys exactly the signals (colour, size, visibility, metadata) that reveal hiding |
| Decode-and-rescan (base64, hex, ROT13, URL, reversed, Morse; depth ≤ 3) | Ignore encodings | Encoded instructions are one of the nine required attack types |
| Asymmetric trust at Layer 3 | Let the LLM override anything | The judge can release or escalate a *quarantined* item; it can never override a confirmed rule hit, so injected text saying "this is benign" cannot win |
| Fail closed | Fail open on API errors | An outage, a bad JSON reply or an exhausted budget leaves content in QUARANTINE, never ALLOW |
| Sanitise instead of only block | Block the whole document | Remove the malicious span and let the legitimate content through — "minimal disruption", as the brief asks |
| Separate `ToolGuard` | Rely on text detection alone | If a bad instruction slips through, a transfer, e-mail or shell call still has to pass an action-time policy and human confirmation |
| `SessionTracker` | Per-message only | Split payloads and slow probing are invisible message-by-message |

---

## 6. How this maps to the judging criteria

| Criterion (from the problem pack) | Where we address it |
|---|---|
| Significance and relevance | Indirect injection is the practical attack on agents that read web pages, files and e-mail |
| Innovation and originality | Hidden-content isolation, decode-and-rescan, asymmetric-trust LLM judge, multi-turn tracker, action-time guard |
| Effective use of AI | Local classifier for recall + LLM judge for ambiguity; AI is central but bounded, not bolted on |
| Technical complexity and execution | 11 format extractors, 78 rules, 3 detection layers, 172 tests, reproducible evaluation |
| Agentic / autonomous capability | Tool-call guard and session tracking operate on an agent's actions and conversation |
| Business / user impact | Stops data leaks and unauthorised actions; sanitising keeps legitimate content flowing |
| Prototype quality and usability | Streamlit app, CLI, generated demo files, one-command checks |
| Scalability, responsible AI, robustness | Fail-closed design, spend cap, key masking, truncation, caching; limitations stated openly |

---

## 7. Disclosures

* **Pre-trained model used:** the DeBERTa prompt-injection classifier above (Hugging Face).
* **External API:** OpenAI, only when Layer 3 is on. Only the *visible text of ambiguous items* (truncated to
  6,000 characters) leaves the machine. For production, use an enterprise endpoint with zero data retention,
  or swap Layer 3 for a local model.
* **Third-party dataset:** `zachz/prompt-injection-benchmark`, used for evaluation only.
* **AI-assisted development:** parts of this project were built with assistance from Claude (Anthropic).
  Keep or remove this line according to the hackathon's rules on AI-assisted work.
