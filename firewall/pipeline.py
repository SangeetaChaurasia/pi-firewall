"""Firewall.scan(): the single entry point. Orchestrates normalize -> detect -> decide."""
from __future__ import annotations

import time

from .config import Config
from .detectors import classifier as ml_classifier
from .detectors.encoded import scan_encoded
from .detectors.heuristics import scan_heuristics
from .detectors.llm_judge import LLMJudge
from .detectors.rules import scan_rules
from .models import AttackType, Decision, Finding, ScanResult, Segment, SourceType
from .normalize.extractors import extract
from .normalize.textclean import clean_text


class Firewall:
    def __init__(self, config: Config | None = None, judge: LLMJudge | None = None):
        self.config = config or Config()
        self._judge = judge  # injectable for tests; otherwise built lazily from config + OPENAI_API_KEY

    def _get_judge(self) -> LLMJudge:
        if self._judge is None:
            c = self.config
            self._judge = LLMJudge(c.llm_judge_model, c.llm_judge_max_chars, c.llm_judge_max_calls,
                                   c.llm_judge_timeout_s)
        return self._judge

    # ------------------------------------------------------------------ public
    def scan(self, data: str | bytes, source: SourceType, filename: str | None = None) -> ScanResult:
        t0 = time.perf_counter()
        cfg = self.config
        warnings: list[str] = []

        if isinstance(data, (str, bytes)) and len(data) > cfg.max_input_chars:
            warnings.append(f"input truncated to {cfg.max_input_chars} chars")
            data = data[: cfg.max_input_chars]

        try:
            segments, extract_warnings = extract(data, source, filename)
        except Exception as e:  # never let a parser crash take the whole app down
            segments, extract_warnings = [], [f"extraction_failed: {type(e).__name__}: {str(e)[:150]}"]
        warnings += extract_warnings

        segments = segments[: cfg.max_derived_segments]
        segments, clean_stats = self._clean_all(segments)

        findings: list[Finding] = []
        i = 0
        ml_warned = False
        while i < len(segments):
            seg = segments[i]
            if seg.scan and seg.text.strip():
                seg_findings = self._scan_segment(seg, i, cfg)
                findings += seg_findings
                if seg.depth < cfg.max_decode_depth:
                    decoded_findings, decoded_texts = scan_encoded(seg.text, i, seg.origin)
                    findings += decoded_findings
                    for dtext in decoded_texts:
                        segments.append(Segment(
                            dtext, f"{seg.origin}(decoded)", hidden=seg.hidden, scan=True,
                            root=i, decoded=True, depth=seg.depth + 1,
                        ))
                if cfg.ml_enabled:
                    ml_finding, ml_error = self._ml_scan(seg, i, cfg, already_flagged=bool(seg_findings))
                    if ml_finding:
                        findings.append(ml_finding)
                    if ml_error and not ml_warned:
                        warnings.append(f"ml_classifier: {ml_error}")
                        ml_warned = True
            i += 1

        hidden_dropped = sum(1 for s in segments if s.hidden)
        safe_text, decision = self._build_output(segments, findings, cfg)

        # Layer 3: only for items the earlier layers left AMBIGUOUS (QUARANTINE).
        judge_info = None
        if decision == Decision.QUARANTINE and cfg.llm_judge_enabled:
            decision, safe_text, judge_info, judge_findings = self._apply_judge(
                segments, findings, source, cfg, warnings)
            findings += judge_findings
        per_type, score = self._score(findings, segments, cfg, visible_only=False)

        result = ScanResult(
            source=source, decision=decision, score=score, per_type=per_type,
            findings=sorted(findings, key=lambda f: -f.weight), safe_text=safe_text,
            warnings=warnings, stats=clean_stats, segments_seen=len(segments),
            hidden_segments_dropped=hidden_dropped if not cfg.forward_hidden_content else 0,
            elapsed_ms=(time.perf_counter() - t0) * 1000, judge=judge_info,
        )
        return result

    # ------------------------------------------------------------------ internals
    def _clean_all(self, segments: list[Segment]) -> tuple[list[Segment], dict]:
        stats: dict[str, int] = {}
        for seg in segments:
            r = clean_text(seg.text)
            seg.text = r.text
            for k, v in r.stats.items():
                stats[k] = stats.get(k, 0) + v
            for origin, extra in r.extras:
                segments.append(Segment(extra, origin, hidden=True, root=segments.index(seg)))
        return segments, stats

    def _apply_judge(self, segments, findings, source, cfg, warnings):
        """Layer 3 resolution of a QUARANTINE decision. Returns (decision, safe_text, info, new_findings).

        Trust is asymmetric on purpose. We reach this point only when NO finding of weight >=
        redact_min_weight exists (otherwise the decision would already be SANITIZE/BLOCK), so
        every signal here is soft: a lone ML flag or a low-weight dual-use rule. The judge may
        therefore:
          * release the item  (benign, high confidence)  -> ALLOW, forwarding the visible text
          * escalate the item (attack, high confidence)  -> BLOCK, nothing forwarded
          * or say nothing useful / fail                 -> stays QUARANTINE (fail closed)
        It can never downgrade a confirmed attack, so text inside the content that says
        "this is benign" cannot talk its way past the rules.
        """
        visible = "\n\n".join(
            s.text for s in segments if s.output and not s.hidden and not s.decoded and s.text.strip())
        hints = sorted({f"{f.rule_id}({f.weight:.2f})" for f in findings})
        judge = self._get_judge()
        v = judge.judge(visible, source.value, hints)
        info = {"layer": 3, **v.to_dict(), "calls_used": judge.calls, "action": "kept_quarantine"}

        if v.error:
            warnings.append(f"llm_judge: {v.error}")
            return Decision.QUARANTINE, "", info, []
        if v.verdict == "benign" and v.confidence >= cfg.llm_judge_clear_conf:
            info["action"] = "released_to_allow"
            return Decision.ALLOW, visible, info, []
        if v.verdict == "attack" and v.confidence >= cfg.llm_judge_block_conf:
            info["action"] = "escalated_to_block"
            from .models import AttackType as _AT
            f = Finding(_AT(v.attack_type or "instruction_override"), "llm_judge", min(v.confidence, 0.95),
                        0, (0, min(len(visible), 80)), visible[:80], "llm_judge",
                        f"LLM judge ({v.model}) classified quarantined content as an attack: {v.reason}")
            return Decision.BLOCK, "", info, [f]
        return Decision.QUARANTINE, "", info, []

    def _ml_scan(self, seg: Segment, idx: int, cfg: Config, already_flagged: bool) -> tuple[Finding | None, str | None]:
        """Layer 2: ask the ML classifier for a second opinion on this segment.
        Only raises a finding if Layer 1 found nothing AND the model is confident — this
        layer exists to catch attacks the regex rules missed, not to duplicate them.
        """
        prob, error = ml_classifier.classify(seg.text, cfg.ml_model_name, cfg.ml_device, cfg.ml_max_chars)
        if prob is None:
            return None, error
        if already_flagged or prob < cfg.ml_score_threshold:
            return None, None
        weight = min(prob, cfg.ml_weight_cap) + (cfg.hidden_boost if seg.hidden else 0.0)
        return Finding(
            AttackType.INSTRUCTION_OVERRIDE, "ml_classifier", min(weight, cfg.ml_weight_cap),
            idx, (0, min(len(seg.text), 80)), seg.text[:80], seg.origin,
            f"ML classifier ({cfg.ml_model_name}) flagged this as likely prompt injection "
            f"(p={prob:.2f}) though no Layer-1 rule matched; sub-type unclassified so it is "
            f"conservatively bucketed as instruction_override.",
        ), None

    def _scan_segment(self, seg: Segment, idx: int, cfg: Config) -> list[Finding]:
        found: list[Finding] = []
        for rule, m in scan_rules(seg.text):
            weight = rule.weight + (cfg.hidden_boost if seg.hidden else 0.0)
            found.append(Finding(
                rule.attack_type, rule.id, min(weight, 0.98), idx, m.span(),
                seg.text[m.start():m.end()][:80], seg.origin, rule.description,
            ))
        found += scan_heuristics(seg.text, idx, seg.origin)
        return found

    def _score(self, findings: list[Finding], segments: list[Segment], cfg: Config, visible_only: bool, exclude_ml_only: bool = False):
        per_type: dict[str, float] = {}
        for f in findings:
            if visible_only and f.segment_index < len(segments) and segments[f.segment_index].hidden:
                continue
            if exclude_ml_only and f.rule_id == "ml_classifier":
                continue
            cur = per_type.get(f.attack_type.value, 0.0)
            # combine multiple hits on the same type with diminishing returns (noisy-OR)
            per_type[f.attack_type.value] = 1 - (1 - cur) * (1 - f.weight)
        overall = 0.0
        for v in per_type.values():
            overall = 1 - (1 - overall) * (1 - v)
        return per_type, overall

    def _resolve(self, segments: list[Segment], seg_idx: int, span: tuple[int, int]) -> tuple[int, tuple[int, int]]:
        """Map a finding's (segment, span) onto the nearest ancestor segment that is actually
        emitted in the output, translating character offsets along the way (one hop today,
        but written to walk further if extractors ever nest deeper)."""
        seen = set()
        while seg_idx not in seen and not segments[seg_idx].output and segments[seg_idx].root is not None:
            seen.add(seg_idx)
            seg = segments[seg_idx]
            base = seg.root_span[0] if seg.root_span else 0
            span = (base + span[0], base + span[1])
            seg_idx = seg.root
        return seg_idx, span

    def _build_output(self, segments: list[Segment], findings: list[Finding], cfg: Config):
        # 1. Which segments actually get concatenated into the model-facing text.
        emit_idx = [
            i for i, s in enumerate(segments)
            if s.output and not s.hidden and not s.decoded
        ]

        # 2. Map every finding onto an emitted segment (or drop it, if it lives only inside
        #    hidden/decoded content that never reaches the output anyway). Kept in two views:
        #    "confirmed" (a Layer-1 rule/heuristic fired) drives BLOCK/SANITIZE on its own.
        #    ML-only findings (rule_id == "ml_classifier") get folded in for redaction once a
        #    decision is already made, but never DRIVE that decision past QUARANTINE by
        #    themselves — a lone ML signal has no confirmed attack sub-type and is known to
        #    misfire on everyday phrasing ("ignore the stain on my shirt"), so it's treated as
        #    "worth a second look" rather than "confirmed attack".
        by_seg_all: dict[int, list[tuple[int, int]]] = {}
        by_seg_confirmed: dict[int, list[tuple[int, int]]] = {}
        for f in findings:
            if f.segment_index >= len(segments):
                continue
            idx, span = self._resolve(segments, f.segment_index, f.span)
            if idx not in emit_idx or f.weight < cfg.redact_min_weight:
                continue
            by_seg_all.setdefault(idx, []).append(span)
            if f.rule_id != "ml_classifier":
                by_seg_confirmed.setdefault(idx, []).append(span)

        has_hidden_finding = any(
            f.segment_index < len(segments) and segments[f.segment_index].hidden and f.weight >= cfg.redact_min_weight
            for f in findings
        )
        _, score_confirmed = self._score(findings, segments, cfg, visible_only=True, exclude_ml_only=True)
        _, score_all = self._score(findings, segments, cfg, visible_only=True, exclude_ml_only=False)

        # 3. Tentatively redact every CONFIRMED flagged span and see how much real content
        #    would be left. This is what decides BLOCK vs SANITIZE: if redacting the
        #    confirmed-malicious parts leaves nothing meaningful, there's nothing safe to
        #    forward. (ML-only spans don't count toward this ratio — they aren't confirmed.)
        total_len, remaining_len = 0, 0
        for idx in emit_idx:
            text = segments[idx].text
            total_len += len(text.strip())
            spans = sorted(set(by_seg_confirmed.get(idx, [])), key=lambda s: s[0])
            cleaned = self._redact(text, spans, cfg.redaction_marker) if spans else text
            remaining_len += len(cleaned.replace(cfg.redaction_marker, "").strip())

        removed_ratio = 1.0 - (remaining_len / total_len) if total_len else 0.0

        if score_confirmed >= cfg.block_threshold and (removed_ratio > 0.6 or total_len == 0):
            decision = Decision.BLOCK
        elif score_confirmed >= cfg.sanitize_threshold or has_hidden_finding or any(by_seg_confirmed.values()):
            decision = Decision.SANITIZE
        elif score_confirmed >= cfg.quarantine_threshold or score_all >= cfg.quarantine_threshold:
            decision = Decision.QUARANTINE
        else:
            decision = Decision.ALLOW

        if decision == Decision.BLOCK:
            safe_text = ""
        elif decision == Decision.QUARANTINE:
            safe_text = ""  # ambiguous whole-message risk; held back for deeper review (L3/human)
        elif decision == Decision.SANITIZE:
            # Redact using ALL flagged spans (confirmed + ml-only) now that we're already
            # sanitizing — no reason to leave an ML-flagged span untouched once we're cleaning.
            parts = []
            for idx in emit_idx:
                text = segments[idx].text
                spans = sorted(set(by_seg_all.get(idx, [])), key=lambda s: s[0])
                parts.append(self._redact(text, spans, cfg.redaction_marker) if spans else text)
            safe_text = "\n\n".join(p for p in parts if p.strip())
        else:
            safe_text = "\n\n".join(segments[i].text for i in emit_idx if segments[i].text.strip())
        return safe_text, decision

    @staticmethod
    def _redact(text: str, spans: list[tuple[int, int]], marker: str) -> str:
        merged: list[list[int]] = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        out, last = [], 0
        for s, e in merged:
            out.append(text[last:s])
            out.append(marker)
            last = e
        out.append(text[last:])
        return "".join(out)
