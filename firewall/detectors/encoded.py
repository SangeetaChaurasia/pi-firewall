"""Wraps the decoder module: turns decoded spans into Findings by re-scanning them with L1 rules."""
from __future__ import annotations

from ..models import AttackType, Finding
from ..normalize.decoders import decode_spans
from .rules import scan_rules


def scan_encoded(text: str, segment_index: int, origin: str) -> tuple[list[Finding], list[str]]:
    """Look for encoded payloads in `text`; decode them and scan the decoded text for attacks.
    Always raises an ENCODED_INSTRUCTION finding for the encoding itself, plus whatever the
    decoded content matches.
    """
    findings: list[Finding] = []
    decoded_texts: list[str] = []
    for d in decode_spans(text):
        seen_rules: set[str] = set()
        decoded_texts.append(d.text)
        base_weight = 0.35 if d.kind in ("base64", "hex", "hex_escape", "unicode_escape", "url_encoding", "morse") else 0.25
        findings.append(Finding(
            AttackType.ENCODED_INSTRUCTION, f"enc_{d.kind}", base_weight,
            segment_index, d.span, text[d.span[0]:d.span[1]][:80], origin,
            f"Suspicious {d.kind} payload decodes to plausible instruction text",
        ))
        for rule, m in scan_rules(d.text):
            seen_rules.add(rule.id)
            findings.append(Finding(
                rule.attack_type, f"{rule.id}+{d.kind}", min(rule.weight + 0.1, 0.95),
                segment_index, d.span, d.text[m.start():m.end()][:80], f"{origin} (decoded:{d.kind})",
                f"{rule.description} [found only after decoding {d.kind}]",
            ))
        # Also re-scan the payload decoded IN PLACE: "\x69\x67...\x20 instructions" only reads as an
        # attack once the decoded words sit next to the plain text around them. Only matches that
        # touch the decoded part count; plain-text matches are the normal scan's job.
        start, end = d.span
        pre, post = text[max(0, start - 200):start], text[end:end + 200]
        spliced = pre + d.text + post
        lo, hi = len(pre), len(pre) + len(d.text)
        for rule, m in scan_rules(spliced):
            if rule.id in seen_rules or m.end() <= lo or m.start() >= hi:
                continue
            seen_rules.add(rule.id)
            findings.append(Finding(
                rule.attack_type, f"{rule.id}+{d.kind}", min(rule.weight + 0.1, 0.95),
                segment_index, d.span, spliced[m.start():m.end()][:80], f"{origin} (decoded:{d.kind}, in context)",
                f"{rule.description} [found only after decoding {d.kind} in place]",
            ))
    return findings, decoded_texts
