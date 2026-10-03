"""Structural / statistical heuristics that a single regex can't express well."""
from __future__ import annotations

import re

from ..models import AttackType, Finding

_DELIMITER_SPAM = re.compile(r"(?:[-=#*_]{4,}\s*){3,}")
_REPEATED_IGNORE = re.compile(r"\b(?:ignore|disregard|override)\b", re.I)
_URGENCY = re.compile(r"\b(?:urgent|immediately|right\s+now|do\s+not\s+delay|act\s+now|before\s+it'?s\s+too\s+late)\b", re.I)
_IMPERATIVE_TO_AI = re.compile(
    r"\b(?:you\s+must|you\s+have\s+to|you\s+need\s+to|it\s+is\s+(?:mandatory|required)\s+that\s+you)\b", re.I
)


def scan_heuristics(text: str, segment_index: int, origin: str) -> list[Finding]:
    findings: list[Finding] = []

    if len(_REPEATED_IGNORE.findall(text)) >= 3:
        findings.append(Finding(
            AttackType.INSTRUCTION_OVERRIDE, "heur_repeated_override_words", 0.4,
            segment_index, (0, min(len(text), 40)), "(repeated override keywords)", origin,
            "Multiple override-style keywords repeated, suggesting adversarial emphasis",
        ))

    if _DELIMITER_SPAM.search(text):
        findings.append(Finding(
            AttackType.CONTEXT_POISONING, "heur_delimiter_spam", 0.3,
            segment_index, (0, min(len(text), 40)), "(delimiter spam)", origin,
            "Repeated fake section delimiters, often used to fake a new context/system block",
        ))

    caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
    if len(caps_words) >= 6 and (_URGENCY.search(text) or _IMPERATIVE_TO_AI.search(text)):
        findings.append(Finding(
            AttackType.INSTRUCTION_OVERRIDE, "heur_shouting_urgency", 0.25,
            segment_index, (0, min(len(text), 40)), "(shouted urgency + imperatives)", origin,
            "Heavy capitalisation combined with urgency/imperative language directed at the AI",
        ))

    return findings
