from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CHANGE = "role_change"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    CREDENTIAL_THEFT = "credential_theft"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"
    ENCODED_INSTRUCTION = "encoded_instruction"
    INDIRECT_INJECTION = "indirect_injection"


class SourceType(str, Enum):
    USER_MESSAGE = "user_message"
    WEB_PAGE = "web_page"
    PDF = "pdf"
    EMAIL = "email"
    MARKDOWN = "markdown"
    HTML = "html"
    DOCX = "docx"
    API_RESPONSE = "api_response"
    OCR_TEXT = "ocr_text"
    SOURCE_CODE = "source_code"
    IMAGE = "image"

    @property
    def trusted(self) -> bool:
        """Only the user's own typed message is treated as (relatively) trusted."""
        return self is SourceType.USER_MESSAGE


class Decision(str, Enum):
    ALLOW = "allow"            # forward safe_text as-is
    SANITIZE = "sanitize"      # forward safe_text (malicious spans removed)
    QUARANTINE = "quarantine"  # hold; needs deeper analysis (L2/L3) or human review
    BLOCK = "block"            # forward nothing


@dataclass
class Segment:
    """A piece of extracted content plus where it came from."""
    text: str
    origin: str = "visible"
    hidden: bool = False          # present in the model's input but not visible to a human
    scan: bool = True             # False = kept for output only (e.g. whole source file)
    root: Optional[int] = None    # index of the segment this one was derived from
    root_span: Optional[tuple[int, int]] = None  # where in the root's text it came from
    depth: int = 0
    decoded: bool = False         # produced by decoding an obfuscated payload
    output: bool = True           # False = detection-only "view" of a parent segment; do not
                                   # emit separately (findings map back onto the parent instead)


@dataclass
class Finding:
    attack_type: AttackType
    rule_id: str
    weight: float
    segment_index: int
    span: tuple[int, int]
    matched: str
    origin: str
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type.value,
            "rule_id": self.rule_id,
            "weight": round(self.weight, 3),
            "origin": self.origin,
            "matched": self.matched,
            "description": self.description,
        }


@dataclass
class ScanResult:
    source: SourceType
    decision: Decision
    score: float
    per_type: dict[str, float]
    findings: list[Finding]
    safe_text: str
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    segments_seen: int = 0
    hidden_segments_dropped: int = 0
    elapsed_ms: float = 0.0
    judge: Optional[dict] = None   # Layer-3 verdict + what it changed (None if L3 did not run)

    @property
    def forward(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.SANITIZE)

    @property
    def attack_types(self) -> list[str]:
        return sorted({f.attack_type.value for f in self.findings})

    def to_dict(self) -> dict:
        return {
            "source": self.source.value,
            "decision": self.decision.value,
            "forward": self.forward,
            "score": round(self.score, 3),
            "per_type": {k: round(v, 3) for k, v in self.per_type.items()},
            "attack_types": self.attack_types,
            "findings": [f.to_dict() for f in self.findings],
            "warnings": self.warnings,
            "stats": self.stats,
            "segments_seen": self.segments_seen,
            "hidden_segments_dropped": self.hidden_segments_dropped,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "judge": self.judge,
        }
