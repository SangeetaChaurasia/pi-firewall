"""Multi-turn session tracker: catches multi-step jailbreaks that no single message reveals.

Per-message scanning has two blind spots an attacker can exploit:
  1. SPLIT PAYLOAD  - "ignore all previous" in turn 1, "instructions and ..." in turn 2.
     Defence: besides scanning the new turn alone, scan the sliding window of the last N turns
     joined together; if the window is worse than the turn, the turn is the completing fragment.
  2. SLOW PROBING   - many individually-mild attempts (each QUARANTINE-ish) that never cross a
     threshold alone. Defence: a time-decayed noisy-OR of per-turn risk scores; if it stays high
     across several suspicious turns the session is escalated.
Neither check ever *lowers* a decision, so wrapping a Firewall in a SessionTracker is strictly
safer than using it bare.
"""
from __future__ import annotations

import dataclasses
from collections import deque
from dataclasses import dataclass, field

from .models import Decision, ScanResult, SourceType
from .pipeline import Firewall

_SEVERITY = {Decision.ALLOW: 0, Decision.QUARANTINE: 1, Decision.SANITIZE: 2, Decision.BLOCK: 3}


@dataclass
class SessionResult:
    result: ScanResult                  # the decision that APPLIES to this turn
    turn_result: ScanResult             # what the turn scored on its own
    window_result: ScanResult | None    # what the last-N-turns window scored (None on turn 1)
    escalated: bool = False
    reason: str = ""
    session_risk: float = 0.0
    suspicious_turns: int = 0
    turn_number: int = 0

    def to_dict(self) -> dict:
        return {"turn": self.turn_number, "decision": self.result.decision.value, "escalated": self.escalated,
                "reason": self.reason, "session_risk": round(self.session_risk, 3),
                "suspicious_turns": self.suspicious_turns, "turn_decision": self.turn_result.decision.value,
                "window_decision": self.window_result.decision.value if self.window_result else None}


class SessionTracker:
    def __init__(self, firewall: Firewall | None = None, window: int = 4, decay: float = 0.75,
                 risk_threshold: float = 0.7, min_suspicious_turns: int = 3, max_history: int = 50):
        self.fw = firewall or Firewall()
        self.window = window
        self.decay = decay
        self.risk_threshold = risk_threshold
        self.min_suspicious_turns = min_suspicious_turns
        self.turns: deque[str] = deque(maxlen=max_history)
        self.scores: deque[float] = deque(maxlen=max_history)
        self.flags: deque[bool] = deque(maxlen=max_history)
        self.count = 0

    def reset(self) -> None:
        self.turns.clear(); self.scores.clear(); self.flags.clear(); self.count = 0

    def _session_risk(self) -> float:
        risk, w = 0.0, 1.0
        for s in reversed(self.scores):          # newest first, older turns count for less
            risk = 1 - (1 - risk) * (1 - s * w)
            w *= self.decay
        return risk

    def scan(self, text: str, source: SourceType = SourceType.USER_MESSAGE) -> SessionResult:
        self.count += 1
        turn = self.fw.scan(text, source)
        self.turns.append(text)
        self.scores.append(turn.score if turn.decision != Decision.ALLOW else 0.0)
        self.flags.append(turn.decision != Decision.ALLOW)

        window_res = None
        final, reason = turn, ""
        if len(self.turns) >= 2:
            recent = list(self.turns)[-self.window:]
            window_res = self.fw.scan(" ".join(recent), source)
            # SPLIT PAYLOAD: this turn looked clean on its own, yet the window got WORSE because of it.
            # "Worse than the window without this turn" is the key test - otherwise a clean message
            # sent after earlier flagged ones would be punished for history it did not create.
            if turn.decision == Decision.ALLOW and _SEVERITY[window_res.decision] >= _SEVERITY[Decision.QUARANTINE]:
                prev = self.fw.scan(" ".join(recent[:-1]), source) if len(recent) >= 2 else None
                prev_sev = _SEVERITY[prev.decision] if prev else 0
                if _SEVERITY[window_res.decision] > prev_sev:
                    new_dec = Decision.BLOCK if _SEVERITY[window_res.decision] >= 2 else Decision.QUARANTINE
                    final = dataclasses.replace(turn, decision=new_dec, safe_text="",
                                                score=max(turn.score, window_res.score),
                                                findings=window_res.findings, per_type=window_res.per_type)
                    reason = (f"split payload: this turn is harmless alone but completes an attack with the "
                              f"previous {len(recent) - 1} turn(s) ({window_res.decision.value.upper()})")

        # SLOW PROBING: repeated flagged turns with high decayed risk. Applies to a turn that is
        # itself flagged; a clean follow-up message from the same user is never punished for history.
        risk = self._session_risk()
        recent_flags = sum(list(self.flags)[-self.window:])
        if (not reason and turn.decision == Decision.QUARANTINE and risk >= self.risk_threshold
                and recent_flags >= self.min_suspicious_turns):
            final = dataclasses.replace(turn, decision=Decision.BLOCK, safe_text="")
            reason = (f"repeated probing: {recent_flags} flagged turns in the last {self.window} "
                      f"(session risk {risk:.2f}) - ambiguous turn escalated QUARANTINE -> BLOCK")

        return SessionResult(final, turn, window_res, escalated=bool(reason), reason=reason,
                             session_risk=risk, suspicious_turns=recent_flags, turn_number=self.count)
