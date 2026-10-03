"""Tool-call guard: a second, independent defense layer that sits between the AI agent's
DECISION to call a tool and the tool actually executing.

Why this is separate from the text firewall (pipeline.py):
- The text firewall protects the PERCEIVE stage - it stops malicious instructions from
  reaching the model's context in the first place.
- This guard protects the ACT stage - even if a malicious instruction somehow gets
  through (a new attack pattern, a bug, a Layer 1/2 miss), the agent still can't
  silently wire $50,000 or email your contacts without a human explicitly saying yes.
- Crucially: `user_confirmed` must be wired to a REAL human confirmation click/prompt
  in your actual agent UI. It must never be settable by the LLM itself, or by content
  the LLM read. This is exactly what defeats the classic "...without asking for
  confirmation" injection technique: the confirmation gate is enforced structurally,
  outside the model's control, not merely obeyed-or-ignored as an instruction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class GuardDecision(str, Enum):
    ALLOW = "allow"      # safe to execute
    CONFIRM = "confirm"  # must get explicit human confirmation first
    BLOCK = "block"       # never execute, regardless of confirmation


@dataclass
class ToolCall:
    name: str
    args: dict = field(default_factory=dict)


@dataclass
class ActionRule:
    id: str
    name_pattern: re.Pattern
    description: str
    requires_confirmation: bool = True
    max_numeric_args: dict = field(default_factory=dict)          # arg_name -> max allowed value
    blocked_value_patterns: dict = field(default_factory=dict)    # arg_name -> [regex, ...]


@dataclass
class GuardResult:
    decision: GuardDecision
    matched_rule: str | None
    reasons: list[str]

    def to_dict(self) -> dict:
        return {"decision": self.decision.value, "matched_rule": self.matched_rule, "reasons": self.reasons}


def _num(raw) -> float | None:
    try:
        return float(str(raw).replace(",", "").replace("$", "").replace("₹", "").strip())
    except (TypeError, ValueError):
        return None


DEFAULT_RULES: list[ActionRule] = [
    ActionRule(
        "guard_email", re.compile(r"send_?email|forward_?email|share_?(contact|data)", re.I),
        "Sends data outside the system - possible exfiltration channel",
        blocked_value_patterns={"to": [
            r"paypa1|micr0soft|goog1e|arnaz0n|app1e",           # typosquatted domains
            r"^\s*$",                                            # empty recipient
        ]},
    ),
    ActionRule(
        "guard_money", re.compile(r"transfer|wire|pay|withdraw", re.I),
        "Moves money - high-impact, hard to reverse",
        max_numeric_args={"amount": 1000},
    ),
    ActionRule(
        "guard_destructive", re.compile(r"delete|drop|wipe|remove_all|truncate", re.I),
        "Destructive/irreversible action",
    ),
    ActionRule(
        "guard_exec", re.compile(r"execute|run_shell|eval|exec|subprocess", re.I),
        "Arbitrary code/command execution",
    ),
    ActionRule(
        "guard_access", re.compile(r"revoke|grant_access|change_permission|reset_password|add_admin", re.I),
        "Security or permission change",
    ),
]


class ToolGuard:
    """Evaluates a proposed tool call against a policy of sensitive-action rules."""

    def __init__(self, rules: list[ActionRule] | None = None):
        self.rules = rules or DEFAULT_RULES

    def evaluate(self, call: ToolCall, user_confirmed: bool = False) -> GuardResult:
        rule = next((r for r in self.rules if r.name_pattern.search(call.name)), None)
        if rule is None:
            return GuardResult(GuardDecision.ALLOW, None, ["no sensitive-action rule matched; allowed by default"])

        # 1. Hard blocks - no confirmation can override these.
        for arg_name, patterns in rule.blocked_value_patterns.items():
            value = str(call.args.get(arg_name, ""))
            for pat in patterns:
                if re.search(pat, value, re.I):
                    return GuardResult(GuardDecision.BLOCK, rule.id,
                        [f"{rule.description}: arg '{arg_name}'={value!r} matched a blocked pattern"])

        # 2. Numeric thresholds - exceeding one always needs a fresh, explicit confirmation,
        #    even if the caller claims prior confirmation, since the amount itself is the risk.
        for arg_name, limit in rule.max_numeric_args.items():
            value = _num(call.args.get(arg_name))
            if value is not None and value > limit:
                if user_confirmed:
                    return GuardResult(GuardDecision.ALLOW, rule.id,
                        [f"{rule.description}: '{arg_name}'={value} exceeds {limit} but was explicitly confirmed"])
                return GuardResult(GuardDecision.CONFIRM, rule.id,
                    [f"{rule.description}: '{arg_name}'={value} exceeds the {limit} auto-approval limit"])

        # 3. Ordinary sensitive action - needs confirmation once, unless already given.
        if rule.requires_confirmation and not user_confirmed:
            return GuardResult(GuardDecision.CONFIRM, rule.id, [f"{rule.description}: requires user confirmation"])

        return GuardResult(GuardDecision.ALLOW, rule.id, [f"{rule.description}: confirmed, no policy violation"])
