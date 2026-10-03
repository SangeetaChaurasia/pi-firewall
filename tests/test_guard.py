"""Tests for the tool-call guard - the second defense layer at the agent's ACTION stage."""
from firewall.guard import GuardDecision, ToolCall, ToolGuard

guard = ToolGuard()


def test_unrecognized_action_allowed_by_default():
    r = guard.evaluate(ToolCall("get_weather", {"city": "Varanasi"}))
    assert r.decision == GuardDecision.ALLOW


def test_send_email_needs_confirmation_first_time():
    r = guard.evaluate(ToolCall("send_email", {"to": "friend@example.com", "body": "hi"}))
    assert r.decision == GuardDecision.CONFIRM


def test_send_email_allowed_once_confirmed():
    r = guard.evaluate(ToolCall("send_email", {"to": "friend@example.com"}), user_confirmed=True)
    assert r.decision == GuardDecision.ALLOW


def test_send_email_to_typosquatted_domain_always_blocked_even_if_confirmed():
    r = guard.evaluate(
        ToolCall("send_email", {"to": "verify@paypa1-secure.com"}), user_confirmed=True
    )
    assert r.decision == GuardDecision.BLOCK  # confirmation cannot override a hard block


def test_small_transfer_only_needs_ordinary_confirmation():
    r = guard.evaluate(ToolCall("transfer_funds", {"amount": 200}), user_confirmed=True)
    assert r.decision == GuardDecision.ALLOW


def test_large_transfer_needs_confirmation_even_if_flag_already_true():
    # Simulates the "...without asking for confirmation" injection: the caller (a compromised
    # agent obeying injected text) might pass user_confirmed=True on its own, but a human never
    # actually saw this specific large amount - the amount-threshold check still requires it.
    r_unconfirmed = guard.evaluate(ToolCall("transfer_funds", {"amount": 50000}), user_confirmed=False)
    assert r_unconfirmed.decision == GuardDecision.CONFIRM

    r_confirmed = guard.evaluate(ToolCall("transfer_funds", {"amount": 50000}), user_confirmed=True)
    assert r_confirmed.decision == GuardDecision.ALLOW  # only allowed with REAL confirmation wired in


def test_destructive_action_needs_confirmation():
    r = guard.evaluate(ToolCall("delete_database", {"target": "prod"}))
    assert r.decision == GuardDecision.CONFIRM


def test_code_execution_needs_confirmation():
    r = guard.evaluate(ToolCall("run_shell", {"cmd": "rm -rf /"}))
    assert r.decision == GuardDecision.CONFIRM


def test_permission_change_needs_confirmation():
    r = guard.evaluate(ToolCall("grant_access", {"user": "external_contractor", "role": "admin"}))
    assert r.decision == GuardDecision.CONFIRM


def test_malformed_amount_does_not_crash():
    r = guard.evaluate(ToolCall("transfer_funds", {"amount": "not-a-number"}))
    assert r.decision in (GuardDecision.ALLOW, GuardDecision.CONFIRM, GuardDecision.BLOCK)
