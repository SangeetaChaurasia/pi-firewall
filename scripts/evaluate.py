"""Evaluation harness: runs the firewall against data/eval/cases.py and reports
precision, recall and false-positive rate — the evidence for the D2 "demonstrable
reliability" claim in the hackathon submission.

Usage:
    python scripts/evaluate.py                # text report
    python scripts/evaluate.py --json out.json
"""
import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from data.eval.cases import CASES
from firewall import Decision, Firewall
from firewall.config import Config
from firewall.models import SourceType


def run(config: Config | None = None, cases=None):
    cases = CASES if cases is None else cases
    fw = Firewall(config)
    rows = []
    # Warm up the ML classifier (if enabled) so its one-time model-load time doesn't pollute
    # the per-scan latency numbers below - that's a fixed startup cost, not steady-state latency.
    fw.scan("warmup", SourceType.USER_MESSAGE)

    for case in cases:
        data, filename = case.build()
        t0 = time.perf_counter()
        result = fw.scan(data, case.source, filename=filename)
        elapsed = (time.perf_counter() - t0) * 1000

        flagged = result.decision != Decision.ALLOW
        is_attack = case.label == "attack"
        correct_flag = flagged == is_attack
        type_hit = (not is_attack) or any(t in result.attack_types for t in case.expected_types) or not case.expected_types

        preview = data[:160] if isinstance(data, str) else "[binary content]"

        rows.append({
            "id": case.id, "format": case.source.value, "label": case.label,
            "expected_types": case.expected_types, "decision": result.decision.value,
            "found_types": result.attack_types, "flagged": flagged,
            "correct_flag": correct_flag, "type_hit": type_hit, "score": result.score,
            "elapsed_ms": round(elapsed, 2), "text_preview": preview,
            "findings": [f.to_dict() for f in result.findings],  # for debugging misses/FPs
            "judge_action": (result.judge or {}).get("action"),
        })
    return rows


def summarize(rows):
    attacks = [r for r in rows if r["label"] == "attack"]
    benign = [r for r in rows if r["label"] == "benign"]

    tp = sum(1 for r in attacks if r["flagged"])
    fn = sum(1 for r in attacks if not r["flagged"])
    fp = sum(1 for r in benign if r["flagged"])
    tn = sum(1 for r in benign if not r["flagged"])
    type_correct = sum(1 for r in attacks if r["flagged"] and r["type_hit"])

    # Not all false positives are equal: QUARANTINE just holds a message for a second look
    # (nothing is lost, nothing reaches the model unreviewed) - BLOCK/SANITIZE on benign
    # content is the actually costly mistake (content destroyed or altered outright).
    fp_hard = sum(1 for r in benign if r["decision"] in ("block", "sanitize"))
    fp_soft = sum(1 for r in benign if r["decision"] == "quarantine")

    recall = tp / len(attacks) if attacks else float("nan")
    fpr = fp / len(benign) if benign else float("nan")
    fpr_hard = fp_hard / len(benign) if benign else float("nan")
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    type_accuracy = type_correct / tp if tp else float("nan")

    by_format = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for r in rows:
        bucket = by_format[r["format"]]
        if r["label"] == "attack":
            bucket["tp" if r["flagged"] else "fn"] += 1
        else:
            bucket["fp" if r["flagged"] else "tn"] += 1

    avg_ms = sum(r["elapsed_ms"] for r in rows) / len(rows) if rows else 0.0

    return {
        "n_cases": len(rows), "n_attacks": len(attacks), "n_benign": len(benign),
        "true_positives": tp, "false_negatives": fn, "false_positives": fp, "true_negatives": tn,
        "false_positives_hard_block_or_sanitize": fp_hard,
        "false_positives_soft_quarantine_only": fp_soft,
        "recall": recall, "precision": precision, "false_positive_rate": fpr,
        "false_positive_rate_hard_only": fpr_hard,
        "attack_type_accuracy_given_flagged": type_accuracy,
        "by_format": dict(by_format), "avg_scan_ms": round(avg_ms, 2),
    }


def print_report(rows, summary):
    print(f"\n{'='*70}\nPROMPT INJECTION FIREWALL — EVALUATION REPORT\n{'='*70}")
    print(f"Cases: {summary['n_cases']}  (attacks: {summary['n_attacks']}, benign: {summary['n_benign']})")
    print(f"\nRecall (attacks correctly flagged):        {summary['recall']:.1%}")
    print(f"Precision (flags that were real attacks):  {summary['precision']:.1%}")
    print(f"False positive rate (any non-ALLOW):        {summary['false_positive_rate']:.1%}")
    print(f"  - of which HARD (block/sanitize) on benign content: {summary['false_positive_rate_hard_only']:.1%} "
          f"({summary['false_positives_hard_block_or_sanitize']} case(s) - content actually lost/altered)")
    print(f"  - of which SOFT (quarantine only) on benign content: "
          f"{summary['false_positives_soft_quarantine_only']} case(s) - held for review, nothing lost")
    print(f"Attack-type accuracy (when flagged):        {summary['attack_type_accuracy_given_flagged']:.1%}")
    print(f"Avg scan time: {summary['avg_scan_ms']} ms")

    j = [r for r in rows if r.get("judge_action")]
    if j:
        from collections import Counter
        c = Counter(r["judge_action"] for r in j)
        print(f"\nLayer 3 (LLM judge) was consulted on {len(j)} ambiguous case(s): "
              + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
        wrong = [r["id"] for r in j if r["judge_action"] == "released_to_allow" and r["label"] == "attack"]
        if wrong:
            print(f"  !! judge wrongly RELEASED attack case(s): {wrong}")

    print(f"\n{'Format':<15}{'TP':>5}{'FN':>5}{'FP':>5}{'TN':>5}   Recall   FPR")
    for fmt, b in sorted(summary["by_format"].items()):
        n_atk = b["tp"] + b["fn"]
        n_ben = b["fp"] + b["tn"]
        rec = f"{b['tp']/n_atk:.0%}" if n_atk else "  -"
        fpr = f"{b['fp']/n_ben:.0%}" if n_ben else "  -"
        print(f"{fmt:<15}{b['tp']:>5}{b['fn']:>5}{b['fp']:>5}{b['tn']:>5}   {rec:>6}   {fpr:>4}")

    misses = [r for r in rows if r["label"] == "attack" and not r["flagged"]]
    fps = [r for r in rows if r["label"] == "benign" and r["flagged"]]
    if misses:
        print(f"\n--- Missed attacks ({len(misses)}) ---")
        for r in misses[:30]:
            print(f"  {r['id']} ({r['format']}): {r['text_preview']!r}")
        if len(misses) > 30:
            print(f"  ... and {len(misses) - 30} more (see --json output for the full list)")
    if fps:
        print(f"\n--- False positives ({len(fps)}) ---")
        for r in fps:
            print(f"  {r['id']} ({r['format']}) -> {r['decision']}: {r['text_preview']!r}")
            for f in r["findings"]:
                print(f"      [{f['weight']:.2f}] {f['rule_id']:<16} {f['attack_type']:<20} {f['matched']!r}")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="also write the full report to this JSON path")
    ap.add_argument("--no-ml", action="store_true", help="disable the Layer-2 ML classifier for this run")
    ap.add_argument("--llm", action="store_true",
                    help="enable Layer 3 (OpenAI judge; needs OPENAI_API_KEY in .env). Off by default so an "
                         "evaluation run never spends money unless you ask.")
    args = ap.parse_args()

    config = Config.from_env(ml_enabled=not args.no_ml, llm_judge_enabled=args.llm)
    rows = run(config)
    summary = summarize(rows)
    print_report(rows, summary)

    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "cases": rows}, indent=2))
        print(f"Full report written to {args.json}")


if __name__ == "__main__":
    main()
