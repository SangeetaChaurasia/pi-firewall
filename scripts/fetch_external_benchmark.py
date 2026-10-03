"""Runs the firewall against an INDEPENDENT, externally-authored benchmark
(zachz/prompt-injection-benchmark on Hugging Face: 200 attacks across 7 categories,
plus 100 benign prompts) using the same evaluation harness as scripts/evaluate.py.

Why this matters: data/eval/cases.py was built by us, so a perfect score there proves
the pipeline works, not that it generalizes. This script closes that gap by scoring
against a test set we didn't write and didn't tune the rules against.

Needs internet access to huggingface.co - this couldn't be verified from the sandbox
that built this project (see README), so run it yourself and share the output.

Usage:
    pip install datasets
    python scripts/fetch_external_benchmark.py
    python scripts/fetch_external_benchmark.py --no-ml
"""
import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from firewall.config import Config
from firewall.models import SourceType
from scripts.evaluate import print_report, run, summarize

DATASET_NAME = "zachz/prompt-injection-benchmark"

# The dataset's exact column names weren't verifiable from the sandbox that wrote this
# script (no internet access there). These are reasonable guesses based on common
# conventions for this kind of dataset - if loading fails or everything ends up on one
# side (all-attack or all-benign), print_columns() below will show you what's actually
# in it so you can adjust PROMPT_COLUMNS / LABEL_COLUMNS / BENIGN_LABEL_VALUES.
PROMPT_COLUMNS = ["prompt", "text", "input", "sentence", "content"]
LABEL_COLUMNS = ["label", "category", "type", "class", "is_injection"]
BENIGN_LABEL_VALUES = {"benign", "safe", "0", "none", "false", "no", "legit", "legitimate"}


@dataclass
class ExternalCase:
    id: str
    source: SourceType
    label: str
    build: Callable
    expected_types: list


def _first_present(row: dict, candidates: list[str]) -> str | None:
    for c in candidates:
        if c in row and row[c] is not None:
            return c
    return None


def print_columns(dataset):
    split = next(iter(dataset.values()))
    print("Could not confidently detect prompt/label columns. Available columns:")
    print(f"  {list(split.features.keys())}")
    print(f"  Example row: {split[0]}")
    print("\nEdit PROMPT_COLUMNS / LABEL_COLUMNS / BENIGN_LABEL_VALUES at the top of this "
          "script to match, then re-run.")


DEFAULT_LOCAL_CSV = Path(__file__).resolve().parent.parent / "data" / "external" / "zachz_pib.csv"


def _load_split(csv_path: str | None):
    """Return a list of row dicts. Uses a local CSV when given (offline), else HF `datasets`."""
    if csv_path:
        import csv
        with open(csv_path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f)), None
    from datasets import load_dataset
    ds = load_dataset(DATASET_NAME)
    split = ds["train"] if "train" in ds else next(iter(ds.values()))
    return list(split), ds


def load_external_cases(csv_path: str | None = None) -> list[ExternalCase]:
    split, ds = _load_split(csv_path)

    prompt_col = _first_present(split[0], PROMPT_COLUMNS)
    # Prefer the dataset's real `label` column (injection|benign) over `category`.
    label_col = _first_present(split[0], LABEL_COLUMNS)
    if prompt_col is None:
        if ds is not None:
            print_columns(ds)
        raise SystemExit(1)

    cases = []
    for i, row in enumerate(split):
        text = row[prompt_col]
        if label_col is not None:
            is_benign = str(row[label_col]).strip().lower() in BENIGN_LABEL_VALUES
        else:
            # Some releases of this kind of dataset split attacks/benign into separate
            # configs rather than a label column - if label_col is None, everything will
            # land on one side, which is your signal to check the dataset structure
            # manually (`load_dataset(DATASET_NAME)` in a REPL) and adjust this script.
            is_benign = False
        cases.append(ExternalCase(
            id=f"ext_{i}", source=SourceType.USER_MESSAGE,
            label="benign" if is_benign else "attack",
            build=(lambda t=text: (t, None)),
            expected_types=[],  # external categories don't map 1:1 to our 9 types
        ))
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--llm", action="store_true", help="enable Layer 3 (OpenAI judge, needs OPENAI_API_KEY in .env)")
    ap.add_argument("--csv", nargs="?", const=str(DEFAULT_LOCAL_CSV), default=None,
                    help="load from a local CSV instead of Hugging Face (default path: "
                         "data/external/zachz_pib.csv)")
    args = ap.parse_args()

    print(f"Loading {DATASET_NAME} ..." if not args.csv else f"Loading local CSV {args.csv} ...")
    cases = load_external_cases(args.csv)
    n_attack = sum(1 for c in cases if c.label == "attack")
    n_benign = sum(1 for c in cases if c.label == "benign")
    print(f"Loaded {len(cases)} cases ({n_attack} attack, {n_benign} benign)")
    if n_attack == 0 or n_benign == 0:
        print("WARNING: all cases landed on one side - the label column was probably "
              "misdetected. Check PROMPT_COLUMNS/LABEL_COLUMNS at the top of this file.")

    rows = run(Config.from_env(ml_enabled=not args.no_ml, llm_judge_enabled=args.llm), cases=cases)
    summary = summarize(rows)
    print_report(rows, summary)


if __name__ == "__main__":
    main()
