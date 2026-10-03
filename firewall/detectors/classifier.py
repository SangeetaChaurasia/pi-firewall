"""Layer 2: an ML classifier as a second opinion alongside the Layer 1 regex rules.

Design goals:
- Optional and resilient: if torch/transformers aren't installed, or the model hasn't
  been downloaded yet (no internet), the firewall must still work on Layer 1 alone.
  We never let this layer crash the pipeline.
- The classifier gives a single "this looks like an injection" probability, with no
  attack-type breakdown. We use it to catch attacks Layer 1's regex missed (recall),
  not to replace Layer 1's typed findings.
"""
from __future__ import annotations

import threading

_lock = threading.Lock()
_state = {"pipeline": None, "attempted": False, "error": None}


def _load(model_name: str, device: str):
    """Lazy-load the HF pipeline exactly once per process."""
    with _lock:
        if _state["attempted"]:
            return _state["pipeline"], _state["error"]
        _state["attempted"] = True
        try:
            import torch  # noqa: F401
            from transformers import (AutoModelForSequenceClassification,
                                       AutoTokenizer, pipeline)

            tok = AutoTokenizer.from_pretrained(model_name, use_fast=False)
            model = AutoModelForSequenceClassification.from_pretrained(model_name)
            clf = pipeline(
                "text-classification", model=model, tokenizer=tok,
                truncation=True, max_length=512, device=device,
            )
            _state["pipeline"] = clf
        except Exception as e:  # ImportError, OSError (no internet / gated), etc.
            _state["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        return _state["pipeline"], _state["error"]


def is_available(model_name: str, device: str = "cpu") -> bool:
    clf, _ = _load(model_name, device)
    return clf is not None


def classify(text: str, model_name: str, device: str = "cpu", max_chars: int = 4000) -> tuple[float | None, str | None]:
    """Returns (injection_probability, error). probability is None if the layer is unavailable."""
    clf, err = _load(model_name, device)
    if clf is None:
        return None, err or "ml_classifier_unavailable"
    if not text.strip():
        return 0.0, None
    try:
        out = clf(text[:max_chars])[0]
        label = str(out["label"]).upper()
        score = float(out["score"])
        # Different model cards use different label spellings; normalize to "is this an attack".
        if any(k in label for k in ("INJECTION", "JAILBREAK", "LABEL_1", "MALICIOUS", "UNSAFE")):
            return score, None
        return 1.0 - score, None
    except Exception as e:  # pragma: no cover - defensive; a bad model output must not crash the app
        return None, f"ml_inference_failed: {type(e).__name__}: {str(e)[:150]}"
