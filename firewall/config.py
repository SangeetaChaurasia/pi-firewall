"""Tunable policy for the firewall. Change values here, not in the logic."""
from dataclasses import dataclass
import os


@dataclass
class Config:
    # Decision thresholds on the overall risk score (0..1)
    block_threshold: float = 0.85
    sanitize_threshold: float = 0.55
    quarantine_threshold: float = 0.30

    # Findings inside content a human cannot see (hidden text, metadata) get a small boost
    hidden_boost: float = 0.10

    # Safe default: hidden / non-visible content is NEVER forwarded to the model.
    forward_hidden_content: bool = False

    # Only findings at or above this weight are cut out during SANITIZE
    redact_min_weight: float = 0.45
    redaction_marker: str = "[REMOVED: suspected prompt injection]"

    # Safety limits
    max_input_chars: int = 1_000_000
    max_derived_segments: int = 60
    max_decode_depth: int = 3
    min_hidden_chars: int = 8  # ignore tiny hidden strings such as alt="logo"

    # --- Layer 2: ML classifier (optional second opinion, see detectors/classifier.py) ---
    ml_enabled: bool = True
    # Swap to "protectai/deberta-v3-small-prompt-injection-v2" if the base model is too
    # slow on your machine (smaller/faster, slightly less accurate).
    ml_model_name: str = "protectai/deberta-v3-base-prompt-injection-v2"
    ml_device: str = "cpu"
    ml_score_threshold: float = 0.55   # below this, we don't even raise a finding
    ml_max_chars: int = 4000           # truncate long segments before classifying (speed)
    ml_weight_cap: float = 0.9         # never let the ML layer alone reach BLOCK on its own

    # --- Layer 3: LLM judge (OpenAI) - resolves the ambiguous QUARANTINE cases -------------
    # OFF by default so tests / library users never spend money by accident. `Config.from_env()`
    # turns it on automatically when OPENAI_API_KEY is present (see .env.example).
    # The API key itself is deliberately NOT a field here: it is read from the environment at
    # call time and never stored on an object that gets printed, logged or serialised.
    llm_judge_enabled: bool = False
    llm_judge_model: str = "gpt-4.1-mini"   # override with OPENAI_MODEL, e.g. gpt-5.4-nano
    llm_judge_clear_conf: float = 0.75      # judge must be this sure a quarantined item is benign to release it
    llm_judge_block_conf: float = 0.75      # ...and this sure it is an attack to upgrade QUARANTINE -> BLOCK
    llm_judge_max_chars: int = 6000         # content sent to the judge is truncated to this
    llm_judge_max_calls: int = 300          # hard spend cap per Firewall instance
    llm_judge_timeout_s: float = 20.0

    @classmethod
    def from_env(cls, **overrides) -> "Config":
        """Build a Config from `.env` / environment variables, then apply keyword overrides.

        PIF_LLM_JUDGE   auto (default: on iff OPENAI_API_KEY is set) | on | off
        OPENAI_MODEL    judge model name
        PIF_LLM_MAX_CALLS   spend cap per process
        PIF_ML_ENABLED  true/false for the Layer-2 DeBERTa classifier
        PIF_ML_MODEL    HF model id for Layer 2
        """
        from .env import has_openai_key, load_env
        load_env()
        mode = os.environ.get("PIF_LLM_JUDGE", "auto").strip().lower()
        judge_on = has_openai_key() if mode == "auto" else mode in ("1", "true", "on", "yes")
        cfg = cls(llm_judge_enabled=judge_on)
        if os.environ.get("OPENAI_MODEL", "").strip():
            cfg.llm_judge_model = os.environ["OPENAI_MODEL"].strip()
        if os.environ.get("PIF_LLM_MAX_CALLS", "").strip().isdigit():
            cfg.llm_judge_max_calls = int(os.environ["PIF_LLM_MAX_CALLS"])
        if os.environ.get("PIF_ML_ENABLED", "").strip():
            cfg.ml_enabled = os.environ["PIF_ML_ENABLED"].strip().lower() in ("1", "true", "on", "yes")
        if os.environ.get("PIF_ML_MODEL", "").strip():
            cfg.ml_model_name = os.environ["PIF_ML_MODEL"].strip()
        for k, v in overrides.items():
            setattr(cfg, k, v)
        return cfg
