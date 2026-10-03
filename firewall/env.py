"""Tiny, dependency-free `.env` loader (so a missing python-dotenv can never break the firewall).

Rules:
- Real environment variables always win over the file (`override=False`), so CI / a shell
  `set OPENAI_API_KEY=...` beats a stale .env.
- The loader returns only the NAMES of variables it set, never their values, so nothing
  secret ends up in logs or the UI by accident.
- Handles what Windows editors produce: UTF-8 BOM, CRLF, `export KEY=...`, quotes, inline comments.
"""
from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_loaded_from: Path | None = None


def _parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.lower().startswith("export "):
        line = line[7:].lstrip()
    if "=" not in line:
        return None
    key, _, value = line.partition("=")
    key, value = key.strip(), value.strip()
    if not key or not (key[0].isalpha() or key[0] == "_") or not all(c.isalnum() or c == "_" for c in key):
        return None
    if value[:1] in ("'", '"'):
        quote = value[0]
        end = value.find(quote, 1)
        value = value[1:end] if end != -1 else value[1:]
        if quote == '"':
            value = value.replace("\\n", "\n").replace('\\"', '"')
    else:
        # unquoted: an inline comment starts at " #"
        hash_at = value.find(" #")
        if hash_at != -1:
            value = value[:hash_at]
        value = value.strip()
    return key, value


def load_env(path: str | os.PathLike | None = None, override: bool = False) -> list[str]:
    """Load KEY=VALUE pairs from a .env file into os.environ. Returns the names that were set."""
    global _loaded_from
    candidates = [Path(path)] if path else [Path.cwd() / ".env", PROJECT_ROOT / ".env"]
    for p in candidates:
        if p.is_file():
            break
    else:
        return []
    set_keys: list[str] = []
    for raw in p.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        parsed = _parse_line(raw)
        if not parsed:
            continue
        k, v = parsed
        if override or k not in os.environ:
            os.environ[k] = v
            set_keys.append(k)
    _loaded_from = p
    return set_keys


def loaded_from() -> Path | None:
    return _loaded_from


def has_openai_key() -> bool:
    k = os.environ.get("OPENAI_API_KEY", "").strip()
    return bool(k) and not k.lower().startswith(("your", "sk-xxxx", "<"))


def mask_secret(value: str | None) -> str:
    """'sk-proj-abc...wxyz' -> 'sk-p…wxyz' - safe to show in a UI or log."""
    if not value:
        return "(not set)"
    value = value.strip()
    return f"{value[:4]}…{value[-4:]}" if len(value) > 12 else "****"
