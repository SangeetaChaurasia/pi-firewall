"""Find and decode obfuscated payloads (base64, hex, escapes, URL-encoding, ROT13, reversed)."""
from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass
from urllib.parse import unquote


@dataclass
class DecodedSpan:
    kind: str
    text: str
    span: tuple[int, int]


_B64 = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){10,}(?![0-9A-Fa-f])")
_HEX_ESC = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){6,}")
_UNI_ESC = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){6,}")
_TOKEN = re.compile(r"\S+")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")

_STRONG = re.compile(
    r"\b(?:ignore|instructions?|prompt|system|password|reveal|secret|override|disregard|credentials?)\b", re.I
)
_COMMON = re.compile(r"\b(?:the|and|you|your|all|previous|assistant|that|this|with)\b", re.I)

_MORSE_TABLE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G",
    "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N",
    "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U",
    "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}
_MORSE_SPAN = re.compile(r"(?:[.\-]{1,6}(?:\s*/\s*|\s+)){3,}[.\-]{1,6}")


def _try_morse(span_text: str) -> str | None:
    normalized = re.sub(r"\s*/\s*", " / ", span_text.strip())
    words = normalized.split(" / ")
    decoded_words = []
    for word in words:
        letters = [_MORSE_TABLE.get(tok) for tok in word.split() if tok]
        if not letters or any(l is None for l in letters):
            return None
        decoded_words.append("".join(letters))
    out = " ".join(decoded_words)
    return out if len(out) >= 4 else None


def _looks_like_text(s: str) -> bool:
    if len(s) < 8:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t\r")
    if printable / len(s) < 0.92:
        return False
    texty = sum(1 for c in s if c.isalpha() or c.isspace())
    return texty / len(s) >= 0.6


def _try_b64(token: str) -> str | None:
    s = token.strip("=").replace("-", "+").replace("_", "/")
    if len(s) % 4 == 1:
        return None
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)
        out = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return out if _looks_like_text(out) else None


def _keyword_variant(text: str, transform, kind: str) -> DecodedSpan | None:
    if len(text) < 20:
        return None
    variant = transform(text)
    if _STRONG.search(variant) and not _STRONG.search(text):
        if len(_COMMON.findall(variant)) > len(_COMMON.findall(text)):
            return DecodedSpan(kind, variant, (0, len(text)))
    return None


def decode_spans(text: str) -> list[DecodedSpan]:
    """Return decoded versions of suspicious encoded regions found inside `text`."""
    found: list[DecodedSpan] = []

    for m in _B64.finditer(text):
        out = _try_b64(m.group(0))
        if out:
            found.append(DecodedSpan("base64", out, m.span()))

    for m in _HEX.finditer(text):
        try:
            out = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(out):
            found.append(DecodedSpan("hex", out, m.span()))

    for m in _HEX_ESC.finditer(text):
        try:
            out = bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(out):
            found.append(DecodedSpan("hex_escape", out, m.span()))

    for m in _UNI_ESC.finditer(text):
        out = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda x: chr(int(x.group(1), 16)), m.group(0))
        if _looks_like_text(out):
            found.append(DecodedSpan("unicode_escape", out, m.span()))

    for m in _TOKEN.finditer(text):
        tok = m.group(0)
        if len(_PCT.findall(tok)) >= 4:
            out = unquote(tok)
            if out != tok and len(out) >= 12 and _looks_like_text(out):
                found.append(DecodedSpan("url_encoding", out, m.span()))

    for kind, fn in (("rot13", lambda t: codecs.decode(t, "rot_13")), ("reversed", lambda t: t[::-1])):
        d = _keyword_variant(text, fn, kind)
        if d:
            found.append(d)

    for m in _MORSE_SPAN.finditer(text):
        out = _try_morse(m.group(0))
        if out:
            found.append(DecodedSpan("morse", out, m.span()))

    return found
