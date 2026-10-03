"""Character-level normalisation: undo invisible / look-alike tricks.

Handles: Unicode tag characters ("ASCII smuggling"), zero-width chars, bidi controls,
NFKC compatibility forms (full-width letters etc.), and mixed-script homoglyph words.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

_ZW_ANY = re.compile("[\u200b\u2060\ufeff\u00ad\u180e]")
_ZW_JOINERS_BETWEEN_ASCII = re.compile("(?<=[A-Za-z0-9])[\u200c\u200d]+(?=[A-Za-z0-9])")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_TAGS = re.compile("[\U000e0000-\U000e007f]+")
_CTRL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MULTISPACE = re.compile(r"[ \t]{2,}")
_WORD = re.compile(r"\w+", re.UNICODE)

_CYR = "\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u0455\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0406"
_CYR_TO = "aeopcxyijsABEKMHOPCTXI"
_GRK = "\u03bf\u03b1\u03b5\u03bd\u03c1\u03c4\u03c5\u03b9\u03ba\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7"
_GRK_TO = "oaevptuikABEZHIKMNOPTYX"
_HOMOGLYPHS = {ord(c): t for c, t in zip(_CYR + _GRK, _CYR_TO + _GRK_TO)}


@dataclass
class CleanResult:
    text: str
    stats: dict[str, int] = field(default_factory=dict)
    extras: list[tuple[str, str]] = field(default_factory=list)  # (origin, hidden text found)


def _bump(stats: dict[str, int], key: str, n: int = 1) -> None:
    if n:
        stats[key] = stats.get(key, 0) + n


def clean_text(text: str) -> CleanResult:
    stats: dict[str, int] = {}
    extras: list[tuple[str, str]] = []

    # 1) Unicode tag characters can smuggle a full hidden ASCII message.
    def _decode_tags(m: re.Match) -> str:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0xE0020 <= ord(c) <= 0xE007E)
        if decoded:
            extras.append(("decoded:unicode_tags", decoded))
        _bump(stats, "unicode_tag_chars", len(m.group(0)))
        return ""

    text = _TAGS.sub(_decode_tags, text)

    # 2) Zero-width / invisible characters (joiners kept when part of emoji sequences)
    n = len(_ZW_ANY.findall(text)) + len(_ZW_JOINERS_BETWEEN_ASCII.findall(text))
    if n:
        _bump(stats, "zero_width_chars", n)
        text = _ZW_ANY.sub("", text)
        text = _ZW_JOINERS_BETWEEN_ASCII.sub("", text)

    # 3) Bidirectional override characters
    n = len(_BIDI.findall(text))
    if n:
        _bump(stats, "bidi_controls", n)
        text = _BIDI.sub("", text)

    # 4) Compatibility normalisation (full-width letters, ligatures, ...)
    text = unicodedata.normalize("NFKC", text)

    # 5) Mixed-script words like "ign<Cyrillic o>re" -> "ignore"
    def _fix_word(m: re.Match) -> str:
        w = m.group(0)
        has_confusable = any(ord(c) in _HOMOGLYPHS for c in w)
        has_latin = any(("a" <= c <= "z") or ("A" <= c <= "Z") for c in w)
        if has_confusable and has_latin:
            _bump(stats, "mixed_script_words")
            return w.translate(_HOMOGLYPHS)
        return w

    text = _WORD.sub(_fix_word, text)

    # 6) Stray control characters and whitespace runs
    text = _CTRL.sub(" ", text)
    text = _MULTISPACE.sub(" ", text)
    return CleanResult(text=text, stats=stats, extras=extras)
