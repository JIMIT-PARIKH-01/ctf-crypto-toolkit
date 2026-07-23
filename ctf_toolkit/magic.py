"""
"Magic" auto-decoder: throw a blob at it and it tries many decodings, scores
each result by how text-like / flag-like it looks, and returns the best guesses.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass

from . import ciphers

# Matches common CTF flag shapes: flag{...}, CTF{...}, picoCTF{...}, HTB{...}
FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,15}\{[^}\n]{2,}\}")
_PRINTABLE = set(string.printable)
_COMMON = set(" etaoinshrdlucmfEATHISON")   # frequent English letters


@dataclass
class Candidate:
    method: str
    output: str
    score: float

    def preview(self, width: int = 70) -> str:
        text = self.output.replace("\n", "\\n")
        return text if len(text) <= width else text[:width] + "…"


def score_text(text: str) -> float:
    """Higher = more likely to be meaningful decoded text."""
    if not text:
        return 0.0
    printable = sum(1 for c in text if c in _PRINTABLE)
    ratio = printable / len(text)
    score = ratio * 100
    if ratio < 0.85:                       # mostly binary garbage
        return score * 0.3
    if FLAG_RE.search(text):               # looks like a flag -> big boost
        score += 250
    common = sum(1 for c in text if c in _COMMON)
    score += (common / len(text)) * 30     # English-ish bonus
    if text.count(" ") and ratio > 0.95:
        score += 10
    return score


def magic(data: str, top: int = 8, deep: bool = True) -> list:
    """Try many decodings; return the top scoring Candidates, best first."""
    data = data.strip()
    seen = set()
    out: list = []

    def add(method: str, text: str) -> None:
        if text and text != data and text not in seen:
            seen.add(text)
            # Prefer the simplest explanation: penalise multi-step decodings so a
            # direct correct decode outranks a chained one that merely looks flag-like.
            penalty = 25 * method.count("+")
            out.append(Candidate(method, text, score_text(text) - penalty))

    # 1) every reversible codec's decode direction
    for name, (_enc, dec) in ciphers.CODECS.items():
        try:
            add(name, dec(data))
        except Exception:  # noqa: BLE001 - a codec that can't parse this input
            pass

    # 2) all Caesar shifts
    for n, text in ciphers.caesar_all(data).items():
        add(f"caesar/rot{n}", text)

    # 3) single-byte XOR brute force (only keep promising ones)
    try:
        raw = data.encode("utf-8", "replace")
        for k, text in ciphers.xor_single_all(raw).items():
            if score_text(text) > 90:
                add(f"xor/0x{k:02x}", text)
    except Exception:  # noqa: BLE001
        pass

    # 4) one shallow second pass: base64 -> (try codecs again) catches nesting
    if deep:
        try:
            once = ciphers.b64_decode(data)
            if once and once != data:
                for name, (_e, dec) in ciphers.CODECS.items():
                    try:
                        add(f"base64+{name}", dec(once))
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass

    out.sort(key=lambda c: c.score, reverse=True)
    return out[:top]
