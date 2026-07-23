"""
Classical ciphers and common encodings for CTF work.

Pure standard library. Every function takes and returns `str` (bytes are
decoded with errors="replace" so nothing ever crashes on odd input).
"""

from __future__ import annotations

import base64
import codecs as _codecs
from urllib.parse import quote, unquote

# --------------------------------------------------------------------------- #
# Encodings (reversible, no key)
# --------------------------------------------------------------------------- #
def _b(s: str) -> bytes:
    return s.encode("utf-8", "replace")


def b64_encode(s: str) -> str:
    return base64.b64encode(_b(s)).decode("ascii")


def b64_decode(s: str) -> str:
    s = "".join(s.split())
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")


def b32_encode(s: str) -> str:
    return base64.b32encode(_b(s)).decode("ascii")


def b32_decode(s: str) -> str:
    s = "".join(s.split()).upper()
    return base64.b32decode(s + "=" * (-len(s) % 8)).decode("utf-8", "replace")


def hex_encode(s: str) -> str:
    return _b(s).hex()


def hex_decode(s: str) -> str:
    s = "".join(s.split())
    return bytes.fromhex(s).decode("utf-8", "replace")


def url_encode(s: str) -> str:
    return quote(s, safe="")


def url_decode(s: str) -> str:
    return unquote(s)


def binary_encode(s: str) -> str:
    return " ".join(format(byte, "08b") for byte in _b(s))


def binary_decode(s: str) -> str:
    bits = "".join(s.split())
    chunks = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    return bytes(int(c, 2) for c in chunks if len(c) == 8).decode("utf-8", "replace")


def decimal_encode(s: str) -> str:
    return " ".join(str(byte) for byte in _b(s))


def decimal_decode(s: str) -> str:
    return bytes(int(x) for x in s.split()).decode("utf-8", "replace")


def reverse(s: str) -> str:
    return s[::-1]


# --------------------------------------------------------------------------- #
# Substitution ciphers (no key / fixed)
# --------------------------------------------------------------------------- #
def rot13(s: str) -> str:
    return _codecs.encode(s, "rot_13")


def rot_n(s: str, n: int) -> str:
    out = []
    for ch in s:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def caesar_all(s: str) -> dict:
    """Return every Caesar shift 1..25 -> decoded text."""
    return {n: rot_n(s, n) for n in range(1, 26)}


def atbash(s: str) -> str:
    out = []
    for ch in s:
        if "A" <= ch <= "Z":
            out.append(chr(90 - (ord(ch) - 65)))
        elif "a" <= ch <= "z":
            out.append(chr(122 - (ord(ch) - 97)))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------- #
# Morse
# --------------------------------------------------------------------------- #
_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "/": "-..-.", "-": "-....-", "(": "-.--.", ")": "-.--.-",
}
_MORSE_REV = {v: k for k, v in _MORSE.items()}


def morse_encode(s: str) -> str:
    return " ".join(_MORSE.get(ch.upper(), "") for ch in s if ch.strip()).strip()


def morse_decode(s: str) -> str:
    words = s.strip().split(" / ") if " / " in s else [s.strip()]
    out = []
    for word in words:
        out.append("".join(_MORSE_REV.get(code, "") for code in word.split()))
    return " ".join(out)


# --------------------------------------------------------------------------- #
# Keyed ciphers
# --------------------------------------------------------------------------- #
def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def xor_str(s: str, key: str) -> str:
    return xor_bytes(_b(s), _b(key)).decode("utf-8", "replace")


def xor_single_all(data: bytes) -> dict:
    """Every single-byte XOR key 0..255 -> decoded text."""
    return {k: xor_bytes(data, bytes([k])).decode("utf-8", "replace")
            for k in range(256)}


def vigenere(s: str, key: str, decode: bool = False) -> str:
    key = [c for c in key.lower() if c.isalpha()]
    if not key:
        return s
    out, ki = [], 0
    for ch in s:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - 97
            if decode:
                shift = -shift
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------- #
# Registry of no-key, reversible codecs (used by the CLI/GUI and magic)
# --------------------------------------------------------------------------- #
CODECS = {
    "base64": (b64_encode, b64_decode),
    "base32": (b32_encode, b32_decode),
    "hex": (hex_encode, hex_decode),
    "url": (url_encode, url_decode),
    "binary": (binary_encode, binary_decode),
    "decimal": (decimal_encode, decimal_decode),
    "morse": (morse_encode, morse_decode),
    "rot13": (rot13, rot13),
    "atbash": (atbash, atbash),
    "reverse": (reverse, reverse),
}
