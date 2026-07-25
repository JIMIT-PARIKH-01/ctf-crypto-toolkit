"""
Identify the likely algorithm behind a hash string, by length + shape.

This is a heuristic (many algorithms share a length), so it returns a ranked
list of candidates rather than a single answer.
"""

from __future__ import annotations

import re

# (regex, [candidate algorithms])  -- checked in order, case-insensitive hex.
_RULES = [
    (r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$", ["bcrypt"]),
    (r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$", ["MD5 crypt (Unix)"]),
    (r"^\$5\$", ["SHA-256 crypt (Unix)"]),
    (r"^\$6\$", ["SHA-512 crypt (Unix)"]),
    (r"^\$argon2(id|i|d)\$", ["Argon2"]),
    (r"^\$P\$[./A-Za-z0-9]{31}$", ["phpass (WordPress / phpBB3)"]),
    (r"^\$H\$[./A-Za-z0-9]{31}$", ["phpass (phpBB3)"]),
    (r"^\$S\$[./A-Za-z0-9]{52}$", ["Drupal 7 (SHA-512 phpass)"]),
    (r"^\$apr1\$", ["Apache MD5 (apr1)"]),
    (r"^\$y\$", ["yescrypt"]),
    (r"^pbkdf2_sha256\$", ["Django (PBKDF2-SHA256)"]),
    (r"^sha1\$[a-f0-9]{5}\$", ["Django (SHA-1)"]),
    (r"^\{SSHA\}", ["LDAP {SSHA}"]),
    (r"^\{SHA\}", ["LDAP {SHA}"]),
    (r"^[a-f0-9]{8}$", ["CRC-32", "Adler-32", "CRC-32B"]),
    (r"^[a-f0-9]{16}$", ["MySQL < 4.1", "Half MD5", "CRC-64"]),
    (r"^[a-f0-9]{32}$", ["MD5", "NTLM", "MD4", "LM", "RIPEMD-128"]),
    (r"^[a-f0-9]{40}$", ["SHA-1", "RIPEMD-160", "MySQL 4.1+ (SHA1)"]),
    (r"^[a-f0-9]{56}$", ["SHA-224", "SHA3-224"]),
    (r"^[a-f0-9]{64}$", ["SHA-256", "SHA3-256", "BLAKE2s", "Keccak-256"]),
    (r"^[a-f0-9]{96}$", ["SHA-384", "SHA3-384"]),
    (r"^[a-f0-9]{128}$", ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"]),
    (r"^[A-Za-z0-9./]{13}$", ["DES crypt (Unix)"]),
    (r"^\*[A-F0-9]{40}$", ["MySQL 4.1+ ('*' prefix)"]),
]


def identify(value: str) -> list:
    """Return a list of likely hash algorithms (best-guess order)."""
    h = value.strip()
    results: list = []
    for pattern, names in _RULES:
        flags = 0 if pattern.startswith("^\\$") or "A-F" in pattern else re.IGNORECASE
        if re.match(pattern, h, flags):
            for n in names:
                if n not in results:
                    results.append(n)
    return results


def report(value: str) -> str:
    h = value.strip()
    cands = identify(h)
    lines = [f"Input  : {h}", f"Length : {len(h)}"]
    if cands:
        lines.append("Likely : " + ", ".join(cands))
    else:
        lines.append("Likely : (no confident match — may be salted, encoded, "
                     "or a non-standard format)")
    return "\n".join(lines)
