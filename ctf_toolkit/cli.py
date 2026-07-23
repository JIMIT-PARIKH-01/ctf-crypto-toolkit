"""
Command line for the CTF Crypto Toolkit.

    python -m ctf_toolkit encode base64 --text "hello"
    python -m ctf_toolkit decode base64 --text "aGVsbG8="
    python -m ctf_toolkit caesar --text "khoor"          # all 25 shifts
    python -m ctf_toolkit rot --n 3 --text "khoor"
    python -m ctf_toolkit xor --key s3cr3t --text "..."
    python -m ctf_toolkit xor --brute --text "..."        # all single-byte keys
    python -m ctf_toolkit vigenere --key lemon --decode --text "LXFOPVEFRNHR"
    python -m ctf_toolkit magic --text "aGVsbG8sIGZsYWd7...}"
    python -m ctf_toolkit hashid --text "5d41402abc4b2a76b9719d911017c592"
"""

from __future__ import annotations

import argparse
import sys

from . import ciphers, magic as magic_mod, hashid


def _get_text(args) -> str:
    if getattr(args, "stdin", False):
        return sys.stdin.read().rstrip("\n")
    if getattr(args, "file", None):
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return args.text or ""


def _add_input(sp) -> None:
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="Literal input.")
    g.add_argument("--file", help="Read input from a file.")
    g.add_argument("--stdin", action="store_true", help="Read input from stdin.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ctf_toolkit",
        description="CTF crypto toolkit: encoders/decoders, magic auto-decode, hash ID.")
    sub = p.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="Encode with a codec.")
    enc.add_argument("codec", choices=sorted(ciphers.CODECS))
    _add_input(enc)

    dec = sub.add_parser("decode", help="Decode with a codec.")
    dec.add_argument("codec", choices=sorted(ciphers.CODECS))
    _add_input(dec)

    ca = sub.add_parser("caesar", help="Show all 25 Caesar shifts.")
    _add_input(ca)

    ro = sub.add_parser("rot", help="Rotate letters by N.")
    ro.add_argument("--n", type=int, required=True)
    _add_input(ro)

    xo = sub.add_parser("xor", help="XOR with a key, or brute all single bytes.")
    xo.add_argument("--key", help="XOR key (text).")
    xo.add_argument("--brute", action="store_true", help="Try all 256 single-byte keys.")
    _add_input(xo)

    vi = sub.add_parser("vigenere", help="Vigenere cipher.")
    vi.add_argument("--key", required=True)
    vi.add_argument("--decode", action="store_true")
    _add_input(vi)

    mg = sub.add_parser("magic", help="Auto-detect and decode.")
    _add_input(mg)

    hi = sub.add_parser("hashid", help="Identify a hash's likely algorithm.")
    _add_input(hi)
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        text = _get_text(args)
    except OSError as exc:
        print(f"Could not read input: {exc}", file=sys.stderr)
        return 2

    cmd = args.command
    if cmd == "encode":
        print(ciphers.CODECS[args.codec][0](text))
    elif cmd == "decode":
        print(ciphers.CODECS[args.codec][1](text))
    elif cmd == "caesar":
        for n, out in ciphers.caesar_all(text).items():
            print(f"ROT{n:>2}: {out}")
    elif cmd == "rot":
        print(ciphers.rot_n(text, args.n))
    elif cmd == "xor":
        if args.brute:
            raw = text.encode("utf-8", "replace")
            for k, out in ciphers.xor_single_all(raw).items():
                if magic_mod.score_text(out) > 90:
                    print(f"0x{k:02x}: {out}")
        elif args.key:
            print(ciphers.xor_str(text, args.key))
        else:
            print("xor needs --key or --brute", file=sys.stderr)
            return 2
    elif cmd == "vigenere":
        print(ciphers.vigenere(text, args.key, decode=args.decode))
    elif cmd == "magic":
        cands = magic_mod.magic(text)
        if not cands:
            print("No promising decodings found.")
        for c in cands:
            print(f"[{c.score:6.1f}] {c.method:<16} {c.preview()}")
    elif cmd == "hashid":
        print(hashid.report(text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
