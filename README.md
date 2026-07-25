# CTF Crypto Toolkit

[![CI](https://github.com/JIMIT-PARIKH-01/ctf-crypto-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/JIMIT-PARIKH-01/ctf-crypto-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen)

A fast, offline **encoder/decoder + auto-decoder + hash identifier** for CTF and
security work — with a **GUI and a CLI**, built on the Python standard library
(zero dependencies).

Made for CTF challenges, your own labs, and learning. 🚩

---

## Features

- **Encodings:** Base64, Base32, Hex, URL, Binary, Decimal, Morse
- **Classical ciphers:** ROT13, ROT-N, Caesar (all 25 shifts), Atbash, Reverse, Vigenère
- **XOR:** with a key, or **brute-force all 256 single-byte keys** (auto-filtered to readable hits)
- **✨ Magic auto-decode:** throw a blob at it — it tries every decoding, scores each by how
  text-/flag-like it looks (recognises `flag{...}`, `CTF{...}`, `picoCTF{...}`, …), and ranks the
  best guesses. Penalises needless multi-step decodes so the simplest correct answer wins.
- **# Hash ID:** guess a hash's algorithm from its length/shape (MD5, SHA-1/224/256/384/512,
  NTLM, bcrypt, CRC-32, Unix crypt, Argon2, …)

---

## Install & run

Just **Python 3.8+** — nothing to install.

```powershell
# GUI (double-click run.bat, or:)
python ctf_toolkit/gui.py

# CLI
python -m ctf_toolkit encode base64 --text "flag{hello}"
python -m ctf_toolkit decode base64 --text "ZmxhZ3toZWxsb30="
python -m ctf_toolkit caesar   --text "khoor"                 # all 25 shifts
python -m ctf_toolkit rot --n 3 --text "hello"
python -m ctf_toolkit xor --brute --text "<ciphertext>"       # try every byte key
python -m ctf_toolkit xor --key s3cr3t --text "<ciphertext>"
python -m ctf_toolkit vigenere --key lemon --decode --text "LXFOPVEFRNHR"
python -m ctf_toolkit magic  --text "ZmxhZ3tiYXNlNjRfaXNfZWFzeX0="
python -m ctf_toolkit hashid --text "5d41402abc4b2a76b9719d911017c592"
```

Input can come from `--text`, `--file`, or `--stdin` (great for piping):

```powershell
cat challenge.txt | python -m ctf_toolkit magic --stdin
```

---

## Example

```
$ python -m ctf_toolkit magic --text "ZmxhZ3tiYXNlNjRfaXNfZWFzeX0="
[ 366.5] base64           flag{base64_is_easy}
[ 343.0] base64+rot13     synt{onfr64_vf_rnfl}
...
```

---

## Project layout

```
ctf-crypto-toolkit/
└── ctf_toolkit/
    ├── ciphers.py   # encodings + classical/keyed ciphers
    ├── magic.py     # scored auto-decoder
    ├── hashid.py    # hash algorithm identification
    ├── cli.py       # command line
    ├── gui.py       # tkinter GUI
    ├── run.bat      # double-click launcher
    └── requirements.txt
```

## Development

```bash
pip install -e .          # install (adds the `ctf-toolkit` command)
pip install pytest
pytest -q                 # run the test suite (27 tests)
```

CI runs the full suite on Python 3.9–3.12 on every push (see the badge above).

## Responsible use
For CTF, your own systems/labs, and authorized security work only.

## License
MIT — see [LICENSE](./LICENSE).
