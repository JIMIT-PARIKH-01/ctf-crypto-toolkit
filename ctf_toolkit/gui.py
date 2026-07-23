"""
Tkinter GUI for the CTF Crypto Toolkit (standard library only).

Paste text, pick an operation, and get the result — plus a one-click
"Magic" auto-decoder and a hash identifier.

Launch with run.bat, or:  python ctf_toolkit/gui.py
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Work whether run as a module or as a loose script.
try:
    from ctf_toolkit import ciphers, magic as magic_mod, hashid
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from ctf_toolkit import ciphers, magic as magic_mod, hashid


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CTF Crypto Toolkit")
        self.geometry("820x660")
        self.minsize(720, 560)

        pad = {"padx": 6, "pady": 4}
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)
        frm.rowconfigure(6, weight=2)

        # --- input ---
        ttk.Label(frm, text="Input").grid(row=0, column=0, sticky="w")
        self.inp = scrolledtext.ScrolledText(frm, height=8, wrap="word",
                                             font=("Consolas", 10))
        self.inp.grid(row=1, column=0, sticky="nsew", pady=(2, 6))

        # --- codec row ---
        row1 = ttk.Frame(frm)
        row1.grid(row=2, column=0, sticky="ew", **pad)
        ttk.Label(row1, text="Codec").pack(side="left")
        self.codec = tk.StringVar(value="base64")
        ttk.Combobox(row1, textvariable=self.codec, width=10, state="readonly",
                     values=sorted(ciphers.CODECS)).pack(side="left", padx=6)
        ttk.Button(row1, text="Encode", command=self.on_encode).pack(side="left")
        ttk.Button(row1, text="Decode", command=self.on_decode).pack(side="left", padx=4)
        ttk.Label(row1, text="Key / N").pack(side="left", padx=(18, 4))
        self.key = tk.StringVar()
        ttk.Entry(row1, textvariable=self.key, width=16).pack(side="left")

        # --- keyed / classical row ---
        row2 = ttk.Frame(frm)
        row2.grid(row=3, column=0, sticky="ew", **pad)
        ttk.Button(row2, text="Caesar (all shifts)", command=self.on_caesar).pack(side="left")
        ttk.Button(row2, text="ROT-N", command=self.on_rotn).pack(side="left", padx=4)
        ttk.Button(row2, text="XOR key", command=self.on_xor_key).pack(side="left")
        ttk.Button(row2, text="XOR brute", command=self.on_xor_brute).pack(side="left", padx=4)
        ttk.Button(row2, text="Vigenère →", command=lambda: self.on_vig(False)).pack(side="left")
        ttk.Button(row2, text="Vigenère ←", command=lambda: self.on_vig(True)).pack(side="left", padx=4)

        # --- headline actions ---
        row3 = ttk.Frame(frm)
        row3.grid(row=4, column=0, sticky="ew", **pad)
        magic_btn = ttk.Button(row3, text="✨  Magic (auto-decode)", command=self.on_magic)
        magic_btn.pack(side="left")
        ttk.Button(row3, text="#  Identify hash", command=self.on_hashid).pack(side="left", padx=6)
        ttk.Button(row3, text="Copy output", command=self.on_copy).pack(side="left", padx=6)
        ttk.Button(row3, text="Clear", command=self.on_clear).pack(side="left")

        # --- output ---
        ttk.Label(frm, text="Output").grid(row=5, column=0, sticky="w")
        self.out = scrolledtext.ScrolledText(frm, height=12, wrap="word",
                                             font=("Consolas", 10), state="disabled")
        self.out.grid(row=6, column=0, sticky="nsew", pady=(2, 0))

        self.status = ttk.Label(self, text="Ready", relief="sunken", anchor="w")
        self.status.pack(fill="x", side="bottom")

    # ------------------------------------------------------------- helpers --
    def _text(self) -> str:
        return self.inp.get("1.0", "end").rstrip("\n")

    def _show(self, text: str, status: str = "Done") -> None:
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text)
        self.out.configure(state="disabled")
        self.status.configure(text=status)

    def _guard(self, fn, status: str) -> None:
        text = self._text()
        if not text.strip():
            messagebox.showinfo("No input", "Type or paste something first.")
            return
        try:
            self._show(fn(text), status)
        except Exception as exc:  # noqa: BLE001 - surface any failure in the output box
            self._show(f"Error: {exc}", "Error")

    def _int_key(self) -> int:
        try:
            return int(self.key.get())
        except (ValueError, TypeError):
            raise ValueError("Enter a whole number in the 'Key / N' box.")

    # ------------------------------------------------------------- actions --
    def on_encode(self) -> None:
        self._guard(lambda t: ciphers.CODECS[self.codec.get()][0](t),
                    f"Encoded ({self.codec.get()})")

    def on_decode(self) -> None:
        self._guard(lambda t: ciphers.CODECS[self.codec.get()][1](t),
                    f"Decoded ({self.codec.get()})")

    def on_caesar(self) -> None:
        self._guard(lambda t: "\n".join(f"ROT{n:>2}: {v}"
                                        for n, v in ciphers.caesar_all(t).items()),
                    "Caesar — all 25 shifts")

    def on_rotn(self) -> None:
        self._guard(lambda t: ciphers.rot_n(t, self._int_key()), "ROT-N")

    def on_xor_key(self) -> None:
        key = self.key.get()
        if not key:
            messagebox.showinfo("No key", "Enter an XOR key in the 'Key / N' box.")
            return
        self._guard(lambda t: ciphers.xor_str(t, key), "XOR (key)")

    def on_xor_brute(self) -> None:
        def run(t: str) -> str:
            raw = t.encode("utf-8", "replace")
            hits = [f"0x{k:02x}: {v}" for k, v in ciphers.xor_single_all(raw).items()
                    if magic_mod.score_text(v) > 90]
            return "\n".join(hits) or "(no promising single-byte XOR keys)"
        self._guard(run, "XOR brute (single byte)")

    def on_vig(self, decode: bool) -> None:
        key = self.key.get()
        if not key:
            messagebox.showinfo("No key", "Enter a Vigenère key in the 'Key / N' box.")
            return
        self._guard(lambda t: ciphers.vigenere(t, key, decode=decode),
                    "Vigenère " + ("decode" if decode else "encode"))

    def on_magic(self) -> None:
        def run(t: str) -> str:
            cands = magic_mod.magic(t)
            if not cands:
                return "No promising decodings found."
            return "\n".join(f"[{c.score:6.1f}] {c.method:<16} {c.output}"
                             for c in cands)
        self._guard(run, "Magic auto-decode")

    def on_hashid(self) -> None:
        self._guard(hashid.report, "Hash identified")

    def on_copy(self) -> None:
        text = self.out.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status.configure(text="Output copied to clipboard.")

    def on_clear(self) -> None:
        self.inp.delete("1.0", "end")
        self._show("", "Cleared")


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
