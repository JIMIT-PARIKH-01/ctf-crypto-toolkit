"""Tests for the 'magic' auto-decoder."""

import base64

from ctf_toolkit import magic


def test_magic_finds_base64_flag_first():
    blob = base64.b64encode(b"flag{base64_is_easy}").decode()
    cands = magic.magic(blob)
    assert cands and "flag{base64_is_easy}" in cands[0].output


def test_magic_finds_hex_flag():
    blob = b"flag{hex_me}".hex()
    cands = magic.magic(blob)
    assert any("flag{hex_me}" in cand.output for cand in cands)


def test_magic_finds_single_byte_xor():
    from ctf_toolkit import ciphers
    ct = ciphers.xor_bytes(b"flag{xor_me}", bytes([0x42])).decode("utf-8", "replace")
    cands = magic.magic(ct)
    assert any("flag{xor_me}" in cand.output for cand in cands)


def test_score_prefers_flaglike_text():
    assert magic.score_text("here is flag{real_one}") > magic.score_text("zxqwvbnmlk")


def test_magic_empty_input():
    assert magic.magic("") == []
