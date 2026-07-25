"""Tests for the cipher/encoding functions."""

from ctf_toolkit import ciphers as c


def test_base64_roundtrip():
    assert c.b64_decode(c.b64_encode("flag{hi}")) == "flag{hi}"


def test_base32_roundtrip():
    assert c.b32_decode(c.b32_encode("hello world")) == "hello world"


def test_hex_roundtrip():
    assert c.hex_decode(c.hex_encode("abc123")) == "abc123"


def test_binary_roundtrip():
    assert c.binary_decode(c.binary_encode("Hi!")) == "Hi!"


def test_decimal_roundtrip():
    assert c.decimal_decode(c.decimal_encode("Zz9")) == "Zz9"


def test_url_roundtrip():
    assert c.url_decode(c.url_encode("a b&c=d")) == "a b&c=d"


def test_rot13_involution():
    assert c.rot13(c.rot13("Secret Message")) == "Secret Message"


def test_rot_n_known():
    assert c.rot_n("abc", 3) == "def"
    assert c.rot_n("xyz", 3) == "abc"


def test_caesar_all_recovers_plaintext():
    # "khoor" is "hello" shifted +3, so ROT23 should recover it
    assert c.caesar_all("khoor")[23] == "hello"


def test_atbash_involution_and_known():
    assert c.atbash(c.atbash("Zebra")) == "Zebra"
    assert c.atbash("abc") == "zyx"


def test_morse_roundtrip():
    assert c.morse_decode(c.morse_encode("SOS")) == "SOS"


def test_vigenere_known_vector():
    # classic LEMON example
    assert c.vigenere("LXFOPVEFRNHR", "lemon", decode=True) == "ATTACKATDAWN"
    assert c.vigenere("ATTACKATDAWN", "lemon") == "LXFOPVEFRNHR"


def test_xor_roundtrip():
    data = b"flag{xor_me}"
    assert c.xor_bytes(c.xor_bytes(data, b"key"), b"key") == data


def test_reverse():
    assert c.reverse("abc") == "cba"


def test_base85_roundtrip():
    assert c.b85_decode(c.b85_encode("flag{85}")) == "flag{85}"


def test_base58_roundtrip():
    assert c.b58_decode(c.b58_encode("Hello, Bitcoin!")) == "Hello, Bitcoin!"


def test_rot47_involution_and_known():
    assert c.rot47(c.rot47("Secret 123!")) == "Secret 123!"
    assert c.rot47("Hello") == "w6==@"


def test_codecs_registry_roundtrips():
    # Morse is case-insensitive (uppercase only), so use an uppercase sample
    # that every registered codec round-trips cleanly.
    sample = "TEST123"
    for name, (enc, dec) in c.CODECS.items():
        assert dec(enc(sample)) == sample, name
