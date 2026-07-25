"""Tests for hash identification."""

from ctf_toolkit import hashid


def test_md5():
    assert "MD5" in hashid.identify("d41d8cd98f00b204e9800998ecf8427e")


def test_sha1():
    assert "SHA-1" in hashid.identify("a" * 40)


def test_sha256():
    assert "SHA-256" in hashid.identify("a" * 64)


def test_sha512():
    assert "SHA-512" in hashid.identify("a" * 128)


def test_bcrypt():
    cands = hashid.identify("$2b$12$" + "a" * 53)
    assert any("bcrypt" in x.lower() for x in cands)


def test_phpass():
    assert any("phpass" in x for x in hashid.identify("$P$" + "B" * 31))


def test_django_pbkdf2():
    assert any("Django" in x for x in hashid.identify("pbkdf2_sha256$260000$salt$hashvalue=="))


def test_ldap_ssha():
    assert any("SSHA" in x for x in hashid.identify("{SSHA}dGVzdHNhbHQ="))


def test_unknown_returns_empty():
    assert hashid.identify("definitely not a hash!") == []


def test_report_contains_length():
    assert "Length : 32" in hashid.report("d41d8cd98f00b204e9800998ecf8427e")
