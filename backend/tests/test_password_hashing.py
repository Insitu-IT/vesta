"""Stored bcrypt hashes and the audited bcrypt 5 input boundary remain stable."""

import pytest
from deps import hash_password, verify_password

# Created with bcrypt 4.0.1 and fixed test salt, never an account credential.
STORED = "$2b$04$abcdefghijklmnopqrstuuZtH7nl.o819BwQ9qKlP9cSzk120dZnK"


@pytest.mark.parametrize("prefix", ["2a", "2b", "2y"])
def test_existing_hash_prefixes(prefix):
    stored = "$" + prefix + STORED[3:]
    assert verify_password("Managed1!Password", stored)
    assert not verify_password("wrong", stored)


@pytest.mark.parametrize("password", ["", "a" * 72, "ש" * 36])
def test_supported_password_byte_boundary(password):
    assert verify_password(password, hash_password(password))


@pytest.mark.parametrize("password", ["a" * 73, "ש" * 37])
def test_oversized_password_retains_bcrypt5_refusal(password):
    with pytest.raises(ValueError):
        hash_password(password)
    with pytest.raises(ValueError):
        verify_password(password, STORED)


@pytest.mark.parametrize("stored", ["", "not-a-hash", "$2b$xx$abc"])
def test_malformed_hash_retains_refusal(stored):
    with pytest.raises(ValueError):
        verify_password("Managed1!Password", stored)
