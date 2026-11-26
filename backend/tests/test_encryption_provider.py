"""SimpleEncryption must not invent a key, and must not log one.

Origin (#51): `SimpleEncryption.__init__` generated a fresh Fernet key when
ENCRYPTION_KEY was unset, and logged it at WARNING. Two defects in a backup
product:

- an ephemeral key encrypts backups that cannot be restored after a restart,
  and the failure is discovered at restore time rather than at backup time
- the key reached the log stream, where it is shipped, indexed and retained

The path is dead — `get_encryption_provider()` has no callers — so these tests
are the only exercise this module gets. That is a reason to have them, not a
reason to skip them: dead code carrying the wrong posture beside live code
carrying the right one is exactly how the agent's TLS pair went unnoticed.
"""

import base64
import logging

import pytest
from cryptography.fernet import Fernet

from core.encryption import SimpleEncryption, get_encryption_provider


@pytest.fixture
def a_key():
    """A real Fernet key, in the base64 form ENCRYPTION_KEY carries."""
    raw = Fernet.generate_key()
    return raw, base64.urlsafe_b64encode(raw).decode()


def test_missing_key_raises_rather_than_generating(monkeypatch):
    """THE defect. Absence must stop the caller, not mint a key."""
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc:
        SimpleEncryption()

    message = str(exc.value)
    assert "ENCRYPTION_KEY is not set" in message
    # The consequence must be in the message. "Not set" alone invites someone to
    # set anything; the reason it matters is that backups become unrestorable.
    assert "restored" in message
    assert "Fernet.generate_key" in message


def test_empty_key_is_treated_as_missing(monkeypatch):
    """ENCRYPTION_KEY="" is the shape a half-configured deployment has."""
    monkeypatch.setenv("ENCRYPTION_KEY", "")

    with pytest.raises(RuntimeError):
        SimpleEncryption()


def test_key_from_environment_is_used(monkeypatch, a_key):
    """Positive control.

    Without it, the assertions above pass against a constructor that raises
    unconditionally — fail-closed in the useless sense.
    """
    raw, encoded = a_key
    monkeypatch.setenv("ENCRYPTION_KEY", encoded)

    provider = SimpleEncryption()
    assert provider.key == raw


def test_explicit_key_bypasses_the_environment(monkeypatch, a_key):
    """An explicitly passed key must win, and must not consult the env at all."""
    raw, _ = a_key
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)

    provider = SimpleEncryption(key=raw)
    assert provider.key == raw


def test_no_key_material_is_ever_logged(monkeypatch, caplog, a_key):
    """The disclosure half — a FORWARD pin, not a regression test.

    Stated precisely because the distinction matters: this test passes against
    the pre-fix module too. The original only logged the key in the branch that
    generated one, and with ENCRYPTION_KEY set that branch never ran. So it did
    not catch the original defect; the fail-closed tests did, by removing the
    branch that logged.

    What it does buy is the next version: a fix that stopped generating keys but
    started logging the configured one would pass every other test in this file.
    """
    raw, encoded = a_key
    monkeypatch.setenv("ENCRYPTION_KEY", encoded)

    with caplog.at_level(logging.DEBUG):
        SimpleEncryption()

    emitted = "\n".join(r.getMessage() for r in caplog.records)
    assert encoded not in emitted, "the configured key was written to the log"
    assert raw.decode() not in emitted, "raw key material was written to the log"
    assert "ENCRYPTION_KEY=" not in emitted


def test_round_trip_still_works(monkeypatch, a_key, tmp_path):
    """The module must still do its job — fail-closed is not the same as broken."""
    _, encoded = a_key
    monkeypatch.setenv("ENCRYPTION_KEY", encoded)

    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"backup contents")
    enc = tmp_path / "enc.bin"
    dec = tmp_path / "dec.bin"

    provider = SimpleEncryption()
    provider.encrypt_file(str(plain), str(enc))
    assert enc.read_bytes() != b"backup contents"

    provider.decrypt_file(str(enc), str(dec))
    assert dec.read_bytes() == b"backup contents"


def test_provider_factory_returns_none_when_encryption_is_off(monkeypatch):
    monkeypatch.setenv("ENABLE_ENCRYPTION", "false")
    assert get_encryption_provider() is None


def test_provider_factory_fails_closed_when_enabled_without_a_key(monkeypatch):
    """The reachable path.

    ENABLE_ENCRYPTION=true with no ENCRYPTION_KEY is how a deployment actually
    arrived at the ephemeral key — the factory asked for simple encryption and
    got a working object built on a key nobody would ever have again.
    """
    monkeypatch.setenv("ENABLE_ENCRYPTION", "true")
    monkeypatch.setenv("ENCRYPTION_TYPE", "simple")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)

    with pytest.raises(RuntimeError):
        get_encryption_provider()


def test_explicit_age_selection_uses_age_without_fernet_key(monkeypatch):
    from core import encryption

    monkeypatch.setenv("ENABLE_ENCRYPTION", "true")
    monkeypatch.setenv("ENCRYPTION_TYPE", "age")
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(encryption.subprocess, "run", lambda *args, **kwargs: None)

    assert isinstance(get_encryption_provider(), encryption.AgeEncryption)


def test_explicit_age_selection_reports_missing_cli(monkeypatch):
    from core import encryption

    monkeypatch.setenv("ENABLE_ENCRYPTION", "true")
    monkeypatch.setenv("ENCRYPTION_TYPE", "age")

    def missing(*args, **kwargs):
        raise FileNotFoundError("age")

    monkeypatch.setattr(encryption.subprocess, "run", missing)
    with pytest.raises(RuntimeError, match="Age CLI not available"):
        get_encryption_provider()
