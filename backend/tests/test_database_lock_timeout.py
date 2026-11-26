"""Synchronous PostgreSQL requests must not wait indefinitely on row locks."""

from database import sync_connect_args


def test_postgres_startup_binds_lock_wait():
    assert sync_connect_args("postgresql://user:pass@db.example/vnbui") == {
        "options": "-c lock_timeout=5s"
    }


def test_postgres_keeps_other_startup_options():
    assert sync_connect_args(
        "postgresql://user:pass@db.example/vnbui?options=-c%20application_name%3Dvnbui"
    ) == {"options": "-c application_name=vnbui -c lock_timeout=5s"}


def test_non_postgres_test_engine_has_no_libpq_options():
    assert sync_connect_args("sqlite:///test.db") == {}
