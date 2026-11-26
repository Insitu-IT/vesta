"""Empty production installations must not acquire invented agent/VM records."""

from unittest.mock import MagicMock


def test_startup_bootstraps_admin_but_never_invents_inventory(monkeypatch):
    import app
    import core.schema_parity

    database = MagicMock()
    bootstrap = MagicMock(return_value=True)
    monkeypatch.setattr(app, "engine", MagicMock())
    monkeypatch.setattr(app, "SessionLocal", lambda: database)
    monkeypatch.setattr(app, "ensure_initial_admin", bootstrap)
    monkeypatch.setattr(core.schema_parity, "assert_schema_current", MagicMock())
    monkeypatch.setattr(app.settings, "demo_mode", False)
    app.init_database()
    bootstrap.assert_called_once()
    database.add.assert_not_called()
    database.query.assert_not_called()
    database.close.assert_called_once()
