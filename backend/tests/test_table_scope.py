"""Ownership inventory conformance includes a deliberately unclassified control."""

import pytest

from core.table_scope import SCOPES, assert_classified
from models import Base


def test_all_application_tables_have_explicit_ownership():
    assert_classified(set(Base.metadata.tables) | {"access_audit"})
    for scope in SCOPES.values():
        assert scope.kind in {"tenant", "parent", "global"}
        assert scope.identity and scope.boundary


def test_new_and_removed_tables_require_a_classification_change():
    with pytest.raises(RuntimeError, match="unclassified=.*new_unowned_table"):
        assert_classified(set(SCOPES) | {"new_unowned_table"})
    with pytest.raises(RuntimeError, match="absent=.*users"):
        assert_classified(set(SCOPES) - {"users"})
