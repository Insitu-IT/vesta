"""Shared bootstrap for the repo-root suites (tests/security, tests/integration).

These suites mint session tokens through ``tests.helpers.create_test_token``,
which reads the signing key from ``deps.jwt_secret()``. That accessor has no
default and raises when ``JWT_SECRET`` is unset — deliberately, so a deployment
cannot sign sessions with a key published in this repository.

The consequence is that the test environment has to supply one, and it has to be
supplied *here* rather than in a fixture: conftest is imported before test
modules are collected, so this covers import-time use as well as call-time use. A
function-scoped fixture would run too late for the former.

``setdefault``, not assignment: CI or a developer may want to pin a specific key,
and silently overriding it would make that pin a lie.
"""

import os
import secrets

# Random per-run rather than a fixed literal. A constant here would be copied
# into a deployment sooner or later — which is the defect these suites exist to
# guard against — and nothing in the tests depends on the value being stable.
os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(32))
