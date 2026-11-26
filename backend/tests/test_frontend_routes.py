"""Verify every frontend API call has a matching backend route.

Statically scans router files for route decorators and compares against
the extracted frontend API calls from api-calls.json. Catches:
- Frontend calling endpoints that don't exist (404s)
- HTTP method mismatches (POST vs PATCH -> 405s)
- Stale frontend code after backend refactoring

No app import needed — works by regex-parsing router files.
"""

import json
import os
import re

import pytest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTERS_DIR = os.path.join(BACKEND_DIR, "routers")
API_CALLS_FILE = os.path.join(BACKEND_DIR, "..", "frontend", "api-calls.json")

# Regex to find router prefix: APIRouter(prefix="/api/v1/foo", ...)
PREFIX_RE = re.compile(r'APIRouter\([^)]*prefix\s*=\s*["\']([^"\']+)["\']')

# Regex to find route decorators: @router.get("/path/{param}")
DECORATOR_RE = re.compile(
    r'@router\.(get|post|put|patch|delete|head|options)\(\s*["\']([^"\']+)["\']'
)


def _scan_backend_routes():
    """Statically scan router files for route decorators."""
    routes = set()

    for filename in os.listdir(ROUTERS_DIR):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue

        filepath = os.path.join(ROUTERS_DIR, filename)
        with open(filepath) as f:
            content = f.read()

        # Find router prefix
        prefix_match = PREFIX_RE.search(content)
        prefix = prefix_match.group(1) if prefix_match else ""

        # Find all route decorators
        for match in DECORATOR_RE.finditer(content):
            method = match.group(1).upper()
            path = match.group(2)
            full_path = prefix + path
            # Normalize {param} -> :param
            normalized = re.sub(r"\{[^}]+\}", ":param", full_path)
            routes.add((method, normalized))

    return routes


def _load_frontend_calls():
    if not os.path.exists(API_CALLS_FILE):
        pytest.skip(
            "api-calls.json not found. "
            "Run: cd frontend && node scripts/extract-api-calls.cjs"
        )
    with open(API_CALLS_FILE) as f:
        return json.load(f)


class TestFrontendRoutes:
    """Verify frontend API calls have matching backend routes."""

    @pytest.fixture(scope="class")
    def backend_routes(self):
        return _scan_backend_routes()

    @pytest.fixture(scope="class")
    def frontend_calls(self):
        return _load_frontend_calls()

    def test_backend_routes_found(self, backend_routes):
        """Sanity check: we should find a reasonable number of routes."""
        assert len(backend_routes) > 50, (
            f"Only found {len(backend_routes)} backend routes — "
            "scanner may be broken"
        )

    def test_all_frontend_calls_have_backend_routes(
        self, backend_routes, frontend_calls
    ):
        """Every frontend API call must have a matching backend route."""
        missing = []
        for call in frontend_calls:
            method = call["method"]
            path = call["path"]

            # HEAD is allowed if GET exists
            candidates = [(method, path)]
            if method == "HEAD":
                candidates.append(("GET", path))

            found = any(c in backend_routes for c in candidates)
            if not found:
                missing.append(
                    f"{method:7s} {path:50s}  (from {call['file']}:{call['line']})"
                )

        if missing:
            msg = (
                f"\n{len(missing)} frontend API calls have no matching backend route:\n"
            )
            msg += "\n".join(f"  {m}" for m in missing)
            pytest.fail(msg)

    def test_no_orphan_methods(self, backend_routes, frontend_calls):
        """Frontend shouldn't use wrong HTTP method for an existing path."""
        mismatches = []
        for call in frontend_calls:
            method = call["method"]
            path = call["path"]

            if (method, path) in backend_routes:
                continue

            path_methods = {m for m, p in backend_routes if p == path}
            if path_methods and method not in path_methods:
                mismatches.append(
                    f"{method:7s} {path:50s}  "
                    f"(backend has: {', '.join(sorted(path_methods))})"
                )

        if mismatches:
            msg = f"\n{len(mismatches)} frontend API calls use wrong HTTP method:\n"
            msg += "\n".join(f"  {m}" for m in mismatches)
            pytest.fail(msg)


class TestPaginatedEndpoints:
    """Verify paginated endpoints exist as GET routes.

    Auto-discovers paginated endpoints by scanning router files for
    functions with integer `skip` parameters, including Annotated validation.
    """

    @staticmethod
    def _discover_paginated():
        """Scan plain and Annotated integer pagination parameters."""
        import re as _re

        prefix_re = _re.compile(r'APIRouter\([^)]*prefix\s*=\s*["\']([^"\']+)["\']')
        dec_re = _re.compile(
            r'@router\.(get|post|put|patch|delete)\(\s*["\']([^"\']+)["\']'
        )

        endpoints = []
        for filename in sorted(os.listdir(ROUTERS_DIR)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
            filepath = os.path.join(ROUTERS_DIR, filename)
            with open(filepath) as f:
                lines = f.readlines()
            content = "".join(lines)
            pm = prefix_re.search(content)
            prefix = pm.group(1) if pm else ""

            for i, line in enumerate(lines):
                m = dec_re.search(line)
                if not m:
                    continue
                method = m.group(1).upper()
                path = m.group(2)
                lookahead = "".join(lines[i : i + 15])
                if _re.search(r"\bskip\s*:\s*(?:Annotated\[\s*)?int\b", lookahead):
                    full = prefix + path
                    normalized = _re.sub(r"\{[^}]+\}", ":param", full)
                    endpoints.append((method, normalized))
        return endpoints

    def test_paginated_endpoints_exist(self):
        """All auto-discovered paginated endpoints must be registered as GET routes."""
        routes = _scan_backend_routes()
        paginated = self._discover_paginated()

        # Validated query annotations must not silently remove these readers
        # from the scanner's denominator.
        assert {
            ("GET", "/api/v1/" + name)
            for name in ("backups", "restores", "users", "vms")
        } <= set(paginated)

        assert (
            len(paginated) >= 10
        ), f"Only found {len(paginated)} paginated endpoints — scanner may be broken"

        missing = []
        for method, path in paginated:
            if (method, path) not in routes:
                missing.append(f"{method} {path}")
        if missing:
            pytest.fail(f"Paginated endpoints not found in backend routes: {missing}")
