"""TLS verification posture across the backend's outbound HTTP clients.

Origin (#50): the OIDC token exchange posted client_secret, the authorization
code and the PKCE code_verifier with ``verify=False``, while the discovery fetch
one function above it — same file, same issuer — verified normally. Nothing was
wrong with either line read on its own. What was wrong was that two calls into
the same system disagreed about whether the peer had to prove its identity.

So this module does not grep for a bad token. It builds the inventory of every
outbound client construction and asserts a property over the whole set, which is
what makes it survive the next call site nobody remembers to check.

BOUND, stated so a green run is not read as more than it is: this recognises the
``verify=`` keyword (httpx and requests share it) and aiohttp's ``ssl=``. It does
not see a preconfigured ssl.SSLContext with check_hostname disabled, an
SSL_CERT_FILE pointing somewhere empty, or verification disabled from config at
runtime. Those are the same defect and this file will not find them.
"""

import ast
import os

import pytest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Tests legitimately construct lax clients against local fixtures; scanning them
# would force a suppression vocabulary, which is the thing being avoided here.
SKIP_DIRS = {"tests", "alembic", "__pycache__", ".venv", "venv"}

# Argument names that turn peer verification off when falsy.
VERIFY_KWARGS = {"verify", "ssl"}


def _iter_source_files():
    for root, dirs, files in os.walk(BACKEND_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(files):
            if name.endswith(".py"):
                yield os.path.join(root, name)


def _falsy_literal(node):
    """True when a kwarg value is a constant that disables verification.

    A non-constant (``verify=ca_path``, ``verify=settings.ca``) is not judged
    here: it may resolve to anything, and guessing would produce exactly the
    false confidence this file exists to prevent.
    """
    return isinstance(node, ast.Constant) and node.value in (False, 0, None, "")


def _callee_name(func):
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def collect_postures(source, filename="<src>"):
    """Every call passing a verification kwarg, with how it was set.

    Returns a list of (filename, lineno, callee, kwarg, rendering, disabled).
    """
    found = []
    for node in ast.walk(ast.parse(source, filename)):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg not in VERIFY_KWARGS:
                continue
            found.append(
                (
                    filename,
                    node.lineno,
                    _callee_name(node.func),
                    kw.arg,
                    ast.unparse(kw.value),
                    _falsy_literal(kw.value),
                )
            )
    return found


def _scan_backend():
    postures = []
    for path in _iter_source_files():
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        try:
            tree_ok = ast.parse(source, path)
        except SyntaxError as exc:  # pragma: no cover - would fail lint first
            pytest.fail(f"cannot parse {path}: {exc}")
        del tree_ok
        postures.extend(collect_postures(source, os.path.relpath(path, BACKEND_DIR)))
    return postures


def test_no_outbound_client_disables_tls_verification():
    disabled = [p for p in _scan_backend() if p[5]]
    assert not disabled, "TLS verification disabled at:\n" + "\n".join(
        f"  {f}:{line} — {callee}({kwarg}={render})"
        for f, line, callee, kwarg, render, _ in disabled
    )


def test_the_detector_can_actually_fire():
    """Positive control.

    Without this, the assertion above passes just as happily against a collector
    that never matches anything — and a scanner that silently stops matching is
    indistinguishable from a clean codebase.
    """
    hits = collect_postures(
        "import httpx\n"
        "async with httpx.AsyncClient(timeout=10.0, verify=False) as c:\n"
        "    pass\n"
    )
    assert len(hits) == 1
    assert hits[0][2] == "httpx.AsyncClient"
    assert hits[0][5] is True, "the exact #50 line must be flagged"

    # ...and the shapes it must not flag, or it would force suppressions.
    for benign in ("verify=ca_path", "verify=True", 'verify="/etc/ca.pem"'):
        hit = collect_postures(f"f({benign})")[0]
        assert hit[5] is False, f"{benign} wrongly flagged"


def test_oidc_token_exchange_verifies():
    """The specific regression, pinned by location rather than by property.

    The property test above would also pass if handle_callback stopped making an
    HTTP call at all. This one fails if the client construction disappears.
    """
    path = os.path.join(BACKEND_DIR, "core", "oidc_service.py")
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)

    exchanges = [
        node
        for fn in ast.walk(tree)
        if isinstance(fn, ast.AsyncFunctionDef) and fn.name == "handle_callback"
        for node in ast.walk(fn)
        if isinstance(node, ast.Call)
        and _callee_name(node.func) in ("httpx.AsyncClient", "httpx.Client")
    ]
    assert len(exchanges) == 1, "expected exactly one client in handle_callback"
    assert not [
        kw for kw in exchanges[0].keywords if kw.arg in VERIFY_KWARGS
    ], "handle_callback must leave verification at the verifying default"


def test_sibling_calls_into_the_same_issuer_agree():
    """The property #50 actually violated.

    Both OIDC discovery fetches and the token exchange talk to the operator's
    issuer. They must not disagree about verification — the failure was never one
    bad line, it was two lines answering the same question differently.
    """
    paths = {
        "core/oidc_service.py": os.path.join(BACKEND_DIR, "core", "oidc_service.py"),
        "routers/auth.py": os.path.join(BACKEND_DIR, "routers", "auth.py"),
        "app_monolith.py": os.path.join(BACKEND_DIR, "app_monolith.py"),
    }
    postures = set()
    seen = []
    for label, path in paths.items():
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _callee_name(node.func) not in ("httpx.AsyncClient", "httpx.Client"):
                continue
            verify = [kw for kw in node.keywords if kw.arg in VERIFY_KWARGS]
            rendering = ast.unparse(verify[0].value) if verify else "<default>"
            postures.add(rendering)
            seen.append(f"{label}:{node.lineno} verify={rendering}")

    assert seen, "no OIDC clients found — the scan lost its target"
    assert (
        len(postures) == 1
    ), "OIDC clients disagree on verification posture:\n  " + "\n  ".join(seen)
