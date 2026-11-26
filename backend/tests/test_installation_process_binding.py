"""Boot authority lasts for an interpreter, independently of request contexts."""

import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

BOOT = """
import json
import os
import uuid
from dataclasses import replace
from core import storage_installation_source as source
from core.s3_ownership import StorageOwnershipError
s = dict(kind="kubernetes_immutable_secret", api_origin="https://api.example.test",
         api_ca_sha256="a"*64, namespace="fixture", name="source-one",
         uid=str(uuid.uuid4()), immutable=True, access_key="access",
         secret_key="secret", trust_key="trust")
a = source.BootBinding(str(uuid.uuid4()), str(uuid.uuid4()), json.dumps(s),
                       "/nonexistent/projected-token", "/nonexistent/api-ca")
def descriptor(b):
    return dict(installation_id=b.installation_id, id=b.generation_id, source=b.source())
def denied(fn):
    try:
        fn()
    except StorageOwnershipError as exc:
        assert str(exc) == "Installation source unavailable"
    else:
        raise AssertionError("Expected exact boot refusal")
def enter(b):
    with source.bound_process(b):
        assert source.require_boot(descriptor(b)) == b
"""


def isolated(code):
    result = subprocess.run(
        [sys.executable, "-c", BOOT + textwrap.dedent(code)],
        text=True,
        capture_output=True,
        timeout=20,
        env=dict(
            os.environ,
            PYTHONPATH=os.pathsep.join(
                str(Path(__file__).resolve().parents[2] / p)
                for p in ("backend", "agent", ".")
            ),
        ),
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "change",
    [
        "dict(generation_id=str(uuid.uuid4()))",
        "dict(installation_id=str(uuid.uuid4()))",
        "dict(boot_id=str(uuid.uuid4()))",
        "dict(source_json=json.dumps(dict(s, uid=str(uuid.uuid4()))))",
        'dict(token_path="/different/token")',
        'dict(api_ca_path="/different/ca")',
    ],
    ids=["generation", "installation", "boot", "source", "token-path", "ca-path"],
)
def test_process_binding_cannot_change_after_context_exit(change):
    isolated(f"""
enter(a)
b = replace(a, **{change})
denied(lambda: enter(b))
enter(a)
""")


def test_same_binding_can_resume_but_nested_or_unbound_context_refuses():
    isolated("""
denied(lambda: source.require_boot(descriptor(a)))
with source.bound_process(a):
    denied(lambda: enter(a))
    assert source.require_boot(descriptor(a)) == a
denied(lambda: source.require_boot(descriptor(a)))
enter(a)
""")


def test_concurrent_first_bind_installs_exactly_one_process_identity():
    isolated("""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
barrier = Barrier(2)
b = replace(a, generation_id=str(uuid.uuid4()), boot_id=str(uuid.uuid4()))
def contender(binding):
    barrier.wait(timeout=5)
    try:
        enter(binding)
        return binding
    except StorageOwnershipError as exc:
        assert str(exc) == "Installation source unavailable"
        return None
with ThreadPoolExecutor(2) as pool:
    results = list(pool.map(contender, (a,b)))
assert sum(v is not None for v in results) == 1
winner = next(v for v in results if v is not None)
enter(winner)
denied(lambda: enter(b if winner == a else a))
""")


def test_forked_child_cannot_reuse_or_replace_inherited_binding():
    isolated("""
with source.bound_process(a):
    child = os.fork()
    if child == 0:
        try:
            denied(lambda: source.require_boot(descriptor(a)))
        except BaseException:
            os._exit(1)
    else:
        assert source.require_boot(descriptor(a)) == a
if child == 0:
    try:
        denied(lambda: enter(a))
        denied(lambda: enter(replace(a, boot_id=str(uuid.uuid4()))))
    except BaseException:
        os._exit(2)
    os._exit(0)
_, status = os.waitpid(child, 0)
assert os.waitstatus_to_exitcode(status) == 0
enter(a)
""")


def test_fresh_interpreters_install_independent_boots():
    isolated("enter(a)")
    isolated("enter(a)")
