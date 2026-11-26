"""Tests for the cluster-singleton scheduler guard (#47).

The defect: the backend runs `replicas: 2` and every pod's scheduler fires every
job, so scheduled backups, retention and stale-cleanup all execute once per
replica. Measured on 2026-07-30 — both pods logged `run_retention_enforcement` at
`03:00:00+00:00`.

The two properties that actually matter here are easy to get wrong in opposite
directions, so both are asserted:

  * the guard must SERIALISE cluster-singleton jobs, and
  * it must LEAVE `collect_gauge_metrics` alone, because each pod has to populate
    its own Prometheus registry. A remedy that gates the scheduler wholesale would
    pass a "no duplicate backups" test and silently blank one pod's `/metrics`.
"""

import ast
import os
import unittest

from sqlalchemy import create_engine

from core.singleton import cluster_singleton, lock_key

# Injected so the guard is exercised against a real (SQLite) engine rather than
# whatever DATABASE_URL happens to point at, which under test is an unreachable
# Postgres.
SQLITE = create_engine("sqlite:///:memory:")

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LockKeyIsStableAcrossProcesses(unittest.TestCase):
    """The one property a single-process test suite cannot catch by accident."""

    def test_key_is_a_pinned_constant_not_a_salted_hash(self):
        """Pinned literals, so a switch to a per-process hash fails here.

        `hash()` on a str is salted by PYTHONHASHSEED, so two pods would derive
        different keys, both acquire the lock, and the guard would do nothing while
        every single-process test still passed. Pinning the actual values is what
        makes that regression visible.
        """
        self.assertEqual(lock_key("retention_enforcement"), 8717396681138720074)
        self.assertEqual(lock_key("cleanup_stale_operations"), 3385440471176433040)

    def test_key_is_deterministic_within_a_run(self):
        self.assertEqual(lock_key("x"), lock_key("x"))

    def test_distinct_jobs_get_distinct_keys(self):
        names = [
            "retention_enforcement",
            "cleanup_stale_operations",
            "scheduled_backup:a",
            "scheduled_backup:b",
        ]
        self.assertEqual(len({lock_key(n) for n in names}), len(names))

    def test_key_fits_a_postgres_bigint(self):
        for n in ("retention_enforcement", "scheduled_backup:" + "z" * 200):
            self.assertGreaterEqual(lock_key(n), -(2**63))
            self.assertLessEqual(lock_key(n), 2**63 - 1)


class NonPostgresIsADeliberateNoOp(unittest.TestCase):
    def test_sqlite_yields_acquired(self):
        """The suite runs on SQLite, which has no advisory locks.

        Failing closed here would silently disable retention and scheduled backups
        in exactly the environments that have a single writer anyway.
        """
        with cluster_singleton("retention_enforcement", engine=SQLITE) as acquired:
            self.assertTrue(acquired)

    def test_reentrant_on_sqlite(self):
        with cluster_singleton("a", engine=SQLITE) as first:
            with cluster_singleton("a", engine=SQLITE) as second:
                self.assertTrue(first and second)

    def test_unreachable_postgres_fails_OPEN_with_a_warning(self):
        """A guard that raises would break the job it protects.

        The warning matters: a run of these in the log means duplicate suppression
        is silently not in effect.
        """
        dead = create_engine("postgresql://nobody@127.0.0.1:1/nowhere")
        with self.assertLogs("core.singleton", level="WARNING") as captured:
            with cluster_singleton("retention_enforcement", engine=dead) as acquired:
                self.assertTrue(acquired)
        self.assertIn("UNGUARDED", "".join(captured.output))


class TheRightJobsAreGuarded(unittest.TestCase):
    """Source-level assertions: which jobs are wrapped is the design, so it is pinned.

    These read the AST rather than executing the jobs, because executing them needs
    a live scheduler, a DB and an agent. What must not drift is the SET of guarded
    jobs, and that is visible statically.
    """

    @staticmethod
    def _calls_guard(path, func_name):
        tree = ast.parse(open(os.path.join(BACKEND, path)).read())
        fn = next(
            (
                n
                for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == func_name
            ),
            None,
        )
        assert fn is not None, f"{func_name} not found in {path}"
        return any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "cluster_singleton"
            for n in ast.walk(fn)
        )

    def test_retention_enforcement_is_guarded(self):
        self.assertTrue(self._calls_guard("app.py", "run_retention_enforcement"))

    def test_scheduled_backup_is_guarded(self):
        self.assertTrue(self._calls_guard("scheduler.py", "execute_scheduled_backup"))

    def test_stale_cleanup_is_guarded(self):
        # The callback submits to its owned application loop; the guard must
        # surround the database worker, not just task submission.
        self.assertTrue(self._calls_guard("app.py", "_cleanup_stale_operations_worker"))
        tree = ast.parse(open(os.path.join(BACKEND, "app.py")).read())
        on_loop = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.AsyncFunctionDef)
            and n.name == "cleanup_stale_operations_on_loop"
        )
        self.assertTrue(
            any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "run_owned_worker"
                and n.args
                and isinstance(n.args[0], ast.Name)
                and n.args[0].id == "_cleanup_stale_operations_worker"
                for n in ast.walk(on_loop)
            )
        )
        callback = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "cleanup_stale_operations"
        )
        self.assertTrue(
            any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "submit"
                and len(n.args) == 1
                and isinstance(n.args[0], ast.Name)
                and n.args[0].id == "cleanup_stale_operations_on_loop"
                for n in ast.walk(callback)
            )
        )

    def test_metrics_collection_is_NOT_guarded(self):
        """Load-bearing negative — see the module docstring.

        `collect_gauge_metrics` populates this pod's Prometheus registry. Guarding it
        would leave the losing pod serving no
        `vnbui_backup_last_success_age_seconds`, which is the staleness gauge the
        internal-DR recurrence detection depends on.
        """
        tree = ast.parse(open(os.path.join(BACKEND, "core", "metrics.py")).read())
        guarded = any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "cluster_singleton"
            for n in ast.walk(tree)
        )
        self.assertFalse(
            guarded, "collect_gauge_metrics must stay per-pod; see the docstring"
        )


class GuardSurvivesAFailingBody(unittest.TestCase):
    def test_exception_inside_the_block_propagates_and_still_releases(self):
        with self.assertRaises(ValueError):
            with cluster_singleton("boom", engine=SQLITE) as acquired:
                self.assertTrue(acquired)
                raise ValueError("body failed")
        # A leaked lock would make the next acquisition fail on Postgres; on SQLite
        # this asserts the context manager's finally ran without raising.
        with cluster_singleton("boom", engine=SQLITE) as acquired:
            self.assertTrue(acquired)


if __name__ == "__main__":
    unittest.main(verbosity=2)
