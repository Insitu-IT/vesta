"""Cluster-singleton guard for scheduled jobs (#47).

WHY THIS EXISTS. The backend runs `replicas: 2` in prod
(`okd/vnbui/overlays/prod/backend-replicas.yaml`) and `scheduler.py` starts a
`BackgroundScheduler` at module import, so **every pod runs every scheduled job**.
Measured on 2026-07-30: both pods logged `run_retention_enforcement` at the same
cron instant, `03:00:00+00:00`. That is fine for per-pod work and wrong for
cluster-singleton work.

`#42` consolidated two schedulers inside one *process*; this is one scheduler per
*pod*, which that change does not reach and was never meant to.

WHAT IS AND IS NOT SINGLETON — the distinction is the whole design, because the
obvious remedy (gate the scheduler to one replica) breaks the second column:

    singleton   execute_scheduled_backup   two pods -> two backups per VM per fire
    singleton   run_retention_enforcement  two pods -> concurrent deletion passes
    singleton   cleanup_stale_operations   two pods -> duplicate failure notifications
    PER-POD     collect_gauge_metrics      each pod MUST populate its own Prometheus
                                           registry; scoping it to one pod blanks the
                                           other's /metrics, including the
                                           vnbui_backup_last_success_age_seconds
                                           staleness gauge the internal-DR work relies
                                           on for recurrence detection.

So the guard is applied per job body, never to the scheduler as a whole.

THAT LAST ROW REACHES OUTSIDE THIS REPO, which is why it is a test and not a note.
The vnbui Prometheus connector in `okd/monitoring-integrations` scrapes `/metrics`
and pushes to the Zabbix trapper on monitor01, so the staleness gauge is on the
alerting path as well. Gating the scheduler wholesale to one replica would blank it
on whichever pod the connector happened to hit — an intermittent, pod-dependent
monitoring gap rather than a clean outage, which is far harder to notice than a
missing alert. (gf-sre, 2026-07-30.)

MECHANISM. A Postgres session-level advisory lock, keyed per job name. Whichever
pod wins runs the body; the other returns immediately and logs at debug. The
database is already the coordination point, so this needs no new infrastructure
and survives rescheduling and scale changes with no configuration.

The lock is SESSION-scoped rather than transaction-scoped on purpose: these job
bodies commit several times, and a transaction-scoped lock
(`pg_advisory_xact_lock`) would be released at the first commit, part-way through
the work it is meant to serialise. Session scope means it is held on one dedicated
connection for the whole body and released in a `finally`.

THE PRICE OF SESSION SCOPE IS A POOL HAZARD, AND IT FAILS QUIETLY. A session-level
lock lives on the *connection*, and `Connection.close()` returns that connection to
the pool rather than ending the Postgres session — so a lock that is not explicitly
released outlives the job. The next caller to check out that same pooled connection
finds the lock held by itself and skips; every fire after that skips too, and the
job silently never runs again. There is no double-run in that state, so it passes a
"did the duplicates stop" check perfectly while the work quietly stops happening.
The release path below therefore checks `pg_advisory_unlock`'s return value and
invalidates the connection if it did not release, rather than trusting `close()`.

WHY NOT `pg_advisory_xact_lock`, which is immune to that by construction: it would
be released at the first of these bodies' several commits. Structural immunity to
the pool hazard is not worth losing the property the lock exists for.

NON-POSTGRES IS A DELIBERATE NO-OP. The unit suite runs on in-memory SQLite, which
has no advisory locks, and a single-process deployment has nothing to serialise
against. On any non-Postgres dialect this yields True — "you hold it, proceed" —
rather than failing closed, because failing closed there would silently disable
retention and scheduled backups in exactly the environments that have only one
writer anyway.
"""

import hashlib
import logging
from contextlib import contextmanager

from sqlalchemy import text

from core.tenant_context import PlatformContext

logger = logging.getLogger(__name__)

# Namespace so these keys cannot collide with an advisory lock taken elsewhere
# against the same database.
_NAMESPACE = "vnbui.scheduler."

# Postgres advisory-lock keys are signed 64-bit.
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def lock_key(job_name: str) -> int:
    """Stable signed-64-bit key for a job name.

    MUST be stable across processes. Python's built-in `hash()` on a str is salted
    per interpreter (PYTHONHASHSEED), so two pods would derive DIFFERENT keys, both
    acquire, and the guard would silently do nothing — while looking correct in a
    single-process test. blake2b is deterministic everywhere.
    """
    digest = hashlib.blake2b(
        (_NAMESPACE + job_name).encode("utf-8"), digest_size=8
    ).digest()
    value = int.from_bytes(digest, "big", signed=True)
    # int.from_bytes(signed=True) over 8 bytes is already in range; assert rather
    # than clamp, so a future digest_size change fails loudly instead of aliasing
    # two job names onto one key.
    assert _INT64_MIN <= value <= _INT64_MAX, f"lock key out of range: {value}"
    return value


@contextmanager
def cluster_singleton(job_name: str, engine=None):
    """Yield True if this process may run `job_name`, False if another holds it.

    Usage:

        with cluster_singleton("retention_enforcement") as acquired:
            if not acquired:
                return
            ...work...

    `engine` is injectable for tests. It defaults to `database.sync_engine`, which
    is the engine the job bodies' `SessionLocal` is bound to — the guard takes its
    own connection from that pool deliberately, because a session-level lock has to
    live on a connection nobody else will return to the pool mid-body.

    FAILS OPEN, LOUDLY. If the lock cannot be taken — DB unreachable, permission
    denied, pool exhausted — this yields True with a warning rather than raising.
    Two reasons: a guard that raises would break the very job it protects, and a
    job body that needs the database is going to fail on its own a moment later
    anyway, where that failure is already handled. The warning is not decorative:
    a run of these in the log means duplicate suppression is not in effect.
    """
    if engine is None:
        from database import sync_engine as engine

    if engine.dialect.name != "postgresql":
        # Single-writer or test environment — see the module docstring.
        yield True
        return

    key = lock_key(job_name)
    conn = None
    acquired = False
    try:
        try:
            # Installation coordination has no tenant. Keep its authority on
            # this dedicated connection, never around the yielded job body.
            with PlatformContext():
                conn = engine.connect()
                acquired = bool(
                    conn.execute(
                        text("SELECT pg_try_advisory_lock(:key)"), {"key": key}
                    ).scalar()
                )
                # Session locks survive rollback; transaction-local identity
                # must not remain installed while the tenant work executes.
                conn.rollback()
        except Exception:
            logger.warning(
                "cluster_singleton: could not take the lock for %s — running "
                "UNGUARDED, so a concurrent replica may duplicate this job",
                job_name,
                exc_info=True,
            )
            yield True
            return

        if not acquired:
            logger.debug(
                "cluster_singleton: another instance holds %s (key=%s); skipping",
                job_name,
                key,
            )
        yield acquired
    finally:
        if conn is not None:
            released = False
            if acquired:
                try:
                    with PlatformContext():
                        released = bool(
                            conn.execute(
                                text("SELECT pg_advisory_unlock(:key)"), {"key": key}
                            ).scalar()
                        )
                        conn.rollback()
                except Exception:
                    released = False
                    logger.warning(
                        "cluster_singleton: unlock raised for %s",
                        job_name,
                        exc_info=True,
                    )

            if acquired and not released:
                # DO NOT hand a lock-holding session back to the pool.
                #
                # conn.close() on a SQLAlchemy Connection RETURNS the DBAPI
                # connection to the pool; it does not end the Postgres session. A
                # session-level advisory lock therefore survives it, and the next
                # caller to check out that same pooled connection finds the lock
                # already held — by itself — and every subsequent fire skips. The
                # job then silently never runs again.
                #
                # Note which way that fails: there is no double-run, so it passes a
                # "did we stop the duplicates" check perfectly while the work
                # quietly stops happening. invalidate() drops the physical
                # connection, which ends the session and releases the lock for
                # certain. (Caught in review by gf-sre; an earlier version of this
                # comment claimed close() was sufficient, which is wrong.)
                logger.warning(
                    "cluster_singleton: %s not released (unlock returned false); "
                    "discarding the connection so the lock cannot outlive the job",
                    job_name,
                )
                conn.invalidate()
            conn.close()
