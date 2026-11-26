"""
Database configuration and session management
"""

from contextlib import contextmanager, asynccontextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker, Session  # noqa: F401
from sqlalchemy.pool import QueuePool
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import logging

from config import settings
from core.postgres_profile import connection_parameters

logger = logging.getLogger(__name__)

# Base class for models
from models import Base  # noqa: E402,F401


# Synchronous engine (for existing code compatibility)
def sync_connect_args(database_url: str) -> dict:
    """Bound lock waits in synchronous handlers that still share the API loop.

    A contended row lock must fail the current transaction, not block liveness
    until kubelet kills an otherwise healthy process. PostgreSQL applies this
    at connection startup, so a rollback cannot silently clear the bound.
    """
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql":
        return {}
    existing = url.query.get("options", "")
    if not isinstance(existing, str):
        raise ValueError("PostgreSQL connection options must be a string")
    return {"options": (existing + " -c lock_timeout=5s").strip()}


sync_url, profile_connect_args = connection_parameters(settings.database_url)
sync_engine = create_engine(
    sync_url,
    connect_args={**sync_connect_args(sync_url), **profile_connect_args},
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=40,
    pool_timeout=30,
    pool_recycle=3600,
    pool_pre_ping=True,  # Verify connections before using
    echo=settings.debug,
)

# Async engine for new async endpoints
async_url, async_profile_connect_args = connection_parameters(
    settings.async_database_url, asynchronous=True
)
async_engine = create_async_engine(
    async_url,
    connect_args=async_profile_connect_args,
    pool_size=20,
    max_overflow=40,
    pool_timeout=30,
    pool_recycle=3600,
    pool_pre_ping=True,
    echo=settings.debug,
)

from core.tenant_database import install_tenant_enforcement, TenantSession  # noqa: E402

install_tenant_enforcement(sync_engine)
install_tenant_enforcement(async_engine.sync_engine)

# Session factories
SyncSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=sync_engine, class_=TenantSession
)

# Alias for backward compatibility
SessionLocal = SyncSessionLocal

AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    sync_session_class=TenantSession,
    expire_on_commit=False,
)


# Add query logging in debug mode
if settings.debug:

    @event.listens_for(sync_engine, "before_cursor_execute")
    def receive_before_cursor_execute(
        conn, cursor, statement, params, context, executemany
    ):
        logger.debug(f"Query: {statement}")
        logger.debug(f"Params: {params}")


@contextmanager
def get_db_transaction():
    """
    Synchronous transaction context manager with automatic commit/rollback

    Usage:
        with get_db_transaction() as db:
            # do database operations
            # automatically commits on success, rolls back on exception
    """
    db = SyncSessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        logger.error(f"Transaction rollback: {e}")
        db.rollback()
        raise
    finally:
        db.close()


@asynccontextmanager
async def get_async_db_transaction():
    """
    Async transaction context manager with automatic commit/rollback

    Usage:
        async with get_async_db_transaction() as db:
            # do async database operations
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            logger.error(f"Async transaction rollback: {e}")
            await session.rollback()
            raise


# FastAPI dependencies
def get_db():
    """
    Synchronous database dependency for FastAPI

    Usage:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()

    Multi-tenancy: Automatically sets RLS context from tenant_context
    """
    db = SyncSessionLocal()
    try:
        # SQL hooks require identity at the point of use. Opening a dependency
        # must not execute SQL before a login/agent path can establish identity.
        yield db
    finally:
        db.close()


async def get_async_db():
    """
    Async database dependency for FastAPI

    Usage:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_async_db)):
            result = await db.execute(select(Item))
            return result.scalars().all()
    """
    async with AsyncSessionLocal() as session:
        yield session


def init_db():
    """Validate the migrated schema; application startup never emits DDL."""
    from core.schema_parity import assert_schema_current

    with sync_engine.connect() as connection:
        assert_schema_current(connection)


async def init_async_db():
    """Validate the same schema from an async connection."""
    from core.schema_parity import assert_schema_current

    async with async_engine.begin() as conn:
        await conn.run_sync(assert_schema_current)
