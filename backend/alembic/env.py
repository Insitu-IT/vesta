"""
Alembic environment configuration
"""

from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import your models and Base
from models import Base
from config import settings
from core.schema_parity import _include_object
from core.postgres_profile import connection_parameters

from core.vesta_environment import vesta_encryption_key

# Historical revisions still read this name directly.
migration_encryption_key = vesta_encryption_key()
if migration_encryption_key is not None:
    os.environ["VNBUI_ENCRYPTION_KEY"] = migration_encryption_key

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None and config.attributes.get("connection") is None:
    fileConfig(config.config_file_name)

# Set sqlalchemy.url from settings
config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))

# add your model's MetaData object here for 'autogenerate' support
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_object=_include_object,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    # Explicit operator stage owns the connection, lock and final commit. The
    # standalone Alembic CLI path below guards its independently opened connection.
    supplied = config.attributes.get("connection")
    if supplied is not None:
        context.configure(
            connection=supplied,
            target_metadata=target_metadata,
            include_object=_include_object,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        return
    url, connect_args = connection_parameters(settings.database_url)
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = url
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=connect_args,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=_include_object,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
