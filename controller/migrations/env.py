"""
Alembic migrations environment
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Add parent to path for models
# .../controller/migrations/env.py -> .../controller/migrations -> .../controller -> .../
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import models for autogenerate
try:
    from controller.db.extensions import db
    from controller.db.models import *  # noqa: F401, F403

    target_metadata = db.Model.metadata
except ImportError:
    target_metadata = None


def get_url():
    """Get database URL from environment or config"""
    return os.environ.get(
        "CONTROLLER_DATABASE_URL",
        os.environ.get("DATABASE_URL", config.get_main_option("sqlalchemy.url")),
    )


def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
