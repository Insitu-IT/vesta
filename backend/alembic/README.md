# Database Migrations with Alembic

This directory contains database migrations for Vesta using Alembic.

## Quick Start

### First Time Setup

```bash
# From project root
./migrate.sh init
```

### Mark Current Database as Up-to-Date (For Existing MVP)

If you already have the MVP database running with all tables:

```bash
# This tells Alembic "the database is already at migration 001_initial"
./migrate.sh stamp
```

### Creating a New Migration

When you modify models.py:

```bash
# Create a migration (Alembic will auto-detect changes)
./migrate.sh create "Add retention_days to backups"

# Review the generated migration in alembic/versions/
# Then apply it:
./migrate.sh upgrade
```

### Applying Migrations

```bash
# Apply all pending migrations
./migrate.sh upgrade
```

### Checking Status

```bash
# See current migration version
./migrate.sh status

# See all migrations
./migrate.sh history
```

### Rolling Back (Be Careful!)

```bash
# Undo the last migration
./migrate.sh downgrade
```

## Migration Workflow

### Example: Adding a New Field

1. **Modify the model**:
```python
# backend/models.py
class Backup(Base):
    # ... existing fields ...
    retention_days = Column(Integer, default=30)  # NEW FIELD
```

2. **Create migration**:
```bash
./migrate.sh create "Add retention_days to Backup"
```

3. **Review generated migration**:
```bash
cat backend/alembic/versions/XXXXXX_add_retention_days_to_backup.py
```

4. **Apply migration**:
```bash
./migrate.sh upgrade
```

5. **Verify in database**:
```bash
docker compose exec postgres psql -U "$DATABASE_USER" -d "$DATABASE_NAME" \
  -c "\d backups"
```

## Important Notes

### For MVP → Production Transition

The initial migration (`001_initial`) represents the MVP schema. When you already have:
- users table
- agents table
- vms table
- backups table

You should **stamp** the database instead of running the initial migration:

```bash
./migrate.sh stamp
```

This tells Alembic: "The database is already at version 001_initial, don't try to create these tables."

### Migration Best Practices

1. **Always review auto-generated migrations** - Alembic is smart but not perfect
2. **Test migrations on a copy of production data** before applying to prod
3. **Never edit applied migrations** - create a new migration instead
4. **Keep migrations small and focused** - one logical change per migration
5. **Add data migrations carefully** - test with real data volumes

### Common Operations

#### Renaming a column (requires manual edit):
```python
def upgrade():
    op.alter_column('backups', 'old_name',
                    new_column_name='new_name')
```

#### Adding an index:
```python
def upgrade():
    op.create_index('ix_backups_status', 'backups', ['status'])
```

#### Adding a constraint:
```python
def upgrade():
    op.create_check_constraint(
        'check_progress_range',
        'backups',
        'progress >= 0 AND progress <= 100'
    )
```

## Troubleshooting

### Migration fails with "table already exists"

The database already has tables, and you're running the initial migration:

```bash
# Solution: Mark database as current without running migrations
./migrate.sh stamp
```

### Can't import models

Make sure `alembic/env.py` has correct path:
```python
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from models import Base
```

### Migration doesn't detect changes

1. Make sure you saved models.py
2. Restart Python if running interactively
3. Check `target_metadata = Base.metadata` in env.py

## Directory Structure

```
alembic/
├── README.md                 # This file
├── env.py                    # Alembic configuration (imports models)
├── script.py.mako            # Template for new migrations
└── versions/                 # Migration files
    ├── 001_initial_...py     # Initial MVP schema
    ├── 002_add_retention.py  # Example future migration
    └── ...
```

## References

- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [Alembic Tutorial](https://alembic.sqlalchemy.org/en/latest/tutorial.html)
- [SQLAlchemy + Alembic Best Practices](https://alembic.sqlalchemy.org/en/latest/cookbook.html)
