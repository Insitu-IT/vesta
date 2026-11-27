"""
FastAPI routers for vnbui API.

Each router handles a specific domain of the API.
"""

from routers.auth import router as auth_router
from routers.agents import router as agents_router
from routers.backups import router as backups_router
from routers.schedules import router as schedules_router
from routers.file_backups import router as file_backups_router
from routers.groups import router as groups_router
from routers.users import router as users_router
from routers.health import router as health_router
from routers.reports import router as reports_router
from routers.restores import router as restores_router
from routers.config import router as config_router
from routers.activity import router as activity_router
from routers.api_keys import router as api_keys_router
from routers.public import router as public_router
from routers.licensing import router as licensing_router
from routers.stats import router as stats_router
from routers.bulk import router as bulk_router
from routers.queue import router as queue_router
from routers.notifications import router as notifications_router
from routers.search import router as search_router
from routers.dashboard import router as dashboard_router
from routers.verification import router as verification_router
from routers.realtime import router as realtime_router
from routers.encryption import router as encryption_router
from routers.pki import router as pki_router
from routers.s3_import import router as s3_import_router
from routers.recovery_trust import router as recovery_trust_router
from routers.demo import router as demo_router
from routers.operator import router as operator_router

__all__ = [
    "auth_router",
    "agents_router",
    "backups_router",
    "schedules_router",
    "file_backups_router",
    "groups_router",
    "users_router",
    "health_router",
    "reports_router",
    "restores_router",
    "config_router",
    "activity_router",
    "api_keys_router",
    "public_router",
    "licensing_router",
    "stats_router",
    "bulk_router",
    "queue_router",
    "notifications_router",
    "search_router",
    "dashboard_router",
    "verification_router",
    "realtime_router",
    "encryption_router",
    "pki_router",
    "s3_import_router",
    "recovery_trust_router",
    "demo_router",
    "operator_router",
]
