"""Fail-closed loading for commercial capability implementations."""

from dataclasses import dataclass
from importlib import import_module
from typing import Callable

from fastapi import FastAPI

from core.licensing import FeatureFlags


class CommercialModuleLoadError(RuntimeError):
    """A configured commercial capability could not be loaded."""


@dataclass(frozen=True)
class CommercialModule:
    feature: str
    import_path: str
    initializer: str


COMMERCIAL_MODULES = (
    CommercialModule(
        "multi_tenancy",
        "commercial.backend.modules.multi_tenant",
        "init_multi_tenancy",
    ),
    CommercialModule(
        "billing_api", "commercial.backend.modules.billing", "init_billing"
    ),
    CommercialModule(
        "white_labeling",
        "commercial.backend.modules.white_label",
        "init_white_labeling",
    ),
)


def load_commercial_modules(app: FastAPI, features: FeatureFlags) -> list[str]:
    """Load every configured module, failing startup when any implementation fails."""
    loaded = []
    for spec in COMMERCIAL_MODULES:
        if not features.is_requested(spec.feature):
            continue
        try:
            module = import_module(spec.import_path)
            initializer: Callable[[FastAPI], None] = getattr(module, spec.initializer)
            initializer(app)
            features.activate(spec.feature)
            loaded.append(spec.feature)
        except Exception as exc:
            raise CommercialModuleLoadError(
                f"Configured feature '{spec.feature}' could not load from "
                f"{spec.import_path}: {exc}"
            ) from exc
    unavailable = features.profile.enabled_modules - set(loaded)
    if unavailable:
        raise CommercialModuleLoadError(
            "Configured modules have no implementation: "
            + ", ".join(sorted(unavailable))
        )
    return loaded
