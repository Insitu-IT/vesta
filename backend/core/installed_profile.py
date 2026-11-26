"""Installed code and authentication scope, independent of advisory licenses."""

from dataclasses import dataclass
import json
import os
from typing import Mapping

from core.vesta_environment import vesta_env

MODULES = frozenset({"multi_tenancy", "billing_api", "white_labeling"})
AUTH_MODES = frozenset({"single_organization", "multi_organization"})


@dataclass(frozen=True)
class InstalledProfile:
    edition: str = "community"
    auth_mode: str = "single_organization"
    enabled_modules: frozenset[str] = frozenset()

    def __post_init__(self):
        if type(self.edition) is not str or self.edition not in {
            "community",
            "commercial",
        }:
            raise ValueError("VESTA_EDITION must be community or commercial")
        if type(self.auth_mode) is not str or self.auth_mode not in AUTH_MODES:
            raise ValueError("Invalid VESTA_AUTH_MODE")
        if (
            not isinstance(self.enabled_modules, frozenset)
            or not self.enabled_modules <= MODULES
        ):
            raise ValueError("Unsupported installed module")
        if self.edition == "community" and (
            self.enabled_modules or self.auth_mode != "single_organization"
        ):
            raise ValueError(
                "Community requires single_organization and no commercial modules"
            )
        if (self.auth_mode == "multi_organization") != (
            "multi_tenancy" in self.enabled_modules
        ):
            raise ValueError(
                "multi_organization requires the configured multi_tenancy module"
            )

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None):
        values = os.environ if environ is None else environ
        artifact = vesta_env("ARTIFACT_EDITION", "community", environ=values)
        if artifact not in {"community", "commercial"}:
            raise ValueError("Invalid VESTA_ARTIFACT_EDITION")
        if artifact == "commercial" and not all(
            vesta_env(key, environ=values) is not None
            for key in ("EDITION", "AUTH_MODE", "ENABLED_MODULES")
        ):
            raise ValueError(
                "Commercial artifact requires explicit installed edition, auth mode and enabled modules"
            )
        edition = vesta_env("EDITION", "community", environ=values)
        if edition != artifact:
            raise ValueError("Installed edition must match VESTA_ARTIFACT_EDITION")
        try:
            modules = json.loads(vesta_env("ENABLED_MODULES", "[]", environ=values))
        except (TypeError, ValueError) as exc:
            raise ValueError("VESTA_ENABLED_MODULES must be a JSON array") from exc
        if (
            type(modules) is not list
            or any(type(item) is not str for item in modules)
            or len(modules) != len(set(modules))
        ):
            raise ValueError("VESTA_ENABLED_MODULES must contain distinct module names")
        return cls(
            edition,
            vesta_env("AUTH_MODE", "single_organization", environ=values),
            frozenset(modules),
        )

    def public(self):
        return {
            "edition": self.edition,
            "auth_mode": self.auth_mode,
            "enabled_modules": sorted(self.enabled_modules),
        }
