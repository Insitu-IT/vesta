"""Read branded settings while retaining explicitly supported legacy inputs."""

import os


def vesta_env(setting, default=None, *, environ=None):
    """An explicitly configured Vesta value, including empty, takes precedence."""
    values = os.environ if environ is None else environ
    current = f"VESTA_{setting}"
    if current in values:
        return values[current]
    return values.get(f"VNBUI_{setting}", default)


def vesta_encryption_key():
    """Refuse ambiguous persistent key material without disclosing either value."""
    current = os.environ.get("VESTA_ENCRYPTION_KEY")
    legacy = os.environ.get("VNBUI_ENCRYPTION_KEY")
    if current is not None and legacy is not None and current != legacy:
        raise ValueError(
            "VESTA_ENCRYPTION_KEY conflicts with the legacy encryption key setting"
        )
    return legacy if current is None else current
