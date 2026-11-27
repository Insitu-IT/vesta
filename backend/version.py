"""
Centralized version management for vnbui backend
Single source of truth for version information

Semantic Versioning Policy:
- MAJOR: Breaking changes (all components must upgrade together)
- MINOR: New features, backward compatible (safe within same MAJOR)
- PATCH: Corrections within the supported protocol; follow documented backend
  and schema prerequisites before upgrading dependent agents.
"""

__version__ = "6.2.0"
__build_date__ = "2026-11-27"
API_SERVICE_NAME = "vesta-api"
# The published OpenAPI revision changes when the operator contract changes.
OPERATOR_API_VERSION = "6.2.0"


def parse_version(version_string: str) -> dict:
    """Parse version string into components"""
    try:
        parts = version_string.split(".")
        return {
            "version": version_string,
            "major": int(parts[0]) if len(parts) > 0 else 0,
            "minor": int(parts[1]) if len(parts) > 1 else 0,
            "patch": (
                int(parts[2].split("-")[0]) if len(parts) > 2 else 0
            ),  # Handle 2.4.0-beta
        }
    except (ValueError, IndexError):
        return {"version": version_string, "major": 0, "minor": 0, "patch": 0}


def check_compatibility(other_version: str) -> dict:
    """
    Check if another component version is compatible with this API.

    Returns:
        dict with 'compatible', 'status', and 'reason' fields
    """
    api = parse_version(__version__)
    other = parse_version(other_version)

    # MAJOR must match
    if api["major"] != other["major"]:
        return {
            "compatible": False,
            "status": "incompatible",
            "reason": f"Major version mismatch: API {api['major']}.x vs {other['major']}.x",
        }

    # MINOR should match for full compatibility
    if api["minor"] != other["minor"]:
        return {
            "compatible": True,  # Still works, but degraded
            "status": "degraded",
            "reason": (
                f"Minor version mismatch: API {api['major']}.{api['minor']}.x"
                f" vs {other['major']}.{other['minor']}.x"
            ),
        }

    # PATCH can differ freely
    return {"compatible": True, "status": "aligned", "reason": None}


def get_version_info():
    """Get complete version information"""
    parsed = parse_version(__version__)
    return {
        "version": __version__,
        "major": parsed["major"],
        "minor": parsed["minor"],
        "patch": parsed["patch"],
        "service": API_SERVICE_NAME,
        "build_date": __build_date__,
        "expected_compatible": f"{parsed['major']}.{parsed['minor']}.x",
        "features": {
            "key_management": True,
            "agent_lifecycle": True,
            "custom_ca_support": True,
            "multi_key_authentication": True,
            "virtnbdbackup_advanced_options": True,  # v2.4.0
            "agent_remote_config": True,  # v2.5.0
        },
    }
