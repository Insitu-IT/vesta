"""
Password Validation

Validates passwords against configurable rules from settings.
"""

import re
from typing import Tuple, List
from sqlalchemy.orm import Session

from .settings_reader import get_setting


def validate_password(password: str, db: Session = None) -> Tuple[bool, List[str]]:
    """
    Validate a password against configured rules.

    Args:
        password: The password to validate
        db: Optional database session for reading settings

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Get configuration from settings
    min_length = get_setting("security", "password_min_length", 8, "integer", db)
    require_complexity = get_setting(
        "security", "require_password_complexity", True, "boolean", db
    )

    # Check minimum length
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")

    # Check complexity if required
    if require_complexity:
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")

    return (len(errors) == 0, errors)


def get_password_requirements(db: Session = None) -> dict:
    """
    Get current password requirements for display to users.

    Args:
        db: Optional database session

    Returns:
        Dictionary describing password requirements
    """
    min_length = get_setting("security", "password_min_length", 8, "integer", db)
    require_complexity = get_setting(
        "security", "require_password_complexity", True, "boolean", db
    )

    requirements = {
        "min_length": min_length,
        "require_complexity": require_complexity,
        "rules": [f"At least {min_length} characters"],
    }

    if require_complexity:
        requirements["rules"].extend(
            [
                "At least one lowercase letter",
                "At least one uppercase letter",
                "At least one number",
                'At least one special character (!@#$%^&*(),.?":{}|<>)',
            ]
        )

    return requirements
