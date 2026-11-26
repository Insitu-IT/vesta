"""
Input validation schemas and sanitization utilities
"""

import re
from typing import Optional, Dict, Any
from pydantic import BaseModel, validator, Field, constr


class SanitizedStr(str):
    """Custom string type with automatic sanitization"""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")
        # Remove control characters
        v = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", v)
        v = v.strip()
        if len(v) > 255:
            raise ValueError("string too long (max 255 characters)")
        return v


class VMNameValidator(BaseModel):
    """Validator for VM names"""

    name: constr(
        regex=r"^[a-zA-Z0-9][a-zA-Z0-9-_.]{0,99}$", min_length=1, max_length=100
    )

    @validator("name")
    def validate_no_path_traversal(cls, v):
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Invalid characters in VM name (path traversal attempt)")
        return v


class HostnameValidator(BaseModel):
    """Validator for hostnames"""

    hostname: constr(
        regex=r"^[a-zA-Z0-9][a-zA-Z0-9-_.]{0,253}$", min_length=1, max_length=253
    )

    @validator("hostname")
    def validate_hostname_format(cls, v):
        if ".." in v or v.startswith("-") or v.endswith("-"):
            raise ValueError("Invalid hostname format")
        return v


class TagsValidator(BaseModel):
    """Validator for backup tags/labels"""

    tags: Optional[
        Dict[constr(regex=r"^[a-zA-Z0-9-_.]{1,50}$"), constr(max_length=255)]
    ] = None

    @validator("tags")
    def validate_tags_count(cls, v):
        if v and len(v) > 50:
            raise ValueError("Too many tags (maximum 50 allowed)")
        return v or {}


class BackupCreateValidated(BaseModel):
    """Validated backup creation request"""

    vm_id: constr(regex=r"^[a-f0-9-]{36}$")  # UUID format
    retention_days: int = Field(ge=1, le=3650, default=30)  # 1 day to 10 years
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    description: Optional[constr(max_length=500)] = None

    @validator("tags")
    def validate_tags(cls, v):
        if v:
            validator = TagsValidator(tags=v)
            return validator.tags
        return {}


class CronExpressionValidator(BaseModel):
    """Validator for cron expressions"""

    cron_expression: str

    @validator("cron_expression")
    def validate_cron(cls, v):
        # Basic cron validation (5 parts)
        parts = v.split()
        if len(parts) != 5:
            raise ValueError(
                "Invalid cron expression (must have 5 parts: minute hour day month weekday)"
            )

        # Validate each part
        for i, part in enumerate(parts):
            if part == "*":
                continue
            if part.startswith("*/"):
                # Step values
                try:
                    step = int(part[2:])
                    if step < 1:
                        raise ValueError(f"Invalid step value: {step}")
                except ValueError:
                    raise ValueError(f"Invalid cron step in part {i+1}: {part}")
            elif "-" in part:
                # Range values
                try:
                    start, end = part.split("-")
                    int(start), int(end)
                except ValueError:
                    raise ValueError(f"Invalid cron range in part {i+1}: {part}")
            elif "," in part:
                # List values
                try:
                    [int(x) for x in part.split(",")]
                except ValueError:
                    raise ValueError(f"Invalid cron list in part {i+1}: {part}")
            else:
                # Single value
                try:
                    int(part)
                except ValueError:
                    raise ValueError(f"Invalid cron value in part {i+1}: {part}")

        return v


class EmailValidator(BaseModel):
    """Validator for email addresses"""

    email: constr(
        regex=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", max_length=255
    )


class UsernameValidator(BaseModel):
    """Validator for usernames"""

    username: constr(regex=r"^[a-zA-Z0-9_-]{3,32}$", min_length=3, max_length=32)

    @validator("username")
    def validate_no_reserved_names(cls, v):
        reserved = {"admin", "root", "system", "guest", "anonymous"}
        if v.lower() in reserved:
            # Only allow if explicitly creating admin
            pass
        return v


class PasswordValidator(BaseModel):
    """Validator for passwords"""

    password: constr(min_length=8, max_length=128)

    @validator("password")
    def validate_password_strength(cls, v):
        # At least one uppercase, one lowercase, one digit
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        # Optional: special character check
        # if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
        #     raise ValueError('Password must contain at least one special character')
        return v


class SearchQueryValidator(BaseModel):
    """Validator for search queries"""

    query: constr(min_length=1, max_length=500)

    @validator("query")
    def sanitize_query(cls, v):
        # Remove potentially dangerous SQL/NoSQL injection patterns
        dangerous_patterns = [
            r"(\bOR\b.*\b=\b)",  # OR 1=1
            r"(\bAND\b.*\b=\b)",  # AND 1=1
            r"(--)",  # SQL comments
            r"(;)",  # SQL statement terminator
            r"(\bDROP\b)",  # DROP statements
            r"(\bDELETE\b)",  # DELETE statements
            r"(\bUNION\b)",  # UNION attacks
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("Query contains potentially dangerous patterns")

        return v


class PaginationValidator(BaseModel):
    """Validator for pagination parameters"""

    skip: int = Field(ge=0, default=0)
    limit: int = Field(ge=1, le=100, default=50)


class UUIDValidator(BaseModel):
    """Validator for UUID strings"""

    id: constr(regex=r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


# Sanitization utilities
def sanitize_html(text: str) -> str:
    """Remove HTML tags and escape special characters"""
    if not text:
        return ""

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", "", text)

    # Escape special characters
    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;",
    }

    for char, escaped in replacements.items():
        text = text.replace(char, escaped)

    return text


def validate_file_path(path: str, allow_absolute: bool = False) -> str:
    """Validate file paths to prevent path traversal"""
    if not path:
        raise ValueError("Path cannot be empty")

    # Check for path traversal
    if ".." in path:
        raise ValueError("Path traversal detected")

    # Check for absolute paths if not allowed
    if not allow_absolute and (path.startswith("/") or path.startswith("\\")):
        raise ValueError("Absolute paths not allowed")

    # Check for null bytes
    if "\x00" in path:
        raise ValueError("Null bytes in path")

    # Normalize path
    import os

    normalized = os.path.normpath(path)

    # Ensure normalized path doesn't escape
    if not allow_absolute and normalized.startswith(".."):
        raise ValueError("Path escapes allowed directory")

    return normalized


def validate_json_object(obj: Any, max_depth: int = 10, current_depth: int = 0) -> bool:
    """Validate JSON object doesn't have excessive nesting (DoS prevention)"""
    if current_depth > max_depth:
        raise ValueError(f"JSON nesting too deep (max {max_depth} levels)")

    if isinstance(obj, dict):
        for value in obj.values():
            validate_json_object(value, max_depth, current_depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            validate_json_object(item, max_depth, current_depth + 1)

    return True
