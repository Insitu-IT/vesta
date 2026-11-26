"""Response validation with an explicit RFC3339 check, including minimal installs."""

from datetime import datetime
import re

from jsonschema import FormatChecker


def contract_format_checker():
    checker = FormatChecker()

    @checker.checks("date-time")
    def date_time(value):
        if not isinstance(value, str):
            return True
        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})",
            value,
        ):
            return False
        try:
            normalized = value.upper()
            # RFC3339 permits leap seconds; Python's calendar parser does not.
            if normalized[17:19] == "60":
                normalized = normalized[:17] + "59" + normalized[19:]
            parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
            return parsed.utcoffset() is not None
        except ValueError:
            return False

    return checker
