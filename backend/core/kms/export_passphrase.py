"""Structural passphrase requirements for creating recovery exports."""

import unicodedata

MIN_EXPORT_PASSPHRASE_LENGTH = 20
MAX_EXPORT_PASSPHRASE_BYTES = 4096
MAX_TRIVIAL_PERIOD = 8

# These blank glyphs have a letter or symbol category. Compatibility forms
# of the Hangul fillers normalize to the two characters listed here.
_BLANK_FILLERS = {"\u115f", "\u1160", "\u2800"}


class ExportPassphraseError(ValueError):
    """An invalid passphrase for a new export."""


def require_export_passphrase(passphrase: str) -> None:
    """Validate a normalized view while preserving the original KDF input."""
    try:
        byte_count = len(passphrase.encode("utf-8"))
    except UnicodeEncodeError:
        raise ExportPassphraseError("Export passphrase must be valid UTF-8") from None
    if byte_count > MAX_EXPORT_PASSPHRASE_BYTES:
        raise ExportPassphraseError("Export passphrase exceeds 4,096 UTF-8 bytes")
    normalized = unicodedata.normalize("NFKC", passphrase)
    visible = "".join(
        character
        for character in normalized
        if unicodedata.category(character)[0] in "LNPS"
        and character not in _BLANK_FILLERS
    )
    if len(visible) < MIN_EXPORT_PASSPHRASE_LENGTH:
        raise ExportPassphraseError(
            f"Export passphrase must contain at least {MIN_EXPORT_PASSPHRASE_LENGTH} "
            "significant characters"
        )

    pattern = visible.lower()
    if any(
        all(
            character == pattern[index % period]
            for index, character in enumerate(pattern)
        )
        for period in range(1, MAX_TRIVIAL_PERIOD + 1)
    ):
        raise ExportPassphraseError(
            "Export passphrase must not use a short repeated pattern"
        )
