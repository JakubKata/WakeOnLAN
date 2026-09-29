"""Input rules. Each function returns the normalized value or raises CommandError."""

import re
import unicodedata

from .errors import CommandError
from .protocol import Err

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,32}")
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]+")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")
RESET_CODE_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{10}")
RESET_CODE_SEPARATORS_RE = re.compile(r"[\s-]")
MAC_SEPARATORS_RE = re.compile(r"[:.-]")
MAC_HEX_RE = re.compile(r"[0-9A-F]{12}")

MAX_EMAIL_LENGTH = 254
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MAX_LABEL_LENGTH = 64
MAX_RECORD_ID = 2**63 - 1
ZERO_WIDTH_JOINER = "\u200d"


def has_other_characters(value: str) -> bool:
    """Unicode category C: controls, surrogates, private use, unassigned and format characters."""
    return any(unicodedata.category(char).startswith("C") for char in value)


def is_username(value: str) -> bool:
    return USERNAME_RE.fullmatch(value) is not None


def username(value: str) -> str:
    if not is_username(value):
        raise CommandError(Err.INVALID_NAME)
    return value


def email(value: str) -> str:
    value = value.strip()
    if len(value) > MAX_EMAIL_LENGTH or not EMAIL_RE.fullmatch(value) or has_other_characters(value):
        raise CommandError(Err.INVALID_EMAIL)
    return value


def password(value: str) -> str:
    if not MIN_PASSWORD_LENGTH <= len(value) <= MAX_PASSWORD_LENGTH or not value.strip():
        raise CommandError(Err.WEAK_PASSWORD)
    return value


def label(value: str) -> str:
    """A user-visible name for a device or target."""
    value = unicodedata.normalize("NFC", value).strip()
    if not 1 <= len(value) <= MAX_LABEL_LENGTH:
        raise CommandError(Err.INVALID_LABEL)
    # The joiner is a format character, but multi-person and profession emoji sequences need it.
    if has_other_characters(value.replace(ZERO_WIDTH_JOINER, "")):
        raise CommandError(Err.INVALID_LABEL)
    return value


def mac(value: str) -> str:
    """Accept AA:BB:CC:DD:EE:FF, AA-BB-..., AABB.CCDD.EEFF or AABBCCDDEEFF."""
    digits = MAC_SEPARATORS_RE.sub("", value.strip()).upper()
    if not MAC_HEX_RE.fullmatch(digits) or int(digits[:2], 16) & 0x01:
        raise CommandError(Err.INVALID_MAC)
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def record_id(value: int) -> int:
    """A database id; anything outside the bigint range cannot exist."""
    if not 1 <= value <= MAX_RECORD_ID:
        raise CommandError(Err.NOT_FOUND)
    return value


def is_token(value: str) -> bool:
    return TOKEN_RE.fullmatch(value) is not None


def token(value: str) -> str:
    if not is_token(value):
        raise CommandError(Err.INVALID_TOKEN)
    return value


def device_id(value: str) -> str:
    """Device ids are server-issued tokens; anything else cannot exist."""
    if not is_token(value):
        raise CommandError(Err.NOT_FOUND)
    return value


def reset_code(value: str) -> str:
    """Accept the code as typed: any case, with spaces or dashes; O/I/L read as 0/1/1."""
    code = RESET_CODE_SEPARATORS_RE.sub("", value).upper()
    code = code.translate(str.maketrans("OIL", "011"))
    if not RESET_CODE_RE.fullmatch(code):
        raise CommandError(Err.INVALID_TOKEN)
    return code
