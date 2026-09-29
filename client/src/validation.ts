// Mirrors server/wol_server/validation.py so forms can reject input before a round trip.

import { t } from "@/i18n";

const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$/;
// Unicode category C (control, format, surrogate, private use, unassigned), as rejected by the server.
const OTHER_CHARACTER_RE = /\p{C}/u;
// Labels may contain the zero-width joiner, which emoji sequences need.
const ZERO_WIDTH_JOINER_RE = /\u200D/g;

export function usernameError(value: string): string | null {
  return USERNAME_RE.test(value) ? null : t.validation.username;
}

export function emailError(value: string): string | null {
  const trimmed = value.trim();
  const valid = trimmed.length <= 254 && EMAIL_RE.test(trimmed) && !OTHER_CHARACTER_RE.test(trimmed);
  return valid ? null : t.validation.email;
}

const RESET_CODE_RE = /^[0-9A-HJKMNP-TV-Z]{10}$/;

/** Length in code points, which is how Python's len() counts; String.length counts UTF-16 units. */
function codePoints(value: string): number {
  return [...value].length;
}

export function passwordError(value: string): string | null {
  const length = codePoints(value);
  return length >= 8 && length <= 128 && value.trim().length > 0 ? null : t.validation.password;
}

export function labelError(value: string): string | null {
  const trimmed = value.normalize("NFC").trim();
  const length = codePoints(trimmed);
  if (length < 1 || length > 64) return t.validation.labelLength;
  if (OTHER_CHARACTER_RE.test(trimmed.replace(ZERO_WIDTH_JOINER_RE, ""))) return t.validation.labelChars;
  return null;
}

/** Accepts the code as typed (any case, spaces, dashes; O/I/L read as 0/1/1), or null if malformed. */
export function normalizeResetCode(value: string): string | null {
  const code = value.replace(/[\s-]/g, "").toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1");
  return RESET_CODE_RE.test(code) ? code : null;
}

/** Returns AA:BB:CC:DD:EE:FF, or null for anything the server would reject. */
export function normalizeMac(value: string): string | null {
  const digits = value.trim().replace(/[:.-]/g, "").toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(digits) || parseInt(digits.slice(0, 2), 16) & 0x01) return null;
  return digits.match(/.{2}/g)!.join(":");
}
