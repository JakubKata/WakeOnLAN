import { t } from "@/i18n";

import type { ErrCode } from "./protocol";

export class WolError extends Error {
  constructor(public readonly code: ErrCode | string) {
    super(errorMessage(code));
    this.name = "WolError";
  }
}

function errorMessage(code: string): string {
  return t.errors[code as ErrCode] ?? t.unknownError(code);
}

export function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}
