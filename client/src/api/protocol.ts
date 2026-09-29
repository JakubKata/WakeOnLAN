// Wire format shared with the server: one JSON object per line, {"COMMAND":[arg,...]}.
// The server caps only what it receives (4096 B); list replies can be much longer.
export const MAX_INBOUND_LINE_BYTES = 64 * 1024;

export const Cmd = {
  ACK: "ACK",
  NACK: "NACK",
  PING: "PING",
  PONG: "PONG",

  REGISTER: "REGISTER",
  LOGIN: "LOGIN",
  RESUME: "RESUME",
  REQUEST_PASSWORD_RESET: "REQUEST_PASSWORD_RESET",
  RESET_PASSWORD: "RESET_PASSWORD",
  LOGOUT: "LOGOUT",
  LOGOUT_ALL: "LOGOUT_ALL",
  CHANGE_PASSWORD: "CHANGE_PASSWORD",
  CHANGE_NAME: "CHANGE_NAME",
  DELETE_ACCOUNT: "DELETE_ACCOUNT",

  CREATE_CLAIM: "CREATE_CLAIM",
  LIST_DEVICES: "LIST_DEVICES",
  RENAME_DEVICE: "RENAME_DEVICE",
  REMOVE_DEVICE: "REMOVE_DEVICE",
  ROTATE_DEVICE_SECRET: "ROTATE_DEVICE_SECRET",

  ADD_TARGET: "ADD_TARGET",
  LIST_TARGETS: "LIST_TARGETS",
  RENAME_TARGET: "RENAME_TARGET",
  ASSIGN_TARGET: "ASSIGN_TARGET",
  REMOVE_TARGET: "REMOVE_TARGET",
  WAKE_UP: "WAKE_UP",
} as const;

export type ErrCode =
  | "bad_frame"
  | "frame_too_long"
  | "unknown_command"
  | "bad_args"
  | "unauthenticated"
  | "already_authenticated"
  | "rate_limited"
  | "invalid_credentials"
  | "invalid_token"
  | "invalid_name"
  | "invalid_email"
  | "invalid_label"
  | "invalid_mac"
  | "weak_password"
  | "account_exists"
  | "name_taken"
  | "not_found"
  | "duplicate"
  | "limit_reached"
  | "no_device"
  | "device_offline"
  | "device_unreachable"
  | "reset_unavailable"
  | "internal"
  // Raised locally by the app, never sent by the server.
  | "connection_failed"
  | "connection_lost"
  | "timeout"
  | "protocol_error";

interface Message {
  command: string;
  args: unknown[];
}

export function encode(command: string, args: readonly unknown[] = []): string {
  return JSON.stringify({ [command]: args }) + "\n";
}

export function decode(line: string): Message | null {
  let data: unknown;
  try {
    data = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) return null;
  const entries = Object.entries(data);
  if (entries.length !== 1) return null;
  const [command, args] = entries[0];
  if (!Array.isArray(args)) return null;
  return { command, args };
}
