import { WolConnection } from "./connection";
import { WolError } from "./errors";
import { Cmd } from "./protocol";

export interface ServerAddress {
  host: string;
  port: number;
}

export interface Device {
  id: string;
  name: string;
  online: boolean;
  last_seen_at: number | null;
}

export interface Target {
  id: number;
  device_id: string | null;
  mac: string;
  name: string;
}

export interface AuthResult {
  token: string;
  name: string;
}

// The server waits up to 5 s for the ESP to confirm a wake-up.
const DEVICE_REQUEST_TIMEOUT_MS = 20_000;

type Guard<T> = (value: unknown) => value is T;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const isString: Guard<string> = (value): value is string => typeof value === "string";

const isNumber: Guard<number> = (value): value is number => typeof value === "number" && Number.isFinite(value);

const isDevice: Guard<Device> = (value): value is Device =>
  isRecord(value) &&
  isString(value.id) &&
  isString(value.name) &&
  typeof value.online === "boolean" &&
  (value.last_seen_at === null || isNumber(value.last_seen_at));

const isTarget: Guard<Target> = (value): value is Target =>
  isRecord(value) &&
  isNumber(value.id) &&
  (value.device_id === null || isString(value.device_id)) &&
  isString(value.mac) &&
  isString(value.name);

function one<T>(value: unknown, guard: Guard<T>): T {
  if (!guard(value)) throw new WolError("protocol_error");
  return value;
}

function list<T>(value: unknown, guard: Guard<T>): T[] {
  if (!Array.isArray(value) || !value.every(guard)) throw new WolError("protocol_error");
  return value;
}

class WolApi {
  private server: ServerAddress | null = null;
  private token: string | null = null;
  // Resolves to the user name once the current connection is authenticated.
  private session: Promise<string> | null = null;
  private readonly conn = new WolConnection(() => {
    this.session = null;
  });

  /** Called when the server no longer accepts the stored session token. */
  onSessionInvalid: () => void = () => {};

  configure(server: ServerAddress, token: string | null): void {
    const changed = this.server?.host !== server.host || this.server?.port !== server.port || this.token !== token;
    this.server = server;
    this.token = token;
    if (changed) this.disconnect();
  }

  disconnect(): void {
    this.session = null;
    this.conn.close();
  }

  // --- session ---

  async register(name: string, email: string, password: string): Promise<AuthResult> {
    return this.authenticate(Cmd.REGISTER, [name, email, password]);
  }

  async login(name: string, password: string): Promise<AuthResult> {
    return this.authenticate(Cmd.LOGIN, [name, password]);
  }

  /** Connects and resumes the stored session unless already connected; returns the user name. */
  connect(): Promise<string> {
    return this.ensureSession();
  }

  async logout(): Promise<void> {
    await this.forget(Cmd.LOGOUT, []);
  }

  async logoutAll(): Promise<void> {
    await this.forget(Cmd.LOGOUT_ALL, []);
  }

  async deleteAccount(password: string): Promise<void> {
    await this.forget(Cmd.DELETE_ACCOUNT, [password]);
  }

  async changePassword(oldPassword: string, newPassword: string): Promise<string> {
    const [token] = await this.call(Cmd.CHANGE_PASSWORD, [oldPassword, newPassword]);
    this.token = one(token, isString);
    return this.token;
  }

  async changeName(newName: string, password: string): Promise<string> {
    const [name] = await this.call(Cmd.CHANGE_NAME, [newName, password]);
    return one(name, isString);
  }

  /** The server answers the same way whether or not the address is registered. */
  async requestPasswordReset(email: string): Promise<void> {
    await this.withSideConnection((conn) => conn.request(Cmd.REQUEST_PASSWORD_RESET, [email]));
  }

  async resetPassword(email: string, code: string, newPassword: string): Promise<AuthResult> {
    return this.authenticate(Cmd.RESET_PASSWORD, [email, code, newPassword]);
  }

  /** Ends a session left over from a logout that could not reach the server. */
  async revokeToken(token: string): Promise<void> {
    await this.withSideConnection(async (conn) => {
      try {
        await conn.request(Cmd.RESUME, [token]);
      } catch (error) {
        if (error instanceof WolError && error.code === "invalid_token") return;
        throw error;
      }
      await conn.request(Cmd.LOGOUT);
    });
  }

  // --- devices ---

  async createClaim(deviceName: string, deviceId: string): Promise<string> {
    const [token] = await this.call(Cmd.CREATE_CLAIM, [deviceName, deviceId]);
    return one(token, isString);
  }

  async listDevices(): Promise<Device[]> {
    const [devices] = await this.call(Cmd.LIST_DEVICES);
    return list(devices, isDevice);
  }

  async renameDevice(deviceId: string, name: string): Promise<void> {
    await this.call(Cmd.RENAME_DEVICE, [deviceId, name]);
  }

  async removeDevice(deviceId: string): Promise<void> {
    await this.call(Cmd.REMOVE_DEVICE, [deviceId]);
  }

  // --- targets ---

  async addTarget(deviceId: string, mac: string, name: string): Promise<Target> {
    const [target] = await this.call(Cmd.ADD_TARGET, [deviceId, mac, name]);
    return one(target, isTarget);
  }

  async listTargets(): Promise<Target[]> {
    const [targets] = await this.call(Cmd.LIST_TARGETS);
    return list(targets, isTarget);
  }

  async renameTarget(targetId: number, name: string): Promise<void> {
    await this.call(Cmd.RENAME_TARGET, [targetId, name]);
  }

  async assignTarget(targetId: number, deviceId: string): Promise<void> {
    await this.call(Cmd.ASSIGN_TARGET, [targetId, deviceId]);
  }

  async removeTarget(targetId: number): Promise<void> {
    await this.call(Cmd.REMOVE_TARGET, [targetId]);
  }

  async wakeUp(targetId: number): Promise<void> {
    await this.call(Cmd.WAKE_UP, [targetId], DEVICE_REQUEST_TIMEOUT_MS);
  }

  // --- plumbing ---

  private async call(command: string, args: unknown[] = [], timeoutMs?: number): Promise<unknown[]> {
    await this.ensureSession();
    try {
      return await this.conn.request(command, args, timeoutMs);
    } catch (error) {
      // The server re-checks sessions periodically and rejects revoked ones.
      if (error instanceof WolError && error.code === "invalid_token") this.sessionRevoked();
      throw error;
    }
  }

  private sessionRevoked(): void {
    this.token = null;
    this.disconnect();
    this.onSessionInvalid();
  }

  /** LOGIN, REGISTER and RESET_PASSWORD run on a fresh, not yet authenticated connection. */
  private async authenticate(command: string, args: unknown[]): Promise<AuthResult> {
    this.token = null;
    this.disconnect();
    await this.open();
    const [token, name] = await this.conn.request(command, args);
    const result = { token: one(token, isString), name: one(name, isString) };
    this.token = result.token;
    this.session = Promise.resolve(result.name);
    return result;
  }

  /** The server ends the session and closes the connection after these. */
  private async forget(command: string, args: unknown[]): Promise<void> {
    await this.call(command, args);
    this.token = null;
    this.disconnect();
  }

  /** A short-lived, unauthenticated connection that leaves the main one alone. */
  private async withSideConnection(use: (conn: WolConnection) => Promise<unknown>): Promise<void> {
    const server = this.server;
    if (server === null) throw new WolError("connection_failed");
    const conn = new WolConnection();
    try {
      await conn.connect(server.host, server.port);
      await use(conn);
    } finally {
      conn.close();
    }
  }

  private ensureSession(): Promise<string> {
    if (this.session === null) {
      const session = this.openSession();
      this.session = session;
      session.catch(() => {
        if (this.session === session) this.session = null;
      });
    }
    return this.session;
  }

  private async openSession(): Promise<string> {
    const token = this.token;
    if (token === null) throw new WolError("unauthenticated");
    await this.open();
    try {
      const [name] = await this.conn.request(Cmd.RESUME, [token]);
      return one(name, isString);
    } catch (error) {
      if (error instanceof WolError && error.code === "invalid_token") this.sessionRevoked();
      throw error;
    }
  }

  private async open(): Promise<void> {
    const server = this.server;
    if (server === null) throw new WolError("connection_failed");
    await this.conn.connect(server.host, server.port);
  }
}

export const api = new WolApi();
