import TcpSocket from "react-native-tcp-socket";

import { WolError } from "./errors";
import { Cmd, MAX_INBOUND_LINE_BYTES, decode, encode } from "./protocol";

type Socket = ReturnType<typeof TcpSocket.connectTLS>;
type CloseCode = "connection_lost" | "timeout" | "protocol_error";

interface Pending {
  resolve: (args: unknown[]) => void;
  reject: (error: WolError) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface Connecting {
  reject: (error: WolError) => void;
  timer: ReturnType<typeof setTimeout>;
}

const CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
// The server drops clients after 300 s of silence.
const PING_INTERVAL_MS = 60_000;

/**
 * One TLS connection to the client port. Replies carry no request id, so they are
 * matched to requests strictly in the order the requests were sent.
 *
 * Every way of closing goes through shutdown(), which settles all pending promises
 * and clears all timers, so nothing from an old socket can touch a newer one.
 */
export class WolConnection {
  private socket: Socket | null = null;
  private buffer = "";
  private pending: Pending[] = [];
  private connecting: Connecting | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly onClosed: () => void = () => {}) {}

  connect(host: string, port: number): Promise<void> {
    this.close();
    return new Promise((resolve, reject) => {
      // Use the OS trust store; the native TLS policy verifies the hostname and TLS >= 1.2.
      const socket = TcpSocket.connectTLS({ host, port }, () => {
        if (this.socket !== socket || this.connecting === null) return;
        clearTimeout(this.connecting.timer);
        this.connecting = null;
        this.pingTimer = setInterval(() => {
          this.request(Cmd.PING).catch(() => {});
        }, PING_INTERVAL_MS);
        resolve();
      });
      const lost = () => {
        if (this.socket !== socket) return;
        if (this.connecting !== null) this.shutdown("connection_lost");
        else this.fail("connection_lost");
      };
      socket.setEncoding("utf8");
      socket.on("data", (data) => {
        if (this.socket === socket) this.onData(typeof data === "string" ? data : data.toString("utf8"));
      });
      socket.on("error", lost);
      socket.on("close", lost);
      this.socket = socket;
      this.connecting = {
        reject,
        timer: setTimeout(() => {
          if (this.socket === socket) this.shutdown("connection_lost");
        }, CONNECT_TIMEOUT_MS),
      };
    });
  }

  request(command: string, args: readonly unknown[] = [], timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS): Promise<unknown[]> {
    const socket = this.socket;
    if (socket === null) return Promise.reject(new WolError("connection_lost"));

    return new Promise((resolve, reject) => {
      // A late reply would be matched to the next request, so a timeout ends the connection.
      const timer = setTimeout(() => this.fail("timeout"), timeoutMs);
      this.pending.push({ resolve, reject, timer });
      socket.write(encode(command, args));
    });
  }

  close(): void {
    if (this.socket === null) return;
    this.shutdown("connection_lost");
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let newline: number;
    while ((newline = this.buffer.indexOf("\n")) !== -1) {
      const line = this.buffer.slice(0, newline).replace(/\r$/, "");
      this.buffer = this.buffer.slice(newline + 1);
      if (line.length > 0) this.onLine(line);
      if (this.socket === null) return;
    }
    if (this.buffer.length > MAX_INBOUND_LINE_BYTES) this.fail("protocol_error");
  }

  private onLine(line: string): void {
    const message = decode(line);
    const request = this.pending.shift();
    if (request === undefined) return;
    clearTimeout(request.timer);

    if (message === null) {
      request.reject(new WolError("protocol_error"));
    } else if (message.command === Cmd.ACK || message.command === Cmd.PONG) {
      request.resolve(message.args);
    } else if (message.command === Cmd.NACK) {
      request.reject(new WolError(typeof message.args[0] === "string" ? message.args[0] : "protocol_error"));
    } else {
      request.reject(new WolError("protocol_error"));
    }
  }

  /** An established connection broke; tells the owner. */
  private fail(code: CloseCode): void {
    if (this.socket === null) return;
    this.shutdown(code);
    this.onClosed();
  }

  private shutdown(code: CloseCode): void {
    const connecting = this.connecting;
    this.connecting = null;
    const pending = this.pending;
    this.pending = [];
    if (this.pingTimer !== null) clearInterval(this.pingTimer);
    this.pingTimer = null;
    const socket = this.socket;
    this.socket = null;
    this.buffer = "";
    if (socket !== null) {
      socket.removeAllListeners();
      socket.destroy();
    }

    if (connecting !== null) {
      clearTimeout(connecting.timer);
      connecting.reject(new WolError("connection_failed"));
    }
    for (const request of pending) {
      clearTimeout(request.timer);
      request.reject(new WolError(code));
    }
  }
}
