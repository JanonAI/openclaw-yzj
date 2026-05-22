import type WebSocket from "ws";

type WsConstructor = typeof WebSocket;

let WebSocketImpl: WsConstructor | undefined;
let wsLoadPromise: Promise<typeof import("ws")> | null = null;
let lastWebSocketImplementation = "unresolved";

function loadWs(): Promise<typeof import("ws")> {
  if (WebSocketImpl) return wsLoadPromise ?? import("ws");
  if (wsLoadPromise) return wsLoadPromise;
  wsLoadPromise = import("ws").then((m) => {
    WebSocketImpl = m.default;
    return m;
  });
  return wsLoadPromise;
}

import { dispatchInboundMessage } from "./inbound-dispatcher.ts";
import {
  classifyWebSocketPayload,
  DEFAULT_WEBSOCKET_HEALTH,
  getReconnectDelayMs,
  shouldReconnectAfterInvalidFrames,
} from "./websocket-client-helpers.ts";
import type { YZJIncomingMessage, YZJLogger } from "./types.ts";
import type { YZJInboundTarget } from "./inbound-dispatcher.ts";
export {
  classifyWebSocketPayload,
  DEFAULT_WEBSOCKET_HEALTH,
  getReconnectDelayMs,
  shouldReconnectAfterInvalidFrames,
} from "./websocket-client-helpers.ts";

type WebSocketLike = {
  readyState: number;
  send: (data: string) => void;
  close: (code?: number, reason?: string) => void;
  addEventListener: (type: string, listener: (event: any) => void) => void;
  removeEventListener?: (type: string, listener: (event: any) => void) => void;
  on?: (type: string, listener: (event?: any) => void) => void;
  off?: (type: string, listener: (event?: any) => void) => void;
  ping?: () => void;
};

type WebSocketFactory = (url: string) => WebSocketLike | Promise<WebSocketLike>;

type TimerApi = {
  setTimeout: typeof setTimeout;
  clearTimeout: typeof clearTimeout;
  setInterval: typeof setInterval;
  clearInterval: typeof clearInterval;
};

type YZJWebSocketClientOptions = {
  url: string | (() => string | Promise<string>);
  target: YZJInboundTarget;
  logger: YZJLogger;
  WebSocketFactory?: WebSocketFactory;
  timers?: TimerApi;
  onReady?: () => void;
  onDegraded?: (message: string) => void;
};

async function defaultWebSocketFactory(url: string): Promise<WebSocketLike> {
  try {
    await loadWs();
    if (WebSocketImpl) {
      lastWebSocketImplementation = "ws";
      return new WebSocketImpl(url) as unknown as WebSocketLike;
    }
  } catch {
    // ws not available, fall back to native WebSocket
  }
  if (typeof globalThis.WebSocket !== "undefined") {
    lastWebSocketImplementation = `global:${globalThis.WebSocket.name || "WebSocket"}`;
    return new globalThis.WebSocket(url) as unknown as WebSocketLike;
  }
  throw new Error("No WebSocket implementation available");
}

function logInfo(logger: YZJLogger, message: string): void {
  logger.info?.(message);
  if (!logger.info) logger.log?.(message);
}

function addSocketControlListener(socket: WebSocketLike, type: "ping" | "pong", listener: () => void): void {
  socket.addEventListener(type, listener);
  if (typeof socket.on === "function") {
    socket.on(type, listener);
  }
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isControlPayload(payload: unknown): boolean {
  if (typeof payload === "string") {
    const normalized = payload.trim().toLowerCase();
    return normalized === "ping" || normalized === "pong";
  }
  if (!payload || typeof payload !== "object") return false;
  const record = payload as Record<string, unknown>;
  const type = typeof record.type === "string" ? record.type.toLowerCase() : "";
  const event = typeof record.event === "string" ? record.event.toLowerCase() : "";
  return ["ping", "pong", "ack", "close"].includes(type) || ["ping", "pong", "ack", "close"].includes(event);
}

function describeWebSocketError(event: unknown): string {
  if (!event || typeof event !== "object") return String(event ?? "unknown error");

  const record = event as Record<string, unknown>;
  const error = record.error;
  if (error instanceof Error) {
    return error.message || error.name;
  }

  const message = typeof record.message === "string" ? record.message.trim() : "";
  if (message) return message;

  const code = typeof record.code === "string" || typeof record.code === "number"
    ? String(record.code)
    : "";
  const reason = typeof record.reason === "string" ? record.reason.trim() : "";
  if (code || reason) return [code, reason].filter(Boolean).join(" ");

  return "unknown error";
}

function normalizeWebSocketData(data: unknown): string | null {
  if (typeof data === "string") return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf8");
  }
  return null;
}

function summarizeWebSocketPayload(payload: unknown): string {
  if (payload === null) return "null";
  if (payload === undefined) return "undefined";
  if (typeof payload === "string") return `string length=${payload.length}`;

  const type = typeof payload;
  if (type !== "object") {
    return type;
  }

  if (Array.isArray(payload)) {
    return `array length=${payload.length}`;
  }

  const keys = Object.keys(payload as Record<string, unknown>);
  const visibleKeys = keys.slice(0, 8).map((key) => {
    return /token|secret|signature|password|credential/i.test(key) ? "<sensitive-key>" : key;
  });
  const suffix = keys.length > visibleKeys.length ? `, +${keys.length - visibleKeys.length} more` : "";
  return `object keys=${keys.length}${visibleKeys.length ? ` [${visibleKeys.join(", ")}${suffix}]` : ""}`;
}

function safeWebSocketUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const accessToken = parsed.searchParams.get("accessToken");
    const yzjtoken = parsed.searchParams.get("yzjtoken");
    if (accessToken) {
      parsed.searchParams.set("accessToken", `<hidden:${accessToken.length}:${accessToken.slice(-4)}>`);
    }
    if (yzjtoken) {
      parsed.searchParams.set("yzjtoken", `<hidden:${yzjtoken.length}:${yzjtoken.slice(-4)}>`);
    }
    return parsed.toString();
  } catch {
    return url.replace(/(accessToken|yzjtoken)=([^&]+)/g, (_match, key, value) => {
      const token = String(value);
      return `${key}=<hidden:${token.length}:${token.slice(-4)}>`;
    });
  }
}

export class YZJWebSocketClient {
  private readonly url: string | (() => string | Promise<string>);
  private readonly target: YZJInboundTarget;
  private readonly logger: YZJLogger;
  private readonly createSocket: WebSocketFactory;
  private readonly timers: TimerApi;
  private readonly onReady?: () => void;
  private readonly onDegraded?: (message: string) => void;

  private socket: WebSocketLike | null = null;
  private stopped = false;
  private reconnectAttempts = 0;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private stableConnectionTimer: ReturnType<typeof setTimeout> | null = null;
  private lastMessageAt = 0;
  private lastPongAt = 0;
  private consecutiveInvalidFrames = 0;
  private missedPongs = 0;

  constructor(options: YZJWebSocketClientOptions) {
    this.url = options.url;
    this.target = options.target;
    this.logger = options.logger;
    this.createSocket = options.WebSocketFactory ?? defaultWebSocketFactory;
    this.timers = options.timers ?? globalThis;
    this.onReady = options.onReady;
    this.onDegraded = options.onDegraded;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.clearTimers();
    this.closeSocket(1000, "shutdown");
  }

  private connect(): void {
    if (this.stopped) return;

    try {
      const urlResult = typeof this.url === "function" ? this.url() : this.url;
      const urlPromise = urlResult instanceof Promise ? urlResult : Promise.resolve(urlResult);
      const promise = urlPromise.then((url) => {
        if (this.stopped) return null;
        logInfo(this.logger, `[${this.target.account.accountId}] yzj websocket dialing ${safeWebSocketUrl(url)}`);
        return this.createSocket(url);
      });
      promise.then(
        (socket) => {
          if (!socket) return;
          if (this.stopped) {
            try {
              socket.close(1000, "shutdown");
            } catch {
              // ignore close failures
            }
            return;
          }
          this.socket = socket;
          this.bindSocket(socket);
          logInfo(this.logger, `[${this.target.account.accountId}] yzj websocket connecting (${lastWebSocketImplementation})`);
        },
        (error) => {
          if (this.stopped) return;
          this.scheduleReconnect(`websocket connect failed: ${describeError(error)}`);
        },
      );
    } catch (error) {
      this.scheduleReconnect(`websocket connect failed: ${describeError(error)}`);
    }
  }

  private bindSocket(socket: WebSocketLike): void {
    socket.addEventListener("open", () => {
      this.lastMessageAt = Date.now();
      this.lastPongAt = Date.now();
      this.consecutiveInvalidFrames = 0;
      this.missedPongs = 0;
      this.startStableConnectionTimer();
      this.startHeartbeat();
      this.updateReadyStatus();
      logInfo(this.logger, `[${this.target.account.accountId}] yzj websocket connected`);
    });

    socket.addEventListener("message", (event: { data?: unknown }) => {
      this.handleMessage(event.data);
    });

    addSocketControlListener(socket, "ping", () => {
      this.lastPongAt = Date.now();
      this.missedPongs = 0;
    });

    addSocketControlListener(socket, "pong", () => {
      this.lastPongAt = Date.now();
      this.missedPongs = 0;
    });

    socket.addEventListener("error", (event) => {
      const detail = describeWebSocketError(event);
      this.scheduleReconnect(`websocket error: ${detail}`);
    });

    socket.addEventListener("close", () => {
      this.scheduleReconnect("websocket closed");
    });
  }

  private handleMessage(data: unknown): void {
    this.lastMessageAt = Date.now();
    const textData = normalizeWebSocketData(data);

    if (textData === null) {
      this.consecutiveInvalidFrames += 1;
      if (shouldReconnectAfterInvalidFrames(this.consecutiveInvalidFrames)) {
        this.forceReconnect("too many invalid websocket frames");
      }
      return;
    }

    let payload: unknown = textData;
    try {
      payload = JSON.parse(textData);
    } catch {
      if (isControlPayload(textData)) {
        this.handleControlPayload(textData);
        return;
      }
      this.consecutiveInvalidFrames += 1;
      this.logger.warn?.(`[${this.target.account.accountId}] yzj invalid websocket frame`);
      if (shouldReconnectAfterInvalidFrames(this.consecutiveInvalidFrames)) {
        this.forceReconnect("too many invalid websocket frames");
      }
      return;
    }

    const classified = classifyWebSocketPayload(payload);
    if (classified.kind === "control") {
      this.handleControlPayload(payload);
      if (classified.reason === "auth") {
        this.logger.info?.(`[${this.target.account.accountId}] yzj websocket auth success`);
      }
      this.sendControlFrame(classified.ack);
      return;
    }

    if (classified.kind !== "dispatch") {
      this.consecutiveInvalidFrames += 1;
      this.logger.warn?.(`[${this.target.account.accountId}] yzj websocket payload missing required fields`);
      this.logger.warn?.(`[${this.target.account.accountId}] payload summary: ${summarizeWebSocketPayload(payload)}`);
      if (shouldReconnectAfterInvalidFrames(this.consecutiveInvalidFrames)) {
        this.forceReconnect("too many invalid websocket frames");
      }
      return;
    }

    this.consecutiveInvalidFrames = 0;
    this.sendControlFrame(classified.ack);
    this.logger.info?.(`[${this.target.account.accountId}] yzj websocket inbound body: ${JSON.stringify(classified.message)}`);
    void dispatchInboundMessage(this.target, classified.message as YZJIncomingMessage, "websocket").catch((error) => {
      this.logger.error?.(`[${this.target.account.accountId}] yzj websocket dispatch failed: ${describeError(error)}`);
    });
  }

  private handleControlPayload(payload: unknown): void {
    this.consecutiveInvalidFrames = 0;
    const normalized = typeof payload === "string"
      ? payload.trim().toLowerCase()
      : String(
          (payload as Record<string, unknown>).cmd
            ?? (payload as Record<string, unknown>).type
            ?? (payload as Record<string, unknown>).event
            ?? "",
        ).toLowerCase();
    if (normalized === "pong" || normalized === "ping") {
      this.lastPongAt = Date.now();
      this.missedPongs = 0;
    }
  }

  private sendControlFrame(frame: string | undefined): void {
    if (!frame || this.socket?.readyState !== 1) return;
    try {
      this.socket.send(frame);
    } catch (error) {
      this.scheduleReconnect(`websocket control send failed: ${describeError(error)}`);
    }
  }

  private startHeartbeat(): void {
    if (this.heartbeatTimer) this.timers.clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = this.timers.setInterval(() => {
      this.checkHealth();
    }, DEFAULT_WEBSOCKET_HEALTH.heartbeatMs);
  }

  private startStableConnectionTimer(): void {
    if (this.stableConnectionTimer) this.timers.clearTimeout(this.stableConnectionTimer);
    this.stableConnectionTimer = this.timers.setTimeout(() => {
      this.reconnectAttempts = 0;
      this.stableConnectionTimer = null;
    }, DEFAULT_WEBSOCKET_HEALTH.heartbeatMs);
  }

  private checkHealth(): void {
    const socket = this.socket;
    if (!socket || this.stopped) return;

    const now = Date.now();
    const lastActivity = Math.max(this.lastMessageAt, this.lastPongAt);
    if (lastActivity > 0 && now - lastActivity >= DEFAULT_WEBSOCKET_HEALTH.staleMs) {
      this.forceReconnect("websocket stale connection detected");
      return;
    }

    if (socket.readyState !== 1) return;

    if (this.missedPongs >= 2) {
      this.forceReconnect(`websocket missed ${this.missedPongs} pongs`);
      return;
    }

    try {
      if (typeof socket.ping === "function") socket.ping();
      else socket.send(JSON.stringify({ cmd: "ping" }));
      this.missedPongs += 1;
      // logInfo(this.logger, `[${this.target.account.accountId}] yzj websocket heartbeat sent`);
    } catch (error) {
      this.forceReconnect(`websocket heartbeat failed: ${describeError(error)}`);
    }
  }

  private updateReadyStatus(): void {
    try {
      this.onReady?.();
    } catch (error) {
      this.logger.warn?.(`[${this.target.account.accountId}] yzj websocket status update failed: ${describeError(error)}`);
    }
  }

  private forceReconnect(message: string): void {
    this.closeSocket(4000, message);
    this.scheduleReconnect(message);
  }

  private scheduleReconnect(message: string): void {
    if (this.stopped) return;
    if (this.reconnectTimer) return;

    try {
      this.onDegraded?.(message);
    } catch (error) {
      this.logger.warn?.(`[${this.target.account.accountId}] yzj websocket status update failed: ${describeError(error)}`);
    }
    this.logger.warn?.(`[${this.target.account.accountId}] yzj ${message}`);
    this.clearHeartbeat();
    this.clearStableConnectionTimer();

    const delay = getReconnectDelayMs(this.reconnectAttempts);
    this.reconnectAttempts += 1;
    this.reconnectTimer = this.timers.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
    this.logger.warn?.(`[${this.target.account.accountId}] yzj websocket reconnect scheduled in ${delay}ms`);
  }

  private closeSocket(code?: number, reason?: string): void {
    const socket = this.socket;
    this.socket = null;
    if (!socket) return;
    try {
      socket.close(code, reason);
    } catch {
      // ignore close failures
    }
  }

  private clearHeartbeat(): void {
    if (!this.heartbeatTimer) return;
    this.timers.clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
  }

  private clearStableConnectionTimer(): void {
    if (!this.stableConnectionTimer) return;
    this.timers.clearTimeout(this.stableConnectionTimer);
    this.stableConnectionTimer = null;
  }

  private clearTimers(): void {
    this.clearHeartbeat();
    this.clearStableConnectionTimer();
    if (this.reconnectTimer) {
      this.timers.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
}
