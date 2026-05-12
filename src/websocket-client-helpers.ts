export const DEFAULT_WEBSOCKET_HEALTH = {
  heartbeatMs: 15_000,
  staleMs: 45_000,
} as const;

const RECONNECT_DELAYS_MS = [1_000, 2_000, 5_000, 10_000, 30_000, 60_000] as const;

export function getReconnectDelayMs(attempt: number): number {
  return RECONNECT_DELAYS_MS[Math.min(Math.max(attempt, 0), RECONNECT_DELAYS_MS.length - 1)] ?? 60_000;
}

export function shouldReconnectAfterInvalidFrames(consecutiveInvalidFrames: number): boolean {
  return consecutiveInvalidFrames >= 3;
}

type BusinessMessage = {
  type: number;
  robotId: string;
  robotName: string;
  operatorOpenid: string;
  operatorName: string;
  time: number;
  msgId: string;
  content: string;
  groupType: number;
  groupId?: string;
};

type ControlResult = {
  kind: "control";
  reason: string;
  ack?: string;
};

type DispatchResult = {
  kind: "dispatch";
  message: BusinessMessage;
  ack?: string;
};

type InvalidResult = {
  kind: "invalid";
};

export function classifyWebSocketPayload(payload: unknown): ControlResult | DispatchResult | InvalidResult {
  if (typeof payload === "string") {
    const normalized = payload.trim().toLowerCase();
    if (normalized === "ping" || normalized === "pong") {
      return { kind: "control", reason: normalized };
    }
    return { kind: "invalid" };
  }

  if (!payload || typeof payload !== "object") return { kind: "invalid" };
  const record = payload as Record<string, unknown>;
  const directPushAck = buildDirectPushAck(record);

  const directBusinessMessage = normalizeBusinessMessage(record);
  if (directBusinessMessage) return { kind: "dispatch", message: directBusinessMessage, ...(directPushAck ? { ack: directPushAck } : {}) };

  const nestedBusinessMessage = normalizeBusinessEnvelope(record);
  if (nestedBusinessMessage) return { kind: "dispatch", message: nestedBusinessMessage, ...(directPushAck ? { ack: directPushAck } : {}) };

  const cmd = typeof record.cmd === "string" ? record.cmd.trim().toLowerCase() : "";
  const type = typeof record.type === "string" ? record.type.trim().toLowerCase() : "";
  const controlName = getControlName(record);

  if (controlName.toLowerCase() === "ping") {
    return { kind: "control", reason: "ping", ack: JSON.stringify({ cmd: "pong" }) };
  }

  if (cmd === "directpush" || type === "msgchg") {
    return { kind: "control", reason: "directPush", ...(directPushAck ? { ack: directPushAck } : {}) };
  }

  if (controlName !== "" ) {
    return {kind: "control", reason: controlName};
  }

  return { kind: "invalid" };
}

function normalizeBusinessEnvelope(record: Record<string, unknown>): BusinessMessage | null {
  const envelopeType = typeof record.type === "string" ? record.type.trim().toLowerCase() : "";
  const cmd = typeof record.cmd === "string" ? record.cmd.trim().toLowerCase() : "";
  if (envelopeType !== "robotmessage" && cmd !== "robotmessage" && cmd !== "directpush") return null;
  if (!record.msg || typeof record.msg !== "object") return null;
  return normalizeBusinessMessage(record.msg as Record<string, unknown>);
}

function normalizeBusinessMessage(record: Record<string, unknown>): BusinessMessage | null {
  if (typeof record.robotId !== "string") return null;
  if (typeof record.robotName !== "string") return null;
  if (typeof record.operatorOpenid !== "string") return null;
  if (typeof record.operatorName !== "string") return null;
  if (typeof record.msgId !== "string") return null;
  if (typeof record.content !== "string") return null;
  if (typeof record.type !== "number") return null;
  if (typeof record.time !== "number") return null;

  const message: BusinessMessage = {
    type: record.type,
    robotId: record.robotId,
    robotName: record.robotName,
    operatorOpenid: record.operatorOpenid,
    operatorName: record.operatorName,
    time: record.time,
    msgId: record.msgId,
    content: record.content,
    groupType: typeof record.groupType === "number" ? record.groupType : 0,
  };
  if (typeof record.groupId === "string" && record.groupId.trim()) {
    message.groupId = record.groupId;
  }
  return message;
}

function buildDirectPushAck(record: Record<string, unknown>): string | undefined {
  const cmd = typeof record.cmd === "string" ? record.cmd.trim().toLowerCase() : "";
  const type = typeof record.type === "string" ? record.type.trim() : "";
  const isDirectPush = cmd === "directpush";
  const isLevelOne = record.level === 1;
  const seq = typeof record.seq === "number" ? record.seq : undefined;

  if (!isDirectPush || record.needAck !== true || !isLevelOne || typeof seq !== "number") return undefined;

  return JSON.stringify({
    cmd: "directPush",
    type: "ack",
    bizType: type || "directPush",
    level: 1,
    endSeqId: seq,
  });
}

function getControlName(record: Record<string, unknown>): string {
  if (typeof record.cmd === "string" && record.cmd.trim()) return record.cmd.trim();
  if (typeof record.type === "string" && record.type.trim()) return record.type.trim();
  if (typeof record.event === "string" && record.event.trim()) return record.event.trim();
  return "";
}
