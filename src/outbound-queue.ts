const queues = new Map<string, Promise<void>>();
const sentTextsByTurn = new Map<string, Map<string, number>>();

export function buildYZJOutboundQueueKey(params: {
  accountId: string;
  groupId?: string;
  toOpenId?: string;
}): string {
  const accountId = params.accountId.trim() || "default";
  const groupId = params.groupId?.trim();
  const toOpenId = params.toOpenId?.trim();
  const target = groupId ? `group:${groupId}` : `user:${toOpenId ?? ""}`;
  return `${accountId}|${target}`;
}

export function enqueueYZJOutbound<T>(key: string, task: () => Promise<T>): Promise<T> {
  const previous = queues.get(key) ?? Promise.resolve();
  let release: () => void = () => undefined;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const next = previous.catch(() => undefined).then(() => current);
  queues.set(key, next);

  return previous
    .catch(() => undefined)
    .then(task)
    .finally(() => {
      release();
      if (queues.get(key) === next) {
        queues.delete(key);
      }
    });
}

function normalizeSentText(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function buildTurnTextKey(queueKey: string, turnId: string): string {
  return `${queueKey}|turn:${turnId.trim()}`;
}

export function markYZJOutboundTextSent(params: {
  queueKey: string;
  turnId?: string;
  text?: string;
}): void {
  const turnId = params.turnId?.trim();
  const text = normalizeSentText(params.text ?? "");
  if (!turnId || !text) return;

  const key = buildTurnTextKey(params.queueKey, turnId);
  const texts = sentTextsByTurn.get(key) ?? new Map<string, number>();
  texts.set(text, (texts.get(text) ?? 0) + 1);
  sentTextsByTurn.set(key, texts);
}

export function consumeYZJOutboundDuplicateText(params: {
  queueKey: string;
  turnId?: string;
  text?: string;
}): boolean {
  const turnId = params.turnId?.trim();
  const text = normalizeSentText(params.text ?? "");
  if (!turnId || !text) return false;

  const key = buildTurnTextKey(params.queueKey, turnId);
  const texts = sentTextsByTurn.get(key);
  const count = texts?.get(text) ?? 0;
  if (!texts || count <= 0) return false;
  if (count === 1) {
    texts.delete(text);
    if (texts.size === 0) sentTextsByTurn.delete(key);
  } else {
    texts.set(text, count - 1);
  }
  return true;
}

export function clearYZJOutboundTurnTexts(params: {
  queueKey: string;
  turnId?: string;
}): void {
  const turnId = params.turnId?.trim();
  if (!turnId) return;
  sentTextsByTurn.delete(buildTurnTextKey(params.queueKey, turnId));
}

export function clearYZJOutboundQueues(): void {
  queues.clear();
  sentTextsByTurn.clear();
}
