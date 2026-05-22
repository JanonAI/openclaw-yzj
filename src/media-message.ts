import * as dns from "node:dns/promises";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import type { ResolvedYZJAccount } from "./types.ts";
import {
  buildYZJReplyParam,
  sendYZJAppMessage,
  type YZJSendByAppResult,
  type YZJSendByAppTarget,
} from "./app-message.ts";
import { getYZJAccessTokenProvider } from "./auth-token.ts";
import { resolveYZJEndpointUrl } from "./ws-url.ts";

type FetchLike = typeof fetch;

type TokenProvider = {
  getAccessToken: () => Promise<string>;
};

export type YZJUploadAndSendMediaTarget = {
  groupId?: string;
  toOpenId?: string;
  text?: string;
  mediaUrl?: string;
  mediaBuffer?: Buffer;
  fileName?: string;
  mediaLocalRoots?: readonly string[];
  reply?: YZJSendByAppTarget["reply"];
};

type MediaOptions = {
  tokenProvider?: TokenProvider;
  fetchImpl?: FetchLike;
  logger?: {
    info?: (message: string) => void;
  };
};

type LoadedMedia = {
  buffer: Buffer;
  fileName: string;
};

type UploadedFile = {
  fileId: string;
};

const MAX_REMOTE_MEDIA_BYTES = 50 * 1024 * 1024;
const IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"]);

function normalizeMediaUrlInput(value: string): string {
  let raw = value.trim();
  if (raw.startsWith("<") && raw.endsWith(">") && raw.length >= 2) {
    raw = raw.slice(1, -1).trim();
  }
  const first = raw[0];
  const last = raw[raw.length - 1];
  if (raw.length >= 2 && ((first === '"' && last === '"') || (first === "'" && last === "'") || (first === "`" && last === "`"))) {
    raw = raw.slice(1, -1).trim();
  }
  return raw;
}

function isWindowsAbsolutePath(value: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(value) || value.startsWith("\\\\");
}

function isLocalMediaPath(value: string): boolean {
  const raw = normalizeMediaUrlInput(value);
  return raw.startsWith("file://") || path.isAbsolute(raw) || isWindowsAbsolutePath(raw);
}

function safeFileUrlToPath(fileUrl: string): string {
  const raw = normalizeMediaUrlInput(fileUrl);
  try {
    return fileURLToPath(raw);
  } catch {
    return new URL(raw).pathname;
  }
}

function stripQueryAndHash(value: string): string {
  return value.split(/[?#]/, 1)[0] ?? value;
}

function resolveBaseNameFromPath(value: string): string | undefined {
  const raw = normalizeMediaUrlInput(value);
  const cleanPath = stripQueryAndHash(raw);
  const fileName = isWindowsAbsolutePath(cleanPath) ? path.win32.basename(cleanPath) : path.basename(cleanPath);
  if (fileName && fileName !== "/" && fileName !== "." && fileName !== "\\") {
    return fileName;
  }
  return undefined;
}

function resolveFileNameFromMediaUrl(mediaUrl: string): string | undefined {
  const raw = normalizeMediaUrlInput(mediaUrl);
  if (!raw) return undefined;

  if (isLocalMediaPath(raw)) {
    if (raw.startsWith("file://")) {
      const fileName = resolveBaseNameFromPath(safeFileUrlToPath(raw));
      if (fileName) return fileName;
    }
    return resolveBaseNameFromPath(raw);
  }

  try {
    const parsed = new URL(raw);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      const fileName = path.posix.basename(parsed.pathname);
      if (fileName && fileName !== "/") return fileName;
    }
  } catch {
    return resolveBaseNameFromPath(raw);
  }
  return undefined;
}

function validateLocalMediaRoots(filePath: string, localRoots: readonly string[] | undefined): void {
  if (localRoots === undefined) {
    throw new Error(`Local file access denied for "${filePath}": mediaLocalRoots is not configured.`);
  }
  if (localRoots.length === 0) {
    throw new Error(`Local file access denied for "${filePath}": mediaLocalRoots is empty.`);
  }

  let resolvedFile: string;
  try {
    resolvedFile = fs.realpathSync(path.resolve(filePath));
  } catch {
    resolvedFile = path.resolve(filePath);
  }

  const allowed = localRoots.some((root) => {
    let resolvedRoot: string;
    try {
      resolvedRoot = fs.realpathSync(path.resolve(root));
    } catch {
      resolvedRoot = path.resolve(root);
    }
    return resolvedFile === resolvedRoot || resolvedFile.startsWith(resolvedRoot + path.sep);
  });
  if (!allowed) {
    throw new Error(`Local file access denied for "${filePath}": path is not under mediaLocalRoots.`);
  }
}

function parseIPv4MappedIPv6(ip: string): string | undefined {
  const normalized = ip.toLowerCase();
  if (!normalized.startsWith("::ffff:")) return undefined;

  const tail = normalized.slice("::ffff:".length);
  if (net.isIP(tail) === 4) return tail;

  const parts = tail.split(":");
  if (parts.length !== 2) return undefined;
  const high = Number.parseInt(parts[0]!, 16);
  const low = Number.parseInt(parts[1]!, 16);
  if (!Number.isInteger(high) || !Number.isInteger(low) || high < 0 || high > 0xffff || low < 0 || low > 0xffff) {
    return undefined;
  }
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

function isPrivateIP(ip: string): boolean {
  const normalized = ip.toLowerCase();
  const mappedIPv4 = parseIPv4MappedIPv6(normalized);
  if (mappedIPv4) return isPrivateIP(mappedIPv4);

  if (normalized.startsWith("127.")) return true;
  if (normalized.startsWith("10.")) return true;
  if (normalized.startsWith("192.168.")) return true;
  if (normalized.startsWith("169.254.")) return true;
  if (normalized === "0.0.0.0") return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(normalized)) return true;
  if (normalized === "::1" || normalized === "::") return true;
  if (normalized.startsWith("fe80:")) return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  return false;
}

function assertMediaSizeAllowed(buffer: Buffer, source: string): void {
  if (buffer.length > MAX_REMOTE_MEDIA_BYTES) {
    throw new Error(`${source} media too large: ${buffer.length} bytes exceeds ${MAX_REMOTE_MEDIA_BYTES} bytes.`);
  }
}

async function validateRemoteUrl(raw: string): Promise<void> {
  const parsed = new URL(raw);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported media protocol "${parsed.protocol}".`);
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(hostname)) {
    if (isPrivateIP(hostname)) {
      throw new Error(`Access to private/reserved IP "${hostname}" is denied.`);
    }
    return;
  }

  const addresses = await dns.lookup(hostname, { all: true });
  for (const address of addresses) {
    if (isPrivateIP(address.address)) {
      throw new Error(`Domain "${hostname}" resolves to private/reserved IP "${address.address}".`);
    }
  }
}

async function fetchMediaBuffer(mediaUrl: string, mediaLocalRoots: readonly string[] | undefined, fetchImpl: FetchLike): Promise<Buffer> {
  const raw = normalizeMediaUrlInput(mediaUrl);
  if (!raw) throw new Error("mediaUrl is required");

  if (isLocalMediaPath(raw)) {
    const filePath = raw.startsWith("file://") ? safeFileUrlToPath(raw) : raw;
    validateLocalMediaRoots(filePath, mediaLocalRoots);
    const buffer = fs.readFileSync(filePath);
    assertMediaSizeAllowed(buffer, "Local");
    return buffer;
  }

  await validateRemoteUrl(raw);
  const response = await fetchImpl(raw, {
    signal: AbortSignal.timeout(30_000),
    redirect: "manual",
  });
  if (response.status >= 300 && response.status < 400) {
    throw new Error(`Remote media redirect is not allowed: HTTP ${response.status}`);
  }
  if (!response.ok) {
    throw new Error(`Failed to fetch media: HTTP ${response.status}`);
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength) {
    const expectedBytes = Number(contentLength);
    if (Number.isFinite(expectedBytes) && expectedBytes > MAX_REMOTE_MEDIA_BYTES) {
      throw new Error(`Remote media too large: ${expectedBytes} bytes exceeds ${MAX_REMOTE_MEDIA_BYTES} bytes.`);
    }
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  assertMediaSizeAllowed(buffer, "Remote");
  return buffer;
}

async function loadYZJMedia(target: YZJUploadAndSendMediaTarget, fetchImpl: FetchLike): Promise<LoadedMedia> {
  const fileName = target.fileName?.trim()
    || (target.mediaUrl ? resolveFileNameFromMediaUrl(target.mediaUrl) : undefined)
    || "file";

  if (target.mediaBuffer) {
    assertMediaSizeAllowed(target.mediaBuffer, "Provided");
    return { buffer: target.mediaBuffer, fileName };
  }
  if (!target.mediaUrl) {
    throw new Error("mediaUrl or mediaBuffer is required");
  }
  return {
    buffer: await fetchMediaBuffer(target.mediaUrl, target.mediaLocalRoots, fetchImpl),
    fileName,
  };
}

function extractUploadedFileId(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const record = body as Record<string, any>;
  const candidates = [
    record.fileId,
    record.file_id,
    record.data?.fileId,
    record.data?.file_id,
    record.data?.id,
    record.data?.fid,
    Array.isArray(record.data) ? record.data[0]?.fileId : undefined,
    Array.isArray(record.data) ? record.data[0]?.file_id : undefined,
    Array.isArray(record.data) ? record.data[0]?.id : undefined,
    Array.isArray(record.data) ? record.data[0]?.fid : undefined,
  ];
  return candidates.find((item) => typeof item === "string" && item.trim())?.trim();
}

async function uploadYZJAppFile(
  account: ResolvedYZJAccount,
  media: LoadedMedia,
  accessToken: string,
  fetchImpl: FetchLike,
  logger?: MediaOptions["logger"],
): Promise<UploadedFile> {
  const form = new FormData();
  const bytes = new Uint8Array(media.buffer);
  form.set("file", new Blob([bytes]), media.fileName);
  const uploadBodySummary = {
    fileName: media.fileName,
    size: media.buffer.length,
  };
  logger?.info?.(`[yzj] uploadfileOpen request body: ${JSON.stringify(uploadBodySummary)}`);

  const response = await fetchImpl(
    resolveYZJEndpointUrl(account.endpoint, "/gateway/docrest/doc/file/uploadfileOpen"),
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      body: form,
    },
  );

  const responseText = await response.text();
  logger?.info?.(`[yzj] uploadfileOpen response status=${response.status} body=${responseText}`);
  let parsed: unknown = undefined;
  if (responseText.trim()) {
    try {
      parsed = JSON.parse(responseText);
    } catch {
      parsed = undefined;
    }
  }

  if (!response.ok) {
    throw new Error(`uploadfileOpen failed: HTTP ${response.status}`);
  }
  if (parsed && typeof parsed === "object" && (parsed as Record<string, unknown>).success === false) {
    const record = parsed as Record<string, unknown>;
    throw new Error(String(record.error ?? record.errorCode ?? "uploadfileOpen failed"));
  }

  const fileId = extractUploadedFileId(parsed);
  if (!fileId) {
    throw new Error("uploadfileOpen response missing fileId");
  }
  return { fileId };
}

function getFileExtension(fileName: string): string {
  const ext = path.extname(fileName).replace(/^\./, "").trim().toLowerCase();
  return ext;
}

function isImageFileName(fileName: string): boolean {
  return IMAGE_EXTENSIONS.has(path.extname(fileName).toLowerCase());
}

function isImageBuffer(buffer: Buffer): boolean {
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return true;
  }
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return true;
  }
  if (buffer.length >= 6) {
    const header = buffer.subarray(0, 6).toString("ascii");
    if (header === "GIF87a" || header === "GIF89a") return true;
    if (buffer.subarray(0, 2).toString("ascii") === "BM") return true;
  }
  if (buffer.length >= 12) {
    const riff = buffer.subarray(0, 4).toString("ascii");
    const webp = buffer.subarray(8, 12).toString("ascii");
    if (riff === "RIFF" && webp === "WEBP") return true;
  }
  return false;
}

function parsePngSize(buffer: Buffer): { width: number; height: number } | undefined {
  if (buffer.length < 24) return undefined;
  if (buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return {
      width: buffer.readUInt32BE(16),
      height: buffer.readUInt32BE(20),
    };
  }
  return undefined;
}

function parseJpegSize(buffer: Buffer): { width: number; height: number } | undefined {
  if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) return undefined;
  let offset = 2;
  while (offset + 9 < buffer.length) {
    if (buffer[offset] !== 0xff) return undefined;
    const marker = buffer[offset + 1];
    const length = buffer.readUInt16BE(offset + 2);
    if (length < 2) return undefined;
    if ((marker >= 0xc0 && marker <= 0xc3) || (marker >= 0xc5 && marker <= 0xc7) || (marker >= 0xc9 && marker <= 0xcb) || (marker >= 0xcd && marker <= 0xcf)) {
      return {
        height: buffer.readUInt16BE(offset + 5),
        width: buffer.readUInt16BE(offset + 7),
      };
    }
    offset += 2 + length;
  }
  return undefined;
}

function detectImageSize(buffer: Buffer): { width: number; height: number } {
  return parsePngSize(buffer) ?? parseJpegSize(buffer) ?? { width: 800, height: 600 };
}

export async function uploadAndSendYZJAppMedia(
  account: ResolvedYZJAccount,
  target: YZJUploadAndSendMediaTarget,
  options: MediaOptions = {},
): Promise<YZJSendByAppResult> {
  const groupId = target.groupId?.trim();
  const toOpenId = target.toOpenId?.trim();
  if (!groupId && !toOpenId) {
    throw new Error("groupId or toOpenId is required");
  }
  if (groupId && toOpenId) {
    throw new Error("groupId and toOpenId cannot both be set");
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const media = await loadYZJMedia(target, fetchImpl);
  const accessToken = await (options.tokenProvider ?? getYZJAccessTokenProvider(account)).getAccessToken();
  const uploaded = await uploadYZJAppFile(account, media, accessToken, fetchImpl, options.logger);

  if (isImageFileName(media.fileName) || isImageBuffer(media.buffer)) {
    const size = detectImageSize(media.buffer);
    const tailText = target.text?.trim() ?? "";
    const content = tailText ? `${tailText}\n[图片]` : "[图片]";
    const param: Record<string, unknown> = {
      desc: [{ type: "image", data: uploaded.fileId, w: size.width, h: size.height }],
    };
    if (target.reply?.replyMsgId) {
      Object.assign(param, buildYZJReplyParam(target.reply));
    }
    return sendYZJAppMessage(account, {
      groupId,
      toOpenId,
      msgType: 23,
      content,
      param,
    }, {
      tokenProvider: { getAccessToken: async () => accessToken },
      fetchImpl,
      logger: options.logger,
    });
  }

  return sendYZJAppMessage(account, {
    groupId,
    toOpenId,
    msgType: 8,
    content: `[文件]:${media.fileName}`,
    param: {
      file_id: uploaded.fileId,
      name: media.fileName,
      size: media.buffer.length,
      ext: getFileExtension(media.fileName),
      ftype: 0,
      unreadMonitor: 1,
      ...(target.reply?.replyMsgId ? buildYZJReplyParam(target.reply) : {}),
    },
  }, {
    tokenProvider: { getAccessToken: async () => accessToken },
    fetchImpl,
    logger: options.logger,
  });
}
