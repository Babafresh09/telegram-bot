import { open, mkdir, readdir, unlink, chmod } from "node:fs/promises";
import path from "node:path";
import { scanJsonReplacer } from "./events.js";
import type { DecodedEvent } from "./decode.js";

export interface EventArchiveOptions {
  dir: string;
  maxBytes?: number;
  maxFiles?: number;
}

export interface EventArchive {
  append(events: readonly DecodedEvent[]): Promise<void>;
  close(): Promise<void>;
}

export interface ReadArchiveOptions {
  /** Yield valid records before a malformed record instead of discarding them. Defaults to false. */
  retainCommitted?: boolean;
}

export type PrivacyFindingKind = "private_chat_id" | "secret_value";

export interface PrivacyFinding {
  kind: PrivacyFindingKind;
  fileName: string;
  lineNumber: number;
  jsonPath: string;
  /** Redacted preview of the matched value; never the raw secret. */
  preview: string;
}

export interface PrivacyReviewReport {
  filesScanned: number;
  recordsScanned: number;
  findings: PrivacyFinding[];
}

export class MalformedArchiveRecordError extends Error {
  readonly fileName: string;
  readonly lineNumber: number;

  constructor(fileName: string, lineNumber: number) {
    const safeFileName = path
      .basename(fileName)
      .replace(/[\x00-\x1f\x7f]/g, " ")
      .slice(0, 128);
    const displayedFileName = safeFileName || "<unknown>";
    super(`Malformed archive record at ${displayedFileName}:${lineNumber}`);
    this.name = "MalformedArchiveRecordError";
    this.fileName = displayedFileName;
    this.lineNumber = lineNumber;
  }
}

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MiB
const DEFAULT_MAX_FILES = 10;
const FILE_MODE = 0o600;

// Telegram chat ids: private chats are positive integers; groups/channels are negative.
const PRIVATE_CHAT_KEY_PATTERN = /^(chat_?id|chatId|chat_id_private|private_chat_id|from_?id|user_?id)$/i;
const SECRET_KEY_PATTERN = /(secret|token|password|passwd|api[_-]?key|private[_-]?key|seed|mnemonic)/i;
// Stellar secret seed (S...), 56 base32 chars.
const STELLAR_SECRET_SEED_PATTERN = /\bS[A-Z2-7]{55}\b/;
// Bot token shaped values: <digits>:<35+ url-safe chars>.
const BOT_TOKEN_PATTERN = /\b\d{6,12}:[A-Za-z0-9_-]{30,}\b/;

function formatArchiveFilename(index: number, timestamp: number): string {
  const ts = new Date(timestamp).toISOString().replace(/[:.]/g, "-");
  const idx = String(index).padStart(6, "0");
  return `events-${ts}-${idx}.jsonl`;
}

export function createEventArchive(options: EventArchiveOptions): EventArchive {
  const { dir } = options;
  const maxBytes = Math.max(1, options.maxBytes ?? DEFAULT_MAX_BYTES);
  const maxFiles = Math.max(1, options.maxFiles ?? DEFAULT_MAX_FILES);

  let currentHandle: any = null;
  let currentFilePath: string | null = null;
  let currentSize = 0;
  let fileIndex = 0;
  let closed = false;

  let queue: Promise<void> = Promise.resolve();

  async function rotateIfNeeded(additionalBytes: number): Promise<void> {
    if (currentHandle && currentSize + additionalBytes <= maxBytes) {
      return;
    }

    if (currentHandle) {
      await currentHandle.sync();
      await currentHandle.close();
      currentHandle = null;
      currentFilePath = null;
    }

    await mkdir(dir, { recursive: true });

    // Enforce maxFiles by deleting older files if needed
    const existing = await listArchiveFiles(dir);
    // If we're creating a new file, we'll have existing.length + 1 files.
    // If existing.length + 1 > maxFiles, remove oldest so we stay within maxFiles.
    const toRemoveCount = Math.max(0, existing.length + 1 - maxFiles);
    for (let i = 0; i < toRemoveCount; i++) {
      const target = existing[i];
      if (!target) continue;
      try {
        await unlink(path.join(dir, target));
      } catch {
        // ignore
      }
    }

    fileIndex += 1;
    const filename = formatArchiveFilename(fileIndex, Date.now());
    currentFilePath = path.join(dir, filename);

    // Open with 'a+' flag (append and reading), 0o600 permissions
    currentHandle = await open(currentFilePath, "a+", FILE_MODE);
    try {
      await chmod(currentFilePath, FILE_MODE);
    } catch {
      // chmod might not be fully supported on some OS/filesystems, safe to ignore
    }

    const st = await currentHandle.stat();
    currentSize = st.size;
  }

  async function doAppend(events: readonly DecodedEvent[]): Promise<void> {
    if (closed) {
      throw new Error("Event archive is closed");
    }
    if (!events || events.length === 0) return;

    for (const event of events) {
      const line = JSON.stringify(event, scanJsonReplacer) + "\n";
      const buffer = Buffer.from(line, "utf8");
      const bytes = buffer.byteLength;

      // Rotate if adding this line exceeds maxBytes, or if no file opened yet
      if (!currentHandle || currentSize + bytes > maxBytes) {
        await rotateIfNeeded(bytes);
      }

      await currentHandle.write(buffer);
      await currentHandle.sync();
      currentSize += bytes;
    }
  }

  async function doClose(): Promise<void> {
    if (closed) return;
    closed = true;
    if (currentHandle) {
      await currentHandle.sync();
      await currentHandle.close();
      currentHandle = null;
    }
  }

  return {
    async append(events: readonly DecodedEvent[]): Promise<void> {
      queue = queue.then(() => doAppend(events));
      return queue;
    },
    async close(): Promise<void> {
      queue = queue.then(() => doClose());
      return queue;
    },
  };
}

async function listArchiveFiles(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir);
    return entries
      .filter((name) => name.startsWith("events-") && name.endsWith(".jsonl"))
      .sort();
  } catch {
    return [];
  }
}

export async function* readArchive(
  dir: string,
  options: ReadArchiveOptions = {},
): AsyncGenerator<DecodedEvent, void, unknown> {
  const files = await listArchiveFiles(dir);
  const stagedEvents: DecodedEvent[] = [];
  const retainCommitted = options.retainCommitted === true;

  for (const file of files) {
    const filePath = path.join(dir, file);
    const handle = await open(filePath, "r");
    try {
      const content = await handle.readFile({ encoding: "utf8" });
      const lines = content.split("\n");
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index]!;
        const trimmed = line.trim();
        if (!trimmed) continue;
        let parsed: DecodedEvent;
        try {
          parsed = JSON.parse(trimmed) as DecodedEvent;
        } catch {
          throw new MalformedArchiveRecordError(file, index + 1);
        }

        if (retainCommitted) {
          yield parsed;
        } else {
          stagedEvents.push(parsed);
        }
      }
    } finally {
      await handle.close();
    }
  }

  for (const event of stagedEvents) {
    yield event;
  }
}

function redactPreview(value: string): string {
  if (value.length <= 4) return "****";
  return `${value.slice(0, 2)}***${value.slice(-2)}`;
}

function scanValue(
  value: unknown,
  jsonPath: string,
  keyHint: string | undefined,
  emit: (kind: PrivacyFindingKind, jsonPath: string, raw: string) => void,
): void {
  if (typeof value === "string") {
    if (keyHint && PRIVATE_CHAT_KEY_PATTERN.test(keyHint) && /^\d+$/.test(value)) {
      emit("private_chat_id", jsonPath, value);
    } else if (keyHint && SECRET_KEY_PATTERN.test(keyHint) && value.length > 0) {
      emit("secret_value", jsonPath, value);
    } else {
      const seed = value.match(STELLAR_SECRET_SEED_PATTERN);
      if (seed) emit("secret_value", jsonPath, seed[0]);
      const token = value.match(BOT_TOKEN_PATTERN);
      if (token) emit("secret_value", jsonPath, token[0]);
    }
    return;
  }
  if (typeof value === "number" && keyHint && PRIVATE_CHAT_KEY_PATTERN.test(keyHint)) {
    if (Number.isInteger(value) && value > 0) {
      emit("private_chat_id", jsonPath, String(value));
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => scanValue(item, `${jsonPath}[${i}]`, undefined, emit));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      scanValue(child, `${jsonPath}.${key}`, key, emit);
    }
  }
}

/**
 * Deterministically scan archived JSONL records for private chat identifiers and
 * secret-shaped values. Reads only local archive files; performs no network I/O.
 */
export async function reviewArchivePrivacy(dir: string): Promise<PrivacyReviewReport> {
  const files = await listArchiveFiles(dir);
  const findings: PrivacyFinding[] = [];
  let recordsScanned = 0;

  for (const file of files) {
    const handle = await open(path.join(dir, file), "r");
    try {
      const content = await handle.readFile({ encoding: "utf8" });
      const lines = content.split("\n");
      for (let index = 0; index < lines.length; index += 1) {
        const trimmed = lines[index]!.trim();
        if (!trimmed) continue;
        recordsScanned += 1;
        let parsed: unknown;
        try {
          parsed = JSON.parse(trimmed);
        } catch {
          throw new MalformedArchiveRecordError(file, index + 1);
        }
        scanValue(parsed, "$", undefined, (kind, jsonPath, raw) => {
          findings.push({
            kind,
            fileName: file,
            lineNumber: index + 1,
            jsonPath,
            preview: redactPreview(raw),
          });
        });
      }
    } finally {
      await handle.close();
    }
  }

  return { filesScanned: files.length, recordsScanned, findings };
}
