import type { DecodedEvent } from "./decode.js";
import { eventHistogram, scanJsonReplacer } from "./events.js";

export interface ScanJsonlEventLine extends DecodedEvent {
  type: "event";
}

export interface ScanJsonlSummaryLine {
  type: "summary";
  eventCount: number;
  histogram: Record<string, number>;
}

export interface PrivacyFinding {
  kind: "private_chat_id" | "secret_like_value";
  line: number;
  path: string;
  preview: string;
}

export interface PrivacyReviewReport {
  type: "privacy_review";
  findingCount: number;
  findings: PrivacyFinding[];
}

const PRIVATE_CHAT_KEYS = new Set(["chatId", "chat_id", "telegramChatId", "userId", "user_id"]);

const SECRET_PATTERNS: RegExp[] = [
  /\bS[A-Z2-7]{55}\b/,
  /\b(?:sk|secret|token|api[_-]?key)[=:]\s*[A-Za-z0-9_\-]{16,}/i,
  /\bBearer\s+[A-Za-z0-9._\-]{16,}/,
  /\b\d{8,12}:[A-Za-z0-9_\-]{30,}\b/,
];

function previewOf(value: string): string {
  return value.length > 12 ? `${value.slice(0, 6)}...${value.slice(-4)}` : "***";
}

function walk(
  value: unknown,
  path: string,
  line: number,
  out: PrivacyFinding[],
): void {
  if (typeof value === "string") {
    for (const pattern of SECRET_PATTERNS) {
      const match = pattern.exec(value);
      if (match) {
        out.push({ kind: "secret_like_value", line, path, preview: previewOf(match[0]) });
        break;
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => walk(item, `${path}[${i}]`, line, out));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const childPath = path ? `${path}.${key}` : key;
      if (PRIVATE_CHAT_KEYS.has(key) && (typeof child === "string" || typeof child === "number")) {
        out.push({ kind: "private_chat_id", line, path: childPath, preview: previewOf(String(child)) });
      }
      walk(child, childPath, line, out);
    }
  }
}

/**
 * Deterministically scan JSONL archive text for private chat identifiers and
 * secret-shaped values. Performs no network I/O. Findings are ordered by
 * line number, then discovery order within each line.
 */
export function reviewJsonlPrivacy(jsonl: string): PrivacyReviewReport {
  const findings: PrivacyFinding[] = [];
  const lines = jsonl.split("\n");
  lines.forEach((raw, index) => {
    const text = raw.trim();
    if (text.length === 0) return;
    const lineNo = index + 1;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      walk(text, "", lineNo, findings);
      return;
    }
    walk(parsed, "", lineNo, findings);
  });
  return { type: "privacy_review", findingCount: findings.length, findings };
}

/**
 * Format decoded events as JSON Lines (NDJSON): one event line per decoded
 * event followed by a final `{ type: "summary" }` line containing the
 * histogram from {@link eventHistogram}.
 */
export function formatScanJsonl(events: readonly DecodedEvent[]): string {
  const lines: string[] = [];
  for (const event of events) {
    lines.push(JSON.stringify({ type: "event", ...event }, scanJsonReplacer));
  }
  const summary: ScanJsonlSummaryLine = {
    type: "summary",
    eventCount: events.length,
    histogram: eventHistogram([...events]),
  };
  lines.push(JSON.stringify(summary, scanJsonReplacer));
  return lines.join("\n") + "\n";
}
