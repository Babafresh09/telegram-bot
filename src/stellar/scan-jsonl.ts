import { createHash } from "node:crypto";
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

/**
 * Hash-chained manifest binding ordered records, network and ledger bounds
 * to a single digest. Each record hash commits to the previous record hash,
 * so missing, reordered or altered records fail verification.
 */
export interface ScanJsonlManifest {
  type: "manifest";
  version: 1;
  network: string;
  ledgerMin: number | null;
  ledgerMax: number | null;
  recordCount: number;
  recordHashes: string[];
  chainHead: string;
}

const GENESIS_HASH = "0".repeat(64);

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function chainStep(prevHash: string, recordLine: string): string {
  return sha256Hex(`${prevHash}\n${recordLine}`);
}

function ledgerOf(event: DecodedEvent): number | null {
  const ledger = (event as { ledger?: unknown }).ledger;
  return typeof ledger === "number" && Number.isFinite(ledger) ? ledger : null;
}

/**
 * Format decoded events as JSON Lines (NDJSON): one event line per decoded
 * event followed by a final `{ type: "summary" }` line containing the
 * histogram from {@link eventHistogram}, then a hash-chained manifest line
 * binding the ordered records, network and ledger bounds.
 */
export function formatScanJsonl(
  events: readonly DecodedEvent[],
  network = "unknown",
): string {
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

  const recordHashes: string[] = [];
  let head = GENESIS_HASH;
  for (const line of lines) {
    head = chainStep(head, line);
    recordHashes.push(head);
  }

  const ledgers = events.map(ledgerOf).filter((l): l is number => l !== null);
  const manifest: ScanJsonlManifest = {
    type: "manifest",
    version: 1,
    network,
    ledgerMin: ledgers.length ? Math.min(...ledgers) : null,
    ledgerMax: ledgers.length ? Math.max(...ledgers) : null,
    recordCount: lines.length,
    recordHashes,
    chainHead: head,
  };
  lines.push(JSON.stringify(manifest, scanJsonReplacer));
  return lines.join("\n") + "\n";
}

export interface VerifyScanJsonlResult {
  ok: boolean;
  reason?: string;
}

/**
 * Verify a JSONL export produced by {@link formatScanJsonl}. Rejects missing,
 * reordered or altered records, and any mismatch in network or ledger bounds.
 */
export function verifyScanJsonl(text: string): VerifyScanJsonlResult {
  const all = text.split("\n");
  if (all[all.length - 1] === "") all.pop();
  if (all.length < 2) return { ok: false, reason: "missing manifest" };

  const manifestLine = all[all.length - 1];
  const recordLines = all.slice(0, -1);
  let manifest: ScanJsonlManifest;
  try {
    manifest = JSON.parse(manifestLine) as ScanJsonlManifest;
  } catch {
    return { ok: false, reason: "manifest is not valid JSON" };
  }
  if (manifest.type !== "manifest") return { ok: false, reason: "missing manifest" };
  if (manifest.recordCount !== recordLines.length) {
    return { ok: false, reason: "record count mismatch" };
  }
  if (!Array.isArray(manifest.recordHashes) || manifest.recordHashes.length !== recordLines.length) {
    return { ok: false, reason: "record hash count mismatch" };
  }

  let head = GENESIS_HASH;
  for (let i = 0; i < recordLines.length; i++) {
    head = chainStep(head, recordLines[i]);
    if (head !== manifest.recordHashes[i]) {
      return { ok: false, reason: `record ${i} altered, reordered or missing` };
    }
  }
  if (head !== manifest.chainHead) return { ok: false, reason: "chain head mismatch" };

  const events: DecodedEvent[] = [];
  for (const line of recordLines) {
    const parsed = JSON.parse(line) as { type: string };
    if (parsed.type === "event") events.push(parsed as unknown as DecodedEvent);
  }
  const ledgers = events.map(ledgerOf).filter((l): l is number => l !== null);
  const ledgerMin = ledgers.length ? Math.min(...ledgers) : null;
  const ledgerMax = ledgers.length ? Math.max(...ledgers) : null;
  if (ledgerMin !== manifest.ledgerMin || ledgerMax !== manifest.ledgerMax) {
    return { ok: false, reason: "ledger bounds mismatch" };
  }
  return { ok: true };
}
