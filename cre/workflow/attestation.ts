import { sha256 } from "@noble/hashes/sha2.js"
import { bytesToHex } from "@noble/hashes/utils.js"

/** Must stay aligned with app/attestation.py. Counts and hashes only. */

export const SCHEMA = "lawbat.redaction-attestation/1"
export const PROJECTION_SCHEMA = "lawbat.redaction-report-projection/1"
export const NOTE =
  "hashes and counts only; no document text leaves this record. Not a clearance to disclose the document."

const SHA = /^[0-9a-f]{64}$/
const CATEGORY = /^[a-z][a-z0-9_]{0,31}$/
const STATE = /^[a-z0-9_]{0,32}$/
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const VERSION = /^[0-9A-Za-z._+-]{1,32}$/
const K_UNIQUE = 1
const K_HIGH = 20

export interface ReidRisk {
  k: number | null
  level: "not_assessed" | "noted" | "high" | "unique"
  level_code: 0 | 1 | 2 | 3
  is_estimate: true
  direction: "optimistic — may under-state risk"
}

export interface Attestation {
  schema: typeof SCHEMA
  note: typeof NOTE
  document_sha256: string
  report_sha256: string
  counts_by_category: Record<string, number>
  accepted: number
  rejected: number
  could_not_remove: number
  ocr_used: boolean
  verification_state: string
  reid_risk: ReidRisk
  tool_version: string
  timestamp: string
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonical(item)).join(",")}]`
  }
  const record = value as Record<string, unknown>
  const keys = Object.keys(record).sort()
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`
}

export function projectionDigest(attestation: {
  document_sha256: string
  counts_by_category: Record<string, number>
  accepted: number
  rejected: number
  could_not_remove: number
  ocr_used: boolean
  verification_state: string
}): string {
  const body = {
    schema: PROJECTION_SCHEMA,
    document_sha256: attestation.document_sha256,
    counts_by_category: attestation.counts_by_category,
    accepted: attestation.accepted,
    rejected: attestation.rejected,
    could_not_remove: attestation.could_not_remove,
    ocr_used: attestation.ocr_used,
    verification_state: attestation.verification_state,
  }
  return bytesToHex(sha256(new TextEncoder().encode(canonical(body))))
}

function requireInt(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 1_000_000) {
    throw new Error(`${name} must be a non-negative integer`)
  }
  return value
}

function riskFromK(k: unknown): ReidRisk {
  const direction = "optimistic — may under-state risk" as const
  if (k === null) {
    return { k: null, level: "not_assessed", level_code: 0, is_estimate: true, direction }
  }
  if (typeof k !== "number" || !Number.isFinite(k) || k < 0) {
    throw new Error("reid_k must be a non-negative number")
  }
  if (k <= K_UNIQUE) {
    return { k, level: "unique", level_code: 3, is_estimate: true, direction }
  }
  if (k <= K_HIGH) {
    return { k, level: "high", level_code: 2, is_estimate: true, direction }
  }
  return { k, level: "noted", level_code: 1, is_estimate: true, direction }
}

const LOOPBACK_ATTESTATION =
  /^http:\/\/(127\.0\.0\.1|localhost)(:\d{1,5})?\/attestation\/?$/

export function assertLoopbackAttestationUrl(url: string): void {
  if (!LOOPBACK_ATTESTATION.test(url)) {
    throw new Error("attestation URL must be http://127.0.0.1:<port>/attestation")
  }
}

export function validateAttestation(input: unknown): Attestation {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("attestation must be an object")
  }
  const raw = input as Record<string, unknown>
  if (raw.schema !== SCHEMA) throw new Error("attestation schema is not recognised")
  if (raw.note !== NOTE) throw new Error("attestation note was replaced")
  if (typeof raw.document_sha256 !== "string" || !SHA.test(raw.document_sha256)) {
    throw new Error("document_sha256 must be the redacted output hash")
  }
  if (typeof raw.report_sha256 !== "string" || !SHA.test(raw.report_sha256)) {
    throw new Error("report_sha256 is not a hash")
  }
  if (raw.counts_by_category === null || typeof raw.counts_by_category !== "object" || Array.isArray(raw.counts_by_category)) {
    throw new Error("counts_by_category must be an object")
  }
  const counts: Record<string, number> = {}
  const entries = Object.entries(raw.counts_by_category as Record<string, unknown>)
  if (entries.length > 32) throw new Error("too many redaction categories")
  for (const [key, value] of entries) {
    if (!CATEGORY.test(key)) throw new Error("a redaction category name is not allowed")
    counts[key] = requireInt(value, "category count")
  }
  const ordered: Record<string, number> = {}
  for (const key of Object.keys(counts).sort()) ordered[key] = counts[key]
  const attestation: Attestation = {
    schema: SCHEMA,
    note: NOTE,
    document_sha256: raw.document_sha256,
    report_sha256: raw.report_sha256,
    counts_by_category: ordered,
    accepted: requireInt(raw.accepted, "accepted"),
    rejected: requireInt(raw.rejected, "rejected"),
    could_not_remove: requireInt(raw.could_not_remove, "could_not_remove"),
    ocr_used: raw.ocr_used === true,
    verification_state: typeof raw.verification_state === "string" ? raw.verification_state : "",
    reid_risk: riskFromK((raw.reid_risk as { k?: unknown } | undefined)?.k),
    tool_version: typeof raw.tool_version === "string" ? raw.tool_version : "",
    timestamp: typeof raw.timestamp === "string" ? raw.timestamp : "",
  }
  if (raw.ocr_used !== true && raw.ocr_used !== false) throw new Error("ocr_used must be boolean")
  if (!STATE.test(attestation.verification_state)) throw new Error("verification_state is not allowed")
  if (!VERSION.test(attestation.tool_version)) throw new Error("tool_version is not allowed")
  if (!TIMESTAMP.test(attestation.timestamp)) throw new Error("timestamp must be UTC")
  const risk = raw.reid_risk as ReidRisk
  if (!risk || risk.level !== attestation.reid_risk.level || risk.level_code !== attestation.reid_risk.level_code) {
    throw new Error("reid_risk level does not match its score")
  }
  if (risk.is_estimate !== true) throw new Error("reid_risk must stay an estimate")
  if (projectionDigest(attestation) !== attestation.report_sha256) {
    throw new Error("report_sha256 does not match the attestation facts")
  }
  return attestation
}

export function unixSeconds(timestamp: string): bigint {
  const millis = Date.parse(timestamp)
  if (!Number.isFinite(millis)) throw new Error("timestamp must be UTC")
  return BigInt(Math.floor(millis / 1000))
}
