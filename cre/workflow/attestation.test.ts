import { describe, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { projectionDigest, validateAttestation } from "./attestation"

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..")

function sampleAttestation(): unknown {
  const ran = spawnSync(
    "python3",
    ["-m", "app.attestation", "sample", "--out", "-"],
    { cwd: repoRoot, env: { ...process.env, PYTHONPATH: repoRoot }, encoding: "utf-8" },
  )
  if (ran.status !== 0) {
    throw new Error(ran.stderr || "sample attestation failed")
  }
  return JSON.parse(ran.stdout)
}

describe("attestation", () => {
  test("matches the Python report hash and accepts the sample", () => {
    const sample = sampleAttestation() as {
      document_sha256: string
      report_sha256: string
      counts_by_category: Record<string, number>
      accepted: number
      rejected: number
      could_not_remove: number
      ocr_used: boolean
      verification_state: string
    }
    expect(projectionDigest(sample)).toBe(sample.report_sha256)
    const checked = validateAttestation(sample)
    expect(checked.reid_risk.level).toBe("high")
    expect(checked.reid_risk.level_code).toBe(2)
  })

  test("refuses a swapped report hash", () => {
    const sample = sampleAttestation() as { report_sha256: string }
    sample.report_sha256 = "ab".repeat(32)
    expect(() => validateAttestation(sample)).toThrow(/report_sha256/)
  })
})
