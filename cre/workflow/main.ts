import {
  bytesToHex,
  consensusIdenticalAggregation,
  decodeJson,
  EVMClient,
  getNetwork,
  handler,
  HTTPCapability,
  HTTPClient,
  json,
  ok,
  prepareReportRequest,
  Runner,
  TxStatus,
  type HTTPPayload,
  type HTTPSendRequester,
  type Runtime,
} from "@chainlink/cre-sdk"
import { encodeAbiParameters, parseAbiParameters, type Hex } from "viem"
import { z } from "zod"
import {
  assertLoopbackAttestationUrl,
  unixSeconds,
  validateAttestation,
  type Attestation,
} from "./attestation"

const configSchema = z.object({
  attestationUrl: z.string().url(),
  chainSelectorName: z.string().min(1),
  consumerAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  gasLimit: z.string().regex(/^[0-9]+$/),
})

type Config = z.infer<typeof configSchema>

const fetchAttestation = (sendRequester: HTTPSendRequester, url: string): string => {
  assertLoopbackAttestationUrl(url)
  const response = sendRequester.sendRequest({ url, method: "GET" }).result()
  if (!ok(response)) {
    throw new Error(`Lawbat attestation request failed with status ${response.statusCode}`)
  }
  return JSON.stringify(validateAttestation(json(response)))
}

const onHttpTrigger = (runtime: Runtime<Config>, payload: HTTPPayload): string => {
  const input = decodeJson(payload.input) as { attestationUrl?: string } | null
  const url = input && typeof input.attestationUrl === "string" ? input.attestationUrl : runtime.config.attestationUrl
  assertLoopbackAttestationUrl(url)

  const httpClient = new HTTPClient()
  const raw = httpClient
    .sendRequest(runtime, fetchAttestation, consensusIdenticalAggregation<string>())(url)
    .result()
  const attestation = JSON.parse(raw) as Attestation
  runtime.log(
    `Validated attestation doc=${attestation.document_sha256} risk=${attestation.reid_risk.level} categories=${Object.keys(attestation.counts_by_category).length}`,
  )

  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: runtime.config.chainSelectorName,
  })
  if (!network) {
    throw new Error(`Unknown chain selector ${runtime.config.chainSelectorName}`)
  }

  const encoded = encodeAbiParameters(
    parseAbiParameters("bytes32 docHash, bytes32 reportHash, uint8 riskLevel, uint64 ts"),
    [
      `0x${attestation.document_sha256}` as Hex,
      `0x${attestation.report_sha256}` as Hex,
      attestation.reid_risk.level_code,
      unixSeconds(attestation.timestamp),
    ],
  )
  const report = runtime.report(prepareReportRequest(encoded)).result()
  runtime.log("Signed the EVM report. Submitting it to RedactionRegistry.")

  const evmClient = new EVMClient(network.chainSelector.selector)
  const writeResult = evmClient
    .writeReport(runtime, {
      receiver: runtime.config.consumerAddress,
      report,
      gasConfig: { gasLimit: runtime.config.gasLimit },
    })
    .result()

  const txHash = bytesToHex(writeResult.txHash ?? new Uint8Array(32))
  if (writeResult.txStatus !== TxStatus.SUCCESS) {
    throw new Error(`EVM write failed with status ${String(writeResult.txStatus)} tx=${txHash}`)
  }
  runtime.log(`RedactionAttested dry-run succeeded tx=${txHash}`)
  return JSON.stringify({
    document_sha256: attestation.document_sha256,
    report_sha256: attestation.report_sha256,
    risk_level: attestation.reid_risk.level_code,
    tx_hash: txHash,
  })
}

const initWorkflow = (config: Config) => {
  // An empty authorized-key list is valid for `cre workflow simulate` only.
  // A deployed HTTP trigger must list KEY_TYPE_ECDSA_EVM keys.
  const http = new HTTPCapability()
  return [handler(http.trigger({}), onHttpTrigger)]
}

export async function main() {
  const runner = await Runner.newRunner<Config>({ configSchema })
  await runner.run(initWorkflow)
}

main()
