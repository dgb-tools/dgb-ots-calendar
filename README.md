# dgb-ots-calendar

**Status: code and offline tests only. Not deployed. No calendar is running.** An
[OpenTimestamps](https://opentimestamps.org) calendar that anchors an hourly Merkle root in
DigiByte instead of Bitcoin, carrying an **experimental DigiByte block-header attestation**
inside a standard OTS proof. Design red-teamed 2026-09-09 (dgb-tools crew, Roundtables 1 and 4).

## What it is, exactly

- The calendar speaks the OTS calendar protocol: `POST /digest` (exactly 32 bytes) returns a
  timestamp ending in `PendingAttestation("https://calendar.dgbinsights.com")`;
  `GET /timestamp/<commitment>` returns the upgraded ops once the batch is in a block.
  `ots stamp -c https://calendar.dgbinsights.com` would work unmodified.
- Every hour the batcher builds a Merkle tree of the submitted commitments (plain OTS
  `append`/`prepend`/`sha256`, no custom ops), writes the 32-byte root in one `OP_RETURN`
  (`DGAT` + root; the prefix is a scanner hint, never an op in the tree), and records for
  each commitment the ops that lift it through the tree, through the transaction's non-witness
  bytes, and up the block's transaction Merkle path to `hashMerkleRoot`. **Shape A:** the
  attestation means *this message equals the Merkle root of DigiByte block N*, exactly what
  Bitcoin and Litecoin attestations mean. A stranger with DigiByte block headers can verify it
  without this server.
- Attestation tag `ba06cf2dad632400` = first 8 bytes of `SHA256("DigiByteBlockHeaderAttestation/v1")`,
  payload = varint block height. Reproducible; published as hex.

## What it is not — receipt text, verbatim on every surface

- Experimental DigiByte block-header attestation. Not registered with, reviewed by, endorsed by,
  or supported by the OpenTimestamps project.
- Stock `ots verify` reporting `UnknownAttestation` is expected — not a pass, not a product bug.
- Not an OpenTimestamps calendar. Not an official OTS attestation. An experimental DigiByte
  extension carried in an OTS envelope.
- Claim ceiling: these exact bytes existed no later than the recorded time of DigiByte block N.
  Not authorship, not truth, not immutable, not notarized.
- `pending` / `finalized under the 100-confirmation policy` are confirmation-depth labels on our
  clock, not OTS states. 100 is a versioned policy constant (Core's coinbase maturity), never a proof.
- Verification requires DigiByte-aware software and an independently trusted DigiByte header
  chain. Trust order: your own `digibyted` → two explorers you choose → a hosted header file
  last, labeled not-a-trust-root.

## Policy (v1)

32-byte digests only · identical digests idempotent · hourly leaf cap 4096, then 503 · per-IP
rate limit at the edge · no accounts · no DigiID · no Bitcoin dual-anchor · no dashboard · no
per-item on-chain writes. Custody: the capped anchor wallet only, one transaction per hour,
fee cap, no automatic refill, proof bundle persisted off-box at anchor time. Deployment gated on
the anchor node's RPC keeper passing an induced-failure test (see `oracle-ops`).

## Layout

`src/ots.js` OTS proof codec, byte-exact with python-opentimestamps (round-trip test on a real
vector) · `src/merkle.js` calendar tree · `src/chain.js` txid, Merkle path and payload→root ops ·
`src/calendar.js` submit / upgrade store · `src/server.js` HTTP · `src/batcher.js` hourly batch
with an injected chain adapter (the RPC adapter is not in this repo yet). `npm test` runs 18
tests, including an offline end-to-end: submit → batch against a fabricated transaction inside a
real mainnet block → upgraded proof attests that block's Merkle root.

Independent community project, part of [dgb-tools](https://github.com/dgb-tools). Not affiliated
with the DigiByte Foundation or the OpenTimestamps project. MIT.
