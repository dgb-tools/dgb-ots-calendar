// Calendar core, mirroring opentimestamps-server: submit() nonces the digest (append 16 random
// bytes, sha256) and returns a timestamp ending in PendingAttestation(uri); the batcher later
// builds the hour tree, anchors the root, and stores each commitment's upgraded ops.
// Storage is a JSONL journal of commitments plus one file per upgraded commitment. No accounts.
import fs from "node:fs"; import path from "node:path"; import { randomBytes } from "node:crypto";
import { TAG, ATTESTATION, serializeOts, parseOts, applyOp } from "./ots.js";
import { buildTree } from "./merkle.js"; import { payloadToRootOps } from "./chain.js";
export const POLICY = { version: 1, confirmations: 100, maxLeavesPerHour: 4096, digestBytes: 32, tag: ATTESTATION.digibyte, derivation: 'SHA256("DigiByteBlockHeaderAttestation/v1")[0:8]' };
const DGAT = Buffer.from("DGAT", "ascii");

export class Calendar {
  constructor({ dir, uri }) { this.dir = dir; this.uri = uri; fs.mkdirSync(path.join(dir, "upgraded"), { recursive: true }); this.journal = path.join(dir, "journal.jsonl"); }
  /** Submit a digest (exactly 32 bytes). Returns { commitment, timestampBytes } — the bytes are a
   *  Timestamp serialization for `digest` (no file header), as the OTS calendar protocol returns. */
  submit(digest) {
    if (!Buffer.isBuffer(digest) || digest.length !== POLICY.digestBytes) throw Object.assign(new Error("digest must be exactly 32 bytes"), { status: 400 });
    const nonce = randomBytes(16);
    const commitment = applyOp({ tag: TAG.sha256 }, applyOp({ tag: TAG.append, arg: nonce }, digest));
    const ts = { msg: digest, attestations: [], ops: [[{ tag: TAG.append, arg: nonce }, { msg: null, attestations: [], ops: [[{ tag: TAG.sha256 }, { msg: commitment, attestations: [{ type: "pending", tag: ATTESTATION.pending, uri: this.uri }], ops: [] }]] }]] };
    fs.appendFileSync(this.journal, JSON.stringify({ t: Math.floor(Date.now() / 1000), c: commitment.toString("hex") }) + "\n");
    return { commitment, timestampBytes: serializeTimestamp(ts) };
  }
  pendingSince(tSec) { if (!fs.existsSync(this.journal)) return []; return fs.readFileSync(this.journal, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((r) => r.t >= tSec && !fs.existsSync(this.upgradedPath(r.c))).map((r) => r.c); }
  upgradedPath(hex) { return path.join(this.dir, "upgraded", hex + ".ots-partial"); }
  /** GET /timestamp/<commitment>: upgraded ops from the commitment to the attestation, or null (404). */
  get(hex) { const p = this.upgradedPath(hex); return fs.existsSync(p) ? fs.readFileSync(p) : null; }
  /** After the batch tx is mined: store each commitment's full path to the DigiByte attestation. */
  recordBatch({ leavesHex, paths, tx, payloadOffset, txids, txIndex, height }) {
    const { ops: chainOps, root } = payloadToRootOps(tx, payloadOffset, 32, txids, txIndex);
    for (let i = 0; i < leavesHex.length; i++) {
      const ops = [...paths[i], ...chainOps];
      const chain = { msg: Buffer.from(leavesHex[i], "hex"), attestations: [], ops: [] }; let node = chain;
      for (const op of ops) { const child = { msg: null, attestations: [], ops: [] }; node.ops.push([op, child]); node = child; }
      node.attestations.push({ type: "digibyte", tag: POLICY.tag, height });
      fs.writeFileSync(this.upgradedPath(leavesHex[i]), serializeTimestamp(chain));
    }
    return root;
  }
}
/** Batch: tree over pending commitments → root and the 36-byte OP_RETURN payload (DGAT + root). */
export function makeBatch(leavesHex) { const leaves = leavesHex.map((h) => Buffer.from(h, "hex")); const { root, paths } = buildTree(leaves); return { root, paths, payload: Buffer.concat([DGAT, root]) }; }
// --- timestamp (without file header) serialize/parse, reusing ots.js internals via a wrapper file ---
export function serializeTimestamp(ts) { const full = serializeOts({ fileHashOp: TAG.sha256, digest: ts.msg, timestamp: ts }); return full.subarray(31 + 1 + 1 + 32); }
export function parseTimestamp(bytes, msg) { const full = Buffer.concat([Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e8929401", "hex"), Buffer.from([TAG.sha256]), msg, bytes]); return parseOts(full).timestamp; }
