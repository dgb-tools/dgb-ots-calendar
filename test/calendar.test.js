import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs"; import os from "node:os"; import path from "node:path"; import { createHash, randomBytes } from "node:crypto";
import { Calendar, parseTimestamp, POLICY } from "../src/calendar.js"; import { runBatch } from "../src/batcher.js"; import { attestations, parseOts, serializeOts, TAG } from "../src/ots.js"; import { applyPath } from "../src/merkle.js"; import { readBlockTxs, merklePathOps } from "../src/chain.js";
const meta = JSON.parse(fs.readFileSync(new URL("./vectors/block.json", import.meta.url))); const blk = Buffer.from(fs.readFileSync(new URL("./vectors/block.hex", import.meta.url), "utf8").trim(), "hex");
const sha256d = (b) => createHash("sha256").update(createHash("sha256").update(b).digest()).digest();
// fabricate a mined tx carrying DGAT+root as a single OP_RETURN output, inside a "block" made of the fixture's txids plus ours
function fakeAdapter() { let payload, txhex, txid; return {
  async sendPayload(p) { payload = p; const out = Buffer.concat([Buffer.alloc(8, 0), Buffer.from([0x26, 0x6a, 0x24]), p]); const tx = Buffer.concat([Buffer.from("02000000", "hex"), Buffer.from("01", "hex"), randomBytes(32), Buffer.from("00000000", "hex"), Buffer.from("00", "hex"), Buffer.from("ffffffff", "hex"), Buffer.from("01", "hex"), out, Buffer.from("00000000", "hex")]); txhex = tx.toString("hex"); txid = Buffer.from(sha256d(tx)).reverse().toString("hex"); return txid; },
  async waitMined(id) { assert.equal(id, txid); return { rawTxHex: txhex, height: 24183559, blockHash: meta.hash, txids: [...meta.txids, txid] }; } }; }
test("submit → batch → upgraded .ots lifts the original digest to the block merkle root", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cal-")); const cal = new Calendar({ dir, uri: "https://calendar.dgbinsights.com" });
  const digests = Array.from({ length: 5 }, () => randomBytes(32)); const subs = digests.map((d) => cal.submit(d));
  // submission response: append nonce, sha256, pending(uri) — parseable as a Timestamp for the digest
  const ts0 = parseTimestamp(subs[0].timestampBytes, digests[0]); const a0 = attestations(ts0); assert.equal(a0.length, 1); assert.equal(a0[0].attestation.type, "pending"); assert.equal(a0[0].msg.toString("hex"), subs[0].commitment.toString("hex"));
  assert.equal(cal.get(subs[0].commitment.toString("hex")), null);
  const adapter = fakeAdapter(); const r = await runBatch(cal, adapter, { since: 0 }); assert.equal(r.leaves, 5);
  const expectedRoot = merklePathOps([...meta.txids, r.txid], meta.txids.length).root; assert.equal(r.merkleRoot, expectedRoot);
  for (let i = 0; i < 5; i++) { const up = cal.get(subs[i].commitment.toString("hex")); assert.ok(up, "upgraded available"); const ts = parseTimestamp(up, subs[i].commitment); const atts = attestations(ts); assert.equal(atts.length, 1); assert.equal(atts[0].attestation.type, "digibyte"); assert.equal(atts[0].attestation.tag, POLICY.tag); assert.equal(atts[0].attestation.height, 24183559);
    assert.equal(Buffer.from(atts[0].msg).reverse().toString("hex"), expectedRoot, "attested message is the block merkle root (shape A)"); }
  // full file: client-side splice of submission ops + upgrade, then stock-format round trip
  const full = { fileHashOp: TAG.sha256, digest: digests[0], timestamp: ts0 }; const pendingNode = (function find(t) { if (t.attestations.length) return t; for (const [, c] of t.ops) { const f = find(c); if (f) return f; } })(ts0);
  const upgraded = parseTimestamp(cal.get(subs[0].commitment.toString("hex")), subs[0].commitment); pendingNode.attestations = []; pendingNode.ops = upgraded.ops;
  const bytes = serializeOts(full); const again = parseOts(bytes); assert.equal(again.digest.toString("hex"), digests[0].toString("hex")); const fa = attestations(again.timestamp); assert.equal(fa[0].attestation.type, "digibyte"); assert.equal(Buffer.from(fa[0].msg).reverse().toString("hex"), expectedRoot);
  fs.writeFileSync(new URL("./vectors/example-upgraded.ots", import.meta.url), bytes);
});
