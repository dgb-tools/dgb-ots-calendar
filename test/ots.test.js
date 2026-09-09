import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs";
import { parseOts, serializeOts, attestations, describe, encodeVarint, applyOp, TAG } from "../src/ots.js";
const vec = fs.readFileSync(new URL("./vectors/pending-two-calendars.ots", import.meta.url));
test("varint matches LEB128 examples", () => { assert.equal(encodeVarint(0).toString("hex"), "00"); assert.equal(encodeVarint(127).toString("hex"), "7f"); assert.equal(encodeVarint(128).toString("hex"), "8001"); assert.equal(encodeVarint(24183500).toString("hex"), "cc85c40b"); // value from python-opentimestamps write_varuint });
test("parse the reference-client vector", () => {
  const p = parseOts(vec); assert.equal(p.fileHashOp, TAG.sha256); assert.equal(p.digest.toString("hex"), "7efaa1362ef6e75662fc10ad56e95d63a0e82e0e32860b47f5fa0bb2db5eb718");
  const lines = describe(p.timestamp); assert.equal(lines[0], "append 60e8b9e8a58968773c9d88281077743f"); assert.equal(lines[1], "  sha256");
  const atts = attestations(p.timestamp); assert.equal(atts.length, 4); assert.deepEqual(atts.map((a) => a.attestation.uri).sort(), ["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org", "https://btc.calendar.catallaxy.com", "https://finney.calendar.eternitywall.com"]);
  assert.ok(atts.every((a) => a.attestation.type === "pending"));
});
test("round-trip is byte-identical", () => { assert.equal(serializeOts(parseOts(vec)).toString("hex"), vec.toString("hex")); });
test("unknown attestation tags survive a round-trip", () => {
  const p = parseOts(vec); const leaf = attestations(p.timestamp)[0]; // add an unknown attestation next to a pending one
  const find = (ts) => { if (ts.attestations.length) return ts; for (const [, c] of ts.ops) { const r = find(c); if (r) return r; } }; const node = find(p.timestamp);
  node.attestations.push({ type: "unknown", tag: "0123456789abcdef", payload: Buffer.from("cafe", "hex") });
  const again = parseOts(serializeOts(p)); const u = attestations(again.timestamp).find((a) => a.attestation.type === "unknown"); assert.equal(u.attestation.tag, "0123456789abcdef"); assert.equal(u.attestation.payload.toString("hex"), "cafe");
});
test("ops compute", () => { const d = Buffer.alloc(32, 1); assert.equal(applyOp({ tag: TAG.append, arg: Buffer.from("ff", "hex") }, d).length, 33); assert.equal(applyOp({ tag: TAG.sha256 }, d).length, 32); });
