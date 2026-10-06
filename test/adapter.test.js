import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs"; import os from "node:os"; import path from "node:path"; import { randomBytes } from "node:crypto";
import { makeAdapter, LIMITS } from "../src/adapter-cli.js";
const payload = Buffer.concat([Buffer.from("DGAT", "ascii"), randomBytes(32)]);
function fakeRpc({ fee = 0.0002, extraOpret = false, outputs = 2, incomplete = false } = {}) {
  const calls = []; const txid = randomBytes(32).toString("hex");
  return { calls, txid, rpc: async (m, p) => { calls.push(m);
    if (m === "createrawtransaction") return "00raw";
    if (m === "fundrawtransaction") return { hex: "00funded", fee };
    if (m === "decoderawtransaction") { const v = [{ scriptPubKey: { type: "witness_v0_keyhash", hex: "0014" + "00".repeat(20) } }, { scriptPubKey: { type: "nulldata", hex: "6a24" + payload.toString("hex") } }]; if (extraOpret) v.push({ scriptPubKey: { type: "nulldata", hex: "6a04deadbeef" } }); while (v.length < outputs) v.push({ scriptPubKey: { type: "witness_v0_keyhash", hex: "0014" + "11".repeat(20) } }); return { vout: v }; }
    if (m === "signrawtransactionwithwallet") return { hex: "00signed", complete: !incomplete };
    if (m === "sendrawtransaction") return txid;
    if (m === "gettransaction") return { blockhash: "ab".repeat(32), confirmations: 1 };
    if (m === "getblock") return { height: 24183559, tx: ["x", txid] };
    if (m === "getrawtransaction") return "00mined";
    throw new Error("unexpected " + m); } };
}
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "adp-")), "state.json");
test("happy path: create → fund → decode shape check → sign → send; then waitMined", async () => {
  const f = fakeRpc(); const a = makeAdapter({ rpc: f.rpc, statePath: tmp() }); const id = await a.sendPayload(payload); assert.equal(id, f.txid);
  assert.deepEqual(f.calls, ["createrawtransaction", "fundrawtransaction", "decoderawtransaction", "signrawtransactionwithwallet", "sendrawtransaction"]);
  const m = await a.waitMined(id, { pollSeconds: 0 }); assert.equal(m.height, 24183559); assert.equal(m.txids[1], id); assert.equal(m.rawTxHex, "00mined");
});
test("refuses before signing: wrong payload, fee over cap, second OP_RETURN, incomplete signature", async () => {
  await assert.rejects(makeAdapter({ rpc: fakeRpc().rpc, statePath: tmp() }).sendPayload(Buffer.alloc(36)), /DGAT/);
  const f1 = fakeRpc({ fee: 0.5 }); await assert.rejects(makeAdapter({ rpc: f1.rpc, statePath: tmp() }).sendPayload(payload), /fee .* exceeds cap/); assert.ok(!f1.calls.includes("signrawtransactionwithwallet"));
  const f2 = fakeRpc({ extraOpret: true }); await assert.rejects(makeAdapter({ rpc: f2.rpc, statePath: tmp() }).sendPayload(payload), /exactly one OP_RETURN/); assert.ok(!f2.calls.includes("signrawtransactionwithwallet"));
  const f3 = fakeRpc({ incomplete: true }); await assert.rejects(makeAdapter({ rpc: f3.rpc, statePath: tmp() }).sendPayload(payload), /could not fully sign/); assert.ok(!f3.calls.includes("sendrawtransaction"));
});
test("budget: one send per hour and a daily cap, persisted", async () => {
  let t = 1_800_000_000; const st = tmp(); const a = makeAdapter({ rpc: fakeRpc().rpc, statePath: st, now: () => t });
  await a.sendPayload(payload); await assert.rejects(a.sendPayload(payload), /too soon/); t += 3600; await a.sendPayload(payload);
  const b = makeAdapter({ rpc: fakeRpc().rpc, statePath: st, now: () => t, limits: { ...LIMITS, maxSendsPerDay: 2 } }); t += 3600; await assert.rejects(b.sendPayload(payload), /budget exhausted/);
});
