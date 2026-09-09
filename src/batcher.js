// Hourly batch: pending commitments → tree → one OP_RETURN tx (DGAT + root) → wait for a block →
// record every commitment's path to the DigiByte attestation. The chain adapter is injected so
// the batch logic is testable offline; the RPC adapter (attest-mcp's create/fund/sign/send path)
// is the only place that touches a wallet, and only the capped anchor wallet, only on the VPS.
import { makeBatch } from "./calendar.js"; import { readTx } from "./chain.js";
/** adapter: { sendPayload(payloadBuf) → txid; waitMined(txid) → { rawTxHex, height, blockHash, txids } } */
export async function runBatch(cal, adapter, { since }) {
  const leaves = cal.pendingSince(since); if (leaves.length === 0) return { leaves: 0 };
  const { root, paths, payload } = makeBatch(leaves);
  const txid = await adapter.sendPayload(payload);
  const mined = await adapter.waitMined(txid);
  const tx = readTx(Buffer.from(mined.rawTxHex, "hex"), 0); if (tx.txid !== txid) throw new Error("adapter returned a different tx");
  const out = tx.vout.find((o) => o.script.length === 38 && o.script[0] === 0x6a && o.script[1] === 0x24 && o.script.subarray(2, 6).toString("ascii") === "DGAT");
  if (!out) throw new Error("no DGAT output in mined tx"); const payloadOffset = out.scriptOffset + 6; // after 6a 24 'DGAT'
  const idx = mined.txids.indexOf(txid); if (idx < 0) throw new Error("txid not in block");
  const rootFromChain = cal.recordBatch({ leavesHex: leaves, paths, tx, payloadOffset, txids: mined.txids, txIndex: idx, height: mined.height });
  return { leaves: leaves.length, root: root.toString("hex"), txid, height: mined.height, blockHash: mined.blockHash, merkleRoot: rootFromChain };
}
