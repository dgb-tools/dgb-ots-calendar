// Chain adapter for the batcher: talks to a local DigiByte node through `digibyte-cli` so this
// process never sees RPC credentials (the CLI reads them from the datadir). Constrained on purpose:
// it will only ever sign and send a transaction with exactly one OP_RETURN output of the shape
// DGAT + 32 bytes, with a fee under a hard cap; anything else aborts before signing. The policy
// limits (one send per hour, daily cap) are enforced here too, in a small state file.
import fs from "node:fs"; import { execFile } from "node:child_process";
export const LIMITS = { maxFeeDgb: 0.01, maxSendsPerDay: 48, minSecondsBetweenSends: 3000 };
const DGAT_HEX = "44474154";

export function cliRunner({ cli, datadir, wallet, chainArgs = [] }) {
  return (method, params = []) => new Promise((resolve, reject) => {
    const args = [`-datadir=${datadir}`, ...chainArgs, `-rpcclienttimeout=60`];
    if (wallet) args.push(`-rpcwallet=${wallet}`);
    args.push(method, ...params.map((p) => (typeof p === "string" ? p : JSON.stringify(p))));
    execFile(cli, args, { maxBuffer: 64 << 20, windowsHide: true }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`${method}: ${(stderr || err.message).trim().slice(0, 300)}`));
      const out = stdout.trim(); try { resolve(JSON.parse(out)); } catch { resolve(out); }
    });
  });
}

/** rpc: (method, params) => Promise<json|string>. statePath: JSON file with { sends: [unixSeconds...] }. */
export function makeAdapter({ rpc, statePath, limits = LIMITS, now = () => Math.floor(Date.now() / 1000) }) {
  const loadState = () => (fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, "utf8")) : { sends: [] });
  const saveState = (s) => fs.writeFileSync(statePath, JSON.stringify(s));
  function checkBudget() {
    const s = loadState(); const t = now(); const day = s.sends.filter((x) => t - x < 86400);
    if (day.length >= limits.maxSendsPerDay) throw new Error(`send budget exhausted: ${day.length} sends in 24h (cap ${limits.maxSendsPerDay})`);
    const last = s.sends[s.sends.length - 1]; if (last && t - last < limits.minSecondsBetweenSends) throw new Error(`too soon after last send (${t - last}s < ${limits.minSecondsBetweenSends}s)`);
  }
  return {
    /** payload: Buffer of exactly 36 bytes (DGAT + root). Returns txid. */
    async sendPayload(payload) {
      if (!Buffer.isBuffer(payload) || payload.length !== 36 || payload.subarray(0, 4).toString("hex") !== DGAT_HEX) throw new Error("payload must be DGAT + 32 bytes");
      checkBudget();
      const raw = await rpc("createrawtransaction", [[], [{ data: payload.toString("hex") }]]);
      const funded = await rpc("fundrawtransaction", [raw]);
      if (typeof funded.fee !== "number" || funded.fee > limits.maxFeeDgb) throw new Error(`fee ${funded.fee} DGB exceeds cap ${limits.maxFeeDgb}`);
      // shape check BEFORE signing: exactly one OP_RETURN output and it is our payload
      const dec = await rpc("decoderawtransaction", [funded.hex]);
      const oprets = dec.vout.filter((o) => (o.scriptPubKey?.type === "nulldata") || (o.scriptPubKey?.hex || "").startsWith("6a"));
      if (oprets.length !== 1) throw new Error(`expected exactly one OP_RETURN output, found ${oprets.length}`);
      if (oprets[0].scriptPubKey.hex !== "6a24" + payload.toString("hex")) throw new Error("OP_RETURN output is not the payload");
      if (dec.vout.length > 2) throw new Error(`unexpected output count ${dec.vout.length}`);
      const signed = await rpc("signrawtransactionwithwallet", [funded.hex]);
      if (!signed.complete) throw new Error("wallet could not fully sign");
      const txid = await rpc("sendrawtransaction", [signed.hex]);
      const s = loadState(); s.sends.push(now()); s.sends = s.sends.slice(-200); saveState(s);
      return txid;
    },
    /** Poll until the tx has >= 1 confirmation. Returns { rawTxHex, height, blockHash, txids }. */
    async waitMined(txid, { pollSeconds = 30, maxSeconds = 7200, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
      const t0 = now();
      for (;;) {
        const tx = await rpc("gettransaction", [txid]);
        if (tx.blockhash && tx.confirmations >= 1) {
          const blk = await rpc("getblock", [tx.blockhash, 1]);
          const rawTxHex = await rpc("getrawtransaction", [txid, false, tx.blockhash]);
          return { rawTxHex, height: blk.height, blockHash: tx.blockhash, txids: blk.tx, confirmations: tx.confirmations };
        }
        if (now() - t0 > maxSeconds) throw new Error(`tx ${txid} not mined after ${maxSeconds}s`);
        await sleep(pollSeconds * 1000);
      }
    },
    /** Confirmations now, for the finality policy (pending until POLICY.confirmations). */
    async confirmations(txid) { const tx = await rpc("gettransaction", [txid]); return tx.confirmations || 0; },
  };
}
