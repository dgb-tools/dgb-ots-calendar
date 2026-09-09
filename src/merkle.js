// Calendar aggregation: an hour of submitted digests → one Merkle root, with each leaf's
// OTS op path (append/prepend + sha256), the same construction OTS calendars use
// (opentimestamps-server: cat_sha256 pairing; odd nodes carried up unchanged). Pure functions.
import { createHash } from "node:crypto";
import { TAG, applyOp } from "./ots.js";
const sha256 = (b) => createHash("sha256").update(b).digest();

/** leaves: Buffer[] → { root, paths } where applying paths[i] to leaves[i] yields root. */
export function buildTree(leaves) {
  if (leaves.length === 0) throw new Error("no leaves");
  const leafNodes = leaves.map((msg) => ({ msg: Buffer.from(msg), ops: [], parent: null }));
  let level = leafNodes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 >= level.length) { next.push(level[i]); continue; }        // carried up, no ops
      const l = level[i], r = level[i + 1];
      const node = { msg: sha256(Buffer.concat([l.msg, r.msg])), ops: [], parent: null };
      l.ops = [{ tag: TAG.append, arg: r.msg }, { tag: TAG.sha256 }]; l.parent = node;   // ops lifting l.msg → node.msg
      r.ops = [{ tag: TAG.prepend, arg: l.msg }, { tag: TAG.sha256 }]; r.parent = node;
      next.push(node);
    }
    level = next;
  }
  const root = level[0].msg;
  const paths = leafNodes.map((n) => { const ops = []; for (let x = n; x.parent; x = x.parent) ops.push(...x.ops); return ops; });
  return { root, paths };
}
export function applyPath(msg, ops) { let m = Buffer.from(msg); for (const op of ops) m = applyOp(op, m); return m; }
