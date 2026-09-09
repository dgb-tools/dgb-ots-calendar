// Calendar aggregation: an hour of submitted digests → one Merkle root, with each leaf's
// OTS op path (append/prepend + sha256), the same construction OTS calendars use
// (opentimestamps-server: cat_sha256 pairing). Pure functions.
import { createHash } from "node:crypto";
import { TAG, applyOp } from "./ots.js";
const sha256 = (b) => createHash("sha256").update(b).digest();

/**
 * Build the tree. leaves: Buffer[] (each a submitted commitment, typically 32 bytes).
 * Returns { root, paths } where paths[i] is the op list for leaf i: applying the ops to
 * leaves[i] yields root. A single leaf gets an empty path (root = leaf). Odd nodes are
 * carried up unchanged (no duplication), matching opentimestamps-server's make_merkle_tree.
 */
export function buildTree(leaves) {
  if (leaves.length === 0) throw new Error("no leaves");
  let level = leaves.map((msg, i) => ({ msg: Buffer.from(msg), ops: [], leaf: i }));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 >= level.length) { next.push(level[i]); continue; }
      const l = level[i], r = level[i + 1];
      const combined = sha256(Buffer.concat([l.msg, r.msg]));
      const node = { msg: combined, children: [l, r] };
      l.ops.push({ tag: TAG.append, arg: r.msg }, { tag: TAG.sha256 });
      r.ops.push({ tag: TAG.prepend, arg: l.msg }, { tag: TAG.sha256 });
      next.push(node);
    }
    level = next;
  }
  const root = level[0].msg;
  const paths = new Array(leaves.length);
  const collect = (n, suffix) => { if (n.children) { collect(n.children[0], suffix); collect(n.children[1], suffix); } else paths[n.leaf] = [...n.ops, ...suffix]; };
  // ops were appended per level from the leaf upward, so each leaf's own list is already
  // leaf→root ordered; suffix is only needed for carried-up odd nodes (their ops accrue later, in order)
  collect(level[0], []);
  return { root, paths };
}
export function applyPath(msg, ops) { let m = Buffer.from(msg); for (const op of ops) m = applyOp(op, m); return m; }
