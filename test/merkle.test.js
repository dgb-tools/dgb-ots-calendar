import test from "node:test"; import assert from "node:assert/strict"; import { randomBytes, createHash } from "node:crypto";
import { buildTree, applyPath } from "../src/merkle.js";
for (const n of [1, 2, 3, 4, 5, 8, 33, 1000]) test(`every leaf path reproduces the root (n=${n})`, () => {
  const leaves = Array.from({ length: n }, () => randomBytes(32)); const { root, paths } = buildTree(leaves);
  for (let i = 0; i < n; i++) assert.equal(applyPath(leaves[i], paths[i]).toString("hex"), root.toString("hex"));
  if (n === 1) assert.equal(paths[0].length, 0);
  if (n === 2) assert.equal(root.toString("hex"), createHash("sha256").update(Buffer.concat(leaves)).digest("hex"));
});
test("odd leaf is carried up unchanged, not duplicated", () => { const a = Buffer.alloc(32, 1), b = Buffer.alloc(32, 2), c = Buffer.alloc(32, 3); const { root } = buildTree([a, b, c]);
  const ab = createHash("sha256").update(Buffer.concat([a, b])).digest(); assert.equal(root.toString("hex"), createHash("sha256").update(Buffer.concat([ab, c])).digest("hex")); });
