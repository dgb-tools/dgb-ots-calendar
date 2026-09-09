// OpenTimestamps proof format — parse and serialize, byte-exact with python-opentimestamps
// (opentimestamps/core/{serialize,timestamp,op,notary}.py). Pure functions, no I/O.
// Unknown attestation tags are preserved losslessly (UnknownAttestation semantics).
import { createHash } from "node:crypto";

export const HEADER_MAGIC = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
export const MAJOR_VERSION = 1;
export const TAG = { sha1: 0x02, ripemd160: 0x03, sha256: 0x08, keccak256: 0x67, append: 0xf0, prepend: 0xf1, reverse: 0xf2, hexlify: 0xf3 };
export const ATTESTATION = { pending: "83dfe30d2ef90c8e", bitcoin: "0588960d73d71901", litecoin: "06869a0d73d71b45" };
const DIGEST_LEN = { [TAG.sha1]: 20, [TAG.ripemd160]: 20, [TAG.sha256]: 32, [TAG.keccak256]: 32 };
const MAX_RESULT = 4096, MAX_ARG = 4096, MAX_URI = 1000, MAX_ATT_PAYLOAD = 8192;

// ---- varint / varbytes (LEB128, low 7 bits first) ----
export function encodeVarint(n) { const out = []; let v = BigInt(n); if (v < 0n) throw new Error("negative varint"); if (v === 0n) return Buffer.from([0]); while (v > 0n) { let b = Number(v & 0x7fn); v >>= 7n; if (v > 0n) b |= 0x80; out.push(b); } return Buffer.from(out); }
function rdVarint(b, i) { let v = 0n, shift = 0n, k = i; for (;;) { const x = b[k++]; if (x === undefined) throw new Error("truncated varint"); v |= BigInt(x & 0x7f) << shift; if (!(x & 0x80)) break; shift += 7n; if (shift > 63n) throw new Error("varint too long"); } return [Number(v), k]; }
function rdVarbytes(b, i, max) { const [n, k] = rdVarint(b, i); if (n > max) throw new Error(`varbytes ${n} > ${max}`); if (k + n > b.length) throw new Error("truncated varbytes"); return [b.subarray(k, k + n), k + n]; }
const varbytes = (buf) => Buffer.concat([encodeVarint(buf.length), buf]);

// ---- ops ----
export function applyOp(op, msg) {
  switch (op.tag) {
    case TAG.sha1: return createHash("sha1").update(msg).digest();
    case TAG.ripemd160: return createHash("ripemd160").update(msg).digest();
    case TAG.sha256: return createHash("sha256").update(msg).digest();
    case TAG.keccak256: throw new Error("keccak256 unsupported in this verifier");
    case TAG.append: return Buffer.concat([msg, op.arg]);
    case TAG.prepend: return Buffer.concat([op.arg, msg]);
    case TAG.reverse: return Buffer.from(msg).reverse();
    case TAG.hexlify: return Buffer.from(msg.toString("hex"), "ascii");
    default: throw new Error(`unknown op 0x${op.tag.toString(16)}`);
  }
}
function rdOp(b, i) { const tag = b[i]; if (tag === TAG.append || tag === TAG.prepend) { const [arg, k] = rdVarbytes(b, i + 1, MAX_ARG); return [{ tag, arg: Buffer.from(arg) }, k]; } if (tag in DIGEST_LEN || tag === TAG.reverse || tag === TAG.hexlify || tag === TAG.keccak256) return [{ tag }, i + 1]; throw new Error(`unknown op tag 0x${tag?.toString(16)} at ${i}`); }
const wrOp = (op) => (op.arg ? Buffer.concat([Buffer.from([op.tag]), varbytes(op.arg)]) : Buffer.from([op.tag]));
// canonical op ordering used by python (tuple compare: tag then arg)
function opKey(op) { return op.tag.toString(16).padStart(2, "0") + (op.arg ? op.arg.toString("hex") : ""); }

// ---- attestations ----
function rdAttestation(b, i) { const tag = b.subarray(i, i + 8).toString("hex"); const [payload, k] = rdVarbytes(b, i + 8, MAX_ATT_PAYLOAD);
  if (tag === ATTESTATION.pending) { const [uri, j] = rdVarbytes(payload, 0, MAX_URI); if (j !== payload.length) throw new Error("pending: trailing"); return [{ type: "pending", tag, uri: Buffer.from(uri).toString("utf8") }, k]; }
  if (tag === ATTESTATION.bitcoin || tag === ATTESTATION.litecoin) { const [height, j] = rdVarint(payload, 0); if (j !== payload.length) throw new Error("blockheader: trailing"); return [{ type: tag === ATTESTATION.bitcoin ? "bitcoin" : "litecoin", tag, height }, k]; }
  return [{ type: "unknown", tag, payload: Buffer.from(payload) }, k]; }
export function wrAttestation(a) { const tag = Buffer.from(a.tag, "hex"); let payload;
  if (a.type === "pending") payload = varbytes(Buffer.from(a.uri, "utf8"));
  else if (a.type === "bitcoin" || a.type === "litecoin" || a.type === "blockheader") payload = encodeVarint(a.height);
  else payload = a.payload;
  return Buffer.concat([tag, varbytes(payload)]); }
// python sorts attestations by (tag, payload) bytes
const attKey = (a) => wrAttestation(a).toString("hex");

// ---- timestamp tree: { attestations: [], ops: [[op, timestamp], ...] } ----
function rdTimestamp(b, i, msg) {
  const ts = { msg, attestations: [], ops: [] };
  const one = (tag, i) => { if (tag === 0x00) { const [a, k] = rdAttestation(b, i); ts.attestations.push(a); return k; } const [op, k] = rdOp(b, i - 1); const out = applyOp(op, msg); if (out.length > MAX_RESULT) throw new Error("result too long"); const [child, k2] = rdTimestamp(b, k, out); ts.ops.push([op, child]); return k2; };
  for (;;) { const tag = b[i++]; if (tag === undefined) throw new Error("truncated timestamp"); if (tag === 0xff) { const t2 = b[i++]; i = one(t2, i); } else { return [ts, one(tag, i)]; } }
}
function wrTimestamp(ts) {
  const atts = [...ts.attestations].sort((x, y) => attKey(x) < attKey(y) ? -1 : attKey(x) > attKey(y) ? 1 : 0);
  const ops = [...ts.ops].sort((x, y) => opKey(x[0]) < opKey(y[0]) ? -1 : opKey(x[0]) > opKey(y[0]) ? 1 : 0);
  if (atts.length === 0 && ops.length === 0) throw new Error("empty timestamp");
  const parts = [];
  for (const a of atts.slice(0, -1)) parts.push(Buffer.from([0xff, 0x00]), wrAttestation(a));
  if (ops.length === 0) { parts.push(Buffer.from([0x00]), wrAttestation(atts[atts.length - 1])); }
  else { if (atts.length) parts.push(Buffer.from([0xff, 0x00]), wrAttestation(atts[atts.length - 1]));
    for (const [op, child] of ops.slice(0, -1)) parts.push(Buffer.from([0xff]), wrOp(op), wrTimestamp(child));
    const [op, child] = ops[ops.length - 1]; parts.push(wrOp(op), wrTimestamp(child)); }
  return Buffer.concat(parts);
}

// ---- detached timestamp file ----
export function parseOts(buf) {
  const b = Buffer.from(buf); if (!b.subarray(0, HEADER_MAGIC.length).equals(HEADER_MAGIC)) throw new Error("bad magic");
  let i = HEADER_MAGIC.length; const [ver, k] = rdVarint(b, i); if (ver !== MAJOR_VERSION) throw new Error(`version ${ver}`); i = k;
  const fileHashOp = b[i++]; const n = DIGEST_LEN[fileHashOp]; if (!n) throw new Error("bad file hash op"); const digest = Buffer.from(b.subarray(i, i + n)); i += n;
  const [timestamp, end] = rdTimestamp(b, i, digest); if (end !== b.length) throw new Error(`trailing ${b.length - end} bytes`);
  return { fileHashOp, digest, timestamp };
}
export function serializeOts({ fileHashOp, digest, timestamp }) { return Buffer.concat([HEADER_MAGIC, encodeVarint(MAJOR_VERSION), Buffer.from([fileHashOp]), digest, wrTimestamp(timestamp)]); }

// ---- walk: every attestation with the message it attests ----
export function attestations(ts, out = []) { for (const a of ts.attestations) out.push({ attestation: a, msg: ts.msg }); for (const [, child] of ts.ops) attestations(child, out); return out; }
export function describe(ts, depth = 0, lines = []) { const pad = "  ".repeat(depth); for (const a of ts.attestations) lines.push(`${pad}verify ${a.type}${a.uri ? `('${a.uri}')` : a.height !== undefined ? `(${a.height})` : `(${a.tag})`}`);
  for (const [op, child] of ts.ops) { const name = Object.keys(TAG).find((k) => TAG[k] === op.tag); lines.push(`${pad}${name}${op.arg ? " " + op.arg.toString("hex") : ""}`); describe(child, depth + 1, lines); } return lines; }
