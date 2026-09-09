// OTS calendar protocol over HTTP: POST /digest, GET /timestamp/<hex>. Rate limits at Cloudflare.
import http from "node:http"; import { Calendar, POLICY } from "./calendar.js";
export function createServer({ dir, uri }) {
  const cal = new Calendar({ dir, uri }); let hourLeaves = 0, hourKey = null;
  return http.createServer((req, res) => {
    const text = (code, body) => { res.writeHead(code, { "Content-Type": "text/plain" }); res.end(body); };
    if (req.method === "POST" && req.url === "/digest") {
      const len = Number(req.headers["content-length"]); if (!(len === POLICY.digestBytes)) return text(400, "digest must be exactly 32 bytes");
      const hk = Math.floor(Date.now() / 3600000); if (hk !== hourKey) { hourKey = hk; hourLeaves = 0; }
      if (hourLeaves >= POLICY.maxLeavesPerHour) return text(503, "hourly leaf cap reached; retry next hour");
      const chunks = []; let got = 0; req.on("data", (c) => { got += c.length; if (got > 64) req.destroy(); else chunks.push(c); });
      req.on("end", () => { const d = Buffer.concat(chunks); if (d.length !== POLICY.digestBytes) return text(400, "digest must be exactly 32 bytes");
        try { const { timestampBytes } = cal.submit(d); hourLeaves++; res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": timestampBytes.length }); res.end(timestampBytes); } catch (e) { text(e.status || 500, e.message); } });
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/timestamp/")) { const hex = req.url.slice(11); if (!/^[0-9a-f]{64}$/.test(hex)) return text(400, "bad commitment"); const b = cal.get(hex); if (!b) return text(404, "pending: not yet anchored"); res.writeHead(200, { "Content-Type": "application/octet-stream", "Cache-Control": "public, max-age=3600" }); return res.end(b); }
    if (req.method === "GET" && req.url === "/") return text(200, `DigiByte OpenTimestamps calendar (experimental). POST /digest (32 bytes) · GET /timestamp/<hex>.\nExperimental DigiByte block-header attestation, tag ${POLICY.tag} (${POLICY.derivation}). Not registered with, reviewed by, or endorsed by the OpenTimestamps project; stock ots verify reports it as unknown. Claim ceiling: these exact bytes existed no later than the recorded time of DigiByte block N. Not authorship, not truth, not immutable, not notarized. pending/final are confirmation-depth labels (policy: ${POLICY.confirmations} confirmations), not OTS states.\n`);
    text(404, "not found");
  });
}
if (process.argv[1] && process.argv[1].endsWith("server.js")) { const port = Number(process.env.PORT || 14170); createServer({ dir: process.env.CAL_DIR || "data", uri: process.env.CAL_URI || "https://calendar.dgbinsights.com" }).listen(port, "127.0.0.1", () => console.error("calendar on 127.0.0.1:" + port)); }
