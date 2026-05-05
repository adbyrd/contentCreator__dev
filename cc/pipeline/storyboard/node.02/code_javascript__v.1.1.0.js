/**
 * HMAC Validation
 * @version 1.1.0
 **/

const crypto = require("crypto");
const body    = $input.item.json.body    ?? $input.item.json;
const headers = $input.item.json.headers ?? {};
const receivedSig = headers["x-hmac-signature"] ?? headers["X-HMAC-Signature"] ?? "";

if (!receivedSig) {
  const ts = new Date().toISOString();
  console.error("[ WEBHOOK TRIGGER : v1.0.0 ] UNAUTHORIZED | missing X-HMAC-Signature | " + ts);
  throw new Error(JSON.stringify({
    ok: false, status: 401,
    error: { type: "UNAUTHORIZED", message: "HMAC signature header missing." },
    meta: { component: "WEBHOOK TRIGGER", version: "v1.0.0", timestamp: ts }
  }));
}

const secret      = $vars.N8N_CALLBACK_SECRET_KEY;  // ← $vars per previous fix
const rawBody     = JSON.stringify(body);
const expectedSig = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
const buf1     = Buffer.from(receivedSig, "hex");
const buf2     = Buffer.from(expectedSig, "hex");
const sigValid = buf1.length === buf2.length && crypto.timingSafeEqual(buf1, buf2);

if (!sigValid) {
  const ts = new Date().toISOString();
  console.error("[ WEBHOOK TRIGGER : v1.0.0 ] INVALID_SIGNATURE | SECURITY EVENT | timestamp: " + ts + " | DO NOT LOG PAYLOAD");
  throw new Error(JSON.stringify({
    ok: false, status: 403,
    error: { type: "INVALID_SIGNATURE", message: "HMAC signature validation failed." },
    meta: { component: "WEBHOOK TRIGGER", version: "v1.0.0", timestamp: ts }
  }));
}

const REQUIRED = ["projectId", "owner", "companyName", "companyDescription","primaryCategory", "customerType", "title", "goal","offer", "misconception", "targetAudience"];

const missing = REQUIRED.filter(function(f) { return !body[f] && body[f] !== 0; });

if (missing.length > 0) {
  const masked = body.owner ? body.owner.substring(0, 6) + "****" : "UNKNOWN";
  console.error("[ WEBHOOK TRIGGER : v1.0.0 ] PAYLOAD_INVALID | projectId: " + body.projectId + " | owner: " + masked + " | missingFields: [" + missing.join(", ") + "]");
  throw new Error(JSON.stringify({
    ok: false, status: 400,
    error: { type: "INVALID_PAYLOAD", message: "Missing required fields: " + missing.join(", ") },
    meta: { component: "WEBHOOK TRIGGER", version: "v1.0.0", missingFields: missing }
  }));
}