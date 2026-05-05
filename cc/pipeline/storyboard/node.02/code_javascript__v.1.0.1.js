/**
 * HMAC Validation
 * @version 1.0.1
 **/

console.log("[ DEBUG ] Raw input keys:", JSON.stringify(Object.keys($input.item.json)));
console.log("[ DEBUG ] Headers object:", JSON.stringify($input.item.json.headers ?? "NO_HEADERS_KEY"));

const crypto = require("crypto");
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

const secret      = $vars.N8N_CALLBACK_SECRET_KEY;
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

const REQUIRED = [
  "projectId", "owner", "companyName", "companyDescription",
  "primaryCategory", "customerType", "title", "goal",
  "offer", "misconception", "targetAudience"
];

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

const requestId   = "req_" + body.projectId + "_" + Date.now();
const maskedOwner = body.owner.substring(0, 6) + "****";

console.log("[ WEBHOOK TRIGGER : v1.0.0 ] HMAC_VALIDATED | requestId: " + requestId + " | projectId: " + body.projectId + " | owner: " + maskedOwner + " | timestamp: " + new Date().toISOString());
console.log("[ WEBHOOK TRIGGER : v1.0.0 ] PAYLOAD_VALID | requestId: " + requestId + " | projectId: " + body.projectId + " | allFields: confirmed");
console.log("[ WEBHOOK TRIGGER : v1.0.0 ] HANDOFF_SUCCESS | requestId: " + requestId + " | projectId: " + body.projectId + " | nextStage: prompt-generation");

return [{
  json: {
    projectId:          body.projectId,
    owner:              body.owner,
    companyName:        body.companyName,
    companyDescription: body.companyDescription,
    primaryCategory:    body.primaryCategory,
    customerType:       body.customerType,
    title:              body.title,
    goal:               body.goal,
    offer:              body.offer,
    misconception:      body.misconception,
    targetAudience:     body.targetAudience,
    requestId:          requestId,
    pipelineVersion:    "v1.0.0",
    stage1CompletedAt:  new Date().toISOString()
  }
}];