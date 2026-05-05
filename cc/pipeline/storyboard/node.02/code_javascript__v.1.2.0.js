/**
 * HMAC Validation
 * @version 1.2.0
 **/
/**
 * [ FILE NAME : stage.01/node.02/code_javascript.js : v1.2.0 ]
 *
 * Node   : Validate HMAC + Payload
 * Stage  : 1 — Webhook Trigger
 * Version: v1.2.0
 *
 * ─── Changelog ────────────────────────────────────────────────────────────────
 * v1.0.1  — Original. Used bare `body` variable (undefined in Code nodes).
 *           Used `$env` for secret access. Missing `return` block — output
 *           was never passed to the next stage.
 *
 * v1.1.0  — Fixed body extraction:
 *             const body = $input.item.json.body ?? $input.item.json;
 *           Switched secret access from `$env` → `$vars` (correct accessor
 *           for n8n Variables in Cloud ≥ 1.x).
 *           Still truncated — `return` block absent, handoff logs absent.
 *
 * v1.0.2  — Added body null-guard, `return` block, and handoff logs.
 *           Incorrectly kept `$env` instead of `$vars`.
 *           Kept stale debug console.log lines that leak input shape to logs.
 *
 * v1.2.0  — Definitive merge of all three prior versions:
 *           1. Body extraction from v1.1.0 (correct accessor path).
 *           2. `$vars` secret accessor from v1.1.0 (not `$env`).
 *           3. Body null-guard from v1.0.2.
 *           4. Complete `return` block and handoff logs from v1.0.2.
 *           5. All version strings bumped to v1.2.0.
 *           6. Debug console.log lines removed — input shape logging
 *              is noise in production and leaks structural metadata.
 *           7. Secret null-guard added — halts with CONFIG_ERROR if
 *              N8N_CALLBACK_SECRET_KEY is not set, instead of producing
 *              a silent wrong-HMAC failure that is hard to trace.
 * ──────────────────────────────────────────────────────────────────────────────
 *
 * Responsibilities:
 *   1. Extract body from the correct path on $input.item.json.
 *   2. Validate X-HMAC-Signature header is present.
 *   3. Validate HMAC-SHA256 signature using timing-safe comparison.
 *   4. Confirm all 11 required payload fields are non-empty.
 *   5. Return validated context object to Stage 2 (Prompt Generation).
 *
 * Secret required:
 *   N8N_CALLBACK_SECRET_KEY  — set in n8n → Settings → Variables
 *
 * HMAC contract:
 *   Signed value : JSON.stringify(body) — the exact serialisation Wix produced
 *   Header name  : x-hmac-signature (case-insensitive, both cases checked)
 */

const crypto = require("crypto");

// ── 1. Body extraction ────────────────────────────────────────────────────────
// In a downstream Code node, the webhook body lives at $input.item.json.body.
// If the webhook node is configured to unwrap the body into json directly,
// it lives at $input.item.json. Check both to cover either mode.
const body    = $input.item.json.body    ?? $input.item.json;
const headers = $input.item.json.headers ?? {};

if (!body || typeof body !== "object") {
  const ts = new Date().toISOString();
  console.error("[ WEBHOOK TRIGGER : v1.2.0 ] MALFORMED_PAYLOAD | body could not be extracted | " + ts);
  throw new Error(JSON.stringify({
    ok: false, status: 400,
    error: { type: "MALFORMED_PAYLOAD", message: "Request body is missing or could not be parsed." },
    meta: { component: "WEBHOOK TRIGGER", version: "v1.2.0", timestamp: ts }
  }));
}

// ── 2. HMAC signature header presence ────────────────────────────────────────
const receivedSig = headers["x-hmac-signature"] ?? headers["X-HMAC-Signature"] ?? "";

if (!receivedSig) {
  const ts = new Date().toISOString();
  console.error("[ WEBHOOK TRIGGER : v1.2.0 ] UNAUTHORIZED | missing X-HMAC-Signature | " + ts);
  throw new Error(JSON.stringify({
    ok: false, status: 401,
    error: { type: "UNAUTHORIZED", message: "HMAC signature header missing." },
    meta: { component: "WEBHOOK TRIGGER", version: "v1.2.0", timestamp: ts }
  }));
}

// ── 3. Secret guard ───────────────────────────────────────────────────────────
// $vars is the correct accessor for n8n Variables (Settings → Variables).
// If the variable is not set the value is undefined — guard before use to
// produce a clear CONFIG_ERROR rather than a silent wrong-HMAC failure.
const secret = $vars.N8N_CALLBACK_SECRET_KEY;

if (!secret) {
  const ts = new Date().toISOString();
  console.error("[ WEBHOOK TRIGGER : v1.2.0 ] CONFIG_ERROR | N8N_CALLBACK_SECRET_KEY not set | " + ts);
  throw new Error(JSON.stringify({
    ok: false, status: 500,
    error: { type: "CONFIG_ERROR", message: "Pipeline secret is not configured." },
    meta: { component: "WEBHOOK TRIGGER", version: "v1.2.0", timestamp: ts }
  }));
}

// ── 4. HMAC-SHA256 validation ─────────────────────────────────────────────────
// rawBody must be JSON.stringify of the same body object Wix signed.
// Wix calls JSON.stringify(n8nPayload) once and sends those exact bytes —
// re-stringifying the parsed body here reproduces the same string.
const rawBody     = JSON.stringify(body);
const expectedSig = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
const buf1        = Buffer.from(receivedSig, "hex");
const buf2        = Buffer.from(expectedSig, "hex");
const sigValid    = buf1.length === buf2.length && crypto.timingSafeEqual(buf1, buf2);

if (!sigValid) {
  const ts = new Date().toISOString();
  console.error("[ WEBHOOK TRIGGER : v1.2.0 ] INVALID_SIGNATURE | SECURITY EVENT | timestamp: " + ts + " | DO NOT LOG PAYLOAD");
  throw new Error(JSON.stringify({
    ok: false, status: 403,
    error: { type: "INVALID_SIGNATURE", message: "HMAC signature validation failed." },
    meta: { component: "WEBHOOK TRIGGER", version: "v1.2.0", timestamp: ts }
  }));
}

// ── 5. Required field presence check ─────────────────────────────────────────
// Mirrors STORYBOARD_REQUIRED_FIELDS in project.web.js v2.3.0.
// Empty string ('') is falsy — treated as absent, same rule as the Wix gate.
const REQUIRED = [
  "projectId",
  "owner",
  "companyName",
  "companyDescription",
  "primaryCategory",
  "customerType",
  "title",
  "goal",
  "offer",
  "misconception",
  "targetAudience"
];

const missing = REQUIRED.filter(function(f) { return !body[f] && body[f] !== 0; });

if (missing.length > 0) {
  const masked = body.owner ? body.owner.substring(0, 6) + "****" : "UNKNOWN";
  console.error(
    "[ WEBHOOK TRIGGER : v1.2.0 ] PAYLOAD_INVALID" +
    " | projectId: "     + (body.projectId ?? "UNKNOWN") +
    " | owner: "         + masked +
    " | missingFields: [" + missing.join(", ") + "]"
  );
  throw new Error(JSON.stringify({
    ok: false, status: 400,
    error: { type: "INVALID_PAYLOAD", message: "Missing required fields: " + missing.join(", ") },
    meta: { component: "WEBHOOK TRIGGER", version: "v1.2.0", missingFields: missing }
  }));
}

// ── 6. Success — build requestId and handoff logs ─────────────────────────────
const requestId   = "req_" + body.projectId + "_" + Date.now();
const maskedOwner = body.owner.substring(0, 6) + "****";

console.log("[ WEBHOOK TRIGGER : v1.2.0 ] HMAC_VALIDATED | requestId: "   + requestId + " | projectId: " + body.projectId + " | owner: " + maskedOwner + " | timestamp: " + new Date().toISOString());
console.log("[ WEBHOOK TRIGGER : v1.2.0 ] PAYLOAD_VALID | requestId: "    + requestId + " | projectId: " + body.projectId + " | allFields: confirmed");
console.log("[ WEBHOOK TRIGGER : v1.2.0 ] HANDOFF_SUCCESS | requestId: "  + requestId + " | projectId: " + body.projectId + " | nextStage: prompt-generation");

// ── 7. Return validated context to Stage 2 ───────────────────────────────────
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
    submissionId:       body.submissionId ?? requestId,
    requestId:          requestId,
    pipelineVersion:    "v1.2.0",
    stage1CompletedAt:  new Date().toISOString()
  }
}];