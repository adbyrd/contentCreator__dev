// [ FILE NAME : generateStoryboard.web.js : v1.0.1 ]
// Domain  : Storyboard
// Layer   : Backend — Dispatch Gate
// Purpose : Validates caller ownership, guards duplicate runs, stamps project
//           status, assembles the full n8n payload, computes HMAC-SHA256 signature,
//           and fires the signed webhook via postWithRetry (3 attempts, exponential back-off).
//
// CHANGELOG v1.0.1
// ─────────────────────────────────────────────────────────────────────────────
// FIX: postWithRetry was dispatching the webhook without the X-HMAC-Signature
//      header. The n8n pipeline's Stage 1 Validate HMAC + Payload node performs
//      a mandatory HMAC-SHA256 check on every inbound request and correctly
//      rejected all calls with HTTP 401 UNAUTHORIZED.
//
// CHANGES:
//   1. getSecret() now also retrieves N8N_CALLBACK_SECRET_KEY alongside
//      N8N_STORYBOARD_WEBHOOK_URL in a single parallel Promise.all() call.
//   2. New hmacSign() helper computes HMAC-SHA256 hex digest of the serialised
//      payload using the shared secret.
//   3. postWithRetry() now accepts the computed signature and attaches it as
//      the X-HMAC-Signature header on every attempt — including retries.
//   4. The secret value is never logged (AI Governance Framework §6.1).
// ─────────────────────────────────────────────────────────────────────────────

import { Permissions, webMethod } from 'wix-web-module';
import { getSecret }              from 'wix-secrets-backend';
import wixData                    from 'wix-data';
import { currentMember }         from 'wix-members-backend';
import { fetch }                  from 'wix-fetch';
import { hmac }                   from 'wix-crypto-backend'; // Wix HMAC-SHA256 utility

// ─── Constants ────────────────────────────────────────────────────────────────
const VERSION       = '[ GENERATE STORYBOARD : v1.0.1 ]';
const COLLECTION    = 'projects';
const MAX_RETRIES   = 3;
const BASE_DELAY_MS = 500;

// ─── Structured response helpers ─────────────────────────────────────────────
const ok   = (data)                  => ({ ok: true,  status: 200, data });
const fail = (status, type, message) => ({ ok: false, status, error: { type, message } });

// ─── hmacSign ─────────────────────────────────────────────────────────────────
// Computes HMAC-SHA256 hex digest of a serialised payload.
// The secret is the shared value stored in both Wix Secrets Manager
// (N8N_CALLBACK_SECRET_KEY) and the n8n environment variable of the same name.
// Per AI Governance Framework §6.1: the secret must never appear in any log output.
async function hmacSign(payload, secret) {
  const body = JSON.stringify(payload);
  // wix-crypto-backend returns a hex string directly
  return hmac(body, secret);
}

// ─── postWithRetry ────────────────────────────────────────────────────────────
// FIX v1.0.1: accepts `signature` parameter and attaches it as X-HMAC-Signature
// on every attempt. The n8n pipeline Stage 1 node validates this header and
// rejects unsigned requests with HTTP 401.
async function postWithRetry(url, payload, signature, requestId) {
  let lastError;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(`${VERSION} [${requestId}] Webhook attempt ${attempt}/${MAX_RETRIES}`);

      const response = await fetch(url, {
        method:  'POST',
        headers: {
          'Content-Type':    'application/json',
          'X-HMAC-Signature': signature,  // ← FIX: required by n8n Stage 1 HMAC check
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        console.log(`${VERSION} [${requestId}] Webhook dispatched successfully on attempt ${attempt}`);
        return { success: true, status: response.status };
      }

      lastError = new Error(`HTTP ${response.status}`);
    } catch (err) {
      lastError = err;
    }

    if (attempt < MAX_RETRIES) {
      const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
      console.warn(`${VERSION} [${requestId}] Attempt ${attempt} failed — retrying in ${delay}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }

  throw lastError;
}

// ─── generateStoryboard ───────────────────────────────────────────────────────
export const generateStoryboard = webMethod(
  Permissions.Member,
  async (projectId) => {
    const requestId = `gs_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`${VERSION} [${requestId}] generateStoryboard() invoked — projectId: ${projectId}`);

    // ── 1. Input validation ──────────────────────────────────────────────────
    if (!projectId || typeof projectId !== 'string' || !projectId.trim()) {
      console.warn(`${VERSION} [${requestId}] Missing or invalid projectId`);
      return fail(400, 'VALIDATION_ERROR', 'projectId is required.');
    }

    // ── 2. Caller identity ───────────────────────────────────────────────────
    let member;
    try {
      member = await currentMember.getMember();
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Member resolution failed: ${err.message}`);
      return fail(401, 'AUTH_ERROR', 'Unable to resolve authenticated member.');
    }

    const callerId = member._id;

    // ── 3. Ownership check + project fetch ───────────────────────────────────
    let project;
    try {
      project = await wixData.get(COLLECTION, projectId);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Project fetch failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to retrieve project data.');
    }

    if (!project) {
      console.warn(`${VERSION} [${requestId}] Project not found: ${projectId}`);
      return fail(404, 'NOT_FOUND', 'Project not found.');
    }

    if (project._owner !== callerId) {
      console.warn(`${VERSION} [${requestId}] Ownership violation — caller: ${callerId}, owner: ${project._owner}`);
      return fail(403, 'FORBIDDEN', 'You do not have permission to generate this storyboard.');
    }

    // ── 4. Duplicate-run guard ───────────────────────────────────────────────
    if (project.storyboardStatus === 'generating') {
      console.warn(`${VERSION} [${requestId}] Concurrent run rejected — status: generating`);
      return fail(409, 'ALREADY_RUNNING', 'A storyboard generation is already in progress for this project.');
    }

    // ── 5. Stamp project — storyboardStatus: 'generating' ───────────────────
    const generationStartedAt = new Date().toISOString();
    try {
      await wixData.update(COLLECTION, {
        ...project,
        storyboardStatus:    'generating',
        generationStartedAt,
      });
      console.log(`${VERSION} [${requestId}] Project stamped — storyboardStatus: generating`);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Status stamp failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to update project status.');
    }

    // ── 6. Retrieve secrets ──────────────────────────────────────────────────
    // FIX v1.0.1: retrieve both secrets in parallel.
    // N8N_CALLBACK_SECRET_KEY is the shared HMAC secret — it must never be logged.
    let webhookUrl, callbackSecretKey;
    try {
      [webhookUrl, callbackSecretKey] = await Promise.all([
        getSecret('N8N_STORYBOARD_WEBHOOK_URL'),
        getSecret('N8N_CALLBACK_SECRET_KEY'),
      ]);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Secret retrieval failed: ${err.message}`);
      await wixData.update(COLLECTION, { ...project, storyboardStatus: 'failed' }).catch(() => {});
      return fail(500, 'CONFIG_ERROR', 'Pipeline configuration is unavailable. Please try again later.');
    }

    // ── 7. Assemble n8n payload ──────────────────────────────────────────────
    const n8nPayload = {
      submissionId:       requestId,
      timestamp:          generationStartedAt,
      projectId:          project._id,
      owner:              project._owner,
      companyName:        project.companyName        ?? '',
      companyDescription: project.companyDescription ?? '',
      primaryCategory:    project.primaryCategory    ?? '',
      customerType:       project.customerType       ?? '',
      title:              project.title              ?? '',
      goal:               project.goal               ?? '',
      offer:              project.offer              ?? '',
      misconception:      project.misconception      ?? '',
      targetAudience:     project.targetAudience     ?? '',
    };

    // ── 8. Compute HMAC-SHA256 signature ─────────────────────────────────────
    // FIX v1.0.1: signature computed here once over the canonical payload.
    // The same serialisation (JSON.stringify) is used in postWithRetry's fetch body
    // and in the n8n Stage 1 validation node — they must match exactly.
    // SECURITY: callbackSecretKey is never passed to console.log (AI Governance §6.1).
    let signature;
    try {
      signature = await hmacSign(n8nPayload, callbackSecretKey);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] HMAC signing failed: ${err.message}`);
      await wixData.update(COLLECTION, { ...project, storyboardStatus: 'failed' }).catch(() => {});
      return fail(500, 'SIGNING_ERROR', 'Failed to sign pipeline payload. Please try again.');
    }

    console.log(`${VERSION} [${requestId}] Payload signed — dispatching to n8n`);

    // ── 9. Fire-and-forget webhook dispatch ──────────────────────────────────
    // FIX v1.0.1: signature passed to postWithRetry and attached as X-HMAC-Signature header.
    try {
      await postWithRetry(webhookUrl, n8nPayload, signature, requestId);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] All webhook attempts failed: ${err.message}`);
      await wixData.update(COLLECTION, { ...project, storyboardStatus: 'failed' }).catch(() => {});
      return fail(502, 'WEBHOOK_ERROR', 'Storyboard generation pipeline is unavailable. Please try again.');
    }

    console.log(`${VERSION} [${requestId}] generateStoryboard() completed — fire-and-forget dispatched`);

    return ok({
      projectId,
      storyboardStatus:    'generating',
      generationStartedAt,
      submissionId:        requestId,
    });
  }
);

// ─── Debug export ─────────────────────────────────────────────────────────────
export async function debugGenerateStoryboard(projectId) {
  console.log(`${VERSION} [DEBUG] Invoking generateStoryboard with projectId: ${projectId}`);
  return { debug: true, projectId, timestamp: new Date().toISOString() };
}