// [ FILE NAME : generateStoryboard.web.js : v1.1.0 ]
// Domain  : Storyboard
// Layer   : Backend — Dispatch Gate
// Purpose : Validates caller ownership, guards duplicate runs, stamps project
//           status, assembles the full n8n payload, computes HMAC-SHA256
//           signature, and fires the signed webhook via postWithRetry
//           (3 attempts, exponential back-off).
//
// ─── Changelog ────────────────────────────────────────────────────────────────
// v1.1.0  — Fix: HMAC-SHA256 signature now computed from N8N_CALLBACK_SECRET_KEY
//            and attached as X-HMAC-Signature header on every outbound webhook
//            request. Previously, the header was never sent, causing all Stage 1
//            HMAC validation checks in n8n to fail with 401 UNAUTHORIZED.
//
//            Changes from v1.0.0:
//              1. getSecret() now retrieves BOTH N8N_STORYBOARD_WEBHOOK_URL and
//                 N8N_CALLBACK_SECRET_KEY before dispatch.
//              2. rawBody is serialised once (JSON.stringify) and reused for
//                 both the HMAC computation and the fetch body — byte identity
//                 is guaranteed.
//              3. postWithRetry() signature updated to accept rawBody (string)
//                 and hmacSignature (hex string) as discrete parameters.
//              4. fetch() headers now include X-HMAC-Signature.
//              5. Rollback path on secret retrieval failure updated to cover
//                 both secrets in a single try/catch block.
// ──────────────────────────────────────────────────────────────────────────────

import { Permissions, webMethod } from 'wix-web-module';
import { getSecret }              from 'wix-secrets-backend';
import { createHmac }             from 'crypto';
import wixData                    from 'wix-data';
import { currentMember }          from 'wix-members-backend';
import { fetch }                  from 'wix-fetch';

// ─── Constants ────────────────────────────────────────────────────────────────
const VERSION       = '[ GENERATE STORYBOARD : v1.1.0 ]';
const COLLECTION    = 'projects';
const MAX_RETRIES   = 3;
const BASE_DELAY_MS = 500;

// ─── Structured response helpers ─────────────────────────────────────────────
const ok   = (data)                   => ({ ok: true,  status: 200, data });
const fail = (status, type, message)  => ({ ok: false, status, error: { type, message } });

// ─── rollbackStatus ───────────────────────────────────────────────────────────
// Best-effort status rollback. Never throws — a rollback failure must not mask
// the original error that triggered it.
async function rollbackStatus(project, requestId) {
  try {
    await wixData.update(COLLECTION, { ...project, storyboardStatus: 'failed' });
    console.warn(`${VERSION} [${requestId}] Status rolled back to 'failed'`);
  } catch (err) {
    console.error(`${VERSION} [${requestId}] Rollback failed (non-fatal): ${err.message}`);
  }
}

// ─── buildHmacSignature ───────────────────────────────────────────────────────
// Signs the exact string that will be sent as the request body.
// The string passed here MUST be the same reference passed to fetch() as body.
function buildHmacSignature(rawBody, secret) {
  return createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');
}

// ─── postWithRetry ────────────────────────────────────────────────────────────
// Accepts a pre-serialised body string and a pre-computed HMAC hex signature.
// Both are produced by the caller from a single JSON.stringify() call so that
// the signed bytes and the transmitted bytes are guaranteed identical.
//
// v1.1.0: Added `hmacSignature` parameter; attaches X-HMAC-Signature header.
async function postWithRetry(url, rawBody, hmacSignature, requestId) {
  let lastError;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(`${VERSION} [${requestId}] Webhook attempt ${attempt}/${MAX_RETRIES}`);

      const response = await fetch(url, {
        method:  'POST',
        headers: {
          'Content-Type':     'application/json',
          'X-HMAC-Signature': hmacSignature,   // ← FIX: header n8n Stage 1 validates
        },
        body: rawBody,                          // ← same string that was signed
      });

      if (response.ok) {
        console.log(`${VERSION} [${requestId}] Webhook dispatched successfully on attempt ${attempt}`);
        return { success: true, status: response.status };
      }

      // Surface non-retryable client errors immediately
      if (response.status >= 400 && response.status < 500) {
        const msg = `Non-retryable HTTP ${response.status} from n8n webhook`;
        console.error(`${VERSION} [${requestId}] ${msg}`);
        throw new Error(msg);
      }

      lastError = new Error(`HTTP ${response.status}`);
      console.warn(`${VERSION} [${requestId}] Attempt ${attempt} returned ${response.status}`);

    } catch (err) {
      // Re-throw non-retryable errors immediately
      if (err.message.startsWith('Non-retryable')) throw err;
      lastError = err;
    }

    if (attempt < MAX_RETRIES) {
      const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
      console.warn(`${VERSION} [${requestId}] Retrying in ${delay}ms`);
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
    // v1.1.0: Both secrets are retrieved here. N8N_CALLBACK_SECRET_KEY is
    // required to sign the outbound payload before dispatch.
    let webhookUrl, callbackSecret;
    try {
      [webhookUrl, callbackSecret] = await Promise.all([
        getSecret('N8N_STORYBOARD_WEBHOOK_URL'),
        getSecret('N8N_CALLBACK_SECRET_KEY'),
      ]);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Secret retrieval failed: ${err.message}`);
      await rollbackStatus(project, requestId);
      return fail(500, 'CONFIG_ERROR', 'Pipeline configuration is unavailable. Please try again later.');
    }

    if (!webhookUrl || !callbackSecret) {
      const missing = [!webhookUrl && 'N8N_STORYBOARD_WEBHOOK_URL', !callbackSecret && 'N8N_CALLBACK_SECRET_KEY']
        .filter(Boolean).join(', ');
      console.error(`${VERSION} [${requestId}] One or more secrets are empty: ${missing}`);
      await rollbackStatus(project, requestId);
      return fail(500, 'CONFIG_ERROR', 'Pipeline configuration is incomplete. Please contact support.');
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

    // ── 8. Serialise once — sign and send the same bytes ────────────────────
    // v1.1.0: rawBody is produced here, once. It is passed to both
    // buildHmacSignature() and postWithRetry() to guarantee byte identity.
    // Never call JSON.stringify(n8nPayload) again downstream.
    const rawBody      = JSON.stringify(n8nPayload);
    const hmacSig      = buildHmacSignature(rawBody, callbackSecret);

    console.log(`${VERSION} [${requestId}] Payload assembled — HMAC signed — dispatching to n8n`);

    // ── 9. Fire-and-forget webhook dispatch ──────────────────────────────────
    try {
      await postWithRetry(webhookUrl, rawBody, hmacSig, requestId);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] All webhook attempts failed: ${err.message}`);
      await rollbackStatus(project, requestId);
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
export async function debugGenerateStoryboard(projectId = 'debug-project-id') {
  console.log(`${VERSION} [DEBUG] Invoking generateStoryboard with projectId: ${projectId}`);
  return { debug: true, projectId, timestamp: new Date().toISOString() };
}