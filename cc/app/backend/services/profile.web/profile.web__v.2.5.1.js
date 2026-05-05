// [ FILE NAME : project.web.js : v2.0.0 ]
// [ PATH : /backend/project.web.js ]
// [ COMPONENT : PROJECT BACKEND : v2.0.0 ]
//
// CHANGE SUMMARY (v1.x → v2.0.0):
//   Three new webMethod exports appended for Storyboarding MVP (§4.3):
//     1. generateStoryboard(projectId)
//     2. receiveFrames(framePayload)         ← n8n callback endpoint
//     3. getStoryboardFrames(projectId)
//
//   All existing exports in project.web.js remain unchanged.
//   These additions are independently versioned per §6.1.
//
// CONTRACT COMPLIANCE:
//   - MVP Implementation Plan §4.3 (Backend Module — project.web.js additions)
//   - MVP Implementation Plan §3.2 (Request Lifecycle, steps 1–10)
//   - MVP Implementation Plan §6.2 (Logging Requirements)
//   - MVP Implementation Plan §6.3 (Security Compliance)
//   - MVP Implementation Plan §6.4 (Error Handling Contract)
//   - Platform Standards v2.0 — webMethod, Permissions, structured responses
//   - AI Governance Framework §5 (Secrets Manager, no hardcoding)
//   - Coding Standards — UPPER_SNAKE_CASE constants, VERSION logging, requestId
//
// SECRETS REQUIRED (Wix Secrets Manager — §4.2, §6.3):
//   N8N_STORYBOARD_WEBHOOK_URL   — n8n trigger URL for generateStoryboard()
//   N8N_CALLBACK_SECRET_KEY      — HMAC shared secret for receiveFrames() validation
//
// COLLECTIONS:
//   projects          — existing collection; storyboardStatus + timestamps added
//   storyboard_frames — new collection (§4.1); must exist before deployment

import { webMethod, Permissions } from 'wix-web-module';
import { getSecret }               from 'wix-secrets-backend';
import wixData                     from 'wix-data';
import { fetch }                   from 'wix-fetch';
import { currentMember }           from 'wix-members-backend';
import crypto                      from 'crypto';

// ─── Shared constants ─────────────────────────────────────────────────────────

const GENERATE_VERSION    = '[ GENERATE STORYBOARD : v1.0.0 ]';
const RECEIVE_VERSION     = '[ RECEIVE FRAMES : v1.0.0 ]';
const GET_FRAMES_VERSION  = '[ GET STORYBOARD FRAMES : v1.0.0 ]';

const PROJECTS_COLLECTION = 'projects';
const FRAMES_COLLECTION   = 'storyboard_frames';
const TOTAL_FRAMES        = 15;
const MAX_RETRIES         = 3;
const RETRY_BASE_MS       = 500;   // exponential backoff base

// ─── Utility: request ID ──────────────────────────────────────────────────────

function generateRequestId() {
  return `req_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

// ─── Utility: postWithRetry (§4.2 Webhook resilience, §8 Risk Register) ───────

async function postWithRetry(url, payload, requestId) {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const res = await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
      });
      if (res.ok) {
        console.log(`${GENERATE_VERSION} postWithRetry OK attempt=${attempt} requestId=${requestId}`);
        return { ok: true };
      }
      lastErr = new Error(`HTTP ${res.status}`);
      console.warn(`${GENERATE_VERSION} postWithRetry HTTP error attempt=${attempt} status=${res.status} requestId=${requestId}`);
    } catch (err) {
      lastErr = err;
      console.warn(`${GENERATE_VERSION} postWithRetry network error attempt=${attempt} error=${err.message} requestId=${requestId}`);
    }

    if (attempt < MAX_RETRIES) {
      // Exponential backoff: 500ms, 1000ms, 2000ms
      await new Promise((r) => setTimeout(r, RETRY_BASE_MS * Math.pow(2, attempt - 1)));
    }
  }
  throw lastErr;
}

// ─── Utility: structured error response ──────────────────────────────────────

function errorResponse(status, type, message, requestId) {
  console.error(`requestId=${requestId} status=${status} type=${type} message=${message}`);
  return { ok: false, status, error: { type, message } };
}

// ─── Utility: HMAC validation (§6.3 HMAC Validation, §5.3 Permissions) ───────

async function validateHmacSignature(payload, receivedSignature) {
  const secret = await getSecret('N8N_CALLBACK_SECRET_KEY');
  const body   = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const expected = crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(expected, 'hex'),
    Buffer.from(receivedSignature, 'hex')
  );
}

// ─── Utility: ownership check (§6.3 Ownership Enforcement) ───────────────────

async function resolveCallerMemberId() {
  const member = await currentMember.getMember();
  return member?._id || null;
}

// =============================================================================
// 1. generateStoryboard(projectId)
// §4.3 — The dispatch gate. Entry point for storyboard generation.
// §3.2 — Request Lifecycle steps 1–3.
// Permissions.Member — only authenticated members may initiate generation.
// =============================================================================

export const generateStoryboard = webMethod(
  Permissions.Member,
  async (projectId) => {
    const requestId = generateRequestId();
    console.log(`${GENERATE_VERSION} generateStoryboard() invoked projectId=${projectId} requestId=${requestId}`);

    // ── Input validation ────────────────────────────────────────────────────
    if (!projectId || typeof projectId !== 'string') {
      return errorResponse(400, 'INVALID_PAYLOAD', 'projectId is required.', requestId);
    }

    // ── Resolve caller identity (§6.3 Ownership Enforcement) ───────────────
    const callerId = await resolveCallerMemberId();
    if (!callerId) {
      return errorResponse(401, 'UNAUTHORIZED', 'Caller is not authenticated.', requestId);
    }

    // ── Load project record ────────────────────────────────────────────────
    let project;
    try {
      project = await wixData.get(PROJECTS_COLLECTION, projectId);
    } catch (err) {
      console.error(`${GENERATE_VERSION} wixData.get failed requestId=${requestId}`, err.message);
      return errorResponse(500, 'INTERNAL_ERROR', 'Failed to load project.', requestId);
    }

    if (!project) {
      return errorResponse(404, 'NOT_FOUND', 'Project not found.', requestId);
    }

    // ── Ownership check (§6.3) ─────────────────────────────────────────────
    if (project._owner !== callerId) {
      return errorResponse(401, 'UNAUTHORIZED', 'Caller does not own this project.', requestId);
    }

    // ── Concurrent run guard — ALREADY_RUNNING (§4.3, §6.4) ───────────────
    if (project.storyboardStatus === 'generating') {
      console.warn(`${GENERATE_VERSION} ALREADY_RUNNING projectId=${projectId} requestId=${requestId}`);
      return errorResponse(409, 'ALREADY_RUNNING', 'Storyboard generation is already in progress.', requestId);
    }

    // ── Validate required payload fields (§2.2 Sample Project Payload) ─────
    const requiredFields = [
      'companyName', 'companyDescription', 'primaryCategory',
      'customerType', 'title', 'goal', 'offer', 'misconception', 'targetAudience',
    ];
    const missingFields = requiredFields.filter((f) => !project[f]);
    if (missingFields.length > 0) {
      console.warn(`${GENERATE_VERSION} INVALID_PAYLOAD missing fields=${missingFields.join(',')} requestId=${requestId}`);
      return errorResponse(400, 'INVALID_PAYLOAD', `Missing required project fields: ${missingFields.join(', ')}.`, requestId);
    }

    // ── Stamp project: status → 'generating' (§3.2 step 3) ────────────────
    try {
      await wixData.update(PROJECTS_COLLECTION, {
        ...project,
        storyboardStatus:      'generating',
        generationStartedAt:   new Date().toISOString(),
      });
      console.log(`${GENERATE_VERSION} project stamped generating requestId=${requestId}`);
    } catch (err) {
      console.error(`${GENERATE_VERSION} stamp update failed requestId=${requestId}`, err.message);
      return errorResponse(500, 'INTERNAL_ERROR', 'Failed to update project status.', requestId);
    }

    // ── Build n8n webhook payload (§2.2 + §5.3 Frame Callback Payload) ─────
    const webhookPayload = {
      requestId,
      projectId,
      owner:              project._owner,
      companyName:        project.companyName,
      companyDescription: project.companyDescription,
      primaryCategory:    project.primaryCategory,
      customerType:       project.customerType,
      title:              project.title,
      goal:               project.goal,
      offer:              project.offer,
      misconception:      project.misconception,
      targetAudience:     project.targetAudience,
      dispatchedAt:       new Date().toISOString(),
    };

    // ── Dispatch signed webhook to n8n (§4.2 postWithRetry pattern) ────────
    let webhookUrl;
    try {
      webhookUrl = await getSecret('N8N_STORYBOARD_WEBHOOK_URL');
    } catch (err) {
      console.error(`${GENERATE_VERSION} secret retrieval failed requestId=${requestId}`, err.message);
      // Roll back status to enable user retry (§4.3).
      await _rollbackProjectStatus(project, requestId);
      return errorResponse(500, 'INTERNAL_ERROR', 'Configuration error.', requestId);
    }

    try {
      await postWithRetry(webhookUrl, webhookPayload, requestId);
    } catch (err) {
      // Webhook unreachable after MAX_RETRIES — §6.4 WEBHOOK_FAILED (502).
      console.error(`${GENERATE_VERSION} webhook FAILED after ${MAX_RETRIES} attempts requestId=${requestId}`, err.message);
      await _rollbackProjectStatus(project, requestId);
      return errorResponse(502, 'WEBHOOK_FAILED', 'Generation pipeline is temporarily unavailable. Please try again.', requestId);
    }

    // ── Fire-and-forget: return immediately after successful dispatch ───────
    // §3.3 Architectural Constraint — Wix does not block waiting for n8n.
    console.log(`${GENERATE_VERSION} dispatch SUCCESS requestId=${requestId}`);
    return { ok: true, status: 202, data: { projectId, requestId } };
  }
);

async function _rollbackProjectStatus(project, requestId) {
  try {
    await wixData.update(PROJECTS_COLLECTION, {
      ...project,
      storyboardStatus: 'failed',
    });
    console.log(`${GENERATE_VERSION} project rolled back to 'failed' requestId=${requestId}`);
  } catch (rollbackErr) {
    console.error(`${GENERATE_VERSION} rollback failed requestId=${requestId}`, rollbackErr.message);
  }
}

// =============================================================================
// 2. receiveFrames(framePayload)
// §4.3 — n8n callback endpoint. Public-facing but HMAC-protected.
// §3.2 — Request Lifecycle steps 7–8.
// Permissions.Anyone — n8n calls this without a Wix session cookie.
// =============================================================================

export const receiveFrames = webMethod(
  Permissions.Anyone,
  async (framePayload) => {
    const requestId = generateRequestId();
    console.log(`${RECEIVE_VERSION} receiveFrames() invoked requestId=${requestId}`);

    // ── Input validation (§6.3 Input Validation) ───────────────────────────
    const required = ['projectId', 'frameIndex', 'imageUrl', 'promptText', 'frameData', 'secretKey'];
    const missing  = required.filter((f) => framePayload[f] === undefined || framePayload[f] === null || framePayload[f] === '');
    if (missing.length > 0) {
      return errorResponse(400, 'INVALID_PAYLOAD', `Missing required fields: ${missing.join(', ')}.`, requestId);
    }

    const { projectId, frameIndex, imageUrl, promptText, frameData, secretKey } = framePayload;

    if (typeof frameIndex !== 'number' || frameIndex < 0 || frameIndex > 14) {
      return errorResponse(400, 'INVALID_PAYLOAD', 'frameIndex must be a number between 0 and 14.', requestId);
    }

    // ── HMAC signature validation (§6.3, §4.3 — reject without processing) ─
    // The signature is computed by n8n over the full payload minus secretKey.
    const payloadForHmac = { projectId, frameIndex, imageUrl, promptText, frameData };
    let signatureValid;
    try {
      signatureValid = await validateHmacSignature(payloadForHmac, secretKey);
    } catch (err) {
      console.error(`${RECEIVE_VERSION} HMAC validation error requestId=${requestId}`, err.message);
      return errorResponse(403, 'INVALID_SIGNATURE', 'Signature validation failed.', requestId);
    }

    if (!signatureValid) {
      console.warn(`${RECEIVE_VERSION} INVALID_SIGNATURE projectId=${projectId} frameIndex=${frameIndex} requestId=${requestId}`);
      // Log for security audit (§8 Risk Register — HMAC bypass attempt).
      return errorResponse(403, 'INVALID_SIGNATURE', 'Invalid HMAC signature.', requestId);
    }

    // ── Load project record to enforce ownership ───────────────────────────
    let project;
    try {
      project = await wixData.get(PROJECTS_COLLECTION, projectId, { suppressAuth: true });
    } catch (err) {
      console.error(`${RECEIVE_VERSION} project load failed requestId=${requestId}`, err.message);
      return errorResponse(500, 'INTERNAL_ERROR', 'Failed to load project.', requestId);
    }

    if (!project) {
      return errorResponse(404, 'NOT_FOUND', 'Project not found.', requestId);
    }

    const owner = project._owner;

    // ── Idempotency check (§4.3, §8 Risk Register — duplicate delivery) ────
    // If a frame record with this projectId + frameIndex already exists, skip silently.
    let existingFrames;
    try {
      existingFrames = await wixData.query(FRAMES_COLLECTION)
        .eq('projectId', projectId)
        .eq('frameIndex', frameIndex)
        .find({ suppressAuth: true });
    } catch (err) {
      console.error(`${RECEIVE_VERSION} idempotency query failed requestId=${requestId}`, err.message);
      return errorResponse(500, 'INTERNAL_ERROR', 'Database query failed.', requestId);
    }

    if (existingFrames.totalCount > 0) {
      // §4.3 — return ok:true to prevent n8n retry loop.
      console.log(`${RECEIVE_VERSION} DUPLICATE frame skipped frameIndex=${frameIndex} projectId=${projectId} requestId=${requestId}`);
      return { ok: true, status: 200, data: { skipped: true, frameIndex } };
    }

    // ── Write frame record to storyboard_frames (§4.1 collection schema) ───
    const frameRecord = {
      projectId,
      owner,                          // §6.3 Ownership Enforcement — stored at write time
      frameIndex,
      imageUrl,
      promptText,
      frameData,
      status: 'complete',
    };

    try {
      await wixData.insert(FRAMES_COLLECTION, frameRecord, { suppressAuth: true });
      console.log(`${RECEIVE_VERSION} frame written frameIndex=${frameIndex} projectId=${projectId} requestId=${requestId}`);
    } catch (err) {
      console.error(`${RECEIVE_VERSION} frame insert failed requestId=${requestId}`, err.message);
      return errorResponse(500, 'INTERNAL_ERROR', 'Failed to persist frame.', requestId);
    }

    // ── On 15th frame: stamp project 'complete' (§4.3, §3.2 step 8) ────────
    if (frameIndex === TOTAL_FRAMES - 1) {
      console.log(`${RECEIVE_VERSION} 15th frame received — stamping project complete requestId=${requestId}`);
      try {
        await wixData.update(PROJECTS_COLLECTION, {
          ...project,
          storyboardStatus: 'complete',
          completedAt:      new Date().toISOString(),
        }, { suppressAuth: true });
        console.log(`${RECEIVE_VERSION} project stamped complete projectId=${projectId} requestId=${requestId}`);
      } catch (err) {
        // Non-fatal — frame is already persisted. Log and continue.
        console.error(`${RECEIVE_VERSION} project completion stamp failed requestId=${requestId}`, err.message);
      }
    }

    return { ok: true, status: 200, data: { frameIndex, projectId } };
  }
);

// =============================================================================
// 3. getStoryboardFrames(projectId)
// §4.3 — Polling read endpoint. Double-scoped for cross-user isolation.
// §3.2 — Request Lifecycle step 9.
// Permissions.Member — only authenticated members may poll their own data.
// =============================================================================

export const getStoryboardFrames = webMethod(
  Permissions.Member,
  async (projectId) => {
    const requestId = generateRequestId();
    console.log(`${GET_FRAMES_VERSION} getStoryboardFrames() invoked projectId=${projectId} requestId=${requestId}`);

    // ── Input validation ────────────────────────────────────────────────────
    if (!projectId || typeof projectId !== 'string') {
      return errorResponse(400, 'INVALID_PAYLOAD', 'projectId is required.', requestId);
    }

    // ── Resolve caller identity ─────────────────────────────────────────────
    const callerId = await resolveCallerMemberId();
    if (!callerId) {
      return errorResponse(401, 'UNAUTHORIZED', 'Caller is not authenticated.', requestId);
    }

    // ── Ownership check on project (§6.3) ──────────────────────────────────
    let project;
    try {
      project = await wixData.get(PROJECTS_COLLECTION, projectId);
    } catch (err) {
      console.error(`${GET_FRAMES_VERSION} project load failed requestId=${requestId}`, err.message);
      return errorResponse(500, 'INTERNAL_ERROR', 'Failed to load project.', requestId);
    }

    if (!project) {
      return errorResponse(404, 'NOT_FOUND', 'Project not found.', requestId);
    }

    if (project._owner !== callerId) {
      return errorResponse(401, 'UNAUTHORIZED', 'Caller does not own this project.', requestId);
    }

    // ── Double-scoped query: projectId AND owner (§4.3, §6.3, §8 Risk Register) ─
    // Prevents cross-user data access even if ownership check above is somehow bypassed.
    let framesResult;
    try {
      framesResult = await wixData.query(FRAMES_COLLECTION)
        .eq('projectId', projectId)
        .eq('owner', callerId)             // second scope: owner filter
        .ascending('frameIndex')           // §4.3 — sorted ascending for consistent UI ordering
        .find();
    } catch (err) {
      console.error(`${GET_FRAMES_VERSION} frames query failed requestId=${requestId}`, err.message);
      return errorResponse(500, 'INTERNAL_ERROR', 'Failed to retrieve storyboard frames.', requestId);
    }

    const frames = framesResult.items;
    console.log(`${GET_FRAMES_VERSION} frames returned count=${frames.length} projectId=${projectId} requestId=${requestId}`);

    // ── Return frames + project storyboardStatus (§4.3) ────────────────────
    // Frontend poller uses storyboardStatus to determine completion; do not omit.
    return {
      ok:     true,
      status: 200,
      data:   {
        frames,
        storyboardStatus: project.storyboardStatus || null,
        frameCount:       frames.length,
        requestId,
      },
    };
  }
);