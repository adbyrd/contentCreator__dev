// [ FILE NAME : receiveFrames.web.js : v1.0.0 ]
// Domain  : Storyboard
// Layer   : Backend — n8n Callback Receiver
// Purpose : Public-facing endpoint that accepts per-frame payloads from n8n.
//           Validates HMAC-SHA256 signature on every request, enforces owner
//           scoping, implements idempotent writes, and stamps the project
//           'complete' on the 15th frame (frameIndex === 14).

import { Permissions, webMethod } from 'wix-web-module';
import { getSecret }              from 'wix-secrets-backend';
import wixData                    from 'wix-data';
import { createHmac }             from 'crypto';

// ─── Constants ────────────────────────────────────────────────────────────────
const VERSION              = '[ RECEIVE FRAMES : v1.0.0 ]';
const FRAMES_COLLECTION    = 'storyboard_frames';
const PROJECTS_COLLECTION  = 'projects';
const TOTAL_FRAMES         = 15;
const FINAL_FRAME_INDEX    = TOTAL_FRAMES - 1; // 14

// ─── Structured response helpers ─────────────────────────────────────────────
const ok    = (data)                  => ({ ok: true,  status: 200, data });
const fail  = (status, type, message) => ({ ok: false, status, error: { type, message } });

// ─── HMAC validation ─────────────────────────────────────────────────────────
async function validateHmac(signature, rawBody, requestId) {
  let secret;
  try {
    secret = await getSecret('N8N_CALLBACK_SECRET_KEY');
  } catch (err) {
    console.error(`${VERSION} [${requestId}] Secret retrieval failed: ${err.message}`);
    throw new Error('SECRET_UNAVAILABLE');
  }

  const expected = createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  // Constant-time comparison to prevent timing attacks
  if (!timingSafeEqual(signature, expected)) {
    console.warn(`${VERSION} [${requestId}] HMAC mismatch — expected: ${expected.slice(0, 8)}...`);
    return false;
  }

  return true;
}

// Naive constant-time string compare (same length enforcement)
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ─── receiveFrames ────────────────────────────────────────────────────────────
export const receiveFrames = webMethod(
  Permissions.Anyone, // Public — n8n has no Wix session; security is HMAC-gated
  async (framePayload) => {
    const requestId = `rf_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`${VERSION} [${requestId}] receiveFrames() invoked`);

    // ── 1. Payload presence check ────────────────────────────────────────────
    if (!framePayload || typeof framePayload !== 'object') {
      console.warn(`${VERSION} [${requestId}] Empty or non-object payload received`);
      return fail(400, 'VALIDATION_ERROR', 'Request payload is missing or malformed.');
    }

    const {
      hmacSignature,
      projectId,
      owner,
      frameIndex,
      imageUrl,
      promptText,
      frameData,
      status = 'complete',
    } = framePayload;

    // ── 2. Required field validation ─────────────────────────────────────────
    const missingFields = [];
    if (!hmacSignature)          missingFields.push('hmacSignature');
    if (!projectId)              missingFields.push('projectId');
    if (!owner)                  missingFields.push('owner');
    if (frameIndex === undefined || frameIndex === null) missingFields.push('frameIndex');
    if (!imageUrl)               missingFields.push('imageUrl');
    if (!promptText)             missingFields.push('promptText');

    if (missingFields.length > 0) {
      console.warn(`${VERSION} [${requestId}] Missing required fields: ${missingFields.join(', ')}`);
      return fail(400, 'VALIDATION_ERROR', `Missing required fields: ${missingFields.join(', ')}`);
    }

    if (typeof frameIndex !== 'number' || frameIndex < 0 || frameIndex > FINAL_FRAME_INDEX) {
      console.warn(`${VERSION} [${requestId}] Invalid frameIndex: ${frameIndex}`);
      return fail(400, 'VALIDATION_ERROR', `frameIndex must be a number between 0 and ${FINAL_FRAME_INDEX}.`);
    }

    // ── 3. HMAC validation ───────────────────────────────────────────────────
    // Re-serialise the payload body WITHOUT the signature for verification
    const bodyForHmac = JSON.stringify({
      projectId,
      owner,
      frameIndex,
      imageUrl,
      promptText,
      frameData: frameData ?? {},
      status,
    });

    let hmacValid;
    try {
      hmacValid = await validateHmac(hmacSignature, bodyForHmac, requestId);
    } catch (err) {
      if (err.message === 'SECRET_UNAVAILABLE') {
        return fail(500, 'CONFIG_ERROR', 'Callback validation is temporarily unavailable.');
      }
      return fail(500, 'HMAC_ERROR', 'Signature validation failed.');
    }

    if (!hmacValid) {
      console.warn(`${VERSION} [${requestId}] HMAC validation failed — rejecting payload`);
      return fail(401, 'SIGNATURE_INVALID', 'Request signature is invalid.');
    }

    console.log(`${VERSION} [${requestId}] HMAC validated — frameIndex: ${frameIndex}, projectId: ${projectId}`);

    // ── 4. Project ownership enforcement ────────────────────────────────────
    let project;
    try {
      project = await wixData.get(PROJECTS_COLLECTION, projectId);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Project fetch failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to verify project ownership.');
    }

    if (!project) {
      console.warn(`${VERSION} [${requestId}] Project not found: ${projectId}`);
      return fail(404, 'NOT_FOUND', 'Referenced project does not exist.');
    }

    if (project._owner !== owner) {
      console.warn(`${VERSION} [${requestId}] Ownership violation — payload owner: ${owner}, project owner: ${project._owner}`);
      return fail(403, 'FORBIDDEN', 'Owner in payload does not match project record.');
    }

    // ── 5. Idempotency — skip duplicate frame writes ──────────────────────────
    let existingFrame;
    try {
      const existingResult = await wixData
        .query(FRAMES_COLLECTION)
        .eq('projectId', projectId)
        .eq('frameIndex', frameIndex)
        .eq('owner', owner)
        .limit(1)
        .find({ suppressAuth: true });

      existingFrame = existingResult.items[0];
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Idempotency check failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to check for existing frame.');
    }

    if (existingFrame) {
      console.log(`${VERSION} [${requestId}] Duplicate frame detected — silently skipping (frameIndex: ${frameIndex})`);
      return ok({ skipped: true, frameIndex, reason: 'DUPLICATE_FRAME' });
    }

    // ── 6. Write frame record ────────────────────────────────────────────────
    const frameRecord = {
      projectId,
      owner,
      frameIndex,
      imageUrl,
      promptText,
      frameData:   frameData ?? {},
      status,
      receivedAt:  new Date().toISOString(),
    };

    try {
      await wixData.insert(FRAMES_COLLECTION, frameRecord, { suppressAuth: true });
      console.log(`${VERSION} [${requestId}] Frame written — frameIndex: ${frameIndex}`);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Frame write failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to persist frame data.');
    }

    // ── 7. Final frame — stamp project complete ───────────────────────────────
    if (frameIndex === FINAL_FRAME_INDEX) {
      const completedAt = new Date().toISOString();
      try {
        await wixData.update(PROJECTS_COLLECTION, {
          ...project,
          storyboardStatus: 'complete',
          completedAt,
        });
        console.log(`${VERSION} [${requestId}] Final frame received — project stamped complete at ${completedAt}`);
      } catch (err) {
        // Non-fatal: frame was written; log and continue
        console.error(`${VERSION} [${requestId}] Project completion stamp failed: ${err.message}`);
      }
    }

    console.log(`${VERSION} [${requestId}] receiveFrames() completed successfully`);

    return ok({
      frameIndex,
      projectId,
      written:   true,
      isFinal:   frameIndex === FINAL_FRAME_INDEX,
    });
  }
);

// ─── Debug export ─────────────────────────────────────────────────────────────
export async function debugReceiveFrames(testProjectId = 'test-project-id') {
  console.log(`${VERSION} [DEBUG] Testing receiveFrames signature validation`);
  const bodyForHmac = JSON.stringify({
    projectId:  testProjectId,
    owner:      'test-owner-id',
    frameIndex: 0,
    imageUrl:   'https://example.com/image.jpg',
    promptText: 'A test prompt',
    frameData:  {},
    status:     'complete',
  });

  const secret = 'OnePhraseTwoViewsOnesBadZeroChoices'; // debug only — never hardcode in production
  const expected = createHmac('sha256', secret).update(bodyForHmac).digest('hex');
  console.log(`${VERSION} [DEBUG] Expected HMAC: ${expected}`);
  return { debug: true, bodyForHmac, expectedHmac: expected };
}