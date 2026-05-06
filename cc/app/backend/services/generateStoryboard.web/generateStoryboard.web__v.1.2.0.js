// [ FILE NAME : generateStoryboard.web.js : v1.2.0 ]
// Domain  : Storyboard
// Layer   : Backend — Dispatch Gate
// Path    : /backend/storyboard/generateStoryboard.web.js
//
// ─── Changelog ────────────────────────────────────────────────────────────────
// v1.2.0  — Profile enrichment: payload fields populated from profiles
//            collection instead of projects collection.
//
//            ROOT CAUSE OF BLANK PAYLOAD FIELDS:
//            project-detail.page.js v2.6.0 imports generateStoryboard from
//            THIS file (backend/storyboard/generateStoryboard.web.js), not
//            from project.web.js. All v2.3.0–v2.4.1 fixes were applied to
//            project.web.js and never reached the deployed execution path.
//
//            The five blank fields in the n8n payload:
//              companyName, companyDescription, primaryCategory,
//              customerType, targetAudience
//
//            Confirmed field source map (from profiles.csv schema):
//              companyName        → profiles collection
//              companyDescription → profiles collection
//              primaryCategory    → profiles collection  (Category Settings modal)
//              customerType       → profiles collection  (Category Settings modal)
//              targetAudience     → projects collection  (no column on profiles)
//
//            Step 5 in the dispatch flow now fetches the caller's profile
//            record in parallel with secrets. Step 6 merges project + profile
//            into a resolved `enriched` context object using the resolution
//            order: project value → profile value → ''.
//            Step 7 assembles the n8n payload from `enriched` for the five
//            profile-sourced fields, and from `project` directly for
//            title, goal, offer, misconception.
//
//            Pre-dispatch validation (step 6a) runs on merged values and
//            routes missing fields to the correct settings panel in the
//            error message:
//              missingProfile[] → Profile Settings (Company / Category modal)
//              missingProject[] → Edit Project modal
//
//            Error response includes missingProfile[] + missingProject[]
//            arrays so the frontend can deep-link to the correct modal.
//
// v1.1.0  — HMAC-SHA256 signature computed from N8N_CALLBACK_SECRET_KEY and
//            attached as X-HMAC-Signature header. rawBody serialised once.
//            postWithRetry() updated to accept rawBody + hmacSignature.
//
// v1.0.0  — Initial implementation.
// ──────────────────────────────────────────────────────────────────────────────

import { Permissions, webMethod } from 'wix-web-module';
import { getSecret }              from 'wix-secrets-backend';
import { createHmac }             from 'crypto';
import wixData                    from 'wix-data';
import { currentMember }          from 'wix-members-backend';
import { fetch }                  from 'wix-fetch';

// ─── Constants ────────────────────────────────────────────────────────────────

const VERSION            = '[ GENERATE STORYBOARD : v1.2.0 ]';

const COLLECTION         = 'projects';
const COLLECTION_PROFILES = 'profiles';

const MAX_RETRIES        = 3;
const BASE_DELAY_MS      = 500;

// Profile-owned fields — sourced from profiles collection.
// These are company identity fields set via the Company and Category
// settings modals. They are NOT stored on individual project records.
const PROFILE_FIELDS     = ['companyName', 'companyDescription', 'primaryCategory', 'customerType'];

// Project-owned fields — sourced from projects collection.
// targetAudience is campaign-specific context; the profiles CMS collection
// has no targetAudience column (confirmed from schema).
const PROJECT_FIELDS     = ['targetAudience'];

// ─── Structured response helpers ─────────────────────────────────────────────

const ok   = (data)                  => ({ ok: true,  status: 200, data });
const fail = (status, type, message) => ({ ok: false, status, error: { type, message } });

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

async function postWithRetry(url, rawBody, hmacSignature, requestId) {
  let lastError;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(`${VERSION} [${requestId}] Webhook attempt ${attempt}/${MAX_RETRIES}`);

      const response = await fetch(url, {
        method:  'POST',
        headers: {
          'Content-Type':     'application/json',
          'X-HMAC-Signature': hmacSignature,
        },
        body: rawBody,
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

    // ── 2. Identity check ────────────────────────────────────────────────────
    let memberId;
    try {
      const member = await currentMember.getMember({ fieldsets: ['PUBLIC'] });
      memberId = member?._id ?? null;
    } catch (err) {
      console.error(`${VERSION} [${requestId}] getMember failed: ${err.message}`);
      memberId = null;
    }

    if (!memberId) {
      console.warn(`${VERSION} [${requestId}] Unauthenticated attempt`);
      return fail(401, 'AUTH_REQUIRED', 'Authentication required.');
    }

    // ── 3. Fetch project + ownership check ───────────────────────────────────
    let project;
    try {
      project = await wixData.get(COLLECTION, projectId, { suppressAuth: true });
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Project fetch failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to load project. Please try again.');
    }

    if (!project) {
      console.warn(`${VERSION} [${requestId}] Project not found: ${projectId}`);
      return fail(404, 'NOT_FOUND', 'Project not found.');
    }

    if (project._owner !== memberId) {
      console.warn(`${VERSION} [${requestId}] Ownership mismatch — caller: ${memberId}`);
      return fail(403, 'FORBIDDEN', 'You do not own this project.');
    }

    // ── 4. Duplicate-run guard ────────────────────────────────────────────────
    if (project.storyboardStatus === 'generating') {
      console.warn(`${VERSION} [${requestId}] Already generating for project: ${projectId}`);
      return fail(409, 'ALREADY_RUNNING', 'Storyboard generation is already in progress.');
    }

    // ── 5. Fetch profile + secrets in parallel ────────────────────────────────
    // Profile supplies the four company identity fields. Secrets are fetched
    // in the same Promise.all() to avoid a second sequential round-trip.
    // Profile fetch failure is surfaced via the validation gate in step 6a —
    // a null profile will produce missingProfile[] entries there.
    let profile = null;
    let webhookUrl, callbackSecret;

    try {
      const [profileResult, webhookUrlValue, callbackSecretValue] = await Promise.all([
        wixData.query(COLLECTION_PROFILES)
          .eq('_owner', memberId)
          .limit(1)
          .find({ suppressAuth: true })
          .then((res) => res.items[0] ?? null),
        getSecret('N8N_STORYBOARD_WEBHOOK_URL'),
        getSecret('N8N_CALLBACK_SECRET_KEY'),
      ]);

      profile        = profileResult;
      webhookUrl     = webhookUrlValue;
      callbackSecret = callbackSecretValue;

    } catch (err) {
      console.error(`${VERSION} [${requestId}] Profile/secret fetch failed: ${err.message}`);
      await rollbackStatus(project, requestId);
      return fail(500, 'CONFIG_ERROR', 'Pipeline configuration is unavailable. Please try again later.');
    }

    if (!profile) {
      console.warn(`${VERSION} [${requestId}] No profile record found for member: ${memberId}`);
    } else {
      console.log(`${VERSION} [${requestId}] Profile loaded — enriching payload`);
    }

    if (!webhookUrl || !callbackSecret) {
      const missing = [!webhookUrl && 'N8N_STORYBOARD_WEBHOOK_URL', !callbackSecret && 'N8N_CALLBACK_SECRET_KEY']
        .filter(Boolean).join(', ');
      console.error(`${VERSION} [${requestId}] Secrets empty: ${missing}`);
      await rollbackStatus(project, requestId);
      return fail(500, 'CONFIG_ERROR', 'Pipeline configuration is incomplete. Please contact support.');
    }

    // ── 5a. Merge project + profile into enriched context ────────────────────
    // Resolution order for profile fields: project value → profile value → ''
    // Project value wins if present, allowing per-project overrides.
    // targetAudience is project-only — the profiles schema has no such column.
    const enriched = {
      companyName:        project.companyName        || profile?.companyName        || '',
      companyDescription: project.companyDescription || profile?.companyDescription || '',
      primaryCategory:    project.primaryCategory    || profile?.primaryCategory    || '',
      customerType:       project.customerType       || profile?.customerType       || '',
      targetAudience:     project.targetAudience     || '',
    };

    console.log(
      `${VERSION} [${requestId}] Enriched` +
      ` | companyName: "${enriched.companyName}"` +
      ` | primaryCategory: "${enriched.primaryCategory}"` +
      ` | customerType: "${enriched.customerType}"` +
      ` | targetAudience: "${enriched.targetAudience}"`
    );

    // ── 6a. Pre-dispatch validation on merged values ──────────────────────────
    // Validates final resolved values — not raw project fields.
    // Splits missing fields by source so the error message routes the user
    // to the correct settings panel.
    const missingProfile = PROFILE_FIELDS.filter((f) => !enriched[f]);
    const missingProject = PROJECT_FIELDS.filter((f) => !enriched[f]);
    const missingFields  = [...missingProfile, ...missingProject];

    if (missingFields.length > 0) {
      const parts = [];
      if (missingProfile.length > 0) {
        parts.push(`Profile Settings missing: ${missingProfile.join(', ')}`);
      }
      if (missingProject.length > 0) {
        parts.push(`Project missing: ${missingProject.join(', ')} — please edit your project`);
      }
      const userMessage = parts.join('. ') + '.';
      console.warn(`${VERSION} [${requestId}] Pre-dispatch validation failed — ${userMessage}`);
      return {
        ok: false, status: 400,
        error: {
          type:           'INCOMPLETE_DATA',
          message:        userMessage,
          missingProfile,
          missingProject,
        },
      };
    }

    console.log(`${VERSION} [${requestId}] Pre-dispatch validation passed — all fields resolved`);

    // ── 6. Stamp project status ───────────────────────────────────────────────
    const generationStartedAt = new Date().toISOString();
    try {
      await wixData.update(COLLECTION, {
        ...project,
        storyboardStatus:      'generating',
        storyboardFrameCount:  0,
        storyboardStartedAt:   generationStartedAt,
        storyboardCompletedAt: null,
      }, { suppressAuth: true });
      console.log(`${VERSION} [${requestId}] Project stamped 'generating'`);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Status stamp failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to update project status.');
    }

    // ── 7. Assemble n8n payload ───────────────────────────────────────────────
    // Profile-sourced fields come from `enriched` (validated above).
    // Project-sourced fields come directly from the project record.
    const n8nPayload = {
      submissionId:       requestId,
      timestamp:          generationStartedAt,
      projectId:          project._id,
      owner:              project._owner,
      companyName:        enriched.companyName,
      companyDescription: enriched.companyDescription,
      primaryCategory:    enriched.primaryCategory,
      customerType:       enriched.customerType,
      targetAudience:     enriched.targetAudience,
      title:              project.title        ?? '',
      goal:               project.goal         ?? '',
      offer:              project.offer        ?? '',
      misconception:      project.misconception ?? '',
    };

    // ── 8. Serialise once — sign and send the same bytes ─────────────────────
    // rawBody is produced here, once. Passed to both buildHmacSignature() and
    // postWithRetry() — byte identity between signed and transmitted is guaranteed.
    const rawBody = JSON.stringify(n8nPayload);
    const hmacSig = buildHmacSignature(rawBody, callbackSecret);

    console.log(`${VERSION} [${requestId}] Payload assembled — HMAC signed — dispatching to n8n`);

    // ── 9. Fire-and-forget webhook dispatch ───────────────────────────────────
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