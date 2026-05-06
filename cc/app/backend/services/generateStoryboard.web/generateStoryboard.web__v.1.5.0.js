// [ FILE NAME : generateStoryboard.web.js : v1.5.0 ]
// Domain  : Storyboard
// Layer   : Backend — Dispatch Gate + Cancel
// Path    : /backend/storyboard/generateStoryboard.web.js
// ──────────────────────────────────────────────────────────────────────────────
// Changelog v1.4.0 → v1.5.0
//
//   FIELD NAME CORRECTIONS (schema alignment)
//   [SCH-01] secondaryCategory → subCategory throughout.
//            The profiles collection stores this field as `subCategory`.
//            All references updated: REQUIRED_PROFILE_FIELDS, enriched merge
//            map, enriched log line, and n8nPayload assembly.
//   [SCH-02] project.targetAudience → project.target_audience.
//            The projects collection stores this field in snake_case as
//            `target_audience`. The enriched map now reads the correct key and
//            normalises to camelCase (`targetAudience`) for n8n consumption.
//            REQUIRED_PROJECT_FIELDS continues to validate against the enriched
//            key (camelCase) — not the raw DB column name.
// ──────────────────────────────────────────────────────────────────────────────

import { Permissions, webMethod } from 'wix-web-module';
import { getSecret }              from 'wix-secrets-backend';
import { createHmac }             from 'crypto';
import wixData                    from 'wix-data';
import { currentMember }          from 'wix-members-backend';
import { fetch }                  from 'wix-fetch';

// ─── Constants ────────────────────────────────────────────────────────────────

const VERSION              = '[ GENERATE STORYBOARD : v1.5.0 ]';
const CANCEL_VERSION       = '[ CANCEL STORYBOARD : v1.2.0 ]';

const COLLECTION_PROJECTS  = 'projects';
const COLLECTION_PROFILES  = 'profiles';

const SECRET_WEBHOOK_URL   = 'N8N_STORYBOARD_WEBHOOK_URL';
const SECRET_CALLBACK_KEY  = 'N8N_CALLBACK_SECRET_KEY';

// Retry / timeout — worst-case execution time ≈ 17 s, within Velo's 30 s limit.
// Delays: attempt 1 → 500 ms, attempt 2 → 1000 ms, attempt 3 → 2000 ms.
// [REL-02] Exponent uses `attempt` (1-based), not `attempt - 1`, so the first
//          retry always waits at least BASE_DELAY_MS.
const MAX_RETRIES          = 3;
const BASE_DELAY_MS        = 500;
const WEBHOOK_TIMEOUT_MS   = 8000;
const RETRYABLE_STATUSES   = [429, 502, 503, 504];

// Status values
const STATUS_GENERATING    = 'generating';
const STATUS_FAILED        = 'failed';
const STATUS_CANCELLED     = 'cancelled';

// Fields that must resolve to a non-empty value before dispatch.
// Profile fields are sourced from the profiles collection (Company / Category
// Settings). targetAudience is project-only — profiles has no such column.
// [SCH-01] subCategory — profiles collection stores this as `subCategory`
//          (was: secondaryCategory — incorrect field name).
const REQUIRED_PROFILE_FIELDS = [
  'companyName',
  'companyDescription',
  'primaryCategory',
  'subCategory',        // [SCH-01] was: secondaryCategory
  'customerType',
];
const REQUIRED_PROJECT_FIELDS = ['targetAudience'];

const DB_OPTIONS = { suppressAuth: true };

// ─── Structured response helpers ──────────────────────────────────────────────

const ok   = (data)                  => ({ ok: true,  status: 200, data });
const fail = (status, type, message) => ({ ok: false, status, error: { type, message } });

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Resolves the currently authenticated member's Wix ID.
 * Returns null on unauthenticated or resolution failure.
 *
 * [FIX-02] fieldsets: ['FULL'] — 'PUBLIC' does not reliably expose _id across
 *          all Wix plans. 'FULL' guarantees the _id field is present.
 *
 * @returns {Promise<string|null>}
 */
async function getMemberId() {
  try {
    // [FIX-02] was: fieldsets: ['PUBLIC']
    const member = await currentMember.getMember({ fieldsets: ['FULL'] });
    return member?._id ?? null;
  } catch (err) {
    console.error(`${VERSION} getMemberId failure: ${err.message}`);
    return null;
  }
}

/**
 * Best-effort status rollback to STATUS_FAILED.
 * Never throws — a rollback failure must not mask the originating error.
 *
 * [REL-03] Targeted patch using _id only instead of spreading the full project
 *          object. Avoids schema-mismatch rejections on unrelated fields.
 *
 * @param {object} project   — full project record from wixData.get()
 * @param {string} requestId
 */
async function rollbackStatus(project, requestId) {
  try {
    // [REL-03] was: wixData.update(COLLECTION_PROJECTS, { ...project, storyboardStatus: STATUS_FAILED })
    await wixData.update(
      COLLECTION_PROJECTS,
      { _id: project._id, storyboardStatus: STATUS_FAILED },
      DB_OPTIONS
    );
    console.warn(`${VERSION} [${requestId}] Status rolled back to '${STATUS_FAILED}'`);
  } catch (err) {
    console.error(`${VERSION} [${requestId}] Rollback failed (non-fatal): ${err.message}`);
  }
}

/**
 * Signs a pre-serialised JSON string with HMAC-SHA256.
 * The string passed here MUST be the same reference passed as the request body
 * so that signed bytes and transmitted bytes are guaranteed identical.
 *
 * @param {string} rawBody  — JSON.stringify() output
 * @param {string} secret   — value of N8N_CALLBACK_SECRET_KEY
 * @returns {string}        — hex digest
 */
function buildHmacSignature(rawBody, secret) {
  return createHmac('sha256', secret).update(rawBody).digest('hex');
}

/**
 * Fires a signed POST to the n8n webhook with exponential backoff.
 *
 * Accepts a pre-serialised body string and pre-computed HMAC hex so that
 * the bytes signed and the bytes transmitted are guaranteed identical.
 *
 * [REL-01] AbortController timer is cleared in a finally block on every code
 *          path, including retryable HTTP error paths — previously a dangling
 *          timer was left on non-success branches.
 * [REL-02] Delay exponent uses `attempt` (1-based) so the first retry always
 *          applies the full BASE_DELAY_MS (was: attempt - 1 → 0 ms on retry 1).
 * [FIX-03] Response body is explicitly drained on non-ok paths to release the
 *          connection before the retry delay.
 *
 * @param {string} url
 * @param {string} rawBody        — pre-serialised JSON (not re-stringified)
 * @param {string} hmacSignature  — hex HMAC-SHA256 of rawBody
 * @param {string} requestId
 * @returns {{ ok: boolean, status: number, data?: any, error?: object }}
 */
async function postWithRetry(url, rawBody, hmacSignature, requestId) {
  let lastError = null;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    // [REL-01] timer reference held outside try so finally can always clear it
    const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);

    try {
      console.log(`${VERSION} [${requestId}] Webhook attempt ${attempt}/${MAX_RETRIES}`);

      const response = await fetch(url, {
        method:  'POST',
        headers: {
          'Content-Type':     'application/json',
          'X-HMAC-Signature': hmacSignature,
        },
        body:   rawBody,
        signal: controller.signal,
      });

      if (response.ok) {
        const data = await response.json().catch(() => ({}));
        console.log(`${VERSION} [${requestId}] Webhook dispatched successfully on attempt ${attempt}`);
        return { ok: true, status: response.status, data };
      }

      // [FIX-03] Drain body on non-ok to release the underlying connection
      //          before the retry delay begins.
      await response.text().catch(() => {});

      // Non-retryable client errors — surface immediately
      if (!RETRYABLE_STATUSES.includes(response.status)) {
        console.error(`${VERSION} [${requestId}] Non-retryable HTTP ${response.status} — aborting`);
        return {
          ok:     false,
          status: response.status,
          error:  { type: 'HTTP_ERROR', message: `Non-retryable HTTP ${response.status}` },
        };
      }

      lastError = `HTTP ${response.status}`;
      console.warn(`${VERSION} [${requestId}] Attempt ${attempt} returned ${response.status}`);

    } catch (err) {
      lastError = err.name === 'AbortError' ? 'TIMEOUT' : err.message;
      console.warn(`${VERSION} [${requestId}] Attempt ${attempt} failed: ${lastError}`);
    } finally {
      // [REL-01] was: clearTimeout(timer) in try-success and try-catch only
      clearTimeout(timer);
    }

    if (attempt < MAX_RETRIES) {
      // [REL-02] was: BASE_DELAY_MS * Math.pow(2, attempt - 1) → 0 ms on attempt 1
      const delay = BASE_DELAY_MS * Math.pow(2, attempt);
      await new Promise((r) => setTimeout(r, delay));
    }
  }

  console.error(
    `${VERSION} [${requestId}] All ${MAX_RETRIES} webhook attempts exhausted. Last error: ${lastError}`
  );
  return {
    ok:     false,
    status: 503,
    error:  { type: 'WEBHOOK_UNAVAILABLE', message: lastError },
  };
}

// ─── generateStoryboard ───────────────────────────────────────────────────────

/**
 * Dispatch gate for the n8n storyboard generation pipeline.
 *
 * Called by: project-detail.page.js → #btnGenerateStoryboard click handler.
 * Import path: backend/storyboard/generateStoryboard.web
 *
 * Execution flow:
 *   1.  Input validation.
 *   2.  Identity check — rejects unauthenticated callers.
 *   3.  Project fetch + ownership check.
 *   4.  Duplicate-run guard — rejects if storyboardStatus === 'generating'.
 *   5.  Parallel fetch: caller's profile record + both Secrets Manager values.
 *   5a. Merge project + profile into enriched context:
 *         resolution order → project value → profile value → ''
 *         targetAudience is project-only (profiles schema has no such column).
 *   6.  Pre-dispatch validation on MERGED values — routes error message to
 *       the correct settings panel (Profile Settings vs. Project).
 *   7.  Status stamp: storyboardStatus = 'generating', storyboardFrameCount = 0.
 *   8.  Assemble n8n payload from merged context + project fields.
 *         [FIX-04] description included.
 *         [SCH-01] subCategory (was: secondaryCategory — wrong field name).
 *         [SCH-02] targetAudience normalised from project.target_audience.
 *   9.  Serialise once → sign → transmit the SAME bytes (byte identity guaranteed).
 *  10.  Fire-and-forget: postWithRetry dispatches the signed webhook.
 *  11.  On dispatch failure: rollback status to 'failed', return structured error.
 *  12.  On success: return immediately. n8n pipeline runs asynchronously.
 *
 * @param {string} projectId
 * @returns {{ ok: boolean, status: number, data?: object, error?: object }}
 */
export const generateStoryboard = webMethod(
  Permissions.SiteMember,
  async (projectId) => {
    const requestId = `gs_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`${VERSION} [${requestId}] generateStoryboard() invoked — projectId: ${projectId}`);

    // ── 1. Input validation ──────────────────────────────────────────────────
    if (!projectId || typeof projectId !== 'string' || !projectId.trim()) {
      console.warn(`${VERSION} [${requestId}] Missing or invalid projectId`);
      return fail(400, 'VALIDATION_ERROR', 'projectId is required.');
    }

    // ── 2. Identity check ────────────────────────────────────────────────────
    const memberId = await getMemberId();
    if (!memberId) {
      console.warn(`${VERSION} [${requestId}] Unauthenticated attempt`);
      return fail(401, 'AUTH_REQUIRED', 'Authentication required.');
    }

    // ── 3. Project fetch + ownership check ───────────────────────────────────
    let project;
    try {
      project = await wixData.get(COLLECTION_PROJECTS, projectId, DB_OPTIONS);
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
    if (project.storyboardStatus === STATUS_GENERATING) {
      console.warn(`${VERSION} [${requestId}] Already generating — projectId: ${projectId}`);
      return fail(409, 'ALREADY_RUNNING', 'Storyboard generation is already in progress.');
    }

    // ── 5. Parallel fetch: profile + secrets ─────────────────────────────────
    // Profile supplies companyName, companyDescription, primaryCategory,
    // subCategory, and customerType. A null profile is not immediately
    // fatal — the validation gate in step 6 catches any blank required fields.
    let profile = null;
    let webhookUrl, callbackSecret;

    try {
      const [profileResult, webhookUrlValue, callbackSecretValue] = await Promise.all([
        wixData
          .query(COLLECTION_PROFILES)
          .eq('_owner', memberId)
          .limit(1)
          .find(DB_OPTIONS)
          .then((res) => res.items[0] ?? null),
        getSecret(SECRET_WEBHOOK_URL),
        getSecret(SECRET_CALLBACK_KEY),
      ]);

      profile        = profileResult;
      webhookUrl     = webhookUrlValue;
      callbackSecret = callbackSecretValue;

    } catch (err) {
      console.error(`${VERSION} [${requestId}] Profile/secret fetch failed: ${err.message}`);
      return fail(500, 'CONFIG_ERROR', 'Pipeline configuration is unavailable. Please try again later.');
    }

    if (!profile) {
      console.warn(`${VERSION} [${requestId}] No profile record found for member: ${memberId}`);
    } else {
      console.log(`${VERSION} [${requestId}] Profile loaded — enriching payload fields`);
    }

    const missingSecrets = [
      !webhookUrl     && SECRET_WEBHOOK_URL,
      !callbackSecret && SECRET_CALLBACK_KEY,
    ].filter(Boolean);

    if (missingSecrets.length > 0) {
      console.error(`${VERSION} [${requestId}] Empty secrets: ${missingSecrets.join(', ')}`);
      return fail(500, 'CONFIG_ERROR', 'Pipeline configuration is incomplete. Please contact support.');
    }

    // ── 5a. Merge project + profile → enriched context ────────────────────────
    //
    // Field source map:
    //   companyName        → profiles collection  (company identity)
    //   companyDescription → profiles collection  (company identity)
    //   primaryCategory    → profiles collection  (Category Settings modal)
    //   subCategory        → profiles collection  (Category Settings modal) [SCH-01]
    //   customerType       → profiles collection  (Category Settings modal)
    //   targetAudience     → projects collection  (DB key: target_audience)  [SCH-02]
    //
    // Resolution order: project value → profile value → ''
    // Project-level values win if populated, enabling per-project overrides.
    // Normalisation: project.target_audience (snake_case DB column) is read
    // and surfaced as enriched.targetAudience (camelCase) for n8n consumption.
    const enriched = {
      companyName:        project.companyName        || profile?.companyName        || '',
      companyDescription: project.companyDescription || profile?.companyDescription || '',
      primaryCategory:    project.primaryCategory    || profile?.primaryCategory    || '',
      subCategory:        project.subCategory        || profile?.subCategory        || '', // [SCH-01] was: secondaryCategory
      customerType:       project.customerType       || profile?.customerType       || '',
      targetAudience:     project.target_audience    || '',  // [SCH-02] was: project.targetAudience
    };

    // [OBS-02] subCategory added to enriched log (was: secondaryCategory)
    console.log(
      `${VERSION} [${requestId}] Enriched` +
      ` | companyName: "${enriched.companyName}"` +
      ` | primaryCategory: "${enriched.primaryCategory}"` +
      ` | subCategory: "${enriched.subCategory}"` +
      ` | customerType: "${enriched.customerType}"` +
      ` | targetAudience: "${enriched.targetAudience}"`
    );

    // ── 6. Pre-dispatch validation on merged values ───────────────────────────
    // Validates final resolved values — NOT raw project or profile fields.
    // Error message routes the user to the correct settings panel.
    const missingProfile = REQUIRED_PROFILE_FIELDS.filter((f) => !enriched[f]);
    const missingProject = REQUIRED_PROJECT_FIELDS.filter((f) => !enriched[f]);
    const missingFields  = [...missingProfile, ...missingProject];

    if (missingFields.length > 0) {
      const parts = [];
      if (missingProfile.length > 0) {
        parts.push(`Profile Settings missing: ${missingProfile.join(', ')}`);
      }
      if (missingProject.length > 0) {
        parts.push(`Project missing: ${missingProject.join(', ')} — please edit your project`);
      }
      const userMessage = `${parts.join('. ')}.`;
      console.warn(`${VERSION} [${requestId}] Pre-dispatch validation failed — ${userMessage}`);
      return {
        ok: false, status: 400,
        error: { type: 'INCOMPLETE_DATA', message: userMessage, missingProfile, missingProject },
      };
    }

    console.log(`${VERSION} [${requestId}] Pre-dispatch validation passed — all required fields resolved`);

    // ── 7. Stamp project status ───────────────────────────────────────────────
    const generationStartedAt = new Date().toISOString();
    try {
      await wixData.update(
        COLLECTION_PROJECTS,
        {
          _id:                   project._id,
          storyboardStatus:      STATUS_GENERATING,
          storyboardFrameCount:  0,
          storyboardStartedAt:   generationStartedAt,
          storyboardCompletedAt: null,
        },
        DB_OPTIONS
      );
      console.log(`${VERSION} [${requestId}] Project stamped '${STATUS_GENERATING}'`);
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Status stamp failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to update project status.');
    }

    // ── 8. Assemble n8n payload ───────────────────────────────────────────────
    // Profile-sourced fields come from `enriched` (validated above).
    // Project-sourced narrative fields come directly from the project record.
    // [FIX-04] description added — was absent in v1.3.0.
    // [SCH-01] subCategory — corrected from secondaryCategory (v1.4.0).
    // [SCH-02] targetAudience — normalised from project.target_audience in enriched.
    const n8nPayload = {
      submissionId:       requestId,
      timestamp:          generationStartedAt,
      projectId:          project._id,
      owner:              project._owner,
      // Company identity (profile-sourced, project-override allowed)
      companyName:        enriched.companyName,
      companyDescription: enriched.companyDescription,
      primaryCategory:    enriched.primaryCategory,
      subCategory:        enriched.subCategory,          // [SCH-01] was: secondaryCategory
      customerType:       enriched.customerType,
      // Campaign fields (project-only)
      targetAudience:     enriched.targetAudience,       // [SCH-02] reads from project.target_audience
      title:              project.title         ?? '',
      description:        project.description   ?? '',   // [FIX-04]
      goal:               project.goal          ?? '',
      offer:              project.offer         ?? '',
      misconception:      project.misconception ?? '',
    };

    // ── 9. Serialise once — sign and send the same bytes ─────────────────────
    // rawBody is produced here, once. Passed to both buildHmacSignature() and
    // postWithRetry() — byte identity between signed and transmitted is guaranteed.
    const rawBody = JSON.stringify(n8nPayload);
    const hmacSig = buildHmacSignature(rawBody, callbackSecret);

    console.log(`${VERSION} [${requestId}] Payload assembled — HMAC signed — dispatching to n8n`);

    // ── 10. Fire-and-forget webhook dispatch ──────────────────────────────────
    const dispatchResult = await postWithRetry(webhookUrl, rawBody, hmacSig, requestId);

    if (!dispatchResult.ok) {
      console.error(
        `${VERSION} [${requestId}] All webhook attempts failed: ${dispatchResult.error?.message}`
      );
      await rollbackStatus(project, requestId);
      return fail(502, 'WEBHOOK_ERROR', 'Storyboard generation pipeline is unavailable. Please try again.');
    }

    // [OBS-01] Explicit DISPATCH_COMPLETE event for end-to-end traceability
    console.log(
      `${VERSION} [${requestId}] DISPATCH_COMPLETE` +
      ` | submissionId: ${requestId}` +
      ` | projectId: ${project._id}` +
      ` | timestamp: ${generationStartedAt}`
    );

    return ok({
      projectId,
      storyboardStatus:    STATUS_GENERATING,
      generationStartedAt,
      submissionId:        requestId,
    });
  }
);

// ─── cancelStoryboard ─────────────────────────────────────────────────────────

/**
 * Stamps the project storyboardStatus as 'cancelled' to halt polling.
 * Idempotent — safe to call on already-cancelled, complete, or failed projects.
 * Does NOT cancel the n8n pipeline itself (MVP scope).
 *
 * Called by: project-detail.page.js → #btnCancelStoryboard click handler.
 * Import path: backend/storyboard/generateStoryboard.web
 *
 * [FIX-01] Permissions.Member → Permissions.SiteMember (Member is not a valid
 *          Wix Permissions export; SiteMember is the correct enum value).
 *
 * @param {string} projectId
 * @returns {{ ok: boolean, status: number, data?: object, error?: object }}
 */
export const cancelStoryboard = webMethod(
  Permissions.SiteMember, // [FIX-01] was: Permissions.Member
  async (projectId) => {
    const requestId = `cs_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`${CANCEL_VERSION} [${requestId}] cancelStoryboard() invoked — projectId: ${projectId}`);

    // ── 1. Input validation ──────────────────────────────────────────────────
    if (!projectId || typeof projectId !== 'string' || !projectId.trim()) {
      console.warn(`${CANCEL_VERSION} [${requestId}] Missing or invalid projectId`);
      return fail(400, 'VALIDATION_ERROR', 'projectId is required.');
    }

    // ── 2. Identity check ────────────────────────────────────────────────────
    const memberId = await getMemberId();
    if (!memberId) {
      console.warn(`${CANCEL_VERSION} [${requestId}] Unauthenticated attempt`);
      return fail(401, 'AUTH_REQUIRED', 'Authentication required.');
    }

    // ── 3. Project fetch + ownership check ───────────────────────────────────
    let project;
    try {
      project = await wixData.get(COLLECTION_PROJECTS, projectId, DB_OPTIONS);
    } catch (err) {
      console.error(`${CANCEL_VERSION} [${requestId}] Project fetch failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to load project.');
    }

    if (!project) {
      console.warn(`${CANCEL_VERSION} [${requestId}] Project not found: ${projectId}`);
      return fail(404, 'NOT_FOUND', 'Project not found.');
    }

    if (project._owner !== memberId) {
      console.warn(`${CANCEL_VERSION} [${requestId}] Ownership mismatch — caller: ${memberId}`);
      return fail(403, 'FORBIDDEN', 'You do not own this project.');
    }

    // ── 4. Idempotent guard — only write if currently generating ─────────────
    if (project.storyboardStatus !== STATUS_GENERATING) {
      // [OBS-03] was: console.log — changed to warn so no-op cancel calls surface
      //          in error dashboards (repeated cancels on a completed project
      //          indicate a frontend state bug worth tracking).
      console.warn(
        `${CANCEL_VERSION} [${requestId}] No-op — status is already: ${project.storyboardStatus}`
      );
      return ok({ projectId, storyboardStatus: project.storyboardStatus, cancelled: false });
    }

    // ── 5. Stamp cancelled ────────────────────────────────────────────────────
    try {
      await wixData.update(
        COLLECTION_PROJECTS,
        { _id: project._id, storyboardStatus: STATUS_CANCELLED, cancelledAt: new Date().toISOString() },
        DB_OPTIONS
      );
    } catch (err) {
      console.error(`${CANCEL_VERSION} [${requestId}] Cancel stamp failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to update project status.');
    }

    console.log(
      `${CANCEL_VERSION} [${requestId}] Project stamped '${STATUS_CANCELLED}' — projectId: ${projectId}`
    );
    return ok({ projectId, storyboardStatus: STATUS_CANCELLED, cancelled: true });
  }
);

// ─── Debug exports ─────────────────────────────────────────────────────────────

export async function debugGenerateStoryboard(projectId = 'debug-project-id') {
  console.log(`${VERSION} [DEBUG] generateStoryboard simulation — projectId: ${projectId}`);
  return { debug: true, projectId, timestamp: new Date().toISOString() };
}

export async function debugCancelStoryboard(projectId = 'debug-project-id') {
  console.log(`${CANCEL_VERSION} [DEBUG] cancelStoryboard simulation — projectId: ${projectId}`);
  return { debug: true, projectId, timestamp: new Date().toISOString() };
}

// [CMP-03] CANCEL_VERSION added alongside VERSION for full component identity
export async function debugWebhookStatus() {
  console.log(`${VERSION} [DEBUG] debugWebhookStatus called`);
  return {
    debug:         true,
    version:       VERSION,
    cancelVersion: CANCEL_VERSION, // [CMP-03]
    timestamp:     new Date().toISOString(),
  };
}