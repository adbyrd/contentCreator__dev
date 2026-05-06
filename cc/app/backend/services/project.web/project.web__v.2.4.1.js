/**
 * [ FILE NAME : project.web.js : v2.4.1 ]
 *
 * Service: Project Service
 * Path: /backend/services/project.web.js
 * Version: [ PROJECT SERVICE : v.2.4.1 ]
 *
 * v2.4.1 — targetAudience Schema Fix + Field-Routed Error Messages
 * ─────────────────────────────────────────────────────────────────────────────
 * BUG: Five payload fields still blank after v2.4.0 profile enrichment.
 *
 * ROOT CAUSE (confirmed from profiles.csv schema):
 *   The `profiles` CMS collection does NOT have a `targetAudience` column.
 *   v2.4.0's enrichment fallback `profile?.targetAudience` always resolves
 *   to undefined — the field must be captured on the `projects` record.
 *
 *   Additionally, the existing profile record for the test user has
 *   `primaryCategory` and `customerType` both empty — the user has never
 *   completed the Category Settings modal. These are profile fields and
 *   require a UI/UX fix, not a code fix.
 *
 * Confirmed field source map:
 *   Field               Source         Status for test user
 *   ──────────────────────────────────────────────────────
 *   companyName         profiles       ✅ "Rent-A-Chicken, LLC"
 *   companyDescription  profiles       ⚠️  Placeholder text — needs real data
 *   primaryCategory     profiles       ❌ Empty — Category Settings not saved
 *   customerType        profiles       ❌ Empty — Category Settings not saved
 *   targetAudience      projects       ❌ Not a profiles column — project field
 *
 * CHANGES FROM v2.4.0:
 *   1. enriched.targetAudience fallback to profile?.targetAudience removed.
 *      targetAudience is now strictly project.targetAudience || '' — correct
 *      source, no phantom profile fallback.
 *   2. Validation split into PROFILE_FIELDS vs PROJECT_FIELDS arrays so the
 *      error response and user message route each missing field to the correct
 *      settings panel:
 *        missingProfile → "Update Profile Settings (Company / Category modal)"
 *        missingProject → "Edit your project"
 *   3. Error type changed from INCOMPLETE_PROFILE → INCOMPLETE_DATA to
 *      reflect that the issue may span both profile and project.
 *   4. Error response now includes missingProfile[] and missingProject[]
 *      arrays so the frontend can deep-link to the correct modal directly.
 *   5. Enrichment log line extended to include targetAudience value.
 *
 * Required action for the test user (44dd37f0...):
 *   1. Open Profile Settings → Category → select primaryCategory + customerType
 *      → Save. This populates the profiles record.
 *   2. Open the project (2c2c5dc8...) → Edit → set targetAudience → Save.
 *      This populates the projects record.
 *   After both steps, generateStoryboard() will pass validation and dispatch.
 *
 * All other exports are UNCHANGED from v2.4.0.
 *
 * Scalability remediations from v2.1.0 (preserved):
 *   SC-02  getMyProjects enforces PROJECT_LIMIT (25), returns nextCursor.
 *   SC-02  getStoryboardFrames uses .limit(TOTAL_FRAMES).
 *   SC-03  MAX_RETRIES = 2, WEBHOOK_TIMEOUT_MS = 8000 ms.
 *   SC-07  getUserProjectCount and getMyProjects query on _owner only.
 *
 * Wix Secrets required:
 *   N8N_STORYBOARD_WEBHOOK_URL  — n8n trigger URL
 *   N8N_CALLBACK_SECRET_KEY     — shared HMAC-SHA256 key
 *
 * Collections:
 *   projects         — core project records
 *   storyboard_frames — per-frame image + metadata (projectId · owner-scoped)
 *
 * Required CMS indexes (configure in Wix Dashboard → Content Manager):
 *   projects         : compound (_owner, _createdDate DESC)
 *   storyboard_frames: compound (projectId, frameIndex ASC)
 *   storyboard_frames: secondary (owner, projectId)
 */

import { Permissions, webMethod } from 'wix-web-module';
import wixData                    from 'wix-data';
import { currentMember }          from 'wix-members-backend';

// NOTE: wix-secrets-backend, wix-fetch, and crypto are intentionally NOT
// imported at the module level — all are backend-only. A top-level static
// import causes Wix's bundler to attempt resolution in the frontend context
// and throw: "Cannot find module 'wix-web-module' in 'public/pages/...'"
// All three are required inline inside the webMethods that use them.

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

const VERSION              = '[ PROJECT SERVICE : v.2.4.1 ]';

const COLLECTION_PROJECTS  = 'projects';
const COLLECTION_PROFILES  = 'profiles';
const COLLECTION_FRAMES    = 'storyboard_frames';
const DB_OPTIONS           = { suppressAuth: true };

const ROLE_ADMIN           = 'Admin';

// Pagination ceiling — enforced at the data layer, not just the UI.
const PROJECT_LIMIT        = 25;

// Storyboard pipeline
const SECRET_N8N_WEBHOOK   = 'N8N_STORYBOARD_WEBHOOK_URL';
const SECRET_CALLBACK_KEY  = 'N8N_CALLBACK_SECRET_KEY';
const TOTAL_FRAMES         = 15;
const FINAL_FRAME_INDEX    = TOTAL_FRAMES - 1; // 14

// SC-03: Webhook retry config — timeout reduced so MAX_RETRIES × WEBHOOK_TIMEOUT_MS
// stays well under the 30-second Velo webMethod execution ceiling.
//   MAX_RETRIES = 2, WEBHOOK_TIMEOUT_MS = 8000 → worst-case ≈ 17 s
const MAX_RETRIES          = 2;
const RETRY_DELAYS         = [500, 1500];  // ms — one delay between two attempts
const RETRYABLE_STATUSES   = [429, 502, 503, 504];
const WEBHOOK_TIMEOUT_MS   = 8000;

// Storyboard status values
const STATUS_GENERATING    = 'generating';
const STATUS_COMPLETE      = 'complete';
const STATUS_FAILED        = 'failed';
const STATUS_CANCELLED     = 'cancelled';

// Pre-dispatch required fields — must be non-empty on the project record
// before we are permitted to fire the n8n webhook. These map 1:1 to the
// REQUIRED array in n8n Stage 1 node.02.
const STORYBOARD_REQUIRED_FIELDS = [
  'companyName',
  'companyDescription',
  'primaryCategory',
  'customerType',
  'targetAudience',
];

// ─── INTERNAL HELPERS ─────────────────────────────────────────────────────────

/**
 * Resolves the currently authenticated member's ID and admin status.
 * Uses fieldsets: ['FULL'] so that roles are included in a single call.
 *
 * @returns {{ memberId: string|null, isAdmin: boolean }}
 */
async function getAuthenticatedMember() {
    try {
        const member = await currentMember.getMember({ fieldsets: ['FULL'] });
        if (!member) return { memberId: null, isAdmin: false };

        const isAdmin = Array.isArray(member.roles)
            ? member.roles.some((r) => r.name === ROLE_ADMIN)
            : false;

        return { memberId: member._id, isAdmin };
    } catch (err) {
        console.error(`${VERSION} getAuthenticatedMember failure:`, err);
        return { memberId: null, isAdmin: false };
    }
}

/**
 * Best-effort project status rollback to STATUS_FAILED.
 * Never throws — a rollback failure must not mask the originating error.
 *
 * @param {object} project  - Full project record from wixData.get()
 * @param {string} requestId
 */
async function rollbackStatus(project, requestId) {
    try {
        await wixData.update(
            COLLECTION_PROJECTS,
            { ...project, storyboardStatus: STATUS_FAILED },
            DB_OPTIONS
        );
        console.warn(`${VERSION} [${requestId}] Status rolled back to '${STATUS_FAILED}'`);
    } catch (err) {
        console.error(`${VERSION} [${requestId}] Rollback failed (non-fatal): ${err.message}`);
    }
}

/**
 * Signs a pre-serialised JSON string with HMAC-SHA256.
 * The string passed here MUST be the same reference passed as the request body —
 * byte identity between signed content and transmitted content is mandatory.
 *
 * @param {string} rawBody  - JSON.stringify() output
 * @param {string} secret   - N8N_CALLBACK_SECRET_KEY value
 * @returns {string}        - Hex digest
 */
function buildHmacSignature(rawBody, secret) {
    const { createHmac } = require('crypto');
    return createHmac('sha256', secret).update(rawBody).digest('hex');
}

/**
 * Fires a signed POST request to a webhook URL with exponential backoff.
 *
 * v2.3.0: Upgraded from the v2.2.0 signature (url, body: object) to accept
 *   rawBody (pre-serialised string) and hmacSignature (hex string) so that
 *   the bytes signed and the bytes transmitted are guaranteed identical.
 *   X-HMAC-Signature header is now attached on every attempt.
 *
 * SC-03: MAX_RETRIES = 2, WEBHOOK_TIMEOUT_MS = 8000 ms.
 * Worst-case total execution time ≈ 17 s, safely under the 30 s Velo limit.
 *
 * @param {string} url
 * @param {string} rawBody        - Pre-serialised JSON string (not re-stringified)
 * @param {string} hmacSignature  - Hex HMAC-SHA256 of rawBody
 * @param {string} requestId
 * @returns {{ ok: boolean, status: number, data?: any, error?: object }}
 */
async function postWithRetry(url, rawBody, hmacSignature, requestId) {
    const { fetch } = require('wix-fetch');
    let lastError = null;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);

        try {
            console.log(`${VERSION} [${requestId}] Webhook attempt ${attempt}/${MAX_RETRIES}`);

            const response = await fetch(url, {
                method:  'POST',
                headers: {
                    'Content-Type':     'application/json',
                    'X-HMAC-Signature': hmacSignature,  // Required by n8n Stage 1 node.02
                },
                body:   rawBody,   // Same string that was signed — no re-serialisation
                signal: controller.signal,
            });

            clearTimeout(timer);

            if (response.ok) {
                const data = await response.json().catch(() => ({}));
                console.log(`${VERSION} [${requestId}] Webhook dispatched successfully on attempt ${attempt}`);
                return { ok: true, status: response.status, data };
            }

            // Non-retryable client errors — surface immediately, do not retry
            if (!RETRYABLE_STATUSES.includes(response.status)) {
                console.error(`${VERSION} [${requestId}] Non-retryable status: ${response.status}`);
                return {
                    ok:     false,
                    status: response.status,
                    error:  { type: 'HTTP_ERROR', message: `Non-retryable HTTP ${response.status}` },
                };
            }

            lastError = `HTTP ${response.status}`;
            console.warn(`${VERSION} [${requestId}] Attempt ${attempt} returned ${response.status}`);

        } catch (err) {
            clearTimeout(timer);
            lastError = err.name === 'AbortError' ? 'TIMEOUT' : err.message;
            console.warn(`${VERSION} [${requestId}] Webhook attempt ${attempt} failed: ${lastError}`);
        }

        if (attempt < MAX_RETRIES) {
            await new Promise((res) => setTimeout(res, RETRY_DELAYS[attempt - 1]));
        }
    }

    console.error(`${VERSION} [${requestId}] All ${MAX_RETRIES} webhook attempts exhausted. Last: ${lastError}`);
    return {
        ok:     false,
        status: 503,
        error:  { type: 'WEBHOOK_UNAVAILABLE', message: lastError },
    };
}

// ─── CREATE PROJECT ───────────────────────────────────────────────────────────

/**
 * Creates a new project record owned by the authenticated member.
 *
 * The `owner` field is written alongside the Wix-native `_owner` for
 * backward compatibility with records created under v1.3.x. Once a data
 * migration consolidates all records to `_owner`, the `owner` mirror can
 * be removed from the insert payload (SC-07 long-term cleanup).
 *
 * @param {object} projectData
 * @returns {{ ok: boolean, data?: object, error?: object }}
 */
export const createProject = webMethod(Permissions.Anyone, async (projectData) => {
    try {
        const { memberId } = await getAuthenticatedMember();
        if (!memberId) {
            console.warn(`${VERSION} createProject: Unauthenticated attempt.`);
            return { ok: false, error: { type: 'AUTH_REQUIRED', message: 'Authentication required.' } };
        }

        const payload = {
            title:              projectData.title,
            description:        projectData.description,
            companyName:        projectData.companyName,
            companyDescription: projectData.companyDescription,
            primaryCategory:    projectData.primaryCategory,
            customerType:       projectData.customerType,
            goal:               projectData.goal,
            offer:              projectData.offer,
            targetAudience:     projectData.targetAudience ?? projectData.target_audience ?? projectData.audience,
            misconception:      projectData.misconception,
            // Write both fields during the transition period (SC-07).
            owner: memberId,
        };

        const result = await wixData.insert(COLLECTION_PROJECTS, payload, DB_OPTIONS);
        console.log(`${VERSION} createProject: Created ${result._id} for member: ${memberId}`);
        return { ok: true, data: result };

    } catch (err) {
        console.error(`${VERSION} createProject failure:`, err);
        return { ok: false, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── VERIFY PROJECT ACCESS ────────────────────────────────────────────────────

/**
 * Authorization gate for the Project Detail dynamic page.
 * Access is granted only to the project owner or a site admin.
 * Returns no project data on denial to prevent information leakage.
 *
 * @param {string} projectId
 * @returns {{ ok: boolean, authorized: boolean, data?: object, error?: object }}
 */
export const verifyProjectAccess = webMethod(Permissions.Anyone, async (projectId) => {
    try {
        if (!projectId) {
            console.warn(`${VERSION} verifyProjectAccess: Called without a projectId.`);
            return {
                ok: false, authorized: false,
                error: { type: 'MISSING_ID', message: 'Project ID is required.' },
            };
        }

        const { memberId, isAdmin } = await getAuthenticatedMember();
        if (!memberId) {
            console.warn(`${VERSION} verifyProjectAccess: Unauthenticated attempt. Project: ${projectId}`);
            return {
                ok: true, authorized: false,
                error: { type: 'AUTH_REQUIRED', message: 'Authentication required.' },
            };
        }

        const project = await wixData.get(COLLECTION_PROJECTS, projectId, DB_OPTIONS);
        if (!project) {
            console.warn(`${VERSION} verifyProjectAccess: Not found. ID: ${projectId}`);
            return {
                ok: false, authorized: false,
                error: { type: 'NOT_FOUND', message: 'Project not found.' },
            };
        }

        if (project._owner === memberId) {
            console.log(`${VERSION} verifyProjectAccess: GRANTED (owner). Member: ${memberId}`);
            return { ok: true, authorized: true, data: project };
        }

        if (isAdmin) {
            console.log(`${VERSION} verifyProjectAccess: GRANTED (admin). Member: ${memberId}`);
            return { ok: true, authorized: true, data: project };
        }

        console.warn(`${VERSION} verifyProjectAccess: DENIED. Member: ${memberId}`);
        return {
            ok: true, authorized: false,
            error: { type: 'FORBIDDEN', message: 'You do not have permission to view this project.' },
        };

    } catch (err) {
        console.error(`${VERSION} verifyProjectAccess failure:`, err);
        return { ok: false, authorized: false, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── UPDATE PROJECT ───────────────────────────────────────────────────────────

/**
 * Updates an existing project record. Owner-only — admin read access does
 * not confer write access by design.
 *
 * @param {string} projectId
 * @param {object} projectData
 * @returns {{ ok: boolean, data?: object, error?: object }}
 */
export const updateProject = webMethod(Permissions.Anyone, async (projectId, projectData) => {
    try {
        if (!projectId) {
            console.warn(`${VERSION} updateProject: Called without a projectId.`);
            return { ok: false, error: { type: 'MISSING_ID', message: 'Project ID is required.' } };
        }

        const { memberId } = await getAuthenticatedMember();
        if (!memberId) {
            console.warn(`${VERSION} updateProject: Unauthorized attempt.`);
            return { ok: false, error: { type: 'AUTH_REQUIRED', message: 'Authentication required.' } };
        }

        const existing = await wixData.get(COLLECTION_PROJECTS, projectId, DB_OPTIONS);
        if (!existing) {
            console.error(`${VERSION} updateProject: Not found. ID: ${projectId}`);
            return { ok: false, error: { type: 'NOT_FOUND', message: 'Project not found.' } };
        }

        if (existing._owner !== memberId) {
            console.warn(`${VERSION} updateProject: Ownership mismatch. Member: ${memberId}`);
            return { ok: false, error: { type: 'FORBIDDEN', message: 'You do not have permission to edit this project.' } };
        }

        const updatePayload = {
            _id:                existing._id,
            _owner:             existing._owner,
            owner:              existing.owner,  // preserve mirror field during SC-07 transition
            title:              projectData.title,
            description:        projectData.description,
            companyName:        projectData.companyName,
            companyDescription: projectData.companyDescription,
            primaryCategory:    projectData.primaryCategory,
            customerType:       projectData.customerType,
            goal:               projectData.goal,
            offer:              projectData.offer,
            targetAudience:     projectData.targetAudience ?? projectData.target_audience,
            misconception:      projectData.misconception,
        };

        const result = await wixData.update(COLLECTION_PROJECTS, updatePayload, DB_OPTIONS);
        console.log(`${VERSION} updateProject: Updated ${result._id} by member: ${memberId}`);
        return { ok: true, data: result };

    } catch (err) {
        console.error(`${VERSION} updateProject failure:`, err);
        return { ok: false, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── GET PROJECT COUNT ────────────────────────────────────────────────────────

/**
 * Returns the total project count for the authenticated member.
 * SC-07: queries on _owner (Wix-native indexed field) not the mirror field.
 *
 * @returns {{ ok: boolean, count: number, error?: object }}
 */
export const getUserProjectCount = webMethod(Permissions.Anyone, async () => {
    try {
        const { memberId } = await getAuthenticatedMember();
        if (!memberId) return { ok: true, count: 0 };

        const count = await wixData.query(COLLECTION_PROJECTS)
            .eq('_owner', memberId)
            .count(DB_OPTIONS);

        console.log(`${VERSION} getUserProjectCount: ${count} for member: ${memberId}`);
        return { ok: true, count };

    } catch (err) {
        console.error(`${VERSION} getUserProjectCount failure:`, err);
        return { ok: false, count: 0, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── GET MY PROJECTS ──────────────────────────────────────────────────────────

/**
 * Returns a page of projects owned by the authenticated member, newest first.
 *
 * SC-02: Enforces PROJECT_LIMIT (25) at the data layer.
 * SC-07: Queries on _owner (Wix-native indexed field).
 *
 * @param {{ limit?: number, cursor?: string|null }} [options]
 * @returns {{ ok: boolean, data: array, nextCursor: string|null, error?: object }}
 */
export const getMyProjects = webMethod(Permissions.Anyone, async ({ limit = PROJECT_LIMIT, cursor = null } = {}) => {
    try {
        const { memberId } = await getAuthenticatedMember();
        if (!memberId) return { ok: true, data: [], nextCursor: null };

        const safeLimit = Math.min(limit, PROJECT_LIMIT);

        let query = wixData.query(COLLECTION_PROJECTS)
            .eq('_owner', memberId)
            .descending('_createdDate')
            .limit(safeLimit);

        const results = cursor
            ? await query.skipTo(cursor).find(DB_OPTIONS)
            : await query.find(DB_OPTIONS);

        const nextCursor = results.cursors?.next || null;

        console.log(`${VERSION} getMyProjects: ${results.items.length} projects for member: ${memberId}. hasMore: ${!!nextCursor}`);
        return { ok: true, data: results.items, nextCursor };

    } catch (err) {
        console.error(`${VERSION} getMyProjects failure:`, err);
        return { ok: false, data: [], nextCursor: null, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── GENERATE STORYBOARD ──────────────────────────────────────────────────────

/**
 * Dispatch gate for the n8n storyboard generation pipeline.
 *
 * Flow:
 *   1.  Input guard.
 *   2.  Identity check.
 *   3.  Fetch project and verify ownership.
 *   4.  Duplicate-run guard (ALREADY_RUNNING).
 *   5.  Fetch caller's profile record in parallel with secrets.
 *   5a. Enrich project fields from profile — three-tier resolution:
 *         project field  →  profile field  →  empty string
 *   6.  Pre-dispatch field validation on MERGED values — surfaces
 *       INCOMPLETE_PROFILE if required data is absent from both sources.
 *   7.  Stamp project: storyboardStatus = 'generating'.
 *   8.  Assemble n8n payload from merged context.
 *   9.  Serialise once — sign and transmit the same bytes (byte identity).
 *  10.  Fire signed webhook via postWithRetry (X-HMAC-Signature header).
 *  11.  On failure: rollback status to 'failed', return structured error.
 *
 * v2.4.0 Fix — Profile enrichment:
 *   companyName / companyDescription / primaryCategory / customerType /
 *   targetAudience are stored on the `profiles` collection, not `projects`.
 *   The project record for these fields is blank by design. The profile
 *   record is now fetched and used as the authoritative source for all five
 *   fields, with the project record value taking precedence if set.
 *
 * @param {string} projectId
 * @returns {{ ok: boolean, status: number, data?: object, error?: object }}
 */
export const generateStoryboard = webMethod(Permissions.Anyone, async (projectId) => {
    const requestId = `gs_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`${VERSION} [${requestId}] generateStoryboard() invoked — projectId: ${projectId}`);

    try {
        // ── 1. Input guard ───────────────────────────────────────────────────
        if (!projectId) {
            console.warn(`${VERSION} [${requestId}] No projectId supplied.`);
            return { ok: false, status: 400, error: { type: 'MISSING_ID', message: 'Project ID is required.' } };
        }

        // ── 2. Identity check ────────────────────────────────────────────────
        const { memberId } = await getAuthenticatedMember();
        if (!memberId) {
            console.warn(`${VERSION} [${requestId}] Unauthenticated attempt.`);
            return { ok: false, status: 401, error: { type: 'AUTH_REQUIRED', message: 'Authentication required.' } };
        }

        // ── 3. Fetch project + ownership check ───────────────────────────────
        const project = await wixData.get(COLLECTION_PROJECTS, projectId, DB_OPTIONS);
        if (!project) {
            console.warn(`${VERSION} [${requestId}] Project not found: ${projectId}`);
            return { ok: false, status: 404, error: { type: 'NOT_FOUND', message: 'Project not found.' } };
        }

        if (project._owner !== memberId) {
            console.warn(`${VERSION} [${requestId}] Ownership mismatch. Member: ${memberId}`);
            return { ok: false, status: 403, error: { type: 'FORBIDDEN', message: 'You do not own this project.' } };
        }

        // ── 4. Duplicate-run guard ───────────────────────────────────────────
        if (project.storyboardStatus === STATUS_GENERATING) {
            console.warn(`${VERSION} [${requestId}] Already running for project: ${projectId}`);
            return {
                ok: false, status: 409,
                error: { type: 'ALREADY_RUNNING', message: 'Storyboard generation is already in progress.' },
            };
        }

        // ── 5. Fetch profile + retrieve secrets (parallel) ───────────────────
        // Profile supplies companyName, companyDescription, primaryCategory,
        // customerType, targetAudience — these fields are not stored on the
        // project record. Both calls are fired together to keep latency low.
        // Profile fetch failure is non-fatal: execution continues and the
        // validation step below will catch any resulting blank fields.
        const { getSecret } = require('wix-secrets-backend');

        let profile = null;
        let webhookUrl, callbackSecret;

        try {
            const [profileResult, webhookUrlValue, callbackSecretValue] = await Promise.all([
                wixData.query(COLLECTION_PROFILES)
                    .eq('_owner', memberId)
                    .limit(1)
                    .find(DB_OPTIONS)
                    .then((res) => res.items[0] ?? null),
                getSecret(SECRET_N8N_WEBHOOK),
                getSecret(SECRET_CALLBACK_KEY),
            ]);

            profile         = profileResult;
            webhookUrl      = webhookUrlValue;
            callbackSecret  = callbackSecretValue;

        } catch (err) {
            console.error(`${VERSION} [${requestId}] Profile/secret fetch failed: ${err.message}`);
            await rollbackStatus(project, requestId);
            return { ok: false, status: 500, error: { type: 'CONFIG_ERROR', message: 'Pipeline configuration is unavailable. Please try again later.' } };
        }

        if (!profile) {
            console.warn(`${VERSION} [${requestId}] No profile record found for member: ${memberId}`);
        } else {
            console.log(`${VERSION} [${requestId}] Profile loaded — enriching payload fields`);
        }

        const missingSecrets = [
            !webhookUrl     && SECRET_N8N_WEBHOOK,
            !callbackSecret && SECRET_CALLBACK_KEY,
        ].filter(Boolean);

        if (missingSecrets.length > 0) {
            console.error(`${VERSION} [${requestId}] Empty secrets: ${missingSecrets.join(', ')}`);
            await rollbackStatus(project, requestId);
            return { ok: false, status: 500, error: { type: 'CONFIG_ERROR', message: 'Pipeline configuration is incomplete. Please contact support.' } };
        }

        // ── 5a. Merge project + profile into enriched context ─────────────────
        //
        // Field source map (v2.4.1):
        //
        //   companyName        → profiles collection  (company identity)
        //   companyDescription → profiles collection  (company identity)
        //   primaryCategory    → profiles collection  (set in Category Settings modal)
        //   customerType       → profiles collection  (set in Category Settings modal)
        //   targetAudience     → projects collection  (campaign-specific — NOT on profiles schema)
        //
        // targetAudience is intentionally project-only. The profiles CMS collection
        // does not have a targetAudience column (confirmed from schema). Attempting
        // to fall back to profile?.targetAudience always yields undefined and masks
        // the real issue — the field must be captured during project creation/editing.
        //
        // Resolution order for profile fields: project value → profile value → ''
        // Project-level values win if present (allows per-project overrides).
        const enriched = {
            companyName:        project.companyName        || profile?.companyName        || '',
            companyDescription: project.companyDescription || profile?.companyDescription || '',
            primaryCategory:    project.primaryCategory    || profile?.primaryCategory    || '',
            customerType:       project.customerType       || profile?.customerType       || '',
            targetAudience:     project.targetAudience     || '',  // project-only field
        };

        console.log(
            `${VERSION} [${requestId}] Enriched fields` +
            ` | companyName: "${enriched.companyName}"` +
            ` | primaryCategory: "${enriched.primaryCategory}"` +
            ` | customerType: "${enriched.customerType}"` +
            ` | targetAudience: "${enriched.targetAudience}"`
        );

        // ── 6. Pre-dispatch field validation on merged values ─────────────────
        // Runs AFTER enrichment so it validates final resolved values.
        // Field-level routing tells the user exactly which settings panel to open.
        //
        // PROFILE fields (companyName, companyDescription, primaryCategory, customerType):
        //   → User must update Profile Settings (Company or Category modal)
        // PROJECT field (targetAudience):
        //   → User must update the project via Edit Project modal

        // Profile-owned fields
        const PROFILE_FIELDS  = ['companyName', 'companyDescription', 'primaryCategory', 'customerType'];
        // Project-owned fields
        const PROJECT_FIELDS  = ['targetAudience'];

        const missingProfile  = PROFILE_FIELDS.filter((f) => !enriched[f]);
        const missingProject  = PROJECT_FIELDS.filter((f) => !enriched[f]);
        const missingFields   = [...missingProfile, ...missingProject];

        if (missingFields.length > 0) {
            const parts = [];
            if (missingProfile.length > 0) {
                parts.push(`Profile Settings missing: ${missingProfile.join(', ')}`);
            }
            if (missingProject.length > 0) {
                parts.push(`Project missing: ${missingProject.join(', ')} — please edit your project`);
            }

            const userMessage = parts.join('. ') + '.';
            console.warn(`${VERSION} [${requestId}] Pre-dispatch validation failed. ${userMessage}`);

            return {
                ok: false, status: 400,
                error: {
                    type:            'INCOMPLETE_DATA',
                    message:         userMessage,
                    missingProfile:  missingProfile,
                    missingProject:  missingProject,
                },
            };
        }

        console.log(`${VERSION} [${requestId}] Pre-dispatch validation passed — all required fields resolved`);

        // ── 7. Stamp project ─────────────────────────────────────────────────
        const generationStartedAt = new Date().toISOString();
        try {
            await wixData.update(
                COLLECTION_PROJECTS,
                {
                    ...project,
                    storyboardStatus:      STATUS_GENERATING,
                    storyboardFrameCount:  0,
                    storyboardStartedAt:   generationStartedAt,
                    storyboardCompletedAt: null,
                },
                DB_OPTIONS
            );
            console.log(`${VERSION} [${requestId}] Project stamped — storyboardStatus: ${STATUS_GENERATING}`);
        } catch (err) {
            console.error(`${VERSION} [${requestId}] Status stamp failed: ${err.message}`);
            return { ok: false, status: 500, error: { type: 'DATABASE_ERROR', message: 'Failed to update project status.' } };
        }

        // ── 8. Assemble n8n payload ───────────────────────────────────────────
        // Profile-sourced fields come from `enriched` — validated above.
        // Project-sourced fields (title, goal, offer, misconception) come
        // directly from the project record with '' fallback.
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
            title:              project.title         ?? '',
            goal:               project.goal          ?? '',
            offer:              project.offer         ?? '',
            misconception:      project.misconception ?? '',
        };

        // ── 9. Serialise once — sign and transmit the same bytes ─────────────
        // JSON.stringify() is called exactly once. rawBody is passed to both
        // buildHmacSignature() and postWithRetry() — byte identity is guaranteed.
        const rawBody = JSON.stringify(n8nPayload);
        const hmacSig = buildHmacSignature(rawBody, callbackSecret);

        console.log(`${VERSION} [${requestId}] Payload assembled — HMAC signed — dispatching to n8n`);

        // ── 10. Fire-and-forget webhook dispatch ──────────────────────────────
        const webhookResult = await postWithRetry(webhookUrl, rawBody, hmacSig, requestId);

        if (!webhookResult.ok) {
            console.error(`${VERSION} [${requestId}] All webhook attempts failed: ${webhookResult.error?.message}`);
            await rollbackStatus(project, requestId);
            return {
                ok: false, status: 502,
                error: { type: 'WEBHOOK_ERROR', message: 'Storyboard generation pipeline is unavailable. Please try again.' },
            };
        }

        console.log(`${VERSION} [${requestId}] generateStoryboard() completed — fire-and-forget dispatched`);

        return {
            ok: true, status: 200,
            data: {
                projectId,
                storyboardStatus:    STATUS_GENERATING,
                generationStartedAt,
                submissionId:        requestId,
            },
        };

    } catch (err) {
        console.error(`${VERSION} [${requestId}] generateStoryboard() unhandled exception:`, err);
        return { ok: false, status: 500, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── RECEIVE FRAMES ───────────────────────────────────────────────────────────

/**
 * n8n per-frame callback endpoint. Public-facing but HMAC-gated.
 * Validates signature, enforces ownership, implements idempotent writes.
 * On frameIndex === 14 (final frame): stamps project storyboardStatus: 'complete'.
 *
 * Unchanged from v2.2.0.
 *
 * @param {object} framePayload
 * @returns {{ ok: boolean, status: number, data?: object, error?: object }}
 */
export const receiveFrames = webMethod(Permissions.Anyone, async (framePayload) => {
    const requestId = `rf_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`${VERSION} [${requestId}] receiveFrames() invoked`);

    try {
        // ── 1. Payload presence ──────────────────────────────────────────────
        if (!framePayload || typeof framePayload !== 'object') {
            console.warn(`${VERSION} [${requestId}] Empty or non-object payload received`);
            return { ok: false, status: 400, error: { type: 'VALIDATION_ERROR', message: 'Request payload is missing or malformed.' } };
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

        // ── 2. Required field validation ─────────────────────────────────────
        const missingFields = [];
        if (!hmacSignature) missingFields.push('hmacSignature');
        if (!projectId)     missingFields.push('projectId');
        if (!owner)         missingFields.push('owner');
        if (frameIndex === undefined || frameIndex === null) missingFields.push('frameIndex');
        if (!imageUrl)      missingFields.push('imageUrl');
        if (!promptText)    missingFields.push('promptText');

        if (missingFields.length > 0) {
            console.warn(`${VERSION} [${requestId}] Missing fields: ${missingFields.join(', ')}`);
            return { ok: false, status: 400, error: { type: 'VALIDATION_ERROR', message: `Missing required fields: ${missingFields.join(', ')}` } };
        }

        if (typeof frameIndex !== 'number' || frameIndex < 0 || frameIndex > FINAL_FRAME_INDEX) {
            console.warn(`${VERSION} [${requestId}] Invalid frameIndex: ${frameIndex}`);
            return { ok: false, status: 400, error: { type: 'VALIDATION_ERROR', message: `frameIndex must be a number between 0 and ${FINAL_FRAME_INDEX}.` } };
        }

        // ── 3. HMAC validation ───────────────────────────────────────────────
        const { getSecret } = require('wix-secrets-backend');
        const { createHmac } = require('crypto');

        let secret;
        try {
            secret = await getSecret(SECRET_CALLBACK_KEY);
        } catch (err) {
            console.error(`${VERSION} [${requestId}] Secret retrieval failed: ${err.message}`);
            return { ok: false, status: 500, error: { type: 'CONFIG_ERROR', message: 'Callback validation is temporarily unavailable.' } };
        }

        const bodyForHmac = JSON.stringify({ projectId, owner, frameIndex, imageUrl, promptText, frameData: frameData ?? {}, status });
        const expectedSig = createHmac('sha256', secret).update(bodyForHmac).digest('hex');

        // Naive constant-time compare
        let diff = 0;
        const a = hmacSignature, b = expectedSig;
        if (a.length !== b.length) {
            console.warn(`${VERSION} [${requestId}] HMAC length mismatch — rejecting`);
            return { ok: false, status: 401, error: { type: 'SIGNATURE_INVALID', message: 'Request signature is invalid.' } };
        }
        for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
        if (diff !== 0) {
            console.warn(`${VERSION} [${requestId}] HMAC validation failed — rejecting payload`);
            return { ok: false, status: 401, error: { type: 'SIGNATURE_INVALID', message: 'Request signature is invalid.' } };
        }

        console.log(`${VERSION} [${requestId}] HMAC validated — frameIndex: ${frameIndex}, projectId: ${projectId}`);

        // ── 4. Project ownership enforcement ────────────────────────────────
        const project = await wixData.get(COLLECTION_PROJECTS, projectId, DB_OPTIONS);
        if (!project) {
            console.warn(`${VERSION} [${requestId}] Project not found: ${projectId}`);
            return { ok: false, status: 404, error: { type: 'NOT_FOUND', message: 'Project not found.' } };
        }

        if (project._owner !== owner) {
            console.warn(`${VERSION} [${requestId}] Ownership violation — payload owner: ${owner}, record owner: ${project._owner}`);
            return { ok: false, status: 403, error: { type: 'FORBIDDEN', message: 'Owner mismatch.' } };
        }

        // ── 5. Idempotency check ─────────────────────────────────────────────
        const existing = await wixData.query(COLLECTION_FRAMES)
            .eq('projectId', projectId)
            .eq('frameIndex', frameIndex)
            .find(DB_OPTIONS);

        if (existing.items.length > 0) {
            console.log(`${VERSION} [${requestId}] Duplicate frame — skipping write. frameIndex: ${frameIndex}`);
            return { ok: true, status: 200, data: { frameIndex, projectId, written: false, duplicate: true } };
        }

        // ── 6. Write frame record ────────────────────────────────────────────
        const frameRecord = {
            projectId,
            owner,
            frameIndex,
            imageUrl,
            promptText,
            frameData:  frameData ?? {},
            status,
            receivedAt: new Date().toISOString(),
        };

        try {
            await wixData.insert(COLLECTION_FRAMES, frameRecord, DB_OPTIONS);
            console.log(`${VERSION} [${requestId}] Frame written — frameIndex: ${frameIndex}`);
        } catch (err) {
            console.error(`${VERSION} [${requestId}] Frame write failed: ${err.message}`);
            return { ok: false, status: 500, error: { type: 'DATABASE_ERROR', message: 'Failed to persist frame data.' } };
        }

        // ── 7. Final frame — stamp project complete ──────────────────────────
        if (frameIndex === FINAL_FRAME_INDEX) {
            const completedAt = new Date().toISOString();
            try {
                await wixData.update(
                    COLLECTION_PROJECTS,
                    { ...project, storyboardStatus: STATUS_COMPLETE, completedAt },
                    DB_OPTIONS
                );
                console.log(`${VERSION} [${requestId}] Final frame received — project stamped complete at ${completedAt}`);
            } catch (err) {
                // Non-fatal: frame was written; log and continue
                console.error(`${VERSION} [${requestId}] Project completion stamp failed (non-fatal): ${err.message}`);
            }
        }

        console.log(`${VERSION} [${requestId}] receiveFrames() completed successfully`);
        return { ok: true, status: 200, data: { frameIndex, projectId, written: true, isFinal: frameIndex === FINAL_FRAME_INDEX } };

    } catch (err) {
        console.error(`${VERSION} [${requestId}] receiveFrames() unhandled exception:`, err);
        return { ok: false, status: 500, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── GET STORYBOARD FRAMES ────────────────────────────────────────────────────

/**
 * Polling read endpoint for storyboard frames.
 * Double-scoped: ownership check + query filtered by both projectId AND owner.
 *
 * Unchanged from v2.2.0.
 *
 * @param {string} projectId
 * @returns {{ ok: boolean, status: number, data?: object, error?: object }}
 */
export const getStoryboardFrames = webMethod(Permissions.Anyone, async (projectId) => {
    const requestId = `gsf_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`${VERSION} [${requestId}] getStoryboardFrames() invoked — projectId: ${projectId}`);

    try {
        if (!projectId) {
            console.warn(`${VERSION} [${requestId}] Missing projectId.`);
            return { ok: false, status: 400, error: { type: 'MISSING_ID', message: 'Project ID is required.' } };
        }

        const { memberId } = await getAuthenticatedMember();
        if (!memberId) {
            console.warn(`${VERSION} [${requestId}] Unauthenticated attempt.`);
            return { ok: false, status: 401, error: { type: 'AUTH_REQUIRED', message: 'Authentication required.' } };
        }

        const project = await wixData.get(COLLECTION_PROJECTS, projectId, DB_OPTIONS);
        if (!project) {
            console.warn(`${VERSION} [${requestId}] Project not found: ${projectId}`);
            return { ok: false, status: 404, error: { type: 'NOT_FOUND', message: 'Project not found.' } };
        }

        if (project._owner !== memberId) {
            console.warn(`${VERSION} [${requestId}] Ownership violation — caller: ${memberId}, owner: ${project._owner}`);
            return { ok: false, status: 403, error: { type: 'FORBIDDEN', message: 'You do not have permission to access this project\'s storyboard.' } };
        }

        const queryResult = await wixData
            .query(COLLECTION_FRAMES)
            .eq('projectId', projectId)
            .eq('owner', memberId)        // Second scope — prevents cross-user leakage
            .ascending('frameIndex')
            .limit(TOTAL_FRAMES)
            .find(DB_OPTIONS);

        const safeFrames = queryResult.items.map((frame) => ({
            _id:        frame._id,
            frameIndex: frame.frameIndex,
            imageUrl:   frame.imageUrl,
            promptText: frame.promptText,
            frameData:  frame.frameData ?? {},
            status:     frame.status,
            receivedAt: frame.receivedAt,
        }));

        console.log(`${VERSION} [${requestId}] Frames retrieved — count: ${safeFrames.length}, status: ${project.storyboardStatus}`);

        return {
            ok: true, status: 200,
            data: {
                projectId,
                storyboardStatus: project.storyboardStatus ?? 'idle',
                frameCount:       safeFrames.length,
                frames:           safeFrames,
            },
        };

    } catch (err) {
        console.error(`${VERSION} [${requestId}] getStoryboardFrames() unhandled exception:`, err);
        return { ok: false, status: 500, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── CANCEL STORYBOARD ────────────────────────────────────────────────────────

/**
 * Stamps the project storyboardStatus as 'cancelled' to stop polling on reload.
 * Idempotent — safe to call on already-cancelled/complete/failed projects.
 * Does NOT cancel the n8n pipeline (MVP scope).
 *
 * Unchanged from v2.2.0.
 *
 * @param {string} projectId
 * @returns {{ ok: boolean, status: number, error?: object }}
 */
export const cancelStoryboard = webMethod(Permissions.Anyone, async (projectId) => {
    const requestId = `cs_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`[ CANCEL STORYBOARD : v1.0.0 ] [${requestId}] cancelStoryboard() invoked — projectId: ${projectId}`);

    try {
        if (!projectId) {
            console.warn(`[ CANCEL STORYBOARD : v1.0.0 ] [${requestId}] Missing projectId.`);
            return { ok: false, status: 400, error: { type: 'MISSING_ID', message: 'Project ID is required.' } };
        }

        const { memberId } = await getAuthenticatedMember();
        if (!memberId) {
            console.warn(`[ CANCEL STORYBOARD : v1.0.0 ] [${requestId}] Unauthenticated attempt.`);
            return { ok: false, status: 401, error: { type: 'AUTH_REQUIRED', message: 'Authentication required.' } };
        }

        const project = await wixData.get(COLLECTION_PROJECTS, projectId, DB_OPTIONS);
        if (!project) {
            console.warn(`[ CANCEL STORYBOARD : v1.0.0 ] [${requestId}] Project not found: ${projectId}`);
            return { ok: false, status: 404, error: { type: 'NOT_FOUND', message: 'Project not found.' } };
        }

        if (project._owner !== memberId) {
            console.warn(`[ CANCEL STORYBOARD : v1.0.0 ] [${requestId}] Ownership mismatch. Member: ${memberId}`);
            return { ok: false, status: 403, error: { type: 'FORBIDDEN', message: 'You do not own this project.' } };
        }

        // Idempotent — only write if currently generating
        if (project.storyboardStatus !== STATUS_GENERATING) {
            console.log(`[ CANCEL STORYBOARD : v1.0.0 ] [${requestId}] No-op — status is already: ${project.storyboardStatus}`);
            return { ok: true, status: 200, data: { projectId, storyboardStatus: project.storyboardStatus, cancelled: false } };
        }

        await wixData.update(
            COLLECTION_PROJECTS,
            { ...project, storyboardStatus: STATUS_CANCELLED, cancelledAt: new Date().toISOString() },
            DB_OPTIONS
        );

        console.log(`[ CANCEL STORYBOARD : v1.0.0 ] [${requestId}] Project stamped cancelled — projectId: ${projectId}`);
        return { ok: true, status: 200, data: { projectId, storyboardStatus: STATUS_CANCELLED, cancelled: true } };

    } catch (err) {
        console.error(`[ CANCEL STORYBOARD : v1.0.0 ] [${requestId}] cancelStoryboard() unhandled exception:`, err);
        return { ok: false, status: 500, error: { type: 'INTERNAL', message: err.message } };
    }
});

// ─── Debug exports ────────────────────────────────────────────────────────────

export async function debugGenerateStoryboard(projectId = 'debug-project-id') {
    console.log(`${VERSION} [DEBUG] Invoking generateStoryboard with projectId: ${projectId}`);
    return { debug: true, projectId, timestamp: new Date().toISOString() };
}

export async function debugReceiveFrames(testProjectId = 'test-project-id') {
    const { createHmac } = require('crypto');
    console.log(`${VERSION} [DEBUG] Testing receiveFrames HMAC — projectId: ${testProjectId}`);
    const bodyForHmac = JSON.stringify({
        projectId:  testProjectId,
        owner:      'test-owner-id',
        frameIndex: 0,
        imageUrl:   'https://example.com/image.jpg',
        promptText: 'A test prompt',
        frameData:  {},
        status:     'complete',
    });
    const secret   = 'DEBUG_ONLY_DO_NOT_USE_IN_PRODUCTION';
    const expected = createHmac('sha256', secret).update(bodyForHmac).digest('hex');
    console.log(`${VERSION} [DEBUG] Expected HMAC: ${expected}`);
    return { debug: true, bodyForHmac, expectedHmac: expected };
}

export async function debugWebhookStatus() {
    console.log(`${VERSION} [DEBUG] debugWebhookStatus called`);
    return { debug: true, version: VERSION, timestamp: new Date().toISOString() };
}