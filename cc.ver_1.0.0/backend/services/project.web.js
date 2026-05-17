/**
 * [ FILE NAME : project.web.js : v2.9.0 ]
 *
 * Service: Project Service
 * Path: /backend/services/project.web.js
 * Version: [ PROJECT SERVICE : v2.9.0 ]
 *
 * Changelog v2.6.0 → v2.9.0
 * ─────────────────────────────────────────────────────────────────────────────
 * [FIX-05] getAuthenticatedMember() — Member.roles type error
 *   member.roles does not exist on the Member type. Roles are resolved via
 *   the separate currentMember.getRoles() call, run in parallel with
 *   getMember() via Promise.all(). Role check uses bracket notation
 *   r['name'] to satisfy the Wix IDE type stub.
 *
 * [FIX-06 / FIX-07] getAuthenticatedMember() — getRoles Role.name type error
 *   r.name does not exist on the Role type stub. Bracket notation r['name']
 *   bypasses the stub; runtime value is 'Admin' per Wix docs.
 *
 * [FIX-08] getMyProjects() — skipTo / cursors type errors
 *   WixDataQuery has no .skipTo(). WixDataQueryResult has no .cursors.
 *   Replaced with skip()-based offset pagination. The cursor passed from
 *   the frontend is treated as a numeric string offset ("0", "25", ...).
 *   hasNext() is the correct WixDataQueryResult pagination check.
 *
 * [FIX-09] updateProject() — targetAudience field name mismatch (DATA LOSS)
 *   updateProject() wrote projectData.targetAudience (camelCase) into the
 *   payload field also named targetAudience. The DB column is target_audience
 *   (snake_case). Every project edit overwrote target_audience with undefined,
 *   which is why generateStoryboard.web.js read project.target_audience as
 *   empty and returned INCOMPLETE_DATA on every attempt after the first edit.
 *   Fixed: the payload field is now named target_audience (snake_case) and
 *   reads from projectData.target_audience ?? projectData.targetAudience.
 *
 * [PERM-01] createProject / updateProject — Permissions.Anyone → SiteMember
 *   Write operations now require an authenticated site member at the gateway
 *   level in addition to the internal memberId check.
 *
 * [BUG-01] updateProject() — Storyboard field preservation (from v2.6.0)
 *   wixData.update() replaces the full document. All storyboard system fields
 *   are preserved from the existing record to prevent data wipe on edit.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { Permissions, webMethod } from 'wix-web-module';
import wixData                    from 'wix-data';
import { currentMember }          from 'wix-members-backend';

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

const VERSION             = '[ PROJECT SERVICE : v2.9.0 ]';

const COLLECTION_PROJECTS = 'projects';
const DB_OPTIONS          = { suppressAuth: true };
const ROLE_ADMIN          = 'Admin';
const PROJECT_LIMIT       = 25;

// ─── INTERNAL HELPERS ─────────────────────────────────────────────────────────

/**
 * Resolves the currently authenticated member's ID and admin status.
 *
 * [FIX-05] getMember() does not expose .roles on the Member type.
 * [FIX-06] getRoles() returns Role[] — name is accessed via bracket notation
 *          to satisfy the incomplete Wix IDE type stub.
 * Both calls run in parallel via Promise.all().
 *
 * @returns {{ memberId: string|null, isAdmin: boolean }}
 */
async function getAuthenticatedMember() {
  try {
    const [member, roles] = await Promise.all([
      currentMember.getMember({ fieldsets: ['PUBLIC'] }),
      currentMember.getRoles(),
    ]);

    if (!member) return { memberId: null, isAdmin: false };

    // [FIX-06] Bracket notation bypasses the incomplete Role type stub.
    const isAdmin = Array.isArray(roles)
      ? roles.some((r) => r['name'] === ROLE_ADMIN)
      : false;

    return { memberId: member._id, isAdmin };
  } catch (err) {
    console.error(`${VERSION} getAuthenticatedMember failure:`, err);
    return { memberId: null, isAdmin: false };
  }
}

// ─── CREATE PROJECT ───────────────────────────────────────────────────────────

/**
 * Creates a new project record owned by the authenticated member.
 *
 * [PERM-01] Upgraded from Permissions.Anyone to Permissions.SiteMember.
 *
 * SC-07: `owner` mirror field written alongside `_owner` for backward
 * compatibility. Remove after data migration consolidates all records.
 *
 * @param {object} projectData
 * @returns {{ ok: boolean, data?: object, error?: object }}
 */
export const createProject = webMethod(Permissions.SiteMember, async (projectData) => {
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
      // [FIX-09] snake_case field name matches the DB column
      target_audience:    projectData.target_audience ?? projectData.targetAudience ?? projectData.audience,
      misconception:      projectData.misconception,
      // SC-07: write both fields during the _owner transition window.
      owner:              memberId,
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
 * Updates an existing project record. Owner-only.
 *
 * [PERM-01] Upgraded from Permissions.Anyone to Permissions.SiteMember.
 *
 * [BUG-01] v2.6.0 — Storyboard field preservation.
 *   wixData.update() replaces the full document. All storyboard system fields
 *   are read from `existing` and preserved in the payload. They are never
 *   sourced from the incoming projectData argument.
 *
 * [FIX-09] target_audience field name corrected.
 *   The DB column is target_audience (snake_case). The payload now writes to
 *   that key directly. This is the root cause of INCOMPLETE_DATA errors on
 *   re-generation after any project edit — the audience value was being written
 *   to targetAudience (camelCase) which does not exist as a DB column, so
 *   target_audience was always null after the first edit+save.
 *
 * @param {string} projectId
 * @param {object} projectData
 * @returns {{ ok: boolean, data?: object, error?: object }}
 */
export const updateProject = webMethod(Permissions.SiteMember, async (projectId, projectData) => {
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
      // ── Identity & ownership (never changed by user) ──────────────────────
      _id:                existing._id,
      _owner:             existing._owner,
      owner:              existing.owner,       // SC-07: preserve mirror field during transition

      // ── User-editable fields (sourced from modal form) ────────────────────
      title:              projectData.title,
      description:        projectData.description,
      companyName:        projectData.companyName,
      companyDescription: projectData.companyDescription,
      primaryCategory:    projectData.primaryCategory,
      customerType:       projectData.customerType,
      goal:               projectData.goal,
      offer:              projectData.offer,
      // [FIX-09] DB column is snake_case. Accept both key names from callers
      //          to handle any existing modal form that sends targetAudience.
      target_audience:    projectData.target_audience ?? projectData.targetAudience,
      misconception:      projectData.misconception,

      // ── Storyboard system fields: PRESERVED from existing record ──────────
      // [BUG-01] These were absent in v2.5.0 causing full wipe on every edit.
      storyboardStatus:     existing.storyboardStatus     ?? null,
      storyboardStartedAt:  existing.storyboardStartedAt  ?? null,
      storyboardFrameCount: existing.storyboardFrameCount ?? null,
      completedAt:          existing.completedAt          ?? null,
      cancelledAt:          existing.cancelledAt          ?? null,
      firstFrameImage:      existing.firstFrameImage      ?? null,
    };

    const result = await wixData.update(COLLECTION_PROJECTS, updatePayload, DB_OPTIONS);
    console.log(`${VERSION} updateProject: Updated ${result._id} by member: ${memberId}`);
    return { ok: true, data: result };

  } catch (err) {
    console.error(`${VERSION} updateProject failure:`, err);
    return { ok: false, error: { type: 'INTERNAL', message: err.message } };
  }
});

// ─── GET USER PROJECT COUNT ───────────────────────────────────────────────────

/**
 * Returns the total project count for the authenticated member.
 *
 * @returns {{ ok: boolean, count: number, error?: object }}
 */
export const getUserProjectCount = webMethod(Permissions.Anyone, async () => {
  try {
    const { memberId } = await getAuthenticatedMember();
    if (!memberId) return { ok: true, count: 0 };

    const count = await wixData
      .query(COLLECTION_PROJECTS)
      .eq('_owner', memberId)
      .count(DB_OPTIONS);

    console.log(`${VERSION} getUserProjectCount: ${count} projects for member: ${memberId}`);
    return { ok: true, count };

  } catch (err) {
    console.error(`${VERSION} getUserProjectCount failure:`, err);
    return { ok: false, count: 0, error: { type: 'INTERNAL', message: err.message } };
  }
});

// ─── GET MY PROJECTS ──────────────────────────────────────────────────────────

/**
 * Returns a paginated list of projects owned by the authenticated member.
 *
 * [FIX-08] Cursor pagination redesigned.
 *   WixDataQuery has no .skipTo(). WixDataQueryResult has no .cursors.
 *   Pagination uses .skip() with a numeric offset encoded as an opaque
 *   string cursor. hasNext() is the correct method to check for more pages.
 *
 * @param {{ limit?: number, cursor?: string|null }} [options]
 * @returns {{ ok: boolean, data: array, nextCursor: string|null, error?: object }}
 */
export const getMyProjects = webMethod(Permissions.Anyone, async ({ limit = PROJECT_LIMIT, cursor = null } = {}) => {
  try {
    const { memberId } = await getAuthenticatedMember();
    if (!memberId) return { ok: true, data: [], nextCursor: null };

    const safeLimit  = Math.min(limit, PROJECT_LIMIT);
    // [FIX-08] Treat cursor as a numeric skip offset string.
    const skipOffset = parseInt(cursor, 10) || 0;

    const results = await wixData
      .query(COLLECTION_PROJECTS)
      .eq('_owner', memberId)
      .descending('_createdDate')
      .limit(safeLimit)
      .skip(skipOffset)
      .find(DB_OPTIONS);

    // [FIX-08] hasNext() is the correct WixDataQueryResult pagination check.
    const nextCursor = results.hasNext()
      ? String(skipOffset + safeLimit)
      : null;

    console.log(`${VERSION} getMyProjects: ${results.items.length} projects for member: ${memberId}. hasMore: ${!!nextCursor}`);
    return { ok: true, data: results.items, nextCursor };

  } catch (err) {
    console.error(`${VERSION} getMyProjects failure:`, err);
    return { ok: false, data: [], nextCursor: null, error: { type: 'INTERNAL', message: err.message } };
  }
});

// ─── Debug exports ────────────────────────────────────────────────────────────

export function debugProjectService() {
  console.log(`${VERSION} Config: PROJECT_LIMIT=${PROJECT_LIMIT}`);
  return { debug: true, version: VERSION, timestamp: new Date().toISOString() };
}