/**
 * [ FILE NAME : project.web.js : v2.5.0 ]
 *
 * Service: Project Service
 * Path: /backend/services/project.web.js
 * Version: [ PROJECT SERVICE : v2.5.0 ]
 *
 * Domain: Project CRUD — create, read, update, access verification.
 *
 * Change log:
 *   v2.5.0  — Storyboard domain excised entirely. generateStoryboard(),
 *             receiveFrames(), getStoryboardFrames(), and cancelStoryboard()
 *             have been removed from this file. They now live exclusively in
 *             their dedicated service files under /backend/storyboard/:
 *               generateStoryboard.web.js  (generateStoryboard, cancelStoryboard)
 *               receiveFrames.web.js       (receiveFrames)
 *               getStoryboardFrames.web.js (getStoryboardFrames)
 *             Dead constants (COLLECTION_FRAMES, SECRET_N8N_WEBHOOK,
 *             SECRET_CALLBACK_KEY, TOTAL_FRAMES, FINAL_FRAME_INDEX,
 *             WEBHOOK_TIMEOUT_MS, RETRYABLE_STATUSES, STATUS_* variants,
 *             STORYBOARD_REQUIRED_FIELDS, buildHmacSignature, postWithRetry,
 *             rollbackStatus) have been removed.
 *   v2.4.1  — Profile enrichment in generateStoryboard (now removed).
 *   v2.4.0  — postWithRetry AbortController + RETRYABLE_STATUSES (now removed).
 *   v2.3.0  — Pre-dispatch validation on merged values (now removed).
 *
 * Exports (public contract — unchanged):
 *   createProject(projectData)               — insert a new project
 *   verifyProjectAccess(projectId)           — auth gate for project detail page
 *   updateProject(projectId, projectData)    — patch an existing project
 *   getUserProjectCount()                    — member's total project count
 *   getMyProjects({ limit?, cursor? })       — paginated project list
 *
 * Frontend imports from this file:
 *   import { verifyProjectAccess, cancelStoryboard } from 'backend/services/project.web';
 *   → cancelStoryboard is NO LONGER exported here. Update the import in
 *     project-detail.page.js to:
 *     import { cancelStoryboard } from 'backend/storyboard/generateStoryboard.web';
 */

import { Permissions, webMethod } from 'wix-web-module';
import wixData                    from 'wix-data';
import { currentMember }          from 'wix-members-backend';

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

const VERSION             = '[ PROJECT SERVICE : v2.5.0 ]';

const COLLECTION_PROJECTS = 'projects';
const COLLECTION_PROFILES = 'profiles';   // read-only reference — profile writes stay in profile.web.js
const DB_OPTIONS          = { suppressAuth: true };
const ROLE_ADMIN          = 'Admin';
const PROJECT_LIMIT       = 25;

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
      // SC-07: write both fields during the _owner transition window.
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
      owner:              existing.owner,  // SC-07: preserve mirror field during transition
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

// ─── GET USER PROJECT COUNT ───────────────────────────────────────────────────

/**
 * Returns the total project count for the authenticated member.
 * SC-07: queries on _owner (Wix-native indexed field), not the mirror field.
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

    let query = wixData
      .query(COLLECTION_PROJECTS)
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

// ─── Debug exports ────────────────────────────────────────────────────────────

export function debugProjectService() {
  console.log(`${VERSION} Config: PROJECT_LIMIT=${PROJECT_LIMIT}`);
  return { debug: true, version: VERSION, timestamp: new Date().toISOString() };
}