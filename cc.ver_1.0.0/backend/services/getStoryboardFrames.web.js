// [ FILE NAME : getStoryboardFrames.web.js : v1.1.0 ]
// Domain  : Storyboard
// Layer   : Backend — Polling Read Endpoint
// Purpose : Returns all persisted storyboard frames for a project, ordered by
//           frameIndex ascending. Double-scoped by BOTH projectId AND owner to
//           prevent cross-user data leakage. Also returns the project's current
//           storyboardStatus so the frontend can determine completion without a
//           separate projects query.
//
// ─────────────────────────────────────────────────────────────────────────────
// Changelog v1.0.0 → v1.1.0
//
// [FIX-PERM-03] Permissions.Member → Permissions.SiteMember
//
//   ERROR (runtime):
//     Permissions.Member is not a valid value in the wix-web-module
//     Permissions enum. The valid values are:
//       Permissions.Anyone      — no authentication required
//       Permissions.SiteMember  — requires a logged-in site member
//       Permissions.Admin       — requires a site admin role
//
//   IMPACT:
//     With Permissions.Member, the webMethod throws at call time for every
//     user, causing every poll tick in storyboard-poller.js to fail with
//     a terminal error. The poller calls onError() and stops, meaning no
//     storyboard frames are ever delivered to the UI regardless of how many
//     frames the n8n pipeline has written to the database.
//
//   FIX:
//     Changed to Permissions.SiteMember. This is the correct permission level
//     for any endpoint that reads user-owned data — it requires authentication
//     but does not restrict to admins.
//
// [FIX-MEMBER-01] currentMember.getMember() — added fieldsets: ['PUBLIC']
//
//   The getMember() call in v1.0.0 was called with no arguments. Without an
//   explicit fieldset, Wix may return a partial member object that does not
//   reliably include _id across all plan types. Added fieldsets: ['PUBLIC']
//   for consistency with the pattern established in project.web.js (FIX-05)
//   and generateStoryboard.web.js.
//
//   Additionally, the member null-guard was tightened: v1.0.0 accessed
//   member._id directly after the try/catch without checking whether member
//   itself was null (getMember() can return null for unauthenticated callers
//   even when it does not throw). A null check is now applied before reading
//   _id, and a proper 401 is returned rather than a TypeError crash.
// ─────────────────────────────────────────────────────────────────────────────

import { Permissions, webMethod } from 'wix-web-module';
import wixData                    from 'wix-data';
import { currentMember }          from 'wix-members-backend';

// ─── Constants ────────────────────────────────────────────────────────────────

const VERSION             = '[ GET STORYBOARD FRAMES : v1.1.0 ]';
const FRAMES_COLLECTION   = 'storyboard_frames';
const PROJECTS_COLLECTION = 'projects';
const MAX_FRAMES          = 15;
const DB_OPTIONS          = { suppressAuth: true };

// ─── Structured response helpers ──────────────────────────────────────────────

const ok   = (data)                  => ({ ok: true,  status: 200, data });
const fail = (status, type, message) => ({ ok: false, status, error: { type, message } });

// ─── getStoryboardFrames ──────────────────────────────────────────────────────

export const getStoryboardFrames = webMethod(
  Permissions.SiteMember,   // [FIX-PERM-03] was: Permissions.Member (invalid enum value)
  async (projectId) => {
    const requestId = `gsf_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    console.log(`${VERSION} [${requestId}] getStoryboardFrames() invoked — projectId: ${projectId}`);

    // ── 1. Input validation ──────────────────────────────────────────────────
    if (!projectId || typeof projectId !== 'string' || !projectId.trim()) {
      console.warn(`${VERSION} [${requestId}] Missing or invalid projectId`);
      return fail(400, 'VALIDATION_ERROR', 'projectId is required.');
    }

    // ── 2. Caller identity ───────────────────────────────────────────────────
    // [FIX-MEMBER-01] Added fieldsets: ['PUBLIC'] for reliable _id resolution.
    // Added explicit null check — getMember() can return null without throwing
    // when the session is unauthenticated, which would cause a TypeError on
    // member._id in v1.0.0.
    let member;
    try {
      member = await currentMember.getMember({ fieldsets: ['PUBLIC'] });
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Member resolution failed: ${err.message}`);
      return fail(401, 'AUTH_ERROR', 'Unable to resolve authenticated member.');
    }

    if (!member || !member._id) {
      console.warn(`${VERSION} [${requestId}] Unauthenticated call — member is null`);
      return fail(401, 'AUTH_REQUIRED', 'Authentication required.');
    }

    const callerId = member._id;

    // ── 3. Project ownership check ───────────────────────────────────────────
    let project;
    try {
      project = await wixData.get(PROJECTS_COLLECTION, projectId, DB_OPTIONS);
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
      return fail(403, 'FORBIDDEN', 'You do not have permission to access this project\'s storyboard.');
    }

    // ── 4. Double-scoped frame query (projectId AND owner) ───────────────────
    let frames;
    try {
      const queryResult = await wixData
        .query(FRAMES_COLLECTION)
        .eq('projectId', projectId)
        .eq('owner', callerId)        // Second scope — prevents cross-user leakage
        .ascending('frameIndex')      // Ordered for consistent UI rendering
        .limit(MAX_FRAMES)
        .find(DB_OPTIONS);

      frames = queryResult.items;
    } catch (err) {
      console.error(`${VERSION} [${requestId}] Frame query failed: ${err.message}`);
      return fail(500, 'DATABASE_ERROR', 'Failed to retrieve storyboard frames.');
    }

    console.log(`${VERSION} [${requestId}] Frames retrieved — count: ${frames.length}, status: ${project.storyboardStatus}`);

    // ── 5. Shape response — expose only safe fields ──────────────────────────
    const safeFrames = frames.map(frame => ({
      _id:        frame._id,
      frameIndex: frame.frameIndex,
      imageUrl:   frame.imageUrl,
      promptText: frame.promptText,
      frameData:  frame.frameData  ?? {},
      status:     frame.status,
      receivedAt: frame.receivedAt,
    }));

    return ok({
      projectId,
      storyboardStatus: project.storyboardStatus ?? 'idle',
      frameCount:       safeFrames.length,
      frames:           safeFrames,
    });
  }
);

// ─── Debug export ─────────────────────────────────────────────────────────────

export async function debugGetStoryboardFrames(projectId = 'test-project-id') {
  console.log(`${VERSION} [DEBUG] Simulating getStoryboardFrames for projectId: ${projectId}`);
  return {
    debug:               true,
    projectId,
    simulatedStatus:     'generating',
    simulatedFrameCount: 7,
    timestamp:           new Date().toISOString(),
  };
}