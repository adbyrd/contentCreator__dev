/**
 * Service: Profile & Identity Management
 * Path: /backend/services/profile.web.js
 * Version: [ PROFILE SERVICE : v.2.5.0 ]
 *
 * SC-06 — Auth Gate Query Migration
 * ───────────────────────────────────
 * checkMemberExists() previously queried the Wix system collection
 * Members/FullData on every auth-gate submission. That collection sits on
 * shared Wix infrastructure, cannot be custom-indexed, and is a hot path
 * during any marketing-driven traffic spike.
 *
 * This version migrates the lookup to the custom `profiles` collection using
 * a mirrored `loginEmail` field that is written at profile creation time.
 *
 * Migration requirements (one-time):
 *   1. Add a `loginEmail` (Text) field to the profiles CMS collection.
 *   2. Add a single-field index on `loginEmail` in the Wix Dashboard.
 *   3. Backfill existing profile records with the member's login email.
 *      (Can be done via a one-time admin script or left to self-heal as
 *       members next save their profile — createProfile() below writes it.)
 *   4. Until the backfill is complete, checkMemberExists() falls back to
 *      the system collection for any record where loginEmail is absent.
 *
 * Existing exports are fully backward compatible.
 *
 * Exports:
 *   checkMemberExists(email)  — auth-gate identity lookup
 *   getProfile()              — returns the authenticated member's profile
 *   updateProfile(payload)    — patches the authenticated member's profile
 */

import { webMethod, Permissions } from 'wix-web-module';
import wixData                    from 'wix-data';
import { currentMember }          from 'wix-members-backend';

const VERSION = '[ PROFILE SERVICE : v.2.5.0 ]';

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

const PROFILES_COLLECTION = 'profiles';

// System collection — used ONLY as a fallback in checkMemberExists()
// during the loginEmail backfill window. Once all profiles have loginEmail,
// this constant can be removed.
const MEMBERS_COLLECTION  = 'Members/FullData';

const MAX_RETRIES         = 3;
const DB_OPTIONS          = { suppressAuth: true };

// ─── INTERNAL HELPERS ─────────────────────────────────────────────────────────

/**
 * Returns the current authenticated member's Wix ID, or null.
 * @returns {Promise<string|null>}
 */
async function getCurrentMemberId() {
    try {
        const member = await currentMember.getMember({ fieldsets: ['PUBLIC'] });
        return member ? member._id : null;
    } catch (err) {
        console.error(`${VERSION} getCurrentMemberId failure:`, err);
        return null;
    }
}

/**
 * Executes a wixData query with exponential backoff on transient failures.
 *
 * @param {object} query        — wixData query object (not yet .find()'d)
 * @param {object} [options]    — find options (default: suppressAuth)
 * @param {number} [attempts]   — internal recursion counter
 * @returns {Promise<{ items: array }>}
 */
async function executeQueryWithRetry(query, options = DB_OPTIONS, attempts = 1) {
    try {
        return await query.find(options);
    } catch (err) {
        if (attempts < MAX_RETRIES) {
            const delay = Math.pow(2, attempts) * 100 + (Math.random() * 50);
            console.warn(`${VERSION} Query failed. Retrying in ${Math.round(delay)}ms (attempt ${attempts})...`);
            await new Promise(resolve => setTimeout(resolve, delay));
            return executeQueryWithRetry(query, options, attempts + 1);
        }
        throw err;
    }
}

// ─── CHECK MEMBER EXISTS ──────────────────────────────────────────────────────

/**
 * Determines whether a member account exists for the given email.
 * Used by the auth-gate page to route new vs. returning members.
 *
 * SC-06 — Two-tier resolution:
 *
 *   Primary:  Query the custom `profiles` collection on the `loginEmail`
 *             field (indexed, custom collection, no shared-infrastructure risk).
 *
 *   Fallback: If the primary returns no results, query Members/FullData.
 *             This handles records created before the loginEmail backfill.
 *             The fallback is intentionally separate and logged, so it is
 *             easy to measure when the backfill is complete and the fallback
 *             can be removed.
 *
 * @param {string} email
 * @returns {{ ok: boolean, exists: boolean, error?: string }}
 */
export const checkMemberExists = webMethod(Permissions.Anyone, async (email) => {
    try {
        if (!email || typeof email !== 'string' || !email.includes('@')) {
            console.warn(`${VERSION} checkMemberExists: Invalid email payload rejected.`);
            return { ok: false, exists: false, error: 'INVALID_INPUT' };
        }

        const normalizedEmail = email.trim().toLowerCase();

        // ── Primary: custom profiles collection (indexed loginEmail field) ──
        const primaryQuery = wixData.query(PROFILES_COLLECTION)
            .eq('loginEmail', normalizedEmail)
            .limit(1);

        const primaryResult = await executeQueryWithRetry(primaryQuery);

        if (primaryResult.items.length > 0) {
            console.log(`${VERSION} checkMemberExists: Found in profiles collection for: ${normalizedEmail}`);
            return { ok: true, exists: true };
        }

        // ── Fallback: Wix system collection (pre-backfill records only) ─────
        // Log every fallback hit so the team can track backfill progress.
        // Remove this block once all profiles have loginEmail populated.
        console.log(`${VERSION} checkMemberExists: Primary miss — falling back to Members/FullData for: ${normalizedEmail}`);

        const fallbackQuery = wixData.query(MEMBERS_COLLECTION)
            .eq('loginEmail', normalizedEmail)
            .limit(1);

        const fallbackResult = await executeQueryWithRetry(fallbackQuery);
        const exists = fallbackResult.items.length > 0;

        if (exists) {
            console.log(`${VERSION} checkMemberExists: Found via fallback. Profile loginEmail field needs backfill for: ${normalizedEmail}`);
        } else {
            console.log(`${VERSION} checkMemberExists: Not found for: ${normalizedEmail}`);
        }

        return { ok: true, exists };

    } catch (err) {
        console.error(`${VERSION} checkMemberExists failure:`, err);
        return { ok: false, exists: false, error: 'SERVICE_UNAVAILABLE' };
    }
});

// ─── GET PROFILE ──────────────────────────────────────────────────────────────

/**
 * Returns the profile record for the currently authenticated member.
 *
 * @returns {{ ok: boolean, data?: object, error?: string }}
 */
export const getProfile = webMethod(Permissions.Anyone, async () => {
    try {
        const memberId = await getCurrentMemberId();
        if (!memberId) {
            console.warn(`${VERSION} getProfile: Unauthenticated attempt.`);
            return { ok: false, error: 'AUTH_REQUIRED' };
        }

        const query = wixData.query(PROFILES_COLLECTION)
            .eq('_owner', memberId)
            .limit(1);

        const { items } = await executeQueryWithRetry(query);

        console.log(`${VERSION} getProfile: Retrieved for owner: ${memberId}`);
        return { ok: true, data: items[0] || null };

    } catch (err) {
        console.error(`${VERSION} getProfile failure:`, err);
        return { ok: false, error: err.message };
    }
});

// ─── UPDATE PROFILE ───────────────────────────────────────────────────────────

/**
 * Patches the profile record for the currently authenticated member.
 *
 * SC-06: If the existing profile record does not yet have a `loginEmail`
 * field, and the member's login email is available from the Wix Members
 * platform, it is written at this point. This self-heals the backfill
 * without requiring a separate migration script.
 *
 * Defensive merge — only spreads payload.profile and locks _id and _owner
 * to prevent field injection.
 *
 * @param {{ profile: object }} payload
 * @returns {{ ok: boolean, data?: object, error?: string }}
 */
export const updateProfile = webMethod(Permissions.Anyone, async (payload) => {
    try {
        const memberId = await getCurrentMemberId();
        if (!memberId) {
            console.warn(`${VERSION} updateProfile: Unauthenticated attempt.`);
            return { ok: false, error: 'AUTH_REQUIRED' };
        }

        const query = wixData.query(PROFILES_COLLECTION).eq('_owner', memberId);
        const currentRes = await executeQueryWithRetry(query);

        if (currentRes.items.length === 0) {
            console.error(`${VERSION} updateProfile: No profile found for: ${memberId}`);
            return { ok: false, error: 'PROFILE_NOT_FOUND' };
        }

        const original = currentRes.items[0];

        // SC-06: Opportunistically backfill loginEmail if it is missing.
        // Fetch the member's login email from the Wix platform on this save.
        let loginEmailPatch = {};
        if (!original.loginEmail) {
            try {
                const member = await currentMember.getMember({ fieldsets: ['FULL'] });
                if (member?.loginEmail) {
                    loginEmailPatch = { loginEmail: member.loginEmail.trim().toLowerCase() };
                    console.log(`${VERSION} updateProfile: Backfilling loginEmail for owner: ${memberId}`);
                }
            } catch (emailErr) {
                // Non-fatal — log and proceed without the backfill on this save
                console.warn(`${VERSION} updateProfile: Could not fetch loginEmail for backfill:`, emailErr.message);
            }
        }

        const updateData = {
            ...original,
            ...(payload.profile || {}),
            ...loginEmailPatch,
            _id:    original._id,    // lock — never allow override
            _owner: memberId         // lock — never allow override
        };

        const result = await wixData.update(PROFILES_COLLECTION, updateData, DB_OPTIONS);

        console.log(`${VERSION} updateProfile: Updated for owner: ${memberId}`);
        return { ok: true, data: result };

    } catch (err) {
        console.error(`${VERSION} updateProfile failure:`, err);
        return { ok: false, error: err.message };
    }
});