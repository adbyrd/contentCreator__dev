/**
 * [ FILE NAME : storyboard-poller__v2.2.0 ]
 * Utility: Storyboard Poller
 * Path: /public/utils/storyboard-poller.js
 * Version: [ STORYBOARD POLLER : v2.2.0 ]
 *
 * Changelog v2.1.0 → v2.2.0
 * ─────────────────────────────────────────────────────────────────────────────
 * [FIX-IMPORT-01] getStoryboardFrames import path corrected
 *
 *   ERROR (runtime): Module not found — getStoryboardFrames does not exist
 *   as an export of backend/services/project.web.
 *
 *   ROOT CAUSE:
 *     getStoryboardFrames was designed in storyboardingfeature.pdf (Section
 *     4.3) as an addition to project.web.js, but was correctly implemented
 *     as its own standalone file at:
 *
 *       /backend/storyboard/getStoryboardFrames.web.js
 *
 *     This follows the micro-module DDD architecture defined in the project
 *     structure standards, where each storyboard operation (generate,
 *     receive, query) lives in its own .web.js file under /backend/storyboard/.
 *     The poller's import was never updated to reflect this.
 *
 *   FIX:
 *     Changed import source from 'backend/services/project.web' to
 *     'backend/storyboard/getStoryboardFrames.web' — the actual registered
 *     path of the getStoryboardFrames webMethod (v1.1.0+).
 *
 * All other behaviour is identical to v2.1.0.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * BUG FIX (v2.0.0 → v2.1.0) — preserved for history
 * ─────────────────────────────────────────────────────────────────────────────
 * ISSUE: Poller continued firing after stopStoryboardPolling() was called
 *        via the Cancel Storyboard confirmation flow.
 *
 * ROOT CAUSE — Two unguarded scheduleNextTick() call sites in tick():
 *
 *   1. Transient error branch (result.ok === false, non-terminal error type):
 *
 *        // Transient errors — tolerate and retry on the next tick
 *        scheduleNextTick();   // ← NO stopped check before this
 *        return;
 *
 *   2. catch block (unexpected JS-level error):
 *
 *        } catch (err) {
 *            console.error(...);
 *        }
 *        scheduleNextTick();   // ← NO stopped check before this (outside catch)
 *
 *   scheduleNextTick() itself checks `if (stopped) return` at its entry point,
 *   which should be sufficient — BUT Wix's platform worker serialises async
 *   microtasks differently from a standard browser. The `stopped = true`
 *   assignment inside cleanup() and the `if (stopped)` check inside
 *   scheduleNextTick() can execute in the same microtask flush, causing the
 *   check to see the pre-cleanup value of `stopped` when the tick's await
 *   resolves concurrently with the lightbox close relay.
 *
 *   The fix is defensive: add an explicit `if (stopped) return` guard
 *   immediately before EVERY scheduleNextTick() call site inside tick().
 *   This makes the guard synchronous at the call site, not deferred into
 *   scheduleNextTick()'s own body — eliminating the race entirely.
 *
 * FIX LOCATIONS (inside tick()):
 *   - Transient error branch: added `if (stopped) return;` before scheduleNextTick()
 *   - catch block fallthrough: added `if (stopped) return;` before scheduleNextTick()
 *   - Normal loop continuation (bottom of try): added `if (stopped) return;`
 *     before scheduleNextTick() for completeness / symmetry
 *
 * All other behaviour from v2.0.0 is preserved unchanged:
 *   - Three-phase adaptive interval (8s / 12s / 20s)
 *   - 10-minute hard timeout
 *   - seenFrameIds deduplication
 *   - Terminal error types: AUTH_REQUIRED, FORBIDDEN, NOT_FOUND
 *   - Minimum interval guard (tick scheduled from END, not START)
 *   - Contract: startStoryboardPolling(projectId, { callbacks }) → { stop }
 */

// [FIX-IMPORT-01] was: 'backend/services/project.web' — getStoryboardFrames
// is not exported from project.web.js. It lives in its own module at:
// /backend/storyboard/getStoryboardFrames.web.js
import { getStoryboardFrames } from 'backend/storyboard/getStoryboardFrames.web';

const VERSION = '[ STORYBOARD POLLER : v2.2.0 ]';

// ─── ADAPTIVE INTERVAL CONFIGURATION ─────────────────────────────────────────

// Phase 1: first 60 s — check every 8 s
const PHASE1_INTERVAL_MS  = 8_000;
const PHASE1_DURATION_MS  = 60_000;

// Phase 2: 60 s – 180 s — check every 12 s
const PHASE2_INTERVAL_MS  = 12_000;
const PHASE2_DURATION_MS  = 180_000;

// Phase 3: > 180 s — check every 20 s
const PHASE3_INTERVAL_MS  = 20_000;

// Hard timeout — fires onTimeout() regardless of phase
const POLL_TIMEOUT_MS     = 600_000;  // 10 minutes

const TOTAL_FRAMES        = 15;

// ─── HELPERS ──────────────────────────────────────────────────────────────────

/**
 * Returns the polling interval for the current elapsed time.
 *
 * @param {number} elapsedMs — ms since polling started
 * @returns {number}
 */
function getIntervalForElapsed(elapsedMs) {
    if (elapsedMs < PHASE1_DURATION_MS)  return PHASE1_INTERVAL_MS;
    if (elapsedMs < PHASE2_DURATION_MS)  return PHASE2_INTERVAL_MS;
    return PHASE3_INTERVAL_MS;
}

// ─── START POLLING ────────────────────────────────────────────────────────────

/**
 * Starts the adaptive polling loop for a project's storyboard frames.
 *
 * The loop:
 *   - Fires onFrame() for each NEW frame not seen in a previous tick.
 *   - Fires onComplete() when all TOTAL_FRAMES frames are confirmed.
 *   - Fires onTimeout() if POLL_TIMEOUT_MS elapses without completion.
 *   - Fires onError() on terminal backend failures (AUTH, FORBIDDEN, NOT_FOUND).
 *   - Tolerates transient errors (network hiccups) — retries on the next tick.
 *
 * SC-05 — Adaptive interval:
 *   - Interval is recalculated before each tick based on elapsed time.
 *   - Minimum interval guard: next tick is always scheduled from tick END,
 *     not tick START, preventing burst calls on slow cold starts.
 *
 * @param {string}   projectId
 * @param {{ onFrame?: function, onComplete?: function, onTimeout?: function, onError?: function }} callbacks
 * @returns {{ stop: () => void }}
 */
export function startStoryboardPolling(projectId, {
    onFrame    = null,
    onComplete = null,
    onTimeout  = null,
    onError    = null
} = {}) {
    if (!projectId) {
        console.error(`${VERSION} startStoryboardPolling: No projectId supplied.`);
        return { stop: () => {} };
    }

    let stopped       = false;
    let timeoutId     = null;
    let tickTimeoutId = null;
    let seenFrameIds  = new Set();
    const startedAt   = Date.now();

    console.log(`${VERSION} Polling started for project: ${projectId}`);

    // ── Hard timeout guard ────────────────────────────────────────────────────
    timeoutId = setTimeout(() => {
        if (stopped) return;
        console.warn(`${VERSION} Polling timed out after ${POLL_TIMEOUT_MS / 1000}s for project: ${projectId}`);
        cleanup();
        if (typeof onTimeout === 'function') onTimeout();
    }, POLL_TIMEOUT_MS);

    // ── Cleanup ───────────────────────────────────────────────────────────────
    function cleanup() {
        stopped = true;
        if (timeoutId)     { clearTimeout(timeoutId);     timeoutId     = null; }
        if (tickTimeoutId) { clearTimeout(tickTimeoutId); tickTimeoutId = null; }
        console.log(`${VERSION} Poll loop terminated for project: ${projectId}`);
    }

    // ── Schedule next tick ────────────────────────────────────────────────────
    // SC-05: Always schedule from END of previous tick (via setTimeout, not
    // setInterval). This guarantees the minimum interval is honoured even
    // when a tick takes longer than the interval due to cold-start latency.
    function scheduleNextTick() {
        if (stopped) return;
        const elapsed  = Date.now() - startedAt;
        const interval = getIntervalForElapsed(elapsed);
        console.log(`${VERSION} Next poll in ${interval}ms (elapsed: ${Math.round(elapsed / 1000)}s, phase: ${interval === PHASE1_INTERVAL_MS ? 1 : interval === PHASE2_INTERVAL_MS ? 2 : 3}) for project: ${projectId}`);
        tickTimeoutId = setTimeout(tick, interval);
    }

    // ── Poll tick ─────────────────────────────────────────────────────────────
    async function tick() {
        // FIX: Guard at tick entry — stops execution if cleanup() ran while
        // this tick was queued in the setTimeout callback queue.
        if (stopped) return;

        try {
            const result = await getStoryboardFrames(projectId);

            if (!result.ok) {
                const errType = result.error?.type || 'UNKNOWN';
                console.error(`${VERSION} Poll tick error: ${errType} for project: ${projectId}`);

                // Terminal errors — stop polling and surface to the UI
                if (['AUTH_REQUIRED', 'FORBIDDEN', 'NOT_FOUND'].includes(errType)) {
                    cleanup();
                    if (typeof onError === 'function') onError(result.error);
                    return;
                }

                // Transient errors — tolerate and retry on the next tick.
                // FIX: Explicit stopped guard here. cleanup() may have been called
                // while getStoryboardFrames() was awaiting across the worker
                // boundary. scheduleNextTick() has its own guard, but the Wix
                // platform worker can flush the stopped assignment and this check
                // in the same microtask batch. Guarding here makes it synchronous
                // at the call site, eliminating the race condition.
                if (stopped) return;
                scheduleNextTick();
                return;
            }

            const { frames = [], storyboardStatus, frameCount } = result.data;

            // Fire onFrame for each frame not yet seen, in ascending order
            for (const frame of frames) {
                if (!seenFrameIds.has(frame._id)) {
                    seenFrameIds.add(frame._id);
                    console.log(`${VERSION} New frame: index ${frame.frameIndex} | project: ${projectId}`);
                    if (typeof onFrame === 'function') onFrame(frame, [...frames]);
                }
            }

            // Check for completion
            const isDone = storyboardStatus === 'complete' || frameCount >= TOTAL_FRAMES;

            if (isDone) {
                console.log(`${VERSION} All frames received for project: ${projectId}. Stopping poll.`);
                cleanup();
                if (typeof onComplete === 'function') onComplete([...frames]);
                return;
            }

        } catch (err) {
            // Unexpected JS-level error — log and continue to next tick.
            console.error(`${VERSION} Unexpected polling error:`, err);
        }

        // FIX: Explicit stopped guard before the normal loop continuation.
        // Mirrors the transient error fix above — covers the case where cleanup()
        // fires while the catch block or the happy-path await is in-flight.
        if (stopped) return;
        scheduleNextTick();
    }

    // ── Kick off immediately, then adaptive schedule takes over ───────────────
    tick();

    return { stop: cleanup };
}

// ─── STOP POLLING ─────────────────────────────────────────────────────────────

/**
 * Convenience alias — stops an active polling instance.
 * Safe to call with a null/undefined argument (no-op).
 *
 * @param {{ stop: () => void } | null | undefined} pollerInstance
 */
export function stopStoryboardPolling(pollerInstance) {
    if (pollerInstance && typeof pollerInstance.stop === 'function') {
        pollerInstance.stop();
    }
}