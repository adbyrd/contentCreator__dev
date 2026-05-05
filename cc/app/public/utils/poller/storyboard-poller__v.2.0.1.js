// [ FILE NAME : storyboard-poller.js : v1.0.0 ]
// [ PATH : /public/utils/storyboard-poller.js ]
// [ COMPONENT : STORYBOARD POLLER : v1.0.0 ]
//
// PURPOSE:
//   Encapsulates all polling timing and state-tracking logic for the
//   storyboard generation feature. Must NOT be embedded in page code.
//   Consumed by project-detail.page.js via import.
//
// CONTRACT COMPLIANCE:
//   - MVP Implementation Plan §4.4 (Frontend Utility — storyboard-poller.js)
//   - MVP Implementation Plan §3.3 (Resumable polling, architectural constraint)
//   - Platform Standards v2.0 (modular utilities, /public/utils/)
//   - AI Governance Framework (no secrets, no direct webhook calls)
//
// EXPORTS:
//   createStoryboardPoller({ projectId, onFrame, onComplete, onTimeout, onError })
//     → { stop }
//
// DEPENDENCIES:
//   Caller must import getStoryboardFrames from backend via project-detail.page.js
//   This module is framework-agnostic and receives the fetch function as a param.

'use strict';

// ─── Constants ───────────────────────────────────────────────────────────────

const VERSION          = '[ STORYBOARD POLLER : v1.0.0 ]';
const POLL_INTERVAL_MS = 4_000;          // §4.4 — 4-second interval
const MAX_TIMEOUT_MS   = 10 * 60_000;   // §4.4 — 10-minute hard timeout
const TOTAL_FRAMES     = 15;            // §3.2 — success at frameCount === 15

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Creates and immediately starts a storyboard polling loop.
 *
 * @param {object}   config
 * @param {string}   config.projectId        - The project being polled.
 * @param {Function} config.fetchFrames       - Async fn(projectId) → { ok, data: { frames, storyboardStatus } }
 *                                             Injected by page code; keeps this module backend-agnostic.
 * @param {Function} config.onFrame           - Called once per NEW frame: onFrame(frame)
 * @param {Function} config.onComplete        - Called when all 15 frames are confirmed complete.
 * @param {Function} config.onTimeout         - Called when the 10-minute hard timeout fires.
 * @param {Function} [config.onError]         - Called on non-transient errors: onError(err).
 *                                             Transient network errors are tolerated silently (§4.4 rule 4).
 *
 * @returns {{ stop: Function }}  Controller object. Call stop() on page navigation cleanup.
 */
export function createStoryboardPoller({
  projectId,
  fetchFrames,
  onFrame,
  onComplete,
  onTimeout,
  onError = () => {},
}) {
  // ── Validate required inputs ──────────────────────────────────────────────
  if (!projectId || typeof fetchFrames !== 'function') {
    const msg = `${VERSION} createStoryboardPoller() requires projectId and fetchFrames`;
    console.error(msg);
    throw new Error(msg);
  }

  console.log(`${VERSION} Poller initializing for projectId=${projectId}`);

  // ── Internal state ────────────────────────────────────────────────────────
  const seenFrameIds   = new Set();  // §4.4 rule 2 — exactly-once onFrame dispatch
  let   intervalHandle = null;
  let   timeoutHandle  = null;
  let   stopped        = false;

  // ── Cleanup helper ────────────────────────────────────────────────────────
  function _clearTimers() {
    if (intervalHandle) { clearInterval(intervalHandle); intervalHandle = null; }
    if (timeoutHandle)  { clearTimeout(timeoutHandle);   timeoutHandle  = null; }
  }

  function _stop(reason) {
    if (stopped) return;
    stopped = true;
    _clearTimers();
    console.log(`${VERSION} Poller stopped. reason=${reason} projectId=${projectId}`);
  }

  // ── Hard timeout §4.4 rule 3 ─────────────────────────────────────────────
  timeoutHandle = setTimeout(() => {
    console.warn(`${VERSION} Hard timeout exceeded (${MAX_TIMEOUT_MS / 60_000}min) projectId=${projectId}`);
    _stop('TIMEOUT');
    onTimeout();
  }, MAX_TIMEOUT_MS);

  // ── Poll tick ─────────────────────────────────────────────────────────────
  async function _tick() {
    if (stopped) return;

    let response;

    try {
      response = await fetchFrames(projectId);
    } catch (networkErr) {
      // §4.4 rule 4 — tolerate transient network errors; continue polling.
      console.warn(`${VERSION} Transient network error (tolerated). projectId=${projectId}`, networkErr.message);
      return;
    }

    // Non-OK response from webMethod → non-transient, escalate.
    if (!response || !response.ok) {
      const errType = response?.error?.type || 'UNKNOWN';
      console.error(`${VERSION} Non-OK poll response. type=${errType} projectId=${projectId}`);

      // §6.4 error types — UNAUTHORIZED is non-recoverable, stop loop.
      if (errType === 'UNAUTHORIZED') {
        _stop('UNAUTHORIZED');
        onError(response?.error || { type: 'UNAUTHORIZED', message: 'Unauthorized access.' });
      }
      // All other backend errors: log and continue; n8n may still be mid-flight.
      return;
    }

    const { frames = [], storyboardStatus } = response.data;

    // Dispatch newly-seen frames — exactly once each (§4.4 rule 2).
    for (const frame of frames) {
      const frameKey = frame._id || `${projectId}_${frame.frameIndex}`;
      if (!seenFrameIds.has(frameKey)) {
        seenFrameIds.add(frameKey);
        console.log(`${VERSION} New frame dispatched. frameIndex=${frame.frameIndex} projectId=${projectId}`);
        onFrame(frame);
      }
    }

    // §3.2 step 10 — stop and fire onComplete when storyboardStatus === 'complete'.
    // Also guard on frameCount === 15 as a belt-and-suspenders check.
    const frameCount = seenFrameIds.size;
    if (storyboardStatus === 'complete' || frameCount >= TOTAL_FRAMES) {
      console.log(`${VERSION} Generation complete. frames=${frameCount} projectId=${projectId}`);
      _stop('COMPLETE');
      onComplete();
    }
  }

  // ── Start interval §4.4 rule 1 ────────────────────────────────────────────
  intervalHandle = setInterval(_tick, POLL_INTERVAL_MS);

  // Fire first tick immediately so UI is responsive without waiting 4 s.
  _tick();

  console.log(`${VERSION} Poller running. interval=${POLL_INTERVAL_MS}ms projectId=${projectId}`);

  // ── Public controller §4.4 rule 5 ────────────────────────────────────────
  return {
    /**
     * Stops the poller immediately. Call on page navigation / component cleanup.
     * Safe to call multiple times (idempotent).
     */
    stop() {
      _stop('MANUAL_STOP');
    },
  };
}