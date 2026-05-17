/**
 * [ FILE NAME : project-detail.page__v2.9.0 ]
 * Page: Project Detail (Dynamic)
 * Path: /page_code/dashboard/project-detail.page.js
 * Version: [ PROJECT DETAIL : v2.9.0 ]
 *
 * Changelog v2.8.0 → v2.9.0
 * ─────────────────────────────────────────────────────────────────────────────
 * [BUG-04] wireCancelButton — _currentProject.storyboardStatus not updated
 *          after successful cancel
 *
 *   ROOT CAUSE:
 *     After a confirmed cancel, wireCancelButton() calls stopActivePoller()
 *     and resetGenerationUI() but does NOT update the in-memory
 *     _currentProject.storyboardStatus value. It remains 'generating'.
 *
 *     If the user immediately clicks Generate Storyboard again (without
 *     refreshing), two things happen:
 *
 *       1. validateProjectForGeneration(_currentProject) passes — the fields
 *          are intact in memory (they haven't been wiped yet at this point
 *          because BUG-03 only wipes on the NEXT stamp write).
 *
 *       2. generateStoryboard() dispatches to the backend. The backend reads
 *          the DB: storyboardStatus is 'cancelled' (not 'generating'), so
 *          the ALREADY_RUNNING guard does NOT fire. The backend proceeds to
 *          stamp the project as 'generating' using the partial-patch pattern
 *          (BUG-03 in generateStoryboard.web.js v1.7.0), which wipes all
 *          content fields (title, description, goal, offer, misconception,
 *          target_audience) from the database.
 *
 *       3. The webhook dispatches successfully, but the database record is
 *          now corrupt. On the next page refresh, the dynamic dataset loads
 *          the corrupt record, _currentProject has all content fields null,
 *          and validateProjectForGeneration() fails with '"Project name" is
 *          required before generating a storyboard.'
 *
 *   NOTE: BUG-03 (the partial stamp in generateStoryboard.web.js) is the
 *   primary data-loss vector. BUG-04 is the UX trigger that sends a second
 *   generate call immediately after cancel, enabling BUG-03 to fire again
 *   on the same session without a page reload. Both bugs must be fixed
 *   together for complete resolution.
 *
 *   FIX:
 *     After cancelStoryboard() returns ok, update _currentProject.storyboardStatus
 *     to STATUS_CANCELLED in memory before calling resetGenerationUI().
 *     This ensures that any immediate re-click of Generate Storyboard enters
 *     a clean state — the backend's ALREADY_RUNNING guard cannot be bypassed
 *     and the UI reflects the true status even before a refresh.
 *
 *     The fix is a single line added in wireCancelButton():
 *       _currentProject = { ..._currentProject, storyboardStatus: STATUS_CANCELLED };
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Changelog v2.7.0 → v2.8.0 — preserved for history
 * ─────────────────────────────────────────────────────────────────────────────
 * [FIX-TOAST-01] 'warning' toaster type replaced with 'success'
 * [FIX-SETUP-01] Removed setupPageUI() and its call site
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Canvas element requirements (full list)
 * ─────────────────────────────────────────────────────────────────────────────
 *   #pageContentContainer      — outer container (hidden until auth passes)
 *   #dynamicDataset            — Wix dynamic dataset bound to projects
 *   #txtBreadcrumb             — breadcrumb text ("Projects / <title>")
 *   #btnBack                   — back button → /projects
 *   #btnEditProject            — opens Project Settings lightbox
 *   #btnGenerateStoryboard     — triggers generation dispatch
 *   #btnCancelStoryboard       — triggers cancellation flow
 *   #loadingPreloader          — collapsible spinner during dispatch
 *   #storyboardRepeater        — repeater for frame items (see above)
 *     └─ #frameImage           — Image element
 *     └─ #frameNumber          — Text element ("Frame N / 15")
 *     └─ #framePrompt          — Text element (prompt text)
 *     └─ #frameNarrativeStage  — Text element (narrative stage label)
 *   #storyboardEmptyState      — shown before any frames arrive
 *   #storyboardCompleteState   — shown after all 15 frames are received
 */

import wixLocation  from 'wix-location';
import wixWindow    from 'wix-window';
import { verifyProjectAccess }                             from 'backend/services/project.web';
import { generateStoryboard, cancelStoryboard }            from 'backend/storyboard/generateStoryboard.web';
import { validateProjectForGeneration }                    from 'public/utils/validation';
// [FIX-IMPORT-02] safeDisable removed — it was imported but never called.
import { safeShow, safeHide, setButtonLoading }            from 'public/utils/ui';
import { showToaster }                                     from 'public/utils/notification';
import { startStoryboardPolling, stopStoryboardPolling }   from 'public/utils/storyboard-poller';

const VERSION           = '[ PROJECT DETAIL : v2.9.0 ]';
const PATH_UNAUTHORIZED = '/cc';

// ─── MESSAGES ─────────────────────────────────────────────────────────────────

const MSG_GENERATION_FAILED   = 'Unable to start generation. Please try again.';
const MSG_DISPATCH_FAILED     = 'The generation pipeline is currently unavailable. Please try again in a moment.';
const MSG_CONFIG_ERROR        = 'Generation is not yet configured. Please contact support.';
const MSG_ALREADY_RUNNING     = 'Generation is already in progress — resuming display.';
const MSG_POLL_TIMEOUT        = "Generation is taking longer than expected. We'll notify you when it's ready.";
const MSG_POLL_ERROR          = 'Lost connection to the generation service. Please refresh the page.';
const MSG_PROJECT_UPDATED     = 'Project updated successfully.';
const MSG_GENERATING          = 'Generating...';
const MSG_GENERATE_DEFAULT    = 'Generate Storyboard';
const MSG_CANCELLED           = 'Storyboard generation cancelled.';
const MSG_CANCEL_FAILED       = 'Unable to cancel generation. Please try again.';

// ─── SELECTORS ────────────────────────────────────────────────────────────────

const BTN_GENERATE         = '#btnGenerateStoryboard';
const BTN_CANCEL           = '#btnCancelStoryboard';
const REPEATER_STORYBOARD  = '#storyboardRepeater';
const EMPTY_STATE          = '#storyboardEmptyState';
const COMPLETE_STATE       = '#storyboardCompleteState';

// ─── STATUS CONSTANTS ─────────────────────────────────────────────────────────

const STATUS_GENERATING = 'generating';
const STATUS_CANCELLED  = 'cancelled';
const TOTAL_FRAMES      = 15;

// ─── MODULE STATE ─────────────────────────────────────────────────────────────

let _currentProject = null;
let _activePoller   = null;

/**
 * Accumulates delivered frames across all poll ticks.
 * Keyed by frameIndex (0–14) to prevent duplicates on mid-generation resume.
 * @type {Map<number, object>}
 */
let _frameMap = new Map();

// ─── BOOT ─────────────────────────────────────────────────────────────────────

$w.onReady(async function () {
    console.log(`${VERSION} Initializing...`);

    // ── 0. SECURITY GATE — hide content BEFORE any async work ────────────────
    safeHide('#pageContentContainer');

    // ── 1. Read project ID from the dynamic dataset ───────────────────────────
    const datasetItem = $w('#dynamicDataset').getCurrentItem();

    if (!datasetItem?._id) {
        console.warn(`${VERSION} No dataset item found. Redirecting.`);
        wixLocation.to(PATH_UNAUTHORIZED);
        return;
    }

    // ── 2. Server-side access verification ───────────────────────────────────
    console.log(`${VERSION} Verifying access for project: ${datasetItem._id}`);
    const accessResult = await verifyProjectAccess(datasetItem._id);

    if (!accessResult.ok || !accessResult.authorized) {
        const reason = accessResult.error?.type || accessResult.error || 'UNKNOWN';
        console.warn(`${VERSION} Access denied. Reason: ${reason}. Redirecting.`);
        wixLocation.to(PATH_UNAUTHORIZED);
        return;
    }

    // ── 3. Populate authoritative module state ────────────────────────────────
    _currentProject = accessResult.data;
    console.log(`${VERSION} Access granted. Rendering: "${_currentProject.title}"`);

    // ── 4. Default UI state ───────────────────────────────────────────────────
    safeHide(BTN_CANCEL);

    // ── 5. Register repeater handler synchronously before any awaits ─────────
    // CRITICAL: onItemReady must be registered before data is assigned.
    // Registering it inside an async callback causes Wix to skip the handler
    // on initial data binding, resulting in a blank repeater.
    registerFrameRepeaterItemReady();

    // ── 6. Render, wire, then reveal ──────────────────────────────────────────
    wireEditButton();
    wireGenerateButton();
    wireCancelButton();

    // ── 7. Auto-resume guard ──────────────────────────────────────────────────
    // Only resume when status is strictly 'generating'.
    // 'cancelled' (written by cancelStoryboard()) must NOT resume the poller —
    // that is the fix for the refresh-after-cancel bug.
    // Other statuses ('complete', 'failed', 'idle', undefined) also fall through
    // without resuming.
    if (_currentProject.storyboardStatus === STATUS_GENERATING) {
        console.log(`${VERSION} storyboardStatus is '${STATUS_GENERATING}' on load — resuming poll.`);
        safeHide(BTN_GENERATE);
        safeShow(BTN_CANCEL);
        safeShow(EMPTY_STATE);
        safeHide(COMPLETE_STATE);
        startPolling();
    } else {
        console.log(`${VERSION} storyboardStatus is '${_currentProject.storyboardStatus || 'idle'}' — idle state.`);
        // Show complete state banner if generation has previously finished
        if (_currentProject.storyboardStatus === 'complete') {
            safeShow(COMPLETE_STATE);
            safeHide(EMPTY_STATE);
        } else {
            safeShow(EMPTY_STATE);
            safeHide(COMPLETE_STATE);
        }
    }

    // Reveal only after ownership is confirmed and UI is ready
    safeShow('#pageContentContainer');
});

// ─── EDIT BUTTON ──────────────────────────────────────────────────────────────

function wireEditButton() {
    $w('#btnEditProject').onClick(async () => {
        if (!_currentProject) {
            console.warn(`${VERSION} Edit triggered but _currentProject is null.`);
            return;
        }

        try {
            console.log(`${VERSION} Opening edit modal for project: ${_currentProject._id}`);
            const result = await wixWindow.openLightbox('Project', { project: _currentProject });

            if (result?.updated) {
                console.log(`${VERSION} Edit confirmed. Re-syncing project state...`);

                const refreshed = await verifyProjectAccess(_currentProject._id);

                if (refreshed.ok && refreshed.authorized) {
                    _currentProject = refreshed.data;
                    console.log(`${VERSION} _currentProject synced: "${_currentProject.title}"`);
                } else {
                    console.warn(`${VERSION} Re-sync access check failed. Redirecting.`);
                    wixLocation.to(PATH_UNAUTHORIZED);
                    return;
                }

                await $w('#dynamicDataset').refresh();
                showToaster(MSG_PROJECT_UPDATED, 'success');

            } else if (result?.errorMessage) {
                showToaster(result.errorMessage, 'error');
            }

        } catch (err) {
            console.error(`${VERSION} Edit modal error:`, err);
        }
    });
}

// ─── GENERATE STORYBOARD BUTTON ───────────────────────────────────────────────

function wireGenerateButton() {
    $w(BTN_GENERATE).onClick(async () => {

        const validation = validateProjectForGeneration(_currentProject);
        if (!validation.isValid) {
            showToaster(validation.message, 'error');
            return;
        }

        setButtonLoading(BTN_GENERATE, MSG_GENERATING, MSG_GENERATE_DEFAULT);
        safeShow('#loadingPreloader');

        if (_activePoller) {
            stopStoryboardPolling(_activePoller);
            _activePoller = null;
        }

        // Clear any stale frames from a previous run before dispatching
        clearStoryboardUI();

        const result = await generateStoryboard(_currentProject._id);

        if (result.ok) {
            // ── Sync in-memory status to match what the backend just stamped ──
            _currentProject = { ..._currentProject, storyboardStatus: STATUS_GENERATING };
            safeHide(BTN_GENERATE);
            safeShow(BTN_CANCEL);
            console.log(`${VERSION} Generation dispatched. Cancel button shown.`);
            startPolling();
            return;
        }

        const errorType = result.error?.type || 'UNKNOWN';
        console.warn(`${VERSION} generateStoryboard failed: type=${errorType}`, result.error);

        if (errorType === 'ALREADY_RUNNING') {
            console.log(`${VERSION} ALREADY_RUNNING — resuming active generation poll.`);
            _currentProject = { ..._currentProject, storyboardStatus: STATUS_GENERATING };
            safeHide(BTN_GENERATE);
            safeShow(BTN_CANCEL);
            showToaster(MSG_ALREADY_RUNNING, 'success');
            startPolling();
            return;
        }

        setButtonLoading(BTN_GENERATE, null, MSG_GENERATE_DEFAULT);
        safeHide('#loadingPreloader');

        if (errorType === 'DISPATCH_FAILED' || errorType === 'WEBHOOK_ERROR' || errorType === 'WEBHOOK_UNAVAILABLE') {
            showToaster(MSG_DISPATCH_FAILED, 'error');
            return;
        }

        if (errorType === 'CONFIG_ERROR' || errorType === 'CONFIGURATION_ERROR') {
            showToaster(MSG_CONFIG_ERROR, 'error');
            return;
        }

        showToaster(MSG_GENERATION_FAILED, 'error');
    });
}

// ─── CANCEL STORYBOARD BUTTON ─────────────────────────────────────────────────

/**
 * Wires #btnCancelStoryboard.
 *
 * Flow:
 *   1. Open confirmation modal.
 *   2. On "Yes I'm Sure": call cancelStoryboard() backend method FIRST.
 *      This stamps storyboardStatus = 'cancelled' in the database so that
 *      a subsequent page refresh does not auto-resume the poller.
 *   3. Only if the backend stamp succeeds: stop the local poller, sync
 *      _currentProject in memory (BUG-04 fix), and reset the UI to idle.
 *   4. If the backend stamp fails: show an error toaster. The modal has
 *      already closed, so we leave the poller running and the cancel
 *      button visible — generation continues and the user can retry.
 *   5. On "Cancel" (modal dismissed): no action, generation continues.
 */
function wireCancelButton() {
    $w(BTN_CANCEL).onClick(async () => {
        console.log(`${VERSION} Cancel button clicked. Opening confirmation modal.`);

        try {
            const result = await wixWindow.openLightbox('CancelStoryboardConfirm');

            if (!result?.confirmed) {
                console.log(`${VERSION} Cancellation dismissed. Generation continues.`);
                return;
            }

            // ── User confirmed — stamp the database FIRST ─────────────────────
            console.log(`${VERSION} User confirmed. Stamping cancellation in database...`);
            const cancelResult = await cancelStoryboard(_currentProject._id);

            if (!cancelResult.ok) {
                // Backend failed to persist the cancellation. Do NOT stop the
                // poller — frontend and backend would be out of sync. Surface
                // an error so the user knows to try again.
                const errType = cancelResult.error?.type || 'UNKNOWN';
                console.error(`${VERSION} cancelStoryboard failed: type=${errType}`, cancelResult.error);
                showToaster(MSG_CANCEL_FAILED, 'error');
                return;
            }

            // ── [BUG-04] FIX: sync in-memory status before resetting UI ───────
            // Without this, _currentProject.storyboardStatus stays 'generating'
            // in memory. A subsequent Generate click would pass front-end
            // validation and dispatch a second backend call in the same session,
            // enabling the partial-stamp data-loss bug (BUG-03) to fire again.
            //
            // Spread to produce a new object reference — prevents accidental
            // mutation of the original record shape.
            _currentProject = { ..._currentProject, storyboardStatus: STATUS_CANCELLED };
            console.log(`${VERSION} _currentProject.storyboardStatus synced to '${STATUS_CANCELLED}'`);

            // ── Backend confirmed — now safe to stop frontend poller ───────────
            console.log(`${VERSION} Database stamped. Stopping poller and resetting UI.`);
            stopActivePoller();
            resetGenerationUI();
            showToaster(MSG_CANCELLED, 'success');

        } catch (err) {
            console.error(`${VERSION} Cancel flow error:`, err);
            showToaster(MSG_CANCEL_FAILED, 'error');
        }
    });
}

// ─── STORYBOARD POLLING ───────────────────────────────────────────────────────

/**
 * Starts the adaptive storyboard poller for the current project.
 *
 * SIGNATURE: startStoryboardPolling(projectId, { callbacks })
 *   — positional args per storyboard-poller.js v2.2.0.
 */
function startPolling() {
    _activePoller = startStoryboardPolling(_currentProject._id, {
        onFrame(frame, frames) {
            renderFrame(frame, frames);
        },
        onComplete(frames) {
            console.log(`${VERSION} Generation complete. Total frames: ${frames.length}`);
            _activePoller = null;
            onGenerationComplete(frames);
        },
        onTimeout() {
            console.warn(`${VERSION} Polling timed out.`);
            _activePoller = null;
            resetGenerationUI();
            showToaster(MSG_POLL_TIMEOUT, 'error');
        },
        onError(error) {
            console.error(`${VERSION} Polling terminal error:`, error);
            _activePoller = null;
            resetGenerationUI();
            showToaster(MSG_POLL_ERROR, 'error');
        },
    });
}

// ─── STORYBOARD FRAME REPEATER ────────────────────────────────────────────────

/**
 * Registers the #storyboardRepeater onItemReady handler.
 *
 * MUST be called synchronously inside $w.onReady before any awaits.
 * Wix skips the handler if it is registered after an async boundary.
 *
 * Canvas element IDs required inside the repeater (see file header):
 *   #frameImage          — Image element
 *   #frameNumber         — Text element  ("Frame N / 15")
 *   #framePrompt         — Text element  (prompt text)
 *   #frameNarrativeStage — Text element  (narrative stage label from frameData)
 */
function registerFrameRepeaterItemReady() {
    $w(REPEATER_STORYBOARD).onItemReady(($item, itemData) => {

        // ── Frame image ───────────────────────────────────────────────────────
        if (itemData.imageUrl) {
            $item('#frameImage').src = itemData.imageUrl;
        }

        // ── Frame number label ────────────────────────────────────────────────
        // frameIndex is 0-based; display as 1-based for the user.
        $item('#frameNumber').text = `Frame ${itemData.frameIndex + 1} / ${TOTAL_FRAMES}`;

        // ── Prompt text ───────────────────────────────────────────────────────
        $item('#framePrompt').text = itemData.promptText || '';

        // ── Narrative stage ───────────────────────────────────────────────────
        // narrativeStage is nested inside frameData (object field in CMS).
        // Falls back gracefully when absent.
        const stage = itemData.frameData?.narrativeStage || '';
        $item('#frameNarrativeStage').text = stage;
    });
}

/**
 * Renders a newly delivered storyboard frame into the page UI.
 *
 * Called by the poller's onFrame callback on every new frame arrival.
 */
function renderFrame(frame, frames) {
    console.log(`${VERSION} Frame received: index ${frame.frameIndex} | total so far: ${frames.length}`);

    // Accumulate — Map keyed by frameIndex deduplicates resumes
    _frameMap.set(frame.frameIndex, frame);

    // Build sorted array for repeater assignment
    const sortedFrames = Array.from(_frameMap.values())
        .sort((a, b) => a.frameIndex - b.frameIndex);

    // Assign full array — Wix diffs by _id, only re-renders new items
    $w(REPEATER_STORYBOARD).data = sortedFrames;

    // Hide empty state on first frame
    if (_frameMap.size === 1) {
        safeHide(EMPTY_STATE);
        safeHide('#loadingPreloader');
        console.log(`${VERSION} First frame received — hiding empty state.`);
    }

    console.log(`${VERSION} Repeater updated — ${_frameMap.size} frame(s) rendered.`);
}

/**
 * Called by the poller's onComplete callback when all 15 frames are confirmed.
 * Shows the completion banner and resets the generation UI controls.
 */
function onGenerationComplete(frames) {
    console.log(`${VERSION} onGenerationComplete — showing complete state banner.`);
    safeShow(COMPLETE_STATE);
    safeHide(EMPTY_STATE);
    resetGenerationUI();
}

/**
 * Clears the frame accumulator and empties the repeater.
 * Called before each new generation run to prevent stale frame bleed-through.
 */
function clearStoryboardUI() {
    _frameMap.clear();
    $w(REPEATER_STORYBOARD).data = [];
    safeShow(EMPTY_STATE);
    safeHide(COMPLETE_STATE);
    console.log(`${VERSION} Storyboard UI cleared.`);
}

// ─── UI HELPERS ───────────────────────────────────────────────────────────────

/**
 * Stops the active poller without touching UI state.
 * Safe to call when no poller is active (no-op).
 */
function stopActivePoller() {
    if (_activePoller) {
        stopStoryboardPolling(_activePoller);
        _activePoller = null;
        console.log(`${VERSION} Active poller stopped.`);
    }
}

/**
 * Resets all generation-related UI to its default (idle) state.
 *
 * Single source of truth for post-generation UI teardown. Called by:
 *   - onGenerationComplete — generation finished successfully
 *   - onTimeout            — generation exceeded the polling window
 *   - onError              — terminal backend error
 *   - wireCancelButton     — user confirmed cancellation (backend stamp succeeded)
 */
function resetGenerationUI() {
    setButtonLoading(BTN_GENERATE, null, MSG_GENERATE_DEFAULT);
    safeShow(BTN_GENERATE);
    safeHide(BTN_CANCEL);
    safeHide('#loadingPreloader');
    console.log(`${VERSION} Generation UI reset to idle.`);
}

// ─── DEBUG ────────────────────────────────────────────────────────────────────

export function debugPageState() {
    console.log(`${VERSION} _currentProject:`, _currentProject);
    console.log(`${VERSION} _activePoller:`,   _activePoller);
    console.log(`${VERSION} _frameMap size:`,  _frameMap.size);
    return {
        version:          '2.9.0',
        projectId:        _currentProject?._id               || null,
        projectTitle:     _currentProject?.title             || null,
        storyboardStatus: _currentProject?.storyboardStatus  || null,
        pollerActive:     !!_activePoller,
        framesReceived:   _frameMap.size,
        frameIndexes:     Array.from(_frameMap.keys()).sort((a, b) => a - b),
        timestamp:        new Date().toISOString(),
    };
}