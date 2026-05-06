/**
 * [ FILE NAME : project-detail.page__v2.6.0 ]
 * Page: Project Detail (Dynamic)
 * Path: /page_code/dashboard/project-detail.page.js
 * Version: [ PROJECT DETAIL : v2.6.0 ]
 *
 * Changes (v2.5.0 → v2.6.0)
 * ─────────────────────────────────────────────────────────────────────────────
 * BUG FIX: Polling resumed after cancellation on page refresh.
 *
 * ROOT CAUSE:
 *   The v2.5.0 cancel flow stopped the frontend poller but never wrote
 *   anything to the database. storyboardStatus remained 'generating' in
 *   the projects collection. On the next page load $w.onReady read that
 *   status, saw 'generating', and correctly (per its own logic) resumed
 *   polling — because the system had no record that cancellation occurred.
 *
 * FIX — Two changes:
 *
 *   1. wireCancelButton() now calls cancelStoryboard() (new backend webMethod)
 *      BEFORE stopping the local poller. This stamps storyboardStatus as
 *      'cancelled' in the database. If the backend call fails the cancel
 *      is aborted — the user is shown an error and generation continues,
 *      keeping frontend and backend state in sync at all times.
 *
 *   2. The auto-resume guard in $w.onReady now explicitly checks for
 *      STATUS_GENERATING ('generating') only. The 'cancelled' status
 *      falls through without resuming the poller, so a refresh after
 *      cancellation correctly shows the idle Generate Storyboard state.
 *      (This was already the behaviour in v2.5.0 because the check was
 *      `=== 'generating'`, but it is now documented explicitly alongside
 *      the fix so the intent is clear.)
 *
 * New import
 * ─────────────────────────────────────────────────────────────────────────────
 *   cancelStoryboard from 'backend/services/project.web'
 *
 * New message constants
 * ─────────────────────────────────────────────────────────────────────────────
 *   MSG_CANCEL_FAILED — shown when the backend stamp fails; generation continues.
 *
 * All v2.5.0 behaviour is preserved unchanged.
 */

import wixLocation  from 'wix-location';
import wixWindow    from 'wix-window';
import { verifyProjectAccess, cancelStoryboard } from 'backend/services/project.web';
import { generateStoryboard }                    from 'backend/storyboard/generateStoryboard.web';
import { validateProjectForGeneration }                              from 'public/utils/validation';
import { safeDisable, safeShow, safeHide, setButtonLoading }        from 'public/utils/ui';
import { showToaster }                                              from 'public/utils/notification';
import { startStoryboardPolling, stopStoryboardPolling }            from 'public/utils/storyboard-poller';

const VERSION           = '[ PROJECT DETAIL : v2.6.0 ]';
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

const BTN_GENERATE = '#btnGenerateStoryboard';
const BTN_CANCEL   = '#btnCancelStoryboard';

// ─── STATUS CONSTANTS ─────────────────────────────────────────────────────────

const STATUS_GENERATING = 'generating';

// ─── MODULE STATE ─────────────────────────────────────────────────────────────

let _currentProject = null;
let _activePoller   = null;

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

    // ── 5. Render, wire, then reveal ──────────────────────────────────────────
    setupPageUI();
    wireEditButton();
    wireGenerateButton();
    wireCancelButton();

    // ── 6. Auto-resume guard ──────────────────────────────────────────────────
    // Only resume when status is strictly 'generating'.
    // 'cancelled' (written by cancelStoryboard()) must NOT resume the poller —
    // that is the fix for the refresh-after-cancel bug.
    // Other statuses ('complete', 'failed', 'idle', undefined) also fall through
    // without resuming.
    if (_currentProject.storyboardStatus === STATUS_GENERATING) {
        console.log(`${VERSION} storyboardStatus is '${STATUS_GENERATING}' on load — resuming poll.`);
        safeHide(BTN_GENERATE);
        safeShow(BTN_CANCEL);
        startPolling();
    } else {
        console.log(`${VERSION} storyboardStatus is '${_currentProject.storyboardStatus || 'idle'}' — idle state, no poll resumed.`);
    }

    // Reveal only after ownership is confirmed and UI is ready
    safeShow('#pageContentContainer');
});

// ─── PAGE SETUP ───────────────────────────────────────────────────────────────

function setupPageUI() {
    $w('#txtBreadcrumb').text = `Projects / ${_currentProject.title}`;
    $w('#btnBack').onClick(() => wixLocation.to('/projects'));
}

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

        const result = await generateStoryboard(_currentProject._id);

        if (result.ok) {
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
 *   3. Only if the backend stamp succeeds: stop the local poller and
 *      reset the UI to idle.
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

            // ── Backend confirmed — now safe to stop frontend poller ───────────
            console.log(`${VERSION} Database stamped. Stopping poller and resetting UI.`);
            stopActivePoller();
            resetGenerationUI();
            showToaster(MSG_CANCELLED, 'warning');

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
 *   — positional args per storyboard-poller.js v2.1.0.
 */
function startPolling() {
    _activePoller = startStoryboardPolling(_currentProject._id, {
        onFrame(frame, frames) {
            renderFrame(frame, frames);
        },
        onComplete(frames) {
            console.log(`${VERSION} Generation complete. Total frames: ${frames.length}`);
            _activePoller = null;
            resetGenerationUI();
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

/**
 * Renders a newly delivered storyboard frame into the page UI.
 *
 * @param {object} frame  — individual frame record (frameIndex, imageUrl, promptText, frameData)
 * @param {array}  frames — all frames delivered so far, ascending by frameIndex
 */
function renderFrame(frame, frames) {
    console.log(`${VERSION} Frame received: index ${frame.frameIndex} | total so far: ${frames.length}`);
    // TODO: wire to repeater / canvas elements
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
 *   - onComplete        — generation finished successfully
 *   - onTimeout         — generation exceeded the polling window
 *   - onError           — terminal backend error
 *   - wireCancelButton  — user confirmed cancellation (backend stamp succeeded)
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
    return {
        version:         '2.6.0',
        projectId:       _currentProject?._id              || null,
        projectTitle:    _currentProject?.title            || null,
        storyboardStatus: _currentProject?.storyboardStatus || null,
        pollerActive:    !!_activePoller,
        timestamp:       new Date().toISOString()
    };
}