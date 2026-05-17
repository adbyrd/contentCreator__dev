/**
 * [ FILE NAME : cancel-storyboard-confirm.modal__v1.0.0 ]
 * Modal: Cancel Storyboard Confirmation
 * Path: /page_code/modals/cancel-storyboard-confirm.modal.js
 * Version: [ CANCEL STORYBOARD CONFIRM : v1.0.0 ]
 *
 * Purpose
 * ─────────────────────────────────────────────────────────────────────────────
 * Presents a confirmation dialog when the user clicks #btnCancelStoryboard on
 * the Project Detail page. Protects against accidental cancellation of an
 * in-progress storyboard generation by requiring explicit intent.
 *
 * Canvas element requirements
 * ─────────────────────────────────────────────────────────────────────────────
 *   #txtModalHeading        — Text element: "Are You Sure?"
 *   #txtModalBody           — Text element: supporting copy
 *   #btnConfirmCancel       — Button: "Yes I'm Sure"  → confirms cancellation
 *   #btnDismissCancel       — Button: "Cancel"        → dismisses without action
 *
 * Lightbox name (Wix Editor)
 * ─────────────────────────────────────────────────────────────────────────────
 *   'CancelStoryboardConfirm'
 *   This name must match the string passed to wixWindow.openLightbox() in
 *   project-detail.page.js exactly.
 *
 * Return contract
 * ─────────────────────────────────────────────────────────────────────────────
 *   "Yes I'm Sure" → wixWindow.lightbox.close({ confirmed: true })
 *   "Cancel"       → wixWindow.lightbox.close()          (no payload)
 *   Backdrop click → handled by Wix platform (no payload, treated as dismiss)
 */

import wixWindow from 'wix-window';

const VERSION = '[ CANCEL STORYBOARD CONFIRM : v1.0.0 ]';

// ─── SELECTORS ────────────────────────────────────────────────────────────────

const BTN_CONFIRM  = '#btnConfirmCancel';   // "Yes I'm Sure"
const BTN_DISMISS  = '#btnDismissCancel';   // "Cancel"

// ─── BOOT ─────────────────────────────────────────────────────────────────────

$w.onReady(function () {
    console.log(`${VERSION} Modal ready.`);
    wireEventHandlers();
});

// ─── EVENT WIRING ─────────────────────────────────────────────────────────────

/**
 * Registers click handlers for both modal action buttons.
 *
 * "Yes I'm Sure" (#btnConfirmCancel)
 *   Closes the lightbox with { confirmed: true }. The caller
 *   (project-detail.page.js) interprets this payload as an instruction to
 *   stop the active poller and reset the generation UI.
 *
 * "Cancel" (#btnDismissCancel)
 *   Closes the lightbox with no payload. The caller treats a missing
 *   or empty result as a dismissal — generation continues uninterrupted.
 */
function wireEventHandlers() {
    $w(BTN_CONFIRM).onClick(() => {
        console.log(`${VERSION} User confirmed cancellation.`);
        wixWindow.lightbox.close({ confirmed: true });
    });

    $w(BTN_DISMISS).onClick(() => {
        console.log(`${VERSION} User dismissed confirmation. No action taken.`);
        wixWindow.lightbox.close();
    });
}

// ─── DEBUG EXPORT ─────────────────────────────────────────────────────────────

export function debugModalState() {
    return {
        version:   '1.0.0',
        modal:     'CancelStoryboardConfirm',
        timestamp: new Date().toISOString()
    };
}