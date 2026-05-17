/**
 * [ FILE NAME : notification.js : v.2.3.0 ]
 * Utility: Notifications & User Feedback
 * Path: /public/utils/notification.js
 * Version: [ NOTIFICATIONS : v.2.3.0 ]
 *
 * Changelog v.2.2.0 → v.2.3.0
 * ─────────────────────────────────────────────────────────────────────────────
 * [FIX-TOAST-02] postMessage approach replaced — page-local toaster pattern
 *
 *   PROBLEM (v.2.2.0 — postMessage bridge):
 *     wixWindow.postMessage() sends to the Master Page. masterPage.js v.1.6.0
 *     intentionally removed wixWindow.onMessage() because it is a lightbox-only
 *     API — calling it on the Master Page throws:
 *       TypeError: i(...).onMessage is not a function
 *     This means postMessage is dispatched but never received. Every showToaster()
 *     call silently dropped the message, producing:
 *       "[ NOTIFICATIONS : v.2.3.0 ] showToaster: #globalToaster not found on
 *        this page."
 *
 *   PROBLEM (v.2.0.0 — direct $w('#globalToaster') on Master Page):
 *     Velo always binds $w() to the calling module's runtime scope — not to
 *     where the element is defined. A public utility calling $w('#globalToaster')
 *     resolves against the current page canvas, not the Master Page canvas.
 *
 *   PROBLEM (Editor — duplicate ID constraint):
 *     Wix enforces globally unique element IDs across ALL canvases on a page,
 *     including the Master Page. Attempting to add #globalToaster to an
 *     individual page canvas while #globalToaster exists on the Master Page
 *     canvas produces the error: "The ID has to be unique."
 *
 *   SOLUTION — Page-local toaster with a unique ID:
 *     Each page canvas that needs toast notifications must have a collapsible
 *     container element with ID #pageToaster and a child text element with ID
 *     #pageToasterMsg. These IDs do not conflict with the Master Page's
 *     #globalToaster / #toasterMsg elements.
 *
 *     showToaster() calls $w('#pageToaster') directly. Because this is a public
 *     utility called from page code, $w() resolves to the current page canvas —
 *     exactly where #pageToaster lives. No postMessage, no cross-scope call.
 *
 *     The Master Page retains its own #globalToaster / #toasterMsg exclusively
 *     for Master Page-level events (e.g. logout failure via masterPage.js).
 *     These two element sets never conflict.
 *
 *   CANVAS REQUIREMENTS — add to EACH page that calls showToaster():
 *     #pageToaster    — collapsible container (hidden/collapsed on load)
 *     #pageToasterMsg — Text element inside #pageToaster
 *
 *   Pages currently calling showToaster():
 *     /projects (Project Explorer)    → add #pageToaster + #pageToasterMsg
 *     /project/{id} (Project Detail)  → add #pageToaster + #pageToasterMsg
 *     settings modals (lightboxes)    → add #pageToaster + #pageToasterMsg
 *     masterPage.js                   → uses its own #globalToaster (no change)
 *
 *   All showToaster() call sites across the application are unchanged —
 *   the public API is fully backward compatible.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * v.2.2.0 — postMessage Toaster Bridge (superseded)
 * v.2.0.0 — Direct $w('#globalToaster') approach (superseded)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Exports:
 *   showToaster(message, type)
 *   showInlineError(selector, message, timeoutMs?)
 *   clearInlineError(selector)
 *   debugNotifications()
 */

const VERSION            = '[ NOTIFICATIONS : v.2.3.0 ]';
const TOASTER_DURATION_MS = 4000;

// Page-local toaster element IDs.
// Must exist on every page canvas that calls showToaster().
// Do NOT use #globalToaster — that ID is reserved for the Master Page canvas.
const SEL_TOASTER     = '#pageToaster';
const SEL_TOASTER_MSG = '#pageToasterMsg';

// Default duration for inline field errors (ms).
const INLINE_ERROR_DURATION_MS = 6000;

// ─── SHARED CONSTANTS ─────────────────────────────────────────────────────────

export const MSG_GENERIC_ERROR  = 'Something went wrong. Please try again or contact support.';
export const MSG_UPDATE_SUCCESS = 'Settings updated successfully.';
export const MSG_SAVE_FAILED    = 'Unable to save. Please try again.';

// ─── GLOBAL TOASTER ───────────────────────────────────────────────────────────

/**
 * Displays the page-local feedback toaster.
 *
 * Requires #pageToaster (collapsible container) and #pageToasterMsg (text
 * element) to be present on the current page canvas. Both must be set to
 * "Collapsed on load" in the Wix Editor.
 *
 * If either element is absent (e.g. during development or on a page not yet
 * configured), the message is logged as a warning but does not throw.
 *
 * @param {string} message
 * @param {'success'|'error'} [type='success']
 */
export function showToaster(message, type = 'success') {
    try {
        const $toaster = $w(SEL_TOASTER);
        const $msg     = $w(SEL_TOASTER_MSG);

        if (typeof $toaster?.expand !== 'function') {
            console.warn(`${VERSION} showToaster: ${SEL_TOASTER} not found on this page. Message: "${message}"`);
            return;
        }

        $msg.text = message;

        if ($toaster.style) {
            $toaster.style.backgroundColor = (type === 'success') ? '#7bef8593' : '#FFEBEE';
        }

        $toaster.expand()
            .then(() => setTimeout(() => {
                if (typeof $toaster.collapse === 'function') $toaster.collapse();
            }, TOASTER_DURATION_MS))
            .catch(err => console.warn(`${VERSION} showToaster expand/collapse error:`, err));

        console.log(`${VERSION} [${type.toUpperCase()}] showToaster: "${message}"`);

    } catch (err) {
        // showToaster must never interrupt the calling flow.
        console.warn(`${VERSION} showToaster: unexpected error. Message was: "${message}"`, err);
    }
}

// ─── INLINE FIELD ERRORS ──────────────────────────────────────────────────────

/**
 * Expands a collapsible error element on the current page and auto-collapses
 * it after a timeout. Falls back to showToaster() if the element is absent.
 *
 * @param {string} selector    - e.g. '#newProjectError'
 * @param {string} message
 * @param {number} [timeoutMs]
 */
export function showInlineError(selector, message, timeoutMs = INLINE_ERROR_DURATION_MS) {
    const $el = $w(selector);

    if (typeof $el?.expand !== 'function') {
        console.warn(`${VERSION} showInlineError: ${selector} not found. Falling back to toaster.`);
        showToaster(message, 'error');
        return;
    }

    $el.text = message;
    $el.expand();

    setTimeout(() => {
        if (typeof $el.collapse === 'function') $el.collapse();
    }, timeoutMs);

    console.warn(`${VERSION} Inline error on ${selector}: "${message}"`);
}

/**
 * Collapses an inline error element immediately.
 *
 * @param {string} selector
 */
export function clearInlineError(selector) {
    const $el = $w(selector);
    if (typeof $el?.collapse === 'function') $el.collapse();
}

// ─── DEBUG ────────────────────────────────────────────────────────────────────

export function debugNotifications() {
    console.log(`${VERSION} Debug: firing test toaster...`);
    showToaster('Notification system operational.', 'success');
}