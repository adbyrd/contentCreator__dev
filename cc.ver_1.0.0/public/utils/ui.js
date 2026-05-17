/**
 * Utility: Shared UI Logic
 * Path: /public/utils/ui.js
 * Version: [ UI LOGIC : v.2.0.0 ]
 *
 * CR-01 Remediation
 * -----------------
 * This file is the SOLE owner of all UI state control primitives.
 * No page controller or modal may define its own safeShow, safeHide,
 * safeDisable, safeEnable, or button loading helpers. Import from here.
 *
 * Also resolves SF-04: safeShow / safeHide / safeDisable have been REMOVED
 * from validation.js. This is the single authoritative source.
 *
 * Exports:
 *   safeShow(selector)
 *   safeHide(selector)
 *   safeDisable(selector)
 *   safeEnable(selector)
 *   setButtonLoading(selector, loadingLabel, defaultLabel)
 *   showModalError(selector, message, timeoutMs?)   ← replaces the old $w-passing pattern
 */

const VERSION = '[ UI LOGIC : v.2.0.0 ]';

// ─── VISIBILITY ───────────────────────────────────────────────────────────────

/**
 * Expands (shows) an element by selector. No-ops silently when the element
 * does not exist on the current page or does not support .expand().
 *
 * @param {string} selector
 */
export function safeShow(selector) {
    const $el = $w(selector);
    if (typeof $el?.expand === 'function') {
        $el.expand();
    } else {
        console.warn(`${VERSION} safeShow: ${selector} not found or does not support expand.`);
    }
}

/**
 * Collapses (hides) an element by selector. No-ops silently when the element
 * does not exist on the current page or does not support .collapse().
 *
 * @param {string} selector
 */
export function safeHide(selector) {
    const $el = $w(selector);
    if (typeof $el?.collapse === 'function') {
        $el.collapse();
    } else {
        console.warn(`${VERSION} safeHide: ${selector} not found or does not support collapse.`);
    }
}

// ─── INTERACTIVE STATE ────────────────────────────────────────────────────────

/**
 * Disables a form element by selector.
 *
 * @param {string} selector
 */
export function safeDisable(selector) {
    const $el = $w(selector);
    if (typeof $el?.disable === 'function') {
        $el.disable();
    } else {
        console.warn(`${VERSION} safeDisable: ${selector} not found or does not support disable.`);
    }
}

/**
 * Enables a form element by selector.
 *
 * @param {string} selector
 */
export function safeEnable(selector) {
    const $el = $w(selector);
    if (typeof $el?.enable === 'function') {
        $el.enable();
    } else {
        console.warn(`${VERSION} safeEnable: ${selector} not found or does not support enable.`);
    }
}

// ─── BUTTON LOADING STATE ─────────────────────────────────────────────────────

/**
 * Toggles a button between its default state and a loading/saving state.
 *
 * Replaces every local toggleLoading() / updateLoadingState() function
 * in modals and page controllers. All buttons use the same behaviour:
 * disable + change label on loading, re-enable + restore label on idle.
 *
 * @param {string} selector      - The $w selector for the button.
 * @param {string|null} loadingLabel - Label to show while loading (e.g. "Saving...").
 *                                    Pass null to restore the button to its default state.
 * @param {string} defaultLabel  - Label to restore when loading is false.
 *
 * @example
 *   // Enter loading state
 *   setButtonLoading('#btnSave', 'Saving...', 'Save Changes');
 *
 *   // Exit loading state (always call in finally block)
 *   setButtonLoading('#btnSave', null, 'Save Changes');
 */
export function setButtonLoading(selector, loadingLabel, defaultLabel) {
    const $btn = $w(selector);

    if (typeof $btn?.disable !== 'function') {
        console.warn(`${VERSION} setButtonLoading: ${selector} not found or is not a button.`);
        return;
    }

    if (loadingLabel !== null && loadingLabel !== undefined) {
        // ── Enter loading state ──────────────────────────────────────────────
        $btn.label = loadingLabel;
        $btn.disable();
    } else {
        // ── Exit loading state ───────────────────────────────────────────────
        $btn.label = defaultLabel;
        $btn.enable();
    }
}

// ─── MODAL INLINE ERRORS ──────────────────────────────────────────────────────

/**
 * Shows a collapsible error element inside a modal or page.
 *
 * This is a UI-layer complement to notification.showInlineError — it does
 * NOT auto-dismiss, because some modal error containers are designed to
 * persist until the user corrects the field. Pass timeoutMs to auto-dismiss.
 *
 * @param {string} selector   - The $w selector for the error container element.
 * @param {string} message    - Error text to display.
 * @param {number} [timeoutMs] - Optional auto-dismiss delay in ms.
 */
export function showModalError(selector, message, timeoutMs = 0) {
    const $container = $w(selector);

    if (typeof $container?.expand !== 'function') {
        console.warn(`${VERSION} showModalError: ${selector} not found. Message: "${message}"`);
        return;
    }

    // Support both plain text elements and container+text pairs.
    if (typeof $container.text !== 'undefined') {
        $container.text = message;
    }

    $container.expand();
    console.warn(`${VERSION} Modal error on ${selector}: "${message}"`);

    if (timeoutMs > 0) {
        setTimeout(() => {
            if (typeof $container.collapse === 'function') $container.collapse();
        }, timeoutMs);
    }
}