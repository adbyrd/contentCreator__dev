/**
 * [ FILE NAME : masterPage.js : v.1.7.0 ]
 * Page Code: Master Page (Global)
 * Path: /page_code/global/masterPage.js
 * Version: [ MASTER PAGE : v.1.7.0 ]
 *
 * Changelog v.1.6.0 → v.1.7.0
 * ─────────────────────────────────────────────────────────────────────────────
 * [CR-01 / UTIL-03] Removed local _safeDisable() — replaced with
 * safeDisable() / safeEnable() from public/utils/ui.
 *
 *   The local _safeDisable(selector, disabled) helper merged disable and
 *   enable into one function with a boolean flag. ui.js exports these as two
 *   separate, CR-01-compliant primitives: safeDisable(selector) and
 *   safeEnable(selector). Both are called explicitly at the two call sites
 *   in _handleLogOut() in place of the removed helper.
 *
 *   NOTE: ui.js is a /public/ module. Public modules are importable from
 *   masterPage.js in Wix Velo — they resolve in the Master Page's runtime
 *   scope and $w() calls inside them resolve against the Master Page canvas,
 *   which is the correct behaviour for #btnLogOut.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * v.1.6.0 — Revert postMessage / onMessage approach
 * ───────────────────────────────────────────────────
 * REMOVED: wixWindow.onMessage() listener (v.1.5.0)
 *
 * ROOT CAUSE: wixWindow.onMessage() is a lightbox API — it is only available
 * inside a lightbox page and on the page that opened it. It does not exist on
 * the regular page or master page context. Calling it throws:
 *   TypeError: i(...).onMessage is not a function
 * This crashed the entire Master Page $w.onReady() before any element wiring
 * could complete, making every element on the Master Page non-functional.
 *
 * CORRECT SCOPE ARCHITECTURE (Velo 2026):
 *   $w()          — resolves elements in the current module's page scope only.
 *   wixWindow.postMessage / onMessage — lightbox ↔ opener only.
 *   Master Page elements — accessible only from masterPage.js via $w().
 *   Page-to-master communication — not supported via any Velo API.
 *
 * RESOLUTION for the global toaster (Issue #2):
 *   The #globalToaster element is duplicated onto each dashboard page canvas
 *   in the Wix Editor. notification.js calls $w('#globalToaster') from page
 *   code, which resolves correctly because the element now exists on the page.
 *   The Master Page retains its own copy for its own error states (e.g. logout).
 *   See notification.js v.2.3.0 for full details.
 *
 * Canvas requirements (Master Page):
 *   #globalToaster  — collapsible container on the Master Page canvas (for logout errors)
 *   #toasterMsg     — Text element inside #globalToaster
 *   #btnLogOut      — Logout button
 */

import wixLocation        from 'wix-location';
import { authentication } from 'wix-members';
// [CR-01 / UTIL-03] Canonical UI primitives — replaces local _safeDisable()
import { safeDisable, safeEnable } from 'public/utils/ui';

const VERSION             = '[ MASTER PAGE : v.1.7.0 ]';
const MSG_ERROR_GENERIC   = 'Technical error encountered. Please try again later.';
const PATH_HOME           = 'https://www.adbyrd.com/cc';
const TOASTER_DURATION_MS = 4000;

// ─── BOOT ─────────────────────────────────────────────────────────────────────

$w.onReady(function () {
    console.log(`${VERSION} Global Master Page Initialized.`);

    $w('#btnLogOut').onClick(async () => {
        await _handleLogOut();
    });
});

// ─── TOASTER (Master Page scope only) ────────────────────────────────────────

/**
 * Shows the toaster for Master Page-level errors (e.g. logout failure).
 * Operates on the Master Page canvas copy of #globalToaster.
 * NOT exported — not callable from page code. Page code has its own copy.
 */
function _showToaster(message, type = 'error') {
    const $toaster = $w('#globalToaster');
    const $text    = $w('#toasterMsg');

    if (typeof $toaster?.expand !== 'function') {
        console.warn(`${VERSION} _showToaster: #globalToaster not on Master Page canvas.`);
        return;
    }

    $text.text = message;

    if ($toaster.style) {
        $toaster.style.backgroundColor = (type === 'success') ? '#7bef8593' : '#FFEBEE';
    }

    $toaster.expand()
        .then(() => setTimeout(() => $toaster.collapse(), TOASTER_DURATION_MS))
        .catch(err => console.warn(`${VERSION} _showToaster error:`, err));

    console.log(`${VERSION} [${type.toUpperCase()}] ${message}`);
}

// ─── LOGOUT ───────────────────────────────────────────────────────────────────

async function _handleLogOut() {
    // [CR-01 / UTIL-03] was: _safeDisable('#btnLogOut', true)
    safeDisable('#btnLogOut');
    console.log(`${VERSION} Logout initiated.`);

    try {
        await authentication.logout();
        console.log(`${VERSION} Logout successful. Redirecting to home.`);
        wixLocation.to(PATH_HOME);
    } catch (err) {
        console.error(`${VERSION} Logout failed:`, err);
        // [CR-01 / UTIL-03] was: _safeDisable('#btnLogOut', false)
        safeEnable('#btnLogOut');
        _showToaster(MSG_ERROR_GENERIC, 'error');
    }
}