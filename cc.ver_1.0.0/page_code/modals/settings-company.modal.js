/**
 * Modal: Company Settings
 * Path: /page_code/modals/settings-company.modal.js
 * Version: [ COMPANY SETTINGS : v.2.1.0 ]
 *
 * CR-01 Remediation
 * -----------------
 * REMOVED: local showError() — replaced by showInlineError() from notification.js
 * REMOVED: local toggleLoading() — replaced by setButtonLoading() from ui.js
 * REMOVED: importMasterPageErrorHandler() / postMessage error channel (CR-02 fix)
 *
 * On save failure the modal now closes with { updated: false, errorMessage }
 * and the calling page (profile-setting.page.js) surfaces it via showToaster.
 */

import wixWindow from 'wix-window';
import { updateProfile }                    from 'backend/services/profile.web';
import { validateEmail, validateUrl }       from 'public/utils/validation.js';
import { showInlineError, clearInlineError } from 'public/utils/notification.js';
import { setButtonLoading }                 from 'public/utils/ui.js';

const VERSION = '[ COMPANY SETTINGS : v.2.1.0 ]';

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

const MSG_ERROR_GENERIC = "We couldn't update your settings. Please check the form and try again.";
const MSG_SAVING        = "Saving...";
const MSG_SAVE_DEFAULT  = "Save Changes";
const ERROR_SELECTOR    = '#errorMsgCompanyDetails';  // collapsible Text element on the canvas
const BTN_SAVE          = '#btnSave';

// ─── MODULE STATE ─────────────────────────────────────────────────────────────

let _isSaving = false;

// ─── BOOT ─────────────────────────────────────────────────────────────────────

$w.onReady(function () {
    console.log(`${VERSION} Modal Initializing...`);
    bootModal();
});

async function bootModal() {
    const context = wixWindow.lightbox.getContext();

    if (context?.profile) {
        console.log(`${VERSION} Hydrating form with existing profile data.`);
        hydrateForm(context.profile);
    }

    // Ensure the error element is hidden on open
    clearInlineError(ERROR_SELECTOR);

    wireEventHandlers();
}

// ─── HYDRATION ────────────────────────────────────────────────────────────────

function hydrateForm(profile) {
    $w('#companyName').value        = profile.companyName        || '';
    $w('#companyURL').value         = profile.companyURL         || '';
    $w('#companyDescription').value = profile.companyDescription || '';
    $w('#companyZipCode').value     = profile.companyZipCode     || '';
    $w('#companyEmail').value       = profile.companyEmail       || '';
    $w('#companyPhone').value       = profile.companyPhone       || '';
}

// ─── EVENT WIRING ─────────────────────────────────────────────────────────────

function wireEventHandlers() {
    $w(BTN_SAVE).onClick(() => handleSave());
    $w('#btnClose').onClick(() => wixWindow.lightbox.close());
}

// ─── SAVE ─────────────────────────────────────────────────────────────────────

async function handleSave() {
    if (_isSaving) return;

    // Clear any previous error before re-validating
    clearInlineError(ERROR_SELECTOR);

    const validation = validateForm();
    if (!validation.isValid) {
        showInlineError(ERROR_SELECTOR, validation.message);
        return;
    }

    _isSaving = true;
    setButtonLoading(BTN_SAVE, MSG_SAVING, MSG_SAVE_DEFAULT);

    const payload = {
        profile: {
            companyName:        $w('#companyName').value,
            companyURL:         $w('#companyURL').value,
            companyDescription: $w('#companyDescription').value,
            companyZipCode:     $w('#companyZipCode').value,
            companyEmail:       $w('#companyEmail').value,
            companyPhone:       $w('#companyPhone').value
        }
    };

    try {
        console.log(`${VERSION} Dispatching updateProfile...`);
        const response = await updateProfile(payload);

        if (response.ok) {
            console.log(`${VERSION} Profile updated. Closing modal.`);
            wixWindow.lightbox.close({ updated: true });
        } else {
            throw new Error(response.error?.message || MSG_ERROR_GENERIC);
        }

    } catch (err) {
        console.error(`${VERSION} Save failed:`, err);
        // Show the error inside the modal. The caller (profile-setting.page.js)
        // checks result.errorMessage and surfaces it via showToaster if needed.
        showInlineError(ERROR_SELECTOR, err.message || MSG_ERROR_GENERIC);
        wixWindow.lightbox.close({ updated: false, errorMessage: err.message || MSG_ERROR_GENERIC });

    } finally {
        _isSaving = false;
        setButtonLoading(BTN_SAVE, null, MSG_SAVE_DEFAULT);
    }
}

// ─── VALIDATION ───────────────────────────────────────────────────────────────

function validateForm() {
    if (!$w('#companyName').value)
        return { isValid: false, message: 'Company name is required.' };
    if (!validateEmail($w('#companyEmail').value))
        return { isValid: false, message: 'A valid email address is required.' };
    if (!validateUrl($w('#companyURL').value))
        return { isValid: false, message: 'A valid website URL is required.' };
    return { isValid: true };
}