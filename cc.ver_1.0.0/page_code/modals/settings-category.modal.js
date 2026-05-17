/**
 * Modal: Category & Audience Settings
 * Path: /page_code/modals/settings-category.modal.js
 * Version: [ CATEGORY & AUDIENCE SETTINGS : v.1.1.0 ]
 *
 * CR-01 Remediation
 * -----------------
 * REMOVED: local toggleLoading() (inline btn.disable/enable/label) — replaced by setButtonLoading()
 * REMOVED: local showError / showModalError calls with $w passed as argument
 * ADDED:   showInlineError() from notification.js for all user-facing errors
 * ADDED:   clearInlineError() on boot to ensure the error container starts hidden
 */

import wixWindow from 'wix-window';
import { updateProfile }                    from 'backend/services/profile.web';
import { getTaxonomy }                      from 'backend/services/category.web';
import { showInlineError, clearInlineError } from 'public/utils/notification.js';
import { setButtonLoading }                 from 'public/utils/ui.js';

const VERSION = '[ CATEGORY & AUDIENCE SETTINGS : v.1.1.0 ]';

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

const MSG_SAVING       = 'Saving...';
const MSG_SAVE_DEFAULT = 'Save Settings';
const MSG_TAXONOMY_ERR = 'Unable to load categories. Please close and try again.';
const MSG_SAVE_FAILED  = 'Unable to save your settings. Please try again.';
const ERROR_SELECTOR   = '#categoryModalError';  // collapsible Text element on the canvas
const BTN_SAVE         = '#btnSave';

// ─── MODULE STATE ─────────────────────────────────────────────────────────────

let _isSaving       = false;
let _taxonomyCache  = null;
let _profileContext = null;

// ─── BOOT ─────────────────────────────────────────────────────────────────────

$w.onReady(async function () {
    console.log(`${VERSION} Modal Initializing...`);

    const context    = wixWindow.lightbox.getContext();
    _profileContext  = context?.profile || null;

    // Ensure the error element is hidden on open
    clearInlineError(ERROR_SELECTOR);

    try {
        const res = await getTaxonomy();

        if (!res?.ok) {
            console.error(`${VERSION} Taxonomy fetch failed.`, res);
            showInlineError(ERROR_SELECTOR, MSG_TAXONOMY_ERR);
            return;
        }

        _taxonomyCache = res;

        setupDropdowns();
        wireEventHandlers();

        if (_profileContext) {
            hydrateForm(_profileContext);
        }

    } catch (err) {
        console.error(`${VERSION} Boot error:`, err);
        showInlineError(ERROR_SELECTOR, MSG_TAXONOMY_ERR);
    }
});

// ─── DROPDOWN SETUP ───────────────────────────────────────────────────────────

function setupDropdowns() {
    $w('#businessCategory').options = [
        { label: 'Select a category...', value: '' },
        ...(_taxonomyCache?.parentOptions || [])
    ];

    $w('#customerBase').options = [
        { label: 'Select your customer base...', value: '' },
        { label: 'B2C (Business-to-Consumer)', value: 'b2c' },
        { label: 'B2B (Business-to-Business)', value: 'b2b' },
        { label: 'Mixed / Hybrid',             value: 'mixed' }
    ];

    resetSubCategory();
}

function resetSubCategory() {
    $w('#businessSubCategory').options = [{ label: 'Select a sub-category...', value: '' }];
    $w('#businessSubCategory').value   = '';
    $w('#businessSubCategory').disable();
}

function updateSubCategoryDropdown(parentValue, selectedSubValue = '') {
    if (!parentValue || !_taxonomyCache) {
        resetSubCategory();
        return;
    }

    const children = _taxonomyCache.childrenByParent?.[parentValue] || [];

    if (children.length > 0) {
        $w('#businessSubCategory').options = [
            { label: 'Select a sub-category...', value: '' },
            ...children
        ];
        $w('#businessSubCategory').enable();

        if (selectedSubValue) {
            $w('#businessSubCategory').value = selectedSubValue;
        }
    } else {
        resetSubCategory();
    }
}

// ─── HYDRATION ────────────────────────────────────────────────────────────────

function hydrateForm(profile) {
    if (profile.primaryCategory) {
        $w('#businessCategory').value = profile.primaryCategory;
        updateSubCategoryDropdown(profile.primaryCategory, profile.subCategory || '');
    }

    if (profile.customerType) {
        $w('#customerBase').value = profile.customerType;
    }

    console.log(`${VERSION} Form hydrated from profile context.`);
}

// ─── EVENT WIRING ─────────────────────────────────────────────────────────────

function wireEventHandlers() {
    $w('#businessCategory').onChange(e => {
        clearInlineError(ERROR_SELECTOR);
        updateSubCategoryDropdown(e.target.value);
    });

    $w(BTN_SAVE).onClick(() => handleSave());
    $w('#btnClose').onClick(() => wixWindow.lightbox.close());
}

// ─── SAVE ─────────────────────────────────────────────────────────────────────

async function handleSave() {
    if (_isSaving) return;

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
            primaryCategory: $w('#businessCategory').value,
            subCategory:     $w('#businessSubCategory').value,
            customerType:    $w('#customerBase').value
        }
    };

    try {
        console.log(`${VERSION} Dispatching updateProfile...`);
        const response = await updateProfile(payload);

        if (response.ok) {
            console.log(`${VERSION} Category settings updated. Closing modal.`);
            wixWindow.lightbox.close({ updated: true });
        } else {
            throw new Error(response.error?.message || MSG_SAVE_FAILED);
        }

    } catch (err) {
        console.error(`${VERSION} Save failed:`, err);
        showInlineError(ERROR_SELECTOR, err.message || MSG_SAVE_FAILED);
        wixWindow.lightbox.close({ updated: false, errorMessage: err.message || MSG_SAVE_FAILED });

    } finally {
        _isSaving = false;
        setButtonLoading(BTN_SAVE, null, MSG_SAVE_DEFAULT);
    }
}

// ─── VALIDATION ───────────────────────────────────────────────────────────────

function validateForm() {
    if (!$w('#businessCategory').value)
        return { isValid: false, message: 'Please select a primary category.' };
    if ($w('#businessSubCategory').enabled && !$w('#businessSubCategory').value)
        return { isValid: false, message: 'Please select a sub-category.' };
    if (!$w('#customerBase').value)
        return { isValid: false, message: 'Please select a customer base.' };
    return { isValid: true };
}