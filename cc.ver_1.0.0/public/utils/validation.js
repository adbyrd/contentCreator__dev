/**
 * Utility: Validation Helpers
 * Path: /public/utils/validation.js
 * Version: [ VALIDATION : v.2.0.0 ]
 *
 * CR-01 / SF-04 Remediation
 * -------------------------
 * REMOVED: safeShow, safeHide, safeDisable — these belong exclusively in ui.js.
 *          Any file previously importing these from validation.js must be updated
 *          to import from 'public/utils/ui.js' instead.
 *
 * This file is strictly concerned with data validation logic.
 * It has zero UI side-effects and no $w references.
 *
 * Exports:
 *   validateEmail(email)
 *   validateUrl(url)
 *   validateRequired(value)
 *   createValidationResult(isValid, message, errorFields)
 *   validateProjectForGeneration(project)
 *   humanizeSlug(slug)
 */

const VERSION = '[ VALIDATION : v.2.0.0 ]';

// ─── PRIMITIVES ───────────────────────────────────────────────────────────────

/**
 * Returns true if the value is a syntactically valid email address.
 * @param {string} email
 * @returns {boolean}
 */
export function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

/**
 * Returns true if the value is a parseable absolute URL.
 * @param {string} url
 * @returns {boolean}
 */
export function validateUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (_) {
        return false;
    }
}

/**
 * Returns true if the value is non-null, non-undefined, and non-empty string.
 * @param {*} value
 * @returns {boolean}
 */
export function validateRequired(value) {
    if (value === null || value === undefined) return false;
    if (typeof value === 'string') return value.trim().length > 0;
    return true;
}

// ─── RESULT FACTORY ───────────────────────────────────────────────────────────

/**
 * Returns a standardised validation result object.
 * All validation functions that return structured results must use this factory.
 *
 * @param {boolean}  isValid
 * @param {string}   [message='']
 * @param {string[]} [errorFields=[]]
 * @returns {{ isValid: boolean, message: string, errorFields: string[] }}
 */
export function createValidationResult(isValid, message = '', errorFields = []) {
    return { isValid, message, errorFields };
}

// ─── DOMAIN VALIDATORS ────────────────────────────────────────────────────────

/**
 * Validates that a project object has all fields required to trigger the
 * n8n storyboard generation pipeline.
 *
 * Called by project-detail.page.js before dispatching generateStoryboard().
 *
 * NOTE: The DB field for audience is 'target_audience' (snake_case) — the
 * schema uses this key at the persistence layer. The project object returned
 * by verifyProjectAccess uses the raw DB keys, so we check 'target_audience'.
 *
 * @param {object} project - Authoritative project record from verifyProjectAccess.
 * @returns {{ isValid: boolean, message: string, failedField?: string }}
 */
export function validateProjectForGeneration(project) {
    if (!project) {
        return createValidationResult(false, 'No project data available.', ['project']);
    }

    const requiredFields = [
        { key: 'title',           label: 'Project name' },
        { key: 'description',     label: 'Project description' },
        { key: 'goal',            label: 'Project goal' },
        { key: 'offer',           label: 'Offer' },
        { key: 'target_audience', label: 'Target audience' },
        { key: 'misconception',   label: 'Misconception' }
    ];

    for (const { key, label } of requiredFields) {
        const value = project[key];
        if (!value || (typeof value === 'string' && value.trim() === '')) {
            console.warn(`${VERSION} validateProjectForGeneration: missing field "${key}".`);
            return {
                isValid:     false,
                message:     `"${label}" is required before generating a storyboard.`,
                failedField: key
            };
        }
    }

    return createValidationResult(true);
}

// ─── FORMATTERS ───────────────────────────────────────────────────────────────

/**
 * Converts a snake_case or kebab-case slug into Title Case display text.
 * @param {string} slug
 * @returns {string}
 */
export function humanizeSlug(slug) {
    if (!slug) return '';
    return slug
        .split(/[_-]/)
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}