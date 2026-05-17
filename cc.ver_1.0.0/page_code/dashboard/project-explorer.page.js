/**
 * [ FILE NAME : project-explorer.page__v.2.2.0 ]
 * Page: Project Explorer
 * Path: /page_code/dashboard/project-explorer.page.js
 * Version: [ PROJECT EXPLORER : v.2.2.0 ]
 *
 * Refactor notes (v.2.1.0 → v.2.2.0)
 * ─────────────────────────────────────────────────────────────────────────────
 * [FIX-IMPORT-03] safeShow / safeHide import path corrected
 *
 *   ERROR (runtime):  ReferenceError on every page load — safeShow and
 *   safeHide do not exist in the module resolved from 'public/utils/validation'.
 *
 *   ROOT CAUSE:
 *     validation.js was refactored in v.2.0.0 (CR-01 / SF-04) to remove all
 *     UI helpers. safeShow and safeHide were moved to public/utils/ui.js,
 *     which is the sole authoritative source for UI primitives per CR-01.
 *     The v.2.1.0 file header acknowledged the v.2.0.0 import fix but
 *     incorrectly re-pointed the import back to validation.js, recreating
 *     the exact bug it claimed to fix.
 *
 *   FIX:
 *     Import safeShow and safeHide from 'public/utils/ui' — the correct
 *     location per CR-01 and the ui.js v.2.0.0 module contract.
 *
 * All other behaviour is identical to v.2.1.0.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Refactor notes (v.2.0.0 → v.2.1.0) — preserved for history
 * ─────────────────────────────────────────────────────────────────────────────
 * ISSUE#1 — Default Image
 *   onItemReady now reads itemData.firstFrameImage and assigns it to
 *   #projectPreviewImage. Falls back to DEFAULT_PROJECT_IMAGE if the field
 *   is absent or empty (image not yet generated).
 *
 * ISSUE#2 — No Projects empty state
 *   renderProjectList() now toggles #noProjects (expand/collapse) alongside
 *   #projectRepeater. When the list is empty: #noProjects is shown,
 *   #projectRepeater and #btnLoadMore are hidden. When projects exist:
 *   #noProjects is hidden, #projectRepeater is shown.
 *
 * ISSUE#3 — Click events on all four repeater interactive elements
 *   #projectPreviewImage, #txtProjectTitle, #txtProjectDescription, and
 *   #btnLauchProject all invoke the same navigateToDetail handler so any
 *   touch target navigates to the project detail page.
 *
 * ISSUE#5 — URL uses /project/{_id}
 *   Removed slugify() and all slug-based navigation. All wixLocation.to()
 *   calls now use the stable /project/${itemData._id} path. Slug-based URLs
 *   break when a project title is renamed; _id-based URLs are permanent.
 *
 * PAGINATION — preserved from v.2.0.0 (SC-02 / SC-07)
 *   Load More pattern with _nextCursor accumulation is retained.
 *   The cursor value is an opaque string passed back to getMyProjects()
 *   unchanged; the backend (project.web.js v2.8.0+) uses it as a skip
 *   offset for page-based pagination.
 *
 * Canvas element requirements
 * ─────────────────────────────────────────────────────────────────────────────
 *   #projectRepeater        — repeater bound to project list
 *     └─ #projectPreviewImage  — image element (Issue#1, Issue#3)
 *     └─ #txtProjectTitle      — project title text (Issue#3)
 *     └─ #txtProjectDescription — description text (Issue#3)
 *     └─ #btnLauchProject      — launch CTA button (Issue#3) [sic — matches canvas name]
 *   #noProjects             — empty-state container (Issue#2)
 *   #projectCount           — text element showing total count
 *   #btnProject             — "New Project" button
 *   #btnLoadMore            — "Load More" button (hidden when no further pages)
 *   #loadingSkeleton        — collapsible loading placeholder (shown on boot)
 */

import wixLocation from 'wix-location';
import wixWindow   from 'wix-window';
import { getMyProjects, getUserProjectCount } from 'backend/services/project.web';
import { showToaster }                        from 'public/utils/notification';
// [FIX-IMPORT-03] safeShow / safeHide belong in ui.js (CR-01 / SF-04).
// validation.js v.2.0.0 removed these exports. Importing from the correct source.
import { safeShow, safeHide }                 from 'public/utils/ui';

const VERSION = '[ PROJECT EXPLORER : v.2.2.0 ]';

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

/**
 * Issue#1 — Fallback image when a project has no firstFrameImage yet.
 */
const DEFAULT_PROJECT_IMAGE = 'https://static.wixstatic.com/media/155164_a0720ebcd82e421c88a366ee8a6f748f~mv2.png';

// ─── MODULE STATE ─────────────────────────────────────────────────────────────

/**
 * Cursor returned by the last getMyProjects() call.
 * null   → no further pages available.
 * string → pass to the next getMyProjects() call for the next page.
 */
let _nextCursor = null;

/**
 * Accumulated project list across all loaded pages.
 * Always assigned as a full replacement array so Wix diffs efficiently.
 */
let _projects   = [];

/** Prevents concurrent load / load-more calls. */
let _isLoading  = false;

// ─── BOOT ─────────────────────────────────────────────────────────────────────

$w.onReady(async function () {
    console.log(`${VERSION} Initializing...`);

    // CRITICAL: onItemReady MUST be registered synchronously before any async
    // calls. Registering it inside an async callback causes Wix to skip the
    // handler on initial data binding, resulting in a blank repeater.
    registerRepeaterItemReady();

    // Show loading skeleton; hide content areas until data resolves
    safeShow('#loadingSkeleton');
    safeHide('#projectRepeater');
    safeHide('#noProjects');
    safeHide('#btnLoadMore');

    handleQueryStatus();
    await loadInitialDashboard();

    $w('#btnProject').onClick(() => openProjectModal());
    $w('#btnLoadMore').onClick(() => loadMoreProjects());
});

// ─── REPEATER ITEM READY ──────────────────────────────────────────────────────

/**
 * Registers the onItemReady handler.
 * Called synchronously inside $w.onReady before any awaits.
 *
 * Issue#1 — Default Image: reads firstFrameImage; falls back to constant.
 * Issue#3 — Click Events:  all four interactive elements share navigateToDetail.
 * Issue#5 — URL:           uses /project/{_id}, no slug.
 */
function registerRepeaterItemReady() {
    $w('#projectRepeater').onItemReady(($item, itemData) => {

        // ── Issue#1: Default image ─────────────────────────────────────────
        const imageSrc = (itemData.firstFrameImage && itemData.firstFrameImage.trim() !== '')
            ? itemData.firstFrameImage
            : DEFAULT_PROJECT_IMAGE;

        $item('#projectPreviewImage').src = imageSrc;

        // ── Text fields ───────────────────────────────────────────────────
        $item('#txtProjectTitle').text       = itemData.title       || 'Untitled Project';
        $item('#txtProjectDescription').text = itemData.description || 'No description provided.';

        // ── Issue#3 + Issue#5: Unified navigation handler ────────────────
        const navigateToDetail = () => {
            console.log(`${VERSION} Navigating to project: ${itemData._id}`);
            wixLocation.to(`/project/${itemData._id}`);
        };

        $item('#projectPreviewImage').onClick(navigateToDetail);
        $item('#txtProjectTitle').onClick(navigateToDetail);
        $item('#txtProjectDescription').onClick(navigateToDetail);
        $item('#btnLauchProject').onClick(navigateToDetail);   // [sic — matches canvas element name]
    });
}

// ─── QUERY STATUS ─────────────────────────────────────────────────────────────

/**
 * Reads URL query parameters and surfaces toasters after CRUD redirects.
 */
function handleQueryStatus() {
    const status = wixLocation.query?.status;
    if (status === 'updated') showToaster('Project saved successfully.', 'success');
    if (status === 'created') showToaster('New project created successfully.', 'success');
    if (status === 'deleted') showToaster('Project deleted.', 'success');
}

// ─── INITIAL LOAD ─────────────────────────────────────────────────────────────

/**
 * Fetches the project count and first page in parallel.
 * Populates the count display, repeater, and Load More state.
 */
async function loadInitialDashboard() {
    if (_isLoading) return;
    _isLoading = true;

    try {
        const [countRes, projectRes] = await Promise.all([
            getUserProjectCount(),
            getMyProjects()
        ]);

        // ── Count display ────────────────────────────────────────────────
        if (countRes.ok) {
            const n = countRes.count;
            $w('#projectCount').text = `You currently have ${n} project${n === 1 ? '' : 's'}.`;
        }

        // ── Repeater ─────────────────────────────────────────────────────
        if (projectRes.ok) {
            _projects   = projectRes.data       || [];
            _nextCursor = projectRes.nextCursor || null;
            renderProjectList(_projects);
            updateLoadMoreButton();
        } else {
            console.warn(`${VERSION} loadInitialDashboard: getMyProjects failed.`);
        }

    } catch (err) {
        console.error(`${VERSION} loadInitialDashboard error:`, err);
        showToaster('Unable to load projects. Please refresh the page.', 'error');
    } finally {
        _isLoading = false;
        safeHide('#loadingSkeleton');
    }
}

// ─── LOAD MORE ────────────────────────────────────────────────────────────────

/**
 * Fetches the next page of projects and appends them to the repeater.
 * Called by the #btnLoadMore onClick handler.
 *
 * Only fires when _nextCursor is non-null (enforced by updateLoadMoreButton).
 * The cursor is an opaque string from the backend — passed back unchanged.
 */
async function loadMoreProjects() {
    if (_isLoading || !_nextCursor) return;
    _isLoading = true;

    console.log(`${VERSION} Loading next page with cursor: ${_nextCursor}`);

    try {
        const res = await getMyProjects({ cursor: _nextCursor });

        if (res.ok) {
            _projects   = [..._projects, ...(res.data || [])];
            _nextCursor = res.nextCursor || null;
            renderProjectList(_projects);
            updateLoadMoreButton();
        } else {
            console.warn(`${VERSION} loadMoreProjects: getMyProjects failed.`);
            showToaster('Unable to load more projects. Please try again.', 'error');
        }

    } catch (err) {
        console.error(`${VERSION} loadMoreProjects error:`, err);
        showToaster('Unable to load more projects. Please try again.', 'error');
    } finally {
        _isLoading = false;
    }
}

// ─── RENDER ───────────────────────────────────────────────────────────────────

/**
 * Assigns data to the repeater and toggles visibility of the list and
 * the empty state.
 *
 * Issue#2 — No Projects:
 *   Empty list  → collapse #projectRepeater, expand #noProjects.
 *   Has items   → collapse #noProjects, expand #projectRepeater.
 *
 * onItemReady is already registered — only data assignment is needed here.
 *
 * @param {Array} projects
 */
function renderProjectList(projects) {
    if (!projects || projects.length === 0) {
        $w('#projectRepeater').data = [];
        safeHide('#projectRepeater');
        safeShow('#noProjects');
        console.log(`${VERSION} No projects. Empty state shown.`);
        return;
    }

    safeHide('#noProjects');
    $w('#projectRepeater').data = projects;
    safeShow('#projectRepeater');
    console.log(`${VERSION} Rendered ${projects.length} project(s).`);
}

/**
 * Shows or hides #btnLoadMore based on whether a next page cursor exists.
 */
function updateLoadMoreButton() {
    if (_nextCursor) {
        safeShow('#btnLoadMore');
    } else {
        safeHide('#btnLoadMore');
    }
}

// ─── MODAL ────────────────────────────────────────────────────────────────────

/**
 * Opens the Project Settings lightbox in CREATE mode.
 * On success: resets pagination state and reloads from page 1 so the new
 * project appears at the top (newest-first ordering).
 * On error: surfaces the message from the modal's error payload via toaster.
 */
async function openProjectModal() {
    try {
        const result = await wixWindow.openLightbox('Project');

        if (result?.updated) {
            console.log(`${VERSION} New project created. Resetting and reloading dashboard.`);

            _projects   = [];
            _nextCursor = null;

            safeShow('#loadingSkeleton');
            safeHide('#projectRepeater');
            safeHide('#noProjects');

            await loadInitialDashboard();
            showToaster('Project created successfully!', 'success');

        } else if (result?.errorMessage) {
            showToaster(result.errorMessage, 'error');
        }

    } catch (err) {
        console.error(`${VERSION} openProjectModal error:`, err);
    }
}

// ─── DEBUG EXPORT ─────────────────────────────────────────────────────────────

export function debugPageState() {
    return {
        version:      '2.2.0',
        projectCount: _projects.length,
        nextCursor:   _nextCursor,
        isLoading:    _isLoading,
        timestamp:    new Date().toISOString()
    };
}