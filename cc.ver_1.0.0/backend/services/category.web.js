/**
 * Service: Category Management
 * Path: /backend/services/category.web.js
 * Version: [ CATEGORY MANAGEMENT : v.2.0.0 ]
 *
 * SC-04 — Taxonomy Cache
 * ──────────────────────
 * getTaxonomy() previously ran a full wixData.query() of up to 1,000 rows
 * on every call, from every user session. The taxonomy is entirely static —
 * it changes only when an administrator adds or removes categories.
 *
 * At 5,000 members with 10% opening the Category modal concurrently, the
 * old pattern produced ~500 identical full-table reads in a short window.
 *
 * This version introduces a two-tier cache:
 *
 *   Tier 1 — Module-level in-process cache (_memoryCache).
 *     Wix does not guarantee a warm module between webMethod calls, but when
 *     the module IS warm (repeated calls within the same Velo instance), the
 *     in-process cache eliminates the DB round-trip entirely.
 *     TTL: MEMORY_CACHE_TTL_MS (5 minutes).
 *
 *   Tier 2 — CMS collection cache (taxonomyCache).
 *     A single record in the taxonomyCache collection holds the serialised
 *     taxonomy payload and a timestamp. When the module is cold or the
 *     memory cache has expired, one lightweight single-record read satisfies
 *     the request instead of the full BusinessCategories query.
 *     TTL: CMS_CACHE_TTL_MS (24 hours).
 *
 *   Cold path (both caches miss or expired):
 *     Full query against BusinessCategories is executed once, the result is
 *     serialised and written back to the CMS cache record, and returned.
 *
 * Required CMS collections:
 *   categories       — source taxonomy (parentCategory, parentLabel,
 *                      subCategory, subLabel, active fields)
 *   taxonomyCache    — single-record cache (fields: payload TEXT, updatedAt DATE)
 *
 * Exports:
 *   getTaxonomy()             — returns taxonomy for dropdown population
 *   refreshTaxonomyCache()    — admin-only: forces a cold rebuild of the cache
 */

import wixData             from 'wix-data';
import { webMethod, Permissions } from 'wix-web-module';

const VERSION = '[ CATEGORY MANAGEMENT : v.2.0.0 ]';

// ─── CONSTANTS ────────────────────────────────────────────────────────────────

const COLLECTION_CATEGORIES   = 'categories';
const COLLECTION_CACHE        = 'taxonomyCache';

// Tier 1 — In-process memory cache TTL (ms).
// Caps repeated calls within the same warm Velo instance.
const MEMORY_CACHE_TTL_MS     = 5 * 60 * 1000;   // 5 minutes

// Tier 2 — CMS cache TTL (ms).
// Caps cold-start full-table reads. Admin must call refreshTaxonomyCache()
// after adding or removing categories if they want an immediate update.
const CMS_CACHE_TTL_MS        = 24 * 60 * 60 * 1000; // 24 hours

const DB_OPTIONS              = { suppressAuth: true };

// ─── TIER 1: IN-PROCESS MEMORY CACHE ─────────────────────────────────────────
// Module-level state — lives as long as this Velo instance is warm.

let _memoryCache          = null;   // { parentOptions, childrenByParent }
let _memoryCacheTimestamp = 0;      // ms timestamp of last population

// ─── HELPERS ──────────────────────────────────────────────────────────────────

/**
 * Normalises a raw DB row into parent/child option entries and merges them
 * into the running maps. Pure function — no side effects.
 *
 * @param {object} row       — raw wixData item from categories collection
 * @param {Map}    parentMap — accumulates unique parent options
 * @param {object} children  — accumulates children arrays keyed by parentValue
 */
function processRow(row, parentMap, children) {
    const pValue = (row.parentCategory || '').toString().trim();
    const pLabel = (row.parentLabel    || '').toString().trim();
    const cValue = (row.subCategory    || '').toString().trim();
    const cLabel = (row.subLabel       || '').toString().trim();

    if (!pValue || !pLabel) return;

    if (!parentMap.has(pValue)) {
        parentMap.set(pValue, { label: pLabel, value: pValue });
        children[pValue] = [];
    }

    if (cValue && cLabel) {
        children[pValue].push({ label: cLabel, value: cValue });
    }
}

/**
 * Runs the full query against the categories collection and assembles the
 * taxonomy object. Used by both the cold path and refreshTaxonomyCache().
 *
 * @returns {{ ok: boolean, parentOptions: array, childrenByParent: object, error?: string }}
 */
async function buildTaxonomyFromSource() {
    const { items } = await wixData
        .query(COLLECTION_CATEGORIES)
        .eq('active', true)
        .limit(1000)
        .find(DB_OPTIONS);

    if (items.length === 0) {
        console.warn(`${VERSION} buildTaxonomyFromSource: No active categories found.`);
        return { ok: false, error: 'EMPTY_COLLECTION', parentOptions: [], childrenByParent: {} };
    }

    const parentMap = new Map();
    const childrenByParent = {};

    items.forEach(row => processRow(row, parentMap, childrenByParent));

    const parentOptions = Array.from(parentMap.values())
        .sort((a, b) => a.label.localeCompare(b.label));

    Object.keys(childrenByParent).forEach(key => {
        childrenByParent[key].sort((a, b) => a.label.localeCompare(b.label));
    });

    console.log(`${VERSION} buildTaxonomyFromSource: Built ${parentOptions.length} parent categories.`);
    return { ok: true, parentOptions, childrenByParent };
}

/**
 * Writes a taxonomy object to the CMS cache collection.
 * Upserts the single cache record (insert if absent, update if present).
 *
 * @param {{ parentOptions: array, childrenByParent: object }} taxonomy
 */
async function writeCmsCache(taxonomy) {
    try {
        const payload  = JSON.stringify({ parentOptions: taxonomy.parentOptions, childrenByParent: taxonomy.childrenByParent });
        const existing = await wixData.query(COLLECTION_CACHE).limit(1).find(DB_OPTIONS);

        if (existing.items.length > 0) {
            await wixData.update(COLLECTION_CACHE, {
                _id:       existing.items[0]._id,
                payload,
                updatedAt: new Date().toISOString()
            }, DB_OPTIONS);
        } else {
            await wixData.insert(COLLECTION_CACHE, {
                payload,
                updatedAt: new Date().toISOString()
            }, DB_OPTIONS);
        }

        console.log(`${VERSION} writeCmsCache: Cache record written.`);
    } catch (err) {
        // Cache write failure is non-fatal — log and continue.
        console.warn(`${VERSION} writeCmsCache: Failed to write cache:`, err.message);
    }
}

// ─── GET TAXONOMY ─────────────────────────────────────────────────────────────

/**
 * Returns the taxonomy object for dropdown population in settings-category.modal.
 *
 * Resolution order:
 *   1. Tier 1 memory cache — zero DB calls when the Velo instance is warm.
 *   2. Tier 2 CMS cache    — one single-record read against taxonomyCache.
 *   3. Cold path           — full query against categories, result cached in both tiers.
 *
 * @returns {{ ok: boolean, parentOptions: array, childrenByParent: object, error?: string }}
 */
export const getTaxonomy = webMethod(Permissions.Anyone, async () => {
    try {
        const now = Date.now();

        // ── Tier 1: memory cache ────────────────────────────────────────────
        if (_memoryCache && (now - _memoryCacheTimestamp) < MEMORY_CACHE_TTL_MS) {
            console.log(`${VERSION} getTaxonomy: Served from memory cache.`);
            return { ok: true, ..._memoryCache };
        }

        // ── Tier 2: CMS cache ───────────────────────────────────────────────
        const cacheResult = await wixData.query(COLLECTION_CACHE).limit(1).find(DB_OPTIONS);
        const cacheRecord = cacheResult.items[0] || null;

        if (cacheRecord) {
            const age = now - new Date(cacheRecord.updatedAt).getTime();

            if (age < CMS_CACHE_TTL_MS) {
                try {
                    const parsed = JSON.parse(cacheRecord.payload);

                    // Promote to memory cache to save the CMS round-trip next time
                    _memoryCache          = parsed;
                    _memoryCacheTimestamp = now;

                    console.log(`${VERSION} getTaxonomy: Served from CMS cache (age: ${Math.round(age / 1000)}s).`);
                    return { ok: true, ...parsed };
                } catch (parseErr) {
                    // Malformed cache record — fall through to cold path
                    console.warn(`${VERSION} getTaxonomy: CMS cache parse failed, rebuilding:`, parseErr.message);
                }
            } else {
                console.log(`${VERSION} getTaxonomy: CMS cache expired (age: ${Math.round(age / 1000)}s). Rebuilding.`);
            }
        }

        // ── Cold path: full taxonomy build ──────────────────────────────────
        console.log(`${VERSION} getTaxonomy: Cache miss — querying categories collection.`);
        const taxonomy = await buildTaxonomyFromSource();

        if (!taxonomy.ok) {
            return taxonomy; // propagate EMPTY_COLLECTION error
        }

        // Populate both cache tiers
        _memoryCache          = { parentOptions: taxonomy.parentOptions, childrenByParent: taxonomy.childrenByParent };
        _memoryCacheTimestamp = now;
        await writeCmsCache(taxonomy);

        return { ok: true, parentOptions: taxonomy.parentOptions, childrenByParent: taxonomy.childrenByParent };

    } catch (err) {
        console.error(`${VERSION} getTaxonomy failure:`, err);
        return { ok: false, error: err.message, parentOptions: [], childrenByParent: {} };
    }
});

// ─── REFRESH TAXONOMY CACHE ───────────────────────────────────────────────────

/**
 * Admin-only: forces an immediate cold rebuild of both the CMS cache and the
 * in-process memory cache.
 *
 * Call this from the Wix API Explorer or an admin panel after adding or
 * removing categories from the categories collection. Regular members should
 * never call this — the Permissions.Admin guard enforces that.
 *
 * @returns {{ ok: boolean, parentOptions?: array, error?: string }}
 */
export const refreshTaxonomyCache = webMethod(Permissions.Admin, async () => {
    try {
        console.log(`${VERSION} refreshTaxonomyCache: Forced rebuild requested by admin.`);

        const taxonomy = await buildTaxonomyFromSource();

        if (!taxonomy.ok) {
            return { ok: false, error: taxonomy.error };
        }

        // Invalidate and repopulate both cache tiers
        _memoryCache          = { parentOptions: taxonomy.parentOptions, childrenByParent: taxonomy.childrenByParent };
        _memoryCacheTimestamp = Date.now();
        await writeCmsCache(taxonomy);

        console.log(`${VERSION} refreshTaxonomyCache: Complete. ${taxonomy.parentOptions.length} parent categories cached.`);
        return { ok: true, parentOptions: taxonomy.parentOptions };

    } catch (err) {
        console.error(`${VERSION} refreshTaxonomyCache failure:`, err);
        return { ok: false, error: err.message };
    }
});