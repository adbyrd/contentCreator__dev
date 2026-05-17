/**
 * Page Code: Profile Settings
 * Path: /page_code/dashboard/profilesetting.page.js
 * Version: [ PROFILE SETTINGS : v.2.3.0 ]
 */

import wixWindow from 'wix-window';
import { getProfile } from 'backend/services/profile.web';
import { showToaster } from 'public/utils/notification';

const VERSION = '[ PROFILE SETTINGS : v.2.3.0 ]';
let _profileData = null;

$w.onReady(async function () {
    console.log(`${VERSION} Dashboard: Profile Settings Initializing...`);
    _profileData = await loadProfileData();
    
    if (_profileData) {
        renderProfile(_profileData);
    } else {
        console.warn(`${VERSION} Failed to load profile data on initialization.`);
    }
    
    wireEventHandlers();
});

async function loadProfileData() {
    try {
        const response = await getProfile();
        if (response.ok) {
            console.log(`${VERSION} Profile data loaded successfully.`);
            return response.data;
        }
        throw new Error(response.error);
    } catch (err) {
        console.error(`${VERSION} Error loading profile data:`, err);
        return null;
    }
}

function renderProfile(profile) {
    if (!profile) return;

    $w('#displayLogo').src = profile.logo || "https://static.wixstatic.com/media/155164_1f5df41ae90741139acb1148f2b4f864~mv2.png";
    $w('#displayCompanyName').text = profile.companyName || "";
    $w('#displayCompanyURL').text = profile.companyURL || "";
    $w('#displayCompanyEmail').text = profile.companyEmail || "";
    $w('#displayCompanyPhone').text = profile.companyPhone || "";
    $w('#displayCompanyZipCode').text = profile.companyZipCode || "";
    $w('#displayCompanyDescription').text = profile.companyDescription || "";

    $w('#displayCategory').text = profile.primaryCategory || "";
    $w('#displaySubCategory').text = profile.subCategory || "";
    $w('#displayCustomerType').text = profile.customerType || "";
    
    console.log(`${VERSION} Profile UI rendered with latest data.`);
}

function wireEventHandlers() {
    $w('#btnCompany').onClick(() => openSettingsModal('Company'));
    $w('#btnCategory').onClick(() => openSettingsModal('Category'));
    $w('#btnMedia').onClick(() => openSettingsModal('Media'));
}

async function openSettingsModal(modalId) {
    try {
        console.log(`${VERSION} Opening modal: ${modalId}`);
        const result = await wixWindow.openLightbox(modalId, { profile: _profileData });

        if (result && result.updated) {
            console.log(`${VERSION} Update detected from ${modalId}. Refreshing UI.`);
            _profileData = await loadProfileData();
            renderProfile(_profileData);
            showToaster("Settings updated successfully.", "success");
        }
    } catch (err) {
        console.error(`${VERSION} Error handling modal close for ${modalId}:`, err);
    }
}