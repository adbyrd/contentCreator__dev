/**
 * Modal: Brand/Media Settings
 * Path: /page_code/modals/settings-brand.modal.js
 * Version: [ BRAND & MEDIA SETTINGS : v.1.0.0 ]
 */

import wixWindow from 'wix-window';
import { updateProfile } from 'backend/services/profile.web';

const VERSION = '[ BRAND & MEDIA SETTINGS : v.1.0.0 ]';
const DEFAULT_AVATAR = "https://static.wixstatic.com/media/155164_1f5df41ae90741139acb1148f2b4f864~mv2.png";
const MSG_SAVING = "Saving...";

let _uploadedFileUrl = null;
let _isSaving = false;

$w.onReady(function () {
    const context = wixWindow.lightbox.getContext();
    
    if (context?.profile?.logo) {
        $w('#imgLogoPreview').src = context.profile.logo;
        _uploadedFileUrl = context.profile.logo;
    } else {
        $w('#imgLogoPreview').src = DEFAULT_AVATAR;
    }

    setupUI();
    wireEventHandlers();
});

function setupUI() {
    $w('#uploadProgressBar').value = 0;
    $w('#uploadProgressBar').hide();
}

function wireEventHandlers() {
    $w('#uploadButton').onChange(async () => {
        if ($w('#uploadButton').value.length > 0) {
            await handleFileUpload();
        }
    });

    $w('#btnSave').onClick(() => saveBrandSettings());
    $w('#btnCancel').onClick(() => wixWindow.lightbox.close({ updated: false }));
}

async function handleFileUpload() {
    $w('#uploadProgressBar').show();
    $w('#uploadProgressBar').value = 10;

    try {
        const uploadResult = await $w('#uploadButton').startUpload();
        
        $w('#uploadProgressBar').value = 100;
        _uploadedFileUrl = uploadResult.url;
        $w('#imgLogoPreview').src = _uploadedFileUrl;
        
        console.log(`${VERSION} Logo uploaded to temporary storage:`, _uploadedFileUrl);
        setTimeout(() => $w('#uploadProgressBar').hide(), 1000);

    } catch (err) {
        console.error(`${VERSION} Upload failed:`, err);
        $w('#uploadProgressBar').hide();
    }
}

async function saveBrandSettings() {
    if (_isSaving || !_uploadedFileUrl) return;

    _isSaving = true;
    $w('#btnSave').label = MSG_SAVING;
    $w('#btnSave').disable();

    try {
        const payload = {
            profile: {
                logo: _uploadedFileUrl
            }
        };

        const response = await updateProfile(payload);

        if (response.ok) {
            console.log(`${VERSION} Brand profile updated.`);
            wixWindow.lightbox.close({ updated: true });
        } else {
            throw new Error(response.error?.message || "Update failed");
        }
    } catch (err) {
        console.error(`${VERSION} Save error:`, err);
        $w('#btnSave').label = "Save Logo";
        $w('#btnSave').enable();
        _isSaving = false;
    }
}