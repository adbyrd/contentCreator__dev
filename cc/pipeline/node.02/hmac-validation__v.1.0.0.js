/**
 * HMAC Validation
 * Node 2
 * @version 1.0.0
 * 
 * This code runs in an n8n Function node to validate incoming webhook requests from the Wix app.
 * It checks for a secret key in the payload against an environment variable, and ensures all required fields are present.
 * If validation fails, it throws an error to reject the webhook call.
 * If validation succeeds, it returns the payload for further processing in the n8n workflow.
 **/

const crypto = require('crypto');
const payload = $input.item.json;
const receivedSecret = payload.secretKey;
const expectedSecret = $env.N8N_CALLBACK_SECRET_KEY;

if (!receivedSecret || receivedSecret !== expectedSecret) {
  throw new Error('[N8N PIPELINE : v1.0.0] HMAC_VALIDATION_FAILED — Unauthorized webhook call rejected.');
}

// Verify all required fields are present
const required = ['projectId','owner','companyName','companyDescription',
  'primaryCategory','customerType','title','goal','offer',
  'misconception','targetAudience'];

for (const field of required) {
  if (!payload[field]) {
    throw new Error(`[N8N PIPELINE : v1.0.0] MISSING_FIELD: ${field}`);
  }
}

return [{ json: payload }];