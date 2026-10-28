import { normalizeUrl, hashPassword } from './security.js';

const urlInput = document.getElementById('urlInput');
const passwordInput = document.getElementById('passwordInput');
const addButton = document.getElementById('addButton');
const addNewButton = document.getElementById('addNewButton');

// Focus URL input on initial popup display
urlInput.focus();

/**
 * Saves or updates a protected website.
 */
async function handleAdd() {
  const rawUrl = urlInput.value.trim();
  const password = passwordInput.value;

  if (!rawUrl) {
    alert('Please enter a website URL.');
    urlInput.focus();
    return;
  }

  if (!password) {
    alert('Please enter a password.');
    passwordInput.focus();
    return;
  }

  let normalizedUrl;
  try {
    normalizedUrl = normalizeUrl(rawUrl);
  } catch (err) {
    alert(err.message || 'Invalid website URL.');
    urlInput.focus();
    return;
  }

  try {
    // Cryptographically derive salt and PBKDF2 hash using Web Crypto API
    const { hash, salt } = await hashPassword(password);

    // Retrieve current protected websites
    const data = await chrome.storage.local.get({ protectedWebsites: [] });
    const websites = Array.isArray(data.protectedWebsites) ? data.protectedWebsites : [];

    // Check if this normalized URL already exists
    const existingIndex = websites.findIndex(w => w.url === normalizedUrl);

    if (existingIndex >= 0) {
      // Update existing website with the new password hash and salt
      websites[existingIndex].passwordHash = hash;
      websites[existingIndex].salt = salt;
      websites[existingIndex].createdAt = new Date().toISOString();
    } else {
      // Append new protected website record conforming to required schema
      websites.push({
        id: crypto.randomUUID(),
        url: normalizedUrl,
        passwordHash: hash,
        salt: salt,
        createdAt: new Date().toISOString()
      });
    }

    await chrome.storage.local.set({ protectedWebsites: websites });

    // Invalidate any existing session authorizations for this URL so password is asked immediately
    try {
      const sessionData = await chrome.storage.session.get({ authorizations: {} });
      const authorizations = sessionData.authorizations || {};
      let authChanged = false;
      for (const key of Object.keys(authorizations)) {
        if (authorizations[key]?.normalizedUrl === normalizedUrl) {
          delete authorizations[key];
          authChanged = true;
        }
      }
      if (authChanged) {
        await chrome.storage.session.set({ authorizations });
      }
    } catch {
      // Best-effort session storage cleanup
    }

    // Clear both fields after successfully saving
    urlInput.value = '';
    passwordInput.value = '';
    urlInput.focus();

    alert('Website protected successfully.');
  } catch (err) {
    alert('Error saving website: ' + (err.message || err));
  }
}

/**
 * Clears both input fields so the user can enter another website and its password.
 */
function handleAddNew() {
  urlInput.value = '';
  passwordInput.value = '';
  urlInput.focus();
}

addButton.addEventListener('click', handleAdd);
addNewButton.addEventListener('click', handleAddNew);

// Convenience: Enter in password input triggers Add
passwordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    handleAdd();
  }
});

