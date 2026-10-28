/**
 * Background Service Worker for Website Locker (Manifest V3)
 * 
 * Responsibilities:
 * - Monitors top-level navigations via chrome.webNavigation
 * - Detects protected URLs and redirects unauthorized visits to lock.html
 * - Manages TAB-SPECIFIC session-based authorizations with expiration checks
 * - Immediately purges authorizations when a tab is closed (chrome.tabs.onRemoved)
 * - Immediately purges authorizations when a tab navigates away from the protected domain
 * - Securely verifies lock challenges and restores original destination URLs
 * - Handles service-worker suspension gracefully using chrome.storage.session
 */

import { AUTH_EXPIRY_MS, normalizeUrl, verifyPassword } from './security.js';

/**
 * Helper to get session storage safely.
 */
async function getSessionData() {
  try {
    return await chrome.storage.session.get({
      authorizations: {},
      pendingChallenges: {}
    });
  } catch (err) {
    console.error('Error reading chrome.storage.session:', err);
    return { authorizations: {}, pendingChallenges: {} };
  }
}

/**
 * Helper to set session storage safely.
 */
async function setSessionData(data) {
  try {
    await chrome.storage.session.set(data);
  } catch (err) {
    console.error('Error writing chrome.storage.session:', err);
  }
}

/**
 * Checks whether valid temporary authorization exists for a specific tab and normalized URL.
 * Scoped strictly to the tab (tabId) so closing a tab or opening a new tab always requires the password.
 * Also cleans up expired authorization on every navigation check.
 * 
 * @param {number} tabId
 * @param {string} normalizedUrl
 * @returns {Promise<boolean>}
 */
async function isAuthorized(tabId, normalizedUrl) {
  if (!tabId || !normalizedUrl) {
    return false;
  }

  const session = await getSessionData();
  const authorizations = session.authorizations || {};
  const authKey = `${tabId}:${normalizedUrl}`;
  const auth = authorizations[authKey];

  if (!auth) {
    return false;
  }

  const now = Date.now();
  if (typeof auth.expiresAt !== 'number' || now >= auth.expiresAt) {
    // Expired authorization - purge it
    delete authorizations[authKey];
    await setSessionData({ authorizations });
    return false;
  }

  return true;
}

/**
 * Handles navigation events (both onBeforeNavigate and onHistoryStateUpdated).
 * 
 * @param {chrome.webNavigation.WebNavigationParentedCallbackDetails} details
 */
async function handleNavigation(details) {
  // Only process top-level window navigation (main frame), not iframes
  if (details.frameId !== 0) {
    return;
  }

  const rawUrl = details.url;
  if (!rawUrl || typeof rawUrl !== 'string') {
    return;
  }

  // Never intercept extension or internal browser pages
  const extensionPrefix = chrome.runtime.getURL('');
  if (
    rawUrl.startsWith(extensionPrefix) ||
    rawUrl.startsWith('chrome:') ||
    rawUrl.startsWith('chrome-extension:') ||
    rawUrl.startsWith('about:') ||
    rawUrl.startsWith('data:') ||
    rawUrl.startsWith('blob:')
  ) {
    return;
  }

  // Attempt normalization
  let normalizedUrl;
  try {
    normalizedUrl = normalizeUrl(rawUrl);
  } catch {
    // Unsupported protocol or invalid URL - do not intercept
    return;
  }

  // If this tab navigates to a different URL/domain, revoke previous authorizations for other URLs in this tab
  const session = await getSessionData();
  const authorizations = session.authorizations || {};
  let authModified = false;

  for (const key of Object.keys(authorizations)) {
    const item = authorizations[key];
    if (item && item.tabId === details.tabId && item.normalizedUrl !== normalizedUrl) {
      delete authorizations[key];
      authModified = true;
    }
  }

  if (authModified) {
    await setSessionData({ authorizations });
  }

  // Check if this URL is registered as a protected website
  const localData = await chrome.storage.local.get({ protectedWebsites: [] });
  const protectedWebsites = Array.isArray(localData.protectedWebsites) ? localData.protectedWebsites : [];
  const isProtected = protectedWebsites.some(site => site.url === normalizedUrl);

  if (!isProtected) {
    // Unregistered website - do not interfere
    return;
  }

  // Check if valid temporary authorization exists for THIS specific tab
  const authorized = await isAuthorized(details.tabId, normalizedUrl);
  if (authorized) {
    // Access is granted under active temporary authorization for this tab
    return;
  }

  // Check if this tab is already pending redirect for this URL (prevent duplicate redirects)
  const currentSession = await getSessionData();
  const pendingChallenges = currentSession.pendingChallenges || {};
  const now = Date.now();

  const activeExistingChallenge = Object.values(pendingChallenges).find(
    c => c.tabId === details.tabId && c.normalizedUrl === normalizedUrl && (now - c.createdAt < 3000)
  );

  if (activeExistingChallenge) {
    return;
  }

  // Clean up any stale challenges older than 10 minutes
  for (const cid of Object.keys(pendingChallenges)) {
    if (!pendingChallenges[cid] || now - pendingChallenges[cid].createdAt > 10 * 60 * 1000) {
      delete pendingChallenges[cid];
    }
  }

  // Create a new cryptographic challenge bound to this tabId
  const challengeId = crypto.randomUUID();
  pendingChallenges[challengeId] = {
    targetUrl: details.url,
    normalizedUrl: normalizedUrl,
    tabId: details.tabId,
    createdAt: now
  };

  await setSessionData({ pendingChallenges });

  // Redirect the tab to lock.html with the challenge ID
  const lockPageUrl = chrome.runtime.getURL(`lock.html?challenge=${encodeURIComponent(challengeId)}`);
  try {
    await chrome.tabs.update(details.tabId, { url: lockPageUrl });
  } catch (err) {
    console.error('Failed to update tab URL to lock screen:', err);
  }
}

// Listen to initial navigation requests
chrome.webNavigation.onBeforeNavigate.addListener(handleNavigation);

// Listen to client-side Single Page Application (SPA) URL changes
chrome.webNavigation.onHistoryStateUpdated.addListener(handleNavigation);

/**
 * CRITICAL: When a tab is closed, instantly destroy all authorizations and challenges for that tab.
 * This guarantees that reopening the website in a new tab will ALWAYS ask for the password.
 */
chrome.tabs.onRemoved.addListener(async (closedTabId) => {
  try {
    const session = await getSessionData();
    let modified = false;

    // Purge all authorizations tied to the closed tab
    const authorizations = session.authorizations || {};
    for (const key of Object.keys(authorizations)) {
      if (authorizations[key]?.tabId === closedTabId || key.startsWith(`${closedTabId}:`)) {
        delete authorizations[key];
        modified = true;
      }
    }

    // Purge any pending challenges tied to the closed tab
    const pendingChallenges = session.pendingChallenges || {};
    for (const cid of Object.keys(pendingChallenges)) {
      if (pendingChallenges[cid]?.tabId === closedTabId) {
        delete pendingChallenges[cid];
        modified = true;
      }
    }

    if (modified) {
      await setSessionData({ authorizations, pendingChallenges });
    }
  } catch (err) {
    console.error('Error cleaning up closed tab authorization:', err);
  }
});

/**
 * Handle incoming messages from extension contexts (lock screen).
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Validate sender security: strictly allow only messages originating from our extension
  if (!sender || sender.id !== chrome.runtime.id) {
    sendResponse({ success: false, error: 'Unauthorized message sender.' });
    return false;
  }

  if (message?.type === 'VERIFY_PASSWORD') {
    (async () => {
      const { challengeId, password } = message;

      if (!challengeId || typeof challengeId !== 'string' || !password || typeof password !== 'string') {
        sendResponse({ success: false, error: 'Invalid verification request.' });
        return;
      }

      const session = await getSessionData();
      const pendingChallenges = session.pendingChallenges || {};
      const challenge = pendingChallenges[challengeId];

      if (!challenge) {
        sendResponse({ success: false, error: 'Lock session expired or invalid. Please reopen the website.' });
        return;
      }

      // Check challenge age (10-minute timeout)
      if (Date.now() - challenge.createdAt > 10 * 60 * 1000) {
        delete pendingChallenges[challengeId];
        await setSessionData({ pendingChallenges });
        sendResponse({ success: false, error: 'Lock session expired. Please reopen the website.' });
        return;
      }

      // Verify that the target URL is still in protected websites
      const localData = await chrome.storage.local.get({ protectedWebsites: [] });
      const protectedWebsites = Array.isArray(localData.protectedWebsites) ? localData.protectedWebsites : [];
      const site = protectedWebsites.find(s => s.url === challenge.normalizedUrl);

      if (!site) {
        delete pendingChallenges[challengeId];
        await setSessionData({ pendingChallenges });
        sendResponse({ success: false, error: 'This website is no longer protected.' });
        return;
      }

      // Cryptographically verify password against stored PBKDF2 hash
      const isMatch = await verifyPassword(password, site.passwordHash, site.salt);

      if (!isMatch) {
        sendResponse({ success: false, error: 'Incorrect password.' });
        return;
      }

      // Correct password! Grant temporary authorization strictly for THIS tab and THIS normalized URL
      const authorizations = session.authorizations || {};
      const authKey = `${challenge.tabId}:${challenge.normalizedUrl}`;
      authorizations[authKey] = {
        tabId: challenge.tabId,
        normalizedUrl: challenge.normalizedUrl,
        grantedAt: Date.now(),
        expiresAt: Date.now() + AUTH_EXPIRY_MS
      };

      // Consume and remove the single-use challenge
      delete pendingChallenges[challengeId];

      await setSessionData({
        authorizations,
        pendingChallenges
      });

      sendResponse({
        success: true,
        redirectUrl: challenge.targetUrl
      });
    })().catch((err) => {
      console.error('Error in VERIFY_PASSWORD handler:', err);
      sendResponse({ success: false, error: 'Verification error occurred.' });
    });

    return true; // Keep asynchronous message response open
  }

  return false;
});
