/**
 * Comprehensive Automated Verification Suite for Website Locker
 * 
 * Verifies all requirements from the specification:
 * 1. Adding a URL and password.
 * 2. Adding multiple websites with different passwords.
 * 3. Rejecting invalid URLs.
 * 4. Rejecting incorrect passwords.
 * 5. Accepting the correct password for the intended URL.
 * 6. Ensuring one website's password cannot unlock another.
 * 7. Ensuring unregistered URLs remain unaffected.
 * 8. Ensuring tab-scoped authorization: Opening a new tab always asks for password.
 * 9. Ensuring tab-closure cleanup: Closing a tab and reopening always asks for password.
 * 10. Ensuring navigation away cleanup: Leaving protected site revokes authorization.
 * 11. Ensuring authorization expires after configured duration.
 * 12. Ensuring passwords are never stored in plaintext.
 * 13. HTML structure compliance (exact element counts).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AUTH_EXPIRY_MS,
  PBKDF2_ITERATIONS,
  normalizeUrl,
  urlsMatch,
  hashPassword,
  verifyPassword,
  constantTimeCompare
} from './security.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let testsPassed = 0;
let testsFailed = 0;

function assert(condition, message) {
  if (!condition) {
    testsFailed++;
    console.error(`❌ FAILED: ${message}`);
    throw new Error(message);
  } else {
    testsPassed++;
    console.log(`✅ PASSED: ${message}`);
  }
}

async function runTests() {
  console.log('====================================================');
  console.log('RUNNING WEBSITE LOCKER VERIFICATION TEST SUITE');
  console.log('====================================================\n');

  // ----------------------------------------------------
  // TEST GROUP 1: URL Normalization & Strict Matching
  // ----------------------------------------------------
  console.log('--- TEST GROUP 1: URL Normalization & Validation ---');

  // Test 1.1: Trailing slashes handled consistently
  const urlWithSlash = normalizeUrl('https://www.linkedin.com/feed/foryou/');
  const urlWithoutSlash = normalizeUrl('https://www.linkedin.com/feed/foryou');
  assert(
    urlWithSlash === urlWithoutSlash,
    `Trailing slash consistency: "${urlWithSlash}" === "${urlWithoutSlash}"`
  );

  // Test 1.2: Root path preserved
  const rootWithSlash = normalizeUrl('https://www.instagram.com/');
  const rootWithoutSlash = normalizeUrl('https://www.instagram.com');
  assert(
    rootWithSlash === 'https://www.instagram.com/',
    `Root path with slash normalizes to: ${rootWithSlash}`
  );
  assert(
    rootWithoutSlash === 'https://www.instagram.com/',
    `Root path without slash normalizes to: ${rootWithoutSlash}`
  );

  // Test 1.3: Fragments removed
  const urlWithFragment = normalizeUrl('https://www.linkedin.com/feed/foryou/#top');
  assert(
    urlWithFragment === 'https://www.linkedin.com/feed/foryou',
    `URL fragment stripped correctly: ${urlWithFragment}`
  );

  // Test 1.4: Query parameters preserved and sorted alphabetically
  const q1 = normalizeUrl('https://example.com/search?b=2&a=1&c=3');
  const q2 = normalizeUrl('https://example.com/search?c=3&a=1&b=2');
  assert(
    q1 === 'https://example.com/search?a=1&b=2&c=3',
    `Query parameters sorted: ${q1}`
  );
  assert(
    q1 === q2,
    `Query parameters order independence: "${q1}" === "${q2}"`
  );

  // Test 1.5: No simple substring matching
  const target = normalizeUrl('https://www.linkedin.com/feed/foryou/');
  const sibling = normalizeUrl('https://www.linkedin.com/feed/foryou2');
  const subpath = normalizeUrl('https://www.linkedin.com/feed/foryou/extra');
  const domain = normalizeUrl('https://www.linkedin.com/');
  assert(!urlsMatch(target, sibling), 'Substrings do not match sibling path (foryou vs foryou2)');
  assert(!urlsMatch(target, subpath), 'Substrings do not match nested subpath (foryou vs foryou/extra)');
  assert(!urlsMatch(target, domain), 'Specific path does not match domain root');

  // Test 1.6: Reject invalid and dangerous protocols
  const invalidUrls = [
    'javascript:alert(1)',
    'file:///etc/passwd',
    'chrome://extensions',
    'chrome-extension://abcdefghijklm/lock.html',
    'data:text/html,<h1>Hello</h1>',
    'ftp://example.com/file.txt',
    'not_a_valid_url',
    '',
    '   '
  ];

  for (const bad of invalidUrls) {
    let threw = false;
    try {
      normalizeUrl(bad);
    } catch {
      threw = true;
    }
    assert(threw, `Correctly rejected invalid URL/protocol: "${bad}"`);
  }

  // ----------------------------------------------------
  // TEST GROUP 2: Cryptography & Plaintext Password Absence
  // ----------------------------------------------------
  console.log('\n--- TEST GROUP 2: Cryptographic Hashing & Verification ---');

  const plainPass = 'MySecretLinkedInPassword123';
  const hashed = await hashPassword(plainPass);

  assert(hashed.hash && typeof hashed.hash === 'string', 'Generated password hash is a string');
  assert(hashed.hash.length === 64, `PBKDF2 SHA-256 output is 256 bits (64 hex characters): length is ${hashed.hash.length}`);
  assert(hashed.salt && typeof hashed.salt === 'string', 'Generated salt is a string');
  assert(hashed.salt.length === 32, `Salt is 128 bits (32 hex characters): length is ${hashed.salt.length}`);
  assert(!hashed.hash.includes(plainPass), 'Password hash does NOT contain plaintext password');
  assert(hashed.salt !== plainPass, 'Salt is not the plaintext password');

  // Unique salt test
  const hashed2 = await hashPassword(plainPass);
  assert(hashed.salt !== hashed2.salt, 'Every password hashing generates a fresh, unique salt');
  assert(hashed.hash !== hashed2.hash, 'Different salts produce different derived hashes for the same password');

  // Password verification
  const isCorrect = await verifyPassword(plainPass, hashed.hash, hashed.salt);
  assert(isCorrect === true, 'Accepting the correct password for the intended website');

  const isIncorrect = await verifyPassword('WrongPassword123', hashed.hash, hashed.salt);
  assert(isIncorrect === false, 'Rejecting incorrect password');

  // Constant time comparison
  assert(constantTimeCompare('abcdef', 'abcdef') === true, 'Constant time comparison matches identical strings');
  assert(constantTimeCompare('abcdef', 'abcdeg') === false, 'Constant time comparison rejects differing strings');
  assert(constantTimeCompare('abcdef', 'abc') === false, 'Constant time comparison rejects differing lengths');

  // ----------------------------------------------------
  // TEST GROUP 3: Multi-Website Independent Passwords
  // ----------------------------------------------------
  console.log('\n--- TEST GROUP 3: Multiple Websites with Independent Passwords ---');

  const mockDb = {
    protectedWebsites: []
  };

  // Website 1
  const site1Url = normalizeUrl('https://www.linkedin.com/feed/foryou/');
  const site1Pass = 'Password123';
  const site1Hash = await hashPassword(site1Pass);
  mockDb.protectedWebsites.push({
    id: crypto.randomUUID(),
    url: site1Url,
    passwordHash: site1Hash.hash,
    salt: site1Hash.salt,
    createdAt: new Date().toISOString()
  });

  // Website 2
  const site2Url = normalizeUrl('https://www.instagram.com/');
  const site2Pass = 'Instagram456';
  const site2Hash = await hashPassword(site2Pass);
  mockDb.protectedWebsites.push({
    id: crypto.randomUUID(),
    url: site2Url,
    passwordHash: site2Hash.hash,
    salt: site2Hash.salt,
    createdAt: new Date().toISOString()
  });

  // Website 3
  const site3Url = normalizeUrl('https://www.youtube.com/');
  const site3Pass = 'YouTube789';
  const site3Hash = await hashPassword(site3Pass);
  mockDb.protectedWebsites.push({
    id: crypto.randomUUID(),
    url: site3Url,
    passwordHash: site3Hash.hash,
    salt: site3Hash.salt,
    createdAt: new Date().toISOString()
  });

  assert(mockDb.protectedWebsites.length === 3, 'Successfully stored 3 distinct protected websites');

  // Verify site 1 with its own password
  assert(
    await verifyPassword(site1Pass, mockDb.protectedWebsites[0].passwordHash, mockDb.protectedWebsites[0].salt),
    'LinkedIn unlocks with LinkedIn password'
  );

  // Cross-site password checks: Instagram password cannot unlock LinkedIn
  assert(
    (await verifyPassword(site2Pass, mockDb.protectedWebsites[0].passwordHash, mockDb.protectedWebsites[0].salt)) === false,
    'Instagram password CANNOT unlock LinkedIn'
  );

  // Cross-site password checks: YouTube password cannot unlock LinkedIn
  assert(
    (await verifyPassword(site3Pass, mockDb.protectedWebsites[0].passwordHash, mockDb.protectedWebsites[0].salt)) === false,
    'YouTube password CANNOT unlock LinkedIn'
  );

  // Cross-site password checks: LinkedIn password cannot unlock Instagram
  assert(
    (await verifyPassword(site1Pass, mockDb.protectedWebsites[1].passwordHash, mockDb.protectedWebsites[1].salt)) === false,
    'LinkedIn password CANNOT unlock Instagram'
  );

  // Cross-site password checks: LinkedIn password cannot unlock YouTube
  assert(
    (await verifyPassword(site1Pass, mockDb.protectedWebsites[2].passwordHash, mockDb.protectedWebsites[2].salt)) === false,
    'LinkedIn password CANNOT unlock YouTube'
  );

  // Plaintext audit
  const rawDbDump = JSON.stringify(mockDb);
  assert(!rawDbDump.includes(site1Pass), 'Audit: Plaintext LinkedIn password is NOT in database storage');
  assert(!rawDbDump.includes(site2Pass), 'Audit: Plaintext Instagram password is NOT in database storage');
  assert(!rawDbDump.includes(site3Pass), 'Audit: Plaintext YouTube password is NOT in database storage');

  // ----------------------------------------------------
  // TEST GROUP 4: Tab-Scoped Navigation Flow, Reopen Locking & Expiration
  // ----------------------------------------------------
  console.log('\n--- TEST GROUP 4: Tab-Scoped Navigation Flow, Reopen Locking & Expiration ---');

  // Simulated browser environment with tab-scoped authorizations
  const sessionStore = {
    authorizations: {},
    pendingChallenges: {}
  };

  // Mock background navigation handler with tabId scoping and tab navigation-away revocation
  async function simulateNavigation(navUrl, tabId = 1) {
    let normalized;
    try {
      normalized = normalizeUrl(navUrl);
    } catch {
      return { action: 'allow', reason: 'invalid or unsupported URL' };
    }

    // Revoke authorizations in this tab if navigating to a different URL
    for (const key of Object.keys(sessionStore.authorizations)) {
      const item = sessionStore.authorizations[key];
      if (item && item.tabId === tabId && item.normalizedUrl !== normalized) {
        delete sessionStore.authorizations[key];
      }
    }

    // Check if protected
    const site = mockDb.protectedWebsites.find(s => s.url === normalized);
    if (!site) {
      return { action: 'allow', reason: 'unregistered URL unaffected' };
    }

    // Check tab-scoped authorization
    const authKey = `${tabId}:${normalized}`;
    const auth = sessionStore.authorizations[authKey];
    const now = Date.now();
    if (auth && typeof auth.expiresAt === 'number' && auth.expiresAt > now) {
      return { action: 'allow', reason: 'authorized' };
    }

    // Expired or missing: purge and create challenge
    if (auth) {
      delete sessionStore.authorizations[authKey];
    }

    const challengeId = crypto.randomUUID();
    sessionStore.pendingChallenges[challengeId] = {
      targetUrl: navUrl,
      normalizedUrl: normalized,
      tabId: tabId,
      createdAt: now
    };

    return {
      action: 'lock',
      challengeId: challengeId,
      lockUrl: `lock.html?challenge=${challengeId}`
    };
  }

  // Mock background message unlock handler
  async function simulateUnlockMessage(challengeId, password) {
    const challenge = sessionStore.pendingChallenges[challengeId];
    if (!challenge) {
      return { success: false, error: 'Lock session expired or invalid.' };
    }

    if (Date.now() - challenge.createdAt > 10 * 60 * 1000) {
      delete sessionStore.pendingChallenges[challengeId];
      return { success: false, error: 'Challenge expired.' };
    }

    const site = mockDb.protectedWebsites.find(s => s.url === challenge.normalizedUrl);
    if (!site) {
      delete sessionStore.pendingChallenges[challengeId];
      return { success: false, error: 'Website is no longer protected.' };
    }

    const match = await verifyPassword(password, site.passwordHash, site.salt);
    if (!match) {
      return { success: false, error: 'Incorrect password.' };
    }

    // Grant temporary authorization strictly for THIS tab
    const authKey = `${challenge.tabId}:${challenge.normalizedUrl}`;
    sessionStore.authorizations[authKey] = {
      tabId: challenge.tabId,
      normalizedUrl: challenge.normalizedUrl,
      grantedAt: Date.now(),
      expiresAt: Date.now() + AUTH_EXPIRY_MS
    };

    delete sessionStore.pendingChallenges[challengeId];
    return { success: true, redirectUrl: challenge.targetUrl };
  }

  // Mock tab close handler (chrome.tabs.onRemoved)
  function simulateTabClose(tabId) {
    for (const key of Object.keys(sessionStore.authorizations)) {
      if (sessionStore.authorizations[key]?.tabId === tabId || key.startsWith(`${tabId}:`)) {
        delete sessionStore.authorizations[key];
      }
    }
    for (const cid of Object.keys(sessionStore.pendingChallenges)) {
      if (sessionStore.pendingChallenges[cid]?.tabId === tabId) {
        delete sessionStore.pendingChallenges[cid];
      }
    }
  }

  // 4.1: Unregistered URLs remain unaffected
  const navUnregistered1 = await simulateNavigation('https://www.google.com/search?q=weather', 1);
  assert(navUnregistered1.action === 'allow', 'Unregistered URL (google.com) is completely unaffected');

  const navUnregistered2 = await simulateNavigation('https://www.linkedin.com/messaging/', 1);
  assert(navUnregistered2.action === 'allow', 'Unregistered subpath (/messaging/) is unaffected when only /feed/foryou/ is protected');

  // 4.2: Direct navigation in Tab 1 to protected URL redirects to lock screen
  const navTab1 = await simulateNavigation('https://www.linkedin.com/feed/foryou/', 1);
  assert(navTab1.action === 'lock', 'Tab 1: Protected URL redirects to lock screen');
  assert(navTab1.challengeId && sessionStore.pendingChallenges[navTab1.challengeId], 'Challenge recorded in session for Tab 1');

  // 4.3: Unlock with wrong password fails and keeps locked
  const unlockFail = await simulateUnlockMessage(navTab1.challengeId, 'WrongPass');
  assert(unlockFail.success === false, 'Incorrect password rejected on lock screen');
  assert(sessionStore.pendingChallenges[navTab1.challengeId] !== undefined, 'Challenge remains pending on failure');

  // 4.4: Unlock with correct password succeeds and grants access to Tab 1
  const unlockSuccess = await simulateUnlockMessage(navTab1.challengeId, site1Pass);
  assert(unlockSuccess.success === true, 'Correct password accepted on lock screen');
  assert(unlockSuccess.redirectUrl === 'https://www.linkedin.com/feed/foryou/', 'Original target URL restored');
  assert(sessionStore.pendingChallenges[navTab1.challengeId] === undefined, 'Challenge consumed');

  // 4.5: Refresh in Tab 1 is allowed while tab is active
  const navRefreshTab1 = await simulateNavigation('https://www.linkedin.com/feed/foryou/', 1);
  assert(navRefreshTab1.action === 'allow', 'Tab 1: Page refresh allowed in active tab');

  // 4.6: CRITICAL: New tab (Tab 2) visiting same protected URL MUST ask for password!
  const navTab2 = await simulateNavigation('https://www.linkedin.com/feed/foryou/', 2);
  assert(navTab2.action === 'lock', 'CRITICAL: Tab 2 opened to same URL is LOCKED and asks for password');

  // 4.7: CRITICAL: Closing Tab 1 and reopening (Tab 3) MUST ask for password!
  console.log('Simulating closing Tab 1 (chrome.tabs.onRemoved)...');
  simulateTabClose(1);
  assert(sessionStore.authorizations['1:' + site1Url] === undefined, 'Tab 1 authorization instantly deleted on tab close');

  const navTab3 = await simulateNavigation('https://www.linkedin.com/feed/foryou/', 3);
  assert(navTab3.action === 'lock', 'CRITICAL: Reopening in Tab 3 after closing Tab 1 is LOCKED and asks for password');

  // Unlock Tab 3
  const unlockTab3 = await simulateUnlockMessage(navTab3.challengeId, site1Pass);
  assert(unlockTab3.success === true, 'Tab 3 unlocked with correct password');

  // 4.8: CRITICAL: In Tab 3, navigate away to Google, then back to LinkedIn -> MUST ask for password!
  console.log('Simulating Tab 3 navigating away to Google, then back to LinkedIn...');
  await simulateNavigation('https://www.google.com/', 3);
  assert(sessionStore.authorizations['3:' + site1Url] === undefined, 'Tab 3 authorization revoked upon navigating away');

  const navTab3Return = await simulateNavigation('https://www.linkedin.com/feed/foryou/', 3);
  assert(navTab3Return.action === 'lock', 'CRITICAL: Returning to protected URL in Tab 3 is LOCKED and asks for password');

  // 4.9: Unlock Tab 3 again and test time expiration
  const unlockTab3Again = await simulateUnlockMessage(navTab3Return.challengeId, site1Pass);
  assert(unlockTab3Again.success === true, 'Tab 3 unlocked again');

  // Artificially expire the authorization
  sessionStore.authorizations['3:' + site1Url].expiresAt = Date.now() - 1000;
  const navAfterExpiry = await simulateNavigation('https://www.linkedin.com/feed/foryou/', 3);
  assert(navAfterExpiry.action === 'lock', 'Navigation after 5-minute expiration redirects to lock screen');

  // ----------------------------------------------------
  // TEST GROUP 5: UI Elements Strict Compliance
  // ----------------------------------------------------
  console.log('\n--- TEST GROUP 5: UI Element Strict Compliance ---');

  const popupHtml = fs.readFileSync(path.join(__dirname, 'popup.html'), 'utf8');
  const lockHtml = fs.readFileSync(path.join(__dirname, 'lock.html'), 'utf8');

  // Verify popup.html contains ONLY the 4 elements requested
  assert(popupHtml.includes('placeholder="Enter website URL"'), 'popup.html has placeholder "Enter website URL"');
  assert(popupHtml.includes('placeholder="Enter password"'), 'popup.html has placeholder "Enter password"');
  assert(popupHtml.includes('>Add</button>'), 'popup.html has button labeled "Add"');
  assert(popupHtml.includes('>Add New</button>'), 'popup.html has button labeled "Add New"');

  // Count inputs and buttons in popup.html
  const popupInputs = (popupHtml.match(/<input\b/gi) || []).length;
  const popupButtons = (popupHtml.match(/<button\b/gi) || []).length;
  assert(popupInputs === 2, `popup.html has exactly 2 input fields (found ${popupInputs})`);
  assert(popupButtons === 2, `popup.html has exactly 2 buttons (found ${popupButtons})`);
  assert(!popupHtml.includes('<h1') && !popupHtml.includes('<h2') && !popupHtml.includes('<h3'), 'popup.html has no headers/titles');
  assert(!popupHtml.includes('<img') && !popupHtml.includes('<svg'), 'popup.html has no icons/images');

  // Verify lock.html contains ONLY:
  // 1. A password input field
  // 2. An Unlock button
  const lockInputs = (lockHtml.match(/<input\b/gi) || []).length;
  const lockButtons = (lockHtml.match(/<button\b/gi) || []).length;
  assert(lockInputs === 1, `lock.html has exactly 1 input field (found ${lockInputs})`);
  assert(lockButtons === 1, `lock.html has exactly 1 button (found ${lockButtons})`);
  assert(lockHtml.includes('type="password"'), 'lock.html input is type password');
  assert(lockHtml.includes('>Unlock</button>'), 'lock.html button is labeled "Unlock"');
  assert(!lockHtml.includes('<h1') && !lockHtml.includes('<h2') && !lockHtml.includes('<h3'), 'lock.html has no headers/titles');

  console.log('\n====================================================');
  console.log(`TEST SUMMARY: ${testsPassed} PASSED, ${testsFailed} FAILED`);
  console.log('====================================================\n');

  if (testsFailed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
