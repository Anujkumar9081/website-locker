# Website Locker

A secure, minimal Google Chrome Extension built with **HTML, CSS, JavaScript, and Chrome Extension Manifest V3**. 

Website Locker allows users to protect individual website URLs with unique, independent passwords. When someone navigates to a protected URL, they are immediately redirected to a minimal lock screen and required to enter the website's password. Once verified, access is granted temporarily (default: 5 minutes) before locking again.

---

## 1. UI Design & Simplicity Principles

The UI strictly follows a zero-clutter, distraction-free design philosophy:
- **White background (`#ffffff`)**, simple black text (`#000000`), basic 1px borders, and small 4px rounded corners.
- **No dashboards, statistics, animations, icons, logos, or extra headers.**

### Extension Popup (`popup.html`)
Contains **ONLY** the four required elements:
1. One text input field with placeholder: `Enter website URL`
2. One password input field with placeholder: `Enter password`
3. One button labeled: `Add` (hashes the password and saves the website)
4. One button labeled: `Add New` (clears both input fields for a new entry)

User feedback and validation errors are communicated exclusively via standard browser `alert()` dialogs rather than extra DOM elements.

### Lock Screen (`lock.html`)
Contains **ONLY** the two required elements:
1. One password input field with placeholder: `Enter password`
2. One button labeled: `Unlock`

---

## 2. Cryptographic Security & Data Storage

All credential handling is executed locally inside the extension's privileged context using the browser's native **Web Crypto API (`window.crypto.subtle`)**.

### Security Model
- **No Plaintext Passwords:** Passwords are never stored in plaintext anywhere (neither in storage, logs, nor memory).
- **PBKDF2 with SHA-256:** Password hashes are derived using **PBKDF2** (Password-Based Key Derivation Function 2) combined with **SHA-256**, running **100,000 iterations** for a 256-bit derived key.
- **Cryptographically Random Salts:** A unique 128-bit (16-byte) random salt is generated for each protected website entry using `crypto.getRandomValues()`.
- **Constant-Time Verification:** Hash verification is performed in constant time (`constantTimeCompare`) to mitigate side-channel timing attacks.
- **Zero External Transmission:** No passwords, hashes, or URLs are ever transmitted to any external server or third-party service.

### Storage Schema
Protected websites are saved in Chrome's local extension storage (`chrome.storage.local`) conforming to a single consistent schema:

```json
{
  "protectedWebsites": [
    {
      "id": "e81f1961-d779-4348-9da4-7bc33b7a544f",
      "url": "https://www.linkedin.com/feed/foryou",
      "passwordHash": "8f48039c09c251d18105d15c7e3f847291a1347072a4c139c8eb10787e974f1b",
      "salt": "a59489f6de3973c1c73f309a6338b146",
      "createdAt": "2026-10-28T06:40:00.000Z"
    }
  ]
}
```

---

## 3. URL Normalization & Matching Rules

URLs are normalized and compared strictly to prevent bypasses and false matches:
- **Strict Protocol Enforcement:** Only `http:` and `https:` URLs can be registered. Dangerous schemes (`javascript:`, `file:`, `chrome:`, `chrome-extension:`, `data:`, `about:`) are rejected.
- **Fragment Stripping:** URL fragments (`#...`) are removed prior to comparison.
- **Consistent Trailing Slash Handling:** Trailing slashes on sub-paths (`pathname.length > 1`) are stripped, ensuring `https://www.linkedin.com/feed/foryou/` and `https://www.linkedin.com/feed/foryou` refer to the same protected resource, while root URLs (`https://www.instagram.com/`) maintain their root slash.
- **Query Parameter Ordering:** Query parameters are parsed into key-value pairs and sorted alphabetically by parameter key. This ensures that semantic equivalents like `https://example.com/search?b=2&a=1` and `https://example.com/search?a=1&b=2` match identically, while preserving query values and preventing ordering manipulation.
- **No Substring Checks:** URLs are compared via exact string equality of their normalized representations. Protecting `https://www.linkedin.com/feed/foryou/` will **never** lock `https://www.linkedin.com/feed/foryou2`, `https://www.linkedin.com/feed/foryou/extra`, or `https://www.linkedin.com/messaging/`.

---

## 4. Website Locking & Service Worker Architecture

### Navigation Interception
- The background service worker (`background.js`) monitors top-level navigations using:
  - `chrome.webNavigation.onBeforeNavigate`: Intercepts standard navigations, typed URLs, bookmarks, and full-page refreshes.
  - `chrome.webNavigation.onHistoryStateUpdated`: Intercepts client-side routing changes in Single Page Applications (SPAs) such as LinkedIn, YouTube, and Instagram.

### Lock Session Flow
1. When a navigation matches a protected URL, the service worker verifies if an active authorization exists in `chrome.storage.session`.
2. If authorization is absent or expired, the service worker creates a cryptographically random, single-use `challengeId` (`crypto.randomUUID()`) linked to `{ targetUrl, normalizedUrl, tabId, createdAt }` in `chrome.storage.session`.
3. The tab is redirected to `lock.html?challenge=<challengeId>`.
4. The lock screen presents the password field. The user inputs their password and submits.
5. The lock screen messages the background service worker:
   - Background checks sender security (strictly verifying `sender.id === chrome.runtime.id` and origin).
   - Verifies the `challengeId` is valid, registered, and not older than 10 minutes.
   - Derives the PBKDF2 hash using the stored salt and verifies against the stored hash in constant time.
6. Upon correct password:
   - A temporary authorization token is stored in `chrome.storage.session` for that exact normalized URL with an expiration timestamp (`Date.now() + 5 minutes`).
   - The challenge is deleted.
   - The lock screen replaces itself in browser history via `window.location.replace(targetUrl)` to prevent back-button loops.
7. Upon incorrect password:
   - An alert is displayed, the password field is cleared, and the page remains locked.

### Expiration & Suspension Handling
- **Tab-Scoped Authorization:** Authorizations are tied strictly to individual browser tabs (`tabId:normalizedUrl`). Unlocking a website in one tab does not unlock it in any other tab.
- **Immediate Cleanup on Tab Close:** The extension listens to `chrome.tabs.onRemoved`. The instant a user closes a tab or window, any authorization for that tab is deleted. Reopening the website in a new tab will **always** prompt for the password.
- **Immediate Cleanup on Navigation Away:** When an authorized tab navigates away from the protected domain (e.g. to Google or another site), its authorization for the protected URL is revoked. Returning or reopening will require the password.
- **Expiration Policy:** Authorizations default to a maximum duration of **5 minutes** (`AUTH_EXPIRY_MS = 300000`) for the active tab.
- **Active Navigation Verification:** Expiration is actively verified on every navigation and reload rather than relying solely on timers. Expired authorizations are purged immediately upon detection.
- **Service Worker Lifecycle:** All authorizations and pending challenges are kept in `chrome.storage.session`, which persists across service worker idle suspensions and restarts throughout the browser session.

---

## 5. Architectural Limitation: Brief Content Flash

> [!NOTE]
> **Chrome Extension API Architectural Boundary**
>
> In Google Chrome Manifest V3, `chrome.webNavigation.onBeforeNavigate` is an **observational API**. When Chrome begins loading a URL, it notifies the extension asynchronously. While the background service worker immediately dispatches `chrome.tabs.update(tabId, { url: lockUrl })`, the browser engine may in certain circumstances (such as high disk/memory cache hits or fast network connections) start rendering the initial cached frame or response bytes for a few milliseconds before the tab redirection completes.
>
> This behavior is an inherent characteristic of Chrome's asynchronous extension architecture. Website Locker redirects the tab as rapidly as Chrome's extension APIs permit, but cannot claim 100% instantaneous pre-render blocking against local browser cache hits without intrusive webRequest blocking mechanisms (which are restricted in MV3).

---

## 6. Project Structure

```
website-locker/
├── manifest.json       # Manifest V3 extension configuration
├── background.js       # Service worker: navigation monitoring & unlock verification
├── security.js         # Web Crypto PBKDF2 hashing, constant-time compare, URL normalization
├── popup.html          # Minimal popup: exactly 2 inputs and 2 buttons
├── popup.css           # Clean minimal styling for popup
├── popup.js            # Popup controller: URL validation, PBKDF2 derivation, storage
├── lock.html           # Minimal lock screen: exactly 1 password field and 1 Unlock button
├── lock.css            # Clean minimal styling for lock screen
├── lock.js             # Lock screen controller: challenge submission and redirection
├── test_suite.js       # Automated end-to-end verification test suite
└── README.md           # Documentation and installation guide
```

---

## 7. How to Install Locally in Google Chrome

1. Open **Google Chrome**.
2. Navigate to `chrome://extensions/` in the address bar.
3. Toggle the **Developer mode** switch in the upper right-hand corner of the page to **ON**.
4. Click the **Load unpacked** button located in the top-left toolbar.
5. In the file picker dialog, select the `website-locker` folder:
   ```
   /Users/anujkumar9081/Desktop/projects/exteansion/website-locker
   ```
6. The **Website Locker** extension will appear in your extensions list and is immediately active.
7. (Optional) Click the puzzle piece icon in the Chrome toolbar and pin **Website Locker** for quick access.

---

## 8. Verification & Test Suite

The project includes an automated test suite (`test_suite.js`) executing **71 automated assertions** covering:
- **URL Normalization:** Trailing slash handling, fragment removal, query parameter sorting, and rejection of dangerous protocols (`javascript:`, `file:`, `chrome:`).
- **Cryptographic Security:** 256-bit PBKDF2 SHA-256 derivation with 100,000 iterations, unique random 128-bit salts, zero plaintext storage, and constant-time string comparison.
- **Multi-Site Password Isolation:** Ensuring each protected URL has an independent password (e.g. Instagram's password cannot unlock LinkedIn, YouTube's password cannot unlock LinkedIn).
- **Navigation & Locking:** Direct navigation redirection, challenge issuance, failed password retention, successful password authorization, target URL restoration, SPA route detection, and uninhibited navigation for unregistered URLs.
- **Tab-Scoped Reopen Security:** Ensuring closing a tab immediately purges authorization, reopening always asks for password, new tabs always ask for password, and navigating away revokes authorization.
- **Authorization Expiration:** Active verification that authorization expires after 5 minutes and is cleaned up on navigation.
- **UI Strict Compliance:** Ensuring `popup.html` contains strictly 2 inputs and 2 buttons, and `lock.html` contains strictly 1 input and 1 button.

To run the automated verification suite:
```bash
node test_suite.js
```

