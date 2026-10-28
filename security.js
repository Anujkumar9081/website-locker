/**
 * Security and Utility Module for Website Locker
 * 
 * Provides:
 * - URL normalization and strict validation
 * - Web Crypto PBKDF2 hashing and verification
 * - Cryptographically secure random salt generation
 * - Constant-time comparison
 */

export const AUTH_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes default authorization
export const PBKDF2_ITERATIONS = 100000;
export const HASH_ALGO = 'SHA-256';
export const KEY_LENGTH_BITS = 256;
export const SALT_BYTE_LENGTH = 16;

/**
 * Normalizes a URL for consistent storage and strict comparison.
 * 
 * Rules:
 * 1. Only valid http: and https: protocols are permitted.
 * 2. Rejects javascript:, file:, chrome:, chrome-extension:, etc.
 * 3. Removes URL fragments (#...).
 * 4. Normalizes hostname to lowercase.
 * 5. Preserves pathname, removing trailing slashes on sub-paths (> 1 char)
 *    so '/feed/foryou/' matches '/feed/foryou' but never unrelated paths.
 * 6. Preserves query parameters, sorting them alphabetically by key
 *    so parameter order does not affect matching.
 * 
 * @param {string} rawUrl - The input URL to normalize
 * @returns {string} The normalized URL
 * @throws {Error} If URL is invalid or uses an unsupported protocol
 */
export function normalizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new Error('Please enter a valid website URL.');
  }

  const trimmed = rawUrl.trim();
  if (!trimmed) {
    throw new Error('Please enter a valid website URL.');
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('Invalid URL format. Please enter a valid URL with http:// or https://.');
  }

  // Reject invalid / dangerous protocols
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS URLs can be protected. Protocols like javascript:, file:, and chrome: are not permitted.');
  }

  if (!parsed.hostname) {
    throw new Error('URL must include a valid hostname.');
  }

  // Normalize pathname: ensure root '/' or strip trailing slash on paths with length > 1
  let pathname = parsed.pathname || '/';
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.replace(/\/+$/, '');
  }
  if (!pathname) {
    pathname = '/';
  }

  // Sort query parameters alphabetically by key, then value
  const searchParams = new URLSearchParams(parsed.search);
  const sortedParams = new URLSearchParams();
  const keys = Array.from(new Set(searchParams.keys())).sort();

  for (const key of keys) {
    const values = searchParams.getAll(key).sort();
    for (const val of values) {
      sortedParams.append(key, val);
    }
  }

  const queryString = sortedParams.toString() ? `?${sortedParams.toString()}` : '';
  const portPart = parsed.port ? `:${parsed.port}` : '';

  return `${parsed.protocol}//${parsed.hostname.toLowerCase()}${portPart}${pathname}${queryString}`;
}

/**
 * Checks if two URLs match strictly after normalization.
 * Does NOT use substring checks.
 * 
 * @param {string} url1
 * @param {string} url2
 * @returns {boolean}
 */
export function urlsMatch(url1, url2) {
  try {
    return normalizeUrl(url1) === normalizeUrl(url2);
  } catch {
    return false;
  }
}

/**
 * Converts an ArrayBuffer or Uint8Array to a lowercase hex string.
 * 
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
export function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Converts a hex string back into an ArrayBuffer.
 * 
 * @param {string} hex
 * @returns {ArrayBuffer}
 */
export function hexToBuffer(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string format.');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes.buffer;
}

/**
 * Generates a cryptographically random salt hex string.
 * 
 * @returns {string} 32-character hex string (16 random bytes)
 */
export function generateSaltHex() {
  const saltBytes = new Uint8Array(SALT_BYTE_LENGTH);
  crypto.getRandomValues(saltBytes);
  return bufferToHex(saltBytes.buffer);
}

/**
 * Hashes a password using PBKDF2 with SHA-256 and Web Crypto API.
 * Never stores or returns the plaintext password.
 * 
 * @param {string} password - Plaintext password to hash
 * @param {string|null} [saltHex=null] - Optional hex salt. If omitted, generates a fresh random salt.
 * @returns {Promise<{hash: string, salt: string}>}
 */
export async function hashPassword(password, saltHex = null) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('Password must be a non-empty string.');
  }

  const enc = new TextEncoder();
  const passwordBuffer = enc.encode(password);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  let saltBuffer;
  if (saltHex) {
    saltBuffer = hexToBuffer(saltHex);
  } else {
    const saltBytes = new Uint8Array(SALT_BYTE_LENGTH);
    crypto.getRandomValues(saltBytes);
    saltBuffer = saltBytes.buffer;
    saltHex = bufferToHex(saltBuffer);
  }

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: PBKDF2_ITERATIONS,
      hash: HASH_ALGO
    },
    keyMaterial,
    KEY_LENGTH_BITS
  );

  return {
    hash: bufferToHex(derivedBits),
    salt: saltHex
  };
}

/**
 * Verifies an entered password against a stored derived hash and salt.
 * Uses constant-time comparison to protect against timing attacks.
 * 
 * @param {string} enteredPassword
 * @param {string} storedHash
 * @param {string} storedSalt
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(enteredPassword, storedHash, storedSalt) {
  if (!enteredPassword || !storedHash || !storedSalt) {
    return false;
  }
  try {
    const derived = await hashPassword(enteredPassword, storedSalt);
    return constantTimeCompare(derived.hash, storedHash);
  } catch {
    return false;
  }
}

/**
 * Constant-time string equality comparison to mitigate timing attacks.
 * 
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

