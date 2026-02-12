// xchat bridge — crypto operations
// Browser-compatible key derivation (matches webapp/public/app.js)

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';

const DOMAIN_SEPARATOR = 'x1-msg-v1';
const SIGN_MESSAGE = 'X1 Encrypted Messaging - Sign to generate your encryption keys';
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// ============================================================================
// BASE58
// ============================================================================

const BASE58_MAP = new Map();
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    BASE58_MAP.set(BASE58_ALPHABET[i], i);
}

export function base58Encode(bytes) {
    if (bytes.length === 0) return '';
    let zeros = 0;
    for (const byte of bytes) {
        if (byte === 0) zeros++;
        else break;
    }
    const digits = [];
    for (const byte of bytes) {
        let carry = byte;
        for (let i = 0; i < digits.length; i++) {
            carry += digits[i] << 8;
            digits[i] = carry % 58;
            carry = Math.floor(carry / 58);
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = Math.floor(carry / 58);
        }
    }
    let result = '1'.repeat(zeros);
    for (let i = digits.length - 1; i >= 0; i--) {
        result += BASE58_ALPHABET[digits[i]];
    }
    return result;
}

export function base58Decode(str) {
    if (str.length === 0) return new Uint8Array(0);
    let zeros = 0;
    for (const char of str) {
        if (char === '1') zeros++;
        else break;
    }
    const bytes = [];
    for (const char of str) {
        const value = BASE58_MAP.get(char);
        if (value === undefined) throw new Error(`Invalid base58 character: ${char}`);
        let carry = value;
        for (let i = 0; i < bytes.length; i++) {
            carry += bytes[i] * 58;
            bytes[i] = carry & 0xff;
            carry >>= 8;
        }
        while (carry > 0) {
            bytes.push(carry & 0xff);
            carry >>= 8;
        }
    }
    const result = new Uint8Array(zeros + bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        result[zeros + bytes.length - 1 - i] = bytes[i];
    }
    return result;
}

// ============================================================================
// HEX
// ============================================================================

export function hexToBytes(hex) {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (clean.length % 2 !== 0) throw new Error('Invalid hex string length');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

export function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// KEY DERIVATION (browser-compatible path)
// ============================================================================

/**
 * Derive all keys from an ed25519 private key.
 * Uses the browser-compatible path: sign SIGN_MESSAGE → HKDF → X25519
 * This matches webapp/public/app.js, NOT src/crypto/keys.ts
 */
export function deriveKeys(privateKeyInput) {
    let seed;
    if (typeof privateKeyInput === 'string') {
        if (privateKeyInput.startsWith('0x') || /^[0-9a-fA-F]{64}$/.test(privateKeyInput)) {
            seed = hexToBytes(privateKeyInput);
        } else {
            seed = base58Decode(privateKeyInput);
        }
    } else {
        seed = privateKeyInput;
    }

    // Solana keypairs can be 64 bytes (seed + pubkey); extract 32-byte seed
    if (seed.length === 64) seed = seed.slice(0, 32);
    if (seed.length !== 32) throw new Error(`Invalid key length: expected 32 or 64 bytes, got ${seed.length}`);

    const ed25519Public = ed25519.getPublicKey(seed);
    const address = base58Encode(ed25519Public);

    // Browser-compatible: sign the canonical message, then HKDF the signature
    const signature = ed25519.sign(
        new TextEncoder().encode(SIGN_MESSAGE),
        seed
    );

    const x25519Private = hkdf(
        sha256, signature, new Uint8Array(0),
        new TextEncoder().encode(DOMAIN_SEPARATOR + '-x25519'), 32
    );
    const x25519Public = x25519.getPublicKey(x25519Private);

    return {
        ed25519Private: seed,
        ed25519Public,
        address,
        x25519Private,
        x25519Public,
        x25519PublicB58: base58Encode(x25519Public),
    };
}

// ============================================================================
// ECDH + ENCRYPTION
// ============================================================================

/**
 * Compute AES-256 session key from X25519 ECDH.
 */
export function computeSessionKey(ourX25519Private, theirX25519Public) {
    const shared = x25519.getSharedSecret(ourX25519Private, theirX25519Public);
    return hkdf(
        sha256, shared, new Uint8Array(0),
        new TextEncoder().encode(DOMAIN_SEPARATOR + '-session'), 32
    );
}

/**
 * Encrypt plaintext string → { nonce, ciphertext } as base58 strings.
 */
export function encrypt(sessionKey, plaintext) {
    const nonce = randomBytes(12);
    const cipher = gcm(sessionKey, nonce);
    const ciphertext = cipher.encrypt(new TextEncoder().encode(plaintext));
    return {
        nonce: base58Encode(nonce),
        ciphertext: base58Encode(ciphertext),
    };
}

/**
 * Decrypt base58-encoded nonce + ciphertext → plaintext string.
 */
export function decrypt(sessionKey, nonceB58, ciphertextB58) {
    const nonce = base58Decode(nonceB58);
    const ciphertext = base58Decode(ciphertextB58);
    const plaintext = gcm(sessionKey, nonce).decrypt(ciphertext);
    return new TextDecoder().decode(plaintext);
}

// ============================================================================
// SIGNING
// ============================================================================

/**
 * Sign a message string with ed25519 private key → base58 signature.
 */
export function signMessage(ed25519Private, message) {
    const sig = ed25519.sign(new TextEncoder().encode(message), ed25519Private);
    return base58Encode(sig);
}

/**
 * Sign the key registration message for the xchat server.
 */
export function signKeyRegistration(ed25519Private, x25519PublicB58) {
    return signMessage(ed25519Private, `X1 Messaging: Register encryption key ${x25519PublicB58}`);
}
