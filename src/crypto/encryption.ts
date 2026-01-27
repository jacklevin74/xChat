import { gcm } from '@noble/ciphers/aes';
import { secureRandomBytes, concatBytes } from './utils.js';

/**
 * AES-GCM nonce size in bytes (96 bits = 12 bytes)
 */
export const NONCE_SIZE = 12;

/**
 * AES-GCM authentication tag size in bytes (128 bits = 16 bytes)
 */
export const TAG_SIZE = 16;

/**
 * Encrypted data with nonce
 */
export interface EncryptedData {
  nonce: Uint8Array;
  ciphertext: Uint8Array; // includes auth tag
}

/**
 * Encrypt data using AES-256-GCM
 * @param key - 32-byte AES-256 key
 * @param plaintext - Data to encrypt
 * @param additionalData - Optional additional authenticated data (AAD)
 * @returns Encrypted data with nonce
 */
export function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): EncryptedData {
  if (key.length !== 32) {
    throw new Error('Invalid key length: expected 32 bytes for AES-256');
  }

  // Generate random nonce
  const nonce = secureRandomBytes(NONCE_SIZE);

  // Create AES-GCM cipher
  const cipher = gcm(key, nonce, additionalData);

  // Encrypt (ciphertext includes auth tag)
  const ciphertext = cipher.encrypt(plaintext);

  return { nonce, ciphertext };
}

/**
 * Decrypt data using AES-256-GCM
 * @param key - 32-byte AES-256 key
 * @param nonce - 12-byte nonce used for encryption
 * @param ciphertext - Encrypted data (includes auth tag)
 * @param additionalData - Optional additional authenticated data (AAD)
 * @returns Decrypted plaintext
 * @throws Error if decryption fails (invalid key, corrupted data, or tampered)
 */
export function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  additionalData?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error('Invalid key length: expected 32 bytes for AES-256');
  }

  if (nonce.length !== NONCE_SIZE) {
    throw new Error(`Invalid nonce length: expected ${NONCE_SIZE} bytes`);
  }

  // Create AES-GCM cipher
  const cipher = gcm(key, nonce, additionalData);

  // Decrypt (throws if auth tag verification fails)
  return cipher.decrypt(ciphertext);
}

/**
 * Encrypt and serialize to a single buffer
 * Format: [nonce (12 bytes)][ciphertext+tag]
 */
export function encryptToBuffer(
  key: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Uint8Array {
  const { nonce, ciphertext } = encrypt(key, plaintext, additionalData);
  return concatBytes(nonce, ciphertext);
}

/**
 * Decrypt from a serialized buffer
 * Format: [nonce (12 bytes)][ciphertext+tag]
 */
export function decryptFromBuffer(
  key: Uint8Array,
  buffer: Uint8Array,
  additionalData?: Uint8Array
): Uint8Array {
  if (buffer.length < NONCE_SIZE + TAG_SIZE) {
    throw new Error('Buffer too short to contain valid encrypted data');
  }

  const nonce = buffer.slice(0, NONCE_SIZE);
  const ciphertext = buffer.slice(NONCE_SIZE);

  return decrypt(key, nonce, ciphertext, additionalData);
}
