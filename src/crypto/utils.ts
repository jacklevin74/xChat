import { randomBytes } from '@noble/ciphers/webcrypto';

/**
 * Domain separator for X1 messaging protocol
 */
export const DOMAIN_SEPARATOR = 'x1-msg-v1';

/**
 * Base58 alphabet (Bitcoin/Solana style)
 */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP = new Map<string, number>();
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_MAP.set(BASE58_ALPHABET[i], i);
}

/**
 * Encode bytes to base58 string (Solana-compatible)
 */
export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Count leading zeros
  let zeros = 0;
  for (const byte of bytes) {
    if (byte === 0) zeros++;
    else break;
  }

  // Convert to base58
  const digits: number[] = [];
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

  // Build string (reverse order)
  let result = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }

  return result;
}

/**
 * Decode base58 string to bytes (Solana-compatible)
 */
export function base58Decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Count leading '1's (zeros)
  let zeros = 0;
  for (const char of str) {
    if (char === '1') zeros++;
    else break;
  }

  // Convert from base58
  const bytes: number[] = [];
  for (const char of str) {
    const value = BASE58_MAP.get(char);
    if (value === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

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

  // Add leading zeros and reverse
  const result = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    result[zeros + bytes.length - 1 - i] = bytes[i];
  }

  return result;
}

/**
 * Generate cryptographically secure random bytes
 */
export function secureRandomBytes(length: number): Uint8Array {
  return randomBytes(length);
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate a unique message ID (8 bytes / 64 bits)
 */
export function generateMessageId(): Uint8Array {
  return secureRandomBytes(8);
}

/**
 * Convert message ID to string for display/storage
 */
export function messageIdToString(id: Uint8Array): string {
  return bytesToHex(id);
}

/**
 * Convert string message ID back to bytes
 */
export function stringToMessageId(str: string): Uint8Array {
  const bytes = hexToBytes(str);
  if (bytes.length !== 8) {
    throw new Error('Invalid message ID length');
  }
  return bytes;
}
