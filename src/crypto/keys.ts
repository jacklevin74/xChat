import { ed25519 } from '@noble/curves/ed25519';
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { DOMAIN_SEPARATOR, hexToBytes, bytesToHex, base58Encode, base58Decode } from './utils.js';

/**
 * Messaging keypair derived from wallet private key
 */
export interface MessagingKeyPair {
  privateKey: Uint8Array;  // 32 bytes (ed25519 seed)
  publicKey: Uint8Array;   // 32 bytes (ed25519 public key)
}

/**
 * Derive a messaging keypair from a wallet private key (Solana-compatible).
 * Uses HKDF-SHA256 with domain separator to ensure:
 * - Deterministic derivation (same wallet = same messaging keys)
 * - Domain separation (messaging keys can't sign transactions)
 */
export function deriveMessagingKeyPair(walletPrivateKey: Uint8Array | string): MessagingKeyPair {
  let privKeyBytes: Uint8Array;

  if (typeof walletPrivateKey === 'string') {
    // Check if it's base58 encoded (Solana style) or hex
    if (walletPrivateKey.startsWith('0x') || /^[0-9a-fA-F]+$/.test(walletPrivateKey)) {
      privKeyBytes = hexToBytes(walletPrivateKey);
    } else {
      // Assume base58
      privKeyBytes = base58Decode(walletPrivateKey);
    }
  } else {
    privKeyBytes = walletPrivateKey;
  }

  // Solana keypairs can be 64 bytes (seed + pubkey) or 32 bytes (seed only)
  // Extract the 32-byte seed
  const seed = privKeyBytes.length === 64 ? privKeyBytes.slice(0, 32) : privKeyBytes;

  if (seed.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 or 64 bytes, got ${privKeyBytes.length}`);
  }

  // Use HKDF to derive messaging private key (seed)
  const derivedSeed = hkdf(
    sha256,
    seed,
    new Uint8Array(0), // salt
    new TextEncoder().encode(DOMAIN_SEPARATOR),
    32 // output length
  );

  // Derive ed25519 public key from seed
  const publicKey = ed25519.getPublicKey(derivedSeed);

  return { privateKey: derivedSeed, publicKey };
}

/**
 * Convert ed25519 public key to X25519 public key for ECDH
 * This uses the birational map from Ed25519 to Curve25519
 */
function ed25519PublicKeyToX25519(ed25519PubKey: Uint8Array): Uint8Array {
  // Ed25519 point (x, y) maps to Curve25519 u-coordinate:
  // u = (1 + y) / (1 - y) mod p
  //
  // The @noble/curves library's x25519 uses Montgomery form directly,
  // so we need to convert the ed25519 public key.
  //
  // For simplicity, we'll derive X25519 keys from the same seed using HKDF
  // with a different domain separator.
  throw new Error('Use deriveX25519KeyPair instead');
}

/**
 * Derive X25519 keypair from ed25519 seed for ECDH
 */
function deriveX25519KeyPair(ed25519Seed: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array } {
  // Derive X25519 private key from ed25519 seed using HKDF with different context
  const x25519PrivateKey = hkdf(
    sha256,
    ed25519Seed,
    new Uint8Array(0),
    new TextEncoder().encode(DOMAIN_SEPARATOR + '-x25519'),
    32
  );

  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey);

  return { privateKey: x25519PrivateKey, publicKey: x25519PublicKey };
}

/**
 * Compute X25519 shared secret between our private key and their public key.
 * Both keys should be X25519 keys (derived from ed25519 seeds).
 */
export function computeSharedSecret(
  ourEd25519Seed: Uint8Array,
  theirX25519PublicKey: Uint8Array
): Uint8Array {
  // Derive our X25519 private key from our ed25519 seed
  const ourX25519 = deriveX25519KeyPair(ourEd25519Seed);

  // Compute X25519 shared secret
  const sharedSecret = x25519.getSharedSecret(ourX25519.privateKey, theirX25519PublicKey);

  // Derive a symmetric key from the shared secret using HKDF
  const symmetricKey = hkdf(
    sha256,
    sharedSecret,
    new Uint8Array(0), // salt
    new TextEncoder().encode(DOMAIN_SEPARATOR + '-session'),
    32 // AES-256 key length
  );

  return symmetricKey;
}

/**
 * Get X25519 public key from ed25519 seed (for key exchange)
 */
export function getX25519PublicKey(ed25519Seed: Uint8Array): Uint8Array {
  return deriveX25519KeyPair(ed25519Seed).publicKey;
}

/**
 * Get ed25519 public key from private key (seed)
 */
export function getPublicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey);
}

/**
 * Validate an ed25519 public key
 */
export function isValidPublicKey(publicKey: Uint8Array): boolean {
  try {
    if (publicKey.length !== 32) return false;
    // Try to create a point from the public key
    ed25519.ExtendedPoint.fromHex(bytesToHex(publicKey));
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate an X25519 public key
 */
export function isValidX25519PublicKey(publicKey: Uint8Array): boolean {
  // X25519 public keys are 32 bytes, any 32-byte value is technically valid
  return publicKey.length === 32;
}

/**
 * Convert public key to Solana address (base58 encoded)
 * In Solana, the address IS the public key (base58 encoded)
 */
export function publicKeyToAddress(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKey.length}`);
  }
  return base58Encode(publicKey);
}

/**
 * Convert Solana address (base58) to public key bytes
 */
export function addressToPublicKey(address: string): Uint8Array {
  const bytes = base58Decode(address);
  if (bytes.length !== 32) {
    throw new Error(`Invalid address: decoded to ${bytes.length} bytes, expected 32`);
  }
  return bytes;
}

/**
 * Sign a message using ed25519
 */
export function sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

/**
 * Verify an ed25519 signature
 */
export function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
