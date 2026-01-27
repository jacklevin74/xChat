import { describe, it, expect } from 'vitest';
import {
  deriveMessagingKeyPair,
  computeSharedSecret,
  publicKeyToAddress,
  addressToPublicKey,
  getX25519PublicKey,
  isValidPublicKey,
  isValidX25519PublicKey,
  sign,
  verify,
  hexToBytes,
  bytesToHex,
  base58Encode,
  base58Decode,
  secureRandomBytes,
  generateMessageId,
  messageIdToString,
  stringToMessageId,
} from '../src/crypto/index.js';
import { encrypt, decrypt, encryptToBuffer, decryptFromBuffer } from '../src/crypto/encryption.js';

describe('Crypto Utils', () => {
  describe('hexToBytes / bytesToHex', () => {
    it('should convert hex to bytes and back', () => {
      const hex = 'deadbeef0102030405060708090a0b0c0d0e0f';
      const bytes = hexToBytes(hex);
      expect(bytesToHex(bytes)).toBe(hex);
    });

    it('should handle 0x prefix', () => {
      const hex = '0xdeadbeef';
      const bytes = hexToBytes(hex);
      expect(bytesToHex(bytes)).toBe('deadbeef');
    });

    it('should throw on invalid hex length', () => {
      expect(() => hexToBytes('abc')).toThrow('Invalid hex string length');
    });
  });

  describe('base58Encode / base58Decode', () => {
    it('should encode and decode bytes correctly', () => {
      const bytes = secureRandomBytes(32);
      const encoded = base58Encode(bytes);
      const decoded = base58Decode(encoded);
      expect(bytesToHex(decoded)).toBe(bytesToHex(bytes));
    });

    it('should handle leading zeros', () => {
      const bytes = new Uint8Array([0, 0, 0, 1, 2, 3]);
      const encoded = base58Encode(bytes);
      expect(encoded.startsWith('111')).toBe(true); // Leading 1s for zeros
      const decoded = base58Decode(encoded);
      expect(bytesToHex(decoded)).toBe(bytesToHex(bytes));
    });

    it('should produce valid Solana-style addresses', () => {
      const pubkey = secureRandomBytes(32);
      const address = base58Encode(pubkey);
      // Solana addresses are typically 32-44 characters
      expect(address.length).toBeGreaterThanOrEqual(32);
      expect(address.length).toBeLessThanOrEqual(44);
      // Should only contain base58 characters
      expect(/^[1-9A-HJ-NP-Za-km-z]+$/.test(address)).toBe(true);
    });

    it('should throw on invalid base58 character', () => {
      expect(() => base58Decode('invalid0char')).toThrow('Invalid base58 character');
    });
  });

  describe('secureRandomBytes', () => {
    it('should generate random bytes of specified length', () => {
      const bytes = secureRandomBytes(32);
      expect(bytes.length).toBe(32);
    });

    it('should generate different bytes each time', () => {
      const a = secureRandomBytes(32);
      const b = secureRandomBytes(32);
      expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    });
  });

  describe('messageId', () => {
    it('should generate 8-byte message IDs', () => {
      const id = generateMessageId();
      expect(id.length).toBe(8);
    });

    it('should convert to string and back', () => {
      const id = generateMessageId();
      const str = messageIdToString(id);
      const back = stringToMessageId(str);
      expect(bytesToHex(back)).toBe(bytesToHex(id));
    });
  });
});

describe('Key Derivation (Solana-compatible)', () => {
  const testPrivateKey = '0x' + 'aa'.repeat(32);

  describe('deriveMessagingKeyPair', () => {
    it('should derive a valid ed25519 keypair from private key', () => {
      const keyPair = deriveMessagingKeyPair(testPrivateKey);

      expect(keyPair.privateKey.length).toBe(32); // ed25519 seed
      expect(keyPair.publicKey.length).toBe(32);  // ed25519 public key
      expect(isValidPublicKey(keyPair.publicKey)).toBe(true);
    });

    it('should be deterministic', () => {
      const keyPair1 = deriveMessagingKeyPair(testPrivateKey);
      const keyPair2 = deriveMessagingKeyPair(testPrivateKey);

      expect(bytesToHex(keyPair1.privateKey)).toBe(bytesToHex(keyPair2.privateKey));
      expect(bytesToHex(keyPair1.publicKey)).toBe(bytesToHex(keyPair2.publicKey));
    });

    it('should produce different keys for different inputs', () => {
      const keyPair1 = deriveMessagingKeyPair('0x' + 'aa'.repeat(32));
      const keyPair2 = deriveMessagingKeyPair('0x' + 'bb'.repeat(32));

      expect(bytesToHex(keyPair1.privateKey)).not.toBe(bytesToHex(keyPair2.privateKey));
    });

    it('should accept base58 encoded private key', () => {
      const seed = secureRandomBytes(32);
      const base58Key = base58Encode(seed);
      const keyPair = deriveMessagingKeyPair(base58Key);

      expect(keyPair.privateKey.length).toBe(32);
      expect(keyPair.publicKey.length).toBe(32);
    });

    it('should handle 64-byte Solana keypair format', () => {
      // Solana keypairs are often 64 bytes: 32-byte seed + 32-byte pubkey
      const seed = secureRandomBytes(32);
      const pubkey = secureRandomBytes(32);
      const fullKeypair = new Uint8Array(64);
      fullKeypair.set(seed, 0);
      fullKeypair.set(pubkey, 32);

      const keyPair = deriveMessagingKeyPair(fullKeypair);
      expect(keyPair.privateKey.length).toBe(32);
    });

    it('should throw on invalid key length', () => {
      expect(() => deriveMessagingKeyPair('0x1234')).toThrow('Invalid private key length');
    });
  });

  describe('publicKeyToAddress / addressToPublicKey', () => {
    it('should convert public key to Solana-style base58 address', () => {
      const keyPair = deriveMessagingKeyPair(testPrivateKey);
      const address = publicKeyToAddress(keyPair.publicKey);

      // Solana addresses are base58 encoded, 32-44 characters
      expect(address.length).toBeGreaterThanOrEqual(32);
      expect(address.length).toBeLessThanOrEqual(44);
      expect(/^[1-9A-HJ-NP-Za-km-z]+$/.test(address)).toBe(true);
    });

    it('should convert address back to public key', () => {
      const keyPair = deriveMessagingKeyPair(testPrivateKey);
      const address = publicKeyToAddress(keyPair.publicKey);
      const recovered = addressToPublicKey(address);

      expect(bytesToHex(recovered)).toBe(bytesToHex(keyPair.publicKey));
    });
  });

  describe('X25519 key derivation', () => {
    it('should derive X25519 public key from ed25519 seed', () => {
      const keyPair = deriveMessagingKeyPair(testPrivateKey);
      const x25519PubKey = getX25519PublicKey(keyPair.privateKey);

      expect(x25519PubKey.length).toBe(32);
      expect(isValidX25519PublicKey(x25519PubKey)).toBe(true);
    });

    it('should be deterministic', () => {
      const keyPair = deriveMessagingKeyPair(testPrivateKey);
      const x25519_1 = getX25519PublicKey(keyPair.privateKey);
      const x25519_2 = getX25519PublicKey(keyPair.privateKey);

      expect(bytesToHex(x25519_1)).toBe(bytesToHex(x25519_2));
    });
  });
});

describe('X25519 Key Exchange', () => {
  it('should compute same shared secret for Alice and Bob', () => {
    const aliceWallet = '0x' + 'aa'.repeat(32);
    const bobWallet = '0x' + 'bb'.repeat(32);

    const alice = deriveMessagingKeyPair(aliceWallet);
    const bob = deriveMessagingKeyPair(bobWallet);

    const aliceX25519 = getX25519PublicKey(alice.privateKey);
    const bobX25519 = getX25519PublicKey(bob.privateKey);

    // Alice computes shared secret with Bob's X25519 public key
    const aliceShared = computeSharedSecret(alice.privateKey, bobX25519);

    // Bob computes shared secret with Alice's X25519 public key
    const bobShared = computeSharedSecret(bob.privateKey, aliceX25519);

    // Both should be equal
    expect(bytesToHex(aliceShared)).toBe(bytesToHex(bobShared));
  });

  it('should produce different secrets for different key pairs', () => {
    const alice = deriveMessagingKeyPair('0x' + 'aa'.repeat(32));
    const bob = deriveMessagingKeyPair('0x' + 'bb'.repeat(32));
    const charlie = deriveMessagingKeyPair('0x' + 'cc'.repeat(32));

    const bobX25519 = getX25519PublicKey(bob.privateKey);
    const charlieX25519 = getX25519PublicKey(charlie.privateKey);

    const aliceBobShared = computeSharedSecret(alice.privateKey, bobX25519);
    const aliceCharlieShared = computeSharedSecret(alice.privateKey, charlieX25519);

    expect(bytesToHex(aliceBobShared)).not.toBe(bytesToHex(aliceCharlieShared));
  });
});

describe('Ed25519 Signatures', () => {
  it('should sign and verify messages', () => {
    const keyPair = deriveMessagingKeyPair('0x' + 'aa'.repeat(32));
    const message = new TextEncoder().encode('Hello, Solana!');

    const signature = sign(keyPair.privateKey, message);
    expect(signature.length).toBe(64); // ed25519 signature is 64 bytes

    const valid = verify(signature, message, keyPair.publicKey);
    expect(valid).toBe(true);
  });

  it('should reject invalid signatures', () => {
    const keyPair = deriveMessagingKeyPair('0x' + 'aa'.repeat(32));
    const message = new TextEncoder().encode('Hello');

    const signature = sign(keyPair.privateKey, message);

    // Tamper with signature
    signature[0] ^= 0xff;

    const valid = verify(signature, message, keyPair.publicKey);
    expect(valid).toBe(false);
  });

  it('should reject wrong public key', () => {
    const alice = deriveMessagingKeyPair('0x' + 'aa'.repeat(32));
    const bob = deriveMessagingKeyPair('0x' + 'bb'.repeat(32));
    const message = new TextEncoder().encode('Hello');

    const signature = sign(alice.privateKey, message);
    const valid = verify(signature, message, bob.publicKey);
    expect(valid).toBe(false);
  });
});

describe('AES-256-GCM Encryption', () => {
  const testKey = secureRandomBytes(32);

  describe('encrypt / decrypt', () => {
    it('should encrypt and decrypt data correctly', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');

      const encrypted = encrypt(testKey, plaintext);
      expect(encrypted.nonce.length).toBe(12);
      expect(encrypted.ciphertext.length).toBeGreaterThan(plaintext.length);

      const decrypted = decrypt(testKey, encrypted.nonce, encrypted.ciphertext);
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, World!');
    });

    it('should produce different ciphertext each time (random nonce)', () => {
      const plaintext = new TextEncoder().encode('Hello!');

      const encrypted1 = encrypt(testKey, plaintext);
      const encrypted2 = encrypt(testKey, plaintext);

      expect(bytesToHex(encrypted1.nonce)).not.toBe(bytesToHex(encrypted2.nonce));
      expect(bytesToHex(encrypted1.ciphertext)).not.toBe(bytesToHex(encrypted2.ciphertext));
    });

    it('should fail to decrypt with wrong key', () => {
      const plaintext = new TextEncoder().encode('Secret');
      const wrongKey = secureRandomBytes(32);

      const encrypted = encrypt(testKey, plaintext);

      expect(() => decrypt(wrongKey, encrypted.nonce, encrypted.ciphertext))
        .toThrow();
    });

    it('should fail to decrypt tampered ciphertext', () => {
      const plaintext = new TextEncoder().encode('Secret');
      const encrypted = encrypt(testKey, plaintext);

      // Tamper with ciphertext
      encrypted.ciphertext[0] ^= 0xff;

      expect(() => decrypt(testKey, encrypted.nonce, encrypted.ciphertext))
        .toThrow();
    });

    it('should throw on invalid key length', () => {
      const plaintext = new TextEncoder().encode('Hello');
      const shortKey = secureRandomBytes(16);

      expect(() => encrypt(shortKey, plaintext)).toThrow('Invalid key length');
    });
  });

  describe('encryptToBuffer / decryptFromBuffer', () => {
    it('should work with buffer format', () => {
      const plaintext = new TextEncoder().encode('Buffer test');

      const buffer = encryptToBuffer(testKey, plaintext);
      expect(buffer.length).toBeGreaterThan(12 + plaintext.length);

      const decrypted = decryptFromBuffer(testKey, buffer);
      expect(new TextDecoder().decode(decrypted)).toBe('Buffer test');
    });

    it('should throw on buffer too short', () => {
      const shortBuffer = new Uint8Array(10);
      expect(() => decryptFromBuffer(testKey, shortBuffer))
        .toThrow('Buffer too short');
    });
  });

  describe('authenticated data (AAD)', () => {
    it('should validate additional data', () => {
      const plaintext = new TextEncoder().encode('Message');
      const aad = new TextEncoder().encode('header data');

      const encrypted = encrypt(testKey, plaintext, aad);

      // Decrypt with same AAD should work
      const decrypted = decrypt(testKey, encrypted.nonce, encrypted.ciphertext, aad);
      expect(new TextDecoder().decode(decrypted)).toBe('Message');

      // Decrypt with different AAD should fail
      const wrongAad = new TextEncoder().encode('wrong header');
      expect(() => decrypt(testKey, encrypted.nonce, encrypted.ciphertext, wrongAad))
        .toThrow();
    });
  });
});

describe('End-to-end Encryption Flow (Solana-compatible)', () => {
  it('should allow Alice to encrypt for Bob using X25519', () => {
    // Setup
    const aliceWallet = '0x' + 'aa'.repeat(32);
    const bobWallet = '0x' + 'bb'.repeat(32);

    const alice = deriveMessagingKeyPair(aliceWallet);
    const bob = deriveMessagingKeyPair(bobWallet);

    const bobX25519 = getX25519PublicKey(bob.privateKey);
    const aliceX25519 = getX25519PublicKey(alice.privateKey);

    // Alice encrypts a message for Bob
    const sessionKey = computeSharedSecret(alice.privateKey, bobX25519);
    const plaintext = new TextEncoder().encode('Hello Bob, this is Alice!');
    const encrypted = encrypt(sessionKey, plaintext);

    // Bob decrypts the message from Alice
    const bobSessionKey = computeSharedSecret(bob.privateKey, aliceX25519);
    const decrypted = decrypt(bobSessionKey, encrypted.nonce, encrypted.ciphertext);

    expect(new TextDecoder().decode(decrypted)).toBe('Hello Bob, this is Alice!');
  });
});
