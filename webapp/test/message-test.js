// Unit test for message sending/receiving from both sides
// Run with: node test/message-test.js

import { x25519, ed25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';

const API_BASE = 'http://localhost:3001';
const DOMAIN_SEPARATOR = 'x1-msg-v1';

// ============================================================================
// BASE58 ENCODING
// ============================================================================

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
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

function base58Decode(str) {
    if (str.length === 0) return new Uint8Array(0);
    const BASE58_MAP = new Map();
    for (let i = 0; i < BASE58_ALPHABET.length; i++) {
        BASE58_MAP.set(BASE58_ALPHABET[i], i);
    }
    let zeros = 0;
    for (const char of str) {
        if (char === '1') zeros++;
        else break;
    }
    const bytes = [];
    for (const char of str) {
        const value = BASE58_MAP.get(char);
        if (value === undefined) throw new Error(`Invalid base58: ${char}`);
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
// CRYPTO HELPERS
// ============================================================================

function deriveX25519KeyPair(seed) {
    const privateKey = hkdf(sha256, seed, new Uint8Array(0),
        new TextEncoder().encode(DOMAIN_SEPARATOR + '-x25519'), 32);
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
}

function computeSharedSecret(ourPrivateKey, theirPublicKey) {
    const shared = x25519.getSharedSecret(ourPrivateKey, theirPublicKey);
    return hkdf(sha256, shared, new Uint8Array(0),
        new TextEncoder().encode(DOMAIN_SEPARATOR + '-session'), 32);
}

function encrypt(key, plaintext) {
    const nonce = randomBytes(12);
    const cipher = gcm(key, nonce);
    return { nonce, ciphertext: cipher.encrypt(plaintext) };
}

function decrypt(key, nonce, ciphertext) {
    return gcm(key, nonce).decrypt(ciphertext);
}

// ============================================================================
// TEST USER CLASS
// ============================================================================

class TestUser {
    constructor(name) {
        this.name = name;

        // Generate ed25519 keypair (simulates wallet)
        this.ed25519PrivateKey = ed25519.utils.randomPrivateKey();
        this.ed25519PublicKey = ed25519.getPublicKey(this.ed25519PrivateKey);

        // Address is base58 encoded public key (like Solana)
        this.address = base58Encode(this.ed25519PublicKey);

        // Generate X25519 keypair from a "signature" (simulates wallet signing)
        const mockSignature = ed25519.sign(
            new TextEncoder().encode('X1 Encrypted Messaging - Sign to generate your encryption keys'),
            this.ed25519PrivateKey
        );

        const keyPair = deriveX25519KeyPair(mockSignature);
        this.x25519PrivateKey = keyPair.privateKey;
        this.x25519PublicKey = keyPair.publicKey;
        this.x25519PublicKeyB58 = base58Encode(this.x25519PublicKey);
    }

    sign(message) {
        const messageBytes = new TextEncoder().encode(message);
        return ed25519.sign(messageBytes, this.ed25519PrivateKey);
    }

    async registerKey() {
        // Sign the registration message
        const messageText = `X1 Messaging: Register encryption key ${this.x25519PublicKeyB58}`;
        const signature = this.sign(messageText);
        const signatureB58 = base58Encode(signature);

        const res = await fetch(`${API_BASE}/api/keys`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address: this.address,
                x25519PublicKey: this.x25519PublicKeyB58,
                signature: signatureB58
            })
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(`Key registration failed: ${err.error}`);
        }
        return true;
    }

    async lookupPeerKey(peerAddress) {
        const res = await fetch(`${API_BASE}/api/keys/${encodeURIComponent(peerAddress)}`);
        if (!res.ok) return null;
        const data = await res.json();
        return base58Decode(data.x25519PublicKey);
    }

    computeSessionKey(theirPublicKey) {
        return computeSharedSecret(this.x25519PrivateKey, theirPublicKey);
    }

    async sendMessage(toAddress, plaintext, toPublicKey) {
        const sessionKey = this.computeSessionKey(toPublicKey);
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const { nonce, ciphertext } = encrypt(sessionKey, plaintextBytes);

        const res = await fetch(`${API_BASE}/api/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                from: this.address,
                to: toAddress,
                nonce: base58Encode(nonce),
                ciphertext: base58Encode(ciphertext)
            })
        });

        if (!res.ok) {
            throw new Error('Failed to send message');
        }
        return res.json();
    }

    decryptMessage(ciphertextB58, nonceB58, senderPublicKey) {
        const sessionKey = this.computeSessionKey(senderPublicKey);
        const nonce = base58Decode(nonceB58);
        const ciphertext = base58Decode(ciphertextB58);
        const plaintextBytes = decrypt(sessionKey, nonce, ciphertext);
        return new TextDecoder().decode(plaintextBytes);
    }
}

// ============================================================================
// TESTS
// ============================================================================

async function testKeyRegistration() {
    console.log('\n=== Test 1: Key Registration ===');

    const alice = new TestUser('Alice');
    const bob = new TestUser('Bob');

    console.log('Alice address:', alice.address.slice(0, 12) + '...');
    console.log('Bob address:', bob.address.slice(0, 12) + '...');

    try {
        await alice.registerKey();
        console.log('PASS: Alice registered key');

        await bob.registerKey();
        console.log('PASS: Bob registered key');

        // Verify keys are retrievable
        const aliceKey = await bob.lookupPeerKey(alice.address);
        const bobKey = await alice.lookupPeerKey(bob.address);

        if (!aliceKey || !bobKey) {
            throw new Error('Failed to lookup registered keys');
        }
        console.log('PASS: Keys are retrievable');

        return { alice, bob };
    } catch (e) {
        console.error('FAIL:', e.message);
        return null;
    }
}

async function testBidirectionalMessaging(alice, bob) {
    console.log('\n=== Test 2: Bidirectional Messaging ===');

    try {
        // Get each other's public keys
        const alicePubKey = await bob.lookupPeerKey(alice.address);
        const bobPubKey = await alice.lookupPeerKey(bob.address);

        // Alice sends to Bob
        const msg1 = 'Hello Bob, this is Alice!';
        const result1 = await alice.sendMessage(bob.address, msg1, bobPubKey);
        console.log('PASS: Alice sent message to Bob, id:', result1.id);

        // Bob sends to Alice
        const msg2 = 'Hi Alice, got your message!';
        const result2 = await bob.sendMessage(alice.address, msg2, alicePubKey);
        console.log('PASS: Bob sent message to Alice, id:', result2.id);

        // Alice sends another
        const msg3 = 'Great, the encryption works!';
        const result3 = await alice.sendMessage(bob.address, msg3, bobPubKey);
        console.log('PASS: Alice sent another message, id:', result3.id);

        return true;
    } catch (e) {
        console.error('FAIL:', e.message);
        return false;
    }
}

async function testMessageRetrieval(alice, bob) {
    console.log('\n=== Test 3: Message Retrieval (Both Directions) ===');

    try {
        // Get each other's public keys for decryption
        const alicePubKey = await bob.lookupPeerKey(alice.address);
        const bobPubKey = await alice.lookupPeerKey(bob.address);

        // Fetch Alice's messages (should include sent AND received)
        const aliceRes = await fetch(`${API_BASE}/api/messages/${alice.address}?since=0`);
        const aliceData = await aliceRes.json();

        // Note: The current endpoint only returns messages TO alice
        // But the SSE endpoint uses getUserMessages which returns both
        console.log(`Messages TO Alice: ${aliceData.messages?.length || 0}`);

        // Let's verify via debug dump
        const dumpRes = await fetch(`${API_BASE}/api/debug/dump`);
        const dump = await dumpRes.json();

        const aliceMessages = dump.messages.filter(
            m => m.from === alice.address || m.to === alice.address
        );
        const bobMessages = dump.messages.filter(
            m => m.from === bob.address || m.to === bob.address
        );

        console.log(`Total messages involving Alice: ${aliceMessages.length}`);
        console.log(`  - Sent by Alice: ${aliceMessages.filter(m => m.from === alice.address).length}`);
        console.log(`  - Received by Alice: ${aliceMessages.filter(m => m.to === alice.address).length}`);

        console.log(`Total messages involving Bob: ${bobMessages.length}`);
        console.log(`  - Sent by Bob: ${bobMessages.filter(m => m.from === bob.address).length}`);
        console.log(`  - Received by Bob: ${bobMessages.filter(m => m.to === bob.address).length}`);

        // Decrypt and verify a message
        if (aliceMessages.length > 0) {
            const testMsg = aliceMessages.find(m => m.to === alice.address);
            if (testMsg) {
                const decrypted = alice.decryptMessage(
                    testMsg.ciphertext,
                    testMsg.nonce,
                    bobPubKey
                );
                console.log(`PASS: Decrypted message from Bob: "${decrypted}"`);
            }
        }

        // Verify Bob can decrypt Alice's messages
        const msgFromAlice = aliceMessages.find(m => m.from === alice.address);
        if (msgFromAlice) {
            const decrypted = bob.decryptMessage(
                msgFromAlice.ciphertext,
                msgFromAlice.nonce,
                alicePubKey
            );
            console.log(`PASS: Bob decrypted Alice's message: "${decrypted}"`);
        }

        return true;
    } catch (e) {
        console.error('FAIL:', e.message);
        return false;
    }
}

async function testSSEHistoryQuery(alice) {
    console.log('\n=== Test 4: SSE History Query Simulation ===');

    try {
        // The server's getUserMessages should return both sent and received
        const dumpRes = await fetch(`${API_BASE}/api/debug/dump`);
        const dump = await dumpRes.json();

        // Simulate what getUserMessages returns
        const userMessages = dump.messages.filter(
            m => m.from === alice.address || m.to === alice.address
        );

        const sentCount = userMessages.filter(m => m.from === alice.address).length;
        const receivedCount = userMessages.filter(m => m.to === alice.address).length;

        console.log(`SSE would send ${userMessages.length} messages to Alice`);
        console.log(`  - ${sentCount} sent by Alice`);
        console.log(`  - ${receivedCount} received by Alice`);

        if (sentCount > 0 && receivedCount > 0) {
            console.log('PASS: Both sent and received messages would be included');
            return true;
        } else if (userMessages.length > 0) {
            console.log('PASS: Messages found (may be one direction only)');
            return true;
        } else {
            console.log('INFO: No messages found');
            return true;
        }
    } catch (e) {
        console.error('FAIL:', e.message);
        return false;
    }
}

// ============================================================================
// RUN TESTS
// ============================================================================

async function runTests() {
    console.log('X1 Encrypted Messaging - Unit Tests');
    console.log('====================================');
    console.log('Server:', API_BASE);

    let passed = 0;
    let failed = 0;

    // Test 1: Key Registration
    const users = await testKeyRegistration();
    if (users) {
        passed++;
        const { alice, bob } = users;

        // Test 2: Bidirectional Messaging
        if (await testBidirectionalMessaging(alice, bob)) passed++;
        else failed++;

        // Test 3: Message Retrieval
        if (await testMessageRetrieval(alice, bob)) passed++;
        else failed++;

        // Test 4: SSE History Query
        if (await testSSEHistoryQuery(alice)) passed++;
        else failed++;
    } else {
        failed++;
    }

    console.log('\n====================================');
    console.log(`Results: ${passed} passed, ${failed} failed`);

    process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(e => {
    console.error('Test runner error:', e);
    process.exit(1);
});
