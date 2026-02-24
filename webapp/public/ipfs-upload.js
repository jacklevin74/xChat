// xChat IPFS File Transfer — True E2E Encryption
//
// Encryption model:
//   File is encrypted with the X25519 ECDH shared secret between sender and
//   recipient — the same key that encrypts xChat messages. The recipient can
//   decrypt without a wallet signature or vault login. IPFS is just storage.
//
// Flow (send):
//   1. Derive shared secret:  ECDH(senderPrivKey, recipientPubKey) → HKDF
//   2. Encrypt file:          AES-256-GCM(sharedSecret, randomIV, fileBytes)
//   3. Upload ciphertext:     POST to vault.x1.xyz/ipfs
//   4. Send CID in message:   { type:'file', cid, name, size, iv, tag }
//
// Flow (receive):
//   1. Derive shared secret:  ECDH(recipientPrivKey, senderPubKey) → HKDF
//   2. Fetch ciphertext:      GET vault.x1.xyz/ipfs/files/<cid>
//   3. Decrypt:               AES-256-GCM(sharedSecret, iv, ciphertext)
//   4. Offer download:        createObjectURL(decryptedBytes)
//
// The server (IPFS) sees only random-looking ciphertext. No key ever touches
// the server. Two people who share a conversation can decrypt; nobody else can.
//
// Built: 2026-02-25 | Theo (@xxen_bot)

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

// ── Constants ────────────────────────────────────────────────────────────────

const IPFS_API       = 'https://vault.x1.xyz/ipfs';
const DOMAIN_SEP     = 'x1-msg-v1';              // same as xchat.js
const FILE_LABEL     = 'x1-file-v1';             // sub-label for file encryption
const MAX_FILE_BYTES = 50 * 1024 * 1024;         // 50 MB

// ── Shared-secret derivation (mirrors xchat.js computeSharedSecret) ──────────

function computeSharedSecret(ourPrivateKey, theirPublicKey) {
    const shared = x25519.getSharedSecret(ourPrivateKey, theirPublicKey);
    // Use a different label than messages so file keys are domain-separated
    return hkdf(sha256, shared, new Uint8Array(0),
        new TextEncoder().encode(DOMAIN_SEP + '-' + FILE_LABEL), 32);
}

// ── AES-256-GCM via WebCrypto (browser native — no extra deps) ───────────────

async function importAESKey(keyBytes) {
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function aesEncrypt(keyBytes, plaintext) {
    const key = await importAESKey(keyBytes);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { iv, ciphertext: new Uint8Array(ct) };
}

async function aesDecrypt(keyBytes, iv, ciphertext) {
    const key = await importAESKey(keyBytes);
    const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new Uint8Array(pt);
}

// ── IPFS upload/download ──────────────────────────────────────────────────────

async function ipfsUpload(ciphertextBytes, filename) {
    const blob = new Blob([ciphertextBytes], { type: 'application/octet-stream' });
    const form = new FormData();
    form.append('file', blob, filename + '.enc');

    const res = await fetch(`${IPFS_API}/api/v0/add`, {
        method: 'POST',
        headers: { 'X-Filename': filename },
        body: form,
    });

    if (!res.ok) {
        const msg = await res.text().catch(() => res.statusText);
        throw new Error(`IPFS upload failed (${res.status}): ${msg}`);
    }

    const data = await res.json();
    const cid  = data.Hash || data.cid || data.CID;
    if (!cid) throw new Error('IPFS returned no CID');
    return cid;
}

async function ipfsFetch(cid) {
    const res = await fetch(`${IPFS_API}/files/${cid}`);
    if (!res.ok) throw new Error(`IPFS fetch failed (${res.status})`);
    return new Uint8Array(await res.arrayBuffer());
}

// ── Base64 helpers (for embedding iv in message JSON) ────────────────────────

function toB64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

function fromB64(str) {
    return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Encrypt a File and upload it to IPFS.
 *
 * @param {File}       file            - Browser File object
 * @param {Uint8Array} ourPrivateKey   - Sender's X25519 private key (from state.privateKey)
 * @param {Uint8Array} theirPublicKey  - Recipient's X25519 public key (from contact.publicKey)
 * @param {Function}   onProgress      - ({ pct, msg }) callback
 * @returns {Object} message attachment payload — embed this in the xChat message
 */
export async function encryptAndUpload(file, ourPrivateKey, theirPublicKey, onProgress = () => {}) {
    if (file.size > MAX_FILE_BYTES) {
        throw new Error(`File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Max 50 MB.`);
    }

    onProgress({ pct: 5, msg: `Reading ${file.name}…` });
    const fileBytes = new Uint8Array(await file.arrayBuffer());

    onProgress({ pct: 20, msg: 'Deriving shared key…' });
    const sharedSecret = computeSharedSecret(ourPrivateKey, theirPublicKey);

    onProgress({ pct: 35, msg: 'Encrypting…' });
    const { iv, ciphertext } = await aesEncrypt(sharedSecret, fileBytes);

    onProgress({ pct: 55, msg: 'Uploading to IPFS…' });
    const cid = await ipfsUpload(ciphertext, file.name);

    onProgress({ pct: 100, msg: 'Done!' });

    // Payload embedded in the xChat message body as JSON
    return {
        type:    'xchat-file-v1',
        cid,
        name:    file.name,
        mime:    file.type || 'application/octet-stream',
        size:    file.size,
        iv:      toB64(iv),          // 12 bytes — safe to send openly
    };
}

/**
 * Fetch and decrypt a file attachment received in an xChat message.
 *
 * @param {Object}     attachment     - The xchat-file-v1 payload from the message
 * @param {Uint8Array} ourPrivateKey  - Recipient's X25519 private key
 * @param {Uint8Array} theirPublicKey - Sender's X25519 public key
 * @param {Function}   onProgress     - ({ pct, msg }) callback
 * @returns {Object} { bytes: Uint8Array, name: string, mime: string }
 */
export async function fetchAndDecrypt(attachment, ourPrivateKey, theirPublicKey, onProgress = () => {}) {
    const { cid, name, mime, iv: ivB64 } = attachment;

    onProgress({ pct: 10, msg: 'Fetching from IPFS…' });
    const ciphertext = await ipfsFetch(cid);

    onProgress({ pct: 60, msg: 'Decrypting…' });
    const sharedSecret = computeSharedSecret(ourPrivateKey, theirPublicKey);
    const iv           = fromB64(ivB64);
    const plaintext    = await aesDecrypt(sharedSecret, iv, ciphertext);

    onProgress({ pct: 100, msg: 'Done!' });

    return { bytes: plaintext, name, mime };
}

/**
 * Trigger a browser download of decrypted file bytes.
 */
export function downloadFile(bytes, name, mime) {
    const blob = new Blob([bytes], { type: mime });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/**
 * Check if a parsed message payload is an xchat-file attachment.
 */
export function isFileAttachment(payload) {
    return payload && payload.type === 'xchat-file-v1' && payload.cid && payload.name;
}
