// X1 Encrypted Chat - Telegram-style UI
// Same encryption architecture, new interface

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { encryptAndUpload, fetchAndDecrypt, downloadFile, isFileAttachment } from './ipfs-upload.js';

// ============================================================================
// CONSTANTS
// ============================================================================

const DOMAIN_SEPARATOR = 'x1-msg-v1';
const SIGN_MESSAGE = 'X1 Encrypted Messaging - Sign to generate your encryption keys';
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const DEMO_ADDRESS = 'DEMO';
const DEMO_DELAY_BASE = 2400; // base ms between messages (3x slower)
const DEMO_DELAY_RANDOM = () => 1000 + Math.random() * 4000; // 1-5 seconds random delay
const STREAM_CHUNK_SIZE = 4096; // bytes — raised from 120 to avoid chunking normal messages
const STREAM_TTL_MS = 2 * 60 * 1000; // 2 minutes

// Demo conversation messages - educational walkthrough
const DEMO_MESSAGES = [
    { direction: 'received', content: 'Welcome to X1 Encrypted Chat! Want to learn how it works?' },
    { direction: 'sent', content: 'Yes! How does the encryption actually work?' },
    { direction: 'received', content: 'Great question! When you sign in, your wallet signature is used to derive an X25519 encryption keypair using HKDF-SHA256' },
    { direction: 'sent', content: 'So my wallet creates my encryption keys? That\'s clever!' },
    { direction: 'received', content: 'Exactly! Your private encryption key never leaves your device. Only the public key is shared with the server' },
    { direction: 'sent', content: 'What happens when I send a message to someone?' },
    { direction: 'received', content: 'Your client performs ECDH (Elliptic Curve Diffie-Hellman) with the recipient\'s public key to create a shared secret' },
    { direction: 'sent', content: 'And that shared secret encrypts the message?' },
    { direction: 'received', content: 'Yes! Messages are encrypted with AES-256-GCM using that shared secret. Each message has a unique nonce for additional security' },
    { direction: 'sent', content: 'Can the server read our messages?' },
    { direction: 'received', content: 'No! The server only sees encrypted ciphertext. Without your private keys, messages are completely unreadable - even to us' },
    { direction: 'sent', content: 'What about metadata? Can anyone see who I\'m talking to?' },
    { direction: 'received', content: 'The server knows sender/recipient addresses for routing, but message content is fully encrypted end-to-end' },
    { direction: 'sent', content: 'This seems perfect for business use cases!' },
    { direction: 'received', content: 'Absolutely! You can use it for transaction invoicing - send payment requests with encrypted details only the payer can see' },
    { direction: 'sent', content: 'And confirmations too? Like receipts for completed transactions?' },
    { direction: 'received', content: 'Yes! Transaction confirmations, order details, contracts - all securely encrypted between wallet holders' },
    { direction: 'sent', content: 'I notice the checkmarks - single when sent, double when read?' },
    { direction: 'received', content: 'Exactly like Telegram! Single ✓ means delivered, double ✓✓ means the recipient has read it' },
    { direction: 'sent', content: 'This is amazing. Secure wallet-to-wallet messaging on X1! 🔐' },
    { direction: 'received', content: 'Try it out! Click "New Chat" and enter any X1 wallet address to start a secure conversation' },
];

const API_BASE = (() => {
    const path = window.location.pathname;
    const match = path.match(/^\/([^\/]+)/);
    return match ? `/${match[1]}` : '';
})();

// ============================================================================
// STATE
// ============================================================================

const state = {
    wallet: null,
    walletProvider: null,
    privateKey: null,
    publicKey: null,
    contacts: new Map(),      // address -> { publicKey, sessionKey, lastMessage, unread }
    messages: new Map(),      // address -> [messages]
    activeChat: null,
    sseConnection: null,
    seenMessageIds: new Set(),
    historyLoaded: false,     // Track if initial history has loaded
    pendingContacts: new Map(), // address -> Promise (prevent race conditions)
    lastSyncTimestamp: 0,     // Track last synced message timestamp for incremental sync
    readMessageIds: new Set(), // Track which messages have been read (persisted to localStorage)
    incomingStreams: new Map(), // stream_id -> { from, to, contactAddress, chunkTotal, receivedChunks, createdAt }
};

// Per-wallet context cache — keyed by wallet address so switching wallets
// preserves each user's own conversation history within the same page session.
const walletStates = new Map();

// ============================================================================
// READ MESSAGE TRACKING (localStorage persistence)
// ============================================================================

function getReadMessagesKey() {
    return state.wallet ? `xchat_read_${state.wallet}` : null;
}

function loadReadMessages() {
    const key = getReadMessagesKey();
    if (!key) return;

    try {
        const stored = localStorage.getItem(key);
        if (stored) {
            const ids = JSON.parse(stored);
            state.readMessageIds = new Set(ids);
            console.log(`[Read] Loaded ${state.readMessageIds.size} read message IDs`);
        }
    } catch (e) {
        console.error('[Read] Failed to load read messages:', e);
        state.readMessageIds = new Set();
    }
}

function saveReadMessages() {
    const key = getReadMessagesKey();
    if (!key) return;

    try {
        // Keep only the last 10000 message IDs to prevent unbounded growth
        const ids = [...state.readMessageIds].slice(-10000);
        localStorage.setItem(key, JSON.stringify(ids));
    } catch (e) {
        console.error('[Read] Failed to save read messages:', e);
    }
}

function markMessageAsRead(messageId) {
    if (!messageId) return;
    state.readMessageIds.add(messageId);
}

function markChatMessagesAsRead(contactAddress) {
    const messages = state.messages.get(contactAddress) || [];
    let marked = 0;
    for (const msg of messages) {
        if (msg.id && !state.readMessageIds.has(msg.id)) {
            state.readMessageIds.add(msg.id);
            marked++;
        }
    }
    if (marked > 0) {
        saveReadMessages();
    }
}

function isMessageRead(messageId) {
    return state.readMessageIds.has(messageId);
}

// ============================================================================
// BASE58 ENCODING
// ============================================================================

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

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// CRYPTO
// ============================================================================

function deriveX25519KeyPair(signature) {
    const privateKey = hkdf(sha256, signature, new Uint8Array(0),
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

function generateStreamId() {
    return base58Encode(randomBytes(12)) + '-' + Date.now().toString(36);
}

function chunkBytes(bytes, size) {
    const chunks = [];
    for (let i = 0; i < bytes.length; i += size) {
        chunks.push(bytes.slice(i, i + size));
    }
    return chunks;
}

function decrypt(key, nonce, ciphertext) {
    return gcm(key, nonce).decrypt(ciphertext);
}

// ============================================================================
// API
// ============================================================================

async function registerPublicKey(address, publicKey, provider) {
    const publicKeyB58 = base58Encode(publicKey);

    // First check if key is already registered
    try {
        const existingKey = await lookupPublicKey(address);
        if (existingKey && base58Encode(existingKey) === publicKeyB58) {
            console.log('[Register] Key already registered');
            return true;
        }
    } catch (e) {
        // Continue to registration
    }

    // Need to register - requires signature
    try {
        const messageText = `X1 Messaging: Register encryption key ${publicKeyB58}`;
        const messageBytes = new TextEncoder().encode(messageText);

        console.log('[Register] Requesting signature for key registration...');
        const { signature } = await provider.signMessage(messageBytes, 'utf8');
        const signatureB58 = base58Encode(signature);

        const res = await fetch(`${API_BASE}/api/keys`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, x25519PublicKey: publicKeyB58, signature: signatureB58 })
        });
        return res.ok;
    } catch (e) {
        // Check if user rejected
        const isUserRejection = e.message?.includes('User rejected') ||
                                e.message?.includes('user rejected') ||
                                e.code === 4001;
        if (isUserRejection) {
            console.log('[Register] User cancelled signature');
        } else {
            console.error('[Register] Failed:', e);
        }
        return false;
    }
}

async function lookupPublicKey(address) {
    try {
        const res = await fetch(`${API_BASE}/api/keys/${encodeURIComponent(address)}`);
        if (!res.ok) return null;
        const data = await res.json();
        return base58Decode(data.x25519PublicKey);
    } catch (e) {
        console.error('Lookup key failed:', e);
        return null;
    }
}

async function sendMessageToServer(from, to, nonce, ciphertext, streamMeta = null) {
    try {
        const payload = { from, to, nonce, ciphertext };
        if (streamMeta) {
            payload.stream_id = streamMeta.stream_id;
            payload.chunk_index = streamMeta.chunk_index;
            payload.chunk_total = streamMeta.chunk_total;
            payload.is_final = streamMeta.is_final;
        }
        const res = await fetch(`${API_BASE}/api/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res.ok) return null;
        const data = await res.json();
        return data.id;  // Return server-generated message ID
    } catch (e) {
        console.error('Send message failed:', e);
        return null;
    }
}

async function sendReadReceipts(contactAddress) {
    if (!state.wallet) return;

    // Get unread received messages from this contact
    const messages = state.messages.get(contactAddress) || [];
    const unreadIds = messages
        .filter(m => m.direction === 'received' && !m.readAt)
        .map(m => m.id);

    if (unreadIds.length === 0) return;

    try {
        const res = await fetch(`${API_BASE}/api/messages/read`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reader: state.wallet, messageIds: unreadIds })
        });

        if (res.ok) {
            // Mark messages as read locally
            const now = Date.now();
            for (const msg of messages) {
                if (unreadIds.includes(msg.id)) {
                    msg.readAt = now;
                }
            }
            console.log(`[Read] Sent read receipts for ${unreadIds.length} messages`);
        }
    } catch (e) {
        console.error('Send read receipts failed:', e);
    }
}

// Update message read status from SSE event
function updateMessageReadStatus(messageId, readAt) {
    // Find and update the message in any conversation
    for (const [address, messages] of state.messages) {
        for (const msg of messages) {
            if (msg.id === messageId) {
                msg.readAt = readAt;
                msg.read = true;
                // If this is the active chat, update the checkmark
                if (state.activeChat === address) {
                    const statusEl = document.querySelector(`.message-status[data-msg-id="${messageId}"]`);
                    if (statusEl) {
                        statusEl.classList.remove('sent');
                        statusEl.classList.add('read');
                        statusEl.innerHTML = `<svg viewBox="0 0 20 12" style="overflow:visible"><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M1 6l4 4 8-8"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M9 10l8-8"/></svg>`;
                    }
                }
                return;
            }
        }
    }
}

// ============================================================================
// CONTACT MANAGEMENT
// ============================================================================

async function getOrCreateContact(address) {
    // Return existing contact — but recompute sessionKey if it was stripped on save
    if (state.contacts.has(address)) {
        const c = state.contacts.get(address);
        if (!c.sessionKey && c.publicKey && state.privateKey) {
            c.sessionKey = computeSharedSecret(state.privateKey, c.publicKey);
        }
        return c;
    }

    // Check if we're already fetching this contact (prevent race condition)
    if (state.pendingContacts.has(address)) {
        await state.pendingContacts.get(address);
        return state.contacts.get(address);
    }

    // Create a promise for this contact lookup
    const promise = (async () => {
        const publicKey = await lookupPublicKey(address);
        if (!publicKey) {
            console.log('[Contact] Key not found for:', address?.slice(0,8));
            return null;
        }

        const sessionKey = computeSharedSecret(state.privateKey, publicKey);
        const contact = { publicKey, sessionKey, lastMessage: null, unread: 0 };
        state.contacts.set(address, contact);
        if (!state.messages.has(address)) {
            state.messages.set(address, []);
        }
        return contact;
    })();

    state.pendingContacts.set(address, promise);
    const result = await promise;
    state.pendingContacts.delete(address);
    return result;
}

function getAvatarClass(address) {
    const num = address.charCodeAt(0) % 6 + 1;
    return `avatar-${num}`;
}

function getAvatarLetters(address) {
    // Return first 2 characters of the address
    if (!address || address.length < 2) return address?.charAt(0)?.toUpperCase() || '?';
    return address.slice(0, 2).toUpperCase();
}

const ADDRESS_NAMES = {
    '3MKtPR7rfkDRPsDqUQY1zs3DgQZePBqPUvmH6njtCkno': 'Theo Prime',
};

function shortenAddress(addr) {
    if (!addr || addr.length <= 12) return addr || '-';
    if (ADDRESS_NAMES[addr]) return ADDRESS_NAMES[addr];
    return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

async function processIncomingMessage(msg) {
    if (state.seenMessageIds.has(msg.id)) {
        return null;
    }
    state.seenMessageIds.add(msg.id);

    try {
        // Determine if this is a sent or received message
        const isSent = msg.from === state.wallet;
        const contactAddress = isSent ? msg.to : msg.from;

        const contact = await getOrCreateContact(contactAddress);
        if (!contact) {
            console.log('[Process] Failed to get contact for:', contactAddress?.slice(0,8));
            return null;
        }

        const nonce = base58Decode(msg.nonce);
        const ciphertext = base58Decode(msg.ciphertext);
        const plaintext = decrypt(contact.sessionKey, nonce, ciphertext);
        const content = new TextDecoder().decode(plaintext);

        return {
            id: msg.id,
            from: msg.from,
            to: msg.to,
            content,
            timestamp: msg.timestamp,
            direction: isSent ? 'sent' : 'received',
            contactAddress,
            readAt: msg.readAt || null,
        };
    } catch (e) {
        console.error('Decrypt failed:', e);
        return null;
    }
}

async function processIncomingStreamChunk(data) {
    try {
        const { message } = data;
        if (!message || !message.stream_id) return null;

        const isSent = message.from === state.wallet;
        const contactAddress = isSent ? message.to : message.from;

        const contact = await getOrCreateContact(contactAddress);
        if (!contact) {
            console.log('[Stream] Failed to get contact for:', contactAddress?.slice(0,8));
            return null;
        }

        const nonce = base58Decode(message.nonce);
        const ciphertext = base58Decode(message.ciphertext);
        const plaintext = decrypt(contact.sessionKey, nonce, ciphertext);
        const content = new TextDecoder().decode(plaintext);

        // Initialize stream tracking
        if (!state.incomingStreams.has(message.stream_id)) {
            state.incomingStreams.set(message.stream_id, {
                from: message.from,
                to: message.to,
                contactAddress,
                chunkTotal: message.chunk_total,
                receivedChunks: new Map(),
                createdAt: Date.now(),
            });
        }

        const stream = state.incomingStreams.get(message.stream_id);
        stream.receivedChunks.set(message.chunk_index, content);
        // Update chunkTotal — final chunk has the authoritative total
        if (message.is_final && message.chunk_total) {
            stream.chunkTotal = message.chunk_total;
        } else if (message.chunk_total && message.chunk_total > stream.chunkTotal) {
            stream.chunkTotal = message.chunk_total;
        }

        // Reassemble in order from received chunks
        const ordered = [];
        const maxIdx = stream.receivedChunks.size;
        for (let i = 0; i < maxIdx; i++) {
            if (!stream.receivedChunks.has(i)) break;
            ordered.push(stream.receivedChunks.get(i));
        }
        const assembled = ordered.join('');

        // Ensure placeholder exists
        const placeholder = ensureStreamPlaceholder(contactAddress, message.stream_id);
        placeholder.from = message.from;
        placeholder.to = message.to;
        placeholder.timestamp = message.timestamp || Date.now();
        placeholder.direction = isSent ? 'sent' : 'received';

        const isFinal = !!message.is_final;
        updateStreamingPlaceholder(contactAddress, message.stream_id, assembled, isFinal);

        if (isFinal) {
            state.incomingStreams.delete(message.stream_id);
        }

        return {
            contactAddress,
            stream_id: message.stream_id,
            content: assembled,
            is_final: isFinal,
            direction: isSent ? 'sent' : 'received',
        };
    } catch (e) {
        console.error('[Stream] Decrypt failed:', e);
        return null;
    } finally {
        pruneExpiredStreams();
    }
}

// ============================================================================
// SSE CONNECTION
// ============================================================================

function connectSSE() {
    if (state.sseConnection) return;
    if (!state.wallet) return;

    // Use in-memory timestamp for incremental sync (within session only)
    // On page refresh, messages Map is empty so we need full sync (since=0)
    const hasLocalMessages = state.messages.size > 0;
    const since = hasLocalMessages ? state.lastSyncTimestamp : 0;

    const url = `${API_BASE}/api/stream/${encodeURIComponent(state.wallet)}?since=${since}`;
    console.log('[SSE] Connecting to:', url, 'since:', since, 'hasLocalMessages:', hasLocalMessages);

    const eventSource = new EventSource(url);

    eventSource.onopen = () => {
        console.log('[SSE] Connection opened');
    };

    eventSource.onmessage = async (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.type === 'connected') {
                updateConnectionStatus(true);
                console.log(`[SSE] Connected, syncing ${data.messageCount ?? '?'} messages since ${data.since ?? 0}`);

                // For backward compatibility: if server doesn't send history_complete,
                // mark history as loaded after a delay
                if (data.messageCount === undefined) {
                    setTimeout(() => {
                        if (!state.historyLoaded) {
                            state.historyLoaded = true;
                            console.log('[SSE] History loaded (legacy mode). Contacts:', state.contacts.size);
                            saveReadMessages();
                            updateContactsList();
                            renderMessages();
                        }
                    }, 1500);
                }
            } else if (data.type === 'history_complete') {
                // History sync is complete, now safe to update UI
                state.historyLoaded = true;
                console.log('[SSE] History sync complete. Contacts:', state.contacts.size, 'Messages:', [...state.messages.values()].reduce((a, b) => a + b.length, 0));
                saveReadMessages(); // Persist any newly read messages (e.g., sent messages)
                updateContactsList();
                renderMessages();
            } else if (data.type === 'ping') {
                // Heartbeat
            } else if (data.type === 'typing') {
                showTypingIndicator(data.from);
            } else if (data.type === 'read_receipt') {
                // Someone read our message - update to double checkmark
                updateMessageReadStatus(data.messageId, data.readAt);
            } else if (data.type === 'stream_chunk') {
                const chunkInfo = await processIncomingStreamChunk(data);
                if (chunkInfo) {
                    if (chunkInfo.direction === 'received') {
                        hideTypingIndicator(chunkInfo.contactAddress);
                    }

                    // Update contact preview with streaming content
                    const contact = state.contacts.get(chunkInfo.contactAddress);
                    if (contact) {
                        contact.lastMessage = {
                            content: chunkInfo.content,
                            timestamp: Date.now(),
                        };
                        contact._streaming = !chunkInfo.is_final;
                    }

                    if (state.historyLoaded) {
                        updateContactsList();
                        if (state.activeChat === chunkInfo.contactAddress) {
                            renderMessages();
                        }
                        if (chunkInfo.direction === 'received' && chunkInfo.is_final) {
                            showNewMessageToast();
                        }
                    }
                }
            } else if (data.type === 'message') {
                const decrypted = await processIncomingMessage(data.message);
                if (decrypted) {
                    // Clear typing indicator when message arrives
                    if (decrypted.direction === 'received') {
                        hideTypingIndicator(decrypted.contactAddress);
                    }

                    addMessageToChat(decrypted.contactAddress, decrypted);

                    // Track latest timestamp for incremental sync on reconnect
                    if (data.message.timestamp > state.lastSyncTimestamp) {
                        state.lastSyncTimestamp = data.message.timestamp;
                    }

                    // Update contact
                    const contact = state.contacts.get(decrypted.contactAddress);
                    if (contact) {
                        contact.lastMessage = decrypted;
                        // Only increment unread for received messages not in active chat and not already read
                        if (decrypted.direction === 'received' &&
                            state.activeChat !== decrypted.contactAddress &&
                            !isMessageRead(decrypted.id)) {
                            contact.unread++;
                        }
                        // Mark as read if in active chat or if sent by us
                        if (state.activeChat === decrypted.contactAddress || decrypted.direction === 'sent') {
                            markMessageAsRead(decrypted.id);
                            if (state.historyLoaded) {
                                saveReadMessages(); // Save immediately for real-time messages
                            }
                        }
                    }

                    // Only update UI after history is loaded (avoid thrashing during initial load)
                    if (state.historyLoaded) {
                        updateContactsList();
                        if (state.activeChat === decrypted.contactAddress) {
                            renderMessages();
                            // Send read receipt immediately if viewing this chat and window is focused
                            if (decrypted.direction === 'received' && document.hasFocus()) {
                                sendReadReceipts(decrypted.contactAddress);
                            }
                        }
                        if (decrypted.direction === 'received') {
                            showNewMessageToast();
                        }
                    }
                }
            }
        } catch (e) {
            console.error('[SSE] Parse error:', e);
        }
    };

    eventSource.onerror = (e) => {
        updateConnectionStatus(false);

        // EventSource auto-reconnects, but if it closes completely, we need to handle it
        if (eventSource.readyState === EventSource.CLOSED) {
            console.log('[SSE] Connection closed, will attempt reconnect...');
            state.sseConnection = null;
            // Reconnect after a delay (with incremental sync)
            setTimeout(() => {
                if (state.wallet && !state.sseConnection) {
                    connectSSE();
                }
            }, 3000);
        }
    };

    state.sseConnection = eventSource;
}

function disconnectSSE() {
    if (state.sseConnection) {
        state.sseConnection.close();
        state.sseConnection = null;
    }
    state.historyLoaded = false;
}

// Snapshot the current chat context for a specific wallet address.
function saveWalletState(address) {
    if (!address) return;
    // Strip sessionKey before saving — it's derived from privateKey which may change.
    // It gets recomputed lazily in getOrCreateContact().
    const contactsClean = new Map(
        [...state.contacts].map(([k, v]) => [k, { publicKey: v.publicKey, sessionKey: null, lastMessage: v.lastMessage, unread: v.unread }])
    );
    walletStates.set(address, {
        contacts: contactsClean,
        messages: new Map([...state.messages].map(([k, v]) => [k, [...v]])),
        activeChat: state.activeChat,
        seenMessageIds: new Set(state.seenMessageIds),
        historyLoaded: state.historyLoaded,
        lastSyncTimestamp: state.lastSyncTimestamp,
        readMessageIds: new Set(state.readMessageIds),
        // pendingContacts and incomingStreams are transient — don't restore them
    });
}

// Restore a previously saved wallet context, or initialise a clean slate.
function loadWalletState(address) {
    const saved = walletStates.get(address);
    if (saved) {
        state.contacts       = saved.contacts;
        state.messages       = saved.messages;
        state.activeChat     = saved.activeChat;
        state.seenMessageIds = saved.seenMessageIds;
        state.historyLoaded  = saved.historyLoaded;
        state.lastSyncTimestamp = saved.lastSyncTimestamp;
        state.readMessageIds = saved.readMessageIds;
        state.pendingContacts = new Map();
        state.incomingStreams  = new Map();
        return true; // restored
    }
    // First time for this wallet — start fresh
    state.contacts        = new Map();
    state.messages        = new Map();
    state.activeChat      = null;
    state.seenMessageIds  = new Set();
    state.historyLoaded   = false;
    state.lastSyncTimestamp = 0;
    state.readMessageIds  = new Set();
    state.pendingContacts = new Map();
    state.incomingStreams  = new Map();
    return false;
}

function updateConnectionStatus(online) {
    const status = document.getElementById('connectionStatus');
    if (online) {
        status.innerHTML = '<span class="status-dot online"></span><span>Live</span>';
    } else {
        status.innerHTML = '<span class="status-dot"></span><span>Reconnecting...</span>';
    }
}

// ============================================================================
// UI FUNCTIONS
// ============================================================================

// Rate limiting for new message toasts
const messageToastState = {
    recentToasts: [],      // Timestamps of recent "new message" toasts
    pendingCount: 0,       // Count of messages since last toast
    batchTimeout: null,    // Timeout for showing batched toast
};

function showNewMessageToast() {
    const now = Date.now();
    const TOAST_WINDOW = 5000;  // 5 second window
    const MAX_TOASTS = 3;

    // Clean up old timestamps
    messageToastState.recentToasts = messageToastState.recentToasts.filter(t => now - t < TOAST_WINDOW);

    if (messageToastState.recentToasts.length < MAX_TOASTS) {
        // Under limit - show individual toast
        messageToastState.recentToasts.push(now);
        showToast('New message received!', 'success');
    } else {
        // Over limit - batch them
        messageToastState.pendingCount++;

        // Clear existing batch timeout
        if (messageToastState.batchTimeout) {
            clearTimeout(messageToastState.batchTimeout);
        }

        // Show batched toast after a short delay
        messageToastState.batchTimeout = setTimeout(() => {
            if (messageToastState.pendingCount > 0) {
                showToast(`${messageToastState.pendingCount}+ new messages`, 'success');
                messageToastState.pendingCount = 0;
                messageToastState.recentToasts.push(Date.now());
            }
        }, 1000);
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function updateContactsList() {
    try {
        const list = document.getElementById('contactsList');
        if (!list) return;

        let html = '';

        // Always show Demo contact first
        const isDemoActive = state.activeChat === DEMO_ADDRESS;
        html += `
            <div class="contact-item ${isDemoActive ? 'active' : ''}" onclick="selectDemo()">
                <div class="contact-avatar" style="background: linear-gradient(135deg, #8b5cf6, #6366f1);">Demo</div>
                <div class="contact-info">
                    <div class="contact-name">Demo Conversation</div>
                    <div class="contact-preview">See how encrypted chat works</div>
                </div>
                <div class="contact-meta">
                    <div class="contact-time"></div>
                </div>
            </div>
        `;

        if (state.contacts.size === 0) {
            list.innerHTML = html;
            return;
        }

        // Sort contacts by last message time
        const sorted = [...state.contacts.entries()].sort((a, b) => {
            const timeA = a[1].lastMessage?.timestamp || 0;
            const timeB = b[1].lastMessage?.timestamp || 0;
            return timeB - timeA;
        });

        for (const [address, contact] of sorted) {
            if (!address || !contact) continue;

            const isActive = state.activeChat === address;
            const preview = contact._typing ? 'typing...' : (contact.lastMessage?.content || 'No messages yet');
            const time = contact.lastMessage ? formatTime(contact.lastMessage.timestamp) : '';

            // Escape the address for onclick to prevent injection
            const escapedAddress = address.replace(/'/g, "\\'");

            html += `
                <div class="contact-item ${isActive ? 'active' : ''}" onclick="selectChat('${escapedAddress}')">
                    <div class="contact-avatar ${getAvatarClass(address)}">${getAvatarLetters(address)}</div>
                    <div class="contact-info">
                        <div class="contact-name">${shortenAddress(address)}</div>
                        <div class="contact-preview ${contact._streaming ? 'streaming' : ''}">${escapeHtml(preview.slice(0, 30))}${preview.length > 30 ? '...' : ''}</div>
                    </div>
                    <div class="contact-meta">
                        <div class="contact-time">${time}</div>
                        ${contact.unread > 0 ? `<div class="contact-unread">${contact.unread}</div>` : ''}
                    </div>
                </div>
            `;
        }
        list.innerHTML = html;
    } catch (e) {
        console.error('[updateContactsList] Error:', e);
    }
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;

    if (diff < 24 * 60 * 60 * 1000) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (diff < 7 * 24 * 60 * 60 * 1000) {
        return date.toLocaleDateString([], { weekday: 'short' });
    } else {
        return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Render markdown-formatted text to HTML.
 * Handles: bold, italic, code blocks, inline code, lists, headings, line breaks.
 */
function renderMarkdown(text) {
    // Escape HTML first
    let html = escapeHtml(text);

    // Code blocks (```...```)
    html = html.replace(/```(\w*)\n?([\s\S]*?)```/g, '<pre><code>$2</code></pre>');

    // Inline code (`...`)
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold (**...**)
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

    // Italic (*...*)
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

    // Split into lines for block-level processing
    const lines = html.split('\n');
    const result = [];
    let inList = false;
    let lastWasBreak = false;

    for (const line of lines) {
        const trimmed = line.trim();

        // Horizontal rule (--- or ***)
        if (/^[-*_]{3,}$/.test(trimmed)) {
            if (inList) { result.push('</ul>'); inList = false; }
            result.push('<hr style="border:none;border-top:1px solid rgba(255,255,255,0.1);margin:6px 0">');
            lastWasBreak = true;
        }
        // Headings
        else if (trimmed.startsWith('### ')) {
            if (inList) { result.push('</ul>'); inList = false; }
            result.push(`<strong>${trimmed.slice(4)}</strong>`);
            lastWasBreak = false;
        } else if (trimmed.startsWith('## ')) {
            if (inList) { result.push('</ul>'); inList = false; }
            result.push(`<strong>${trimmed.slice(3)}</strong>`);
            lastWasBreak = false;
        } else if (trimmed.startsWith('# ')) {
            if (inList) { result.push('</ul>'); inList = false; }
            result.push(`<strong>${trimmed.slice(2)}</strong>`);
            lastWasBreak = false;
        }
        // List items (- or * with space, but not italic like *word*)
        else if (/^[-] /.test(trimmed) || /^\* /.test(trimmed)) {
            if (!inList) { result.push('<ul>'); inList = true; }
            result.push(`<li>${trimmed.slice(2)}</li>`);
            lastWasBreak = false;
        }
        // Numbered list items (1. 2. etc)
        else if (/^\d+\.\s/.test(trimmed)) {
            if (!inList) { result.push('<ol>'); inList = 'ol'; }
            result.push(`<li>${trimmed.replace(/^\d+\.\s/, '')}</li>`);
            lastWasBreak = false;
        }
        // Empty line — collapse consecutive blanks into one break
        else if (trimmed === '') {
            if (inList) { result.push(inList === 'ol' ? '</ol>' : '</ul>'); inList = false; lastWasBreak = true; }
            if (!lastWasBreak) { result.push('<div style="height:0.6em"></div>'); lastWasBreak = true; }
        }
        // Regular text
        else {
            if (inList) { result.push(inList === 'ol' ? '</ol>' : '</ul>'); inList = false; }
            result.push(line);
            lastWasBreak = false;
        }
    }
    if (inList) result.push(inList === 'ol' ? '</ol>' : '</ul>');

    return result.join('');
}

function addMessageToChat(address, message) {
    if (!state.messages.has(address)) {
        state.messages.set(address, []);
    }
    state.messages.get(address).push(message);
}

function ensureStreamPlaceholder(contactAddress, streamId) {
    const messages = state.messages.get(contactAddress) || [];
    const existing = messages.find(m => m.stream_id === streamId && m.is_streaming_placeholder);
    if (existing) return existing;

    const placeholder = {
        id: `stream-${streamId}`,
        stream_id: streamId,
        from: null,
        to: null,
        content: '',
        timestamp: Date.now(),
        direction: 'received',
        is_streaming_placeholder: true,
        streaming: true,
    };
    addMessageToChat(contactAddress, placeholder);
    return placeholder;
}

function updateStreamingPlaceholder(contactAddress, streamId, content, isFinal) {
    const messages = state.messages.get(contactAddress) || [];
    const placeholder = messages.find(m => m.stream_id === streamId && m.is_streaming_placeholder);
    if (!placeholder) return;
    placeholder.content = content;
    placeholder.streaming = !isFinal;
    if (isFinal) {
        placeholder.is_streaming_placeholder = false;
    }
}

function pruneExpiredStreams() {
    const now = Date.now();
    for (const [streamId, stream] of state.incomingStreams.entries()) {
        if (now - stream.createdAt > STREAM_TTL_MS) {
            state.incomingStreams.delete(streamId);
        }
    }
}

function renderMessages() {
    try {
        const container = document.getElementById('messagesContainer');
        if (!container) return;

        if (!state.activeChat) {
            container.innerHTML = '';
            return;
        }

        const messages = state.messages.get(state.activeChat) || [];

        if (messages.length === 0) {
            container.innerHTML = `
                <div style="flex: 1; display: flex; align-items: center; justify-content: center; color: var(--text-muted);">
                    <p>No messages yet. Say hello!</p>
                </div>
            `;
            return;
        }

        let html = '';
        let lastDate = null;

        for (const msg of messages) {
            if (!msg) continue;

            const timestamp = msg.timestamp || Date.now();
            const msgDate = new Date(timestamp).toDateString();
            if (msgDate !== lastDate) {
                lastDate = msgDate;
                const dateStr = formatDateDivider(timestamp);
                html += `<div class="message-date-divider"><span>${dateStr}</span></div>`;
            }

            const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const direction = msg.direction || 'received';
            
            // Parse message content - may contain file data
            let textContent = '';
            let fileData = msg.file || null;
            
            if (msg.content) {
                try {
                    const parsed = JSON.parse(msg.content);
                    if (parsed && typeof parsed === 'object') {
                        textContent = parsed.text || '';
                        fileData = parsed.file || fileData;
                    } else {
                        textContent = msg.content;
                    }
                } catch (e) {
                    // Not JSON, treat as plain text
                    textContent = msg.content;
                }
            }
            
            // Use msg.text if available (for locally created messages)
            if (msg.text) {
                textContent = msg.text;
            }

            // Checkmarks for sent messages: single = sent, double = read
            let statusHtml = '';
            if (direction === 'sent') {
                const isRead = msg.readAt || msg.read;
                const statusClass = isRead ? 'read' : 'sent';
                const checkmark = isRead
                    ? `<svg viewBox="0 0 20 12" style="overflow:visible"><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M1 6l4 4 8-8"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M9 10l8-8"/></svg>`  // Double checkmark
                    : `<svg viewBox="0 0 14 12"><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M1 6l4 4 8-8"/></svg>`;  // Single checkmark
                statusHtml = `<span class="message-status ${statusClass}" data-msg-id="${msg.id}">${checkmark}</span>`;
            }

            const streamingClass = msg.streaming ? ' streaming' : '';
            const streamingDots = msg.streaming ? '<span class="streaming-dots"><span>.</span><span>.</span><span>.</span></span>' : '';

            // Build file attachment HTML if present
            let fileHtml = '';
            if (fileData && (fileData.fileId || isFileAttachment(fileData))) {
                fileHtml = renderFileAttachment(fileData, direction, msg.from !== state.wallet ? msg.from : state.activeChat);
            }

            // Build text content HTML
            let textHtml = '';
            if (textContent) {
                textHtml = renderMarkdown(textContent);
            }

            html += `
                <div class="message ${direction}${streamingClass}" data-msg-id="${msg.id}">
                    ${fileHtml}
                    ${textHtml ? `<div class="message-content">${textHtml}${streamingDots}</div>` : ''}
                    <div class="message-meta">
                        <span class="message-time">${time}</span>
                        ${statusHtml}
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;

        // Re-render any existing reactions
        messageReactions.forEach((_, msgId) => renderReactions(msgId));

        // Attach right-click / long-press context menu to every message
        container.querySelectorAll('.message[data-msg-id]').forEach(el => {
            const msgId = el.dataset.msgId;
            const msgText = el.querySelector('.message-content')?.textContent?.trim() || '';

            // Right-click
            el.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                showCtxMenu(e.clientX, e.clientY, msgId, msgText);
            });

            // Long-press for mobile
            let pressTimer;
            el.addEventListener('pointerdown', () => {
                pressTimer = setTimeout(() => showCtxMenu(
                    el.getBoundingClientRect().left,
                    el.getBoundingClientRect().top,
                    msgId, msgText
                ), 500);
            });
            el.addEventListener('pointerup', () => clearTimeout(pressTimer));
            el.addEventListener('pointermove', () => clearTimeout(pressTimer));
        });

        // Use requestAnimationFrame to ensure DOM is updated before scrolling
        requestAnimationFrame(() => {
            container.scrollTop = container.scrollHeight;
        });
    } catch (e) {
        console.error('[renderMessages] Error:', e);
    }
}

function formatDateDivider(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;

    if (date.toDateString() === now.toDateString()) {
        return 'Today';
    } else if (diff < 2 * 24 * 60 * 60 * 1000) {
        return 'Yesterday';
    } else {
        return date.toLocaleDateString([], { month: 'long', day: 'numeric', year: 'numeric' });
    }
}

// ============================================================================
// TYPING INDICATOR
// ============================================================================

const typingTimers = new Map(); // address -> timeout ID

function showTypingIndicator(fromAddress) {
    // Clear existing timer for this sender
    if (typingTimers.has(fromAddress)) {
        clearTimeout(typingTimers.get(fromAddress));
    }

    // Auto-hide after 15 seconds (agent responses can take a while)
    typingTimers.set(fromAddress, setTimeout(() => {
        hideTypingIndicator(fromAddress);
    }, 15000));

    // Update chat status if this is the active chat
    if (state.activeChat === fromAddress) {
        const chatStatus = document.getElementById('chatStatus');
        if (chatStatus) {
            chatStatus.innerHTML = '<span class="typing-status">typing<span class="typing-dots"><span>.</span><span>.</span><span>.</span></span></span>';
        }
    }

    // Update contact preview
    const contact = state.contacts.get(fromAddress);
    if (contact) {
        contact._typing = true;
        updateContactsList();
    }
}

function hideTypingIndicator(fromAddress) {
    typingTimers.delete(fromAddress);

    const contact = state.contacts.get(fromAddress);
    if (contact) {
        contact._typing = false;
    }

    if (state.activeChat === fromAddress) {
        const chatStatus = document.getElementById('chatStatus');
        if (chatStatus) {
            chatStatus.textContent = 'End-to-end encrypted';
        }
    }

    updateContactsList();
}

// ============================================================================
// CHAT SELECTION
// ============================================================================

window.selectChat = function(address) {
    try {
        state.activeChat = address;

        // Clear unread and mark messages as read
        const contact = state.contacts.get(address);
        if (contact) {
            contact.unread = 0;
        }
        markChatMessagesAsRead(address);

        // Update UI - ensure elements exist
        const noChat = document.getElementById('noChat');
        const chatView = document.getElementById('chatView');

        if (noChat) noChat.classList.add('hidden');
        if (chatView) chatView.classList.remove('hidden');

        const avatar = document.getElementById('chatAvatar');
        if (avatar) {
            avatar.textContent = getAvatarLetters(address);
            avatar.className = `avatar ${getAvatarClass(address)}`;
            avatar.style.background = '';  // Reset if coming from demo
        }

        const chatName = document.getElementById('chatName');
        if (chatName) {
            chatName.innerHTML = `
                <span title="${address}" style="cursor:pointer;" onclick="copyAddress()">${shortenAddress(address)}</span>
                <button onclick="copyAddress()" title="Copy full address" style="background:none;border:none;cursor:pointer;padding:0 4px;color:var(--text-muted);vertical-align:middle;line-height:1;">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                    </svg>
                </button>
            `;
        }

        const chatStatus = document.getElementById('chatStatus');
        if (chatStatus) chatStatus.textContent = 'End-to-end encrypted';

        updateContactsList();
        renderMessages();

        // Send read receipts for unread messages in this chat
        sendReadReceipts(address);

        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            messageInput.disabled = false;
            messageInput.placeholder = 'Type a message...';
            messageInput.focus();
        }
    } catch (e) {
        console.error('[selectChat] Error:', e);
    }
};

window.selectDemo = async function() {
    state.activeChat = DEMO_ADDRESS;

    // Update UI
    const noChat = document.getElementById('noChat');
    const chatView = document.getElementById('chatView');

    if (noChat) noChat.classList.add('hidden');
    if (chatView) chatView.classList.remove('hidden');

    const avatar = document.getElementById('chatAvatar');
    if (avatar) {
        avatar.textContent = 'Demo';
        avatar.className = 'avatar';
        avatar.style.background = 'linear-gradient(135deg, #8b5cf6, #6366f1)';
    }

    const chatName = document.getElementById('chatName');
    if (chatName) chatName.textContent = 'Demo Conversation';

    const chatStatus = document.getElementById('chatStatus');
    if (chatStatus) chatStatus.textContent = 'See how encrypted chat works';

    updateContactsList();

    // Clear messages container and run demo
    const container = document.getElementById('messagesContainer');
    if (container) container.innerHTML = '';

    // Initialize demo messages array
    state.messages.set(DEMO_ADDRESS, []);

    // Display messages one by one with animation
    const baseTime = Date.now() - (DEMO_MESSAGES.length * 3000);
    for (let i = 0; i < DEMO_MESSAGES.length; i++) {
        // Random delay between messages (1-5 seconds)
        const delay = DEMO_DELAY_BASE + DEMO_DELAY_RANDOM();
        await new Promise(resolve => setTimeout(resolve, delay));

        if (state.activeChat !== DEMO_ADDRESS) return; // User switched away

        const msg = {
            id: `demo-${i}`,
            ...DEMO_MESSAGES[i],
            timestamp: baseTime + (i * 3000),
            readAt: DEMO_MESSAGES[i].direction === 'received' ? Date.now() : (i < DEMO_MESSAGES.length - 1 ? Date.now() : null),
        };
        state.messages.get(DEMO_ADDRESS).push(msg);
        renderMessages();
    }

    // Disable input for demo
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.placeholder = 'Demo mode - start a real chat to send messages';
        messageInput.disabled = true;
    }
};

window.copyAddress = function() {
    if (state.activeChat) {
        navigator.clipboard.writeText(state.activeChat);
        showToast('Address copied!', 'success');
    }
};

// ── Message context menu (right-click or long-press) ─────────────────────────

const ctxMenu = {
    el: null,
    msgId: null,
    msgText: null,
};

function initContextMenu() {
    ctxMenu.el = document.getElementById('msgContextMenu');
    if (!ctxMenu.el) return;

    // Emoji reactions
    ctxMenu.el.querySelectorAll('.ctx-emoji').forEach(btn => {
        btn.addEventListener('click', () => {
            if (!ctxMenu.msgId) return;
            addReaction(ctxMenu.msgId, btn.dataset.emoji);
            hideCtxMenu();
        });
    });

    // Copy text
    document.getElementById('ctxCopy').addEventListener('click', () => {
        if (ctxMenu.msgText) {
            navigator.clipboard.writeText(ctxMenu.msgText);
            showToast('Copied!', 'success');
        }
        hideCtxMenu();
    });

    // Delete message
    document.getElementById('ctxDelete').addEventListener('click', () => {
        if (ctxMenu.msgId) deleteMessage(ctxMenu.msgId);
        hideCtxMenu();
    });

    // Click outside → close
    document.addEventListener('click', (e) => {
        if (ctxMenu.el && !ctxMenu.el.contains(e.target)) hideCtxMenu();
    });
}

function showCtxMenu(x, y, msgId, msgText) {
    if (!ctxMenu.el) return;
    ctxMenu.msgId = msgId;
    ctxMenu.msgText = msgText;

    // Position — keep inside viewport
    ctxMenu.el.style.display = 'block';
    const rect = ctxMenu.el.getBoundingClientRect();
    const vw = window.innerWidth, vh = window.innerHeight;
    ctxMenu.el.style.left = Math.min(x, vw - rect.width - 8) + 'px';
    ctxMenu.el.style.top  = Math.min(y, vh - rect.height - 8) + 'px';
}

function hideCtxMenu() {
    if (ctxMenu.el) ctxMenu.el.style.display = 'none';
    ctxMenu.msgId = null;
    ctxMenu.msgText = null;
}

// Reactions stored in memory (per session)
const messageReactions = new Map(); // msgId → Map(emoji → count)

function addReaction(msgId, emoji) {
    if (!messageReactions.has(msgId)) messageReactions.set(msgId, new Map());
    const map = messageReactions.get(msgId);
    map.set(emoji, (map.get(emoji) || 0) + 1);
    renderReactions(msgId);
}

function renderReactions(msgId) {
    const msgEl = document.querySelector(`.message[data-msg-id="${msgId}"]`);
    if (!msgEl) return;
    let reactEl = msgEl.querySelector('.message-reactions');
    if (!reactEl) {
        reactEl = document.createElement('div');
        reactEl.className = 'message-reactions';
        msgEl.appendChild(reactEl);
    }
    const map = messageReactions.get(msgId) || new Map();
    reactEl.innerHTML = [...map.entries()]
        .map(([emoji, count]) => `<span class="reaction-badge" onclick="toggleReaction('${msgId}','${emoji}')">${emoji} ${count}</span>`)
        .join('');
}

window.toggleReaction = function(msgId, emoji) {
    const map = messageReactions.get(msgId);
    if (!map) return;
    const cur = map.get(emoji) || 0;
    if (cur <= 1) map.delete(emoji);
    else map.set(emoji, cur - 1);
    renderReactions(msgId);
};

function deleteMessage(msgId) {
    if (!state.activeChat) return;
    const msgs = state.messages.get(state.activeChat);
    if (!msgs) return;
    const idx = msgs.findIndex(m => m.id === msgId);
    if (idx !== -1) msgs.splice(idx, 1);
    renderMessages();
    showToast('Message deleted', 'success');
}

window.copyWalletAddress = function() {
    if (state.wallet) {
        navigator.clipboard.writeText(state.wallet);
        showToast('Your address copied!', 'success');
    }
};

function updateWalletDisplay() {
    const badgeEl = document.getElementById('walletBadge');
    const textEl = document.getElementById('walletAddressText');
    const avatarEl = document.getElementById('walletAvatar');
    if (!badgeEl || !textEl) return;

    if (state.wallet) {
        // Show first 5 characters only
        textEl.textContent = state.wallet.slice(0, 5);
        if (avatarEl) {
            avatarEl.textContent = state.wallet.slice(0, 2).toUpperCase();
        }
        badgeEl.classList.add('visible');
    } else {
        badgeEl.classList.remove('visible');
    }
}

window.deleteConversation = async function() {
    if (!state.activeChat || !state.walletProvider) return;

    try {
        const messageText = `X1 Messaging: Delete my message history`;
        const messageBytes = new TextEncoder().encode(messageText);
        showToast('Sign to delete...', 'info');
        const { signature } = await state.walletProvider.signMessage(messageBytes, 'utf8');

        const res = await fetch(`${API_BASE}/api/messages/${encodeURIComponent(state.wallet)}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ signature: base58Encode(signature) })
        });

        if (res.ok) {
            state.messages.clear();
            state.contacts.forEach(c => { c.lastMessage = null; c.unread = 0; });
            updateContactsList();
            renderMessages();
            showToast('Messages deleted', 'success');
        }
    } catch (e) {
        if (!e.message?.includes('User rejected')) {
            showToast('Delete failed', 'error');
        }
    }
};

// ============================================================================
// NEW CHAT MODAL
// ============================================================================

window.openNewChatModal = function() {
    document.getElementById('newChatModal').classList.remove('hidden');
    document.getElementById('newChatAddress').value = '';
    document.getElementById('newChatAddress').focus();
};

window.closeNewChatModal = function() {
    document.getElementById('newChatModal').classList.add('hidden');
};

window.startNewChat = async function() {
    const address = document.getElementById('newChatAddress').value.trim();
    if (!address) {
        showToast('Enter an address', 'error');
        return;
    }

    const contact = await getOrCreateContact(address);
    if (!contact) {
        showToast('User not registered. They need to connect first.', 'error');
        return;
    }

    closeNewChatModal();
    updateContactsList();
    selectChat(address);
};

// ============================================================================
// FILE UPLOAD
// ============================================================================

const fileState = {
    selectedFile: null,
    uploading: false,
};

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

window.triggerFileUpload = function() {
    if (fileState.uploading) return;
    document.getElementById('fileInput').click();
};

window.handleFileSelect = function(event) {
    const file = event.target.files[0];
    if (!file) return;

    // Check file size (50MB max)
    if (file.size > 50 * 1024 * 1024) {
        showToast('File too large. Max size is 50MB.', 'error');
        event.target.value = '';
        return;
    }

    fileState.selectedFile = file;

    // Show preview bar
    const previewBar = document.getElementById('filePreviewBar');
    const previewName = document.getElementById('filePreviewName');
    const previewSize = document.getElementById('filePreviewSize');

    previewName.textContent = file.name;
    previewSize.textContent = formatFileSize(file.size);
    previewBar.classList.add('visible');
};

window.clearFileSelection = function() {
    fileState.selectedFile = null;
    document.getElementById('fileInput').value = '';
    document.getElementById('filePreviewBar').classList.remove('visible');
};

// ── IPFS E2E File Upload ──────────────────────────────────────────────────────
// Encrypts with the X25519 shared secret (same key as messages).
// Recipient decrypts locally — IPFS sees only ciphertext.

async function uploadFile(file) {
    const progressBar  = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('uploadProgressFill');
    const progressText = document.getElementById('uploadProgressText');

    // Debug: log state at upload time
    console.log('[Upload] state.activeChat:', state.activeChat);
    console.log('[Upload] state.privateKey:', state.privateKey ? 'SET' : 'NULL');
    const contact = state.contacts.get(state.activeChat);
    console.log('[Upload] contact:', contact ? `publicKey=${contact.publicKey ? 'SET' : 'NULL'} sessionKey=${contact.sessionKey ? 'SET' : 'NULL'}` : 'NOT FOUND');

    // Need an active chat to know who the recipient is
    if (!state.activeChat) {
        showToast('❌ Upload failed: no active chat', 'error');
        throw new Error('No active chat');
    }
    if (!contact?.publicKey) {
        showToast('❌ Upload failed: recipient public key not found', 'error');
        throw new Error('Recipient public key not found');
    }
    if (!state.privateKey) {
        showToast('❌ Upload failed: wallet not connected', 'error');
        throw new Error('Wallet not connected');
    }

    fileState.uploading = true;
    progressBar.classList.add('visible');
    progressText.textContent = 'Starting upload…';
    progressFill.style.width = '0%';

    try {
        const attachment = await encryptAndUpload(
            file,
            state.privateKey,
            contact.publicKey,
            ({ pct, msg }) => {
                progressFill.style.width = pct + '%';
                progressText.textContent = msg;
                console.log(`[Upload] ${pct}% — ${msg}`);
            }
        );

        fileState.uploading = false;
        progressFill.style.width = '100%';
        progressText.textContent = `✅ Uploaded to IPFS — CID: ${attachment.cid}`;
        console.log('[Upload] ✅ Success! CID:', attachment.cid);
        // Keep success message visible briefly before hiding
        setTimeout(() => progressBar.classList.remove('visible'), 3000);
        return attachment;   // xchat-file-v1 payload — goes into message JSON

    } catch (e) {
        fileState.uploading = false;
        progressFill.style.width = '100%';
        progressFill.style.background = '#e53e3e';
        progressText.textContent = `❌ Upload failed: ${e.message}`;
        console.error('[Upload] ❌ Failed:', e);
        setTimeout(() => {
            progressBar.classList.remove('visible');
            progressFill.style.background = '';
        }, 5000);
        throw e;
    }
}

function isImageMimeType(mimeType) {
    return mimeType && mimeType.startsWith('image/');
}

function renderFileAttachment(fileData, direction, contactAddress) {
    // Handle both old local-file shape and new xchat-file-v1 IPFS shape
    const isIPFS = isFileAttachment(fileData);
    const name   = isIPFS ? fileData.name : (fileData.originalName || 'file');
    const mime   = isIPFS ? fileData.mime : (fileData.mimeType || '');
    const size   = isIPFS ? fileData.size : (fileData.size || 0);
    const cid    = isIPFS ? fileData.cid  : null;

    // Legacy local files still use the old URL
    const fileUrl = isIPFS ? null : `${API_BASE}/api/files/${fileData.fileId}`;

    // Legacy local image preview (non-IPFS only — IPFS images need decrypt first)
    if (!isIPFS && isImageMimeType(mime)) {
        return `
            <a href="${fileUrl}" target="_blank" rel="noopener">
                <img src="${fileUrl}" alt="${escapeHtml(name)}" class="message-file-image" 
                     onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                <div class="message-file" style="display: none;">
                    <div class="message-file-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                            <circle cx="8.5" cy="8.5" r="1.5"/>
                            <path d="M21 15l-5-5L5 21"/>
                        </svg>
                    </div>
                    <div class="message-file-info">
                        <div class="message-file-name">${escapeHtml(name)}</div>
                        <div class="message-file-size">${formatFileSize(size)}</div>
                    </div>
                </div>
            </a>
        `;
    }

    // ── IPFS E2E encrypted file ──────────────────────────────────────────────
    if (isIPFS) {
        const attachId = 'ipfs-' + cid.slice(0, 8);

        // Pick icon SVG based on mime type
        const isVideo = mime && mime.startsWith('video/');
        const isImg   = mime && mime.startsWith('image/');
        const isAudio = mime && mime.startsWith('audio/');
        const iconSvg = isVideo
            ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="2" y="7" width="15" height="10" rx="2" ry="2"/>
                <path d="M17 9l5-3v12l-5-3V9z"/>
               </svg>`
            : isImg
            ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                <circle cx="8.5" cy="8.5" r="1.5"/>
                <path d="M21 15l-5-5L5 21"/>
               </svg>`
            : isAudio
            ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>
               </svg>`
            : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0110 0v4"/>
               </svg>`;

        const typeLabel = isVideo ? '🎬 video' : isImg ? '🖼 image' : isAudio ? '🎵 audio' : '📎 file';

        // Register a one-time click handler for decrypt+download
        setTimeout(() => {
            const el = document.getElementById(attachId);
            if (!el) return;
            el.addEventListener('click', async () => {
                const contact = state.contacts.get(contactAddress || state.activeChat);
                if (!contact?.publicKey) {
                    showToast('Cannot decrypt: recipient public key missing', 'error');
                    return;
                }
                el.style.opacity = '0.6';
                el.title = 'Decrypting…';
                try {
                    const { bytes, name: n, mime: m } = await fetchAndDecrypt(
                        fileData,
                        state.privateKey,
                        contact.publicKey,
                        ({ msg }) => { el.title = msg; }
                    );
                    downloadFile(bytes, n, m);
                    el.style.opacity = '1';
                    el.title = 'Downloaded ✓';
                    // Show a brief "saved" indicator
                    const sizeEl = el.querySelector('.message-file-size');
                    if (sizeEl) sizeEl.textContent = '✓ Saved to downloads';
                } catch (e) {
                    showToast('Decrypt failed: ' + e.message, 'error');
                    el.style.opacity = '1';
                    el.title = 'Decrypt failed';
                }
            });
        }, 0);

        return `
            <div id="${attachId}" class="message-file" style="cursor:pointer;" title="Click to decrypt & download">
                <div class="message-file-icon">${iconSvg}</div>
                <div class="message-file-info">
                    <div class="message-file-name">${escapeHtml(name)}</div>
                    <div class="message-file-size">${formatFileSize(size)} · ${typeLabel} · 🔐 E2E · IPFS</div>
                </div>
            </div>
        `;
    }

    // ── Legacy local file (server no longer stores files) ───────────────────
    return `
        <div class="message-file" style="opacity:0.5;cursor:default;" title="This file was stored locally and is no longer available">
            <div class="message-file-icon">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                    <path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>
                </svg>
            </div>
            <div class="message-file-info">
                <div class="message-file-name">${escapeHtml(name)}</div>
                <div class="message-file-size">${formatFileSize(size)} · unavailable (pre-IPFS)</div>
            </div>
        </div>
    `;
}

// ============================================================================
// SEND MESSAGE
// ============================================================================

window.sendMessage = async function() {
    const input = document.getElementById('messageInput');
    let content = input.value.trim();
    const hasFile = fileState.selectedFile !== null;

    if (!content && !hasFile) return;
    if (!state.activeChat) return;

    const contact = state.contacts.get(state.activeChat);
    if (!contact) {
        showToast('Contact not found', 'error');
        return;
    }

    try {
        // Handle file upload first if present
        let fileData = null;
        if (hasFile) {
            try {
                // uploadFile returns a xchat-file-v1 IPFS attachment payload
                fileData = await uploadFile(fileState.selectedFile);
                clearFileSelection();
            } catch (e) {
                showToast('File upload failed', 'error');
                return;
            }
        }

        // Build message content
        // xchat-file-v1 payloads are self-describing; text is plain string for BC
        let messagePayload = {};
        if (fileData) {
            messagePayload.file = fileData;   // { type:'xchat-file-v1', cid, name, mime, size, iv }
        }
        if (content) {
            messagePayload.text = content;
        }

        // Backward-compat: pure text stays as plain string, not JSON
        const finalContent = fileData ? JSON.stringify(messagePayload) : content;
        const plaintext = new TextEncoder().encode(finalContent);

        if (plaintext.length > STREAM_CHUNK_SIZE) {
            const streamId = generateStreamId();
            const chunks = chunkBytes(plaintext, STREAM_CHUNK_SIZE);
            const total = chunks.length;

            for (let i = 0; i < chunks.length; i++) {
                const { nonce, ciphertext } = encrypt(contact.sessionKey, chunks[i]);
                const isFinal = i === chunks.length - 1;

                await sendMessageToServer(
                    state.wallet,
                    state.activeChat,
                    base58Encode(nonce),
                    base58Encode(ciphertext),
                    {
                        stream_id: streamId,
                        chunk_index: i,
                        chunk_total: total,
                        is_final: isFinal,
                    }
                );
            }

            // Show full message locally
            const message = {
                id: `stream-${streamId}`,
                from: state.wallet,
                to: state.activeChat,
                content,
                timestamp: Date.now(),
                direction: 'sent',
                stream_id: streamId,
            };
            addMessageToChat(state.activeChat, message);
            contact.lastMessage = message;

            input.value = '';
            input.style.height = 'auto';
            updateContactsList();
            renderMessages();
            return;
        }

        const { nonce, ciphertext } = encrypt(contact.sessionKey, plaintext);

        const messageId = await sendMessageToServer(
            state.wallet,
            state.activeChat,
            base58Encode(nonce),
            base58Encode(ciphertext)
        );

        if (!messageId) {
            showToast('Failed to send', 'error');
            return;
        }

        const message = {
            id: messageId,  // Use server-generated ID for read receipt matching
            from: state.wallet,
            to: state.activeChat,
            content: finalContent,
            timestamp: Date.now(),
            direction: 'sent',
            file: fileData,  // Include file data for rendering
            text: content,   // Include original text
        };

        addMessageToChat(state.activeChat, message);
        contact.lastMessage = { ...message, content: content || (fileData ? `📎 ${fileData.name || fileData.originalName || 'file'}` : '') };

        input.value = '';
        input.style.height = 'auto';
        updateContactsList();
        renderMessages();

    } catch (e) {
        console.error('Send failed:', e);
        showToast('Send failed', 'error');
    }
};

window.handleKeyDown = function(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
};

// Auto-resize textarea — show scrollbar only when multiline
document.addEventListener('DOMContentLoaded', () => {
    const textarea = document.getElementById('messageInput');
    if (textarea) {
        const resize = function() {
            this.style.height = 'auto';
            const newHeight = Math.min(this.scrollHeight, 120);
            this.style.height = newHeight + 'px';
            // Show scrollbar only when content exceeds max-height
            this.style.overflowY = this.scrollHeight > 120 ? 'auto' : 'hidden';
        };
        textarea.addEventListener('input', resize);
        // Also handle paste
        textarea.addEventListener('paste', function() {
            setTimeout(() => resize.call(this), 0);
        });
    }
});

// ============================================================================
// WALLET CONNECTION
// ============================================================================

function updateConnectOverlay(state, walletAddress = null) {
    const messageEl = document.getElementById('connectMessage');
    const walletInfoEl = document.getElementById('connectedWalletInfo');
    const walletAddrEl = document.getElementById('connectedWalletAddr');
    const connectBtn = document.getElementById('connectBtn');

    if (!messageEl || !connectBtn) return;

    if (state === 'sign' && walletAddress) {
        // Wallet connected, needs signature
        messageEl.textContent = 'Sign the message in your wallet to create an encrypted session';
        if (walletInfoEl) walletInfoEl.style.display = 'block';
        if (walletAddrEl) walletAddrEl.textContent = `${walletAddress.slice(0, 4)}...${walletAddress.slice(-4)}`;
        connectBtn.textContent = 'Waiting for signature...';
        connectBtn.disabled = true;
        connectBtn.style.opacity = '0.7';
    } else {
        // Reset to initial state
        messageEl.textContent = 'Connect your wallet to start secure, end-to-end encrypted messaging';
        if (walletInfoEl) walletInfoEl.style.display = 'none';
        connectBtn.textContent = 'Connect Wallet';
        connectBtn.disabled = false;
        connectBtn.style.opacity = '1';
    }
}

window.connectWallet = async function() {
    try {
        // Check if wallet is already available
        let provider = window.x1Wallet || window.x1 || window.x1_wallet || window.backpack ||
                       window.phantom?.solana || window.solana;

        // If not found, wait for wallet initialization events (up to 3 seconds)
        if (!provider) {
            provider = await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    // Final check before giving up
                    const p = window.x1Wallet || window.x1 || window.x1_wallet || window.backpack ||
                              window.phantom?.solana || window.solana;
                    if (p) resolve(p);
                    else reject(new Error('timeout'));
                }, 3000);

                const onInit = () => {
                    clearTimeout(timeout);
                    const p = window.x1Wallet || window.x1 || window.x1_wallet || window.backpack ||
                              window.phantom?.solana || window.solana;
                    if (p) resolve(p);
                };
                window.addEventListener('x1Wallet#initialized', onInit, { once: true });
                window.addEventListener('solana#initialized', onInit, { once: true });
            }).catch(() => null);
        }

        if (!provider) {
            showToast('No wallet found. Please install X1 Wallet or Phantom.', 'error');
            return;
        }

        // Always call connect() to ensure wallet is fully connected
        // (publicKey may exist from previous session but wallet disconnected internally)
        console.log('[Connect] Requesting wallet connection...');
        const resp = await provider.connect();
        const walletAddress = resp.publicKey.toString();

        // If a different wallet was already active, save its context before switching
        if (state.wallet && state.wallet !== walletAddress) {
            saveWalletState(state.wallet);
            disconnectSSE();
        }

        state.wallet = walletAddress;
        state.walletProvider = provider;
        localStorage.setItem('x1msg-wallet', walletAddress);

        // Restore this wallet's context (or initialise a clean slate)
        loadWalletState(walletAddress);
        loadReadMessages();

        // Check for cached signature
        const cacheKey = `x1msg-sig-${walletAddress}`;
        let signatureBytes = null;
        const cached = localStorage.getItem(cacheKey);

        if (cached) {
            signatureBytes = base58Decode(cached);
        } else {
            // Update overlay to show wallet connected, needs signature
            updateConnectOverlay('sign', walletAddress);

            const message = new TextEncoder().encode(SIGN_MESSAGE);
            const { signature } = await provider.signMessage(message, 'utf8');
            signatureBytes = signature;
            localStorage.setItem(cacheKey, base58Encode(signature));
            // Wait for wallet popup to fully close before next signature request
            await new Promise(r => setTimeout(r, 500));
        }

        const keyPair = deriveX25519KeyPair(signatureBytes);
        state.privateKey = keyPair.privateKey;
        state.publicKey = keyPair.publicKey;

        showToast('Registering encryption key...', 'info');
        const registered = await registerPublicKey(walletAddress, keyPair.publicKey, provider);
        if (!registered) {
            // Clean up partial state
            state.wallet = null;
            state.walletProvider = null;
            state.privateKey = null;
            state.publicKey = null;
            localStorage.removeItem('x1msg-wallet');
            localStorage.removeItem(cacheKey);
            // Don't show error toast - registerPublicKey handles it for user rejection
            return;
        }

        document.getElementById('connectOverlay').classList.add('hidden');
        document.getElementById('disconnectBtn')?.classList.remove('hidden');
        updateWalletDisplay();
        connectSSE();
        showToast('Connected!', 'success');

    } catch (e) {
        // Reset overlay to initial state
        updateConnectOverlay('reset');

        // Check if user rejected/cancelled the request
        const isUserRejection = e.message?.includes('User rejected') ||
                                e.message?.includes('User cancelled') ||
                                e.message?.includes('user rejected') ||
                                e.code === 4001; // Standard wallet rejection code

        if (isUserRejection) {
            console.log('[Connect] User cancelled');
            // Clean up partial state if wallet was set
            if (state.wallet && !state.privateKey) {
                state.wallet = null;
                state.walletProvider = null;
                localStorage.removeItem('x1msg-wallet');
            }
        } else {
            console.error('Connect failed:', e);
            showToast('Connection failed', 'error');
        }
    }
};

window.disconnectWallet = function() {
    // Save current wallet's context before tearing down
    if (state.wallet) {
        saveWalletState(state.wallet);
    }

    // Disconnect SSE
    disconnectSSE();

    // Clear active session state (context is preserved in walletStates)
    state.wallet = null;
    state.walletProvider = null;
    state.privateKey = null;
    state.publicKey = null;
    state.contacts.clear();
    state.messages.clear();
    state.activeChat = null;
    state.seenMessageIds.clear();
    state.historyLoaded = false;
    state.pendingContacts.clear();
    state.lastSyncTimestamp = 0;
    state.readMessageIds.clear();
    state.incomingStreams.clear();

    // Clear localStorage
    const cachedWallet = localStorage.getItem('x1msg-wallet');
    if (cachedWallet) {
        localStorage.removeItem('x1msg-wallet');
        localStorage.removeItem(`x1msg-sig-${cachedWallet}`);
    }

    // Reset UI
    document.getElementById('connectOverlay').classList.remove('hidden');
    document.getElementById('disconnectBtn')?.classList.add('hidden');
    document.getElementById('noChat').classList.remove('hidden');
    document.getElementById('chatView').classList.add('hidden');
    document.getElementById('contactsList').innerHTML = '';
    updateConnectionStatus(false);
    updateWalletDisplay();

    showToast('Disconnected', 'info');
};

// ============================================================================
// AUTO-RECONNECT
// ============================================================================

async function tryAutoReconnect() {
    const cachedWallet = localStorage.getItem('x1msg-wallet');
    if (!cachedWallet) return;

    const cacheKey = `x1msg-sig-${cachedWallet}`;
    const cachedSig = localStorage.getItem(cacheKey);
    if (!cachedSig) return;

    try {
        const signatureBytes = base58Decode(cachedSig);
        const keyPair = deriveX25519KeyPair(signatureBytes);

        const serverKey = await lookupPublicKey(cachedWallet);
        if (!serverKey) {
            localStorage.removeItem('x1msg-wallet');
            return;
        }

        const ourKeyB58 = base58Encode(keyPair.publicKey);
        const serverKeyB58 = base58Encode(serverKey);
        if (ourKeyB58 !== serverKeyB58) {
            localStorage.removeItem('x1msg-wallet');
            return;
        }

        state.wallet = cachedWallet;
        state.privateKey = keyPair.privateKey;
        state.publicKey = keyPair.publicKey;
        state.walletProvider = window.x1Wallet || window.x1 || window.x1_wallet || window.backpack ||
                               window.phantom?.solana || window.solana;

        // Restore any previously saved context for this wallet
        loadWalletState(cachedWallet);
        loadReadMessages();

        document.getElementById('connectOverlay').classList.add('hidden');
        document.getElementById('disconnectBtn')?.classList.remove('hidden');
        updateWalletDisplay();
        connectSSE();
        console.log('[Auto] Restored session:', cachedWallet);

    } catch (e) {
        console.log('[Auto] Restore failed:', e.message);
        localStorage.removeItem('x1msg-wallet');
    }
}

// ============================================================================
// INIT
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('X1 Chat initialized');
    initContextMenu();     // Message right-click menu + emoji reactions
    updateContactsList();  // Show demo contact immediately
    // Wait longer for wallet extensions to inject their providers
    const attemptReconnect = () => {
        const hasWallet = window.x1Wallet || window.x1 || window.x1_wallet || window.backpack ||
                          window.phantom?.solana || window.solana;
        if (hasWallet) {
            tryAutoReconnect();
        } else {
            // Listen for wallet init events as fallback
            const onInit = () => tryAutoReconnect();
            window.addEventListener('x1Wallet#initialized', onInit, { once: true });
            window.addEventListener('solana#initialized', onInit, { once: true });
            // Final fallback after 2 seconds
            setTimeout(tryAutoReconnect, 2000);
        }
    };
    setTimeout(attemptReconnect, 500);

    // Send read receipts when user focuses the window/tab
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible' && state.activeChat) {
            sendReadReceipts(state.activeChat);
        }
    });

    window.addEventListener('focus', () => {
        if (state.activeChat) {
            sendReadReceipts(state.activeChat);
        }
    });
});

// Debug
window.chatState = state;
