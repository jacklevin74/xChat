// X1 Encrypted Chat - Telegram-style UI
// Same encryption architecture, new interface

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';

// ============================================================================
// CONSTANTS
// ============================================================================

const DOMAIN_SEPARATOR = 'x1-msg-v1';
const SIGN_MESSAGE = 'X1 Encrypted Messaging - Sign to generate your encryption keys';
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

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
};

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

async function sendMessageToServer(from, to, nonce, ciphertext) {
    try {
        const res = await fetch(`${API_BASE}/api/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ from, to, nonce, ciphertext })
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
    // Return existing contact
    if (state.contacts.has(address)) {
        return state.contacts.get(address);
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

function shortenAddress(addr) {
    if (!addr || addr.length <= 12) return addr || '-';
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
            } else if (data.type === 'read_receipt') {
                // Someone read our message - update to double checkmark
                updateMessageReadStatus(data.messageId, data.readAt);
            } else if (data.type === 'message') {
                const decrypted = await processIncomingMessage(data.message);
                if (decrypted) {
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

        if (state.contacts.size === 0) {
            list.innerHTML = `
                <div style="padding: 40px 20px; text-align: center; color: var(--text-muted);">
                    <p>No conversations yet</p>
                    <p style="font-size: 13px; margin-top: 8px;">Start a new chat below</p>
                </div>
            `;
            return;
        }

        // Sort contacts by last message time
        const sorted = [...state.contacts.entries()].sort((a, b) => {
            const timeA = a[1].lastMessage?.timestamp || 0;
            const timeB = b[1].lastMessage?.timestamp || 0;
            return timeB - timeA;
        });

        let html = '';
        for (const [address, contact] of sorted) {
            if (!address || !contact) continue;

            const isActive = state.activeChat === address;
            const preview = contact.lastMessage?.content || 'No messages yet';
            const time = contact.lastMessage ? formatTime(contact.lastMessage.timestamp) : '';

            // Escape the address for onclick to prevent injection
            const escapedAddress = address.replace(/'/g, "\\'");

            html += `
                <div class="contact-item ${isActive ? 'active' : ''}" onclick="selectChat('${escapedAddress}')">
                    <div class="contact-avatar ${getAvatarClass(address)}">${getAvatarLetters(address)}</div>
                    <div class="contact-info">
                        <div class="contact-name">${shortenAddress(address)}</div>
                        <div class="contact-preview">${escapeHtml(preview.slice(0, 30))}${preview.length > 30 ? '...' : ''}</div>
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

function addMessageToChat(address, message) {
    if (!state.messages.has(address)) {
        state.messages.set(address, []);
    }
    state.messages.get(address).push(message);
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
            const content = msg.content || '';

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

            html += `
                <div class="message ${direction}" data-msg-id="${msg.id}">
                    <div class="message-content">${escapeHtml(content)}</div>
                    <div class="message-meta">
                        <span class="message-time">${time}</span>
                        ${statusHtml}
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;

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
        }

        const chatName = document.getElementById('chatName');
        if (chatName) chatName.textContent = shortenAddress(address);

        const chatStatus = document.getElementById('chatStatus');
        if (chatStatus) chatStatus.textContent = 'End-to-end encrypted';

        updateContactsList();
        renderMessages();

        // Send read receipts for unread messages in this chat
        sendReadReceipts(address);

        const messageInput = document.getElementById('messageInput');
        if (messageInput) messageInput.focus();
    } catch (e) {
        console.error('[selectChat] Error:', e);
    }
};

window.copyAddress = function() {
    if (state.activeChat) {
        navigator.clipboard.writeText(state.activeChat);
        showToast('Address copied!', 'success');
    }
};

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
// SEND MESSAGE
// ============================================================================

window.sendMessage = async function() {
    const input = document.getElementById('messageInput');
    const content = input.value.trim();

    if (!content || !state.activeChat) return;

    const contact = state.contacts.get(state.activeChat);
    if (!contact) {
        showToast('Contact not found', 'error');
        return;
    }

    try {
        const plaintext = new TextEncoder().encode(content);
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
            content,
            timestamp: Date.now(),
            direction: 'sent',
        };

        addMessageToChat(state.activeChat, message);
        contact.lastMessage = message;

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

// Auto-resize textarea
document.addEventListener('DOMContentLoaded', () => {
    const textarea = document.getElementById('messageInput');
    if (textarea) {
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 120) + 'px';
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
        // Wait a moment for wallet extensions to fully initialize
        await new Promise(r => setTimeout(r, 100));

        let provider = window.x1_wallet || window.x1Wallet || window.backpack ||
                       window.phantom?.solana || window.solana;

        if (!provider) {
            showToast('No wallet found. Please install X1 Wallet.', 'error');
            return;
        }

        // Always call connect() to ensure wallet is fully connected
        // (publicKey may exist from previous session but wallet disconnected internally)
        console.log('[Connect] Requesting wallet connection...');
        const resp = await provider.connect();
        const walletAddress = resp.publicKey.toString();
        state.wallet = walletAddress;
        state.walletProvider = provider;
        localStorage.setItem('x1msg-wallet', walletAddress);
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
    // Disconnect SSE
    disconnectSSE();

    // Clear state
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
    state.readMessageIds.clear();

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
        state.walletProvider = window.x1_wallet || window.x1Wallet || window.backpack ||
                               window.phantom?.solana || window.solana;
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
    setTimeout(tryAutoReconnect, 500);

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
