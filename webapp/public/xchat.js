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
};

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
    try {
        const publicKeyB58 = base58Encode(publicKey);
        const messageText = `X1 Messaging: Register encryption key ${publicKeyB58}`;
        const messageBytes = new TextEncoder().encode(messageText);
        const { signature } = await provider.signMessage(messageBytes, 'utf8');
        const signatureB58 = base58Encode(signature);

        const res = await fetch(`${API_BASE}/api/keys`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, x25519PublicKey: publicKeyB58, signature: signatureB58 })
        });
        return res.ok;
    } catch (e) {
        console.error('Register key failed:', e);
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
        return res.ok;
    } catch (e) {
        console.error('Send message failed:', e);
        return false;
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
                console.log(`[SSE] Connected, syncing ${data.messageCount} messages since ${data.since}`);
            } else if (data.type === 'history_complete') {
                // History sync is complete, now safe to update UI
                state.historyLoaded = true;
                console.log('[SSE] History sync complete. Contacts:', state.contacts.size, 'Messages:', [...state.messages.values()].reduce((a, b) => a + b.length, 0));
                updateContactsList();
                renderMessages();
            } else if (data.type === 'ping') {
                // Heartbeat
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
                        // Only increment unread for received messages not in active chat
                        if (decrypted.direction === 'received' && state.activeChat !== decrypted.contactAddress) {
                            contact.unread++;
                        }
                    }

                    // Only update UI after history is loaded (avoid thrashing during initial load)
                    if (state.historyLoaded) {
                        updateContactsList();
                        if (state.activeChat === decrypted.contactAddress) {
                            renderMessages();
                        }
                        if (decrypted.direction === 'received') {
                            showToast('New message received!', 'success');
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

            html += `
                <div class="message ${direction}">
                    <div class="message-content">${escapeHtml(content)}</div>
                    <div class="message-time">${time}</div>
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

        // Clear unread
        const contact = state.contacts.get(address);
        if (contact) {
            contact.unread = 0;
        }

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

        const sent = await sendMessageToServer(
            state.wallet,
            state.activeChat,
            base58Encode(nonce),
            base58Encode(ciphertext)
        );

        if (!sent) {
            showToast('Failed to send', 'error');
            return;
        }

        const message = {
            id: bytesToHex(randomBytes(8)),
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

window.connectWallet = async function() {
    try {
        let provider = window.x1_wallet || window.x1Wallet || window.backpack ||
                       window.phantom?.solana || window.solana;

        if (!provider) {
            showToast('No wallet found', 'error');
            return;
        }

        const resp = await provider.connect();
        const walletAddress = resp.publicKey.toString();
        state.wallet = walletAddress;
        state.walletProvider = provider;
        localStorage.setItem('x1msg-wallet', walletAddress);

        // Check for cached signature
        const cacheKey = `x1msg-sig-${walletAddress}`;
        let signatureBytes = null;
        const cached = localStorage.getItem(cacheKey);

        if (cached) {
            signatureBytes = base58Decode(cached);
        } else {
            showToast('Please sign to generate encryption keys...', 'info');
            const message = new TextEncoder().encode(SIGN_MESSAGE);
            const { signature } = await provider.signMessage(message, 'utf8');
            signatureBytes = signature;
            localStorage.setItem(cacheKey, base58Encode(signature));
        }

        const keyPair = deriveX25519KeyPair(signatureBytes);
        state.privateKey = keyPair.privateKey;
        state.publicKey = keyPair.publicKey;

        showToast('Registering encryption key...', 'info');
        const registered = await registerPublicKey(walletAddress, keyPair.publicKey, provider);
        if (!registered) {
            showToast('Failed to register key', 'error');
            return;
        }

        document.getElementById('connectOverlay').classList.add('hidden');
        document.getElementById('disconnectBtn')?.classList.remove('hidden');
        connectSSE();
        showToast('Connected!', 'success');

    } catch (e) {
        console.error('Connect failed:', e);
        showToast('Connection failed', 'error');
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

        document.getElementById('connectOverlay').classList.add('hidden');
        document.getElementById('disconnectBtn')?.classList.remove('hidden');
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
});

// Debug
window.chatState = state;
