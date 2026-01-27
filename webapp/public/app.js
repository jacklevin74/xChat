// X1 Encrypted Messaging - Secure Version
// Keys derived from wallet signature (only owner can produce)

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
// SSE connection (replaces polling)

// Detect base path from URL
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
    privateKey: null,        // X25519 private key (from signature)
    publicKey: null,         // X25519 public key
    peers: new Map(),        // address -> { publicKey, sessionKey }
    messages: [],
    lastSender: null,
    lastFetchTime: 0,
    sseConnection: null,     // EventSource for real-time messages
    seenMessageIds: new Set(),
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
    // Derive X25519 private key from signature using HKDF
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
        // Sign a human-readable message that includes the public key
        const publicKeyB58 = base58Encode(publicKey);
        const messageText = `X1 Messaging: Register encryption key ${publicKeyB58}`;
        const messageBytes = new TextEncoder().encode(messageText);

        const { signature } = await provider.signMessage(messageBytes, 'utf8');
        const signatureB58 = base58Encode(signature);

        const res = await fetch(`${API_BASE}/api/keys`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address,
                x25519PublicKey: publicKeyB58,
                signature: signatureB58
            })
        });

        if (!res.ok) {
            const err = await res.json();
            console.error('Register key rejected:', err);
        }
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

async function fetchMessages(address, since = 0) {
    try {
        const res = await fetch(`${API_BASE}/api/messages/${encodeURIComponent(address)}?since=${since}`);
        if (!res.ok) return [];
        const data = await res.json();
        return data.messages || [];
    } catch (e) {
        console.error('Fetch messages failed:', e);
        return [];
    }
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

async function getOrCreatePeerSession(address) {
    if (state.peers.has(address)) {
        return state.peers.get(address);
    }

    // Lookup peer's public key from registry
    const publicKey = await lookupPublicKey(address);
    if (!publicKey) {
        return null; // Peer not registered
    }

    // Compute shared session key
    const sessionKey = computeSharedSecret(state.privateKey, publicKey);
    const peer = { publicKey, sessionKey };
    state.peers.set(address, peer);
    updatePeersList();
    return peer;
}

async function processIncomingMessage(msg) {
    if (state.seenMessageIds.has(msg.id)) return null;
    state.seenMessageIds.add(msg.id);

    try {
        const peer = await getOrCreatePeerSession(msg.from);
        if (!peer) return null;

        const nonce = base58Decode(msg.nonce);
        const ciphertext = base58Decode(msg.ciphertext);
        const plaintext = decrypt(peer.sessionKey, nonce, ciphertext);
        const content = new TextDecoder().decode(plaintext);

        return {
            id: msg.id,
            from: msg.from,
            to: msg.to,
            content,
            timestamp: msg.timestamp,
            direction: 'received',
        };
    } catch (e) {
        console.error('Decrypt failed:', e);
        return null;
    }
}

async function checkForNewMessages() {
    if (!state.wallet || !state.privateKey) return;

    const messages = await fetchMessages(state.wallet, state.lastFetchTime);
    let newCount = 0;

    for (const msg of messages) {
        const decrypted = await processIncomingMessage(msg);
        if (decrypted) {
            state.messages.push(decrypted);
            state.lastSender = decrypted.from;
            newCount++;
        }
    }

    if (messages.length > 0) {
        state.lastFetchTime = Math.max(...messages.map(m => m.timestamp));
    }

    if (newCount > 0) {
        updateUI();
        showToast(`${newCount} new message${newCount > 1 ? 's' : ''}!`, 'success');
    }
}

function connectSSE() {
    if (state.sseConnection) return;
    if (!state.wallet) return;

    const url = `${API_BASE}/api/stream/${encodeURIComponent(state.wallet)}`;
    console.log('[SSE] Connecting to:', url);

    const eventSource = new EventSource(url);

    eventSource.onopen = () => {
        console.log('[SSE] Connection opened');
    };

    eventSource.onmessage = async (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.type === 'connected') {
                console.log('[SSE] Connected to server');
                updateConnectionStatus(true);
            } else if (data.type === 'ping') {
                // Heartbeat, ignore
            } else if (data.type === 'message') {
                // New message received
                const decrypted = await processIncomingMessage(data.message);
                if (decrypted) {
                    state.messages.push(decrypted);
                    state.lastSender = decrypted.from;
                    state.lastFetchTime = Math.max(state.lastFetchTime, data.message.timestamp);
                    updateUI();
                    showToast('New message received!', 'success');
                }
            }
        } catch (e) {
            console.error('[SSE] Parse error:', e);
        }
    };

    eventSource.onerror = (error) => {
        console.error('[SSE] Error:', error);
        updateConnectionStatus(false);
        // EventSource will auto-reconnect
    };

    state.sseConnection = eventSource;
}

function disconnectSSE() {
    if (state.sseConnection) {
        state.sseConnection.close();
        state.sseConnection = null;
        console.log('[SSE] Disconnected');
    }
}

function updateConnectionStatus(online) {
    const connectionStatus = document.getElementById('connectionStatus');
    if (online) {
        connectionStatus.innerHTML = '<span class="status-dot online"></span><span>Live</span>';
    } else {
        connectionStatus.innerHTML = '<span class="status-dot offline"></span><span>Reconnecting...</span>';
    }
}

// ============================================================================
// UI
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
    }, 4000);
}

function shortenAddress(addr) {
    if (!addr || addr.length <= 12) return addr || '-';
    return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function updateUI() {
    const walletDisconnected = document.getElementById('walletDisconnected');
    const walletConnected = document.getElementById('walletConnected');
    const walletAddress = document.getElementById('walletAddress');
    const myAddress = document.getElementById('myAddress');
    const connectionStatus = document.getElementById('connectionStatus');
    const sendBtn = document.getElementById('sendBtn');

    if (state.wallet) {
        walletDisconnected.classList.add('hidden');
        walletConnected.classList.remove('hidden');
        walletAddress.textContent = shortenAddress(state.wallet);
        myAddress.textContent = shortenAddress(state.wallet);
        // SSE connection status is updated separately via updateConnectionStatus()
        if (state.sseConnection && state.sseConnection.readyState === EventSource.OPEN) {
            connectionStatus.innerHTML = '<span class="status-dot online"></span><span>Live</span>';
        } else if (state.sseConnection) {
            connectionStatus.innerHTML = '<span class="status-dot offline"></span><span>Connecting...</span>';
        } else {
            connectionStatus.innerHTML = '<span class="status-dot online"></span><span>Connected</span>';
        }
        sendBtn.disabled = false;
    } else {
        walletDisconnected.classList.remove('hidden');
        walletConnected.classList.add('hidden');
        walletAddress.textContent = '-';
        myAddress.textContent = 'Not connected';
        connectionStatus.innerHTML = '<span class="status-dot offline"></span><span>Offline</span>';
        sendBtn.disabled = true;
    }

    updatePeersList();
    updateMessagesList();
}

function updatePeersList() {
    const peersList = document.getElementById('peersList');
    if (state.peers.size === 0) {
        peersList.innerHTML = '<div class="empty-peers">No contacts yet</div>';
        return;
    }
    let html = '';
    for (const [address] of state.peers) {
        html += `<div class="peer-item" onclick="selectPeer('${address}')">
            <span class="peer-address">${shortenAddress(address)}</span>
            <span class="peer-select">Select</span>
        </div>`;
    }
    peersList.innerHTML = html;
}

function updateMessagesList() {
    const messagesList = document.getElementById('messagesList');
    if (state.messages.length === 0) {
        messagesList.innerHTML = `<div class="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
            </svg>
            <p>No messages yet</p>
            <span>Connect wallet and start messaging</span>
        </div>`;
        return;
    }
    let html = '';
    for (const msg of state.messages.slice().reverse()) {
        const time = new Date(msg.timestamp).toLocaleTimeString();
        const dir = msg.direction;
        const other = dir === 'sent' ? msg.to : msg.from;
        const clickable = dir === 'received' ? `onclick="replyTo('${other}')" style="cursor:pointer;" title="Click to reply"` : '';
        html += `<div class="message-item ${dir}" ${clickable}>
            <div class="message-header">
                <span class="message-direction">${dir}</span>
                <span class="message-time">${time}</span>
            </div>
            <div class="message-address">${dir === 'sent' ? 'To' : 'From'}: ${shortenAddress(other)}</div>
            <div class="message-content">${escapeHtml(msg.content)}</div>
        </div>`;
    }
    messagesList.innerHTML = html;
}

// ============================================================================
// WALLET CONNECTION
// ============================================================================

window.connectWallet = async function() {
    try {
        // Find wallet provider
        let provider = window.x1_wallet || window.x1Wallet || window.backpack ||
                       window.phantom?.solana || window.solana;

        if (!provider) {
            showToast('No wallet found. Install Phantom or Backpack.', 'error');
            return;
        }

        // Connect
        const resp = await provider.connect();
        const walletAddress = resp.publicKey.toString();
        state.wallet = walletAddress;
        state.walletProvider = provider;

        // Save wallet address for auto-reconnect
        localStorage.setItem('x1msg-wallet', walletAddress);

        // Check for cached signature
        const cacheKey = `x1msg-sig-${walletAddress}`;
        let signatureBytes = null;
        const cached = localStorage.getItem(cacheKey);

        if (cached) {
            signatureBytes = base58Decode(cached);
            showToast('Using cached keys', 'info');
        } else {
            // Request signature
            showToast('Please sign to generate encryption keys...', 'info');
            const message = new TextEncoder().encode(SIGN_MESSAGE);
            const { signature } = await provider.signMessage(message, 'utf8');
            signatureBytes = signature;

            // Cache signature
            localStorage.setItem(cacheKey, base58Encode(signature));
        }

        // Derive X25519 keypair from signature
        const keyPair = deriveX25519KeyPair(signatureBytes);
        state.privateKey = keyPair.privateKey;
        state.publicKey = keyPair.publicKey;

        // Register public key (with signature proof)
        showToast('Registering encryption key...', 'info');
        const registered = await registerPublicKey(walletAddress, keyPair.publicKey, provider);
        if (!registered) {
            showToast('Failed to register key', 'error');
            return;
        }

        updateUI();
        showToast('Connected!', 'success');

        // Connect to SSE for real-time messages
        connectSSE();

        console.log('Connected:', walletAddress);

    } catch (e) {
        console.error('Connect failed:', e);
        showToast('Connection failed: ' + e.message, 'error');
    }
};

window.disconnectWallet = function() {
    disconnectSSE();
    // Clear cached wallet (but keep signature for faster reconnect if they connect again)
    localStorage.removeItem('x1msg-wallet');
    state.wallet = null;
    state.walletProvider = null;
    state.privateKey = null;
    state.publicKey = null;
    state.lastFetchTime = 0;
    updateUI();
    showToast('Disconnected', 'info');
};

window.copyAddress = function() {
    if (state.wallet) {
        navigator.clipboard.writeText(state.wallet);
        showToast('Address copied!', 'success');
    }
};

window.selectPeer = function(address) {
    document.getElementById('recipientAddress').value = address;
    showToast(`Selected: ${shortenAddress(address)}`, 'info');
};

window.swapAddresses = function() {
    if (state.lastSender) {
        document.getElementById('recipientAddress').value = state.lastSender;
        showToast('Swapped to last sender', 'info');
    }
};

window.replyTo = function(address) {
    document.getElementById('recipientAddress').value = address;
    document.getElementById('messageContent').focus();
    showToast('Replying to ' + shortenAddress(address), 'info');
};

// ============================================================================
// MESSAGING
// ============================================================================

window.sendMessage = async function() {
    const recipientAddress = document.getElementById('recipientAddress').value.trim();
    const content = document.getElementById('messageContent').value.trim();

    if (!recipientAddress) {
        showToast('Enter recipient address', 'error');
        return;
    }
    if (!content) {
        showToast('Enter a message', 'error');
        return;
    }
    if (!state.privateKey) {
        showToast('Connect wallet first', 'error');
        return;
    }

    // Get or create peer session (looks up their public key)
    const peer = await getOrCreatePeerSession(recipientAddress);
    if (!peer) {
        showToast('Recipient not registered. They need to connect first.', 'error');
        return;
    }

    try {
        const plaintext = new TextEncoder().encode(content);
        const { nonce, ciphertext } = encrypt(peer.sessionKey, plaintext);

        const nonceB58 = base58Encode(nonce);
        const ciphertextB58 = base58Encode(ciphertext);

        const sent = await sendMessageToServer(state.wallet, recipientAddress, nonceB58, ciphertextB58);
        if (!sent) {
            showToast('Failed to send', 'error');
            return;
        }

        state.messages.push({
            id: bytesToHex(randomBytes(8)),
            from: state.wallet,
            to: recipientAddress,
            content,
            timestamp: Date.now(),
            direction: 'sent',
        });

        document.getElementById('messageContent').value = '';
        updateUI();
        showToast('Message sent!', 'success');

    } catch (e) {
        console.error('Send failed:', e);
        showToast('Send failed: ' + e.message, 'error');
    }
};

window.refreshMessages = async function() {
    if (!state.wallet) {
        showToast('Connect wallet first', 'error');
        return;
    }
    showToast('Checking...', 'info');
    await checkForNewMessages();
};

// ============================================================================
// INIT
// ============================================================================

async function tryAutoReconnect() {
    // Check for cached wallet and signature
    const cachedWallet = localStorage.getItem('x1msg-wallet');
    if (!cachedWallet) return;

    const cacheKey = `x1msg-sig-${cachedWallet}`;
    const cachedSig = localStorage.getItem(cacheKey);
    if (!cachedSig) return;

    try {
        // Restore keys from cached signature (no wallet interaction needed)
        const signatureBytes = base58Decode(cachedSig);
        const keyPair = deriveX25519KeyPair(signatureBytes);

        // Verify our key is still registered on server
        const serverKey = await lookupPublicKey(cachedWallet);
        if (!serverKey) {
            console.log('[Auto] Key not on server, need full reconnect');
            localStorage.removeItem('x1msg-wallet');
            return;
        }

        // Verify it matches our derived key
        const ourKeyB58 = base58Encode(keyPair.publicKey);
        const serverKeyB58 = base58Encode(serverKey);
        if (ourKeyB58 !== serverKeyB58) {
            console.log('[Auto] Key mismatch, need full reconnect');
            localStorage.removeItem('x1msg-wallet');
            return;
        }

        // Restore state
        state.wallet = cachedWallet;
        state.privateKey = keyPair.privateKey;
        state.publicKey = keyPair.publicKey;

        // Find wallet provider (for sending, but don't connect yet)
        state.walletProvider = window.x1_wallet || window.x1Wallet || window.backpack ||
                               window.phantom?.solana || window.solana;

        updateUI();
        connectSSE();
        console.log('[Auto] Restored session:', cachedWallet);

    } catch (e) {
        console.log('[Auto] Restore failed:', e.message);
        localStorage.removeItem('x1msg-wallet');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    updateUI();
    console.log('X1 Encrypted Messaging (Secure Version)');

    // Try auto-reconnect after a short delay (let wallet extension load)
    setTimeout(tryAutoReconnect, 500);
});

// Debug exports
window.messagingState = state;
window.base58Encode = base58Encode;
window.base58Decode = base58Decode;
