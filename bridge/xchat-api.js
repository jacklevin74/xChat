// xchat bridge — HTTP/SSE client for xchat server

import http from 'node:http';
import https from 'node:https';

/**
 * Register X25519 public key on the xchat server.
 */
export async function registerKey(server, address, x25519PublicKeyB58, signatureB58) {
    const res = await fetch(`${server}/api/keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            address,
            x25519PublicKey: x25519PublicKeyB58,
            signature: signatureB58,
        }),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(`Register key failed: ${res.status} ${err.error || ''}`);
    }
    return true;
}

/**
 * Lookup a wallet's X25519 public key from the server.
 * Returns the base58-encoded key string, or null if not found.
 */
export async function lookupKey(server, address) {
    const res = await fetch(`${server}/api/keys/${encodeURIComponent(address)}`);
    if (!res.ok) return null;
    const data = await res.json();
    return data.x25519PublicKey || null;
}

/**
 * Send an encrypted message via the xchat server.
 * nonce and ciphertext should be base58-encoded strings.
 */
export async function sendMessage(server, from, to, nonce, ciphertext) {
    const res = await fetch(`${server}/api/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ from, to, nonce, ciphertext }),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(`Send message failed: ${res.status} ${err.error || ''}`);
    }
    const data = await res.json();
    return data.id;
}

/**
 * Send a typing indicator to a recipient via the xchat server.
 */
export async function sendTyping(server, from, to) {
    await fetch(`${server}/api/typing`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ from, to }),
    }).catch(() => {}); // best-effort, don't fail on typing indicator
}

/**
 * Connect to the xchat SSE stream for real-time messages.
 * Returns a cleanup function to close the connection.
 *
 * onEvent receives parsed SSE data objects:
 *   { type: 'message', message: { id, from, to, nonce, ciphertext, timestamp } }
 *   { type: 'connected', since, messageCount }
 *   { type: 'history_complete', count }
 *   { type: 'read_receipt', messageId, readAt }
 *   { type: 'ping' }
 */
export function connectSSE(server, address, since, onEvent) {
    let destroyed = false;
    let currentReq = null;
    let reconnectTimer = null;
    let reconnectDelay = 1000;

    function connect() {
        if (destroyed) return;

        const url = `${server}/api/stream/${encodeURIComponent(address)}?since=${since}`;
        const mod = url.startsWith('https') ? https : http;

        currentReq = mod.get(url, (res) => {
            if (res.statusCode !== 200) {
                console.error(`[SSE] Bad status: ${res.statusCode}`);
                res.destroy();
                scheduleReconnect();
                return;
            }

            reconnectDelay = 1000; // reset on success
            let buffer = '';

            res.setEncoding('utf8');
            res.on('data', (chunk) => {
                buffer += chunk;
                // SSE events are separated by \n\n
                const parts = buffer.split('\n\n');
                buffer = parts.pop(); // keep incomplete part
                for (const part of parts) {
                    for (const line of part.split('\n')) {
                        if (line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.slice(6));
                                // Update since timestamp for reconnect
                                if (data.type === 'message' && data.message?.timestamp) {
                                    since = Math.max(since, data.message.timestamp);
                                }
                                onEvent(data);
                            } catch (e) {
                                // ignore parse errors
                            }
                        }
                    }
                }
            });

            res.on('end', () => {
                if (!destroyed) scheduleReconnect();
            });

            res.on('error', () => {
                if (!destroyed) scheduleReconnect();
            });
        });

        currentReq.on('error', () => {
            if (!destroyed) scheduleReconnect();
        });
    }

    function scheduleReconnect() {
        if (destroyed) return;
        console.log(`[SSE] Reconnecting in ${reconnectDelay / 1000}s...`);
        reconnectTimer = setTimeout(() => {
            reconnectDelay = Math.min(reconnectDelay * 2, 30000);
            connect();
        }, reconnectDelay);
    }

    connect();

    // Return cleanup function
    return function destroy() {
        destroyed = true;
        if (reconnectTimer) clearTimeout(reconnectTimer);
        if (currentReq) {
            currentReq.destroy();
            currentReq = null;
        }
    };
}
