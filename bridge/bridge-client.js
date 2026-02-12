// xchat bridge — per-TCP-connection client state and logic

import {
    deriveKeys, computeSessionKey, encrypt, decrypt,
    signKeyRegistration, base58Decode,
} from './crypto.js';
import { registerKey, lookupKey, sendMessage, sendTyping, connectSSE } from './xchat-api.js';
import { sendToAgent } from './openclaw.js';

export class BridgeClient {
    constructor(config) {
        this.config = config; // { xchatServer, openclaw: { agentId, sessionId } }
        this.keys = null;     // from deriveKeys()
        this.peers = new Map(); // address -> { x25519Public, sessionKey }
        this.sseCleanup = null;
        this.onEvent = null;  // callback for events to push to TCP client
        this._pendingMessages = new Map(); // sender -> { messages[], timer, lastMsgId }
        this._senderLocks = new Map();    // sender -> Promise chain (serialize agent calls per sender)
    }

    /**
     * Authenticate with an ed25519 private key.
     * Derives X25519 keys, registers with xchat server, starts SSE listener.
     */
    async auth(privateKey) {
        // Derive all keys
        this.keys = deriveKeys(privateKey);

        // Bind agent session to this wallet — each wallet gets its own session
        this.config.openclaw.sessionId = this.keys.address;

        // Sign and register X25519 public key with xchat server
        let registered = false;
        try {
            const signature = signKeyRegistration(this.keys.ed25519Private, this.keys.x25519PublicB58);
            await registerKey(
                this.config.xchatServer,
                this.keys.address,
                this.keys.x25519PublicB58,
                signature
            );
            registered = true;
        } catch (e) {
            console.error('[Bridge] Key registration failed (xchat server may be down):', e.message);
        }

        // Start SSE listener for incoming messages
        if (registered) {
            this.startSSE();
        }

        return {
            address: this.keys.address,
            x25519: this.keys.x25519PublicB58,
            session: this.config.openclaw.sessionId,
            xchatRegistered: registered,
        };
    }

    /**
     * Send an encrypted message to a wallet address via xchat,
     * then forward to the OpenClaw agent.
     */
    async send(toAddress, text) {
        if (!this.keys) throw new Error('Not authenticated');

        // Get or create peer session
        const peer = await this.getOrCreatePeer(toAddress);
        if (!peer) throw new Error(`Cannot find key for ${toAddress}`);

        // Encrypt and send via xchat
        const { nonce, ciphertext } = encrypt(peer.sessionKey, text);
        const msgId = await sendMessage(
            this.config.xchatServer,
            this.keys.address, toAddress,
            nonce, ciphertext
        );

        // Forward to OpenClaw agent
        let agentReply = null;
        try {
            agentReply = await sendToAgent(this.config.openclaw, text, this.keys.address);
        } catch (e) {
            console.error('[Bridge] Agent error:', e.message);
        }

        // If agent replied, send the reply back to the wallet via xchat
        if (agentReply) {
            try {
                const reply = encrypt(peer.sessionKey, agentReply);
                await sendMessage(
                    this.config.xchatServer,
                    this.keys.address, toAddress,
                    reply.nonce, reply.ciphertext
                );
            } catch (e) {
                console.error('[Bridge] Failed to send agent reply via xchat:', e.message);
            }
        }

        return { id: msgId, agentReply };
    }

    /**
     * Switch to a named session. Creates it if it doesn't exist,
     * reconnects if it does.
     */
    setSession(sessionId) {
        if (!sessionId || typeof sessionId !== 'string') {
            throw new Error('Session name is required');
        }
        // Sanitize: allow alphanumeric, hyphens, underscores
        const clean = sessionId.replace(/[^a-zA-Z0-9_-]/g, '');
        if (!clean) throw new Error('Invalid session name');
        this.config.openclaw.sessionId = clean;
        return { session: clean };
    }

    /**
     * Send a message directly to the OpenClaw agent (no xchat encryption).
     */
    async chat(text) {
        const reply = await sendToAgent(this.config.openclaw, text, this.keys?.address);
        return { reply };
    }

    /**
     * List known peers.
     */
    getPeers() {
        return Array.from(this.peers.entries()).map(([address]) => ({ address }));
    }

    /**
     * Get connection status.
     */
    getStatus() {
        return {
            authenticated: !!this.keys,
            address: this.keys?.address || null,
            x25519: this.keys?.x25519PublicB58 || null,
            agent: this.config.openclaw.agentId,
            session: this.config.openclaw.sessionId,
            server: this.config.xchatServer,
            peers: this.peers.size,
            sseConnected: !!this.sseCleanup,
        };
    }

    /**
     * Lookup or create a peer session (X25519 key + shared session key).
     */
    async getOrCreatePeer(address) {
        if (this.peers.has(address)) return this.peers.get(address);

        const keyB58 = await lookupKey(this.config.xchatServer, address);
        if (!keyB58) return null;

        const x25519Public = base58Decode(keyB58);
        const sessionKey = computeSessionKey(this.keys.x25519Private, x25519Public);
        const peer = { x25519Public, sessionKey };
        this.peers.set(address, peer);
        return peer;
    }

    /**
     * Start SSE listener for incoming xchat messages.
     */
    startSSE() {
        if (this.sseCleanup) this.sseCleanup();
        if (!this.keys) return;

        // Use current timestamp to only get new messages
        const since = Date.now();

        this.sseCleanup = connectSSE(
            this.config.xchatServer,
            this.keys.address,
            since,
            (data) => this.handleSSEEvent(data)
        );
    }

    /**
     * Handle an SSE event from the xchat server.
     */
    async handleSSEEvent(data) {
        if (data.type === 'connected') {
            this.emit({ ok: true, event: 'sse_connected', messageCount: data.messageCount });
            return;
        }

        if (data.type === 'history_complete') {
            this.emit({ ok: true, event: 'sse_ready' });
            return;
        }

        if (data.type === 'message') {
            const msg = data.message;
            // Only process messages TO us, not FROM us
            if (!msg || msg.to !== this.keys.address || msg.from === this.keys.address) return;

            await this.handleIncomingMessage(msg);
        }
    }

    /**
     * Decrypt an incoming xchat message, debounce rapid messages from same sender.
     * Waits 1.5s for more messages before sending batch to agent.
     */
    async handleIncomingMessage(msg) {
        try {
            const peer = await this.getOrCreatePeer(msg.from);
            if (!peer) {
                console.error(`[Bridge] Cannot decrypt — no key for ${msg.from.slice(0, 8)}...`);
                return;
            }

            const plaintext = decrypt(peer.sessionKey, msg.nonce, msg.ciphertext);

            // Emit decrypted message to TCP client
            this.emit({
                ok: true, event: 'message',
                from: msg.from, text: plaintext,
                id: msg.id, ts: msg.timestamp,
            });

            // Send typing indicator
            sendTyping(this.config.xchatServer, this.keys.address, msg.from);

            // Debounce: collect rapid messages from same sender
            const sender = msg.from;
            let pending = this._pendingMessages.get(sender);
            if (pending) {
                clearTimeout(pending.timer);
                pending.messages.push(plaintext);
                pending.lastMsgId = msg.id;
            } else {
                pending = { messages: [plaintext], lastMsgId: msg.id, peer };
                this._pendingMessages.set(sender, pending);
            }

            pending.timer = setTimeout(() => {
                this._flushMessages(sender);
            }, 1500);

        } catch (e) {
            console.error('[Bridge] Message handling error:', e.message);
        }
    }

    /**
     * Flush debounced messages for a sender — serialized so replies stay in order.
     */
    _flushMessages(sender) {
        const lock = this._senderLocks.get(sender) || Promise.resolve();
        const next = lock.then(() => this._doFlush(sender)).catch(() => {});
        this._senderLocks.set(sender, next);
    }

    async _doFlush(sender) {
        const pending = this._pendingMessages.get(sender);
        if (!pending) return;
        this._pendingMessages.delete(sender);

        const { messages, lastMsgId, peer } = pending;
        const combined = messages.join('\n');

        // Forward to OpenClaw agent
        let agentReply = null;
        try {
            agentReply = await sendToAgent(this.config.openclaw, combined, sender);
        } catch (e) {
            console.error('[Bridge] Agent error:', e.message);
        }

        // Only send reply if we got a real response
        if (agentReply) {
            this.emit({
                ok: true, event: 'reply',
                from: 'agent', text: agentReply,
                inReplyTo: lastMsgId,
            });

            try {
                const reply = encrypt(peer.sessionKey, agentReply);
                await sendMessage(
                    this.config.xchatServer,
                    this.keys.address, sender,
                    reply.nonce, reply.ciphertext
                );
            } catch (e) {
                console.error('[Bridge] Failed to send reply:', e.message);
            }
        } else {
            console.log(`[Bridge] No reply for ${sender.slice(0, 8)}... (agent returned empty)`);
        }
    }

    /**
     * Emit an event to the TCP client.
     */
    emit(event) {
        if (this.onEvent) this.onEvent(event);
    }

    /**
     * Cleanup all resources.
     */
    destroy() {
        if (this.sseCleanup) {
            this.sseCleanup();
            this.sseCleanup = null;
        }
        this.keys = null;
        this.peers.clear();
        this.onEvent = null;
    }
}
