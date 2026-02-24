// X1 Encrypted Messaging Server - Secure Version with SSE + SQLite
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync } from 'fs';
import { createServer } from 'https';
import { ed25519 } from '@noble/curves/ed25519';
import Database from 'better-sqlite3';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3001;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;
const TLS_CERT = process.env.TLS_CERT || '/tmp/xchat-cert.pem';
const TLS_KEY = process.env.TLS_KEY || '/tmp/xchat-key.pem';

// SQLite database
const db = new Database(join(__dirname, 'data', 'messages.db'));
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
    CREATE TABLE IF NOT EXISTS keys (
        address TEXT PRIMARY KEY,
        x25519_public_key TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
    );

    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        read_at INTEGER DEFAULT NULL,
        stream_id TEXT DEFAULT NULL,
        chunk_index INTEGER DEFAULT NULL,
        chunk_total INTEGER DEFAULT NULL,
        is_final BOOLEAN DEFAULT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient, created_at);
    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
`);

// Add read_at column if it doesn't exist (migration for existing DBs)
try {
    db.exec('ALTER TABLE messages ADD COLUMN read_at INTEGER DEFAULT NULL');
} catch (e) {
    // Column already exists
}

// Add streaming columns if they don't exist
try { db.exec('ALTER TABLE messages ADD COLUMN stream_id TEXT DEFAULT NULL'); } catch (e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN chunk_index INTEGER DEFAULT NULL'); } catch (e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN chunk_total INTEGER DEFAULT NULL'); } catch (e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN is_final BOOLEAN DEFAULT NULL'); } catch (e) {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_messages_stream_id ON messages(stream_id)'); } catch (e) {}

// Prepared statements
const stmts = {
    getKey: db.prepare('SELECT x25519_public_key FROM keys WHERE address = ?'),
    setKey: db.prepare('INSERT OR REPLACE INTO keys (address, x25519_public_key) VALUES (?, ?)'),
    getAllKeys: db.prepare('SELECT address, x25519_public_key FROM keys'),

    insertMessage: db.prepare('INSERT INTO messages (id, sender, recipient, nonce, ciphertext, created_at, stream_id, chunk_index, chunk_total, is_final) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
    getMessages: db.prepare('SELECT * FROM messages WHERE recipient = ? AND created_at > ? ORDER BY created_at ASC'),
    getUserMessages: db.prepare('SELECT * FROM messages WHERE sender = ? OR recipient = ? ORDER BY created_at ASC'),
    getUserMessagesSince: db.prepare('SELECT * FROM messages WHERE (sender = ? OR recipient = ?) AND created_at > ? ORDER BY created_at ASC'),
    deleteUserMessages: db.prepare('DELETE FROM messages WHERE sender = ? OR recipient = ?'),
    getAllMessages: db.prepare('SELECT * FROM messages ORDER BY created_at ASC'),
    markMessagesRead: db.prepare('UPDATE messages SET read_at = ? WHERE id IN (SELECT value FROM json_each(?)) AND recipient = ? AND read_at IS NULL'),
    getMessageById: db.prepare('SELECT * FROM messages WHERE id = ?'),
};

// SSE clients (in-memory, not persisted)
const sseClients = new Map();     // address -> Set of response objects

// Base58 decode for verification
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
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

// Middleware
app.use(express.json());

// Rewrite /xchat/api/* or /xchat2/api/* to /api/* for proxy compatibility
app.use((req, res, next) => {
    if (req.path.startsWith('/xchat/api/') || req.path.startsWith('/xchat2/api/')) {
        req.url = req.url.replace(/^\/xchat2?\/api\//, '/api/');
    }
    next();
});

// Redirect /xchat2 to /xchat2/ so relative paths resolve correctly
app.get(['/xchat', '/xchat2'], (req, res) => {
    if (!req.originalUrl.endsWith('/') && !req.originalUrl.includes('?')) {
        return res.redirect(301, req.originalUrl + '/');
    }
    res.sendFile(join(__dirname, 'public', 'xchat.html'));
});

// Also serve the HTML at /xchat2/ (with trailing slash)
app.get(['/xchat/', '/xchat2/'], (req, res) => {
    res.sendFile(join(__dirname, 'public', 'xchat.html'));
});

// Serve static files — JS/CSS never cached so updates take effect immediately
const staticOpts = {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.js') || filePath.endsWith('.css')) {
            res.setHeader('Cache-Control', 'no-store');
        }
    }
};
app.use('/xchat2', express.static(join(__dirname, 'public'), staticOpts));
app.use(express.static(join(__dirname, 'public'), staticOpts));

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// ============================================================================
// KEY REGISTRY (with signature verification)
// ============================================================================

app.post('/api/keys', (req, res) => {
    const { address, x25519PublicKey, signature } = req.body;

    if (!address || !x25519PublicKey || !signature) {
        return res.status(400).json({ error: 'Missing address, x25519PublicKey, or signature' });
    }

    try {
        const walletPubKey = base58Decode(address);
        if (walletPubKey.length !== 32) {
            return res.status(400).json({ error: 'Invalid address length' });
        }

        const signatureBytes = base58Decode(signature);
        if (signatureBytes.length !== 64) {
            return res.status(400).json({ error: 'Invalid signature length' });
        }

        const messageText = `X1 Messaging: Register encryption key ${x25519PublicKey}`;
        const messageBytes = new TextEncoder().encode(messageText);

        const isValid = ed25519.verify(signatureBytes, messageBytes, walletPubKey);

        if (!isValid) {
            console.log(`[Keys] REJECTED: ${address.slice(0, 8)}...`);
            return res.status(401).json({ error: 'Invalid signature' });
        }

        stmts.setKey.run(address, x25519PublicKey);
        console.log(`[Keys] Registered: ${address.slice(0, 8)}...`);
        res.json({ success: true });

    } catch (e) {
        console.error('[Keys] Error:', e.message);
        res.status(400).json({ error: 'Verification failed' });
    }
});

app.get('/api/keys/:address', (req, res) => {
    const row = stmts.getKey.get(req.params.address);
    if (!row) {
        return res.status(404).json({ error: 'Not found' });
    }
    res.json({ address: req.params.address, x25519PublicKey: row.x25519_public_key });
});

// ============================================================================
// SSE - Server-Sent Events for real-time messages
// ============================================================================

app.get('/api/stream/:address', (req, res) => {
    const address = req.params.address;
    const since = parseInt(req.query.since) || 0;

    // Set SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();

    // Register this client
    if (!sseClients.has(address)) {
        sseClients.set(address, new Set());
    }
    sseClients.get(address).add(res);

    // Fetch messages newer than 'since' timestamp
    const rows = stmts.getUserMessagesSince.all(address, address, since);
    const messageCount = rows.length;

    // Send initial connection message with sync info
    res.write(`data: ${JSON.stringify({ type: 'connected', since, messageCount })}\n\n`);

    console.log(`[SSE] Connected: ${address.slice(0, 8)}... (${sseClients.get(address).size} clients, syncing ${messageCount} msgs since ${since})`);

    // Send only messages newer than 'since'
    let readCount = 0;
    for (const r of rows) {
        const msg = {
            id: r.id,
            from: r.sender,
            to: r.recipient,
            nonce: r.nonce,
            ciphertext: r.ciphertext,
            timestamp: r.created_at,
            readAt: r.read_at || null,
            stream_id: r.stream_id || null,
            chunk_index: r.chunk_index ?? null,
            chunk_total: r.chunk_total ?? null,
            is_final: r.is_final ?? null,
        };
        if (r.read_at) readCount++;
        const eventType = r.stream_id ? 'stream_chunk' : 'message';
        res.write(`data: ${JSON.stringify({ type: eventType, message: msg })}\n\n`);
    }
    console.log(`[SSE] Sent ${rows.length} messages, ${readCount} with readAt`);

    // Signal that history sync is complete
    res.write(`data: ${JSON.stringify({ type: 'history_complete', count: messageCount })}\n\n`);

    // Heartbeat to keep connection alive
    const heartbeat = setInterval(() => {
        res.write(`data: ${JSON.stringify({ type: 'ping' })}\n\n`);
    }, 30000);

    // Cleanup on disconnect
    req.on('close', () => {
        clearInterval(heartbeat);
        sseClients.get(address)?.delete(res);
        console.log(`[SSE] Disconnected: ${address.slice(0, 8)}...`);
    });
});

// ============================================================================
// MESSAGES
// ============================================================================

app.post('/api/typing', (req, res) => {
    const { from, to } = req.body;
    if (!from || !to) {
        return res.status(400).json({ error: 'Missing from or to' });
    }

    const clients = sseClients.get(to);
    if (clients && clients.size > 0) {
        const data = JSON.stringify({ type: 'typing', from });
        for (const client of clients) {
            client.write(`data: ${data}\n\n`);
        }
    }
    res.json({ success: true });
});

app.post('/api/messages', (req, res) => {
    const { from, to, nonce, ciphertext, stream_id, chunk_index, chunk_total, is_final } = req.body;
    if (!from || !to || !nonce || !ciphertext) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    const message = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2),
        from, to, nonce, ciphertext,
        timestamp: Date.now(),
        stream_id: stream_id ?? null,
        chunk_index: Number.isFinite(Number(chunk_index)) ? Number(chunk_index) : null,
        chunk_total: Number.isFinite(Number(chunk_total)) ? Number(chunk_total) : null,
        is_final: typeof is_final === 'boolean' ? (is_final ? 1 : 0) : null,
        readAt: null,
    };

    // Store message in SQLite
    stmts.insertMessage.run(
        message.id,
        from,
        to,
        nonce,
        ciphertext,
        message.timestamp,
        message.stream_id,
        message.chunk_index,
        message.chunk_total,
        message.is_final
    );

    const eventType = message.stream_id ? 'stream_chunk' : 'message';

    // Push to connected SSE clients
    const clients = sseClients.get(to);
    if (clients && clients.size > 0) {
        const data = JSON.stringify({ type: eventType, message });
        for (const client of clients) {
            client.write(`data: ${data}\n\n`);
        }
        console.log(`[Msg] ${from.slice(0, 8)}... -> ${to.slice(0, 8)}... (pushed to ${clients.size} clients)`);
    } else {
        console.log(`[Msg] ${from.slice(0, 8)}... -> ${to.slice(0, 8)}... (stored, recipient offline)`);
    }

    res.json({ success: true, id: message.id });
});

// Mark messages as read - sends read receipt to sender
app.post('/api/messages/read', (req, res) => {
    const { reader, messageIds } = req.body;
    if (!reader || !messageIds || !Array.isArray(messageIds) || messageIds.length === 0) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    const now = Date.now();

    // Get messages that will be marked as read (to notify senders)
    const messagesToNotify = [];
    for (const id of messageIds) {
        const msg = stmts.getMessageById.get(id);
        if (msg && msg.recipient === reader && !msg.read_at) {
            messagesToNotify.push({ id: msg.id, sender: msg.sender });
        }
    }

    // Mark messages as read in database
    const result = stmts.markMessagesRead.run(now, JSON.stringify(messageIds), reader);
    console.log(`[Read] ${reader.slice(0, 8)}... marked ${result.changes} messages as read`);

    // Notify senders via SSE
    console.log(`[Read] Notifying ${messagesToNotify.length} senders`);
    for (const { id, sender } of messagesToNotify) {
        const clients = sseClients.get(sender);
        if (clients && clients.size > 0) {
            const data = JSON.stringify({ type: 'read_receipt', messageId: id, readAt: now });
            console.log(`[Read] Sending read_receipt to ${sender.slice(0, 8)}... for msg ${id}`);
            for (const client of clients) {
                client.write(`data: ${data}\n\n`);
            }
        } else {
            console.log(`[Read] Sender ${sender.slice(0, 8)}... not connected`);
        }
    }

    res.json({ success: true, marked: result.changes });
});

app.get('/api/messages/:address', (req, res) => {
    const since = parseInt(req.query.since) || 0;
    const rows = stmts.getMessages.all(req.params.address, since);
    const messages = rows.map(r => ({
        id: r.id,
        from: r.sender,
        to: r.recipient,
        nonce: r.nonce,
        ciphertext: r.ciphertext,
        timestamp: r.created_at,
        readAt: r.read_at || null,
        stream_id: r.stream_id || null,
        chunk_index: r.chunk_index ?? null,
        chunk_total: r.chunk_total ?? null,
        is_final: r.is_final ?? null
    }));
    res.json({ messages });
});

// Delete message history - requires signature proof
app.delete('/api/messages/:address', (req, res) => {
    const address = req.params.address;
    const { signature } = req.body;

    if (!signature) {
        return res.status(400).json({ error: 'Missing signature' });
    }

    try {
        const walletPubKey = base58Decode(address);
        if (walletPubKey.length !== 32) {
            return res.status(400).json({ error: 'Invalid address' });
        }

        const signatureBytes = base58Decode(signature);
        if (signatureBytes.length !== 64) {
            return res.status(400).json({ error: 'Invalid signature' });
        }

        // Verify signature on deletion request
        const messageText = `X1 Messaging: Delete my message history`;
        const messageBytes = new TextEncoder().encode(messageText);
        const isValid = ed25519.verify(signatureBytes, messageBytes, walletPubKey);

        if (!isValid) {
            return res.status(401).json({ error: 'Invalid signature' });
        }

        // Delete messages where this address is sender OR recipient
        const result = stmts.deleteUserMessages.run(address, address);
        const deletedCount = result.changes;

        console.log(`[Msg] Deleted ${deletedCount} messages for ${address.slice(0, 8)}...`);
        res.json({ success: true, deleted: deletedCount });

    } catch (e) {
        console.error('[Msg] Delete error:', e.message);
        res.status(400).json({ error: 'Delete failed' });
    }
});

// NOTE: File storage removed. All file transfers use IPFS (vault.x1.xyz).
// Files are encrypted client-side with the X25519 shared secret before upload.
// The server never sees file contents or handles file storage.

// ============================================================================
// DEBUG
// ============================================================================

app.get('/api/debug/dump', (req, res) => {
    const keys = stmts.getAllKeys.all();
    const messages = stmts.getAllMessages.all();
    const dump = {
        keys: keys.reduce((acc, r) => { acc[r.address] = r.x25519_public_key; return acc; }, {}),
        messages: messages.map(r => ({
            id: r.id, from: r.sender, to: r.recipient,
            nonce: r.nonce, ciphertext: r.ciphertext, timestamp: r.created_at,
            stream_id: r.stream_id || null,
            chunk_index: r.chunk_index ?? null,
            chunk_total: r.chunk_total ?? null,
            is_final: r.is_final ?? null
        })),
        sseClients: Object.fromEntries([...sseClients.entries()].map(([k, v]) => [k, v.size]))
    };
    res.json(dump);
});

// ============================================================================
// START
// ============================================================================

// HTTP server
app.listen(PORT, () => {
    console.log(`\nX1 Encrypted Messaging Server (SSE)`);
    console.log(`====================================`);
    console.log(`http://localhost:${PORT}`);
    console.log(`\nEndpoints:`);
    console.log(`  POST /api/keys        - Register key (with signature)`);
    console.log(`  GET  /api/keys/:a     - Lookup public key`);
    console.log(`  GET  /api/stream/:a   - SSE stream for real-time messages`);
    console.log(`  POST /api/messages    - Send message`);
    console.log(`  GET  /api/messages/:a - Get messages\n`);
});

// HTTPS server (needed for wallet extensions that require secure context)
if (existsSync(TLS_CERT) && existsSync(TLS_KEY)) {
    const httpsServer = createServer({
        cert: readFileSync(TLS_CERT),
        key: readFileSync(TLS_KEY),
    }, app);
    httpsServer.listen(HTTPS_PORT, '127.0.0.1', () => {
        console.log(`HTTPS: https://localhost:${HTTPS_PORT}`);
        console.log(`(X1 Wallet requires HTTPS for provider injection)\n`);
    });
} else {
    console.log(`\nNo TLS certs found at ${TLS_CERT} / ${TLS_KEY}`);
    console.log(`HTTPS disabled. X1 Wallet won't work over plain HTTP.\n`);
}
