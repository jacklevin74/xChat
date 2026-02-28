// X1 Encrypted Messaging Server v3 - Bidirectional File Exchange via Handshake PDA
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync } from 'fs';
import { createServer } from 'https';
import http from 'http';
import httpsModule from 'https';
import { ed25519 } from '@noble/curves/ed25519';
import Database from 'better-sqlite3';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3999;
const HTTPS_PORT = process.env.HTTPS_PORT || 4443;
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

    CREATE TABLE IF NOT EXISTS shared_files (
        id TEXT PRIMARY KEY,
        cid TEXT NOT NULL UNIQUE,
        filename TEXT NOT NULL,
        sender_wallet TEXT NOT NULL,
        recipient_wallet TEXT NOT NULL,
        handshake_pda TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        kem_variant INTEGER NOT NULL DEFAULT 1,
        file_size INTEGER DEFAULT 0,
        mime_type TEXT DEFAULT 'application/octet-stream'
    );

    CREATE TABLE IF NOT EXISTS bookmarks (
        id TEXT PRIMARY KEY,
        owner_wallet TEXT NOT NULL,
        cid TEXT NOT NULL,
        filename TEXT NOT NULL,
        mime_type TEXT DEFAULT 'application/octet-stream',
        file_size INTEGER DEFAULT 0,
        iv TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        label TEXT DEFAULT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_bookmarks_owner ON bookmarks(owner_wallet, timestamp);

    CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient, created_at);
    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
    CREATE INDEX IF NOT EXISTS idx_shared_files_pda ON shared_files(handshake_pda, timestamp);
    CREATE INDEX IF NOT EXISTS idx_shared_files_cid ON shared_files(cid);
`);

// Add read_at column if it doesn't exist (migration for existing DBs)
try { db.exec('ALTER TABLE messages ADD COLUMN read_at INTEGER DEFAULT NULL'); } catch (e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN stream_id TEXT DEFAULT NULL'); } catch (e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN chunk_index INTEGER DEFAULT NULL'); } catch (e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN chunk_total INTEGER DEFAULT NULL'); } catch (e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN is_final BOOLEAN DEFAULT NULL'); } catch (e) {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_messages_stream_id ON messages(stream_id)'); } catch (e) {}

// Add bookmarks table migration for existing DBs
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS bookmarks (
            id TEXT PRIMARY KEY,
            owner_wallet TEXT NOT NULL,
            cid TEXT NOT NULL,
            filename TEXT NOT NULL,
            mime_type TEXT DEFAULT 'application/octet-stream',
            file_size INTEGER DEFAULT 0,
            iv TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            label TEXT DEFAULT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bookmarks_owner ON bookmarks(owner_wallet, timestamp);
    `);
} catch (e) {}

// Prepared statements
const stmts = {
    getKey: db.prepare('SELECT x25519_public_key FROM keys WHERE address = ?'),
    setKey: db.prepare('INSERT OR REPLACE INTO keys (address, x25519_public_key) VALUES (?, ?)'),
    getAllKeys: db.prepare('SELECT address, x25519_public_key FROM keys'),

    insertMessage: db.prepare('INSERT INTO messages (id, sender, recipient, nonce, ciphertext, created_at, stream_id, chunk_index, chunk_total, is_final) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
    getMessages: db.prepare('SELECT * FROM messages WHERE recipient = ? AND created_at > ? ORDER BY created_at ASC'),
    getUserMessages: db.prepare('SELECT * FROM messages WHERE sender = ? OR recipient = ? ORDER BY created_at ASC'),
    getUserMessagesSince: db.prepare('SELECT * FROM messages WHERE (sender = ? OR recipient = ?) AND created_at >= ? ORDER BY created_at ASC'),
    deleteUserMessages: db.prepare('DELETE FROM messages WHERE sender = ? OR recipient = ?'),
    deleteConversation: db.prepare('DELETE FROM messages WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)'),
    getAllMessages: db.prepare('SELECT * FROM messages ORDER BY created_at ASC'),
    markMessagesRead: db.prepare('UPDATE messages SET read_at = ? WHERE id IN (SELECT value FROM json_each(?)) AND recipient = ? AND read_at IS NULL'),
    getMessageById: db.prepare('SELECT * FROM messages WHERE id = ?'),

    // Shared files
    insertSharedFile: db.prepare('INSERT OR REPLACE INTO shared_files (id, cid, filename, sender_wallet, recipient_wallet, handshake_pda, timestamp, kem_variant, file_size, mime_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
    getFilesByPda: db.prepare('SELECT * FROM shared_files WHERE handshake_pda = ? ORDER BY timestamp ASC'),
    getFileByCid: db.prepare('SELECT * FROM shared_files WHERE cid = ?'),
    deleteFileByCid: db.prepare('DELETE FROM shared_files WHERE cid = ?'),

    // Bookmarks (private file storage)
    insertBookmark: db.prepare('INSERT INTO bookmarks (id, owner_wallet, cid, filename, mime_type, file_size, iv, timestamp, label) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'),
    getBookmarks: db.prepare('SELECT * FROM bookmarks WHERE owner_wallet = ? ORDER BY timestamp DESC'),
    deleteBookmark: db.prepare('DELETE FROM bookmarks WHERE id = ? AND owner_wallet = ?'),
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

// Rewrite /xchat/api/* or /xchat2/api/* or /xchat3/api/* to /api/* for proxy compatibility
app.use((req, res, next) => {
    if (req.path.startsWith('/xchat/api/') || req.path.startsWith('/xchat2/api/') || req.path.startsWith('/xchat3/api/')) {
        req.url = req.url.replace(/^\/xchat[23]?\/api\//, '/api/');
    }
    next();
});

// Redirect /xchat3 to /xchat3/ so relative paths resolve correctly
app.get(['/xchat', '/xchat2', '/xchat3'], (req, res) => {
    if (!req.originalUrl.endsWith('/') && !req.originalUrl.includes('?')) {
        return res.redirect(301, req.originalUrl + '/');
    }
    res.sendFile(join(__dirname, 'public', 'xchat.html'));
});

// Also serve the HTML at /xchat3/ (with trailing slash)
app.get(['/xchat/', '/xchat2/', '/xchat3/'], (req, res) => {
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
app.use('/xchat3', express.static(join(__dirname, 'public'), staticOpts));
app.use('/xchat2', express.static(join(__dirname, 'public'), staticOpts));
app.use(express.static(join(__dirname, 'public'), staticOpts));

// CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
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

    stmts.insertMessage.run(
        message.id, from, to, nonce, ciphertext, message.timestamp,
        message.stream_id, message.chunk_index, message.chunk_total, message.is_final
    );

    const eventType = message.stream_id ? 'stream_chunk' : 'message';

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

app.post('/api/messages/read', (req, res) => {
    const { reader, messageIds } = req.body;
    if (!reader || !messageIds || !Array.isArray(messageIds) || messageIds.length === 0) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    const now = Date.now();

    const messagesToNotify = [];
    for (const id of messageIds) {
        const msg = stmts.getMessageById.get(id);
        if (msg && msg.recipient === reader && !msg.read_at) {
            messagesToNotify.push({ id: msg.id, sender: msg.sender });
        }
    }

    const result = stmts.markMessagesRead.run(now, JSON.stringify(messageIds), reader);
    console.log(`[Read] ${reader.slice(0, 8)}... marked ${result.changes} messages as read`);

    for (const { id, sender } of messagesToNotify) {
        const clients = sseClients.get(sender);
        if (clients && clients.size > 0) {
            const data = JSON.stringify({ type: 'read_receipt', messageId: id, readAt: now });
            for (const client of clients) {
                client.write(`data: ${data}\n\n`);
            }
        }
    }

    res.json({ success: true, marked: result.changes });
});

app.get('/api/messages/:address', (req, res) => {
    const since = parseInt(req.query.since) || 0;
    const rows = stmts.getMessages.all(req.params.address, since);
    const messages = rows.map(r => ({
        id: r.id, from: r.sender, to: r.recipient,
        nonce: r.nonce, ciphertext: r.ciphertext, timestamp: r.created_at,
        readAt: r.read_at || null,
        stream_id: r.stream_id || null,
        chunk_index: r.chunk_index ?? null,
        chunk_total: r.chunk_total ?? null,
        is_final: r.is_final ?? null
    }));
    res.json({ messages });
});

app.delete('/api/messages/:address', (req, res) => {
    const address = req.params.address;
    const { signature } = req.body;

    if (!signature) return res.status(400).json({ error: 'Missing signature' });

    try {
        const walletPubKey = base58Decode(address);
        if (walletPubKey.length !== 32) return res.status(400).json({ error: 'Invalid address' });

        const signatureBytes = base58Decode(signature);
        if (signatureBytes.length !== 64) return res.status(400).json({ error: 'Invalid signature' });

        const messageText = `X1 Messaging: Delete my message history`;
        const messageBytes = new TextEncoder().encode(messageText);
        const isValid = ed25519.verify(signatureBytes, messageBytes, walletPubKey);

        if (!isValid) return res.status(401).json({ error: 'Invalid signature' });

        const { peer } = req.body;
        let deletedCount;
        if (peer && typeof peer === 'string') {
            const peerKey = base58Decode(peer);
            if (peerKey.length !== 32) return res.status(400).json({ error: 'Invalid peer address' });
            const result = stmts.deleteConversation.run(address, peer, peer, address);
            deletedCount = result.changes;
        } else {
            const result = stmts.deleteUserMessages.run(address, address);
            deletedCount = result.changes;
        }
        console.log(`[Msg] Deleted ${deletedCount} messages for ${address.slice(0,8)}...`);
        res.json({ success: true, deleted: deletedCount });

    } catch (e) {
        console.error('[Msg] Delete error:', e.message);
        res.status(400).json({ error: 'Delete failed' });
    }
});

app.delete('/api/messages/single/:id', (req, res) => {
    const { id } = req.params;
    const { senderAddress } = req.body;

    if (!senderAddress) return res.status(400).json({ error: 'Missing senderAddress' });

    try {
        const msg = stmts.getMessageById.get(id);
        if (!msg) return res.status(404).json({ error: 'Message not found' });
        if (msg.sender !== senderAddress) return res.status(403).json({ error: 'Not your message' });

        db.prepare('DELETE FROM messages WHERE id = ?').run(id);

        const recipientClients = sseClients.get(msg.recipient);
        if (recipientClients) {
            const event = JSON.stringify({ type: 'message_deleted', id });
            for (const client of recipientClients) {
                client.write(`data: ${event}\n\n`);
            }
        }

        res.json({ success: true });
    } catch (e) {
        console.error('[Msg] Single delete error:', e.message);
        res.status(500).json({ error: 'Delete failed' });
    }
});

// ============================================================================
// SHARED FILES (Bidirectional file discovery via Handshake PDA)
// ============================================================================

// POST /api/files — Register a file in the shared session
app.post('/api/files', (req, res) => {
    const { cid, filename, senderWallet, recipientWallet, handshakePda, kemVariant, fileSize, mimeType } = req.body;

    if (!cid || !filename || !senderWallet || !recipientWallet || !handshakePda) {
        return res.status(400).json({ error: 'Missing required fields: cid, filename, senderWallet, recipientWallet, handshakePda' });
    }

    // Validate wallets are plausible base58 strings (basic sanity check)
    if (typeof senderWallet !== 'string' || senderWallet.length < 32) {
        return res.status(400).json({ error: 'Invalid senderWallet' });
    }

    try {
        const id = Date.now().toString(36) + Math.random().toString(36).slice(2);
        const timestamp = Date.now();
        const variant = Number.isFinite(Number(kemVariant)) ? Number(kemVariant) : 1;
        const size = Number.isFinite(Number(fileSize)) ? Number(fileSize) : 0;
        const mime = mimeType || 'application/octet-stream';

        stmts.insertSharedFile.run(id, cid, filename, senderWallet, recipientWallet, handshakePda, timestamp, variant, size, mime);

        console.log(`[Files] Registered: ${filename} (${cid.slice(0,8)}...) in PDA ${handshakePda.slice(0,8)}...`);

        // Push SSE notification to both parties
        const fileEvent = JSON.stringify({
            type: 'file_shared',
            file: { id, cid, filename, senderWallet, recipientWallet, handshakePda, timestamp, kemVariant: variant, fileSize: size, mimeType: mime }
        });

        for (const addr of [senderWallet, recipientWallet]) {
            const clients = sseClients.get(addr);
            if (clients && clients.size > 0) {
                for (const client of clients) {
                    client.write(`data: ${fileEvent}\n\n`);
                }
            }
        }

        res.json({ success: true, id, timestamp });

    } catch (e) {
        // Handle UNIQUE constraint on cid (file already registered)
        if (e.message && e.message.includes('UNIQUE constraint')) {
            return res.json({ success: true, duplicate: true });
        }
        console.error('[Files] Register error:', e.message);
        res.status(500).json({ error: 'Failed to register file' });
    }
});

// GET /api/files/:handshakePda — Fetch all files for a handshake session
app.get('/api/files/:handshakePda', (req, res) => {
    try {
        const rows = stmts.getFilesByPda.all(req.params.handshakePda);
        const files = rows.map(r => ({
            id: r.id,
            cid: r.cid,
            filename: r.filename,
            senderWallet: r.sender_wallet,
            recipientWallet: r.recipient_wallet,
            handshakePda: r.handshake_pda,
            timestamp: r.timestamp,
            kemVariant: r.kem_variant,
            fileSize: r.file_size,
            mimeType: r.mime_type,
        }));
        res.json({ files });
    } catch (e) {
        console.error('[Files] Fetch error:', e.message);
        res.status(500).json({ error: 'Failed to fetch files' });
    }
});

// DELETE /api/files/:cid — Remove a file from the registry (cleanup)
app.delete('/api/files/:cid', (req, res) => {
    try {
        const result = stmts.deleteFileByCid.run(req.params.cid);
        console.log(`[Files] Deleted: ${req.params.cid.slice(0,8)}... (${result.changes} rows)`);
        res.json({ success: true, deleted: result.changes });
    } catch (e) {
        console.error('[Files] Delete error:', e.message);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

// ============================================================================
// DEBUG
// ============================================================================
// BOOKMARKS (Private file storage per wallet)
// ============================================================================

// POST /api/bookmarks — Save a new bookmark
app.post('/api/bookmarks', (req, res) => {
    const { owner, cid, filename, mime_type, file_size, iv, label } = req.body;

    if (!owner || !cid || !filename || !iv) {
        return res.status(400).json({ error: 'Missing required fields: owner, cid, filename, iv' });
    }

    try {
        const id = Date.now().toString(36) + Math.random().toString(36).slice(2);
        const timestamp = Date.now();

        stmts.insertBookmark.run(id, owner, cid, filename, mime_type || 'application/octet-stream', file_size || 0, iv, timestamp, label || null);

        console.log(`[Bookmarks] Saved: ${filename} (${cid.slice(0, 8)}...) for ${owner.slice(0, 8)}...`);
        res.json({ success: true, id, timestamp });
    } catch (e) {
        console.error('[Bookmarks] Save error:', e.message);
        res.status(500).json({ error: 'Failed to save bookmark' });
    }
});

// GET /api/bookmarks/:owner — Get all bookmarks for a wallet
app.get('/api/bookmarks/:owner', (req, res) => {
    try {
        const rows = stmts.getBookmarks.all(req.params.owner);
        const bookmarks = rows.map(r => ({
            id: r.id,
            cid: r.cid,
            filename: r.filename,
            mime_type: r.mime_type,
            file_size: r.file_size,
            iv: r.iv,
            timestamp: r.timestamp,
            label: r.label
        }));
        res.json({ bookmarks });
    } catch (e) {
        console.error('[Bookmarks] Fetch error:', e.message);
        res.status(500).json({ error: 'Failed to fetch bookmarks' });
    }
});

// DELETE /api/bookmarks/:id — Delete a bookmark
app.delete('/api/bookmarks/:id', (req, res) => {
    const { owner } = req.body;
    if (!owner) {
        return res.status(400).json({ error: 'Missing owner' });
    }

    try {
        const result = stmts.deleteBookmark.run(req.params.id, owner);
        console.log(`[Bookmarks] Deleted: ${req.params.id} (${result.changes} rows)`);
        res.json({ success: true, deleted: result.changes });
    } catch (e) {
        console.error('[Bookmarks] Delete error:', e.message);
        res.status(500).json({ error: 'Failed to delete bookmark' });
    }
});

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
// PRIVACY PROXY — strips tracking params, masks user IP from destination
// ============================================================================

// Native HTTP/HTTPS fetch helper (avoids TLS cert store issues with bare fetch)
function proxyFetch(url, { timeout = 10000, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const mod = parsed.protocol === 'https:' ? httpsModule : http;
        const opts = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; xChat-Privacy-Proxy/1.0)', ...headers },
            rejectUnauthorized: false,
            timeout
        };
        const req = mod.request(opts, (resp) => {
            // Follow redirects (up to 5)
            if ([301,302,303,307,308].includes(resp.statusCode) && resp.headers.location) {
                proxyFetch(new URL(resp.headers.location, url).toString(), { timeout, headers })
                    .then(resolve).catch(reject);
                resp.resume();
                return;
            }
            const chunks = [];
            resp.on('data', c => chunks.push(c));
            resp.on('end', () => resolve({ statusCode: resp.statusCode, headers: resp.headers, body: Buffer.concat(chunks) }));
        });
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        req.on('error', reject);
        req.end();
    });
}

// Simple in-memory rate limiter: 60 req/min per IP
const proxyRateMap = new Map();
function proxyRateLimit(ip) {
    const now = Date.now();
    const window = 60_000;
    let entry = proxyRateMap.get(ip);
    if (!entry || now - entry.ts > window) {
        entry = { ts: now, count: 0 };
        proxyRateMap.set(ip, entry);
    }
    entry.count++;
    return entry.count <= 60;
}

// Block private/internal addresses (SSRF prevention)
function isPrivateUrl(url) {
    try {
        const { hostname } = new URL(url);
        return /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|::1|fc00:|fe80:)/i.test(hostname);
    } catch { return true; }
}

// Tracking params to strip
const TRACKING_PARAMS = ['utm_source','utm_medium','utm_campaign','utm_term','utm_content',
    'fbclid','gclid','gclsrc','dclid','msclkid','twclid','mc_eid','ml_subscriber',
    'ref','referrer','source','igshid','s_cid','_hsenc','_hsmi','mkt_tok'];

app.get('/api/proxy', async (req, res) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    if (!proxyRateLimit(clientIp)) {
        return res.status(429).json({ error: 'Rate limit exceeded' });
    }

    const raw = req.query.url;
    if (!raw || typeof raw !== 'string') {
        return res.status(400).json({ error: 'Missing url param' });
    }

    let targetUrl;
    try {
        targetUrl = new URL(raw);
        if (!['http:', 'https:'].includes(targetUrl.protocol)) throw new Error('bad protocol');
    } catch {
        return res.status(400).json({ error: 'Invalid URL' });
    }

    if (isPrivateUrl(raw)) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    // Strip tracking params
    for (const p of TRACKING_PARAMS) targetUrl.searchParams.delete(p);

    proxyFetch(targetUrl.toString(), { timeout: 10000 })
        .then(({ statusCode, headers, body }) => {
            const contentType = headers['content-type'] || 'application/octet-stream';
            res.setHeader('Content-Type', contentType);
            res.setHeader('X-Proxied-By', 'xChat-Privacy-Proxy');
            res.setHeader('Cache-Control', 'public, max-age=300');
            res.status(statusCode).send(body);
        })
        .catch(e => {
            console.error('[Proxy] Error:', e.message);
            res.status(e.message === 'timeout' ? 504 : 502).json({ error: 'Proxy fetch failed' });
        });
});

// OG metadata fetch — server-side, user IP never touches destination
app.get('/api/og', async (req, res) => {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    if (!proxyRateLimit(clientIp)) return res.status(429).json({ error: 'Rate limit exceeded' });

    const raw = req.query.url;
    if (!raw) return res.status(400).json({ error: 'Missing url' });
    if (isPrivateUrl(raw)) return res.status(403).json({ error: 'Forbidden' });

    try {
        const { body: htmlBuf } = await proxyFetch(raw, { timeout: 8000, headers: { 'Accept': 'text/html' } });
        const html = htmlBuf.toString('utf8');

        const get = (prop) => {
            const m = html.match(new RegExp(`<meta[^>]+(?:property|name)=["']${prop}["'][^>]+content=["']([^"']+)["']`, 'i'))
                     || html.match(new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']${prop}["']`, 'i'));
            return m?.[1] || '';
        };

        res.json({
            title: get('og:title') || html.match(/<title>([^<]+)<\/title>/i)?.[1] || '',
            description: get('og:description') || get('description'),
            image: get('og:image'),
            siteName: get('og:site_name'),
            url: get('og:url') || raw,
        });
    } catch (e) {
        res.status(e.message === 'timeout' ? 504 : 502).json({ error: 'Fetch failed' });
    }
});

// ============================================================================
// START
// ============================================================================

app.listen(PORT, () => {
    console.log(`\nX1 Encrypted Messaging Server v3 (xChat3)`);
    console.log(`==========================================`);
    console.log(`http://localhost:${PORT}`);
    console.log(`\nEndpoints:`);
    console.log(`  POST /api/keys              - Register key (with signature)`);
    console.log(`  GET  /api/keys/:a           - Lookup public key`);
    console.log(`  GET  /api/stream/:a         - SSE stream for real-time messages`);
    console.log(`  POST /api/messages          - Send message`);
    console.log(`  GET  /api/messages/:a       - Get messages`);
    console.log(`  POST /api/files             - Register shared file (by handshake PDA)`);
    console.log(`  GET  /api/files/:pda        - Get all files in a handshake session`);
    console.log(`  DELETE /api/files/:cid      - Remove file from registry`);
    console.log(`  POST /api/bookmarks         - Save private bookmark`);
    console.log(`  GET  /api/bookmarks/:owner  - Get all bookmarks for wallet`);
    console.log(`  DELETE /api/bookmarks/:id   - Delete bookmark\n`);
});

// HTTPS server (needed for wallet extensions that require secure context)
if (existsSync(TLS_CERT) && existsSync(TLS_KEY)) {
    const httpsServer = createServer({
        cert: readFileSync(TLS_CERT),
        key: readFileSync(TLS_KEY),
    }, app);
    httpsServer.listen(HTTPS_PORT, '127.0.0.1', () => {
        console.log(`HTTPS: https://localhost:${HTTPS_PORT}`);
    });
} else {
    console.log(`\nNo TLS certs found at ${TLS_CERT} / ${TLS_KEY}`);
    console.log(`HTTPS disabled.\n`);
}
