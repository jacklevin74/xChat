// X1 Encrypted Messaging Server - Secure Version with Key Verification
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { ed25519 } from '@noble/curves/ed25519';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3001;

// In-memory storage
const keyRegistry = new Map();    // address -> x25519PublicKey
const messageStore = new Map();   // recipient -> messages[]

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
app.use(express.static(join(__dirname, 'public')));

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
        // Decode address (which is the ed25519 public key)
        const walletPubKey = base58Decode(address);
        if (walletPubKey.length !== 32) {
            return res.status(400).json({ error: 'Invalid address length' });
        }

        // Decode signature
        const signatureBytes = base58Decode(signature);
        if (signatureBytes.length !== 64) {
            return res.status(400).json({ error: 'Invalid signature length' });
        }

        // The signed message is human-readable: "X1 Messaging: Register encryption key <key>"
        const messageText = `X1 Messaging: Register encryption key ${x25519PublicKey}`;
        const messageBytes = new TextEncoder().encode(messageText);

        // Verify signature
        const isValid = ed25519.verify(signatureBytes, messageBytes, walletPubKey);

        if (!isValid) {
            console.log(`[Keys] REJECTED: Invalid signature for ${address.slice(0, 8)}...`);
            return res.status(401).json({ error: 'Invalid signature - you must prove ownership of this address' });
        }

        // Signature valid - store the key
        keyRegistry.set(address, x25519PublicKey);
        console.log(`[Keys] VERIFIED & Registered: ${address.slice(0, 8)}...`);
        res.json({ success: true });

    } catch (e) {
        console.error('[Keys] Error:', e.message);
        res.status(400).json({ error: 'Verification failed: ' + e.message });
    }
});

// Lookup X25519 public key
app.get('/api/keys/:address', (req, res) => {
    const key = keyRegistry.get(req.params.address);
    if (!key) {
        return res.status(404).json({ error: 'Not found' });
    }
    res.json({ address: req.params.address, x25519PublicKey: key });
});

// ============================================================================
// MESSAGES
// ============================================================================

app.post('/api/messages', (req, res) => {
    const { from, to, nonce, ciphertext } = req.body;
    if (!from || !to || !nonce || !ciphertext) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    const message = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2),
        from, to, nonce, ciphertext,
        timestamp: Date.now()
    };

    if (!messageStore.has(to)) {
        messageStore.set(to, []);
    }
    messageStore.get(to).push(message);

    console.log(`[Msg] ${from.slice(0, 8)}... -> ${to.slice(0, 8)}...`);
    res.json({ success: true, id: message.id });
});

app.get('/api/messages/:address', (req, res) => {
    const since = parseInt(req.query.since) || 0;
    const messages = (messageStore.get(req.params.address) || [])
        .filter(m => m.timestamp > since);
    res.json({ messages });
});

// ============================================================================
// START
// ============================================================================

app.listen(PORT, () => {
    console.log(`\nX1 Encrypted Messaging Server (Secure + Verified Keys)`);
    console.log(`=======================================================`);
    console.log(`http://localhost:${PORT}`);
    console.log(`\nKey Registration: Requires signature proof of ownership`);
    console.log(`Endpoints:`);
    console.log(`  POST /api/keys     - Register key (with signature)`);
    console.log(`  GET  /api/keys/:a  - Lookup public key`);
    console.log(`  POST /api/messages - Send message`);
    console.log(`  GET  /api/messages/:a - Get messages\n`);
});
