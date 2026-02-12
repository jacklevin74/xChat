# xchat TCP Bridge

TCP server that bridges xchat encrypted messaging with OpenClaw AI agents. Connect from any TCP client (netcat, scripts, bots) to send/receive encrypted messages and chat with an AI agent.

```
TCP Client (netcat/script/bot)
    |
    |  TCP (line-delimited JSON)
    |
+---+------------------------------------+
|  xchat-tcp-bridge                      |
|  +- TCP server (port 9100)             |
|  +- OpenClaw agent driver              | --> openclaw CLI (agent session)
|  +- xchat crypto (AES-256-GCM)         |
|  +- SSE listener (incoming messages)   | --> xchat server (port 3001)
+----------------------------------------+
```

## Quick Start

```bash
# Start the bridge
XCHAT_BRIDGE_PORT=9101 npm run bridge

# Connect from another terminal
node bridge/example-client.js 9101
```

## Architecture

### Components

| File | Role |
|------|------|
| `tcp-bridge.js` | TCP server, connection handling, protocol parsing |
| `bridge-client.js` | Per-connection state: auth, send, chat, incoming messages |
| `openclaw.js` | Sends messages to OpenClaw agent via `openclaw agent` CLI |
| `xchat-api.js` | HTTP/SSE client for xchat server (keys, messages, stream) |
| `crypto.js` | Key derivation, AES-256-GCM encrypt/decrypt, base58 |

### Message Flows

**Chat with AI agent (no xchat):**

```
TCP client  -->  bridge  -->  openclaw CLI  -->  AI agent
TCP client  <--  bridge  <--  openclaw CLI  <--  AI response
```

**Send encrypted message + get agent response:**

```
TCP client  -->  bridge  -->  encrypt  -->  xchat server  -->  recipient
                    |
                    +-->  openclaw CLI  -->  AI agent
                    +<--  openclaw CLI  <--  AI response
                    +-->  encrypt       -->  xchat server  -->  recipient
TCP client  <--  bridge  (sent confirmation + agent reply)
```

**Receive encrypted message (via SSE):**

```
sender  -->  xchat server  -->  SSE  -->  bridge  -->  decrypt  -->  TCP client
                                            |
                                            +-->  openclaw CLI  -->  AI agent
                                            +<--  AI response
                                            +-->  encrypt  -->  xchat server  -->  sender
                                    TCP client  <--  (incoming msg + agent reply)
```

### Crypto

Uses the browser-compatible key derivation path so messages interoperate with the xchat webapp:

1. `ed25519.sign("X1 Encrypted Messaging - Sign to generate your encryption keys", privateKey)` -> 64-byte signature
2. `HKDF-SHA256(signature, "x1-msg-v1-x25519")` -> X25519 private key (32 bytes)
3. `x25519.getPublicKey(private)` -> X25519 public key
4. Per-peer session key: `X25519 ECDH` -> `HKDF-SHA256(shared, "x1-msg-v1-session")` -> AES-256 key
5. Encryption: `AES-256-GCM` with random 12-byte nonce
6. Wire format: base58-encoded nonce + ciphertext

All crypto uses `@noble/curves`, `@noble/hashes`, `@noble/ciphers` (already in package.json).

### OpenClaw Integration

The bridge drives OpenClaw agent sessions via the gateway `sessions_send` tool:

```
POST http://127.0.0.1:18789/tools/invoke
{
  "tool": "sessions_send",
  "args": {
    "sessionKey": "agent:opus:xchat:<session-name>",
    "message": "..."
  }
}
```

- Sessions auto-create on first message (no setup needed)
- Each session gets a distinct key like `agent:opus:xchat:my-project`
- Sessions appear separately in the OpenClaw web portal
- Session history persists across bridge restarts
- Clients can switch sessions with the `session` command

## Protocol

Line-delimited JSON over TCP. Also supports plaintext commands (auto-detected).

### Commands

| Command | JSON | Plaintext |
|---------|------|-----------|
| Authenticate | `{"cmd":"auth","key":"<ed25519-key>"}` | `auth <key>` |
| Chat with agent | `{"cmd":"chat","text":"hello"}` | `chat hello` |
| Send xchat message | `{"cmd":"send","to":"<addr>","text":"hi"}` | `send <addr> hi` |
| List peers | `{"cmd":"peers"}` | `peers` |
| Connection status | `{"cmd":"status"}` | `status` |
| Help | `{"cmd":"help"}` | `help` |
| Disconnect | `{"cmd":"close"}` | `quit` |

### Events

All responses are JSON, one per line:

```json
{"ok":true,"event":"welcome","version":"1.0"}
{"ok":true,"event":"auth","address":"2jcho...","x25519":"GvCG...","session":"xchat-bridge","xchatRegistered":true}
{"ok":true,"event":"reply","from":"agent","text":"Hello! How can I help?"}
{"ok":true,"event":"sent","to":"AivknDqD...","id":"ml2u4enp","agentReply":"..."}
{"ok":true,"event":"message","from":"AivknDqD...","text":"Hey!","id":"abc123","ts":1707600000000}
{"ok":true,"event":"status","authenticated":true,"address":"2jcho...","agent":"opus","session":"xchat-bridge","peers":1}
{"ok":true,"event":"peers","list":[{"address":"AivknDqD..."}]}
{"ok":false,"error":"Not authenticated. Use auth first.","code":"AUTH_REQUIRED"}
```

## Configuration

All via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `XCHAT_BRIDGE_PORT` | `9100` | TCP server port |
| `XCHAT_SERVER` | `http://localhost:3001` | xchat server URL |
| `OPENCLAW_AGENT` | `opus` | OpenClaw agent ID |
| `OPENCLAW_SESSION` | `xchat-bridge` | Session ID for conversation continuity |
| `OPENCLAW_GATEWAY` | `http://127.0.0.1:18789` | OpenClaw gateway URL |
| `OPENCLAW_TOKEN` | *(from openclaw.json)* | Gateway auth token |
| `XCHAT_WALLET_KEY` | (none) | Auto-authenticate on connect |

## Usage Examples

### Chat with the AI agent

No xchat server needed. Just the OpenClaw gateway.

```bash
$ XCHAT_BRIDGE_PORT=9101 npm run bridge &
$ nc 127.0.0.1 9101
{"ok":true,"event":"welcome","version":"1.0"}
{"cmd":"chat","text":"summarize the last 3 commits"}
{"ok":true,"event":"reply","from":"agent","text":"Here are the last 3 commits: ..."}
```

### Send encrypted messages

Requires xchat server running (`npm run webapp`).

```bash
{"cmd":"auth","key":"5cPZtFuz...base58-private-key..."}
{"ok":true,"event":"auth","address":"2jcho...","xchatRegistered":true}

{"cmd":"send","to":"AivknDqD...recipient-address...","text":"Hello from the bridge!"}
{"ok":true,"event":"sent","to":"AivknDqD...","id":"ml2u4enp","agentReply":"I said hello to them for you."}
```

### Auto-auth mode

Pre-configure the wallet key so clients don't need to authenticate:

```bash
XCHAT_WALLET_KEY="5cPZtFuz..." XCHAT_BRIDGE_PORT=9101 npm run bridge
```

Clients get an `auth` event immediately on connect.

### Scripting

```bash
#!/bin/bash
exec 3<>/dev/tcp/127.0.0.1/9101
read -r WELCOME <&3
echo '{"cmd":"chat","text":"what time is it?"}' >&3
read -r RESPONSE <&3
echo "$RESPONSE" | jq -r '.text'
exec 3>&-
```

### Node.js client

```javascript
import net from 'node:net';
import readline from 'node:readline';

const client = net.connect(9101, '127.0.0.1');
const rl = readline.createInterface({ input: client });

rl.on('line', (line) => {
    const event = JSON.parse(line);
    if (event.event === 'reply') console.log('Agent:', event.text);
});

client.on('connect', () => {
    client.write('{"cmd":"chat","text":"hello"}\n');
});
```

## Dependencies

None beyond what's already in `package.json`:

- `@noble/curves` (ed25519, x25519)
- `@noble/hashes` (HKDF, SHA-256)
- `@noble/ciphers` (AES-256-GCM)
- Node built-ins: `net`, `readline`, `child_process`, `http`

## Security Notes

- TCP server binds to `127.0.0.1` only (localhost)
- Private keys transit over local TCP — do not expose the port externally
- All xchat messages are end-to-end encrypted with AES-256-GCM
- The bridge never stores private keys to disk
