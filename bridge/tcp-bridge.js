#!/usr/bin/env node
// xchat TCP Bridge — main entry point
// Runs a TCP server that lets clients interact with xchat + OpenClaw agent

import net from 'node:net';
import readline from 'node:readline';
import { BridgeClient } from './bridge-client.js';

// ============================================================================
// CONFIG (from environment variables)
// ============================================================================

const TCP_PORT = parseInt(process.env.XCHAT_BRIDGE_PORT || '9100');
const XCHAT_SERVER = process.env.XCHAT_SERVER || 'http://localhost:3001';
const OPENCLAW_AGENT = process.env.OPENCLAW_AGENT || 'opus';
const OPENCLAW_SESSION = process.env.OPENCLAW_SESSION || 'xchat-bridge';
const AUTO_KEY = process.env.XCHAT_WALLET_KEY || null;

// ============================================================================
// PROTOCOL — parse commands, format responses
// ============================================================================

function parseCommand(line) {
    line = line.trim();
    if (!line) return null;

    // JSON mode
    if (line.startsWith('{')) {
        try {
            return JSON.parse(line);
        } catch {
            return null;
        }
    }

    // Plaintext mode
    const parts = line.split(/\s+/);
    const cmd = parts[0].toLowerCase();

    switch (cmd) {
        case 'auth':
            return { cmd: 'auth', key: parts[1], server: parts[2] };
        case 'send':
            return { cmd: 'send', to: parts[1], text: parts.slice(2).join(' ') };
        case 'chat':
            return { cmd: 'chat', text: parts.slice(1).join(' ') };
        case 'peers':
            return { cmd: 'peers' };
        case 'status':
            return { cmd: 'status' };
        case 'session':
            return { cmd: 'session', name: parts[1] };
        case 'close':
        case 'quit':
        case 'exit':
            return { cmd: 'close' };
        case 'help':
            return { cmd: 'help' };
        default:
            return null;
    }
}

function send(socket, obj) {
    try {
        socket.write(JSON.stringify(obj) + '\n');
    } catch {
        // socket closed
    }
}

// ============================================================================
// STANDALONE AGENT — shared client that auto-auths on startup
// ============================================================================

let agentClient = null; // shared agent client, created when XCHAT_WALLET_KEY is set

async function startAgentBot() {
    if (!AUTO_KEY) return;

    console.log('[Agent] Starting standalone agent bot...');

    agentClient = new BridgeClient({
        xchatServer: XCHAT_SERVER,
        openclaw: {
            agentId: OPENCLAW_AGENT,
            sessionId: OPENCLAW_SESSION,
        },
    });

    // Log events to stdout
    agentClient.onEvent = (event) => {
        if (event.event === 'message') {
            console.log(`[Agent] Message from ${event.from?.slice(0, 8)}...: ${event.text}`);
        } else if (event.event === 'reply') {
            console.log(`[Agent] Reply to ${event.inReplyTo || 'unknown'}: ${event.text?.slice(0, 100)}...`);
        } else if (event.event === 'sse_connected') {
            console.log(`[Agent] SSE connected (${event.messageCount} messages)`);
        } else if (event.event === 'sse_ready') {
            console.log('[Agent] SSE ready — listening for messages');
        }
    };

    try {
        const result = await agentClient.auth(AUTO_KEY);
        console.log(`[Agent] Authenticated: ${result.address}`);
        if (!result.xchatRegistered) {
            console.log('[Agent] WARNING: xchat server not available — cannot receive messages');
        }
    } catch (e) {
        console.error(`[Agent] Auth failed: ${e.message}`);
        agentClient = null;
    }
}

// ============================================================================
// CONNECTION HANDLER
// ============================================================================

function handleConnection(socket) {
    const remoteAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[TCP] Connected: ${remoteAddr}`);

    const client = new BridgeClient({
        xchatServer: XCHAT_SERVER,
        openclaw: {
            agentId: OPENCLAW_AGENT,
            sessionId: OPENCLAW_SESSION,
        },
    });

    // Push events from bridge client to TCP socket
    client.onEvent = (event) => send(socket, event);

    // Welcome
    send(socket, { ok: true, event: 'welcome', version: '1.0' });

    // Auto-auth TCP connections too if wallet key provided
    if (AUTO_KEY) {
        (async () => {
            try {
                const result = await client.auth(AUTO_KEY);
                send(socket, { ok: true, event: 'auth', ...result });
            } catch (e) {
                send(socket, { ok: false, error: `Auto-auth failed: ${e.message}`, code: 'AUTH_FAILED' });
            }
        })();
    }

    const rl = readline.createInterface({ input: socket });

    // Serialize async command handling to prevent race conditions
    let processing = Promise.resolve();
    rl.on('line', (line) => {
        processing = processing.then(() => handleLine(line)).catch((e) => {
            send(socket, { ok: false, error: e.message, code: 'INTERNAL_ERROR' });
        });
    });

    async function handleLine(line) {
        const cmd = parseCommand(line);
        if (!cmd) {
            send(socket, { ok: false, error: 'Invalid command. Try: auth, send, chat, peers, status, help', code: 'PARSE_ERROR' });
            return;
        }

        try {
            switch (cmd.cmd) {
                case 'auth': {
                    if (!cmd.key) {
                        send(socket, { ok: false, error: 'Missing key', code: 'MISSING_KEY' });
                        return;
                    }
                    const result = await client.auth(cmd.key);
                    send(socket, { ok: true, event: 'auth', ...result });
                    break;
                }

                case 'send': {
                    if (!client.keys) {
                        send(socket, { ok: false, error: 'Not authenticated. Use auth first.', code: 'AUTH_REQUIRED' });
                        return;
                    }
                    if (!cmd.to || !cmd.text) {
                        send(socket, { ok: false, error: 'Usage: send <address> <text>', code: 'MISSING_ARGS' });
                        return;
                    }
                    const result = await client.send(cmd.to, cmd.text);
                    send(socket, { ok: true, event: 'sent', to: cmd.to, id: result.id, agentReply: result.agentReply });
                    break;
                }

                case 'chat': {
                    if (!cmd.text) {
                        send(socket, { ok: false, error: 'Usage: chat <text>', code: 'MISSING_ARGS' });
                        return;
                    }
                    const result = await client.chat(cmd.text);
                    send(socket, { ok: true, event: 'reply', from: 'agent', text: result.reply });
                    break;
                }

                case 'session': {
                    if (!cmd.name) {
                        // No name = show current session
                        send(socket, { ok: true, event: 'session', session: client.config.openclaw.sessionId });
                        return;
                    }
                    const result = client.setSession(cmd.name);
                    send(socket, { ok: true, event: 'session', ...result, info: 'Session set. Next chat message will use this session.' });
                    break;
                }

                case 'peers': {
                    send(socket, { ok: true, event: 'peers', list: client.getPeers() });
                    break;
                }

                case 'status': {
                    send(socket, { ok: true, event: 'status', ...client.getStatus() });
                    break;
                }

                case 'help': {
                    send(socket, {
                        ok: true, event: 'help',
                        commands: {
                            auth: 'auth <private-key> — Authenticate with ed25519 key (hex or base58)',
                            send: 'send <address> <text> — Send encrypted xchat message + get agent response',
                            chat: 'chat <text> — Chat directly with the OpenClaw agent',
                            session: 'session [name] — Show or switch session (creates new if needed)',
                            peers: 'peers — List known xchat peers',
                            status: 'status — Show connection status',
                            close: 'close — Disconnect',
                        },
                    });
                    break;
                }

                case 'close': {
                    send(socket, { ok: true, event: 'bye' });
                    client.destroy();
                    socket.end();
                    break;
                }
            }
        } catch (e) {
            send(socket, { ok: false, error: e.message, code: 'ERROR' });
        }
    }

    socket.on('close', () => {
        console.log(`[TCP] Disconnected: ${remoteAddr}`);
        client.destroy();
    });

    socket.on('error', (e) => {
        if (e.code !== 'ECONNRESET') {
            console.error(`[TCP] Error (${remoteAddr}):`, e.message);
        }
        client.destroy();
    });
}

// ============================================================================
// SERVER
// ============================================================================

const server = net.createServer(handleConnection);

server.listen(TCP_PORT, '127.0.0.1', () => {
    console.log('═══════════════════════════════════════');
    console.log('  xchat TCP Bridge');
    console.log('═══════════════════════════════════════');
    console.log(`  TCP:      127.0.0.1:${TCP_PORT}`);
    console.log(`  xchat:    ${XCHAT_SERVER}`);
    console.log(`  Agent:    ${OPENCLAW_AGENT}`);
    console.log(`  Session:  ${OPENCLAW_SESSION}`);
    if (AUTO_KEY) console.log(`  Mode:     Agent bot (auto-auth)`);
    console.log('═══════════════════════════════════════');
    console.log(`\n  Connect: nc localhost ${TCP_PORT}\n`);

    // Start standalone agent bot if wallet key is configured
    startAgentBot();
});

server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        console.error(`Port ${TCP_PORT} already in use. Set XCHAT_BRIDGE_PORT to use a different port.`);
    } else {
        console.error('Server error:', e);
    }
    process.exit(1);
});
