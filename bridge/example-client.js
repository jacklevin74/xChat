#!/usr/bin/env node
// Interactive client for xchat TCP bridge
// Usage: node bridge/example-client.js [port]

import net from 'node:net';
import readline from 'node:readline';

const PORT = parseInt(process.argv[2] || '9101');
const client = net.connect(PORT, '127.0.0.1');

// Read responses from bridge
const bridgeRL = readline.createInterface({ input: client });
bridgeRL.on('line', (line) => {
    try {
        const data = JSON.parse(line);
        if (data.event === 'reply') {
            console.log(`\x1b[36m[agent]\x1b[0m ${data.text}`);
        } else if (data.event === 'message') {
            console.log(`\x1b[33m[${data.from?.slice(0, 8)}...]\x1b[0m ${data.text}`);
        } else if (data.event === 'welcome') {
            console.log(`\x1b[2mConnected to xchat bridge v${data.version}\x1b[0m`);
        } else if (data.event === 'auth') {
            console.log(`\x1b[32mAuthenticated:\x1b[0m ${data.address}`);
            if (!data.xchatRegistered) console.log(`\x1b[2m(xchat server not available — chat command still works)\x1b[0m`);
        } else if (data.event === 'session') {
            console.log(`\x1b[35mSession:\x1b[0m ${data.session}${data.info ? ` — ${data.info}` : ''}`);
        } else if (data.event === 'sent') {
            console.log(`\x1b[32mSent\x1b[0m to ${data.to?.slice(0, 8)}... (id: ${data.id})`);
            if (data.agentReply) console.log(`\x1b[36m[agent]\x1b[0m ${data.agentReply}`);
        } else if (data.event === 'bye') {
            // handled by close
        } else if (!data.ok) {
            console.log(`\x1b[31mError:\x1b[0m ${data.error}`);
        } else {
            console.log('\x1b[2m<\x1b[0m', line);
        }
    } catch {
        console.log('<', line);
    }
});

// Read user input from stdin
const stdinRL = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: '> ' });

client.on('connect', () => {
    console.log(`\x1b[2mType commands (help for list). Prefix with / for shortcuts.\x1b[0m`);
    console.log(`\x1b[2mShortcuts: /chat <msg>, /auth <key>, /send <addr> <msg>, /session [name], /status, /peers, /quit\x1b[0m\n`);
    stdinRL.prompt();
});

stdinRL.on('line', (line) => {
    line = line.trim();
    if (!line) { stdinRL.prompt(); return; }

    // Shortcuts starting with /
    if (line.startsWith('/')) {
        const parts = line.slice(1).split(/\s+/);
        const cmd = parts[0].toLowerCase();
        switch (cmd) {
            case 'chat': case 'c':
                client.write(JSON.stringify({ cmd: 'chat', text: parts.slice(1).join(' ') }) + '\n');
                break;
            case 'auth': case 'a':
                client.write(JSON.stringify({ cmd: 'auth', key: parts[1] }) + '\n');
                break;
            case 'send': case 's':
                client.write(JSON.stringify({ cmd: 'send', to: parts[1], text: parts.slice(2).join(' ') }) + '\n');
                break;
            case 'session':
                if (parts[1]) {
                    client.write(JSON.stringify({ cmd: 'session', name: parts[1] }) + '\n');
                } else {
                    client.write('{"cmd":"session"}\n');
                }
                break;
            case 'status':
                client.write('{"cmd":"status"}\n');
                break;
            case 'peers':
                client.write('{"cmd":"peers"}\n');
                break;
            case 'help': case 'h':
                client.write('{"cmd":"help"}\n');
                break;
            case 'quit': case 'q': case 'exit':
                client.write('{"cmd":"close"}\n');
                return;
            default:
                console.log('Unknown shortcut. Try /help');
        }
    } else if (line.startsWith('{')) {
        // Raw JSON
        client.write(line + '\n');
    } else {
        // Default: treat as chat message
        client.write(JSON.stringify({ cmd: 'chat', text: line }) + '\n');
    }

    stdinRL.prompt();
});

client.on('close', () => {
    console.log('\nDisconnected');
    process.exit(0);
});

client.on('error', (e) => {
    console.error('Connection error:', e.message);
    process.exit(1);
});

stdinRL.on('close', () => {
    client.write('{"cmd":"close"}\n');
    setTimeout(() => process.exit(0), 500);
});
