// xchat bridge — OpenClaw agent client
// Uses the gateway sessions_send tool to create proper named sessions

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

// Gateway config
const GATEWAY_URL = process.env.OPENCLAW_GATEWAY || 'http://127.0.0.1:18789';
const GATEWAY_TOKEN = process.env.OPENCLAW_TOKEN || loadGatewayToken();

function loadGatewayToken() {
    try {
        const cfgPath = path.join(process.env.HOME || '/root', '.openclaw', 'openclaw.json');
        const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
        return cfg?.gateway?.auth?.token || '';
    } catch {
        return '';
    }
}

/**
 * Build the session key for a given session/sender.
 * When senderAddress is provided, each sender gets their own session.
 * Format: agent:opus:xchat:<senderAddress|sessionId>
 */
function buildSessionKey(config, senderAddress) {
    const agentId = config.agentId || 'opus';
    const id = senderAddress || config.sessionId || 'main';
    return `agent:${agentId}:xchat:${id}`;
}

/**
 * Send a message to the OpenClaw agent via gateway sessions_send tool.
 * This creates a proper named session in the portal.
 *
 * @param {object} config - { agentId, sessionId }
 * @param {string} message - The message text to send to the agent
 * @param {string} [senderAddress] - Optional sender wallet address for context
 * @returns {Promise<string>} The agent's response text
 */
export async function sendToAgent(config, message, senderAddress) {
    const sessionKey = buildSessionKey(config, senderAddress);

    // Format message with sender context if available
    const agentMessage = senderAddress
        ? `[xChat from ${senderAddress.slice(0, 8)}...] ${message}`
        : message;

    const body = JSON.stringify({
        tool: 'sessions_send',
        args: {
            sessionKey,
            message: agentMessage,
        },
    });

    const result = await gatewayPost('/tools/invoke', body);

    // Parse the response
    const details = result?.result?.details;
    if (details?.reply) return details.reply;
    if (details?.status === 'ok' && details?.reply === '') {
        console.log('[OpenClaw] Agent returned empty reply for session:', sessionKey);
        return null;
    }

    // Fallback: parse text content
    const content = result?.result?.content;
    if (Array.isArray(content) && content.length > 0) {
        const text = content[0]?.text;
        if (text) {
            try {
                const parsed = JSON.parse(text);
                if (parsed.reply) return parsed.reply;
                if (parsed.status === 'error') throw new Error(parsed.error || 'Agent error');
            } catch (e) {
                if (e.message.startsWith('Agent error')) throw e;
                return text;
            }
        }
    }

    console.log('[OpenClaw] Unexpected response shape:', JSON.stringify(result).slice(0, 300));
    return null;
}

/**
 * POST JSON to the OpenClaw gateway.
 */
function gatewayPost(endpoint, body) {
    return new Promise((resolve, reject) => {
        const url = new URL(endpoint, GATEWAY_URL);
        const options = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${GATEWAY_TOKEN}`,
                'Content-Length': Buffer.byteLength(body),
            },
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    if (parsed.ok === false) {
                        reject(new Error(parsed.error?.message || 'Gateway error'));
                        return;
                    }
                    resolve(parsed);
                } catch {
                    reject(new Error(`Gateway returned non-JSON: ${data.slice(0, 200)}`));
                }
            });
        });

        req.on('error', (e) => reject(new Error(`Gateway connection failed: ${e.message}`)));
        req.setTimeout(300_000, () => {
            req.destroy();
            reject(new Error('Gateway request timed out'));
        });
        req.write(body);
        req.end();
    });
}
