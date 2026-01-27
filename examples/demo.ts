#!/usr/bin/env npx tsx
/**
 * X1 E2E Encrypted Messaging Demo (Solana-compatible)
 *
 * Simulates Alice and Bob exchanging encrypted messages using
 * ed25519 keys and X25519 key exchange (Solana-compatible).
 *
 * Run with: npm run demo
 */

import { MessagingClient, SQLiteAdapter, bytesToHex } from '../src/index.js';
import * as readline from 'readline';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, '..', 'data');

// Ensure data directory exists
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Demo wallet private keys (DO NOT use these in production!)
const ALICE_PRIVATE_KEY = '0x' + 'aa'.repeat(32);
const BOB_PRIVATE_KEY = '0x' + 'bb'.repeat(32);

// Shared storage (simulates on-chain messages)
const dbPath = path.join(dataDir, 'demo.db');

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║   X1 E2E Encrypted Messaging Protocol Demo (Solana-style)    ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  // Remove old database to start fresh
  if (fs.existsSync(dbPath)) {
    fs.unlinkSync(dbPath);
  }

  // Create shared storage
  const storage = new SQLiteAdapter(dbPath);

  // Initialize Alice
  const alice = new MessagingClient({
    privateKey: ALICE_PRIVATE_KEY,
    storage,
  });

  // Initialize Bob (separate client, same storage)
  const bob = new MessagingClient({
    privateKey: BOB_PRIVATE_KEY,
    storage,
  });

  console.log('Clients initialized (Solana-compatible ed25519/X25519):\n');
  console.log(`   Alice's address (base58):     ${alice.getAddress()}`);
  console.log(`   Alice's X25519 key (base58):  ${alice.getX25519PublicKeyBase58()}`);
  console.log();
  console.log(`   Bob's address (base58):       ${bob.getAddress()}`);
  console.log(`   Bob's X25519 key (base58):    ${bob.getX25519PublicKeyBase58()}`);
  console.log();

  // Register each other's X25519 public keys (for ECDH key exchange)
  console.log('Exchanging X25519 public keys for ECDH...\n');
  alice.registerPeer(bob.getAddress(), bob.getX25519PublicKey());
  bob.registerPeer(alice.getAddress(), alice.getX25519PublicKey());

  // Set up real-time message watchers
  alice.onMessage((msg) => {
    console.log(`\n   Alice received: "${msg.content}" (from ${msg.from.slice(0, 8)}...)`);
    printPrompt(currentUser);
  });

  bob.onMessage((msg) => {
    console.log(`\n   Bob received: "${msg.content}" (from ${msg.from.slice(0, 8)}...)`);
    printPrompt(currentUser);
  });

  // Interactive CLI
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  let currentUser: 'alice' | 'bob' = 'alice';

  const printHelp = () => {
    console.log('\nCommands:');
    console.log('   /switch     - Switch between Alice and Bob');
    console.log('   /inbox      - View inbox');
    console.log('   /info       - Show current user info');
    console.log('   /quit       - Exit demo');
    console.log('   <message>   - Send message to the other user\n');
  };

  const printPrompt = (user: string) => {
    process.stdout.write(`\n[${user}] > `);
  };

  const getCurrentClient = () => currentUser === 'alice' ? alice : bob;
  const getOtherClient = () => currentUser === 'alice' ? bob : alice;
  const getOtherUser = () => currentUser === 'alice' ? 'bob' : 'alice';

  printHelp();
  printPrompt(currentUser);

  rl.on('line', async (input) => {
    const trimmed = input.trim();

    if (!trimmed) {
      printPrompt(currentUser);
      return;
    }

    try {
      if (trimmed === '/switch') {
        currentUser = currentUser === 'alice' ? 'bob' : 'alice';
        console.log(`\n   Switched to ${currentUser.toUpperCase()}`);
      } else if (trimmed === '/inbox') {
        const client = getCurrentClient();
        const messages = await client.getMessages({ limit: 10 });

        if (messages.length === 0) {
          console.log('\n   Inbox is empty');
        } else {
          console.log(`\n   Inbox (${messages.length} messages):`);
          for (const msg of messages) {
            const time = new Date(msg.timestamp).toLocaleTimeString();
            console.log(`   [${time}] From ${msg.from.slice(0, 8)}...: ${msg.content}`);
          }
        }
      } else if (trimmed === '/info') {
        const client = getCurrentClient();
        console.log(`\n   Current user: ${currentUser.toUpperCase()}`);
        console.log(`   Address (base58): ${client.getAddress()}`);
        console.log(`   Ed25519 pubkey:   ${client.getPublicKeyBase58()}`);
        console.log(`   X25519 pubkey:    ${client.getX25519PublicKeyBase58()}`);
      } else if (trimmed === '/quit' || trimmed === '/exit') {
        console.log('\n   Goodbye!\n');
        await alice.close();
        rl.close();
        process.exit(0);
      } else if (trimmed.startsWith('/')) {
        console.log(`\n   Unknown command: ${trimmed}`);
        printHelp();
      } else {
        // Send message
        const client = getCurrentClient();
        const other = getOtherClient();
        const otherUser = getOtherUser();

        console.log(`\n   Sending encrypted message to ${otherUser.toUpperCase()}...`);

        const messageId = await client.sendMessage({
          to: other.getAddress(),
          content: trimmed,
        });

        console.log(`   Message sent! (ID: ${messageId.slice(0, 8)}...)`);
      }
    } catch (error) {
      console.error(`\n   Error: ${error instanceof Error ? error.message : error}`);
    }

    printPrompt(currentUser);
  });

  rl.on('close', () => {
    process.exit(0);
  });
}

// Demo non-interactive mode (for quick verification)
async function runAutomatedDemo() {
  console.log('\nRunning automated demo (Solana-compatible)...\n');

  // Use in-memory storage for automated demo
  const storage = new SQLiteAdapter(':memory:');

  const alice = new MessagingClient({
    privateKey: ALICE_PRIVATE_KEY,
    storage,
  });

  const bob = new MessagingClient({
    privateKey: BOB_PRIVATE_KEY,
    storage,
  });

  console.log('Addresses (Solana-style base58):');
  console.log(`  Alice: ${alice.getAddress()}`);
  console.log(`  Bob:   ${bob.getAddress()}`);
  console.log();

  // Exchange X25519 keys for ECDH
  alice.registerPeer(bob.getAddress(), bob.getX25519PublicKey());
  bob.registerPeer(alice.getAddress(), alice.getX25519PublicKey());

  console.log('Step 1: Alice sends message to Bob');
  console.log('-'.repeat(40));

  await alice.sendMessage({
    to: bob.getAddress(),
    content: 'Hello Bob! This is a secret message.',
  });
  console.log('Alice: Sent encrypted message');

  // Bob checks inbox
  const bobMessages = await bob.getMessages();
  console.log(`Bob: Received ${bobMessages.length} message(s)`);
  console.log(`Bob: Decrypted content: "${bobMessages[0].content}"`);

  console.log('\nStep 2: Bob replies to Alice');
  console.log('-'.repeat(40));

  await bob.sendMessage({
    to: alice.getAddress(),
    content: 'Hi Alice! Got your message. Encryption works!',
  });
  console.log('Bob: Sent encrypted reply');

  const aliceMessages = await alice.getMessages();
  console.log(`Alice: Received ${aliceMessages.length} message(s)`);
  console.log(`Alice: Decrypted content: "${aliceMessages[0].content}"`);

  console.log('\nStep 3: Test long message (chunking)');
  console.log('-'.repeat(40));

  const longMessage = 'This is a very long message that exceeds the maximum payload size of a single envelope. '.repeat(5);
  const beforeLongMsg = Date.now();

  await alice.sendMessage({
    to: bob.getAddress(),
    content: longMessage,
  });
  console.log(`Alice: Sent ${longMessage.length}-byte message (requires chunking)`);

  // Get messages since before the long message was sent to avoid conflicts with earlier messages
  const bobLongMessages = await bob.getMessages({ since: beforeLongMsg - 1 });
  if (bobLongMessages.length > 0) {
    const received = bobLongMessages[0].content;
    console.log(`Bob: Received and reassembled ${received.length}-byte message`);
    console.log(`Bob: Content matches: ${received === longMessage}`);
  } else {
    console.log('Bob: Message still being reassembled (chunks received separately)');
  }

  console.log('\nAutomated demo completed successfully!\n');

  await alice.close();
}

// Check command line args
const args = process.argv.slice(2);
if (args.includes('--auto') || args.includes('-a')) {
  runAutomatedDemo().catch(console.error);
} else {
  main().catch(console.error);
}
