import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MessagingClient } from '../src/client.js';
import { SQLiteAdapter } from '../src/storage/index.js';
import { bytesToHex } from '../src/crypto/index.js';

describe('MessagingClient (Solana-compatible)', () => {
  // Test wallet private keys
  const aliceWallet = '0x' + 'aa'.repeat(32);
  const bobWallet = '0x' + 'bb'.repeat(32);

  let storage: SQLiteAdapter;
  let alice: MessagingClient;
  let bob: MessagingClient;

  beforeEach(() => {
    // Use shared in-memory storage so Alice and Bob can communicate
    storage = new SQLiteAdapter(':memory:');

    alice = new MessagingClient({
      privateKey: aliceWallet,
      storage,
    });

    bob = new MessagingClient({
      privateKey: bobWallet,
      storage,
    });

    // Register each other's X25519 public keys for key exchange
    alice.registerPeer(bob.getAddress(), bob.getX25519PublicKey());
    bob.registerPeer(alice.getAddress(), alice.getX25519PublicKey());
  });

  afterEach(async () => {
    await alice.close();
    // Bob uses same storage, already closed
  });

  describe('initialization', () => {
    it('should derive Solana-style base58 address from private key', () => {
      // Solana addresses are 32-44 base58 characters
      expect(alice.getAddress().length).toBeGreaterThanOrEqual(32);
      expect(alice.getAddress().length).toBeLessThanOrEqual(44);
      expect(/^[1-9A-HJ-NP-Za-km-z]+$/.test(alice.getAddress())).toBe(true);

      expect(bob.getAddress().length).toBeGreaterThanOrEqual(32);
      expect(/^[1-9A-HJ-NP-Za-km-z]+$/.test(bob.getAddress())).toBe(true);
    });

    it('should have different addresses for different keys', () => {
      expect(alice.getAddress()).not.toBe(bob.getAddress());
    });

    it('should derive 32-byte ed25519 public key', () => {
      expect(alice.getPublicKey().length).toBe(32);
      expect(bob.getPublicKey().length).toBe(32);
    });

    it('should derive 32-byte X25519 public key for key exchange', () => {
      expect(alice.getX25519PublicKey().length).toBe(32);
      expect(bob.getX25519PublicKey().length).toBe(32);
    });

    it('should have different public keys for different keys', () => {
      expect(bytesToHex(alice.getPublicKey())).not.toBe(bytesToHex(bob.getPublicKey()));
      expect(bytesToHex(alice.getX25519PublicKey())).not.toBe(bytesToHex(bob.getX25519PublicKey()));
    });

    it('should be deterministic', () => {
      const alice2 = new MessagingClient({
        privateKey: aliceWallet,
        storage: new SQLiteAdapter(':memory:'),
      });

      expect(alice2.getAddress()).toBe(alice.getAddress());
      expect(bytesToHex(alice2.getPublicKey())).toBe(bytesToHex(alice.getPublicKey()));
      expect(bytesToHex(alice2.getX25519PublicKey())).toBe(bytesToHex(alice.getX25519PublicKey()));
    });

    it('should provide base58 encoded public keys', () => {
      const base58Pubkey = alice.getPublicKeyBase58();
      const base58X25519 = alice.getX25519PublicKeyBase58();

      // Should be valid base58
      expect(/^[1-9A-HJ-NP-Za-km-z]+$/.test(base58Pubkey)).toBe(true);
      expect(/^[1-9A-HJ-NP-Za-km-z]+$/.test(base58X25519)).toBe(true);

      // Public key as base58 should equal address (Solana-style)
      expect(base58Pubkey).toBe(alice.getAddress());
    });
  });

  describe('sendMessage / getMessages', () => {
    it('should send and receive a message', async () => {
      const messageId = await alice.sendMessage({
        to: bob.getAddress(),
        content: 'Hello Bob!',
      });

      expect(messageId).toBeDefined();
      expect(messageId.length).toBe(16); // 8 bytes = 16 hex chars

      // Bob retrieves messages
      const messages = await bob.getMessages();

      expect(messages.length).toBe(1);
      expect(messages[0].from).toBe(alice.getAddress());
      expect(messages[0].to).toBe(bob.getAddress());
      expect(messages[0].content).toBe('Hello Bob!');
    });

    it('should handle multiple messages', async () => {
      await alice.sendMessage({ to: bob.getAddress(), content: 'Message 1' });
      await alice.sendMessage({ to: bob.getAddress(), content: 'Message 2' });
      await alice.sendMessage({ to: bob.getAddress(), content: 'Message 3' });

      const messages = await bob.getMessages();

      expect(messages.length).toBe(3);
      // Messages are ordered by timestamp descending
      expect(messages.map((m) => m.content)).toContain('Message 1');
      expect(messages.map((m) => m.content)).toContain('Message 2');
      expect(messages.map((m) => m.content)).toContain('Message 3');
    });

    it('should filter messages by sender', async () => {
      // Create a third user
      const charlieWallet = '0x' + 'cc'.repeat(32);
      const charlie = new MessagingClient({
        privateKey: charlieWallet,
        storage,
      });
      charlie.registerPeer(bob.getAddress(), bob.getX25519PublicKey());
      bob.registerPeer(charlie.getAddress(), charlie.getX25519PublicKey());

      await alice.sendMessage({ to: bob.getAddress(), content: 'From Alice' });
      await charlie.sendMessage({ to: bob.getAddress(), content: 'From Charlie' });

      // Get only Alice's messages
      const aliceMessages = await bob.getMessages({ from: alice.getAddress() });
      expect(aliceMessages.length).toBe(1);
      expect(aliceMessages[0].content).toBe('From Alice');

      // Get only Charlie's messages
      const charlieMessages = await bob.getMessages({ from: charlie.getAddress() });
      expect(charlieMessages.length).toBe(1);
      expect(charlieMessages[0].content).toBe('From Charlie');
    });

    it('should filter messages by timestamp', async () => {
      await alice.sendMessage({ to: bob.getAddress(), content: 'Old message' });
      const cutoff = Date.now();
      await new Promise((r) => setTimeout(r, 10)); // Small delay
      await alice.sendMessage({ to: bob.getAddress(), content: 'New message' });

      const newMessages = await bob.getMessages({ since: cutoff });
      expect(newMessages.length).toBe(1);
      expect(newMessages[0].content).toBe('New message');
    });

    it('should limit number of messages', async () => {
      await alice.sendMessage({ to: bob.getAddress(), content: 'Message 1' });
      await alice.sendMessage({ to: bob.getAddress(), content: 'Message 2' });
      await alice.sendMessage({ to: bob.getAddress(), content: 'Message 3' });

      const messages = await bob.getMessages({ limit: 2 });
      expect(messages.length).toBe(2);
    });

    it('should handle binary content', async () => {
      const binaryContent = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe]);

      await alice.sendMessage({
        to: bob.getAddress(),
        content: binaryContent,
      });

      const messages = await bob.getMessages();
      expect(messages.length).toBe(1);
      expect(bytesToHex(messages[0].contentBytes)).toBe(bytesToHex(binaryContent));
    });

    it('should handle long messages (chunking)', async () => {
      // Create a message longer than MAX_PAYLOAD_SIZE (230 bytes)
      const longContent = 'A'.repeat(1000);

      await alice.sendMessage({
        to: bob.getAddress(),
        content: longContent,
      });

      const messages = await bob.getMessages();
      expect(messages.length).toBe(1);
      expect(messages[0].content).toBe(longContent);
    });

    it('should throw when no session key available', async () => {
      // Unknown Solana-style address
      const unknownAddress = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';

      await expect(alice.sendMessage({
        to: unknownAddress,
        content: 'Hello?',
      })).rejects.toThrow('No session key');
    });

    it('should work with provided recipient X25519 public key', async () => {
      // Create new client without pre-registered peers
      const newAlice = new MessagingClient({
        privateKey: aliceWallet,
        storage: new SQLiteAdapter(':memory:'),
      });

      const newBob = new MessagingClient({
        privateKey: bobWallet,
        storage: newAlice['storage'], // Share storage
      });

      // Bob registers Alice to receive her messages
      newBob.registerPeer(newAlice.getAddress(), newAlice.getX25519PublicKey());

      // Alice sends with explicit X25519 public key
      await newAlice.sendMessage({
        to: newBob.getAddress(),
        content: 'Hello with explicit key!',
        recipientPublicKey: newBob.getX25519PublicKey(),
      });

      const messages = await newBob.getMessages();
      expect(messages.length).toBe(1);
      expect(messages[0].content).toBe('Hello with explicit key!');
    });
  });

  describe('onMessage (real-time)', () => {
    it('should receive messages in real-time', async () => {
      const receivedMessages: string[] = [];

      bob.onMessage((msg) => {
        receivedMessages.push(msg.content);
      });

      await alice.sendMessage({ to: bob.getAddress(), content: 'Real-time 1' });
      await alice.sendMessage({ to: bob.getAddress(), content: 'Real-time 2' });

      // Wait for messages to be processed
      await new Promise((r) => setTimeout(r, 50));

      expect(receivedMessages).toContain('Real-time 1');
      expect(receivedMessages).toContain('Real-time 2');
    });

    it('should support multiple handlers', async () => {
      const handler1Messages: string[] = [];
      const handler2Messages: string[] = [];

      bob.onMessage((msg) => handler1Messages.push(msg.content));
      bob.onMessage((msg) => handler2Messages.push(msg.content));

      await alice.sendMessage({ to: bob.getAddress(), content: 'Multi-handler test' });

      await new Promise((r) => setTimeout(r, 50));

      expect(handler1Messages).toContain('Multi-handler test');
      expect(handler2Messages).toContain('Multi-handler test');
    });

    it('should unsubscribe correctly', async () => {
      const receivedMessages: string[] = [];

      const unsubscribe = bob.onMessage((msg) => {
        receivedMessages.push(msg.content);
      });

      await alice.sendMessage({ to: bob.getAddress(), content: 'Before unsub' });
      await new Promise((r) => setTimeout(r, 50));

      unsubscribe();

      await alice.sendMessage({ to: bob.getAddress(), content: 'After unsub' });
      await new Promise((r) => setTimeout(r, 50));

      expect(receivedMessages).toContain('Before unsub');
      expect(receivedMessages).not.toContain('After unsub');
    });
  });

  describe('bidirectional communication', () => {
    it('should allow both parties to send and receive', async () => {
      // Alice sends to Bob
      await alice.sendMessage({ to: bob.getAddress(), content: 'Alice to Bob' });

      // Bob sends to Alice
      await bob.sendMessage({ to: alice.getAddress(), content: 'Bob to Alice' });

      // Check Alice's inbox
      const aliceInbox = await alice.getMessages();
      expect(aliceInbox.length).toBe(1);
      expect(aliceInbox[0].content).toBe('Bob to Alice');
      expect(aliceInbox[0].from).toBe(bob.getAddress());

      // Check Bob's inbox
      const bobInbox = await bob.getMessages();
      expect(bobInbox.length).toBe(1);
      expect(bobInbox[0].content).toBe('Alice to Bob');
      expect(bobInbox[0].from).toBe(alice.getAddress());
    });

    it('should support a full conversation', async () => {
      await alice.sendMessage({ to: bob.getAddress(), content: 'Hi Bob!' });
      await bob.sendMessage({ to: alice.getAddress(), content: 'Hello Alice!' });
      await alice.sendMessage({ to: bob.getAddress(), content: 'How are you?' });
      await bob.sendMessage({ to: alice.getAddress(), content: 'Great, thanks!' });

      const aliceInbox = await alice.getMessages();
      const bobInbox = await bob.getMessages();

      expect(aliceInbox.length).toBe(2);
      expect(bobInbox.length).toBe(2);

      // Verify message contents
      const aliceContents = aliceInbox.map((m) => m.content);
      expect(aliceContents).toContain('Hello Alice!');
      expect(aliceContents).toContain('Great, thanks!');

      const bobContents = bobInbox.map((m) => m.content);
      expect(bobContents).toContain('Hi Bob!');
      expect(bobContents).toContain('How are you?');
    });
  });
});
