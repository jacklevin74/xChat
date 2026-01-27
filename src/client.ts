import {
  deriveMessagingKeyPair,
  computeSharedSecret,
  publicKeyToAddress,
  getX25519PublicKey,
  base58Encode,
  generateMessageId,
  messageIdToString,
} from './crypto/index.js';
import { encrypt, decrypt } from './crypto/encryption.js';
import {
  MessageType,
  encodeEnvelope,
  decodeEnvelope,
  createEnvelopes,
  reassembleChunks,
  hasAllChunks,
  type Envelope,
} from './codec/index.js';
import {
  SQLiteAdapter,
  type StorageAdapter,
  type StoredMessage,
} from './storage/index.js';
import type {
  MessagingClientConfig,
  SendMessageOptions,
  GetMessagesOptions,
  Message,
  MessageHandler,
} from './types.js';

/**
 * Main client for X1 E2E encrypted messaging (Solana-compatible)
 */
export class MessagingClient {
  private privateKey: Uint8Array;      // ed25519 seed
  private publicKey: Uint8Array;       // ed25519 public key (for address)
  private x25519PublicKey: Uint8Array; // X25519 public key (for key exchange)
  private address: string;             // Solana-style base58 address
  private storage: StorageAdapter;
  private sessionKeys: Map<string, Uint8Array> = new Map();
  private pendingChunks: Map<string, Envelope[]> = new Map();
  private messageHandlers: Set<MessageHandler> = new Set();
  private unsubscribe: (() => void) | null = null;

  constructor(config: MessagingClientConfig) {
    // Derive messaging keypair from wallet private key
    const keyPair = deriveMessagingKeyPair(config.privateKey);
    this.privateKey = keyPair.privateKey;
    this.publicKey = keyPair.publicKey;
    this.x25519PublicKey = getX25519PublicKey(this.privateKey);
    this.address = publicKeyToAddress(this.publicKey);

    // Initialize storage
    this.storage = config.storage ?? new SQLiteAdapter(config.dbPath ?? ':memory:');
  }

  /**
   * Get this client's wallet address (Solana-style base58)
   */
  getAddress(): string {
    return this.address;
  }

  /**
   * Get this client's ed25519 public key (32 bytes)
   */
  getPublicKey(): Uint8Array {
    return this.publicKey;
  }

  /**
   * Get public key as base58 string (same as address for Solana)
   */
  getPublicKeyBase58(): string {
    return base58Encode(this.publicKey);
  }

  /**
   * Get X25519 public key for key exchange (32 bytes)
   * Share this with peers for establishing encrypted sessions
   */
  getX25519PublicKey(): Uint8Array {
    return this.x25519PublicKey;
  }

  /**
   * Get X25519 public key as base58 string
   */
  getX25519PublicKeyBase58(): string {
    return base58Encode(this.x25519PublicKey);
  }

  /**
   * Send an encrypted message to another wallet
   */
  async sendMessage(options: SendMessageOptions): Promise<string> {
    const { to, content, recipientPublicKey } = options;

    // Get or compute session key
    const sessionKey = await this.getOrCreateSessionKey(to, recipientPublicKey);

    // Convert content to bytes
    const contentBytes = typeof content === 'string'
      ? new TextEncoder().encode(content)
      : content;

    // Generate message ID
    const messageId = generateMessageId();

    // Encrypt the content (nonce is generated internally)
    const { nonce, ciphertext } = encrypt(sessionKey, contentBytes);

    // Create envelopes (handles chunking if needed)
    const envelopes = createEnvelopes(
      MessageType.MESSAGE,
      nonce,
      ciphertext,
      messageId
    );

    // Send each envelope
    for (const envelope of envelopes) {
      const payload = encodeEnvelope(envelope);

      await this.storage.sendMessage({
        id: `${messageIdToString(messageId)}-${envelope.header.chunkIndex}`,
        sender: this.address,
        recipient: to,
        payload,
      });
    }

    return messageIdToString(messageId);
  }

  /**
   * Get messages from inbox
   */
  async getMessages(options: GetMessagesOptions = {}): Promise<Message[]> {
    const storedMessages = await this.storage.getMessages({
      recipient: this.address,
      sender: options.from,
      since: options.since,
      before: options.before,
      limit: options.limit,
      order: 'desc',
    });

    // Group by message ID and reassemble
    const messageGroups = new Map<string, StoredMessage[]>();
    for (const stored of storedMessages) {
      try {
        const envelope = decodeEnvelope(stored.payload);
        const msgId = messageIdToString(envelope.header.messageId);

        if (!messageGroups.has(msgId)) {
          messageGroups.set(msgId, []);
        }
        messageGroups.get(msgId)!.push(stored);
      } catch {
        // Skip invalid messages
        continue;
      }
    }

    // Decrypt complete messages
    const messages: Message[] = [];
    for (const [msgId, storedList] of messageGroups) {
      try {
        const envelopes = storedList.map((s) => decodeEnvelope(s.payload));

        if (!hasAllChunks(envelopes, msgId)) {
          continue; // Skip incomplete messages
        }

        const firstStored = storedList[0];
        const message = await this.decryptMessage(
          envelopes,
          firstStored.sender,
          firstStored.createdAt
        );

        if (message) {
          messages.push(message);
        }
      } catch {
        // Skip messages that fail to decrypt
        continue;
      }
    }

    return messages;
  }

  /**
   * Watch for new messages (real-time)
   */
  onMessage(handler: MessageHandler): () => void {
    this.messageHandlers.add(handler);

    // Start watching if not already
    if (!this.unsubscribe) {
      this.unsubscribe = this.storage.watchInbox(
        this.address,
        this.handleIncomingMessage.bind(this)
      );
    }

    // Return unsubscribe function
    return () => {
      this.messageHandlers.delete(handler);
      if (this.messageHandlers.size === 0 && this.unsubscribe) {
        this.unsubscribe();
        this.unsubscribe = null;
      }
    };
  }

  /**
   * Register a peer's X25519 public key for direct communication
   * @param address - Peer's Solana address (base58)
   * @param x25519PublicKey - Peer's X25519 public key for key exchange (32 bytes)
   */
  registerPeer(address: string, x25519PublicKey: Uint8Array): void {
    const sessionKey = computeSharedSecret(this.privateKey, x25519PublicKey);
    this.sessionKeys.set(address, sessionKey);
  }

  /**
   * Close the client and release resources
   */
  async close(): Promise<void> {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
    await this.storage.close();
  }

  /**
   * Get or create a session key for a recipient
   */
  private async getOrCreateSessionKey(
    recipientAddress: string,
    recipientX25519PublicKey?: Uint8Array
  ): Promise<Uint8Array> {
    // Check if we already have a session key
    // Solana addresses are case-sensitive (base58)
    const existing = this.sessionKeys.get(recipientAddress);
    if (existing) {
      return existing;
    }

    // If recipient X25519 public key provided, compute session key
    if (recipientX25519PublicKey) {
      const sessionKey = computeSharedSecret(this.privateKey, recipientX25519PublicKey);
      this.sessionKeys.set(recipientAddress, sessionKey);
      return sessionKey;
    }

    // Without recipient's X25519 public key, we can't establish a session
    throw new Error(
      `No session key for ${recipientAddress}. ` +
      `Call registerPeer() with their X25519 public key first, ` +
      `or provide recipientPublicKey in sendMessage().`
    );
  }

  /**
   * Handle an incoming stored message
   */
  private async handleIncomingMessage(stored: StoredMessage): Promise<void> {
    try {
      const envelope = decodeEnvelope(stored.payload);
      const msgId = messageIdToString(envelope.header.messageId);

      // Handle single-chunk messages directly
      if (envelope.header.chunkTotal === 1) {
        const message = await this.decryptMessage(
          [envelope],
          stored.sender,
          stored.createdAt
        );
        if (message) {
          this.notifyHandlers(message);
        }
        return;
      }

      // Multi-chunk message: add to pending and check if complete
      if (!this.pendingChunks.has(msgId)) {
        this.pendingChunks.set(msgId, []);
      }
      this.pendingChunks.get(msgId)!.push(envelope);

      if (hasAllChunks(this.pendingChunks.get(msgId)!, msgId)) {
        const envelopes = this.pendingChunks.get(msgId)!;
        this.pendingChunks.delete(msgId);

        const message = await this.decryptMessage(
          envelopes,
          stored.sender,
          stored.createdAt
        );
        if (message) {
          this.notifyHandlers(message);
        }
      }
    } catch (error) {
      console.error('Failed to process incoming message:', error);
    }
  }

  /**
   * Decrypt a message from envelopes
   */
  private async decryptMessage(
    envelopes: Envelope[],
    sender: string,
    timestamp: number
  ): Promise<Message | null> {
    try {
      // Reassemble chunks
      const ciphertext = reassembleChunks(envelopes);

      // Get session key for sender (Solana addresses are case-sensitive)
      const sessionKey = this.sessionKeys.get(sender);
      if (!sessionKey) {
        console.warn(`No session key for sender: ${sender}`);
        return null;
      }

      // Get nonce from first envelope
      const nonce = envelopes[0].header.nonce;

      // Decrypt
      const contentBytes = decrypt(sessionKey, nonce, ciphertext);
      const content = new TextDecoder().decode(contentBytes);

      return {
        id: messageIdToString(envelopes[0].header.messageId),
        from: sender,
        to: this.address,
        content,
        contentBytes,
        timestamp,
      };
    } catch (error) {
      console.error('Failed to decrypt message:', error);
      return null;
    }
  }

  /**
   * Notify all message handlers
   */
  private notifyHandlers(message: Message): void {
    for (const handler of this.messageHandlers) {
      try {
        handler(message);
      } catch (error) {
        console.error('Error in message handler:', error);
      }
    }
  }
}
