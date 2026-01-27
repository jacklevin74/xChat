import type { StorageAdapter } from './storage/adapter.js';

/**
 * Configuration for MessagingClient
 */
export interface MessagingClientConfig {
  /** Wallet private key (32 bytes hex string or Uint8Array) */
  privateKey: string | Uint8Array;
  /** Storage adapter instance (defaults to in-memory SQLite) */
  storage?: StorageAdapter;
  /** Database path for SQLite storage (ignored if storage is provided) */
  dbPath?: string;
}

/**
 * Options for sending a message
 */
export interface SendMessageOptions {
  /** Recipient wallet address */
  to: string;
  /** Message content (string or binary) */
  content: string | Uint8Array;
  /** Recipient's public messaging key (optional, derived from address if not provided) */
  recipientPublicKey?: Uint8Array;
}

/**
 * Options for retrieving messages
 */
export interface GetMessagesOptions {
  /** Filter by sender address */
  from?: string;
  /** Get messages after this timestamp (ms) */
  since?: number;
  /** Get messages before this timestamp (ms) */
  before?: number;
  /** Maximum number of messages to return */
  limit?: number;
}

/**
 * Decrypted message
 */
export interface Message {
  /** Unique message ID */
  id: string;
  /** Sender address */
  from: string;
  /** Recipient address */
  to: string;
  /** Decrypted message content */
  content: string;
  /** Raw content bytes */
  contentBytes: Uint8Array;
  /** Message timestamp (ms) */
  timestamp: number;
}

/**
 * Callback for incoming messages
 */
export type MessageHandler = (message: Message) => void;
