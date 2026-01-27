/**
 * Stored message record
 */
export interface StoredMessage {
  id: string;           // Unique message ID (uuid or hex)
  sender: string;       // Sender wallet address
  recipient: string;    // Recipient wallet address
  payload: Uint8Array;  // Encrypted envelope (binary)
  createdAt: number;    // Unix timestamp in milliseconds
}

/**
 * Query options for retrieving messages
 */
export interface GetMessagesOptions {
  /** Filter by recipient address */
  recipient?: string;
  /** Filter by sender address */
  sender?: string;
  /** Get messages after this timestamp (ms) */
  since?: number;
  /** Get messages before this timestamp (ms) */
  before?: number;
  /** Maximum number of messages to return */
  limit?: number;
  /** Order by timestamp ('asc' or 'desc') */
  order?: 'asc' | 'desc';
}

/**
 * Callback for watching inbox
 */
export type MessageCallback = (message: StoredMessage) => void;

/**
 * Unsubscribe function returned by watch methods
 */
export type Unsubscribe = () => void;

/**
 * Abstract storage adapter interface.
 * Implementations can use SQLite, blockchain, or any other backend.
 */
export interface StorageAdapter {
  /**
   * Store a message
   */
  sendMessage(message: Omit<StoredMessage, 'createdAt'>): Promise<StoredMessage>;

  /**
   * Retrieve messages matching the query
   */
  getMessages(options?: GetMessagesOptions): Promise<StoredMessage[]>;

  /**
   * Get a single message by ID
   */
  getMessage(id: string): Promise<StoredMessage | null>;

  /**
   * Watch for new messages to a recipient
   * Returns an unsubscribe function
   */
  watchInbox(recipient: string, callback: MessageCallback): Unsubscribe;

  /**
   * Delete a message by ID (for cleanup)
   */
  deleteMessage(id: string): Promise<boolean>;

  /**
   * Close the storage connection
   */
  close(): Promise<void>;
}
