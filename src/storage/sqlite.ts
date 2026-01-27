import Database from 'better-sqlite3';
import type {
  StorageAdapter,
  StoredMessage,
  GetMessagesOptions,
  MessageCallback,
  Unsubscribe,
} from './adapter.js';

/**
 * SQLite storage adapter for prototype/development
 */
export class SQLiteAdapter implements StorageAdapter {
  private db: Database.Database;
  private watchers: Map<string, Set<MessageCallback>> = new Map();
  private pollInterval: NodeJS.Timeout | null = null;
  private lastPollTime: Map<string, number> = new Map();

  constructor(dbPath: string = ':memory:') {
    this.db = new Database(dbPath);
    this.initialize();
  }

  private initialize(): void {
    // Create messages table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        id          TEXT PRIMARY KEY,
        sender      TEXT NOT NULL,
        recipient   TEXT NOT NULL,
        payload     BLOB NOT NULL,
        created_at  INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_recipient_time
        ON messages (recipient, created_at);

      CREATE INDEX IF NOT EXISTS idx_sender_time
        ON messages (sender, created_at);
    `);
  }

  async sendMessage(
    message: Omit<StoredMessage, 'createdAt'>
  ): Promise<StoredMessage> {
    const createdAt = Date.now();

    const stmt = this.db.prepare(`
      INSERT INTO messages (id, sender, recipient, payload, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(
      message.id,
      message.sender,
      message.recipient,
      Buffer.from(message.payload),
      createdAt
    );

    const storedMessage: StoredMessage = {
      ...message,
      createdAt,
    };

    // Notify watchers
    this.notifyWatchers(message.recipient, storedMessage);

    return storedMessage;
  }

  async getMessages(options: GetMessagesOptions = {}): Promise<StoredMessage[]> {
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (options.recipient) {
      conditions.push('recipient = ?');
      params.push(options.recipient);
    }

    if (options.sender) {
      conditions.push('sender = ?');
      params.push(options.sender);
    }

    if (options.since !== undefined) {
      conditions.push('created_at > ?');
      params.push(options.since);
    }

    if (options.before !== undefined) {
      conditions.push('created_at < ?');
      params.push(options.before);
    }

    const whereClause = conditions.length > 0
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const orderClause = `ORDER BY created_at ${options.order === 'asc' ? 'ASC' : 'DESC'}`;
    const limitClause = options.limit ? `LIMIT ${options.limit}` : '';

    const query = `
      SELECT id, sender, recipient, payload, created_at
      FROM messages
      ${whereClause}
      ${orderClause}
      ${limitClause}
    `;

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as {
      id: string;
      sender: string;
      recipient: string;
      payload: Buffer;
      created_at: number;
    }[];

    return rows.map((row) => ({
      id: row.id,
      sender: row.sender,
      recipient: row.recipient,
      payload: new Uint8Array(row.payload),
      createdAt: row.created_at,
    }));
  }

  async getMessage(id: string): Promise<StoredMessage | null> {
    const stmt = this.db.prepare(`
      SELECT id, sender, recipient, payload, created_at
      FROM messages
      WHERE id = ?
    `);

    const row = stmt.get(id) as {
      id: string;
      sender: string;
      recipient: string;
      payload: Buffer;
      created_at: number;
    } | undefined;

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      sender: row.sender,
      recipient: row.recipient,
      payload: new Uint8Array(row.payload),
      createdAt: row.created_at,
    };
  }

  watchInbox(recipient: string, callback: MessageCallback): Unsubscribe {
    // Add callback to watchers
    if (!this.watchers.has(recipient)) {
      this.watchers.set(recipient, new Set());
    }
    this.watchers.get(recipient)!.add(callback);

    // Initialize last poll time for this recipient
    if (!this.lastPollTime.has(recipient)) {
      this.lastPollTime.set(recipient, Date.now());
    }

    // Start polling if not already running
    this.startPolling();

    // Return unsubscribe function
    return () => {
      const callbacks = this.watchers.get(recipient);
      if (callbacks) {
        callbacks.delete(callback);
        if (callbacks.size === 0) {
          this.watchers.delete(recipient);
          this.lastPollTime.delete(recipient);
        }
      }

      // Stop polling if no more watchers
      if (this.watchers.size === 0) {
        this.stopPolling();
      }
    };
  }

  async deleteMessage(id: string): Promise<boolean> {
    const stmt = this.db.prepare('DELETE FROM messages WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  async close(): Promise<void> {
    this.stopPolling();
    this.db.close();
  }

  private notifyWatchers(recipient: string, message: StoredMessage): void {
    const callbacks = this.watchers.get(recipient);
    if (callbacks) {
      for (const callback of callbacks) {
        try {
          callback(message);
        } catch (error) {
          console.error('Error in message watcher callback:', error);
        }
      }
    }
  }

  private startPolling(): void {
    if (this.pollInterval) {
      return;
    }

    // Poll every 100ms for new messages
    this.pollInterval = setInterval(() => {
      this.pollForNewMessages();
    }, 100);
  }

  private stopPolling(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  private pollForNewMessages(): void {
    for (const [recipient, callbacks] of this.watchers) {
      const since = this.lastPollTime.get(recipient) ?? Date.now();

      const stmt = this.db.prepare(`
        SELECT id, sender, recipient, payload, created_at
        FROM messages
        WHERE recipient = ? AND created_at > ?
        ORDER BY created_at ASC
      `);

      const rows = stmt.all(recipient, since) as {
        id: string;
        sender: string;
        recipient: string;
        payload: Buffer;
        created_at: number;
      }[];

      for (const row of rows) {
        const message: StoredMessage = {
          id: row.id,
          sender: row.sender,
          recipient: row.recipient,
          payload: new Uint8Array(row.payload),
          createdAt: row.created_at,
        };

        for (const callback of callbacks) {
          try {
            callback(message);
          } catch (error) {
            console.error('Error in message watcher callback:', error);
          }
        }

        // Update last poll time
        this.lastPollTime.set(recipient, row.created_at);
      }
    }
  }
}
