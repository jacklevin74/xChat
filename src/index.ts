// Main client
export { MessagingClient } from './client.js';

// Types
export type {
  MessagingClientConfig,
  SendMessageOptions,
  GetMessagesOptions,
  Message,
  MessageHandler,
} from './types.js';

// Crypto utilities
export {
  deriveMessagingKeyPair,
  computeSharedSecret,
  publicKeyToAddress,
  addressToPublicKey,
  getX25519PublicKey,
  isValidPublicKey,
  isValidX25519PublicKey,
  sign,
  verify,
  hexToBytes,
  bytesToHex,
  base58Encode,
  base58Decode,
  type MessagingKeyPair,
} from './crypto/index.js';

// Codec types
export {
  MessageType,
  PROTOCOL_VERSION,
  type Envelope,
  type EnvelopeHeader,
} from './codec/index.js';

// Storage
export type {
  StorageAdapter,
  StoredMessage,
  GetMessagesOptions as StorageGetMessagesOptions,
} from './storage/index.js';
export { SQLiteAdapter } from './storage/index.js';
