/**
 * Protocol version
 */
export const PROTOCOL_VERSION = 0x01;

/**
 * Message types
 */
export enum MessageType {
  HANDSHAKE = 0x01,   // Initial key exchange / session request
  MESSAGE = 0x02,     // Encrypted message chunk
  ACK = 0x03,         // Message receipt acknowledgment
  KEY_ROTATE = 0x04,  // Session key rotation signal
}

/**
 * Maximum payload size in a single envelope (~230 bytes)
 * Total envelope: 256 bytes
 * Header: version(1) + type(1) + nonce(12) + msgId(8) + chunkIndex(2) + chunkTotal(2) = 26 bytes
 * Payload: 256 - 26 = 230 bytes
 */
export const MAX_PAYLOAD_SIZE = 230;

/**
 * Header size in bytes
 */
export const HEADER_SIZE = 26;

/**
 * Message envelope header
 */
export interface EnvelopeHeader {
  version: number;      // Protocol version (1 byte)
  type: MessageType;    // Message type (1 byte)
  nonce: Uint8Array;    // AES-GCM nonce (12 bytes)
  messageId: Uint8Array; // Unique message identifier (8 bytes)
  chunkIndex: number;   // Chunk number (2 bytes)
  chunkTotal: number;   // Total chunks (2 bytes)
}

/**
 * Complete message envelope
 */
export interface Envelope {
  header: EnvelopeHeader;
  payload: Uint8Array;  // Encrypted data or chunk (~230 bytes max)
}

/**
 * Decoded message (after decryption and reassembly)
 */
export interface DecodedMessage {
  messageId: string;
  type: MessageType;
  content: Uint8Array;
  timestamp?: number;
}

/**
 * Handshake payload structure
 */
export interface HandshakePayload {
  ephemeralPublicKey: Uint8Array;  // 33 bytes (compressed secp256k1)
  sessionMetadata?: Uint8Array;     // Optional encrypted metadata
}

/**
 * ACK payload structure
 */
export interface AckPayload {
  acknowledgedMessageId: Uint8Array;  // 8 bytes
  status: number;                      // 1 byte (0 = success, 1+ = error codes)
}
