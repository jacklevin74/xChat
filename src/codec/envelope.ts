import {
  PROTOCOL_VERSION,
  MessageType,
  MAX_PAYLOAD_SIZE,
  HEADER_SIZE,
  type EnvelopeHeader,
  type Envelope,
} from './types.js';
import { NONCE_SIZE } from '../crypto/encryption.js';
import { concatBytes, generateMessageId, messageIdToString } from '../crypto/utils.js';

/**
 * Encode an envelope to binary format
 *
 * Binary layout (26 + payload bytes):
 * [0]      version     (1 byte)
 * [1]      type        (1 byte)
 * [2-13]   nonce       (12 bytes)
 * [14-21]  messageId   (8 bytes)
 * [22-23]  chunkIndex  (2 bytes, big-endian)
 * [24-25]  chunkTotal  (2 bytes, big-endian)
 * [26+]    payload     (variable, max ~230 bytes)
 */
export function encodeEnvelope(envelope: Envelope): Uint8Array {
  const { header, payload } = envelope;

  if (payload.length > MAX_PAYLOAD_SIZE) {
    throw new Error(`Payload too large: ${payload.length} > ${MAX_PAYLOAD_SIZE}`);
  }

  if (header.nonce.length !== NONCE_SIZE) {
    throw new Error(`Invalid nonce length: ${header.nonce.length} != ${NONCE_SIZE}`);
  }

  if (header.messageId.length !== 8) {
    throw new Error(`Invalid messageId length: ${header.messageId.length} != 8`);
  }

  const buffer = new Uint8Array(HEADER_SIZE + payload.length);

  // Write header
  buffer[0] = header.version;
  buffer[1] = header.type;
  buffer.set(header.nonce, 2);
  buffer.set(header.messageId, 14);

  // Write chunk info (big-endian)
  buffer[22] = (header.chunkIndex >> 8) & 0xff;
  buffer[23] = header.chunkIndex & 0xff;
  buffer[24] = (header.chunkTotal >> 8) & 0xff;
  buffer[25] = header.chunkTotal & 0xff;

  // Write payload
  buffer.set(payload, HEADER_SIZE);

  return buffer;
}

/**
 * Decode binary data to an envelope
 */
export function decodeEnvelope(data: Uint8Array): Envelope {
  if (data.length < HEADER_SIZE) {
    throw new Error(`Data too short: ${data.length} < ${HEADER_SIZE}`);
  }

  const version = data[0];
  if (version !== PROTOCOL_VERSION) {
    throw new Error(`Unsupported protocol version: ${version}`);
  }

  const type = data[1] as MessageType;
  if (!Object.values(MessageType).includes(type)) {
    throw new Error(`Invalid message type: ${type}`);
  }

  const nonce = data.slice(2, 14);
  const messageId = data.slice(14, 22);

  const chunkIndex = (data[22] << 8) | data[23];
  const chunkTotal = (data[24] << 8) | data[25];

  const payload = data.slice(HEADER_SIZE);

  return {
    header: {
      version,
      type,
      nonce,
      messageId,
      chunkIndex,
      chunkTotal,
    },
    payload,
  };
}

/**
 * Split a message into multiple envelopes if needed
 */
export function createEnvelopes(
  type: MessageType,
  nonce: Uint8Array,
  encryptedPayload: Uint8Array,
  messageId?: Uint8Array
): Envelope[] {
  const msgId = messageId ?? generateMessageId();
  const chunks = splitIntoChunks(encryptedPayload, MAX_PAYLOAD_SIZE);
  const totalChunks = chunks.length;

  return chunks.map((chunk, index) => ({
    header: {
      version: PROTOCOL_VERSION,
      type,
      nonce,
      messageId: msgId,
      chunkIndex: index,
      chunkTotal: totalChunks,
    },
    payload: chunk,
  }));
}

/**
 * Reassemble chunks into the original payload
 */
export function reassembleChunks(envelopes: Envelope[]): Uint8Array {
  if (envelopes.length === 0) {
    throw new Error('No envelopes to reassemble');
  }

  // Verify all envelopes have the same message ID
  const messageId = messageIdToString(envelopes[0].header.messageId);
  for (const env of envelopes) {
    if (messageIdToString(env.header.messageId) !== messageId) {
      throw new Error('Mismatched message IDs in chunk set');
    }
  }

  // Sort by chunk index
  const sorted = [...envelopes].sort(
    (a, b) => a.header.chunkIndex - b.header.chunkIndex
  );

  // Verify we have all chunks
  const expectedTotal = sorted[0].header.chunkTotal;
  if (sorted.length !== expectedTotal) {
    throw new Error(
      `Missing chunks: got ${sorted.length}, expected ${expectedTotal}`
    );
  }

  // Verify chunk indices are sequential
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i].header.chunkIndex !== i) {
      throw new Error(`Missing chunk at index ${i}`);
    }
  }

  // Concatenate payloads
  return concatBytes(...sorted.map((env) => env.payload));
}

/**
 * Split data into chunks of maxSize
 */
function splitIntoChunks(data: Uint8Array, maxSize: number): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += maxSize) {
    chunks.push(data.slice(i, Math.min(i + maxSize, data.length)));
  }
  // Handle empty data case
  if (chunks.length === 0) {
    chunks.push(new Uint8Array(0));
  }
  return chunks;
}

/**
 * Check if all chunks for a message have been received
 */
export function hasAllChunks(
  envelopes: Envelope[],
  messageId: string
): boolean {
  const matching = envelopes.filter(
    (env) => messageIdToString(env.header.messageId) === messageId
  );

  if (matching.length === 0) {
    return false;
  }

  const expectedTotal = matching[0].header.chunkTotal;
  if (matching.length !== expectedTotal) {
    return false;
  }

  // Check all indices are present
  const indices = new Set(matching.map((env) => env.header.chunkIndex));
  for (let i = 0; i < expectedTotal; i++) {
    if (!indices.has(i)) {
      return false;
    }
  }

  return true;
}
