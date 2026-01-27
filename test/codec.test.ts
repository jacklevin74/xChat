import { describe, it, expect } from 'vitest';
import {
  PROTOCOL_VERSION,
  MessageType,
  MAX_PAYLOAD_SIZE,
  HEADER_SIZE,
  encodeEnvelope,
  decodeEnvelope,
  createEnvelopes,
  reassembleChunks,
  hasAllChunks,
  type Envelope,
} from '../src/codec/index.js';
import { secureRandomBytes, generateMessageId, messageIdToString, bytesToHex } from '../src/crypto/index.js';

describe('Envelope Codec', () => {
  const createTestEnvelope = (payloadSize: number = 100): Envelope => ({
    header: {
      version: PROTOCOL_VERSION,
      type: MessageType.MESSAGE,
      nonce: secureRandomBytes(12),
      messageId: generateMessageId(),
      chunkIndex: 0,
      chunkTotal: 1,
    },
    payload: secureRandomBytes(payloadSize),
  });

  describe('encodeEnvelope / decodeEnvelope', () => {
    it('should encode and decode an envelope correctly', () => {
      const original = createTestEnvelope();

      const encoded = encodeEnvelope(original);
      expect(encoded.length).toBe(HEADER_SIZE + original.payload.length);

      const decoded = decodeEnvelope(encoded);

      expect(decoded.header.version).toBe(original.header.version);
      expect(decoded.header.type).toBe(original.header.type);
      expect(bytesToHex(decoded.header.nonce)).toBe(bytesToHex(original.header.nonce));
      expect(bytesToHex(decoded.header.messageId)).toBe(bytesToHex(original.header.messageId));
      expect(decoded.header.chunkIndex).toBe(original.header.chunkIndex);
      expect(decoded.header.chunkTotal).toBe(original.header.chunkTotal);
      expect(bytesToHex(decoded.payload)).toBe(bytesToHex(original.payload));
    });

    it('should handle all message types', () => {
      for (const type of [MessageType.HANDSHAKE, MessageType.MESSAGE, MessageType.ACK, MessageType.KEY_ROTATE]) {
        const envelope: Envelope = {
          header: {
            version: PROTOCOL_VERSION,
            type,
            nonce: secureRandomBytes(12),
            messageId: generateMessageId(),
            chunkIndex: 0,
            chunkTotal: 1,
          },
          payload: new Uint8Array([1, 2, 3]),
        };

        const encoded = encodeEnvelope(envelope);
        const decoded = decodeEnvelope(encoded);

        expect(decoded.header.type).toBe(type);
      }
    });

    it('should handle chunk indices correctly', () => {
      const envelope: Envelope = {
        header: {
          version: PROTOCOL_VERSION,
          type: MessageType.MESSAGE,
          nonce: secureRandomBytes(12),
          messageId: generateMessageId(),
          chunkIndex: 1234,
          chunkTotal: 5678,
        },
        payload: new Uint8Array([1, 2, 3]),
      };

      const encoded = encodeEnvelope(envelope);
      const decoded = decodeEnvelope(encoded);

      expect(decoded.header.chunkIndex).toBe(1234);
      expect(decoded.header.chunkTotal).toBe(5678);
    });

    it('should handle empty payload', () => {
      const envelope = createTestEnvelope(0);
      const encoded = encodeEnvelope(envelope);
      const decoded = decodeEnvelope(encoded);

      expect(decoded.payload.length).toBe(0);
    });

    it('should throw on payload too large', () => {
      const envelope = createTestEnvelope(MAX_PAYLOAD_SIZE + 1);

      expect(() => encodeEnvelope(envelope)).toThrow('Payload too large');
    });

    it('should throw on invalid nonce length', () => {
      const envelope = createTestEnvelope();
      envelope.header.nonce = new Uint8Array(10); // Wrong length

      expect(() => encodeEnvelope(envelope)).toThrow('Invalid nonce length');
    });

    it('should throw on data too short', () => {
      const shortData = new Uint8Array(10);

      expect(() => decodeEnvelope(shortData)).toThrow('Data too short');
    });

    it('should throw on unsupported protocol version', () => {
      const envelope = createTestEnvelope();
      const encoded = encodeEnvelope(envelope);
      encoded[0] = 0x99; // Invalid version

      expect(() => decodeEnvelope(encoded)).toThrow('Unsupported protocol version');
    });

    it('should throw on invalid message type', () => {
      const envelope = createTestEnvelope();
      const encoded = encodeEnvelope(envelope);
      encoded[1] = 0x99; // Invalid type

      expect(() => decodeEnvelope(encoded)).toThrow('Invalid message type');
    });
  });

  describe('createEnvelopes (chunking)', () => {
    it('should create single envelope for small payload', () => {
      const payload = secureRandomBytes(100);
      const nonce = secureRandomBytes(12);

      const envelopes = createEnvelopes(MessageType.MESSAGE, nonce, payload);

      expect(envelopes.length).toBe(1);
      expect(envelopes[0].header.chunkIndex).toBe(0);
      expect(envelopes[0].header.chunkTotal).toBe(1);
      expect(bytesToHex(envelopes[0].payload)).toBe(bytesToHex(payload));
    });

    it('should split large payload into multiple envelopes', () => {
      const payload = secureRandomBytes(500); // > MAX_PAYLOAD_SIZE (230)
      const nonce = secureRandomBytes(12);

      const envelopes = createEnvelopes(MessageType.MESSAGE, nonce, payload);

      expect(envelopes.length).toBe(3); // 500 / 230 = 3 chunks (230 + 230 + 40)

      // All should have same message ID and nonce
      const msgId = messageIdToString(envelopes[0].header.messageId);
      for (const env of envelopes) {
        expect(messageIdToString(env.header.messageId)).toBe(msgId);
        expect(bytesToHex(env.header.nonce)).toBe(bytesToHex(nonce));
        expect(env.header.chunkTotal).toBe(3);
      }

      // Check chunk indices
      expect(envelopes[0].header.chunkIndex).toBe(0);
      expect(envelopes[1].header.chunkIndex).toBe(1);
      expect(envelopes[2].header.chunkIndex).toBe(2);
    });

    it('should handle empty payload', () => {
      const payload = new Uint8Array(0);
      const nonce = secureRandomBytes(12);

      const envelopes = createEnvelopes(MessageType.MESSAGE, nonce, payload);

      expect(envelopes.length).toBe(1);
      expect(envelopes[0].payload.length).toBe(0);
    });

    it('should use provided message ID', () => {
      const payload = secureRandomBytes(100);
      const nonce = secureRandomBytes(12);
      const customId = generateMessageId();

      const envelopes = createEnvelopes(MessageType.MESSAGE, nonce, payload, customId);

      expect(bytesToHex(envelopes[0].header.messageId)).toBe(bytesToHex(customId));
    });
  });

  describe('reassembleChunks', () => {
    it('should reassemble single chunk', () => {
      const originalPayload = secureRandomBytes(100);
      const nonce = secureRandomBytes(12);
      const envelopes = createEnvelopes(MessageType.MESSAGE, nonce, originalPayload);

      const reassembled = reassembleChunks(envelopes);

      expect(bytesToHex(reassembled)).toBe(bytesToHex(originalPayload));
    });

    it('should reassemble multiple chunks', () => {
      const originalPayload = secureRandomBytes(500);
      const nonce = secureRandomBytes(12);
      const envelopes = createEnvelopes(MessageType.MESSAGE, nonce, originalPayload);

      const reassembled = reassembleChunks(envelopes);

      expect(bytesToHex(reassembled)).toBe(bytesToHex(originalPayload));
    });

    it('should handle out-of-order chunks', () => {
      const originalPayload = secureRandomBytes(500);
      const nonce = secureRandomBytes(12);
      const envelopes = createEnvelopes(MessageType.MESSAGE, nonce, originalPayload);

      // Shuffle chunks
      const shuffled = [envelopes[2], envelopes[0], envelopes[1]];

      const reassembled = reassembleChunks(shuffled);

      expect(bytesToHex(reassembled)).toBe(bytesToHex(originalPayload));
    });

    it('should throw on empty array', () => {
      expect(() => reassembleChunks([])).toThrow('No envelopes');
    });

    it('should throw on mismatched message IDs', () => {
      const envelopes1 = createEnvelopes(
        MessageType.MESSAGE,
        secureRandomBytes(12),
        secureRandomBytes(100)
      );
      const envelopes2 = createEnvelopes(
        MessageType.MESSAGE,
        secureRandomBytes(12),
        secureRandomBytes(100)
      );

      expect(() => reassembleChunks([envelopes1[0], envelopes2[0]]))
        .toThrow('Mismatched message IDs');
    });

    it('should throw on missing chunks', () => {
      const originalPayload = secureRandomBytes(500);
      const nonce = secureRandomBytes(12);
      const envelopes = createEnvelopes(MessageType.MESSAGE, nonce, originalPayload);

      // Remove middle chunk
      const incomplete = [envelopes[0], envelopes[2]];

      expect(() => reassembleChunks(incomplete)).toThrow('Missing chunks');
    });
  });

  describe('hasAllChunks', () => {
    it('should return true when all chunks present', () => {
      const envelopes = createEnvelopes(
        MessageType.MESSAGE,
        secureRandomBytes(12),
        secureRandomBytes(500)
      );
      const msgId = messageIdToString(envelopes[0].header.messageId);

      expect(hasAllChunks(envelopes, msgId)).toBe(true);
    });

    it('should return false when chunks missing', () => {
      const envelopes = createEnvelopes(
        MessageType.MESSAGE,
        secureRandomBytes(12),
        secureRandomBytes(500)
      );
      const msgId = messageIdToString(envelopes[0].header.messageId);

      // Remove one chunk
      const incomplete = envelopes.slice(0, -1);

      expect(hasAllChunks(incomplete, msgId)).toBe(false);
    });

    it('should return false for wrong message ID', () => {
      const envelopes = createEnvelopes(
        MessageType.MESSAGE,
        secureRandomBytes(12),
        secureRandomBytes(100)
      );

      expect(hasAllChunks(envelopes, 'wrongid1234567')).toBe(false);
    });

    it('should return false for empty array', () => {
      expect(hasAllChunks([], 'someid')).toBe(false);
    });
  });
});
