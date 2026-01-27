export {
  PROTOCOL_VERSION,
  MessageType,
  MAX_PAYLOAD_SIZE,
  HEADER_SIZE,
  type EnvelopeHeader,
  type Envelope,
  type DecodedMessage,
  type HandshakePayload,
  type AckPayload,
} from './types.js';

export {
  encodeEnvelope,
  decodeEnvelope,
  createEnvelopes,
  reassembleChunks,
  hasAllChunks,
} from './envelope.js';
