export {
  DOMAIN_SEPARATOR,
  secureRandomBytes,
  concatBytes,
  hexToBytes,
  bytesToHex,
  base58Encode,
  base58Decode,
  generateMessageId,
  messageIdToString,
  stringToMessageId,
} from './utils.js';

export {
  type MessagingKeyPair,
  deriveMessagingKeyPair,
  computeSharedSecret,
  getPublicKeyFromPrivate,
  getX25519PublicKey,
  isValidPublicKey,
  isValidX25519PublicKey,
  publicKeyToAddress,
  addressToPublicKey,
  sign,
  verify,
} from './keys.js';

export {
  NONCE_SIZE,
  TAG_SIZE,
  type EncryptedData,
  encrypt,
  decrypt,
  encryptToBuffer,
  decryptFromBuffer,
} from './encryption.js';
