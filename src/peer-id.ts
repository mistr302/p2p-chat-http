import { base58btc } from 'multiformats/bases/base58';
import { identity } from 'multiformats/hashes/identity';
import { sha256 } from 'multiformats/hashes/sha2';

const MAX_INLINE_KEY_LENGTH = 42;

export async function peerIdFromPublicKey(protobufPublicKey: Uint8Array): Promise<string> {
  const digest =
    protobufPublicKey.length <= MAX_INLINE_KEY_LENGTH
      ? await identity.digest(protobufPublicKey)
      : await sha256.digest(protobufPublicKey);

  return base58btc.baseEncode(digest.bytes);
}
