import type { KeyLike, JWSHeaderParameters } from 'jose';
import { KeyNotFoundError } from '../errors.js';
import type { PublicKeySource } from '../keys.js';

/**
 * The broker key for a JWS protected header. Since 2026-09-30 every broker JWS
 * names its key (`kid`: a JWKS kid, or a DID URL whose fragment is one). A
 * header with no `kid` is older and was signed with the Ed25519 key.
 */
export async function brokerKeyFor(
  source: PublicKeySource,
  header: Pick<JWSHeaderParameters, 'kid' | 'alg'>
): Promise<{ key: KeyLike | Uint8Array; keyId: string }> {
  const kid = header.kid?.includes('#') ? header.kid.split('#').pop() : header.kid;
  if (kid && source.resolveKeySet) {
    const set = await source.resolveKeySet();
    const found = set.find((k) => k.kid === kid) ?? (set.length === 1 && !set[0]?.jwk.x ? set[0] : undefined);
    if (!found) throw new KeyNotFoundError(kid);
    if (header.alg && found.alg !== header.alg) throw new KeyNotFoundError(kid, `Key ${kid} is ${found.alg}, but the JWS says ${header.alg}`);
    return { key: found.josePublicKey, keyId: found.kid };
  }
  if (header.alg === 'EdDSA') {
    const legacy = await source.resolve();
    return { key: legacy.josePublicKey, keyId: legacy.keyId };
  }
  throw new KeyNotFoundError(kid ?? '(none)', kid
    ? `This key source can only verify Ed25519 artifacts; use createPublicKeySource() or staticJwks() for ${header.alg}`
    : 'Broker JWS has no kid');
}
