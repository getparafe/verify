import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { SignJWT, type JWK } from 'jose';
import { createPublicKeySource, pinKey, staticKey, staticJwks, computeKeyThumbprint, type Jwks } from '../../src/keys.js';
import { verifyConsent } from '../../src/index.js';
import { createTestKeyring } from '../helpers/mint.js';

// A broker from before 2026-09-30: no JWKS (404), only /public-key.
function mockFetchOk(body: unknown): typeof fetch {
  return vi.fn(async (url: string) => String(url).endsWith('/.well-known/jwks.json')
    ? new Response('{"error":"not_found"}', { status: 404 })
    : new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;
}

describe('createPublicKeySource', () => {
  it('fetches /public-key and caches the result', async () => {
    const kr = await createTestKeyring();
    const fetchMock = mockFetchOk({
      public_key: kr.publicKeyBase64Der,
      algorithm: 'Ed25519',
      key_id: 'parafe-signing-key-v1',
    });
    const source = createPublicKeySource({ brokerUrl: 'https://fake.example', fetch: fetchMock });

    const r1 = await source.resolve();
    const r2 = await source.resolve();
    expect(r1).toBe(r2);
    expect(r1.keyId).toBe('parafe-signing-key-v1');
    expect(fetchMock).toHaveBeenCalledTimes(2); // JWKS (404), then /public-key; cached after
  });

  it('strips trailing slash from broker URL', async () => {
    const kr = await createTestKeyring();
    const fetchMock = mockFetchOk({
      public_key: kr.publicKeyBase64Der,
      algorithm: 'Ed25519',
      key_id: 'k1',
    });
    const source = createPublicKeySource({ brokerUrl: 'https://fake.example/', fetch: fetchMock });
    await source.resolve();
    expect(fetchMock).toHaveBeenCalledWith('https://fake.example/public-key');
  });

  it('throws KeyFetchError on non-200 response', async () => {
    const fetchMock = vi.fn(async () => new Response('nope', { status: 503 })) as unknown as typeof fetch;
    const source = createPublicKeySource({ brokerUrl: 'https://fake.example', fetch: fetchMock });
    await expect(source.resolve()).rejects.toMatchObject({ code: 'KEY_FETCH_FAILED' });
  });

  it('throws KeyFetchError when broker returns non-Ed25519 algorithm', async () => {
    const kr = await createTestKeyring();
    const fetchMock = mockFetchOk({
      public_key: kr.publicKeyBase64Der,
      algorithm: 'RSA',
      key_id: 'k1',
    });
    const source = createPublicKeySource({ brokerUrl: 'https://fake.example', fetch: fetchMock });
    await expect(source.resolve()).rejects.toMatchObject({ code: 'KEY_FETCH_FAILED' });
  });

  it('enforces key_id pin on resolve', async () => {
    const kr = await createTestKeyring();
    const fetchMock = mockFetchOk({
      public_key: kr.publicKeyBase64Der,
      algorithm: 'Ed25519',
      key_id: 'unexpected-id',
    });
    const source = createPublicKeySource({
      brokerUrl: 'https://fake.example',
      fetch: fetchMock,
      pin: { keyId: 'parafe-signing-key-v1' },
    });
    await expect(source.resolve()).rejects.toMatchObject({ code: 'KEY_PIN_MISMATCH' });
  });

  it('enforces SHA-256 thumbprint pin on resolve', async () => {
    const kr = await createTestKeyring();
    const fetchMock = mockFetchOk({
      public_key: kr.publicKeyBase64Der,
      algorithm: 'Ed25519',
      key_id: 'k1',
    });
    const goodPin = computeKeyThumbprint(kr.publicKeyBase64Der);
    const okSource = createPublicKeySource({
      brokerUrl: 'https://fake.example',
      fetch: fetchMock,
      pin: { thumbprintSha256: goodPin },
    });
    const resolved = await okSource.resolve();
    expect(resolved.thumbprintSha256).toBe(goodPin);

    const badSource = createPublicKeySource({
      brokerUrl: 'https://fake.example',
      fetch: mockFetchOk({
        public_key: kr.publicKeyBase64Der,
        algorithm: 'Ed25519',
        key_id: 'k1',
      }),
      pin: { thumbprintSha256: '0'.repeat(64) },
    });
    await expect(badSource.resolve()).rejects.toMatchObject({ code: 'KEY_PIN_MISMATCH' });
  });
});

describe('pinKey', () => {
  it('re-checks pinning on a pre-built source', async () => {
    const kr = await createTestKeyring('k-from-static');
    const source = staticKey(kr.publicKeyBase64Der, 'k-from-static');
    const pinned = pinKey(source, { keyId: 'wrong' });
    await expect(pinned.resolve()).rejects.toMatchObject({ code: 'KEY_PIN_MISMATCH' });

    const goodPinned = pinKey(source, { keyId: 'k-from-static' });
    const resolved = await goodPinned.resolve();
    expect(resolved.keyId).toBe('k-from-static');
  });

  it('layers on top of createPublicKeySource', async () => {
    const kr = await createTestKeyring();
    const fetchMock = mockFetchOk({
      public_key: kr.publicKeyBase64Der,
      algorithm: 'Ed25519',
      key_id: 'fetched-id',
    });
    const base = createPublicKeySource({ brokerUrl: 'https://fake.example', fetch: fetchMock });
    const pinned = pinKey(base, { keyId: 'unexpected' });
    await expect(pinned.resolve()).rejects.toMatchObject({ code: 'KEY_PIN_MISMATCH' });
  });
});

// S-66: a JWKS kid is the key's RFC 7638 thumbprint, and both pins apply to the JWKS keys.
describe('pinning the JWKS keys (S-66)', () => {
  const fx = JSON.parse(readFileSync(new URL('../fixtures/broker-v2-artifacts.json', import.meta.url), 'utf8'));
  const jwks = fx.jwks as Jwks;
  const now = new Date(fx.issued_at);
  const es256 = jwks.keys.find((k) => k.alg === 'ES256')!;
  const ed25519 = jwks.keys.find((k) => k.alg === 'EdDSA')!;
  const spkiPrint = (jwk: JWK) => computeKeyThumbprint(
    createPublicKey({ key: jwk as never, format: 'jwk' }).export({ type: 'spki', format: 'der' }).toString('base64'));
  const serve = (body: unknown) => vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;

  // An attacker's ES256 key under the broker's real kid, and a token it signed.
  const attacker = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const attackerJwk = { ...(attacker.publicKey.export({ format: 'jwk' }) as JWK), kid: es256.kid, alg: 'ES256', use: 'sig', status: 'active' };
  const substituted = { keys: [attackerJwk, ed25519] } as Jwks;
  const forge = () => new SignJWT({ token_type: 'consent', scope: 's', permissions: [], session_id: 's' })
    .setProtectedHeader({ alg: 'ES256', kid: es256.kid }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('1h')
    .sign(attacker.privateKey);

  it('the real JWKS loads: every kid is its key\'s thumbprint', async () => {
    expect((await staticJwks(jwks).resolveKeySet!()).map((k) => k.kid)).toEqual(jwks.keys.map((k) => k.kid));
    const forged = await forge();
    expect((await verifyConsent(forged, { key: staticJwks(jwks) })).error?.code).toBe('INVALID_SIGNATURE');
  });

  it('refuses a substituted JWKS that labels another key with a real kid, pinned or not', async () => {
    const forged = await forge();
    for (const pin of [undefined, { keyId: es256.kid }]) {
      const source = createPublicKeySource({ brokerUrl: 'https://broker.test', fetch: serve(substituted), ...(pin ? { pin } : {}) });
      await expect(source.resolveKeySet!()).rejects.toMatchObject({ code: 'KEY_FETCH_FAILED', message: expect.stringContaining('RFC 7638') });
      await expect(verifyConsent(forged, { key: source })).rejects.toMatchObject({ code: 'KEY_FETCH_FAILED' });
    }
    await expect(verifyConsent(forged, { key: staticJwks(substituted) })).rejects.toMatchObject({ code: 'KEY_FETCH_FAILED' });
    await expect(verifyConsent(forged, { key: pinKey(staticJwks(substituted), { keyId: es256.kid }) })).rejects.toMatchObject({ code: 'KEY_FETCH_FAILED' });
  });

  it('a thumbprint pin keeps only that key; another key\'s thumbprint is refused', async () => {
    const goodPin = spkiPrint(es256);
    const otherPin = spkiPrint(generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' }) as JWK);
    const sources = (thumbprintSha256: string) => [
      createPublicKeySource({ brokerUrl: 'https://broker.test', fetch: serve(jwks), pin: { thumbprintSha256 } }),
      pinKey(staticJwks(jwks), { thumbprintSha256 }),
    ];
    for (const source of sources(goodPin.toUpperCase())) {
      const set = await source.resolveKeySet!();
      expect(set.map((k) => k.kid)).toEqual([es256.kid]);
      expect(set[0]!.thumbprintSha256).toBe(goodPin);
      expect((await verifyConsent(fx.consent_token, { key: source, now })).valid).toBe(true);
      await expect(source.resolve()).rejects.toMatchObject({ code: 'KEY_PIN_MISMATCH' }); // the Ed25519 key isn't pinned
    }
    for (const source of sources(otherPin)) {
      await expect(source.resolveKeySet!()).rejects.toMatchObject({ code: 'KEY_PIN_MISMATCH' });
      await expect(verifyConsent(fx.consent_token, { key: source, now })).rejects.toMatchObject({ code: 'KEY_PIN_MISMATCH' });
    }
  });

  it('a thumbprint pin on the Ed25519 key keeps its meaning (hex SHA-256 of the base64 SPKI)', async () => {
    const edPin = spkiPrint(ed25519);
    const source = createPublicKeySource({ brokerUrl: 'https://broker.test', fetch: serve(jwks), pin: { thumbprintSha256: edPin } });
    expect((await source.resolve()).thumbprintSha256).toBe(edPin);
    expect((await source.resolveKeySet!()).map((k) => k.kid)).toEqual([ed25519.kid]);
    expect((await verifyConsent(fx.consent_token, { key: source, now })).error?.code).toBe('KEY_NOT_FOUND'); // ES256, not pinned
  });
});
