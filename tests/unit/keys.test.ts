import { describe, it, expect, vi } from 'vitest';
import { createPublicKeySource, pinKey, staticKey, computeKeyThumbprint } from '../../src/keys.js';
import { createTestKeyring } from '../helpers/mint.js';

function mockFetchOk(body: unknown): typeof fetch {
  return vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;
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
    expect(fetchMock).toHaveBeenCalledTimes(1);
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
