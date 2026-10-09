import { describe, it, expect } from 'vitest';
import { verifyCredential, verifyConsent } from '../../src/verify.js';
import { verifyCredentialJWT, verifyConsentJWT } from '../../src/jwt-verify.js';
import { createTestKeyring, mintCredential, mintConsent } from '../helpers/mint.js';
import { staticKey } from '../../src/keys.js';

describe('verifyCredentialJWT', () => {
  it('verifies a valid credential', async () => {
    const kr = await createTestKeyring();
    const jwt = await mintCredential({ privateKey: kr.joseSigningKey, sub: 'prf_agent_x' });
    const result = await verifyCredentialJWT(jwt, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('jwt');
    expect(result.keyId).toBe(kr.esKeyId);
    expect(result.claims?.sub).toBe('prf_agent_x');
    expect(result.error).toBeUndefined();
  });

  it('rejects a tampered signature', async () => {
    const kr = await createTestKeyring();
    const jwt = await mintCredential({ privateKey: kr.joseSigningKey });
    // Flip a bit in the signature (last base64 segment)
    const parts = jwt.split('.');
    const sig = parts[2] as string;
    const tampered = [parts[0], parts[1], sig.slice(0, -4) + (sig.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA')].join('.');
    const result = await verifyCredentialJWT(tampered, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('INVALID_SIGNATURE');
  });

  it('verifies a credential issued before SPEC-002 (owner, no principal_name)', async () => {
    const kr = await createTestKeyring();
    const jwt = await mintCredential({ privateKey: kr.joseSigningKey, omit: ['principal_name'], extra: { owner: 'Old Org' } });
    const result = await verifyCredentialJWT(jwt, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.claims?.owner).toBe('Old Org');
  });

  it('verifies a credential with neither name claim (the free-text name is not required)', async () => {
    const kr = await createTestKeyring();
    const jwt = await mintCredential({ privateKey: kr.joseSigningKey, omit: ['principal_name'] });
    expect((await verifyCredentialJWT(jwt, { key: kr.keySource })).valid).toBe(true);
  });

  it('rejects an expired credential', async () => {
    const kr = await createTestKeyring();
    const now = Math.floor(Date.now() / 1000);
    const jwt = await mintCredential({ privateKey: kr.joseSigningKey, iat: now - 7200, exp: now - 3600 });
    const result = await verifyCredentialJWT(jwt, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('EXPIRED');
  });

  it('rejects wrong issuer', async () => {
    const kr = await createTestKeyring();
    const jwt = await mintCredential({ privateKey: kr.joseSigningKey, iss: 'evil-issuer' });
    const result = await verifyCredentialJWT(jwt, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('ISSUER_MISMATCH');
  });

  it('rejects signature from a different key', async () => {
    const signerKr = await createTestKeyring();
    const verifierKr = await createTestKeyring();
    const jwt = await mintCredential({ privateKey: signerKr.joseSigningKey });
    const result = await verifyCredentialJWT(jwt, { key: verifierKr.keySource });
    expect(result.valid).toBe(false);
    // Its kid isn't the verifier's key.
    expect(result.error?.code).toBe('KEY_NOT_FOUND');
  });

  it('refuses a token signed with the retired Ed25519 key (S-72), and a tampered one', async () => {
    const kr = await createTestKeyring();
    const { importPKCS8, SignJWT } = await import('jose');
    const edKey = await importPKCS8(kr.nodePrivateKey.export({ format: 'pem', type: 'pkcs8' }) as string, 'EdDSA');
    const old = await new SignJWT({ sub: 'prf_agent_old', name: 'Old', identity_assurance: 'registered', verification_tier: 'unverified', pub_key_thumbprint: 'a'.repeat(64) })
      .setProtectedHeader({ alg: 'EdDSA' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('1h').sign(edKey);
    const r = await verifyCredentialJWT(old, { key: kr.keySource });
    expect(r.valid).toBe(false);
    expect(r.error?.code).toBe('INVALID_SIGNATURE');
    expect(r.error?.message).toMatch(/retired Ed25519 key/);
    // The same key still checks v1 receipts.
    expect((await kr.keySource.resolve()).algorithm).toBe('Ed25519');
  });

  it('rejects a consent token passed to verifyCredential', async () => {
    const kr = await createTestKeyring();
    const token = await mintConsent({ privateKey: kr.joseSigningKey });
    const result = await verifyCredentialJWT(token, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('WRONG_ARTIFACT_TYPE');
  });
});

describe('verifyConsentJWT', () => {
  it('verifies a valid consent token', async () => {
    const kr = await createTestKeyring();
    const token = await mintConsent({
      privateKey: kr.joseSigningKey,
      scope: 'read_bookings',
      permissions: ['read:bookings', 'list:bookings'],
      session_id: 'sess_abc',
    });
    const result = await verifyConsentJWT(token, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.claims?.scope).toBe('read_bookings');
    expect(result.claims?.permissions).toEqual(['read:bookings', 'list:bookings']);
    expect(result.claims?.session_id).toBe('sess_abc');
    expect(result.claims?.token_type).toBe('consent');
  });

  it('rejects a credential passed to verifyConsent', async () => {
    const kr = await createTestKeyring();
    const credential = await mintCredential({ privateKey: kr.joseSigningKey });
    const result = await verifyConsentJWT(credential, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('WRONG_ARTIFACT_TYPE');
  });

  it('allows clock tolerance', async () => {
    const kr = await createTestKeyring();
    const now = Math.floor(Date.now() / 1000);
    // Expired 30s ago
    const token = await mintConsent({ privateKey: kr.joseSigningKey, iat: now - 3700, exp: now - 30 });
    const strict = await verifyConsentJWT(token, { key: kr.keySource });
    expect(strict.valid).toBe(false);
    const lenient = await verifyConsentJWT(token, { key: kr.keySource, clockToleranceSec: 120 });
    expect(lenient.valid).toBe(true);
  });
});

describe('verifyCredential (auto-detect)', () => {
  it('routes JWT strings to JWT verifier', async () => {
    const kr = await createTestKeyring();
    const jwt = await mintCredential({ privateKey: kr.joseSigningKey });
    const result = await verifyCredential(jwt, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('jwt');
  });

  it('returns FORMAT_UNKNOWN for garbage input', async () => {
    const kr = await createTestKeyring();
    const result = await verifyCredential('not-a-jwt', { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('FORMAT_UNKNOWN');
  });
});

describe('staticKey', () => {
  it('resolves without network', async () => {
    const kr = await createTestKeyring();
    const source = staticKey(kr.publicKeyBase64Der, 'custom-key-id');
    const resolved = await source.resolve();
    expect(resolved.keyId).toBe('custom-key-id');
    expect(resolved.algorithm).toBe('Ed25519');
    expect(resolved.rawBytes.length).toBe(32);
    expect(resolved.thumbprintSha256).toMatch(/^[0-9a-f]{64}$/);
  });
});
