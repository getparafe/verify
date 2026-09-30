/**
 * AP2 change request Phase 1 (verify 0.3.0). Fixtures in tests/fixtures/:
 * - production-v1-receipt-*.json: v1 receipts issued by api.parafe.ai (fictional
 *   SoHo Donuts demo data), signed by production's Ed25519 key.
 * - broker-v2-artifacts.json: artifacts from a local Phase 1 broker with its JWKS.
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { SignJWT, calculateJwkThumbprint, type JWK } from 'jose';
import {
  verifyReceipt, verifyCredential, verifyConsent, verifyPresentationProof, verifyIdentityCredential,
  matchAgentKey, staticKey, staticJwks, createPublicKeySource, type ConsentClaims, type ReceiptV2Payload,
} from '../../src/index.js';

const fx = JSON.parse(readFileSync(new URL('../fixtures/broker-v2-artifacts.json', import.meta.url), 'utf8'));
const PRODUCTION_ED25519 = 'MCowBQYDK2VwAyEAfO5+V104wZuSqkFJ0dLHeZf8eW3cnSpaS3oPXWdSEzQ=';
const now = new Date(fx.issued_at);
const key = staticJwks(fx.jwks);
const opts = { key, now };

describe('v1 receipts from production still verify', () => {
  for (const name of ['production-v1-receipt-rcpt_5ecddf49.json', 'production-v1-receipt-rcpt_e13da133.json']) {
    const receipt = JSON.parse(readFileSync(new URL(`../fixtures/${name}`, import.meta.url), 'utf8'));
    it(`${name} verifies with production's Ed25519 key; a tampered copy does not`, async () => {
      const ok = await verifyReceipt(receipt, { key: staticKey(PRODUCTION_ED25519) });
      expect(ok.valid).toBe(true);
      expect(ok.format).toBe('receipt');
      const bad = await verifyReceipt({ ...receipt, session_id: 'sess_tampered' }, { key: staticKey(PRODUCTION_ED25519) });
      expect(bad.valid).toBe(false);
    });
  }
});

describe('broker keys by kid (B10)', () => {
  it('verifies an ES256 credential and consent token against the JWKS', async () => {
    const cred = await verifyCredential(fx.credential_jwt, opts);
    expect(cred.valid).toBe(true);
    expect(cred.keyId).toBe(fx.jwks.keys.find((k: { status: string }) => k.status === 'active').kid);
  });

  it('fetches the JWKS from the broker (createPublicKeySource)', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(fx.jwks), { status: 200 })) as unknown as typeof fetch;
    const source = createPublicKeySource({ brokerUrl: 'https://broker.test', fetch: fetchMock });
    expect((await verifyConsent(fx.consent_token, { key: source, now })).valid).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith('https://broker.test/.well-known/jwks.json');
  });

  it('refetches the JWKS once when an artifact names a kid it does not have, rate-limited', async () => {
    const extra = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const extraJwk = { ...(extra.publicKey.export({ format: 'jwk' }) as JWK), kid: 'added-later', alg: 'ES256', status: 'active' };
    let calls = 0;
    const fetchMock = vi.fn(async () => {
      calls++;
      return new Response(JSON.stringify(calls === 1 ? fx.jwks : { keys: [...fx.jwks.keys, extraJwk] }), { status: 200 });
    }) as unknown as typeof fetch;
    const token = await new SignJWT({ token_type: 'consent', scope: 's', permissions: [], session_id: 's' })
      .setProtectedHeader({ alg: 'ES256', kid: 'added-later' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('1h').sign(extra.privateKey);
    const source = createPublicKeySource({ brokerUrl: 'https://broker.test', fetch: fetchMock, minRefetchIntervalMs: 0 });
    await source.resolve();
    expect((await verifyConsent(token, { key: source })).valid).toBe(true);
    expect(calls).toBe(2);
    calls = 0;
    const limited = createPublicKeySource({ brokerUrl: 'https://broker.test', fetch: fetchMock });
    await limited.resolve();
    expect((await verifyConsent(token, { key: limited })).error?.code).toBe('KEY_NOT_FOUND');
    expect(calls).toBe(1);
  });

  it('an Ed25519-only key source reports KEY_NOT_FOUND for an ES256 artifact; an unknown kid too', async () => {
    const r = await verifyConsent(fx.consent_token, { key: staticKey(PRODUCTION_ED25519), now });
    expect(r.valid).toBe(false);
    expect(r.error?.code).toBe('KEY_NOT_FOUND');
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const forged = await new SignJWT({ token_type: 'consent', scope: 's', permissions: [], session_id: 's' })
      .setProtectedHeader({ alg: 'ES256', kid: 'nope' }).setIssuer('parafe-trust-broker').sign(other.privateKey);
    expect((await verifyConsent(forged, opts)).error?.code).toBe('KEY_NOT_FOUND');
  });
});

describe('consent token v2 (B7, B14)', () => {
  it('reports exclusions, key binding and initiator_proof', async () => {
    const r = await verifyConsent(fx.consent_token, opts);
    expect(r.valid).toBe(true);
    const c = r.claims as ConsentClaims;
    expect(c.exclusions).toEqual(['issue_refund']);
    expect(c.excluded).toEqual(['issue_refund']);
    expect(c.cnf?.jkt).toBe(await calculateJwkThumbprint(fx.initiator_jwk as JWK));
    expect(c.aud).toBe(fx.target_did);
    expect(c.initiator_proof).toBe('pop');
  });

  it('checks the presentation proof: right key, token, audience, message', async () => {
    const claims = (await verifyConsent(fx.consent_token, opts)).claims as ConsentClaims;
    const ok = await verifyPresentationProof(fx.presentation_proof, fx.consent_token, claims, { initiatorKey: fx.initiator_jwk, expectedAudience: fx.target_did, expectedMessageId: 'msg-fixture-1', now });
    expect(ok.valid).toBe(true);
    expect(ok.jti).toBeTruthy();
    const wrongMid = await verifyPresentationProof(fx.presentation_proof, fx.consent_token, claims, { initiatorKey: fx.initiator_jwk, expectedMessageId: 'other', now });
    expect(wrongMid.valid).toBe(false);
    const wrongToken = await verifyPresentationProof(fx.presentation_proof, fx.credential_jwt, claims, { initiatorKey: fx.initiator_jwk, now });
    expect(wrongToken.error?.code).toBe('PROOF_INVALID');
    const otherKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' }) as JWK;
    expect((await verifyPresentationProof(fx.presentation_proof, fx.consent_token, claims, { initiatorKey: otherKey, now })).valid).toBe(false);
    const late = await verifyPresentationProof(fx.presentation_proof, fx.consent_token, claims, { initiatorKey: fx.initiator_jwk, now: new Date(now.getTime() + 10 * 60_000) });
    expect(late.valid).toBe(false);
  });

  it('fetches the initiator key from its DID document when not given', async () => {
    const claims = (await verifyConsent(fx.consent_token, opts)).claims as ConsentClaims;
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ verificationMethod: [{ publicKeyJwk: fx.initiator_jwk }] }), { status: 200 })) as unknown as typeof fetch;
    const r = await verifyPresentationProof(fx.presentation_proof, fx.consent_token, claims, { brokerUrl: 'https://broker.test', fetch: fetchMock, now });
    expect(r.valid).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(`https://broker.test/agents/${claims.sub}/did.json`);
  });
});

describe('session receipt v2 (B4)', () => {
  it('verifies the JWS (string or { receipt }) and returns its claims', async () => {
    for (const input of [fx.receipt_jws, { receipt: fx.receipt_jws }]) {
      const r = await verifyReceipt(input, opts);
      expect(r.valid).toBe(true);
      expect(r.format).toBe('receipt-jws');
      const c = r.claims as ReceiptV2Payload;
      expect(c.ver).toBe(2);
      expect(c.consent_tokens[0]?.exclusions).toEqual(['issue_refund']);
      expect(c.consent_tokens[0]?.token_ref).toBe(createHash('sha256').update(fx.consent_token).digest('base64url'));
      expect(JSON.stringify(c)).not.toContain('glazed');
    }
  });

  it('a tampered receipt fails', async () => {
    const [h, p, s] = fx.receipt_jws.split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    claims.consent_tokens[0].exclusions = [];
    const r = await verifyReceipt(`${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${s}`, opts);
    expect(r.valid).toBe(false);
    expect(r.error?.code).toBe('INVALID_SIGNATURE');
  });
});

describe('identity credential as an SD-JWT VC (B13)', () => {
  it('verifies, binds the agent key and discloses owner and owner_id', async () => {
    const r = await verifyIdentityCredential(fx.credential_sd_jwt, opts);
    expect(r.valid).toBe(true);
    expect(r.claims?.cnf.jwk).toEqual(fx.initiator_jwk);
    expect(r.claims?.owner).toBe('Fixture Owner');
    expect(r.claims?.owner_id).toMatch(/^prf_user_/);
    expect(r.claims).not.toHaveProperty('org_domain');
  });

  it('works with a disclosure withheld, and refuses one the issuer never signed', async () => {
    const [jwt, d1] = fx.credential_sd_jwt.split('~');
    const partial = await verifyIdentityCredential(`${jwt}~${d1}~`, opts);
    expect(partial.valid).toBe(true);
    expect(Object.keys(partial.claims ?? {}).filter((k) => k === 'owner' || k === 'owner_id')).toHaveLength(1);
    const fake = Buffer.from(JSON.stringify(['salt', 'verification_tier_override', 'org_verified'])).toString('base64url');
    expect((await verifyIdentityCredential(`${jwt}~${fake}~`, opts)).valid).toBe(false);
  });

  it('matchAgentKey: an AP2 open mandate bound to the agent key matches; another key does not', async () => {
    const claims = (await verifyIdentityCredential(fx.credential_sd_jwt, opts)).claims!;
    expect(await matchAgentKey(claims, { cnf: { jwk: fx.initiator_jwk } })).toBe(true);
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    expect(await matchAgentKey(claims, { cnf: { jwk: other.publicKey.export({ format: 'jwk' }) as JWK } })).toBe(false);
    const mandate = await new SignJWT({ vct: 'mandate.checkout.open.1', cnf: { jwk: fx.initiator_jwk } }).setProtectedHeader({ alg: 'ES256' }).sign(other.privateKey);
    expect(await matchAgentKey(claims, `${mandate}~`)).toBe(true);
  });
});
