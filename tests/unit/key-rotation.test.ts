/**
 * Broker SPEC-006: an agent replaced its key. Its DID document lists the
 * retired key after the current one, with `parafe:retiredAt`. A receipt signed
 * with the retired key counts only with the broker's acknowledgment from
 * before then; a presentation proof must come from the current key.
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { SignJWT, decodeJwt, calculateJwkThumbprint, type JWK } from 'jose';
import { verifyActionReceipt, verifyPresentationProof, staticJwks, KeyRetiredError } from '../../src/index.js';

const fx = JSON.parse(readFileSync(new URL('../fixtures/broker-phase2-artifacts.json', import.meta.url), 'utf8'));
const now = new Date(fx.issued_at);
const key = staticJwks(fx.jwks);
const shopId = fx.shop_did.split(':').pop();
const shopDoc = fx.did_documents[shopId];
const shopReceipt = fx.action_receipts[1]; // kid #keys-1
const shopAck = fx.acknowledgments[1];
const indexedAt = decodeJwt(shopAck).indexed_at as string;
const after = new Date(Date.parse(indexedAt) + 60_000).toISOString();
const before = new Date(Date.parse(indexedAt) - 60_000).toISOString();
const newKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });

function rotatedDoc(retiredAt: unknown) {
  const old = shopDoc.verificationMethod[0];
  return {
    ...shopDoc,
    verificationMethod: [
      { ...old, id: `${fx.shop_did}#keys-2`, publicKeyJwk: newKey.publicKey.export({ format: 'jwk' }) },
      { ...old, 'parafe:retiredAt': retiredAt },
    ],
    authentication: [`${fx.shop_did}#keys-2`],
    assertionMethod: [`${fx.shop_did}#keys-2`],
  };
}
const opts = (retiredAt: unknown, extra: Record<string, unknown> = {}) => ({
  brokerUrl: 'https://broker.test', now, ...extra,
  fetch: vi.fn(async () => new Response(JSON.stringify(rotatedDoc(retiredAt)), { status: 200 })) as unknown as typeof fetch,
});
function tamper(jws: string, change: Record<string, unknown>): string {
  const [h, p, s] = jws.split('.');
  return `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, 'base64url').toString()), ...change })).toString('base64url')}.${s}`;
}

describe('a receipt signed with a retired key', () => {
  it('checks out with the broker acknowledgment of a receipt indexed before the key retired', async () => {
    const r = await verifyActionReceipt(shopReceipt, opts(after, { acknowledgment: shopAck, key }));
    expect(r.valid).toBe(true);
    expect(r.keyRetiredAt).toBe(after);
    expect(r.keyId).toBe(`${fx.shop_did}#keys-1`);
    expect(r).not.toHaveProperty('issuerRevokedAt');
  });

  it('without an acknowledgment, says the key was retired', async () => {
    const r = await verifyActionReceipt(shopReceipt, opts(after));
    expect(r.valid).toBe(false);
    expect(r.error?.code).toBe('KEY_RETIRED');
    expect((r.error as KeyRetiredError).retiredAt).toBe(after);
  });

  it('indexed after the key retired, or with a tampered acknowledgment, fails', async () => {
    const late = await verifyActionReceipt(shopReceipt, opts(before, { acknowledgment: shopAck, key }));
    expect(late.error?.code).toBe('KEY_RETIRED');
    const tampered = await verifyActionReceipt(shopReceipt, opts(after, { acknowledgment: tamper(shopAck, { indexed_at: before }), key }));
    expect(tampered.valid).toBe(false);
    expect(tampered.error?.code).toBe('INVALID_SIGNATURE');
  });

  it('an unreadable retirement time is refused', async () => {
    const r = await verifyActionReceipt(shopReceipt, opts('soon', { acknowledgment: shopAck, key }));
    expect(r.valid).toBe(false);
    expect(r.error?.code).toBe('MALFORMED');
  });

  it("a receipt signed with the retired key but naming the current kid doesn't verify", async () => {
    const [, p, s] = shopReceipt.split('.');
    const header = JSON.parse(Buffer.from(shopReceipt.split('.')[0], 'base64url').toString());
    const relabelled = `${Buffer.from(JSON.stringify({ ...header, kid: `${fx.shop_did}#keys-2` })).toString('base64url')}.${p}.${s}`;
    const r = await verifyActionReceipt(relabelled, opts(after));
    expect(r.valid).toBe(false);
    expect(r.error?.code).toBe('INVALID_SIGNATURE');
  });
});

describe('presentation proofs after a rotation', () => {
  const oldKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const DID = 'did:web:broker.test:agents:prf_agent_alex';
  const jwk = (k: typeof oldKey) => k.publicKey.export({ format: 'jwk' }) as JWK;
  const doc = {
    id: DID,
    verificationMethod: [{ id: `${DID}#keys-2`, publicKeyJwk: jwk(newKey) }, { id: `${DID}#keys-1`, publicKeyJwk: jwk(oldKey), 'parafe:retiredAt': after }],
    authentication: [`${DID}#keys-2`],
  };
  const fetchDoc = vi.fn(async () => new Response(JSON.stringify(doc), { status: 200 })) as unknown as typeof fetch;
  async function present(k: typeof oldKey) {
    const token = 'header.payload.sig';
    const claims = { sub: 'prf_agent_alex', aud: 'did:web:broker.test:agents:prf_agent_shop', cnf: { jkt: await calculateJwkThumbprint(jwk(k)) } };
    const ath = (await import('node:crypto')).createHash('sha256').update(token).digest('base64url');
    const proof = await new SignJWT({ ath, aud: claims.aud, jti: randomUUID() })
      .setProtectedHeader({ alg: 'ES256', typ: 'parafe-pop+jwt' }).setIssuedAt().sign(k.privateKey);
    return verifyPresentationProof(proof, token, claims, { brokerUrl: 'https://broker.test', fetch: fetchDoc });
  }

  it('the current key (in authentication) proves; the retired key, still listed, does not', async () => {
    expect((await present(newKey)).valid).toBe(true);
    const old = await present(oldKey);
    expect(old.valid).toBe(false);
    expect(old.error?.code).toBe('PROOF_INVALID');
  });
});
