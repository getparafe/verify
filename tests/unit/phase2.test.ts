/**
 * AP2 change request Phase 2 (B6): action receipts, index acknowledgments and
 * the session receipt's index. Fixture: tests/fixtures/broker-phase2-artifacts.json,
 * from a local Phase 2 broker (tests/scripts/generate-phase2-fixtures.ts).
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { decodeJwt, type JWK } from 'jose';
import {
  verifyActionReceipt, verifyIndexAck, verifySessionIndex, verifyReceipt, receiptHash, consentRef, entryHash,
  staticJwks, IssuerRevokedError, type ReceiptV2Payload,
} from '../../src/index.js';

const fx = JSON.parse(readFileSync(new URL('../fixtures/broker-phase2-artifacts.json', import.meta.url), 'utf8'));
const now = new Date(fx.issued_at);
const key = staticJwks(fx.jwks);
const sha = (s: string) => createHash('sha256').update(s).digest('base64url');
const didFetch = vi.fn(async (url: string) => {
  const id = String(url).split('/agents/')[1]?.split('/')[0] ?? '';
  const doc = fx.did_documents[decodeURIComponent(id)];
  return new Response(JSON.stringify(doc ?? {}), { status: doc ? 200 : 404 });
}) as unknown as typeof fetch;
const shopJwk = (): JWK => fx.did_documents[fx.shop_did.split(':').pop()].verificationMethod[0].publicKeyJwk;

function tamper(jws: string, change: Record<string, unknown>): string {
  const [h, p, s] = jws.split('.');
  const claims = JSON.parse(Buffer.from(p!, 'base64url').toString());
  return `${h}.${Buffer.from(JSON.stringify({ ...claims, ...change })).toString('base64url')}.${s}`;
}

describe('hashes', () => {
  it('receiptHash and consentRef are base64url SHA-256 of the JWS; entryHash chains seq|hash|prev', () => {
    expect(receiptHash(fx.action_receipts[0])).toBe(sha(fx.action_receipts[0]));
    expect(consentRef(fx.consent_tokens.order)).toBe(sha(fx.consent_tokens.order));
    expect(entryHash(1, 'h1', null)).toBe(sha('1|h1|'));
    expect(entryHash(2, 'h2', 'e1')).toBe(sha('2|h2|e1'));
  });
});

describe('action receipts', () => {
  it('verify with the issuer key from its DID document: ES256 (shop) and EdDSA (customer)', async () => {
    const shop = await verifyActionReceipt(fx.action_receipts[1], { brokerUrl: 'https://broker.test', fetch: didFetch, now, consentToken: fx.consent_tokens.order, expectedSessionId: fx.session_id });
    expect(shop.valid).toBe(true);
    expect(shop.claims).toMatchObject({ iss: fx.shop_did, action: 'create_order', result: 'success', business_ref: 'ord_fixture_1' });
    expect(shop.keyId).toBe(`${fx.shop_did}#keys-1`);
    const cust = await verifyActionReceipt(fx.action_receipts[3], { brokerUrl: 'https://broker.test', fetch: didFetch, now });
    expect(cust.valid).toBe(true);
    expect(cust.claims).toMatchObject({ iss: fx.customer_did, result: 'error', error: 'failed' });
  });

  it('a refusal carries its error code', async () => {
    const r = await verifyActionReceipt(fx.action_receipts[2], { issuerKey: shopJwk(), now });
    expect(r.claims).toMatchObject({ action: 'issue_refund', result: 'error', error: 'excluded' });
  });

  it('a tampered receipt, another consent token or another session fails', async () => {
    const tampered = await verifyActionReceipt(tamper(fx.action_receipts[1], { action: 'issue_refund' }), { issuerKey: shopJwk(), now });
    expect(tampered.valid).toBe(false);
    expect(tampered.error?.code).toBe('INVALID_SIGNATURE');
    const otherToken = await verifyActionReceipt(fx.action_receipts[1], { issuerKey: shopJwk(), now, consentToken: fx.consent_tokens.browse });
    expect(otherToken.valid).toBe(false);
    expect(otherToken.error?.code).toBe('MALFORMED');
    const otherSession = await verifyActionReceipt(fx.action_receipts[1], { issuerKey: shopJwk(), now, expectedSessionId: 'sess_other' });
    expect(otherSession.valid).toBe(false);
  });

  it("a receipt claiming another agent's DID doesn't verify with that agent's key", async () => {
    const forged = tamper(fx.action_receipts[3], { iss: fx.shop_did });
    const r = await verifyActionReceipt(forged, { brokerUrl: 'https://broker.test', fetch: didFetch, now });
    expect(r.valid).toBe(false);
  });
});

describe("a revoked agent's receipts (broker decision (f))", () => {
  const shopId = fx.shop_did.split(':').pop();
  const shopReceipt = fx.action_receipts[1];
  const shopAck = fx.acknowledgments[1];
  const indexedAt = decodeJwt(shopAck).indexed_at as string;
  const revokedFetch = (revokedAt: string | undefined) => vi.fn(async () => new Response(JSON.stringify({
    error: 'agent_revoked', ...(revokedAt ? { revoked_at: revokedAt } : {}),
    did_document: fx.did_documents[shopId], did_document_metadata: { deactivated: true },
  }), { status: 410 })) as unknown as typeof fetch;
  const after = new Date(Date.parse(indexedAt) + 60_000).toISOString();
  const before = new Date(Date.parse(indexedAt) - 60_000).toISOString();
  const opts = (revokedAt: string | undefined, extra: Record<string, unknown> = {}) => ({ brokerUrl: 'https://broker.test', fetch: revokedFetch(revokedAt), now, ...extra });

  it('checks out with the broker acknowledgment of a receipt indexed before the revocation', async () => {
    const r = await verifyActionReceipt(shopReceipt, opts(after, { acknowledgment: shopAck, key }));
    expect(r.valid).toBe(true);
    expect(r.issuerRevokedAt).toBe(after);
    expect(r.claims).toMatchObject({ iss: fx.shop_did, action: 'create_order' });
  });

  it('without an acknowledgment, says the agent was revoked', async () => {
    const r = await verifyActionReceipt(shopReceipt, opts(after));
    expect(r.valid).toBe(false);
    expect(r.error?.code).toBe('ISSUER_REVOKED');
    expect((r.error as IssuerRevokedError).revokedAt).toBe(after);
  });

  it('a receipt indexed after the revocation, an acknowledgment of another receipt, or a tampered one, fails', async () => {
    const late = await verifyActionReceipt(shopReceipt, opts(before, { acknowledgment: shopAck, key }));
    expect(late.error?.code).toBe('ISSUER_REVOKED');
    const other = await verifyActionReceipt(shopReceipt, opts(after, { acknowledgment: fx.acknowledgments[0], key }));
    expect(other.error?.code).toBe('MALFORMED');
    const tampered = await verifyActionReceipt(shopReceipt, opts(after, { acknowledgment: tamper(shopAck, { indexed_at: before }), key }));
    expect(tampered.valid).toBe(false);
    expect(tampered.error?.code).toBe('INVALID_SIGNATURE');
  });

  it('an acknowledgment without the broker key source is refused; an active agent has no issuerRevokedAt', async () => {
    const noKey = await verifyActionReceipt(shopReceipt, opts(after, { acknowledgment: shopAck }));
    expect(noKey.valid).toBe(false);
    expect(noKey.error?.code).toBe('MALFORMED');
    const active = await verifyActionReceipt(shopReceipt, { brokerUrl: 'https://broker.test', fetch: didFetch, now, acknowledgment: shopAck, key });
    expect(active.valid).toBe(true);
    expect(active).not.toHaveProperty('issuerRevokedAt');
  });

  it('a 410 without a revocation time is a key fetch failure', async () => {
    await expect(verifyActionReceipt(shopReceipt, opts(undefined, { acknowledgment: shopAck, key }))).rejects.toMatchObject({ code: 'KEY_FETCH_FAILED' });
  });
});

describe('index acknowledgments', () => {
  it('verify against the broker JWKS and recompute entry_hash', async () => {
    for (const [i, ack] of fx.acknowledgments.entries()) {
      const r = await verifyIndexAck(ack, { key, now, expectedIssuer: 'did:web:api.parafe.ai' });
      expect(r.valid).toBe(true);
      expect(r.claims).toMatchObject({ seq: i + 1, session_id: fx.session_id, receipt_hash: sha(fx.action_receipts[i]) });
    }
  });

  it('a tampered acknowledgment fails', async () => {
    const r = await verifyIndexAck(tamper(fx.acknowledgments[0], { seq: 2 }), { key, now });
    expect(r.valid).toBe(false);
  });
});

describe('the session receipt lists every action receipt (verifySessionIndex)', () => {
  it('chain_head recomputes; every receipt is listed; every acknowledgment matches its entry', async () => {
    const session = await verifyReceipt(fx.session_receipt, { key, now });
    expect(session.valid).toBe(true);
    const claims = session.claims as ReceiptV2Payload;
    expect(claims.actions.map((a) => a.action)).toEqual(['read_menu', 'create_order', 'issue_refund', 'confirm_pickup']);
    const r = await verifySessionIndex(claims, { receipts: fx.action_receipts, acknowledgments: fx.acknowledgments, key, now });
    expect(r.error).toBeUndefined();
    expect(r.valid).toBe(true);
    expect(r.chainHead).toBe(claims.chain_head);
    expect(r.listed.map((l) => l.seq)).toEqual([1, 2, 3, 4]);
  });

  it('a receipt that was never filed is reported as not listed', async () => {
    const claims = decodeJwt(fx.session_receipt) as unknown as ReceiptV2Payload;
    const r = await verifySessionIndex(claims, { receipts: [tamper(fx.action_receipts[0], { action: 'other' })] });
    expect(r.valid).toBe(false);
    expect(r.listed[0]?.seq).toBeNull();
  });

  it('a reordered or truncated action list does not recompute to chain_head', async () => {
    const claims = decodeJwt(fx.session_receipt) as unknown as ReceiptV2Payload;
    const swapped = [claims.actions[1]!, claims.actions[0]!, ...claims.actions.slice(2)].map((a, i) => ({ ...a, seq: i + 1 }));
    expect((await verifySessionIndex({ ...claims, actions: swapped })).valid).toBe(false);
    expect((await verifySessionIndex({ ...claims, actions: claims.actions.slice(0, 3) })).valid).toBe(false);
  });

  it("an acknowledgment from another session's chain does not match", async () => {
    const claims = decodeJwt(fx.session_receipt) as unknown as ReceiptV2Payload;
    const r = await verifySessionIndex({ ...claims, session_id: 'sess_other' }, { acknowledgments: [fx.acknowledgments[0]], key, now });
    expect(r.valid).toBe(false);
  });
});
