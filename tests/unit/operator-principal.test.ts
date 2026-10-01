/**
 * Broker SPEC-002 (operator and principal), verify 0.6.0. Fixture:
 * tests/fixtures/broker-operator-principal-artifacts.json, from a local broker
 * (tests/scripts/generate-operator-principal-fixtures.ts): a platform org's
 * agent acting for one of its users (acts_for), and a session with its shop.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { decodeJwt } from 'jose';
import { verifyCredential, verifyIdentityCredential, verifyConsent, verifyReceipt, staticJwks, type Parties, type ReceiptV2Payload } from '../../src/index.js';

const fx = JSON.parse(readFileSync(new URL('../fixtures/broker-operator-principal-artifacts.json', import.meta.url), 'utf8'));
const opts = { key: staticJwks(fx.jwks), now: new Date((decodeJwt(fx.credential_jwt).iat as number) * 1000 + 1000) };
const userParties: Parties = { operator: { type: 'org', id: fx.platform_org_id }, principal: { type: 'external', ref: 'user-fx1' } };

describe('operator and principal (SPEC-002)', () => {
  it('verifies a credential naming the principal and the operator (no owner claim)', async () => {
    const r = await verifyCredential(fx.credential_jwt, opts);
    expect(r.valid).toBe(true);
    expect(r.claims).toMatchObject({ principal_name: 'Fixture User', principal_type: 'external', principal_ref: 'user-fx1', operator_type: 'org', operator_id: fx.platform_org_id });
    expect(r.claims).not.toHaveProperty('owner');
  });

  it('the SD-JWT VC carries the operator and its verified domain; the principal is disclosable', async () => {
    const r = await verifyIdentityCredential(fx.credential_sd_jwt, opts);
    expect(r.valid).toBe(true);
    expect(r.claims).toMatchObject({ principal_type: 'external', operator_type: 'org', operator_id: fx.platform_org_id, operator_domain: fx.domain, principal_name: 'Fixture User', principal_ref: 'user-fx1' });
    expect(typeof r.claims?.operator_domain_verified_at).toBe('number');
    expect(r.claims).not.toHaveProperty('org_domain');
  });

  it('consent token and receipt name both parties', async () => {
    const c = await verifyConsent(fx.consent_token, opts);
    expect(c.valid).toBe(true);
    expect(c.claims?.initiator_parties).toEqual(userParties);
    expect(c.claims?.target_parties).toEqual({ operator: { type: 'org', id: fx.platform_org_id }, principal: { type: 'org', id: fx.platform_org_id } });
    const rc = await verifyReceipt(fx.receipt_jws, opts);
    expect(rc.valid).toBe(true);
    expect((rc.claims as ReceiptV2Payload).participants.initiator.parties).toEqual(userParties);
  });
});
