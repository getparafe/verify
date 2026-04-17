/**
 * End-to-end integration test: runs a full handshake against a real Parafe broker,
 * captures every artifact, and verifies each of them with @getparafe/verify — fully
 * offline after the initial /public-key fetch.
 *
 * Run against staging:
 *   PARAFE_TEST_BROKER_URL=https://parafe-staging.up.railway.app npm run test:integration
 *
 * Gated on PARAFE_TEST_BROKER_URL — skipped automatically if unset, matching the
 * A2A extension's convention.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair, exportSPKI, SignJWT, type KeyLike } from 'jose';
import { createPublicKeySource } from '../../src/keys.js';
import {
  verifyCredential,
  verifyConsent,
  verifyReceipt,
} from '../../src/verify.js';

const BROKER_URL = process.env.PARAFE_TEST_BROKER_URL;
const suite = BROKER_URL ? describe : describe.skip;

suite('integration: full handshake lifecycle against a live broker', () => {
  async function freshAgent(): Promise<{ privateKey: KeyLike; publicKeyPem: string }> {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const publicKeyPem = await exportSPKI(publicKey);
    return { privateKey, publicKeyPem };
  }

  async function signChallenge(privateKey: KeyLike, nonce: string, issuer: string): Promise<string> {
    return new SignJWT({ nonce })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt()
      .setIssuer(issuer)
      .setExpirationTime('5m')
      .sign(privateKey);
  }

  async function post<T>(path: string, body: unknown, apiKey?: string): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) headers['X-API-Key'] = apiKey;
    const res = await fetch(`${BROKER_URL}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`${res.status} ${path}: ${await res.text()}`);
    return res.json() as Promise<T>;
  }

  it('verifies credentials, consent tokens, and receipts from a real broker', async () => {
    const key = createPublicKeySource({ brokerUrl: BROKER_URL as string });

    // Signup
    const suffix = Date.now();
    const signup = await post<{ api_key: string }>('/auth/signup', {
      email: `verify-integ-${suffix}@test.parafe.ai`,
      password: 'test-password-12345',
      org_name: `Verify Integ ${suffix}`,
    });
    const apiKey = signup.api_key;

    // Register two agents
    const initiator = await freshAgent();
    const target = await freshAgent();
    const initReg = await post<{ agent_id: string; credential: string; credential_vdc: unknown }>(
      '/agents/register',
      { agent_name: `integ-initiator-${suffix}`, owner_type: 'personal', public_key: initiator.publicKeyPem },
      apiKey
    );
    const targReg = await post<{ agent_id: string; credential: string; credential_vdc: unknown }>(
      '/agents/register',
      { agent_name: `integ-target-${suffix}`, owner_type: 'personal', public_key: target.publicKeyPem },
      apiKey
    );

    // Verify credential (JWT form)
    const credResult = await verifyCredential(initReg.credential, { key });
    expect(credResult.valid).toBe(true);
    expect(credResult.claims?.sub).toBe(initReg.agent_id);

    // Verify credential (VDC form)
    if (initReg.credential_vdc) {
      const credVdcResult = await verifyCredential(initReg.credential_vdc, { key });
      expect(credVdcResult.valid).toBe(true);
    }

    // Handshake
    const initiate = await post<{ handshake_id: string; initiator_challenge: string; target_challenge: string }>(
      '/handshake/initiate',
      { initiator_agent_id: initReg.agent_id, target_agent_id: targReg.agent_id, scope: 'read_profile' },
      apiKey
    );
    const initProof = await signChallenge(initiator.privateKey, initiate.initiator_challenge, initReg.agent_id);
    const targProof = await signChallenge(target.privateKey, initiate.target_challenge, targReg.agent_id);

    const complete = await post<{ session_id: string; consent_token: string; consent_token_vdc?: unknown }>(
      '/handshake/complete',
      { handshake_id: initiate.handshake_id, initiator_proof: initProof, target_proof: targProof },
      apiKey
    );

    // Verify consent token (JWT)
    const consentResult = await verifyConsent(complete.consent_token, { key });
    expect(consentResult.valid).toBe(true);
    expect(consentResult.claims?.session_id).toBe(complete.session_id);

    // Verify consent token (VDC)
    if (complete.consent_token_vdc) {
      const consentVdcResult = await verifyConsent(complete.consent_token_vdc, { key });
      expect(consentVdcResult.valid).toBe(true);
    }

    // Close session + verify receipt
    const close = await post<Record<string, unknown>>('/session/close', { session_id: complete.session_id }, apiKey);
    const { receipt_vdc, ...receipt } = close as Record<string, unknown> & { receipt_vdc?: unknown };

    const receiptResult = await verifyReceipt(receipt, { key });
    expect(receiptResult.valid).toBe(true);
    expect(receiptResult.claims?.session_id).toBe(complete.session_id);

    if (receipt_vdc) {
      const receiptVdcResult = await verifyReceipt(receipt_vdc, { key });
      expect(receiptVdcResult.valid).toBe(true);
    }
  });

  it('offline verification works after the public key is cached (no extra /public-key calls)', async () => {
    const calls: string[] = [];
    const fetchSpy: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/public-key')) calls.push(url);
      return fetch(input as string, init);
    };
    const key = createPublicKeySource({ brokerUrl: BROKER_URL as string, fetch: fetchSpy });

    // Mint one credential by fetching the key once, then verify N times without touching fetch again.
    const suffix = Date.now();
    const signup = await post<{ api_key: string }>('/auth/signup', {
      email: `verify-offline-${suffix}@test.parafe.ai`,
      password: 'test-password-12345',
      org_name: `Verify Offline ${suffix}`,
    });
    const agent = await freshAgent();
    const reg = await post<{ credential: string }>(
      '/agents/register',
      { agent_name: `offline-${suffix}`, owner_type: 'personal', public_key: agent.publicKeyPem },
      signup.api_key
    );

    await verifyCredential(reg.credential, { key });
    await verifyCredential(reg.credential, { key });
    await verifyCredential(reg.credential, { key });

    expect(calls.length).toBe(1);
  });
});
