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
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { createPublicKeySource } from '../../src/keys.js';
import {
  verifyCredential,
  verifyConsent,
  verifyReceipt,
} from '../../src/verify.js';

const BROKER_URL = process.env.PARAFE_TEST_BROKER_URL;
const suite = BROKER_URL ? describe : describe.skip;

suite('integration: full handshake lifecycle against a live broker', () => {
  function freshAgent(): { privateKey: KeyObject; publicKeyBase64: string } {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    return { privateKey, publicKeyBase64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') };
  }

  // The target proves key possession by signing the broker's hex challenge.
  function signChallenge(privateKey: KeyObject, challengeHex: string): string {
    return nodeSign(null, Buffer.from(challengeHex, 'hex'), privateKey).toString('base64');
  }

  async function post<T>(path: string, body: unknown, bearer?: string): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
    const res = await fetch(`${BROKER_URL}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`${res.status} ${path}: ${await res.text()}`);
    return res.json() as Promise<T>;
  }

  async function signupApiKey(label: string): Promise<string> {
    const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const signup = await post<{ api_key: { key: string } }>('/auth/signup', {
      email: `verify-${label}-${suffix}@example.com`,
      password: 'test-password-12345',
      name: `Verify ${label}`,
    });
    return signup.api_key.key;
  }

  async function register(apiKey: string, name: string, publicKeyBase64: string, extra: Record<string, unknown> = {}) {
    return post<{ agent_id: string; credential: string }>(
      '/agents/register',
      { agent_name: `${name}-${Date.now().toString(36)}`, owner: 'Verify Integration', public_key: publicKeyBase64, ...extra },
      apiKey
    );
  }

  it('verifies credentials, consent tokens, and receipts from a real broker', async () => {
    const key = createPublicKeySource({ brokerUrl: BROKER_URL as string });
    const apiKey = await signupApiKey('integ');

    const initiator = freshAgent();
    const target = freshAgent();
    const initReg = await register(apiKey, 'integ-initiator', initiator.publicKeyBase64);
    const targReg = await register(apiKey, 'integ-target', target.publicKeyBase64, {
      scope_policies: { 'read-profile': { permissions: ['read_profile'], exclusions: ['delete_profile'] } },
    });

    const credResult = await verifyCredential(initReg.credential, { key });
    expect(credResult.valid).toBe(true);
    expect(credResult.claims?.sub).toBe(initReg.agent_id);

    // Handshake: initiator asks, target signs the challenge
    const initiate = await post<{ handshake_id: string; challenge_for_target: string }>('/handshake/initiate', {
      initiator_credential: initReg.credential,
      target_agent_id: targReg.agent_id,
      requested_scope: 'read-profile',
      authorization: { modality: 'autonomous' },
    });
    const complete = await post<{ session: { session_id: string }; consent_token: { token: string } }>('/handshake/complete', {
      handshake_id: initiate.handshake_id,
      target_credential: targReg.credential,
      challenge_response: signChallenge(target.privateKey, initiate.challenge_for_target),
    });
    const sessionId = complete.session.session_id;

    const consentResult = await verifyConsent(complete.consent_token.token, { key });
    expect(consentResult.valid).toBe(true);
    expect(consentResult.claims?.session_id).toBe(sessionId);
    expect(consentResult.claims?.excluded).toEqual(['delete_profile']);

    // Close as a participant (the agent's own credential) and verify the receipt
    const receipt = await post<Record<string, unknown>>('/session/close', { session_id: sessionId }, initReg.credential);
    const receiptResult = await verifyReceipt(receipt, { key });
    expect(receiptResult.valid).toBe(true);
    expect(receiptResult.claims?.session_id).toBe(sessionId);
    expect(receiptResult.claims).not.toHaveProperty('receipt_vdc');

    // The same receipt as @getparafe/sdk 0.3.2+ returns it: camelCase copy + `issued`
    const sdkShaped = { receiptId: receipt['receipt_id'], signature: receipt['signature'], issued: receipt };
    expect((await verifyReceipt(sdkShaped, { key })).valid).toBe(true);

    // Tampering is caught
    const tampered = { ...receipt, session_id: 'sess_attacker' };
    expect((await verifyReceipt(tampered, { key })).valid).toBe(false);
  });

  it('offline verification works after the public key is cached (no extra /public-key calls)', async () => {
    const calls: string[] = [];
    const fetchSpy: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/public-key')) calls.push(url);
      return fetch(input as string, init);
    };
    const key = createPublicKeySource({ brokerUrl: BROKER_URL as string, fetch: fetchSpy });

    // Fetch the key once, then verify N times without touching fetch again.
    const apiKey = await signupApiKey('offline');
    const reg = await register(apiKey, 'offline', freshAgent().publicKeyBase64);

    await verifyCredential(reg.credential, { key });
    await verifyCredential(reg.credential, { key });
    await verifyCredential(reg.credential, { key });

    expect(calls.length).toBe(1);
  });
});
