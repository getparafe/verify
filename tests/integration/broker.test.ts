/**
 * End-to-end integration test: runs a full handshake against a real Parafe broker,
 * captures every artifact, and verifies each of them with @getparafe/verify — fully
 * offline after the initial key fetch (the broker JWKS).
 *
 * Run against staging:
 *   PARAFE_TEST_BROKER_URL=https://parafe-staging.up.railway.app npm run test:integration
 *
 * Gated on PARAFE_TEST_BROKER_URL — skipped automatically if unset, matching the
 * A2A extension's convention.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as nodeSign, randomUUID, createHash, type KeyObject } from 'node:crypto';
import { SignJWT } from 'jose';
import { createPublicKeySource } from '../../src/keys.js';
import {
  verifyCredential,
  verifyConsent,
  verifyReceipt,
} from '../../src/verify.js';
import { verifyIdentityCredential } from '../../src/identity-credential.js';
import { verifyPresentationProof } from '../../src/presentation.js';
import { verifyActionReceipt, verifyIndexAck, verifySessionIndex, consentRef } from '../../src/action-receipt.js';
import type { ConsentClaims, ReceiptV2Payload } from '../../src/types.js';

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

  // B7: a proof of possession signed with the agent's key, bound to the request.
  function proof(privateKey: KeyObject, claims: Record<string, unknown>): Promise<string> {
    return new SignJWT({ iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...claims })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'parafe-pop+jwt' })
      .sign(privateKey);
  }

  async function post<T>(path: string, body: unknown, bearer?: string, extra: Record<string, string> = {}): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json', ...extra };
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
    return post<{ agent_id: string; did: string; credential: string; credential_sd_jwt: string }>(
      '/agents/register',
      { agent_name: `${name}-${Date.now().toString(36)}`, principal_name: 'Verify Integration', public_key: publicKeyBase64, ...extra },
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
    const sdResult = await verifyIdentityCredential(initReg.credential_sd_jwt, { key });
    expect(sdResult.valid).toBe(true);
    expect(sdResult.claims?.agent_id).toBe(initReg.agent_id);

    // Handshake: initiator asks, target signs the challenge
    const initiate = await post<{ handshake_id: string; challenge_for_target: string }>('/handshake/initiate', {
      initiator_credential: initReg.credential,
      target_agent_id: targReg.agent_id,
      requested_scope: 'read-profile',
      authorization: { modality: 'autonomous' },
    }, undefined, {
      'Parafe-PoP': await proof(initiator.privateKey, { htm: 'POST', htu: `${BROKER_URL}/handshake/initiate`, target_agent_id: targReg.agent_id, requested_scope: 'read-profile' }),
    });
    const complete = await post<{ session: { session_id: string }; consent_token: { token: string } }>('/handshake/complete', {
      handshake_id: initiate.handshake_id,
      target_credential: targReg.credential,
      challenge_response: signChallenge(target.privateKey, initiate.challenge_for_target),
    });
    const sessionId = complete.session.session_id;

    const token = complete.consent_token.token;
    const consentResult = await verifyConsent(token, { key });
    expect(consentResult.valid).toBe(true);
    const consent = consentResult.claims as ConsentClaims;
    expect(consent.session_id).toBe(sessionId);
    expect(consent.exclusions).toEqual(['delete_profile']);
    expect(consent.initiator_proof).toBe('pop');

    // The initiator presents the token with a proof; the target checks it offline
    const presentation = await proof(initiator.privateKey, { ath: createHash('sha256').update(token).digest('base64url'), aud: targReg.did });
    const pop = await verifyPresentationProof(presentation, token, consent, { brokerUrl: BROKER_URL as string, expectedAudience: targReg.did });
    expect(pop.valid).toBe(true);

    // B6: the target signs an action receipt and files it; the broker acknowledges it
    const actionReceipt = await new SignJWT({
      iss: targReg.did, iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ver: 1, session_id: sessionId,
      consent_ref: consentRef(token), action: 'read_profile', result: 'success', error: null,
    }).setProtectedHeader({ alg: 'EdDSA', kid: `${targReg.did}#keys-1`, typ: 'parafe-action-receipt+jwt' }).sign(target.privateKey);
    const filed = await post<{ acknowledgment: string }>(`/sessions/${sessionId}/action-receipts`, { receipt: actionReceipt }, targReg.credential, {
      'Parafe-PoP': await proof(target.privateKey, { htm: 'POST', htu: `${BROKER_URL}/sessions/${sessionId}/action-receipts`, session_id: sessionId }),
    });
    const arResult = await verifyActionReceipt(actionReceipt, { brokerUrl: BROKER_URL as string, consentToken: token, expectedSessionId: sessionId });
    expect(arResult.valid).toBe(true);
    expect((await verifyIndexAck(filed.acknowledgment, { key })).valid).toBe(true);

    // Close as a participant (credential + proof) and verify the receipt (v2 JWS)
    const closed = await post<{ receipt: string }>('/session/close', { session_id: sessionId }, initReg.credential, {
      'Parafe-PoP': await proof(initiator.privateKey, { htm: 'POST', htu: `${BROKER_URL}/session/close`, session_id: sessionId }),
    });
    const receiptResult = await verifyReceipt(closed, { key });
    expect(receiptResult.valid).toBe(true);
    expect((receiptResult.claims as ReceiptV2Payload).session_id).toBe(sessionId);
    expect((receiptResult.claims as ReceiptV2Payload).consent_tokens[0]?.exclusions).toEqual(['delete_profile']);
    const index = await verifySessionIndex(receiptResult.claims as ReceiptV2Payload, { receipts: [actionReceipt], acknowledgments: [filed.acknowledgment], key });
    expect(index.valid).toBe(true);
    expect(index.listed[0]?.seq).toBe(1);

    // Tampering is caught
    const [h, p, sig] = closed.receipt.split('.');
    const claims = JSON.parse(Buffer.from(p as string, 'base64url').toString());
    claims.session_id = 'sess_attacker';
    const tampered = `${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${sig}`;
    expect((await verifyReceipt(tampered, { key })).valid).toBe(false);
  });

  it('offline verification works after the keys are cached (one JWKS fetch)', async () => {
    const calls: string[] = [];
    const fetchSpy: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/public-key') || url.includes('/jwks.json')) calls.push(url);
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
