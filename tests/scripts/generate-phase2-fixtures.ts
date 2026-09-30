/**
 * Generates tests/fixtures/broker-phase2-artifacts.json (B6: action receipts,
 * index acknowledgments, a session receipt listing them) from a running
 * Phase 2 broker. Not run in CI; the fixture is committed.
 *
 *   PARAFE_TEST_BROKER_URL=http://localhost:3310 npx tsx tests/scripts/generate-phase2-fixtures.ts
 *
 * Works whether or not the broker requires proofs of possession (it always sends them).
 */
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, generateKeyPairSync, randomUUID, sign as nodeSign, type KeyObject } from 'node:crypto';
import { SignJWT } from 'jose';

const BROKER_URL = (process.env.PARAFE_TEST_BROKER_URL ?? 'http://localhost:3000').replace(/\/$/, '');
const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'broker-phase2-artifacts.json');
const sha = (s: string) => createHash('sha256').update(s).digest('base64url');
const now = () => Math.floor(Date.now() / 1000);

interface Agent { id: string; did: string; credential: string; privateKey: KeyObject }

const algOf = (k: KeyObject) => (k.asymmetricKeyType === 'ec' ? 'ES256' : 'EdDSA');

async function proof(agent: Agent, method: string, path: string, claims: Record<string, unknown>): Promise<string> {
  return new SignJWT({ htm: method, htu: `${BROKER_URL}${path}`, iat: now(), jti: randomUUID(), ...claims })
    .setProtectedHeader({ alg: algOf(agent.privateKey), typ: 'parafe-pop+jwt' })
    .sign(agent.privateKey);
}

async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<any> {
  const res = await fetch(`${BROKER_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`${res.status} ${path}: ${JSON.stringify(json)}`);
  return json;
}

async function asAgent(agent: Agent, method: string, path: string, body: unknown, claims: Record<string, unknown>): Promise<any> {
  return call(method, path, body, { Authorization: `Bearer ${agent.credential}`, 'Parafe-PoP': await proof(agent, method, path, claims) });
}

async function main(): Promise<void> {
  const suffix = Date.now().toString(36);
  const signup = await call('POST', '/auth/signup', { email: `verify-p2-${suffix}@example.com`, password: 'test-password-12345', name: 'Verify Fixtures' });
  const apiKey = signup.api_key.key as string;

  const register = async (name: string, kind: 'p256' | 'ed25519', scope_policies?: unknown): Promise<Agent> => {
    const { privateKey, publicKey } = kind === 'p256' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('ed25519');
    const r = await call('POST', '/agents/register', {
      agent_name: `${name}-${suffix}`, owner: 'Verify Fixtures', public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      ...(scope_policies ? { scope_policies } : {}),
    }, { Authorization: `Bearer ${apiKey}` });
    return { id: r.agent_id, did: r.did, credential: r.credential, privateKey };
  };
  const shop = await register('shop', 'p256', {
    'menu-browse': { permissions: ['read_menu'], exclusions: [] },
    'place-order': { permissions: ['create_order'], exclusions: ['issue_refund'] },
  });
  const cust = await register('customer', 'ed25519');

  const init = await asAgent(cust, 'POST', '/handshake/initiate', { initiator_credential: cust.credential, target_agent_id: shop.id, requested_scope: 'menu-browse' },
    { target_agent_id: shop.id, requested_scope: 'menu-browse' });
  const challenge = Buffer.from(init.challenge_for_target, 'hex');
  const sig = nodeSign('sha256', challenge, { key: shop.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
  const done = await call('POST', '/handshake/complete', { handshake_id: init.handshake_id, target_credential: shop.credential, challenge_response: sig });
  const sessionId = done.session.session_id as string;
  const browseToken = done.consent_token.token as string;
  const esc = await asAgent(cust, 'POST', '/handshake/initiate',
    { initiator_credential: cust.credential, target_agent_id: shop.id, requested_scope: 'place-order', session_id: sessionId },
    { target_agent_id: shop.id, requested_scope: 'place-order', session_id: sessionId });
  const orderToken = esc.consent_token.token as string;

  const actionReceipt = (agent: Agent, claims: Record<string, unknown>) => new SignJWT({
    iss: agent.did, iat: now(), jti: randomUUID(), ver: 1, session_id: sessionId,
    result: 'success', error: null, error_description: null, request_ref: null, details_hash: null, business_ref: null, mandate_ref: null, ...claims,
  }).setProtectedHeader({ alg: algOf(agent.privateKey), kid: `${agent.did}#keys-1`, typ: 'parafe-action-receipt+jwt' }).sign(agent.privateKey);

  const receipts = [
    await actionReceipt(shop, { consent_ref: sha(browseToken), action: 'read_menu' }),
    await actionReceipt(shop, { consent_ref: sha(orderToken), action: 'create_order', business_ref: 'ord_fixture_1' }),
    await actionReceipt(shop, { consent_ref: sha(orderToken), action: 'issue_refund', result: 'error', error: 'excluded', error_description: 'issue_refund is excluded' }),
    await actionReceipt(cust, { consent_ref: sha(orderToken), action: 'confirm_pickup', result: 'error', error: 'failed', error_description: 'shop closed' }),
  ];
  const acks: string[] = [];
  const path = `/sessions/${sessionId}/action-receipts`;
  for (const r of receipts) {
    const filer = r === receipts[2] ? cust : shop; // the initiator files the refusal
    acks.push((await asAgent(filer, 'POST', path, { receipt: r }, { session_id: sessionId })).acknowledgment);
  }
  const close = await asAgent(cust, 'POST', '/session/close', { session_id: sessionId }, { session_id: sessionId });
  const jwks = await call('GET', '/.well-known/jwks.json');
  const didDocuments = {
    [shop.id]: await call('GET', `/agents/${shop.id}/did.json`),
    [cust.id]: await call('GET', `/agents/${cust.id}/did.json`),
  };

  writeFileSync(OUT, `${JSON.stringify({
    note: 'Generated by a local Phase 2 broker (not production): B6 action receipts, index acknowledgments and the session receipt listing them.',
    issued_at: new Date().toISOString(),
    broker_url: BROKER_URL,
    jwks,
    did_documents: didDocuments,
    shop_did: shop.did,
    customer_did: cust.did,
    session_id: sessionId,
    consent_tokens: { browse: browseToken, order: orderToken },
    action_receipts: receipts,
    acknowledgments: acks,
    session_receipt: close.receipt,
  }, null, 2)}\n`);
  console.log(`Wrote ${OUT}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
