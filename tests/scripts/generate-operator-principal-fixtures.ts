/**
 * Artifacts from a broker running SPEC-002 (operator and principal), for unit tests.
 * Usage (a broker on :3000 with PARAFE_ADMIN_KEY=local-admin, PoP required or not):
 *   PARAFE_TEST_BROKER_URL=http://localhost:3000 PARAFE_TEST_ADMIN_KEY=local-admin npx tsx tests/scripts/generate-operator-principal-fixtures.ts
 * Writes tests/fixtures/broker-operator-principal-artifacts.json. Not run in CI.
 */
import { writeFileSync } from 'node:fs';
import { generateKeyPairSync, sign as nodeSign, randomUUID, type KeyObject } from 'node:crypto';
import { SignJWT, exportJWK } from 'jose';

const BROKER = (process.env.PARAFE_TEST_BROKER_URL ?? 'http://localhost:3000').replace(/\/$/, '');
const ADMIN = process.env.PARAFE_TEST_ADMIN_KEY ?? 'local-admin';
const run = Date.now().toString(36);

async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const r = await fetch(`${BROKER}${path}`, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body ? JSON.stringify(body) : undefined });
  const json = await r.json();
  if (!r.ok) throw new Error(`${method} ${path} → ${r.status} ${JSON.stringify(json)}`);
  return json;
}
async function pop(privateKey: KeyObject, htm: string, path: string, claims: Record<string, unknown>) {
  return new SignJWT({ htm, htu: `${BROKER}${path}`, jti: randomUUID(), ...claims })
    .setProtectedHeader({ alg: 'ES256', typ: 'parafe-pop+jwt' }).setIssuedAt().sign(privateKey);
}
const spki = (k: KeyObject) => k.export({ type: 'spki', format: 'der' }).toString('base64');

// A domain-verified platform org (test org), a user's agent (acts_for) and a shop agent.
const domain = `platform-${run}.example.com`;
const setup = await call('POST', '/admin/test/handshake-setup', { verification_tier: 'domain_verified', domain }, { Authorization: `Bearer ${ADMIN}` });
const key = { Authorization: `Bearer ${setup.api_key}` };
const ini = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const tgt = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const a = await call('POST', '/agents/register', { agent_name: `fx-user-${run}`, principal_name: 'Fixture User', public_key: spki(ini.publicKey), acts_for: { ref: 'user-fx1' } }, key);
const b = await call('POST', '/agents/register', { agent_name: `fx-shop-${run}`, principal_name: 'Fixture Shop', public_key: spki(tgt.publicKey) }, key);
const initPath = '/handshake/initiate';
const init = await call('POST', initPath, { initiator_credential: a.credential, target_agent_id: b.agent_id, requested_scope: 'any', authorization: { modality: 'autonomous' } },
  { 'Parafe-PoP': await pop(ini.privateKey, 'POST', initPath, { target_agent_id: b.agent_id, requested_scope: 'any' }) });
const challenge = nodeSign('sha256', Buffer.from(init.challenge_for_target, 'hex'), { key: tgt.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
const done = await call('POST', '/handshake/complete', { handshake_id: init.handshake_id, target_credential: b.credential, challenge_response: challenge });
const closePath = '/session/close';
const close = await call('POST', closePath, { session_id: done.session.session_id },
  { Authorization: `Bearer ${a.credential}`, 'Parafe-PoP': await pop(ini.privateKey, 'POST', closePath, { session_id: done.session.session_id }) });
const jwks = await (await fetch(`${BROKER}/.well-known/jwks.json`)).json();

writeFileSync(new URL('../fixtures/broker-operator-principal-artifacts.json', import.meta.url), JSON.stringify({
  note: `Generated ${new Date().toISOString()} by a local broker with SPEC-002 (operator and principal).`,
  jwks, platform_org_id: setup.org_id, domain,
  credential_jwt: a.credential, credential_sd_jwt: a.credential_sd_jwt,
  consent_token: done.consent_token.token, receipt_jws: close.receipt,
  initiator_jwk: await exportJWK(ini.publicKey),
}, null, 2) + '\n');
console.log('wrote tests/fixtures/broker-operator-principal-artifacts.json');
