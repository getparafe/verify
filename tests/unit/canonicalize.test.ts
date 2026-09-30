import { describe, it, expect } from 'vitest';
import { canonicalize, signingInputForReceipt } from '../../src/canonicalize.js';

describe('canonicalize', () => {
  it('sorts object keys alphabetically at every level', () => {
    const input = { b: 1, a: { z: 1, y: 2 }, c: [{ b: 2, a: 1 }, 3] };
    expect(canonicalize(input)).toBe('{"a":{"y":2,"z":1},"b":1,"c":[{"a":1,"b":2},3]}');
  });

  it('preserves array order', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('treats null as primitive', () => {
    expect(canonicalize({ b: null, a: 1 })).toBe('{"a":1,"b":null}');
  });

  it('produces identical output for equivalent objects', () => {
    const a = { foo: 1, bar: 2, baz: { y: 2, x: 1 } };
    const b = { baz: { x: 1, y: 2 }, bar: 2, foo: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  // Golden vector: matches the broker's output exactly. Generated with the
  // broker's canonicalize() (the same function signs receipts) on this input.
  it('matches a broker golden vector for a nested payload', () => {
    const vdc = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://schema.parafe.ai/v1'],
      type: ['VerifiableCredential', 'ParafeIdentityCredential'],
      issuer: 'did:web:api.parafe.ai',
      issuanceDate: '2026-04-01T00:00:00.000Z',
      expirationDate: '2026-05-01T00:00:00.000Z',
      credentialSubject: {
        id: 'did:web:api.parafe.ai:agent:prf_agent_abc',
        agent_id: 'prf_agent_abc',
        agent_name: 'Test',
        owner: 'Org',
        identity_assurance: 'registered',
        verification_tier: 'unverified',
        public_key_thumbprint: 'deadbeef',
      },
    };
    // Alphabetical top level: @context, credentialSubject, expirationDate, issuanceDate, issuer, type
    // credentialSubject is alphabetized too: agent_id, agent_name, id, identity_assurance, owner, public_key_thumbprint, verification_tier
    expect(canonicalize(vdc)).toBe(
      '{"@context":["https://www.w3.org/2018/credentials/v1","https://schema.parafe.ai/v1"],"credentialSubject":{"agent_id":"prf_agent_abc","agent_name":"Test","id":"did:web:api.parafe.ai:agent:prf_agent_abc","identity_assurance":"registered","owner":"Org","public_key_thumbprint":"deadbeef","verification_tier":"unverified"},"expirationDate":"2026-05-01T00:00:00.000Z","issuanceDate":"2026-04-01T00:00:00.000Z","issuer":"did:web:api.parafe.ai","type":["VerifiableCredential","ParafeIdentityCredential"]}'
    );
  });
});

describe('signingInputForReceipt', () => {
  it('strips signature and receipt_vdc before canonicalizing', () => {
    const receipt = {
      receipt_id: 'rcpt_abc',
      signature: 'zzz',
      receipt_vdc: { should: 'be stripped' },
      issued_at: '2026-04-01T00:00:00.000Z',
    };
    const out = signingInputForReceipt(receipt);
    expect(out).not.toContain('signature');
    expect(out).not.toContain('receipt_vdc');
    expect(out).toBe('{"issued_at":"2026-04-01T00:00:00.000Z","receipt_id":"rcpt_abc"}');
  });
});
