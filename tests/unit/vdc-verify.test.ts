import { describe, it, expect } from 'vitest';
import { verifyCredentialVDC, verifyConsentVDC, verifyReceiptVDC } from '../../src/vdc-verify.js';
import { verifyCredential, verifyConsent, verifyReceipt } from '../../src/verify.js';
import { createTestKeyring, mintIdentityVDC, mintConsentVDC, mintReceiptVDC } from '../helpers/mint.js';

describe('verifyCredentialVDC', () => {
  it('verifies a valid identity VDC', async () => {
    const kr = await createTestKeyring();
    const vdc = mintIdentityVDC({ nodePrivateKey: kr.nodePrivateKey, agent_id: 'prf_agent_x' });
    const result = await verifyCredentialVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('vdc');
    expect(result.claims?.sub).toBe('prf_agent_x');
    expect(result.keyId).toBe(kr.keyId);
  });

  it('rejects a tampered credentialSubject', async () => {
    const kr = await createTestKeyring();
    const vdc = mintIdentityVDC({
      nodePrivateKey: kr.nodePrivateKey,
      agent_id: 'prf_agent_original',
      mutateAfterSigning: (v) => {
        (v['credentialSubject'] as Record<string, unknown>)['agent_id'] = 'prf_agent_attacker';
      },
    });
    const result = await verifyCredentialVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('INVALID_SIGNATURE');
  });

  it('rejects the wrong VDC type', async () => {
    const kr = await createTestKeyring();
    const consent = mintConsentVDC({ nodePrivateKey: kr.nodePrivateKey });
    const result = await verifyCredentialVDC(consent, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('WRONG_ARTIFACT_TYPE');
  });

  it('rejects an expired VDC', async () => {
    const kr = await createTestKeyring();
    const vdc = mintIdentityVDC({
      nodePrivateKey: kr.nodePrivateKey,
      issuanceDate: new Date(Date.now() - 7200 * 1000).toISOString(),
      expirationDate: new Date(Date.now() - 3600 * 1000).toISOString(),
    });
    const result = await verifyCredentialVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('EXPIRED');
  });

  it('rejects a VDC signed by a different key', async () => {
    const signerKr = await createTestKeyring();
    const verifierKr = await createTestKeyring();
    const vdc = mintIdentityVDC({ nodePrivateKey: signerKr.nodePrivateKey });
    const result = await verifyCredentialVDC(vdc, { key: verifierKr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('INVALID_SIGNATURE');
  });

  it('rejects when issuer does not match did:web prefix', async () => {
    const kr = await createTestKeyring();
    const vdc = mintIdentityVDC({ nodePrivateKey: kr.nodePrivateKey, issuer: 'urn:evil:issuer' });
    const result = await verifyCredentialVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('ISSUER_MISMATCH');
  });

  it('rejects a VDC whose issuanceDate is in the future', async () => {
    const kr = await createTestKeyring();
    const vdc = mintIdentityVDC({
      nodePrivateKey: kr.nodePrivateKey,
      issuanceDate: new Date(Date.now() + 3600 * 1000).toISOString(),
      expirationDate: new Date(Date.now() + 7200 * 1000).toISOString(),
    });
    const result = await verifyCredentialVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('NOT_YET_VALID');
  });

  it('rejects a VDC missing the proof field', async () => {
    const kr = await createTestKeyring();
    const vdc = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'ParafeIdentityCredential'],
      issuer: 'did:web:api.parafe.ai',
      issuanceDate: new Date().toISOString(),
      credentialSubject: { id: 'did:web:x' },
    };
    const result = await verifyCredentialVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('MALFORMED');
  });
});

describe('verifyConsentVDC', () => {
  it('verifies a valid consent VDC', async () => {
    const kr = await createTestKeyring();
    const vdc = mintConsentVDC({
      nodePrivateKey: kr.nodePrivateKey,
      scope: 'read_bookings',
      permissions: ['read:bookings'],
    });
    const result = await verifyConsentVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.claims?.scope).toBe('read_bookings');
    expect(result.claims?.permissions).toEqual(['read:bookings']);
    expect(result.claims?.token_type).toBe('consent');
  });

  it('rejects an identity VDC passed to verifyConsent', async () => {
    const kr = await createTestKeyring();
    const vdc = mintIdentityVDC({ nodePrivateKey: kr.nodePrivateKey });
    const result = await verifyConsentVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('WRONG_ARTIFACT_TYPE');
  });
});

describe('verifyReceiptVDC', () => {
  it('verifies a valid receipt VDC', async () => {
    const kr = await createTestKeyring();
    const vdc = mintReceiptVDC({ nodePrivateKey: kr.nodePrivateKey, receipt_id: 'rcpt_test_vdc' });
    const result = await verifyReceiptVDC(vdc, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect((result.claims as unknown as { receipt_id: string })?.receipt_id).toBe('rcpt_test_vdc');
  });
});

describe('auto-detect routing for VDC/receipt', () => {
  it('routes identity VDCs to verifyCredentialVDC', async () => {
    const kr = await createTestKeyring();
    const vdc = mintIdentityVDC({ nodePrivateKey: kr.nodePrivateKey });
    const result = await verifyCredential(vdc, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('vdc');
  });

  it('routes consent VDCs to verifyConsentVDC', async () => {
    const kr = await createTestKeyring();
    const vdc = mintConsentVDC({ nodePrivateKey: kr.nodePrivateKey });
    const result = await verifyConsent(vdc, { key: kr.keySource });
    expect(result.valid).toBe(true);
  });

  it('routes receipt VDCs to verifyReceiptVDC', async () => {
    const kr = await createTestKeyring();
    const vdc = mintReceiptVDC({ nodePrivateKey: kr.nodePrivateKey });
    const result = await verifyReceipt(vdc, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('vdc');
  });
});
