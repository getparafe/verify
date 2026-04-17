import { describe, it, expect } from 'vitest';
import { verifySignedReceipt } from '../../src/receipt-verify.js';
import { verifyReceipt } from '../../src/verify.js';
import { createTestKeyring, mintSignedReceipt } from '../helpers/mint.js';

describe('verifySignedReceipt', () => {
  it('verifies a valid receipt', async () => {
    const kr = await createTestKeyring();
    const receipt = mintSignedReceipt({ nodePrivateKey: kr.nodePrivateKey, receipt_id: 'rcpt_valid_1' });
    const result = await verifySignedReceipt(receipt, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('receipt');
    expect(result.claims?.receipt_id).toBe('rcpt_valid_1');
  });

  it('rejects a tampered receipt field (post-signing mutation)', async () => {
    const kr = await createTestKeyring();
    const receipt = mintSignedReceipt({ nodePrivateKey: kr.nodePrivateKey });
    (receipt as Record<string, unknown>)['receipt_id'] = 'rcpt_attacker';
    const result = await verifySignedReceipt(receipt, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('INVALID_SIGNATURE');
  });

  it('rejects a tampered signature', async () => {
    const kr = await createTestKeyring();
    const receipt = mintSignedReceipt({ nodePrivateKey: kr.nodePrivateKey }) as Record<string, unknown>;
    const sig = receipt['signature'] as string;
    receipt['signature'] = sig.slice(0, -4) + (sig.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
    const result = await verifySignedReceipt(receipt, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('INVALID_SIGNATURE');
  });

  it('rejects a receipt missing required fields', async () => {
    const kr = await createTestKeyring();
    const result = await verifySignedReceipt({ receipt_id: 'incomplete', signature: 'xxx' }, { key: kr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('MALFORMED');
  });

  it('rejects a receipt signed by a different key', async () => {
    const signerKr = await createTestKeyring();
    const verifierKr = await createTestKeyring();
    const receipt = mintSignedReceipt({ nodePrivateKey: signerKr.nodePrivateKey });
    const result = await verifySignedReceipt(receipt, { key: verifierKr.keySource });
    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe('INVALID_SIGNATURE');
  });

  it('ignores receipt_vdc field when verifying signature', async () => {
    // Broker strips signature + receipt_vdc before signing. We must do the same.
    const kr = await createTestKeyring();
    const receipt = mintSignedReceipt({ nodePrivateKey: kr.nodePrivateKey }) as Record<string, unknown>;
    receipt['receipt_vdc'] = { should: 'be ignored' };
    const result = await verifySignedReceipt(receipt, { key: kr.keySource });
    expect(result.valid).toBe(true);
  });
});

describe('verifyReceipt (auto-detect)', () => {
  it('routes signed receipts to verifySignedReceipt', async () => {
    const kr = await createTestKeyring();
    const receipt = mintSignedReceipt({ nodePrivateKey: kr.nodePrivateKey });
    const result = await verifyReceipt(receipt, { key: kr.keySource });
    expect(result.valid).toBe(true);
    expect(result.format).toBe('receipt');
  });
});
