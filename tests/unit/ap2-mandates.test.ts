/**
 * AP2 change request A1: AP2 v0.2 mandate verification.
 *
 * Vectors: tests/fixtures/ap2-sdk-vectors.json (minted and verified by the AP2
 * Python SDK, tests/scripts/generate-ap2-vectors.py), the AP2 spec's encoded
 * examples (ap2-spec-examples.json) and the golden vectors proposed in AP2 PR
 * #307 (ap2-pr307-delegate-sd-jwt-vectors.json). Negative variants are minted
 * here with the SDK vectors' test keys, one per AP2 issue class in A1.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import type { JWK } from 'jose';
import {
  verifyAp2Mandate, verifyAp2Chain, ap2MandateReferences, matchAgentKey, lineItemsSatisfied, merchantMatches,
  type Ap2MandateOptions,
} from '../../src/index.js';
import { checkMandate } from '../../src/ap2/mandate.js';
import { splitChain, parseSegment, verifySegmentSignature, cnfJwk, sdHash } from '../../src/ap2/sdjwt.js';
import { segment, hop, join, pub, sha, sign, disclosure, checkoutJwt } from '../helpers/ap2-mint.js';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../fixtures/${f}`, import.meta.url), 'utf8'));
const fx = load('ap2-sdk-vectors.json');
const spec = load('ap2-spec-examples.json').examples as Record<string, string>;
const pr307 = load('ap2-pr307-delegate-sd-jwt-vectors.json');
const V = Object.fromEntries(fx.vectors.map((v: { id: string }) => [v.id, v])) as Record<string, any>;
const K = fx.keys as Record<'provider' | 'agent' | 'agent2' | 'merchant', JWK>;
const now = new Date(fx.generated_at * 1000);
const trusted = [{ jwk: pub(K.provider), name: 'Test Agent Provider' }];
const base = (o: Partial<Ap2MandateOptions> = {}): Ap2MandateOptions => ({ trustedIssuers: trusted, now, ...o });

describe('AP2 Python SDK vectors: same verdict as the SDK', () => {
  it('human not present, checkout: open mandate → agent-signed closed mandate', async () => {
    const v = V['hnp-checkout'];
    expect(v.sdk).toEqual({ chain_valid: true, violations: [] });
    const r = await verifyAp2Mandate(v.chain, base({ expectedAudience: 'merchant', expectedNonce: v.nonce, checkoutJwt: v.checkout_jwt }));
    expect(r.error).toBeUndefined();
    expect(r).toMatchObject({ valid: true, family: 'checkout', mode: 'human_not_present', audience: 'merchant', nonce: v.nonce, checkoutHash: sha(v.checkout_jwt) });
    expect(r.issuer).toMatchObject({ kid: 'agent-provider-key-1', name: 'Test Agent Provider' });
    expect(r.openSegmentHashes).toEqual([v.open_checkout_hash]);
    expect(r.references?.closedJwt).toBe(v.sdk_reference);
    expect(r.checkout).toMatchObject({ id: 'chk_hnp_1', merchant: { id: 'merchant_1' } });
    expect(await matchAgentKey({ cnf: { jwk: pub(K.agent) } }, r)).toBe(true);
    expect(await matchAgentKey({ cnf: { jwk: pub(K.agent2) } }, r)).toBe(false);
    expect(await matchAgentKey({ cnf: { jwk: pub(K.agent) } }, v.chain)).toBe(true);
  });

  it('human not present, payment, bound to its checkout (transaction_id, payment.reference)', async () => {
    const co = V['hnp-checkout'], v = V['hnp-payment'];
    expect(v.sdk).toEqual({ chain_valid: true, violations: [] });
    const checkout = await verifyAp2Mandate(co.chain, base({ expectedAudience: 'merchant', checkoutJwt: co.checkout_jwt }));
    const r = await verifyAp2Mandate(v.chain, base({ expectedAudience: 'credential-provider', expectedNonce: v.nonce, checkout }));
    expect(r.error).toBeUndefined();
    expect(r).toMatchObject({ valid: true, family: 'payment', mode: 'human_not_present', transactionId: checkout.checkoutHash });
    expect(r.references?.closedJwt).toBe(v.sdk_reference);
    // The same thing with the raw inputs instead of the checkout result.
    const r2 = await verifyAp2Mandate(v.chain, base({ checkoutJwt: v.checkout_jwt, openCheckoutHashes: [v.open_checkout_hash] }));
    expect(r2.valid).toBe(true);
  });

  it('recurring payment: budget and recurrence need the usage context', async () => {
    const v = V['hnp-payment-recurring'];
    const o = base({ checkoutJwt: v.checkout_jwt, openCheckoutHashes: [v.open_checkout_hash] });
    const lastMonth = fx.generated_at - 40 * 86400;
    const ok = await verifyAp2Mandate(v.chain, { ...o, context: { ...v.contexts.within_budget.context, lastUsedAt: lastMonth } });
    expect(v.contexts.within_budget.sdk.violations).toEqual([]);
    expect(ok.error).toBeUndefined();
    const over = await verifyAp2Mandate(v.chain, { ...o, context: { ...v.contexts.over_budget.context, lastUsedAt: lastMonth } });
    expect(v.contexts.over_budget.sdk.violations).toHaveLength(1);
    expect(over.error).toMatchObject({ ap2Error: 'invalid_mandate', reason: 'constraint_failed' });
    expect(over.error?.message).toContain('payment.budget');
    // No context: the SDK reports a violation; we say it can't be evaluated.
    const none = await verifyAp2Mandate(v.chain, o);
    expect(none.error).toMatchObject({ ap2Error: 'unresolved_constraint' });
    // Spec: "sufficiently separated in time … to meet the frequency"; the SDK counts uses only.
    const sameMonth = await verifyAp2Mandate(v.chain, { ...o, context: { totalAmount: 0, totalUses: 1, lastUsedAt: fx.generated_at - 60 } });
    const startOfMonth = new Date(now); startOfMonth.setUTCDate(1); startOfMonth.setUTCHours(0, 0, 0, 0);
    if (fx.generated_at - 60 >= startOfMonth.getTime() / 1000) expect(sameMonth.error?.message).toContain('already used');
    const noLast = await verifyAp2Mandate(v.chain, { ...o, context: { totalAmount: 0, totalUses: 1 } });
    expect(noLast.error).toMatchObject({ ap2Error: 'unresolved_constraint' });
  });

  it('two hops: provider → shopping agent → sub-agent → closed payment; every open mandate applies', async () => {
    const v = V['hnp-payment-two-hops'];
    expect(v.sdk).toMatchObject({ chain_valid: true, payload_count: 3 });
    const r = await verifyAp2Mandate(v.chain, base({ expectedAudience: 'credential-provider', checkoutJwt: v.checkout_jwt, openCheckoutHashes: [v.open_checkout_hash] }));
    expect(r.error).toBeUndefined();
    expect(r.openMandates).toHaveLength(2);
    expect(r.segments.map((s) => s.typ)).toEqual(['example+sd-jwt', 'kb+sd-jwt+kb', 'kb+sd-jwt']);
    expect(await matchAgentKey({ cnf: { jwk: pub(K.agent2) } }, r)).toBe(true);
    expect(r.references?.closedJwt).toBe(v.sdk_reference);
  });

  it('human present: closed mandates signed by the trusted issuer', async () => {
    for (const id of ['hp-checkout', 'hp-payment']) {
      const v = V[id];
      expect(v.sdk.chain_valid).toBe(true);
      const r = await verifyAp2Mandate(v.chain, base({ checkoutJwt: v.checkout_jwt }));
      expect(r.error).toBeUndefined();
      expect(r).toMatchObject({ valid: true, family: v.family, mode: 'human_present' });
      expect(r.agentKey).toBeUndefined();
      expect(r.references?.closedJwt).toBe(v.sdk_reference);
    }
  });

  it('an issuer that is not on the trust list is refused', async () => {
    const r = await verifyAp2Mandate(V['hnp-checkout'].chain, base({ trustedIssuers: [{ jwk: pub(K.merchant) }], checkoutJwt: V['hnp-checkout'].checkout_jwt }));
    expect(r.error).toMatchObject({ ap2Error: 'invalid_credential', reason: 'untrusted_issuer' });
    expect(r.references?.closedJwt).toBe(V['hnp-checkout'].sdk_reference); // a rejection receipt still has its reference
    const none = await verifyAp2Mandate(V['hnp-checkout'].chain, base({ trustedIssuers: [] }));
    expect(none.error?.reason).toBe('untrusted_issuer');
  });
});

describe("AP2 spec's encoded examples (checkout_mandate.md, payment_mandate.md)", () => {
  // The examples publish no key for their root issuer ("agent-provider-key-1"),
  // so the root signature can't be checked; every other rule is.
  const at = new Date(1777342400 * 1000);
  const segs = (name: string) => splitChain(spec[name]!).map((r, i) => parseSegment(r, i));

  it('parse; disclosures resolve to what the docs show', () => {
    const [open, closed] = segs('checkout_chain');
    expect(open!.item).toMatchObject({ vct: 'mandate.checkout.open.1', constraints: [{ type: 'checkout.line_items' }, { type: 'checkout.allowed_merchants', allowed: [{ id: 'merchant_1' }] }] });
    expect(closed!.item).toMatchObject({ vct: 'mandate.checkout.1', checkout_hash: 'NivWhuqfzcvZNapvIEJ2-3tsdQLkiuIcye2g46WVgX8' });
    expect(segs('checkout_open')[0]!.item).toEqual(open!.item);
    expect(segs('payment_chain')[1]!.item).toMatchObject({ vct: 'mandate.payment.1', transaction_id: 'NivWhuqfzcvZNapvIEJ2-3tsdQLkiuIcye2g46WVgX8' });
  });

  it('each hop is signed by the open mandate cnf key and bound by sd_hash', async () => {
    for (const name of ['checkout_chain', 'payment_chain']) {
      const [open, closed] = segs(name);
      expect(await verifySegmentSignature(closed!, cnfJwk(open!)!)).toBe(true);
      expect(closed!.claims.sd_hash).toBe(sdHash(open!));
    }
  });

  it('the examples form one purchase: checkout mandate, then payment mandate', async () => {
    const co = segs('checkout_chain');
    const checkout = { valid: true, openMandates: [], openSegmentHashes: [], payloads: [], segments: [], verifiedAt: '' } as Parameters<typeof checkMandate>[2];
    await checkMandate(co, base({ now: at }), checkout);
    expect(checkout).toMatchObject({ family: 'checkout', mode: 'human_not_present', checkoutHash: 'NivWhuqfzcvZNapvIEJ2-3tsdQLkiuIcye2g46WVgX8' });
    // payment.reference's conditional_transaction_id is the open checkout segment's sd_hash.
    expect(checkout.openSegmentHashes).toEqual(['FzLoxbbtgQGYZxoSM2NJYJtkFTSsdfUBoVEQ12k7JN8']);
    const payment = { valid: false, openMandates: [], openSegmentHashes: [], payloads: [], segments: [], verifiedAt: '' } as Parameters<typeof checkMandate>[2];
    await checkMandate(segs('payment_chain'), base({ now: at, checkout }), payment);
    expect(payment).toMatchObject({ family: 'payment', transactionId: checkout.checkoutHash });
  });

  it('with any trust list the root is refused (its key is not published)', async () => {
    const r = await verifyAp2Mandate(spec.checkout_chain!, base({ now: at }));
    expect(r.error).toMatchObject({ ap2Error: 'invalid_credential', reason: 'untrusted_issuer' });
    expect(r.references).toEqual(ap2MandateReferences(spec.checkout_chain!));
  });
});

describe('AP2 PR #307 golden vectors (chain layer)', () => {
  const at = new Date(1785268700 * 1000);
  const get = (path: (string | number)[], payloads: unknown[]) => path.reduce<unknown>((o, k) => (o as Record<string | number, unknown> | undefined)?.[k], payloads);
  for (const v of pr307.vectors) {
    it(v.id, async () => {
      const o: Parameters<typeof verifyAp2Chain>[1] = { trustedIssuers: [{ jwk: v.root_public_jwk }], now: at };
      if (v.verification.expected_aud) { o.expectedAudience = v.verification.expected_aud; o.expectedNonce = v.verification.expected_nonce; }
      const r = await verifyAp2Chain(v.compact_serialization, o);
      expect(r.error).toBeUndefined();
      expect(r.payloads).toHaveLength(v.expected.hop_count);
      for (const a of v.expected.payload_assertions) {
        if ('equals' in a) expect(get(a.path, r.payloads)).toEqual(a.equals);
        if (a.present) expect(get(a.path, r.payloads)).toBeDefined();
        if (a.absent) expect(get(a.path, r.payloads)).toBeUndefined();
      }
      // They exercise the chain only: as mandates they lack the schema-required
      // constraints and use placeholder hashes, so full verification refuses them.
      const m = await verifyAp2Mandate(v.compact_serialization, { ...o, checkoutHash: 'placeholder' });
      expect(m.valid).toBe(false);
    });
  }
  it('a flipped signature byte or a collapsed ~~ fails', async () => {
    const v = pr307.vectors.find((x: { id: string }) => x.id === 'single-hop-payment-chain');
    const o = { trustedIssuers: [{ jwk: v.root_public_jwk }], now: at };
    const s: string = v.compact_serialization;
    const i = s.lastIndexOf('.') + 5;
    const flipped = s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
    expect((await verifyAp2Chain(flipped, o)).valid).toBe(false);
    expect((await verifyAp2Chain(s.replace('~~', '~'), o)).valid).toBe(false);
  });
});

// ─── Negative tests: one per AP2 issue class (change request A1) ───

const MERCHANT = { id: 'merchant_1', name: 'Demo Merchant', website: 'https://demo-merchant.example' };
const CARD = { id: 'pi_card_4242', type: 'card', description: 'Card 4242' };
const iat = fx.generated_at as number;
const cnf = { jwk: pub(K.agent) };
const lineItemsC = (acceptable: unknown[], quantity = 1) => ({ type: 'checkout.line_items', items: [{ id: 'line_1', quantity, acceptable_items: acceptable }] });
const GOLD = { id: 'sku_gold', title: 'Gold' };

async function mkCheckout(lines: [string, number][], merchant: Record<string, unknown> = MERCHANT) {
  return checkoutJwt({ id: 'chk_1', merchant, currency: 'USD', status: 'ready_for_complete',
    line_items: lines.map(([sku, q]) => ({ id: `li_${sku}`, item: { id: sku, title: sku, price: 1000 }, quantity: q, totals: [] })), totals: [] }, K.merchant);
}

async function checkoutChain(o: {
  constraints?: unknown[]; open?: Record<string, unknown>; closed?: Record<string, unknown>; cj?: string; lines?: [string, number][];
  merchant?: Record<string, unknown>; hopOpts?: Parameters<typeof hop>[3]; openExtra?: string[]; openWithhold?: string[];
} = {}) {
  const cj = o.cj ?? await mkCheckout(o.lines ?? [['sku_gold', 1]], o.merchant);
  const open = await segment({
    mandate: o.open ?? { vct: 'mandate.checkout.open.1', constraints: o.constraints ?? [lineItemsC([GOLD]), { type: 'checkout.allowed_merchants', allowed: [MERCHANT] }], cnf, iat, exp: iat + 3600 },
    key: K.provider, header: { kid: 'agent-provider-key-1' }, extraDisclosures: o.openExtra ?? [], withhold: o.openWithhold ?? [],
  });
  const closed = await hop(open, o.closed ?? { vct: 'mandate.checkout.1', checkout_jwt: cj, checkout_hash: sha(cj), iat }, K.agent, { iat, ...(o.hopOpts ?? {}) });
  return { chain: join(open, closed), cj, open };
}

async function paymentChain(o: { constraints?: unknown[]; closed?: Record<string, unknown>; open?: Record<string, unknown> } = {}) {
  const tx = 'tx-hash-of-checkout';
  const open = await segment({
    mandate: o.open ?? { vct: 'mandate.payment.open.1', cnf, iat, exp: iat + 3600,
      constraints: o.constraints ?? [{ type: 'payment.amount_range', currency: 'USD', max: 5000 }, { type: 'payment.reference', conditional_transaction_id: 'open-co-hash' }] },
    key: K.provider,
  });
  const closed = await hop(open, { vct: 'mandate.payment.1', transaction_id: tx, payee: MERCHANT, payment_amount: { amount: 2500, currency: 'USD' }, payment_instrument: CARD, iat, ...(o.closed ?? {}) }, K.agent, { iat, aud: 'credential-provider' });
  return { chain: join(open, closed), tx, opts: base({ checkoutHash: tx, openCheckoutHashes: ['open-co-hash'] }) };
}

describe('negative: one test per AP2 issue class', () => {
  it('baseline: the minted checkout chain verifies', async () => {
    const { chain, cj } = await checkoutChain();
    const r = await verifyAp2Mandate(chain, base({ expectedAudience: 'merchant', expectedNonce: 'nonce-1', checkoutJwt: cj }));
    expect(r.error).toBeUndefined();
  });

  it('#319/#342: a terminal hop without aud or nonce fails even when no audience or nonce is expected', async () => {
    const noAud = await checkoutChain({ hopOpts: { aud: null } });
    expect((await verifyAp2Mandate(noAud.chain, base())).error).toMatchObject({ ap2Error: 'invalid_credential', reason: 'missing_audience' });
    const noNonce = await checkoutChain({ hopOpts: { nonce: null } });
    expect((await verifyAp2Mandate(noNonce.chain, base())).error).toMatchObject({ ap2Error: 'invalid_credential', reason: 'missing_nonce' });
    const { chain } = await checkoutChain();
    expect((await verifyAp2Mandate(chain, base({ expectedAudience: 'other-merchant' }))).error?.reason).toBe('audience_mismatch');
    expect((await verifyAp2Mandate(chain, base({ expectedNonce: 'other' }))).error?.reason).toBe('nonce_mismatch');
  });

  it('#298: empty acceptable_items is not a wildcard, and quantities are filled exactly', async () => {
    const empty = await checkoutChain({ constraints: [lineItemsC([])] });
    expect((await verifyAp2Mandate(empty.chain, base())).error).toMatchObject({ ap2Error: 'invalid_mandate', reason: 'constraint_failed' });
    const under = await checkoutChain({ constraints: [lineItemsC([GOLD], 2)] });
    expect((await verifyAp2Mandate(under.chain, base())).error?.message).toContain('line_items');
    const extra = await checkoutChain({ lines: [['sku_gold', 1], ['sku_other', 1]] });
    expect((await verifyAp2Mandate(extra.chain, base())).error?.reason).toBe('constraint_failed');
    // Undisclosed acceptable items are the design; a revealed one still matches.
    const dGold = disclosure(GOLD), dSilver = disclosure({ id: 'sku_silver', title: 'Silver' });
    const partial = await checkoutChain({
      constraints: [{ type: 'checkout.line_items', items: [{ id: 'line_1', quantity: 1, acceptable_items: [{ '...': sha(dGold) }, { '...': sha(dSilver) }] }] }],
      openExtra: [dGold, dSilver], openWithhold: [dSilver],
    });
    expect((await verifyAp2Mandate(partial.chain, base())).error).toBeUndefined();
    expect(lineItemsSatisfied([{ accepts: new Set(['a', 'b']), quantity: 1 }, { accepts: new Set(['a']), quantity: 1 }], new Map([['a', 1], ['b', 1]]))).toBe(true);
    expect(lineItemsSatisfied([{ accepts: new Set(['a']), quantity: 1 }, { accepts: new Set(['a']), quantity: 1 }], new Map([['a', 1], ['b', 1]]))).toBe(false);
  });

  it('#315: merchants match by id, never by display name and website', async () => {
    const lookalike = { id: 'merchant_evil', name: MERCHANT.name, website: MERCHANT.website };
    const r = await checkoutChain({ merchant: lookalike });
    expect((await verifyAp2Mandate(r.chain, base())).error?.message).toContain('allowed_merchants');
    expect(merchantMatches({ id: '', name: MERCHANT.name, website: MERCHANT.website }, { id: '', name: MERCHANT.name, website: MERCHANT.website })).toBe(false);
    const payee = await paymentChain({ closed: { payee: lookalike }, constraints: [{ type: 'payment.allowed_payees', allowed: [MERCHANT] }, { type: 'payment.reference', conditional_transaction_id: 'open-co-hash' }] });
    expect((await verifyAp2Mandate(payee.chain, payee.opts)).error?.message).toContain('allowed_payees');
  });

  it('#358: the closed checkout mandate is bound to the Checkout JWT presented', async () => {
    const otherCj = await mkCheckout([['sku_gold', 1]]);
    const { chain, cj } = await checkoutChain();
    expect((await verifyAp2Mandate(chain, base({ checkoutJwt: otherCj }))).error?.reason).toBe('checkout_hash_mismatch');
    // checkout_jwt withheld: the verifier must bring it, and it must hash to checkout_hash.
    const dJwt = disclosure('checkout_jwt', cj);
    const open = await segment({ mandate: { vct: 'mandate.checkout.open.1', constraints: [lineItemsC([GOLD])], cnf, iat, exp: iat + 3600 }, key: K.provider });
    const closed = await hop(open, { vct: 'mandate.checkout.1', _sd: [sha(dJwt)], checkout_hash: sha(cj), iat }, K.agent, { iat });
    const withheld = join(open, closed);
    expect((await verifyAp2Mandate(withheld, base())).error?.reason).toBe('checkout_jwt_required');
    expect((await verifyAp2Mandate(withheld, base({ checkoutJwt: otherCj }))).error?.reason).toBe('checkout_hash_mismatch');
    expect((await verifyAp2Mandate(withheld, base({ checkoutJwt: cj }))).error).toBeUndefined();
  });

  it('#320: payment instruments match by id and type', async () => {
    const p = await paymentChain({
      closed: { payment_instrument: { id: CARD.id, type: 'bank_account' } },
      constraints: [{ type: 'payment.allowed_payment_instruments', allowed: [CARD] }, { type: 'payment.reference', conditional_transaction_id: 'open-co-hash' }],
    });
    expect((await verifyAp2Mandate(p.chain, p.opts)).error?.message).toContain('allowed_payment_instruments');
  });

  it('#339: a withheld constraint (or withheld claim of an open mandate) is refused', async () => {
    const dAmount = disclosure({ type: 'payment.amount_range', currency: 'USD', max: 100 });
    const hidden = await segment({
      mandate: { vct: 'mandate.payment.open.1', cnf, iat, exp: iat + 3600, constraints: [{ '...': sha(dAmount) }, { type: 'payment.reference', conditional_transaction_id: 'open-co-hash' }] },
      key: K.provider, extraDisclosures: [dAmount], withhold: [dAmount],
    });
    const closed = await hop(hidden, { vct: 'mandate.payment.1', transaction_id: 'tx', payee: MERCHANT, payment_amount: { amount: 999999, currency: 'USD' }, payment_instrument: CARD, iat }, K.agent, { iat });
    const r = await verifyAp2Mandate(join(hidden, closed), base({ checkoutHash: 'tx', openCheckoutHashes: ['open-co-hash'] }));
    expect(r.error).toMatchObject({ ap2Error: 'unresolved_constraint', reason: 'withheld_disclosure' });
    // Disclosed, the same constraint refuses the amount.
    const shown = await segment({
      mandate: { vct: 'mandate.payment.open.1', cnf, iat, exp: iat + 3600, constraints: [{ '...': sha(dAmount) }, { type: 'payment.reference', conditional_transaction_id: 'open-co-hash' }] },
      key: K.provider, extraDisclosures: [dAmount],
    });
    const closed2 = await hop(shown, { vct: 'mandate.payment.1', transaction_id: 'tx', payee: MERCHANT, payment_amount: { amount: 999999, currency: 'USD' }, payment_instrument: CARD, iat }, K.agent, { iat });
    expect((await verifyAp2Mandate(join(shown, closed2), base({ checkoutHash: 'tx', openCheckoutHashes: ['open-co-hash'] }))).error?.message).toContain('amount_range');
    // A withheld property of the open mandate (here the whole constraints list).
    const dList = disclosure('constraints', [{ type: 'payment.amount_range', currency: 'USD', max: 100 }]);
    const noList = await segment({ mandate: { vct: 'mandate.payment.open.1', cnf, iat, _sd: [sha(dList)] }, key: K.provider, extraDisclosures: [dList], withhold: [dList] });
    const closed3 = await hop(noList, { vct: 'mandate.payment.1', transaction_id: 'tx', payee: MERCHANT, payment_amount: { amount: 5, currency: 'USD' }, payment_instrument: CARD, iat }, K.agent, { iat });
    expect((await verifyAp2Mandate(join(noList, closed3), base({ checkoutHash: 'tx' }))).error?.reason).toBe('withheld_disclosure');
  });

  it('an unknown constraint fails as unresolved_constraint', async () => {
    const r = await checkoutChain({ constraints: [lineItemsC([GOLD]), { type: 'checkout.max_weight', kg: 3 }] });
    expect((await verifyAp2Mandate(r.chain, base())).error).toMatchObject({ ap2Error: 'unresolved_constraint', reason: 'unknown_constraint' });
    const p = await paymentChain({ constraints: [{ type: 'payment.reference', conditional_transaction_id: 'open-co-hash' }, { type: 'checkout.line_items', items: [] }] });
    expect((await verifyAp2Mandate(p.chain, p.opts)).error?.reason).toBe('unknown_constraint');
  });

  it('the vct must match exactly, version suffix included', async () => {
    for (const vct of ['mandate.checkout.open.2', 'mandate.checkout.open', 'mandate.checkout.open.1.0']) {
      const r = await checkoutChain({ open: { vct, constraints: [lineItemsC([GOLD])], cnf, iat } });
      expect((await verifyAp2Mandate(r.chain, base())).error).toMatchObject({ ap2Error: 'invalid_mandate', reason: 'wrong_vct' });
    }
    const cj = await mkCheckout([['sku_gold', 1]]);
    const closed = await checkoutChain({ closed: { vct: 'mandate.checkout.2', checkout_jwt: cj, checkout_hash: sha(cj) }, cj });
    expect((await verifyAp2Mandate(closed.chain, base())).error?.reason).toBe('wrong_vct');
  });

  it('#346: the same closed mandate presented twice has the same references (the broker refuses the second)', async () => {
    const v = V['hnp-checkout'];
    const a = await verifyAp2Mandate(v.chain, base({ checkoutJwt: v.checkout_jwt }));
    const b = await verifyAp2Mandate(v.chain, base({ checkoutJwt: v.checkout_jwt }));
    expect(a.valid && b.valid).toBe(true); // offline verification is stateless
    expect(a.references).toEqual(b.references);
  });
});

describe('negative: chain integrity', () => {
  it('a tampered disclosure, signature or binding fails', async () => {
    const { chain, cj } = await checkoutChain();
    const [open, closed] = splitChain(chain);
    // Change the open mandate's disclosure: its digest no longer matches the signed one.
    const parts = open!.split('~');
    const item = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
    item[1].constraints[0].items[0].quantity = 5;
    parts[1] = Buffer.from(JSON.stringify(item)).toString('base64url');
    const tampered = join(parts.join('~'), closed!);
    expect((await verifyAp2Mandate(tampered, base({ checkoutJwt: cj }))).error).toMatchObject({ ap2Error: 'invalid_credential' });
    // A hop signed by a key the open mandate didn't endorse.
    const wrongKey = await hop(open!, { vct: 'mandate.checkout.1', checkout_jwt: cj, checkout_hash: sha(cj), iat }, K.agent2, { iat });
    expect((await verifyAp2Mandate(join(open!, wrongKey), base())).error?.reason).toBe('signature');
    // A hop bound to another root.
    const other = await checkoutChain();
    const [, otherClosed] = splitChain(other.chain);
    expect((await verifyAp2Mandate(join(open!, otherClosed!), base())).error?.reason).toBe('binding_mismatch');
    // Wrong typ for a terminal hop.
    const badTyp = await hop(open!, { vct: 'mandate.checkout.1', checkout_jwt: cj, checkout_hash: sha(cj), iat }, K.agent, { iat, typ: 'JWT' });
    expect((await verifyAp2Mandate(join(open!, badTyp), base())).error?.reason).toBe('typ');
  });

  it('an expired open mandate, or a stale presentation, fails', async () => {
    const r = await checkoutChain({ open: { vct: 'mandate.checkout.open.1', constraints: [lineItemsC([GOLD])], cnf, iat: iat - 7200, exp: iat - 3600 } });
    expect((await verifyAp2Mandate(r.chain, base())).error?.reason).toBe('expired');
    const fresh = await checkoutChain({ hopOpts: { iat: iat - 3600 } });
    expect((await verifyAp2Mandate(fresh.chain, base({ maxPresentationAgeSec: 300 }))).error?.reason).toBe('stale');
  });

  it('shape: a chain ending in an open mandate, or mixing families, fails', async () => {
    const open = await segment({ mandate: { vct: 'mandate.checkout.open.1', constraints: [lineItemsC([GOLD])], cnf, iat }, key: K.provider });
    expect((await verifyAp2Mandate(open, base())).error?.reason).toBe('chain_shape');
    const mixed = await hop(open, { vct: 'mandate.payment.1', transaction_id: 't', payee: MERCHANT, payment_amount: { amount: 1, currency: 'USD' }, payment_instrument: CARD, iat }, K.agent, { iat });
    expect((await verifyAp2Mandate(join(open, mixed), base({ checkoutHash: 't' }))).error?.reason).toBe('chain_shape');
  });

  it('claims set by the open mandate reach the closed mandate unchanged', async () => {
    const p = await paymentChain({
      open: { vct: 'mandate.payment.open.1', cnf, iat, payee: MERCHANT, payment_amount: { amount: 2000, currency: 'USD' }, constraints: [{ type: 'payment.reference', conditional_transaction_id: 'open-co-hash' }] },
    });
    expect((await verifyAp2Mandate(p.chain, p.opts)).error).toMatchObject({ ap2Error: 'invalid_mandate', reason: 'preset_mismatch' });
  });

  it('payment: transaction_id and payment.reference are checked', async () => {
    const p = await paymentChain();
    expect((await verifyAp2Mandate(p.chain, p.opts)).error).toBeUndefined();
    expect((await verifyAp2Mandate(p.chain, base({ openCheckoutHashes: ['open-co-hash'] }))).error?.reason).toBe('transaction_id_unchecked');
    expect((await verifyAp2Mandate(p.chain, base({ checkoutHash: 'other', openCheckoutHashes: ['open-co-hash'] }))).error?.reason).toBe('transaction_id_mismatch');
    expect((await verifyAp2Mandate(p.chain, base({ checkoutHash: p.tx, openCheckoutHashes: ['another'] }))).error?.message).toContain('payment.reference');
    expect((await verifyAp2Mandate(p.chain, base({ checkoutHash: p.tx }))).error?.ap2Error).toBe('unresolved_constraint');
    const noRef = await paymentChain({ constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 5000 }] });
    expect((await verifyAp2Mandate(noRef.chain, noRef.opts)).error?.reason).toBe('constraint_missing');
  });

  it('payment: amount range, PISPs and execution date', async () => {
    const ref = { type: 'payment.reference', conditional_transaction_id: 'open-co-hash' };
    const over = await paymentChain({ constraints: [{ type: 'payment.amount_range', currency: 'USD', min: 3000, max: 5000 }, ref] });
    expect((await verifyAp2Mandate(over.chain, over.opts)).error?.message).toContain('below');
    const eur = await paymentChain({ constraints: [{ type: 'payment.amount_range', currency: 'EUR', max: 5000 }, ref] });
    expect((await verifyAp2Mandate(eur.chain, eur.opts)).error?.message).toContain('currency');
    const pisp = { legal_name: 'Example Payment Services Ltd.', brand_name: 'ExamplePay', domain_name: 'examplepay.com' };
    const okPisp = await paymentChain({ closed: { pisp }, constraints: [{ type: 'payment.allowed_pisps', allowed: [pisp] }, ref] });
    expect((await verifyAp2Mandate(okPisp.chain, okPisp.opts)).error).toBeUndefined();
    const badPisp = await paymentChain({ closed: { pisp: { ...pisp, domain_name: 'evilpay.com' } }, constraints: [{ type: 'payment.allowed_pisps', allowed: [pisp] }, ref] });
    expect((await verifyAp2Mandate(badPisp.chain, badPisp.opts)).error?.message).toContain('allowed_pisps');
    const late = await paymentChain({ closed: { execution_date: '2027-01-01T00:00:00Z' }, constraints: [{ type: 'payment.execution_date', not_after: '2026-12-31T23:59:59Z' }, ref] });
    expect((await verifyAp2Mandate(late.chain, late.opts)).error?.message).toContain('execution_date');
  });
});

describe('Phase 3 review fixes', () => {
  it('P-36: an AP2 SDK mandate with decoy digests is refused (a decoy looks like a withheld claim); the SDK accepts it', async () => {
    const v = V['hnp-checkout-decoys'];
    expect(v.sdk).toEqual({ chain_valid: true, violations: [] });
    const r = await verifyAp2Mandate(v.chain, base({ checkoutJwt: v.checkout_jwt }));
    expect(r.error).toMatchObject({ ap2Error: 'unresolved_constraint', reason: 'withheld_disclosure' });
    expect(r.error?.message).toContain('decoy');
    // The chain itself is sound.
    expect((await verifyAp2Chain(v.chain, base())).valid).toBe(true);
  });

  it('S-53: says who signed the closed mandate', async () => {
    const hnp = await verifyAp2Mandate(V['hnp-checkout'].chain, base({ checkoutJwt: V['hnp-checkout'].checkout_jwt }));
    expect(hnp).toMatchObject({ closedBy: 'open_mandate_key', closedByKeyThumbprint: hnp.agentKeyThumbprint });
    const hp = await verifyAp2Mandate(V['hp-checkout'].chain, base({ checkoutJwt: V['hp-checkout'].checkout_jwt }));
    expect(hp.closedBy).toBe('issuer');
    expect(hp.closedByKey).toBeUndefined();
    // User Credential model: a root credential whose cnf is the holder's key, then the holder's hop.
    const cj = await mkCheckout([['sku_gold', 1]]);
    const cred = `${await sign({ iss: 'https://bank.example', vct: 'com.emvco.dpc', cnf: { jwk: pub(K.agent2) }, iat }, K.provider, { kid: 'agent-provider-key-1' })}~`;
    const hop1 = await hop(cred, { vct: 'mandate.checkout.1', checkout_jwt: cj, checkout_hash: sha(cj), iat }, K.agent2, { iat });
    const uc = await verifyAp2Mandate(join(cred, hop1), base());
    expect(uc.error).toBeUndefined();
    expect(uc).toMatchObject({ mode: 'human_present', closedBy: 'credential_holder' });
    expect(uc.closedByKey).toEqual(pub(K.agent2));
  });

  it('S-59: says who signed the first open mandate (the limits)', async () => {
    // Root = the open mandate, signed by the issuer.
    const hnp = await verifyAp2Mandate(V['hnp-checkout'].chain, base({ checkoutJwt: V['hnp-checkout'].checkout_jwt }));
    expect(hnp.openedBy).toBe('issuer');
    expect(hnp.openedByKey).toBeUndefined();
    const hp = await verifyAp2Mandate(V['hp-checkout'].chain, base({ checkoutJwt: V['hp-checkout'].checkout_jwt }));
    expect(hp.openedBy).toBeUndefined();
    // User Credential model: a root credential certifies a key; that key signs the open mandate; the agent closes it.
    const cj = await mkCheckout([['sku_gold', 1]]);
    const cred = `${await sign({ iss: 'https://bank.example', vct: 'com.emvco.dpc', cnf: { jwk: pub(K.agent2) }, iat }, K.provider, { kid: 'agent-provider-key-1' })}~`;
    const open = await hop(cred, {
      vct: 'mandate.checkout.open.1', cnf: { jwk: pub(K.agent) }, iat,
      constraints: [{ type: 'checkout.line_items', items: [{ id: 'l1', quantity: 1, acceptable_items: [{ id: 'sku_gold', title: 'Gold' }] }] }],
    }, K.agent2, { iat });
    const closed = await hop(open, { vct: 'mandate.checkout.1', checkout_jwt: cj, checkout_hash: sha(cj), iat }, K.agent, { iat });
    const uc = await verifyAp2Mandate(join(cred, open, closed), base());
    expect(uc.error).toBeUndefined();
    expect(uc).toMatchObject({ mode: 'human_not_present', openedBy: 'credential_holder', closedBy: 'open_mandate_key' });
    expect(uc.openedByKey).toEqual(pub(K.agent2));
    expect(uc.agentKey).toEqual(pub(K.agent));
  });

  it("S-53: a Parafé agent identity credential can't be a mandate's root", async () => {
    const cj = await mkCheckout([['sku_gold', 1]]);
    const cred = `${await sign({ iss: 'did:web:broker.test', vct: 'https://parafe.ai/vct/agent-identity/1', sub: 'did:web:broker.test:agents:prf_agent_x', cnf: { jwk: pub(K.agent) }, iat }, K.provider, { typ: 'dc+sd-jwt' })}~`;
    const closed = await hop(cred, { vct: 'mandate.checkout.1', checkout_jwt: cj, checkout_hash: sha(cj), iat }, K.agent, { iat });
    const r = await verifyAp2Mandate(join(cred, closed), base());
    expect(r.error).toMatchObject({ ap2Error: 'invalid_credential', reason: 'agent_credential_root' });
  });

  it('S-56: an oversized line_items constraint is unresolved, quickly', async () => {
    const reqs = Array.from({ length: 150 }, (_, i) => ({ id: `r${i}`, quantity: 1, acceptable_items: [{ id: `sku_${i}`, title: 't' }] }));
    const r = await checkoutChain({ constraints: [{ type: 'checkout.line_items', items: reqs }], lines: reqs.map((x, i) => [`sku_${i}`, 1] as [string, number]) });
    const t0 = performance.now();
    const res = await verifyAp2Mandate(r.chain, base());
    expect(res.error).toMatchObject({ ap2Error: 'unresolved_constraint', reason: 'constraint_unresolved' });
    expect(performance.now() - t0).toBeLessThan(500);
    // At the limit: a full 100×100 bipartite graph (every requirement accepts every SKU) is fast.
    const all = Array.from({ length: 10 }, (_, i) => ({ id: `sku_${i}`, title: 't' }));
    const cart = new Map(all.map((a) => [a.id, 10]));
    const t1 = performance.now();
    expect(lineItemsSatisfied(Array.from({ length: 100 }, () => ({ accepts: new Set(all.map((a) => a.id)), quantity: 1 })), cart)).toBe(true);
    expect(performance.now() - t1).toBeLessThan(200);
  });
});
