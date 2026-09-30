/**
 * AP2 v0.2 constraint evaluation (checkout_mandate.md, payment_mandate.md).
 *
 * Deliberately stricter than the AP2 Python SDK where the SDK has open issues:
 * - merchants and payees match by a non-empty `id` only, never by display name
 *   or website (#315);
 * - payment instruments match by `id` AND `type` (#320);
 * - a `checkout.line_items` requirement with no revealed `acceptable_items`
 *   matches nothing, and each requirement's quantity must be filled exactly
 *   (#298: the SDK treats an empty list as a wildcard and quantity as a cap);
 * - budget and recurrence need the caller's usage context, else unresolved.
 * Unknown constraint types are `unresolved_constraint` (agent_authorization.md).
 */
import type { Ap2MandateContext } from './types.js';

export interface ConstraintOutcome {
  /** Failed constraints: `invalid_mandate`. */
  violations: string[];
  /** Constraints that couldn't be evaluated: `unresolved_constraint`. */
  unresolved: string[];
}

export const CHECKOUT_CONSTRAINTS = ['checkout.allowed_merchants', 'checkout.line_items'];
export const PAYMENT_CONSTRAINTS = [
  'payment.agent_recurrence', 'payment.allowed_payees', 'payment.allowed_payment_instruments', 'payment.allowed_pisps',
  'payment.amount_range', 'payment.budget', 'payment.execution_date', 'payment.reference',
];

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v);

/** Merchants (and payees) match by a non-empty `id`, nothing else (#315). */
export function merchantMatches(allowed: unknown, actual: unknown): boolean {
  return isObj(allowed) && isObj(actual) && nonEmpty(allowed.id) && allowed.id === actual.id;
}

/** ISO 4217 minor-unit digits for the few currencies that aren't 2. */
const MINOR_DIGITS: Record<string, number> = {
  BIF: 0, CLP: 0, DJF: 0, GNF: 0, ISK: 0, JPY: 0, KMF: 0, KRW: 0, PYG: 0, RWF: 0, UGX: 0, UYI: 0, VND: 0, VUV: 0, XAF: 0, XOF: 0, XPF: 0,
  BHD: 3, IQD: 3, JOD: 3, KWD: 3, LYD: 3, OMR: 3, TND: 3, CLF: 4, UYW: 4,
};
export function toMinorUnits(major: number, currency: string): number {
  return Math.round(major * 10 ** (MINOR_DIGITS[currency.toUpperCase()] ?? 2));
}

/**
 * `checkout.line_items` as a maximum flow (checkout_mandate.md): source → each
 * requirement (capacity = quantity) → each checkout item ID it accepts (∞) →
 * sink (capacity = that ID's total quantity). Met when the flow equals both the
 * total required quantity and the total checkout quantity.
 */
export function lineItemsSatisfied(requirements: { accepts: Set<string>; quantity: number }[], cart: Map<string, number>): boolean {
  const need = requirements.reduce((a, r) => a + r.quantity, 0);
  const have = [...cart.values()].reduce((a, q) => a + q, 0);
  if (need !== have) return false;
  const skus = [...cart.keys()];
  const R = requirements.length;
  const N = 2 + R + skus.length;
  const S = 0, T = N - 1;
  const cap: number[][] = Array.from({ length: N }, () => new Array<number>(N).fill(0));
  requirements.forEach((r, i) => {
    cap[S]![1 + i] = r.quantity;
    skus.forEach((sku, j) => { if (r.accepts.has(sku)) cap[1 + i]![1 + R + j] = Number.MAX_SAFE_INTEGER; });
  });
  skus.forEach((sku, j) => { cap[1 + R + j]![T] = cart.get(sku)!; });
  let flow = 0;
  for (;;) { // Edmonds–Karp
    const prev = new Array<number>(N).fill(-1);
    prev[S] = S;
    const queue = [S];
    while (queue.length && prev[T] === -1) {
      const u = queue.shift()!;
      for (let v = 0; v < N; v++) if (prev[v] === -1 && cap[u]![v]! > 0) { prev[v] = u; queue.push(v); }
    }
    if (prev[T] === -1) break;
    let bottleneck = Number.MAX_SAFE_INTEGER;
    for (let v = T; v !== S; v = prev[v]!) bottleneck = Math.min(bottleneck, cap[prev[v]!]![v]!);
    for (let v = T; v !== S; v = prev[v]!) { cap[prev[v]!]![v]! -= bottleneck; cap[v]![prev[v]!]! += bottleneck; }
    flow += bottleneck;
  }
  return flow === need;
}

function evalCheckout(c: Obj, checkout: Obj, out: ConstraintOutcome): void {
  switch (c.type) {
    case 'checkout.allowed_merchants': {
      const allowed = Array.isArray(c.allowed) ? c.allowed : [];
      if (!allowed.length) { out.violations.push('checkout.allowed_merchants: no merchant is revealed'); return; }
      if (!isObj(checkout.merchant)) { out.violations.push('checkout.allowed_merchants: the checkout names no merchant'); return; }
      if (!allowed.some((m) => merchantMatches(m, checkout.merchant))) {
        out.violations.push(`checkout.allowed_merchants: merchant "${String((checkout.merchant as Obj).id ?? '')}" is not allowed (matched by id)`);
      }
      return;
    }
    case 'checkout.line_items': {
      const items = Array.isArray(c.items) ? c.items : [];
      if (!items.length) { out.violations.push('checkout.line_items: no requirements'); return; }
      const reqs: { accepts: Set<string>; quantity: number }[] = [];
      for (const it of items) {
        if (!isObj(it) || !isInt(it.quantity) || it.quantity <= 0) { out.violations.push('checkout.line_items: a requirement needs a positive integer quantity'); return; }
        const acc = Array.isArray(it.acceptable_items) ? it.acceptable_items : [];
        reqs.push({ accepts: new Set(acc.filter(isObj).map((a) => a.id).filter(nonEmpty)), quantity: it.quantity });
      }
      if (reqs.some((r) => r.accepts.size === 0)) out.violations.push('checkout.line_items: a requirement reveals no acceptable item (an empty list matches nothing)');
      const lines = Array.isArray(checkout.line_items) ? checkout.line_items : [];
      const cart = new Map<string, number>();
      for (const li of lines) {
        const id = isObj(li) && isObj(li.item) ? li.item.id : undefined;
        if (!isObj(li) || !nonEmpty(id) || !isInt(li.quantity) || li.quantity <= 0) { out.violations.push('checkout.line_items: a checkout line item has no item.id or quantity'); return; }
        cart.set(id, (cart.get(id) ?? 0) + li.quantity);
      }
      if (!cart.size) { out.violations.push('checkout.line_items: the checkout is empty'); return; }
      if (!lineItemsSatisfied(reqs, cart)) out.violations.push('checkout.line_items: the checkout items do not fill the requirements exactly');
      return;
    }
    default:
      out.unresolved.push(`unknown constraint "${String(c.type)}"`);
  }
}

function periodStart(nowSec: number, frequency: string): number | undefined {
  const d = new Date(nowSec * 1000);
  const y = d.getUTCFullYear(), m = d.getUTCMonth(), day = d.getUTCDate();
  switch (frequency) {
    case 'ON_DEMAND': return undefined;
    case 'DAILY': return Date.UTC(y, m, day) / 1000;
    case 'WEEKLY': return Date.UTC(y, m, day - ((d.getUTCDay() + 6) % 7)) / 1000;
    case 'BIWEEKLY': return nowSec - 14 * 86400;
    case 'MONTHLY': return Date.UTC(y, m, 1) / 1000;
    case 'QUARTERLY': return Date.UTC(y, m - (m % 3), 1) / 1000;
    case 'ANNUALLY': return Date.UTC(y, 0, 1) / 1000;
    default: return NaN;
  }
}

export interface PaymentEvalInput {
  closed: Obj;
  constraints: Obj[];
  nowSec: number;
  context?: Ap2MandateContext | undefined;
  /** sd_hash of each open segment of the checkout chain this payment belongs to (for payment.reference). */
  openCheckoutHashes?: string[] | undefined;
}

function evalPayment(c: Obj, input: PaymentEvalInput, out: ConstraintOutcome): void {
  const { closed, context } = input;
  const amount = isObj(closed.payment_amount) ? closed.payment_amount : {};
  switch (c.type) {
    case 'payment.amount_range': {
      if (!nonEmpty(c.currency) || !isInt(c.max) || (c.min !== undefined && !isInt(c.min))) { out.violations.push('payment.amount_range: malformed (integer minor units)'); return; }
      if (amount.currency !== c.currency) out.violations.push(`payment.amount_range: currency ${String(amount.currency)} is not ${c.currency}`);
      if (!isInt(amount.amount)) { out.violations.push('payment.amount_range: the payment amount is not an integer'); return; }
      if (isInt(c.min) && amount.amount < c.min) out.violations.push(`payment.amount_range: ${amount.amount} is below ${c.min}`);
      if (amount.amount > c.max) out.violations.push(`payment.amount_range: ${amount.amount} is above ${c.max}`);
      return;
    }
    case 'payment.budget': {
      if (typeof c.max !== 'number' || !nonEmpty(c.currency)) { out.violations.push('payment.budget: malformed'); return; }
      if (amount.currency !== c.currency) { out.violations.push(`payment.budget: currency ${String(amount.currency)} is not ${c.currency}`); return; }
      if (!context || typeof context.totalAmount !== 'number') { out.unresolved.push('payment.budget: needs the amount already spent under this mandate (context.totalAmount)'); return; }
      const limit = toMinorUnits(c.max, c.currency);
      const total = context.totalAmount + (isInt(amount.amount) ? amount.amount : Infinity);
      if (total > limit) out.violations.push(`payment.budget: ${total} would exceed ${limit}`);
      return;
    }
    case 'payment.agent_recurrence': {
      const frequency = String(c.frequency);
      const start = periodStart(input.nowSec, frequency);
      if (Number.isNaN(start)) { out.violations.push(`payment.agent_recurrence: unknown frequency "${frequency}"`); return; }
      if (!input.constraints.some((x) => x.type === 'payment.amount_range')) out.violations.push('payment.agent_recurrence requires payment.amount_range');
      if (!input.constraints.some((x) => x.type === 'payment.budget')) out.violations.push('payment.agent_recurrence requires payment.budget');
      if (!context || typeof context.totalUses !== 'number') { out.unresolved.push('payment.agent_recurrence: needs the number of earlier uses (context.totalUses)'); return; }
      if (c.max_occurrences !== undefined) {
        if (!isInt(c.max_occurrences)) { out.violations.push('payment.agent_recurrence: malformed max_occurrences'); return; }
        if (context.totalUses >= c.max_occurrences) out.violations.push(`payment.agent_recurrence: ${context.totalUses} uses reach the limit of ${c.max_occurrences}`);
      }
      if (start !== undefined && context.totalUses > 0) {
        if (typeof context.lastUsedAt !== 'number') { out.unresolved.push('payment.agent_recurrence: needs the time of the last use (context.lastUsedAt)'); return; }
        if (context.lastUsedAt >= start) out.violations.push(`payment.agent_recurrence: already used this ${frequency.toLowerCase()} period`);
      }
      return;
    }
    case 'payment.allowed_payees': {
      const allowed = Array.isArray(c.allowed) ? c.allowed : [];
      if (!allowed.length) { out.violations.push('payment.allowed_payees: no payee is revealed'); return; }
      if (!allowed.some((m) => merchantMatches(m, closed.payee))) out.violations.push(`payment.allowed_payees: payee "${String(isObj(closed.payee) ? closed.payee.id ?? '' : '')}" is not allowed (matched by id)`);
      return;
    }
    case 'payment.allowed_payment_instruments': {
      const allowed = Array.isArray(c.allowed) ? c.allowed : [];
      const pi = closed.payment_instrument;
      if (!allowed.length) { out.violations.push('payment.allowed_payment_instruments: no instrument is revealed'); return; }
      if (!isObj(pi) || !nonEmpty(pi.id) || !nonEmpty(pi.type)) { out.violations.push('payment.allowed_payment_instruments: the payment names no instrument id and type'); return; }
      if (!allowed.some((a) => isObj(a) && a.id === pi.id && a.type === pi.type)) out.violations.push(`payment.allowed_payment_instruments: ${pi.type} "${pi.id}" is not allowed (matched by id and type)`);
      return;
    }
    case 'payment.allowed_pisps': {
      const allowed = Array.isArray(c.allowed) ? c.allowed : [];
      const p = closed.pisp;
      if (!isObj(p)) { out.violations.push('payment.allowed_pisps: the payment names no PISP'); return; }
      const same = (a: unknown) => isObj(a) && nonEmpty(a.domain_name) && String(a.domain_name).toLowerCase() === String(p.domain_name ?? '').toLowerCase()
        && a.legal_name === p.legal_name && a.brand_name === p.brand_name;
      if (!allowed.some(same)) out.violations.push(`payment.allowed_pisps: PISP "${String(p.domain_name ?? '')}" is not allowed`);
      return;
    }
    case 'payment.execution_date': {
      const at = closed.execution_date === undefined ? input.nowSec * 1000 : Date.parse(String(closed.execution_date));
      if (Number.isNaN(at)) { out.violations.push('payment.execution_date: the execution date is not a date'); return; }
      for (const [k, cmp] of [['not_before', (b: number) => at < b], ['not_after', (b: number) => at > b]] as const) {
        if (c[k] === undefined) continue;
        const bound = Date.parse(String(c[k]));
        if (Number.isNaN(bound)) { out.violations.push(`payment.execution_date: ${k} is not a date`); continue; }
        if (cmp(bound)) out.violations.push(`payment.execution_date: ${closed.execution_date ?? 'immediate execution'} is ${k === 'not_before' ? 'before' : 'after'} ${String(c[k])}`);
      }
      return;
    }
    case 'payment.reference': {
      if (!nonEmpty(c.conditional_transaction_id)) { out.violations.push('payment.reference: no conditional_transaction_id'); return; }
      if (!input.openCheckoutHashes) { out.unresolved.push('payment.reference: needs the checkout mandate chain (or its open checkout hashes)'); return; }
      if (!input.openCheckoutHashes.includes(c.conditional_transaction_id)) out.violations.push('payment.reference: no open checkout mandate in the checkout chain has this hash');
      return;
    }
    default:
      out.unresolved.push(`unknown constraint "${String(c.type)}"`);
  }
}

export function evaluateCheckoutConstraints(constraints: Obj[], checkout: Obj): ConstraintOutcome {
  const out: ConstraintOutcome = { violations: [], unresolved: [] };
  for (const c of constraints) evalCheckout(c, checkout, out);
  return out;
}

export function evaluatePaymentConstraints(input: PaymentEvalInput): ConstraintOutcome {
  const out: ConstraintOutcome = { violations: [], unresolved: [] };
  for (const c of input.constraints) evalPayment(c, input, out);
  return out;
}
