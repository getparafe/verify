"""Mint AP2 v0.2 mandate vectors with the AP2 Python SDK (reference implementation).

Writes tests/fixtures/ap2-sdk-vectors.json: keys (test-only), mandate chains
built with MandateClient.create/present, Checkout JWTs signed ES256 with
ap2.sdk.jwt_helper.create_jwt, and the SDK's own verdict for each vector
(MandateClient.verify + CheckoutMandateChain/PaymentMandateChain.verify), so
the TypeScript tests can check that @getparafe/verify agrees.

Run with the AP2 repo (google-agentic-commerce/AP2 at e1ea56d, Python >= 3.11,
its SDK dependencies installed):

  PYTHONPATH=<AP2>/code/sdk/python python tests/scripts/generate-ap2-vectors.py
"""

from __future__ import annotations

import json
import pathlib
import time

from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.constraints import MandateContext
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import (
    AllowedMerchants,
    Item as ReqItem,
    LineItemRequirements,
    LineItems,
    OpenCheckoutMandate,
)
from ap2.sdk.generated.open_payment_mandate import (
    AgentRecurrence,
    AllowedPayees,
    AllowedPaymentInstruments,
    AmountRange,
    Budget,
    OpenPaymentMandate,
    PaymentReference,
)
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.checkout import Checkout, Status
from ap2.sdk.generated.types.item import Item
from ap2.sdk.generated.types.line_item import LineItem
from ap2.sdk.generated.types.link import Link
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.generated.types.total import Total
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.sdjwt import kb_sd_jwt, sd_jwt
from ap2.sdk.sdjwt.common import compute_sd_hash, parse_token
from ap2.sdk.utils import compute_sha256_b64url
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

OUT = pathlib.Path(__file__).resolve().parents[1] / 'fixtures' / 'ap2-sdk-vectors.json'
NOW = int(time.time())
client = MandateClient()


def key(kid: str) -> JWK:
    d = json.loads(JWK.from_pyca(ec.generate_private_key(ec.SECP256R1())).export())
    d['kid'] = kid
    return JWK(**d)


def pub(k: JWK) -> dict:
    return json.loads(k.export_public())


provider = key('agent-provider-key-1')  # Trusted Agent Provider (root issuer)
agent = key('shopping-agent-key-1')  # the shopping agent's key (cnf)
agent2 = key('sub-agent-key-1')  # a second agent for a multi-hop chain
merchant_key = key('merchant-key-1')  # signs the Checkout JWT
MERCHANT = Merchant(id='merchant_1', name='Demo Merchant', website='https://demo-merchant.example')
CARD = PaymentInstrument(id='pi_card_4242', type='card', description='Card 4242')


def checkout_jwt(checkout_id: str, lines: list[tuple[str, int, int]], merchant=MERCHANT) -> str:
    items = [
        LineItem(id=f'li_{sku}', item=Item(id=sku, title=sku, price=price), quantity=qty,
                 totals=[Total(type='total', amount=price * qty)])
        for sku, qty, price in lines
    ]
    total = sum(price * qty for _, qty, price in lines)
    checkout = Checkout(
        id=checkout_id, merchant=merchant, line_items=items, status=Status.ready_for_complete,
        currency='USD', totals=[Total(type='total', amount=total)],
        links=[Link(type='terms_of_service', url='https://demo-merchant.example/tos')],
    )
    return create_jwt({'alg': 'ES256', 'typ': 'JWT', 'kid': 'merchant-key-1'},
                      json.loads(checkout.model_dump_json(exclude_none=True)), merchant_key)


def sdk_verify(chain: str, family: str, aud: str, nonce: str, **kw) -> dict:
    """The AP2 SDK's verdict: chain verification, then the typed chain's violations."""
    try:
        payloads = client.verify(token=chain, key_or_provider=lambda _t: provider,
                                 expected_aud=aud, expected_nonce=nonce)
    except Exception as e:  # noqa: BLE001
        return {'chain_valid': False, 'error': f'{type(e).__name__}: {e}'}
    if len(payloads) != 2:
        return {'chain_valid': True, 'payload_count': len(payloads)}
    if family == 'checkout':
        violations = CheckoutMandateChain.parse(payloads).verify(
            expected_checkout_hash=kw.get('expected_checkout_hash'), checkout_jwt=kw.get('checkout_jwt'))
    else:
        violations = PaymentMandateChain.parse(payloads).verify(
            expected_transaction_id=kw.get('expected_transaction_id'),
            expected_open_checkout_hash=kw.get('open_checkout_hash'),
            mandate_context=kw.get('context'))
    return {'chain_valid': True, 'violations': violations}


vectors: list[dict] = []

# ── 1. Human not present: open checkout mandate → agent-signed closed checkout mandate ──
cj = checkout_jwt('chk_hnp_1', [('sku_gold_sneaker_9', 1, 19900)])
open_checkout = client.create(payloads=[OpenCheckoutMandate(
    constraints=[
        LineItems(items=[LineItemRequirements(id='line_1', quantity=1, acceptable_items=[
            ReqItem(id='sku_gold_sneaker_9', title='Gold Sneaker 9'),
            ReqItem(id='sku_silver_sneaker_9', title='Silver Sneaker 9')])]),
        AllowedMerchants(allowed=[MERCHANT]),
    ],
    cnf={'jwk': pub(agent)}, iat=NOW, exp=NOW + 3600,
)], issuer_key=provider)
checkout_chain = client.present(
    holder_key=agent, mandate_token=open_checkout,
    payloads=[CheckoutMandate(checkout_jwt=cj, checkout_hash=compute_sha256_b64url(cj), iat=NOW)],
    aud='merchant', nonce='nonce-checkout-1')
open_checkout_hash = compute_sd_hash(parse_token(checkout_chain.split('~~')[0] + '~'))
vectors.append({
    'id': 'hnp-checkout', 'family': 'checkout', 'mode': 'human_not_present',
    'chain': checkout_chain, 'checkout_jwt': cj, 'aud': 'merchant', 'nonce': 'nonce-checkout-1',
    'sdk_reference': compute_sha256_b64url(client.get_closed_mandate_jwt(checkout_chain)),
    'open_checkout_hash': open_checkout_hash,
    'sdk': sdk_verify(checkout_chain, 'checkout', 'merchant', 'nonce-checkout-1',
                      checkout_jwt=cj, expected_checkout_hash=compute_sha256_b64url(cj)),
})

# ── 2. Human not present: open payment mandate → agent-signed closed payment mandate ──
tx = compute_sha256_b64url(cj)
open_payment = client.create(payloads=[OpenPaymentMandate(
    constraints=[
        AmountRange(currency='USD', min=0, max=25000),
        AllowedPayees(allowed=[MERCHANT]),
        AllowedPaymentInstruments(allowed=[CARD]),
        PaymentReference(conditional_transaction_id=open_checkout_hash),
    ],
    cnf={'jwk': pub(agent)}, iat=NOW, exp=NOW + 3600,
)], issuer_key=provider)
payment_chain = client.present(
    holder_key=agent, mandate_token=open_payment,
    payloads=[PaymentMandate(transaction_id=tx, payee=MERCHANT, payment_amount=Amount(amount=19900, currency='USD'),
                             payment_instrument=CARD, iat=NOW)],
    aud='credential-provider', nonce='nonce-payment-1')
vectors.append({
    'id': 'hnp-payment', 'family': 'payment', 'mode': 'human_not_present',
    'chain': payment_chain, 'checkout_jwt': cj, 'aud': 'credential-provider', 'nonce': 'nonce-payment-1',
    'open_checkout_hash': open_checkout_hash,
    'sdk_reference': compute_sha256_b64url(client.get_closed_mandate_jwt(payment_chain)),
    'sdk': sdk_verify(payment_chain, 'payment', 'credential-provider', 'nonce-payment-1',
                      expected_transaction_id=tx, open_checkout_hash=open_checkout_hash),
})

# ── 3. Recurring payment: budget + agent recurrence (needs usage context) ──
open_recurring = client.create(payloads=[OpenPaymentMandate(
    constraints=[
        AmountRange(currency='USD', max=5000),
        Budget(currency='USD', max=100.0),
        # model_construct: the SDK's model_dump keeps the enum, which JSON can't encode
        AgentRecurrence.model_construct(type='payment.agent_recurrence', frequency='MONTHLY', max_occurrences=12),
        AllowedPayees(allowed=[MERCHANT]),
        PaymentReference(conditional_transaction_id=open_checkout_hash),
    ],
    cnf={'jwk': pub(agent)}, iat=NOW, exp=NOW + 3600,
)], issuer_key=provider)
cj_small = checkout_jwt('chk_hnp_2', [('sku_socks', 1, 1500)])
recurring_chain = client.present(
    holder_key=agent, mandate_token=open_recurring,
    payloads=[PaymentMandate(transaction_id=compute_sha256_b64url(cj_small), payee=MERCHANT,
                             payment_amount=Amount(amount=1500, currency='USD'), payment_instrument=CARD, iat=NOW)],
    aud='credential-provider', nonce='nonce-recurring-1')
ctx_ok = MandateContext(total_amount=8000, total_uses=3)
ctx_over = MandateContext(total_amount=9000, total_uses=3)
vectors.append({
    'id': 'hnp-payment-recurring', 'family': 'payment', 'mode': 'human_not_present',
    'chain': recurring_chain, 'checkout_jwt': cj_small, 'aud': 'credential-provider', 'nonce': 'nonce-recurring-1',
    'open_checkout_hash': open_checkout_hash,
    'contexts': {
        'within_budget': {'context': {'totalAmount': 8000, 'totalUses': 3},
                          'sdk': sdk_verify(recurring_chain, 'payment', 'credential-provider', 'nonce-recurring-1',
                                            expected_transaction_id=compute_sha256_b64url(cj_small),
                                            open_checkout_hash=open_checkout_hash, context=ctx_ok)},
        'over_budget': {'context': {'totalAmount': 9000, 'totalUses': 3},
                        'sdk': sdk_verify(recurring_chain, 'payment', 'credential-provider', 'nonce-recurring-1',
                                          expected_transaction_id=compute_sha256_b64url(cj_small),
                                          open_checkout_hash=open_checkout_hash, context=ctx_over)},
    },
})

# ── 4. Two hops: provider → shopping agent (open) → sub-agent (open) → closed payment ──
# present() appends one hop to a single token, so the chain is built from the
# SDK's segment primitives (as its own three-step flow test does).
hop1 = kb_sd_jwt.create(
    prev_token=parse_token(open_payment), holder_key=agent,
    payload=OpenPaymentMandate(
        constraints=[AmountRange(currency='USD', max=20000), PaymentReference(conditional_transaction_id=open_checkout_hash)],
        cnf={'jwk': pub(agent2)}, iat=NOW, exp=NOW + 1800),
    aud='sub-agent', nonce='nonce-hop-1').sd_jwt_issuance
hop2 = kb_sd_jwt.create(
    prev_token=parse_token(hop1), holder_key=agent2,
    payload=PaymentMandate(transaction_id=tx, payee=MERCHANT, payment_amount=Amount(amount=19900, currency='USD'),
                           payment_instrument=CARD, iat=NOW),
    aud='credential-provider', nonce='nonce-multi-1').sd_jwt_issuance
multi = f'{open_payment[:-1]}~~{hop1[:-1]}~~{hop2}'
vectors.append({
    'id': 'hnp-payment-two-hops', 'family': 'payment', 'mode': 'human_not_present',
    'chain': multi, 'checkout_jwt': cj, 'aud': 'credential-provider', 'nonce': 'nonce-multi-1',
    'open_checkout_hash': open_checkout_hash,
    'sdk_reference': compute_sha256_b64url(client.get_closed_mandate_jwt(multi)),
    'sdk': sdk_verify(multi, 'payment', 'credential-provider', 'nonce-multi-1',
                      expected_transaction_id=tx, open_checkout_hash=open_checkout_hash),
})

# ── 5. Human present: the Agent Provider's trusted surface signs the closed mandates directly ──
cj_hp = checkout_jwt('chk_hp_1', [('sku_gold_sneaker_9', 1, 19900)])
hp_checkout = client.create(payloads=[CheckoutMandate(checkout_jwt=cj_hp, checkout_hash=compute_sha256_b64url(cj_hp), iat=NOW)],
                            issuer_key=provider)
hp_payment = client.create(payloads=[PaymentMandate(
    transaction_id=compute_sha256_b64url(cj_hp), payee=MERCHANT, payment_amount=Amount(amount=19900, currency='USD'),
    payment_instrument=CARD, iat=NOW)], issuer_key=provider)


def sdk_verify_single(token: str, model) -> dict:
    try:
        m = client.verify(token=token, key_or_provider=JWK(**pub(provider)), payload_type=model)
        return {'chain_valid': True, 'vct': m.mandate_payload.vct}
    except Exception as e:  # noqa: BLE001
        return {'chain_valid': False, 'error': f'{type(e).__name__}: {e}'}


vectors.append({'id': 'hp-checkout', 'family': 'checkout', 'mode': 'human_present', 'chain': hp_checkout, 'checkout_jwt': cj_hp,
                'sdk_reference': compute_sha256_b64url(client.get_closed_mandate_jwt(hp_checkout)),
                'sdk': sdk_verify_single(hp_checkout, CheckoutMandate)})
vectors.append({'id': 'hp-payment', 'family': 'payment', 'mode': 'human_present', 'chain': hp_payment, 'checkout_jwt': cj_hp,
                'sdk_reference': compute_sha256_b64url(client.get_closed_mandate_jwt(hp_payment)),
                'sdk': sdk_verify_single(hp_payment, PaymentMandate)})

# ── 6. Decoy digests (RFC 9901 §4.2.5): the SDK adds them when asked (P-36) ──
decoy_open = sd_jwt.create(payload=OpenCheckoutMandate(
    constraints=[LineItems(items=[LineItemRequirements(id='line_1', quantity=1, acceptable_items=[ReqItem(id='sku_gold_sneaker_9', title='Gold Sneaker 9')])])],
    cnf={'jwk': pub(agent)}, iat=NOW, exp=NOW + 3600,
), issuer_key=provider, add_decoy_claims=True).sd_jwt_issuance
decoy_chain = client.present(
    holder_key=agent, mandate_token=decoy_open,
    payloads=[CheckoutMandate(checkout_jwt=cj, checkout_hash=compute_sha256_b64url(cj), iat=NOW)],
    aud='merchant', nonce='nonce-decoy-1')
vectors.append({
    'id': 'hnp-checkout-decoys', 'family': 'checkout', 'mode': 'human_not_present',
    'chain': decoy_chain, 'checkout_jwt': cj, 'aud': 'merchant', 'nonce': 'nonce-decoy-1',
    'sdk_reference': compute_sha256_b64url(client.get_closed_mandate_jwt(decoy_chain)),
    'sdk': sdk_verify(decoy_chain, 'checkout', 'merchant', 'nonce-decoy-1', checkout_jwt=cj, expected_checkout_hash=compute_sha256_b64url(cj)),
})

fixture = {
    'generated_at': NOW,
    'generator': 'tests/scripts/generate-ap2-vectors.py with the AP2 Python SDK (google-agentic-commerce/AP2 e1ea56d)',
    'note': 'Test-only keys. Private keys are included so tests can mint negative variants.',
    'keys': {
        'provider': json.loads(provider.export()), 'agent': json.loads(agent.export()),
        'agent2': json.loads(agent2.export()), 'merchant': json.loads(merchant_key.export()),
    },
    'vectors': vectors,
}
OUT.write_text(json.dumps(fixture, indent=2) + '\n')
print(f'wrote {OUT} ({len(vectors)} vectors)')
for v in vectors:
    print(v['id'], json.dumps(v.get('sdk') or {k: c['sdk'] for k, c in v.get('contexts', {}).items()})[:300])
