/**
 * Deterministic JSON canonicalization. Must produce byte-identical output to the
 * broker's receipt canonicalizer (broker/src/routes/receipt.js, `canonicalize`).
 *
 * Rules:
 * - Object keys sorted alphabetically (localeCompare) at every level.
 * - Arrays preserved in original order, elements canonicalized recursively.
 * - Primitives untouched. `null` treated as primitive.
 * - Output is a single-line JSON string (no whitespace), UTF-8.
 *
 * Any drift from the broker's behavior silently breaks signature verification,
 * so this function is exported for users who want to build their own verifier.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
      );
    }
    return v;
  });
}

/**
 * Strip `signature` and `receipt_vdc` from a receipt and return the canonical
 * signing input, as the broker's /receipt/verify does. Receipts issued before
 * 2026-09-29 carried a `receipt_vdc` that was never part of the signed payload.
 */
export function signingInputForReceipt(receipt: object): string {
  const { signature: _sig, receipt_vdc: _vdc, ...rest } = receipt as Record<string, unknown>;
  return canonicalize(rest);
}
