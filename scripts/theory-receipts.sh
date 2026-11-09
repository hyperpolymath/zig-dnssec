#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
#
# theory-receipts.sh [OUT]
#
# Checks the chain-of-trust theorems in all three provers and writes one proof
# receipt per leg, as PROOF-POLICY §8.2 (PWG-1) describes. Each receipt holds:
#   - the checker and its version, and the invocation;
#   - a SHA-256 digest of the input file;
#   - the observed result, and the axioms the checker reports (§8.4);
#   - the source repository and its full 40-character commit.
#
# Receipts are written to OUT (default: theory-receipts.jsonl), one JSON record
# per line, keys sorted and no whitespace (jq -cS), per the estate JSON policy.
#
# Fails closed. The script exits 1 if any of these happens:
#   - a checker is missing;
#   - a leg does not compile;
#   - Agda's comment-aware postulate scan finds a postulate;
#   - Rocq's `Print Assumptions` reports anything but "Closed under the global
#     context" for each of the four theorems;
#   - Lean's `#print axioms` reports anything but "does not depend on any
#     axioms" for each of the four theorems.
# A missing tool is a failure, never a skip.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

OUT="${1:-theory-receipts.jsonl}"
: >"$OUT"
COMMIT="$(git rev-parse HEAD)"
REPO="hyperpolymath/zig-dnssec"
THEOREMS=4
fail=0

need() { command -v "$1" >/dev/null 2>&1 || { echo "FAIL: $1 not on PATH" >&2; exit 1; }; }
need agda; need coqc; need lean; need jq; need sha256sum

receipt() {
  # $1 leg, $2 checker, $3 version, $4 invocation, $5 input, $6 result, $7 axioms (JSON array)
  jq -cnS --arg leg "$1" --arg checker "$2" --arg version "$3" --arg invocation "$4" \
    --arg input "$5" --arg digest "sha256:$(sha256sum "$5" | cut -d' ' -f1)" \
    --arg result "$6" --argjson axioms "$7" --arg repo "$REPO" --arg commit "$COMMIT" \
    '{leg:$leg, checker:$checker, version:$version, invocation:$invocation,
      input:$input, input_digest:$digest, result:$result, axioms:$axioms,
      repo:$repo, commit:$commit}' >>"$OUT"
}

# --- Agda (source of truth) ----------------------------------------------------
AGDA_IN=verification/proofs/agda/ChainOfTrust.agda
AGDA_CMD="agda --safe --without-K --cubical-compatible ChainOfTrust.agda"
# Comment-aware postulate scan of the import cone (this one file: it imports
# nothing). Agda block comments {- -} nest (pragmas {-# #-} use the same
# delimiters), so they are removed with a depth counter, then -- line comments
# outside them.
strip_agda_comments() {
  awk '{
    line = $0; out = ""; i = 1; n = length(line)
    while (i <= n) {
      two = substr(line, i, 2)
      if (two == "{-") { depth++; i += 2; continue }
      if (depth > 0 && two == "-}") { depth--; i += 2; continue }
      if (depth == 0 && two == "--") break
      if (depth == 0) out = out substr(line, i, 1)
      i++
    }
    print out
  }' "$1"
}
postulates="$(strip_agda_comments "$AGDA_IN" | grep -cE '(^|[[:space:]])postulate([[:space:]]|$)' || true)"
if (cd verification/proofs/agda && $AGDA_CMD >/dev/null 2>&1) && [ "$postulates" = 0 ]; then
  receipt agda agda "$(agda --version | head -1)" "$AGDA_CMD" "$AGDA_IN" proven '[]'
  echo "agda: PROVEN (postulates: 0, import cone: $AGDA_IN only)"
else
  receipt agda agda "$(agda --version | head -1)" "$AGDA_CMD" "$AGDA_IN" failed '[]'
  echo "agda: FAILED (postulates: $postulates)" >&2; fail=1
fi

# --- Rocq leg --------------------------------------------------------------------
COQ_IN=verification/proofs/coq/ChainOfTrust.v
if out="$(cd verification/proofs/coq && coqc ChainOfTrust.v 2>&1)"; then
  closed="$(grep -c '^Closed under the global context$' <<<"$out" || true)"
  other="$(grep -v '^Closed under the global context$' <<<"$out" | grep -c . || true)"
  if [ "$closed" = "$THEOREMS" ] && [ "$other" = 0 ]; then
    receipt rocq coqc "$(coqc --version | head -1)" "coqc ChainOfTrust.v" "$COQ_IN" proven '[]'
    echo "rocq: PROVEN (Print Assumptions: closed x$closed)"
  else
    receipt rocq coqc "$(coqc --version | head -1)" "coqc ChainOfTrust.v" "$COQ_IN" axioms "$(jq -cn --arg o "$out" '[$o]')"
    echo "rocq: AXIOMS REPORTED" >&2; echo "$out" >&2; fail=1
  fi
else
  receipt rocq coqc "$(coqc --version | head -1)" "coqc ChainOfTrust.v" "$COQ_IN" failed '[]'
  echo "rocq: FAILED" >&2; echo "$out" >&2; fail=1
fi
rm -f verification/proofs/coq/ChainOfTrust.{vo,vok,vos,glob} verification/proofs/coq/.ChainOfTrust.aux

# --- Lean leg --------------------------------------------------------------------
LEAN_IN=verification/proofs/lean4/ChainOfTrust.lean
if out="$(cd verification/proofs/lean4 && lean ChainOfTrust.lean 2>&1)"; then
  clean="$(grep -c "does not depend on any axioms$" <<<"$out" || true)"
  other="$(grep -v "does not depend on any axioms$" <<<"$out" | grep -c . || true)"
  if [ "$clean" = "$THEOREMS" ] && [ "$other" = 0 ]; then
    receipt lean lean "$(lean --version | head -1)" "lean ChainOfTrust.lean" "$LEAN_IN" proven '[]'
    echo "lean: PROVEN (#print axioms: none x$clean)"
  else
    receipt lean lean "$(lean --version | head -1)" "lean ChainOfTrust.lean" "$LEAN_IN" axioms "$(jq -cn --arg o "$out" '[$o]')"
    echo "lean: AXIOMS REPORTED" >&2; echo "$out" >&2; fail=1
  fi
else
  receipt lean lean "$(lean --version | head -1)" "lean ChainOfTrust.lean" "$LEAN_IN" failed '[]'
  echo "lean: FAILED" >&2; echo "$out" >&2; fail=1
fi

echo "receipts: $OUT ($(wc -l <"$OUT") legs, commit $COMMIT)"
exit "$fail"
