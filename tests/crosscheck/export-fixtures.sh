#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
#
# Bundles the traces recorded by run.sh, with Unbound's verdict for each
# query, into tests/testdata/crosscheck.traces for the offline replay tests.
#
# Format:   @query <name> <TYPE> <unbound-verdict>
#           <qname> <QTYPE> <base64 response>     (one line per exchange)
set -euo pipefail
cd "$(dirname "$0")"
W=work
OUT=../testdata/crosscheck.traces
cp zones/root.anchor ../testdata/crosscheck-root.anchor
{
  echo "; Recorded by tests/crosscheck/run.sh on $(date -u +%Y-%m-%d) against NSD + Unbound."
  echo "; Zones signed 2026-10-01..2027-10-01 (expired.test: 2026-08-01..2026-09-01;"
  echo "; notyet.test: 2030-01-01..2031-01-01). Replay with now = 2026-10-14T00:00:00Z."
  while IFS=$'\t' read -r name type ov orr rv rr ub ld; do
    f="$W/traces/$(tr '/' '_' <<<"$name")$type.trace"
    [[ -s "$f" ]] || { echo "missing trace for $name $type" >&2; exit 1; }
    echo "@query $name $type $ub"
    sort -u "$f"
  done < "$W/results.tsv"
} > "$OUT"
echo "wrote $OUT ($(grep -c '^@query' "$OUT") queries, $(wc -c < "$OUT") bytes)"
