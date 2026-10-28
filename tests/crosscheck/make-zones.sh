#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
#
# Builds the cross-check zone set: a fake root, a "test." TLD and one
# leaf zone per scenario (algorithms, NSEC/NSEC3 variants, insecure and
# broken chains). Keys are generated into keys/ (git-ignored) on first use and
# reused afterwards. The signed zones in zones/ and zones/root.anchor are the
# committed fixture; regenerating keys produces a new, equally valid set.
#
# Usage: ./make-zones.sh [--new-keys] [--inception YYYYMMDD] [--expiration YYYYMMDD]
# Requires: ldnsutils (ldns-keygen, ldns-signzone, ldns-key2ds).
# THE KEYS IN keys/ ARE TEST KEYS. Never use them for anything real.
set -euo pipefail
cd "$(dirname "$0")"

INCEPTION=20261001
EXPIRATION=20271001
NEW_KEYS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --new-keys) NEW_KEYS=1 ;;
    --inception) INCEPTION="$2"; shift ;;
    --expiration) EXPIRATION="$2"; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

KEYS=keys
OUT=zones
mkdir -p "$KEYS" "$OUT"
[[ $NEW_KEYS == 1 ]] && rm -f "$KEYS"/K*

# zone -> "algorithm bits denial(nsec|nsec3) nsec3-args"
declare -A ALG BITS
ALG[.]=RSASHA256;          BITS[.]=2048
ALG[test.]=ECDSAP256SHA256
ALG[rsasha256.test.]=RSASHA256; BITS[rsasha256.test.]=2048
ALG[rsasha512.test.]=RSASHA512; BITS[rsasha512.test.]=2048
ALG[rsasha1.test.]=RSASHA1;     BITS[rsasha1.test.]=2048
ALG[nsec3sha1.test.]=RSASHA1-NSEC3-SHA1; BITS[nsec3sha1.test.]=1024
ALG[ecdsa256.test.]=ECDSAP256SHA256
ALG[ecdsa384.test.]=ECDSAP384SHA384
ALG[ed25519.test.]=ED25519
ALG[ed448.test.]=ED448
for z in expired notyet wrongkey nodnskey tampered badsig highiter dname island dssha1; do
  ALG[$z.test.]=ECDSAP256SHA256
done

declare -A NSEC3ARGS
NSEC3ARGS[test.]="-n -t 0"
NSEC3ARGS[rsasha512.test.]="-n -t 0"
NSEC3ARGS[nsec3sha1.test.]="-n -t 5 -s aabbccdd"
NSEC3ARGS[ecdsa256.test.]="-n -t 0 -p"
NSEC3ARGS[highiter.test.]="-n -t 200 -s 01"

# Signing windows per zone (default: INCEPTION..EXPIRATION).
declare -A INC EXP
INC[expired.test.]=20260801; EXP[expired.test.]=20260901
INC[notyet.test.]=20300101;  EXP[notyet.test.]=20310101

keybase() { # zone role -> base name of key file (generated on demand)
  local zone=$1 role=$2 alg=${ALG[$1]} bits=${BITS[$1]:-}
  local tag="${zone%.}"; tag=${tag:-root}
  local link="$KEYS/$tag.$role"
  if [[ ! -e "$link.key" ]]; then
    local flag=""; [[ $role == ksk || $role == csk || $role == other ]] && flag="-k"
    local b=""; [[ -n "$bits" ]] && b="-b $bits"
    local base
    base=$(cd "$KEYS" && ldns-keygen -a "$alg" $b $flag -r /dev/urandom "$zone")
    mv "$KEYS/$base.key" "$link.key"
    mv "$KEYS/$base.private" "$link.private"
    rm -f "$KEYS/$base.ds"
  fi
  echo "$link"
}

leaf_body() { # zone
  local z=$1
  cat <<EOF
\$ORIGIN $z
\$TTL 3600
@     SOA ns1.$z hostmaster.$z 2026101301 3600 900 1209600 300
@     NS  ns1.$z
@     MX  10 mail.$z
ns1   A   127.0.0.1
www   A   192.0.2.1
www   AAAA 2001:db8::1
mail  A   192.0.2.25
txt   TXT "zig-dnssec cross-check fixture"
alias CNAME www.$z
*.wild A  192.0.2.99
a.b.ent A 192.0.2.50
EOF
}

sign() { # zone srcfile keys...
  local zone=$1 src=$2; shift 2
  local tag="${zone%.}"; tag=${tag:-root}
  local inc=${INC[$zone]:-$INCEPTION} exp=${EXP[$zone]:-$EXPIRATION}
  # shellcheck disable=SC2086
  ldns-signzone ${NSEC3ARGS[$zone]:-} -i "$inc" -e "$exp" -o "$zone" -f "$OUT/$tag.signed" "$src" "$@" >/dev/null
}

ds_of() { # keybase [digest-flag]
  ldns-key2ds -n ${2:--2} "$1.key"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

LEAVES=(rsasha256 rsasha512 rsasha1 nsec3sha1 ecdsa256 ecdsa384 ed25519 ed448
        expired notyet wrongkey nodnskey tampered badsig highiter dname island dssha1)

: > "$work/test.ds"
for l in "${LEAVES[@]}"; do
  z="$l.test."
  k=$(keybase "$z" csk)
  leaf_body "$z" > "$work/$l.zone"
  case $l in
    ecdsa256)
      # Unsigned delegation inside an Opt-Out NSEC3 zone.
      printf 'unsigned NS ns1.unsigned.%s\nns1.unsigned A 127.0.0.1\n' "$z" >> "$work/$l.zone" ;;
    dname)
      printf 'redir DNAME rsasha256.test.\n' >> "$work/$l.zone" ;;
  esac
  sign "$z" "$work/$l.zone" "$k"
  case $l in
    nodnskey)  # drop the DNSKEY RRset and its signatures: a missing chain link
      awk '!($4=="DNSKEY" || ($4=="RRSIG" && $5=="DNSKEY"))' "$OUT/$l.test.signed" > "$work/x" && mv "$work/x" "$OUT/$l.test.signed" ;;
    tampered)  # change data after signing
      sed -i 's/\(^www\.tampered\.test\.[[:space:]].*IN[[:space:]]A[[:space:]]\)192\.0\.2\.1$/\1192.0.2.66/' "$OUT/$l.test.signed"
      grep -q '192.0.2.66' "$OUT/$l.test.signed" ;;
    badsig)    # corrupt one signature (the www AAAA RRSIG): flip a base64 char
      awk '{ if ($1=="www.badsig.test." && $4=="RRSIG" && $5=="AAAA" && !done) { s=$NF; c=substr(s,10,1); r=(c=="A")?"B":"A"; $NF=substr(s,1,9) r substr(s,11); done=1 } print }' \
        "$OUT/$l.test.signed" > "$work/x" && mv "$work/x" "$OUT/$l.test.signed" ;;
  esac
  case $l in
    island) ;;                                   # signed, but no DS in parent
    wrongkey) ds_of "$(keybase "$z" other)" >> "$work/test.ds" ;;  # DS of a key not in the zone
    dssha1) ds_of "$k" -1 >> "$work/test.ds" ;;   # SHA-1 digest only
    *) ds_of "$k" >> "$work/test.ds" ;;
  esac
done

# Unsigned zones.
cat > "$OUT/insecure.test.signed" <<EOF
$(leaf_body insecure.test.)
EOF
cat > "$OUT/unsigned.ecdsa256.test.signed" <<EOF
$(leaf_body unsigned.ecdsa256.test.)
EOF

# test. TLD
{
  cat <<EOF
\$ORIGIN test.
\$TTL 3600
@    SOA ns1.test. hostmaster.test. 2026101301 3600 900 1209600 300
@    NS  ns1.test.
ns1  A   127.0.0.1
EOF
  for l in "${LEAVES[@]}" insecure; do
    printf '%s NS ns1.%s.test.\nns1.%s A 127.0.0.1\n' "$l" "$l" "$l"
  done
  cat "$work/test.ds"
} > "$work/test.zone"
sign test. "$work/test.zone" "$(keybase test. csk)"

# Fake root with separate KSK and ZSK.
{
  cat <<EOF
\$ORIGIN .
\$TTL 3600
.        SOA a.root. hostmaster.root. 2026101301 3600 900 1209600 300
.        NS  a.root.
a.root.  A   127.0.0.1
test.    NS  ns1.test.
ns1.test. A  127.0.0.1
EOF
  ds_of "$(keybase test. csk)"
} > "$work/root.zone"
sign . "$work/root.zone" "$(keybase . ksk)" "$(keybase . zsk)"
ds_of "$(keybase . ksk)" > "$OUT/root.anchor"

echo "signed zones in $OUT/; trust anchor in $OUT/root.anchor"
