/* SPDX-License-Identifier: MPL-2.0 */
/* SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell */

/*
 * zig-dnssec C ABI, version 1.
 *
 * EXPERIMENTAL and not independently reviewed. Do not rely on it for security
 * decisions yet; see docs/reports/VERIFICATION.adoc.
 *
 * This header is the contract of the seam. The Zig implementation
 * (src/interface/ffi/src/main.zig) is checked against it at compile time, and
 * the Idris2 model (src/interface/Abi/) is checked against it by
 * `zig build test`.
 *
 * Fail-closed rules every function keeps:
 *   - verdict.security is ZIG_DNSSEC_SECURITY_NONE (0) whenever a call returns
 *     anything other than ZIG_DNSSEC_OK, so a zeroed or stale verdict never
 *     reads as secure;
 *   - answer text is written only when the security is SECURE or INSECURE;
 *     for BOGUS and INDETERMINATE text stays the empty string and text_len
 *     is 0;
 *   - unknown policy bits are rejected, not ignored.
 *
 * No global state: calls are independent and may run on different threads.
 * Nothing returned needs freeing; the *_name functions return static strings.
 */

#ifndef ZIG_DNSSEC_H
#define ZIG_DNSSEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZIG_DNSSEC_ABI_VERSION 1

/* ---- Call status (return value of the validate functions) --------------- */

#define ZIG_DNSSEC_OK 0
/* A required pointer was NULL, the policy had unknown bits, or the query
 * type was a meta-type (OPT, ANY, AXFR, ...). */
#define ZIG_DNSSEC_ERR_INVALID_ARGUMENT 1
#define ZIG_DNSSEC_ERR_OUT_OF_MEMORY 2
/* The trust-anchor text did not parse, or held no DS/DNSKEY records. */
#define ZIG_DNSSEC_ERR_BAD_ANCHORS 3
/* The query name is not a valid domain name in presentation format. */
#define ZIG_DNSSEC_ERR_BAD_NAME 4
/* The recorded trace did not parse (zig_dnssec_validate_trace only). */
#define ZIG_DNSSEC_ERR_BAD_TRACE 5
/* The initial query got no usable response (transport error, or a response
 * that does not match the question). Failures of the follow-up DS/DNSKEY
 * fetches are reported in the verdict instead. */
#define ZIG_DNSSEC_ERR_QUERY_FAILED 6
/* text was non-NULL and too small; verdict.text_len holds the length needed
 * (excluding the terminating NUL). */
#define ZIG_DNSSEC_ERR_BUFFER_TOO_SMALL 7

/* ---- Security of the answer (verdict.security) --------------------------- */

#define ZIG_DNSSEC_SECURITY_NONE 0          /* no verdict: the call failed */
#define ZIG_DNSSEC_SECURITY_SECURE 1        /* authenticated to a trust anchor */
#define ZIG_DNSSEC_SECURITY_INSECURE 2      /* proven unsigned, or allowed by policy */
#define ZIG_DNSSEC_SECURITY_BOGUS 3         /* validation failed: do not use */
#define ZIG_DNSSEC_SECURITY_INDETERMINATE 4 /* could not decide: do not use */

/* ---- Reason (verdict.reason); 0 for SECURE -------------------------------- */

#define ZIG_DNSSEC_REASON_NONE 0
/* insecure */
#define ZIG_DNSSEC_REASON_INSECURE_DELEGATION 1
#define ZIG_DNSSEC_REASON_NSEC3_OPT_OUT 2
#define ZIG_DNSSEC_REASON_UNSUPPORTED_ALGORITHM_POLICY 3
#define ZIG_DNSSEC_REASON_NSEC3_ITERATIONS_POLICY 4
/* bogus */
#define ZIG_DNSSEC_REASON_SIGNATURE_INVALID 5
#define ZIG_DNSSEC_REASON_SIGNATURE_EXPIRED 6
#define ZIG_DNSSEC_REASON_SIGNATURE_NOT_YET_VALID 7
#define ZIG_DNSSEC_REASON_SIGNATURE_BAD_PERIOD 8
#define ZIG_DNSSEC_REASON_NO_MATCHING_KEY 9
#define ZIG_DNSSEC_REASON_NO_SUPPORTED_SIGNATURE 10
#define ZIG_DNSSEC_REASON_MISSING_SIGNATURE 11
#define ZIG_DNSSEC_REASON_DNSKEY_MISSING 12
#define ZIG_DNSSEC_REASON_DNSKEY_NOT_AUTHENTICATED 13
#define ZIG_DNSSEC_REASON_DS_NOT_AUTHENTICATED 14
#define ZIG_DNSSEC_REASON_BAD_SIGNER 15
#define ZIG_DNSSEC_REASON_DENIAL_FAILED 16
#define ZIG_DNSSEC_REASON_DENIAL_MISSING 17
#define ZIG_DNSSEC_REASON_NSEC3_INCONSISTENT_PARAMS 18
#define ZIG_DNSSEC_REASON_UNSUPPORTED_ALGORITHM 19
#define ZIG_DNSSEC_REASON_NSEC3_ITERATIONS_EXCEEDED 20
#define ZIG_DNSSEC_REASON_RESOURCE_LIMIT 21
#define ZIG_DNSSEC_REASON_CNAME_LOOP 22
#define ZIG_DNSSEC_REASON_DNAME_MISMATCH 23
#define ZIG_DNSSEC_REASON_MALFORMED_RESPONSE 24
#define ZIG_DNSSEC_REASON_CHAIN_LOOP 25
/* indeterminate */
#define ZIG_DNSSEC_REASON_NO_TRUST_ANCHOR 26
#define ZIG_DNSSEC_REASON_FETCH_FAILED 27
#define ZIG_DNSSEC_REASON_UPSTREAM_RCODE 28
#define ZIG_DNSSEC_REASON_TRUNCATED 29

/* ---- Policy flags (0 = the library's fail-closed defaults) --------------- */

/* Treat zones whose DS set holds only unsupported algorithms as insecure
 * (RFC 4035 section 5.2) instead of bogus. */
#define ZIG_DNSSEC_POLICY_UNSUPPORTED_INSECURE 1
/* Treat NSEC3 with iterations above 150 as insecure (RFC 9276) instead of
 * bogus. */
#define ZIG_DNSSEC_POLICY_ITERATIONS_INSECURE 2
/* Refuse SHA-1 in signatures and DS digests. */
#define ZIG_DNSSEC_POLICY_NO_SHA1 4

/* ---- Verdict --------------------------------------------------------------- */

#define ZIG_DNSSEC_WHERE_MAX 1024

/* 1048 bytes, 4-byte alignment; the layout is part of the ABI and is proved
 * aligned in src/interface/Abi/Layout.idr. */
typedef struct zig_dnssec_verdict {
    uint8_t security;       /* ZIG_DNSSEC_SECURITY_* */
    uint8_t reason;         /* ZIG_DNSSEC_REASON_* */
    uint16_t reserved;      /* always 0 */
    uint16_t rcode;         /* response code of the answer (SECURE, INSECURE) */
    uint16_t rtype;         /* RR type where validation failed (BOGUS, INDETERMINATE) */
    uint32_t ttl;           /* TTL to cache the answer for (SECURE, INSECURE) */
    uint32_t fetches;       /* follow-up queries made */
    uint32_t verifications; /* signature verifications made */
    uint32_t text_len;      /* bytes of answer text, excluding the NUL */
    /* NUL-terminated presentation-format name: the zone where insecurity was
     * established (INSECURE) or where validation failed (BOGUS,
     * INDETERMINATE); empty otherwise. */
    char where[ZIG_DNSSEC_WHERE_MAX];
} zig_dnssec_verdict;

/* ---- Transport --------------------------------------------------------------
 *
 * Sends one DNS query message and stores the response message. The library
 * sets the CD and DO bits and validates everything itself; the upstream only
 * has to pass messages through (DNS-over-HTTPS is the intended carrier).
 * Return 0 on success and any other value on failure. response_cap is 65535.
 */
typedef int (*zig_dnssec_exchange_fn)(void *ctx, const uint8_t *query, size_t query_len,
                                      uint8_t *response, size_t response_cap,
                                      size_t *response_len);

/* ---- Functions ------------------------------------------------------------ */

/* ZIG_DNSSEC_ABI_VERSION of the library actually linked. */
uint32_t zig_dnssec_abi_version(void);

/*
 * Queries qname/qtype through `exchange` and validates the answer.
 *
 *   anchors  trust anchors as DS or DNSKEY records in presentation format,
 *            NUL-terminated; NULL selects the built-in IANA root anchors.
 *   qname    NUL-terminated domain name; qtype a data RR type (not a meta-type).
 *   now      the time to check signature validity against, in seconds since
 *            the Unix epoch. The library never reads the clock itself.
 *   policy   ZIG_DNSSEC_POLICY_* bits, 0 for the defaults.
 *   out      receives the verdict (required).
 *   text     set to the empty string first; then receives the answer RRsets in
 *            presentation format, one record per line, NUL-terminated, for
 *            SECURE and INSECURE only. May be NULL when only the verdict is
 *            wanted (text_len still reports the size).
 */
int zig_dnssec_validate(zig_dnssec_exchange_fn exchange, void *ctx, const char *anchors,
                        const char *qname, uint16_t qtype, int64_t now, uint32_t policy,
                        zig_dnssec_verdict *out, char *text, size_t text_cap);

/*
 * As zig_dnssec_validate, answering every query from a recorded trace
 * (lines of "<qname> <TYPE> <base64 response>", as written by
 * `dnssec-stub --record`). Offline and deterministic; meant for tests and for
 * re-checking a recorded resolution.
 */
int zig_dnssec_validate_trace(const char *trace, const char *anchors, const char *qname,
                              uint16_t qtype, int64_t now, uint32_t policy,
                              zig_dnssec_verdict *out, char *text, size_t text_cap);

/* Static, NUL-terminated names; "unknown" for codes outside the tables. */
const char *zig_dnssec_status_name(int status);
const char *zig_dnssec_security_name(uint8_t security);
const char *zig_dnssec_reason_name(uint8_t reason);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_DNSSEC_H */
