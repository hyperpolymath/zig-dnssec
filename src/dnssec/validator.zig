// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Chain-of-trust validation of DNS responses for a security-aware stub
//! (RFC 4033 §4.9, RFC 4035 §5).
//!
//! Model: the stub asks a recursive resolver (with DO=1, CD=1) and then
//! authenticates the answer itself. Missing keys and delegation signers
//! are fetched through a caller-supplied `Fetcher` and walked bottom-up to
//! the closest configured trust anchor.
//!
//! Outcomes are a tagged union. The answer data is only reachable through
//! the `.secure` arm, or through the `.insecure` arm together with the
//! reason and the zone where insecurity was *proven*. Every failure path
//! returns `.bogus` or `.indeterminate`; nothing falls through to
//! `.insecure` without an authenticated proof (or an explicit policy that
//! the caller opted into).

const std = @import("std");
const wire_name = @import("../wire/name.zig");
const types = @import("../wire/types.zig");
const rdata = @import("../wire/rdata.zig");
const message = @import("../wire/message.zig");
const crypto = @import("crypto.zig");
const keys = @import("keys.zig");
const rrset_mod = @import("rrset.zig");
const nsec = @import("nsec.zig");
const nsec3 = @import("nsec3.zig");
const anchors_mod = @import("anchors.zig");

const Name = wire_name.Name;
const Type = types.Type;
const RrSet = rrset_mod.RrSet;
const Allocator = std.mem.Allocator;
pub const TrustAnchors = anchors_mod.TrustAnchors;

pub const Security = enum { secure, insecure, bogus, indeterminate };

pub const Reason = enum {
    // --- insecure (proven or policy) ---
    /// Authenticated proof that a delegation has no DS (RFC 4035 §5.2).
    insecure_delegation,
    /// NSEC3 Opt-Out covers the relevant name (RFC 5155 §9.2).
    nsec3_opt_out,
    /// Policy `.insecure`: the DS set has only unsupported algorithms.
    unsupported_algorithm_policy,
    /// Policy `.insecure`: NSEC3 iterations above the configured limit.
    nsec3_iterations_policy,

    // --- bogus ---
    signature_invalid,
    signature_expired,
    signature_not_yet_valid,
    signature_bad_period,
    /// No RRSIG names a usable key (tag/algorithm) in the zone's key set.
    no_matching_key,
    /// RRSIGs present but none with a supported, enabled algorithm.
    no_supported_signature,
    /// Unsigned data in a zone that is provably signed.
    missing_signature,
    /// The zone's DNSKEY RRset could not be obtained (a missing chain link).
    dnskey_missing,
    /// No DNSKEY matching an authenticated DS (or anchor) signs the key set.
    dnskey_not_authenticated,
    /// The DS RRset failed to verify with the parent's keys.
    ds_not_authenticated,
    /// RRSIG signer is not an ancestor of the owner, or a DS/denial signer
    /// is not a proper ancestor where it must be.
    bad_signer,
    /// Authenticated NSEC/NSEC3 do not prove what the response claims.
    denial_failed,
    /// A negative or wildcard response from a signed zone without proof.
    denial_missing,
    nsec3_inconsistent_params,
    /// Policy `.fail` (default): only unsupported algorithms available.
    unsupported_algorithm,
    /// Policy `.fail` (default): NSEC3 iterations above the limit.
    nsec3_iterations_exceeded,
    /// Fetch, signature or hash budget exhausted (KeyTrap-class defence).
    resource_limit,
    cname_loop,
    dname_mismatch,
    /// The response does not answer the question asked, or is inconsistent.
    malformed_response,
    /// Recursion detected while establishing zone keys.
    chain_loop,

    // --- indeterminate ---
    no_trust_anchor,
    fetch_failed,
    upstream_rcode,
    truncated,

    pub fn fromSigError(e: anyerror) Reason {
        return switch (e) {
            error.SignatureExpired => .signature_expired,
            error.SignatureNotYetValid => .signature_not_yet_valid,
            error.BadValidityPeriod => .signature_bad_period,
            error.SignerNotAncestor => .bad_signer,
            error.UnsupportedAlgorithm, error.UnsupportedKeySize => .no_supported_signature,
            else => .signature_invalid,
        };
    }
};

pub const Failure = struct {
    reason: Reason,
    /// Name at which the failure was detected.
    name: Name,
    rtype: Type,
    /// The underlying error, when one exists (e.g. error.SignatureExpired).
    detail: ?anyerror = null,
};

pub const Answer = struct {
    rcode: types.Rcode,
    qname: Name,
    qtype: Type,
    /// Name the answer (or the denial) applies to after CNAME/DNAME chasing.
    final_name: Name,
    /// The CNAME/DNAME chain and, for positive answers, the final RRset.
    rrsets: []const RrSet,
    ttl: u32,
};

pub const Insecure = struct {
    answer: Answer,
    reason: Reason,
    /// Zone (or delegation point) at which insecurity was established.
    zone: Name,
};

pub const Verdict = union(Security) {
    secure: Answer,
    insecure: Insecure,
    bogus: Failure,
    indeterminate: Failure,
};

pub const Stats = struct {
    fetches: u32 = 0,
    verifications: u32 = 0,
};

pub const Result = struct {
    arena: std.heap.ArenaAllocator,
    verdict: Verdict,
    stats: Stats,

    pub fn deinit(r: *Result) void {
        r.arena.deinit();
        r.* = undefined;
    }

    pub fn security(r: *const Result) Security {
        return r.verdict;
    }
};

pub const Policy = struct {
    /// What to do when a DS RRset (or anchor) contains only algorithms or
    /// digests this library cannot use. RFC 4035 §5.2 says "insecure";
    /// the default here is to fail, so that a gap in this implementation
    /// never turns into an unauthenticated answer.
    unsupported_algorithm: enum { fail, insecure } = .fail,
    /// NSEC3 iterations above `max_nsec3_iterations`: RFC 9276 §3.2 allows
    /// insecure or SERVFAIL; the default is to fail.
    nsec3_iterations: enum { fail, insecure } = .fail,
    max_nsec3_iterations: u16 = 150,
    /// Accept RSASHA1 / RSASHA1-NSEC3-SHA1 signatures and SHA-1 DS digests.
    /// RFC 9905 directs operators to treat them as unsupported; implementing
    /// them remains a MUST, so they are on by default and can be disabled.
    allow_sha1: bool = true,
    /// Symmetric tolerance on RRSIG validity windows, in seconds.
    clock_skew: u32 = 0,
    max_fetches: u32 = 64,
    max_verifications: u32 = 512,
    /// Failed signature checks tolerated per RRset (KeyTrap mitigation).
    max_failures_per_rrset: u32 = 8,
    max_nsec3_hashes: u32 = 128,
    max_chain: u32 = 12,
};

/// Source of DS and DNSKEY responses (the stub's upstream resolver).
pub const Fetcher = struct {
    ptr: *anyopaque,
    fetchFn: *const fn (ptr: *anyopaque, gpa: Allocator, qname: Name, qtype: Type) anyerror!message.Message,

    pub fn fetch(f: Fetcher, gpa: Allocator, qname: Name, qtype: Type) anyerror!message.Message {
        return f.fetchFn(f.ptr, gpa, qname, qtype);
    }
};

pub const Validator = struct {
    anchors: *const TrustAnchors,
    policy: Policy = .{},
    fetcher: Fetcher,

    /// Validates `response` as the answer to (qname, qtype, IN). `now` is
    /// seconds since the epoch (it is reduced modulo 2^32 for RRSIG serial
    /// arithmetic). The response must already have been matched to the
    /// query by the transport (ID, source).
    pub fn validate(
        v: *const Validator,
        gpa: Allocator,
        qname: Name,
        qtype: Type,
        response: *const message.Message,
        now: i64,
    ) Allocator.Error!Result {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        var s: Session = .{
            .a = arena.allocator(),
            .v = v,
            .now = @truncate(@as(u64, @bitCast(now))),
        };
        const verdict = try s.validateResponse(qname, qtype, response);
        return .{ .arena = arena, .verdict = verdict, .stats = s.stats };
    }
};

// ---------------------------------------------------------------------------
// Internal state for one validation.
// ---------------------------------------------------------------------------

const KeyStatus = union(enum) {
    secure: *const RrSet,
    insecure: struct { reason: Reason, zone: Name },
    bogus: Failure,
    indeterminate: Failure,
};

const NameStatus = union(enum) {
    /// Unsigned data here is legitimately unsigned.
    insecure: struct { reason: Reason, zone: Name },
    /// The name lies in this zone, which is provably signed.
    signed_zone: Name,
    bogus: Failure,
    indeterminate: Failure,
};

/// Combined status while assembling an answer.
const Acc = struct {
    insecure: ?struct { reason: Reason, zone: Name } = null,
    ttl: u32 = std.math.maxInt(u32),

    fn markInsecure(acc: *Acc, reason: Reason, zone: Name) void {
        if (acc.insecure == null) acc.insecure = .{ .reason = reason, .zone = zone };
    }
};

const SetOutcome = union(enum) {
    secure: struct { signer: Name, labels: u8, ttl: u32 },
    insecure: struct { reason: Reason, zone: Name },
    bogus: Failure,
    indeterminate: Failure,
};

const Session = struct {
    a: Allocator,
    v: *const Validator,
    now: u32,
    stats: Stats = .{},
    zone_cache: std.ArrayList(struct { name: Name, status: KeyStatus }) = .empty,
    in_progress: std.ArrayList(Name) = .empty,
    fetch_cache: std.ArrayList(struct { name: Name, t: Type, msg: ?*message.Message }) = .empty,

    fn fail(reason: Reason, n: Name, t: Type, detail: ?anyerror) Failure {
        return .{ .reason = reason, .name = n, .rtype = t, .detail = detail };
    }

    // ----- fetching ------------------------------------------------------

    const FetchResult = union(enum) { ok: *message.Message, err: Failure };

    fn fetch(s: *Session, n: Name, t: Type) Allocator.Error!FetchResult {
        for (s.fetch_cache.items) |e| {
            if (e.t == t and e.name.eql(&n)) {
                if (e.msg) |m| return .{ .ok = m };
                return .{ .err = fail(.fetch_failed, n, t, null) };
            }
        }
        if (s.stats.fetches >= s.v.policy.max_fetches) return .{ .err = fail(.resource_limit, n, t, null) };
        s.stats.fetches += 1;
        const got = s.v.fetcher.fetch(s.a, n, t) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            try s.fetch_cache.append(s.a, .{ .name = n, .t = t, .msg = null });
            return .{ .err = fail(.fetch_failed, n, t, e) };
        };
        const m = try s.a.create(message.Message);
        m.* = got;
        if (shapeCheck(m, n, t)) |f| {
            try s.fetch_cache.append(s.a, .{ .name = n, .t = t, .msg = null });
            return .{ .err = f };
        }
        try s.fetch_cache.append(s.a, .{ .name = n, .t = t, .msg = m });
        return .{ .ok = m };
    }

    /// Response sanity common to the main answer and fetched responses.
    fn shapeCheck(m: *const message.Message, qname: Name, qtype: Type) ?Failure {
        const h = m.header;
        if (!h.flags.qr or h.flags.opcode != .query) return fail(.malformed_response, qname, qtype, null);
        if (m.questions.len != 1) return fail(.malformed_response, qname, qtype, null);
        const q = m.questions[0];
        if (!q.name.eql(&qname) or q.qtype != qtype or q.qclass != .in) return fail(.malformed_response, qname, qtype, null);
        if (h.flags.tc) return fail(.truncated, qname, qtype, null);
        switch (m.rcode()) {
            .noerror, .nxdomain => {},
            else => return fail(.upstream_rcode, qname, qtype, null),
        }
        return null;
    }

    // ----- signature checking ---------------------------------------------

    const KeyCheck = union(enum) { ok: u32, err: Failure };

    /// Verifies `set` with any key in `keyset` (all of which share the zone
    /// name `keyset.name`). Bounded by the per-RRset failure budget.
    fn verifyWithKeys(s: *Session, set: *const RrSet, keyset: *const RrSet) Allocator.Error!KeyCheck {
        var failures: u32 = 0;
        var last: ?Failure = null;
        var any_supported = false;
        for (set.sigs) |*sig| {
            if (!sig.rrsig.signer.eql(&keyset.name)) continue;
            const alg = sig.rrsig.algorithm;
            if (!crypto.isSupported(alg)) continue;
            if (crypto.usesSha1(alg) and !s.v.policy.allow_sha1) continue;
            any_supported = true;
            for (keyset.rdatas) |kr| {
                if (kr.len < 4 or kr[3] != @backingInt(alg)) continue;
                if (keys.keyTag(kr) != sig.rrsig.key_tag) continue;
                if (s.stats.verifications >= s.v.policy.max_verifications or failures >= s.v.policy.max_failures_per_rrset) {
                    return .{ .err = fail(.resource_limit, set.name, set.type, null) };
                }
                s.stats.verifications += 1;
                if (rrset_mod.verify(s.a, set, sig, &keyset.name, kr, s.now, s.v.policy.clock_skew)) |_| {
                    return .{ .ok = rrset_mod.effectiveTtl(set, sig, s.now) };
                } else |e| {
                    if (e == error.OutOfMemory) return error.OutOfMemory;
                    failures += 1;
                    last = fail(Reason.fromSigError(e), set.name, set.type, e);
                }
            }
        }
        if (last) |l| return .{ .err = l };
        if (!any_supported) return .{ .err = fail(.no_supported_signature, set.name, set.type, null) };
        return .{ .err = fail(.no_matching_key, set.name, set.type, null) };
    }

    /// Authenticates one RRset from a response.
    fn validateSet(s: *Session, set: *const RrSet) Allocator.Error!SetOutcome {
        if (!set.isSigned()) {
            return switch (try s.nameStatus(set.name)) {
                .insecure => |i| .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
                .signed_zone => .{ .bogus = fail(.missing_signature, set.name, set.type, null) },
                .bogus => |f| .{ .bogus = f },
                .indeterminate => |f| .{ .indeterminate = f },
            };
        }
        // Try each distinct signer named by the RRSIGs.
        var first_failure: ?SetOutcome = null;
        for (set.sigs, 0..) |*sig, si| {
            const signer = sig.rrsig.signer;
            var dup = false;
            for (set.sigs[0..si]) |*prev| if (prev.rrsig.signer.eql(&signer)) {
                dup = true;
            };
            if (dup) continue;
            if (!set.name.isSubdomainOf(&signer)) {
                if (first_failure == null) first_failure = .{ .bogus = fail(.bad_signer, set.name, set.type, null) };
                continue;
            }
            const out: SetOutcome = switch (try s.zoneStatus(signer)) {
                .secure => |ks| switch (try s.verifyWithKeys(set, ks)) {
                    .ok => |ttl| .{ .secure = .{ .signer = signer, .labels = labelsUsed(set, signer), .ttl = ttl } },
                    .err => |f| .{ .bogus = f },
                },
                .insecure => |i| .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
                .bogus => |f| .{ .bogus = f },
                .indeterminate => |f| .{ .indeterminate = f },
            };
            if (out == .secure or out == .insecure) return out;
            if (first_failure == null) first_failure = out;
        }
        return first_failure.?;
    }

    /// Smallest RRSIG Labels value among the set's signatures by `signer`
    /// (a value below the owner's label count means wildcard expansion).
    fn labelsUsed(set: *const RrSet, signer: Name) u8 {
        var l: u8 = set.name.rrsigLabelCount();
        for (set.sigs) |*sig| {
            if (sig.rrsig.signer.eql(&signer)) l = @min(l, sig.rrsig.labels);
        }
        return l;
    }

    // ----- zone keys --------------------------------------------------------

    fn zoneStatus(s: *Session, zone: Name) Allocator.Error!KeyStatus {
        for (s.zone_cache.items) |e| if (e.name.eql(&zone)) return e.status;
        for (s.in_progress.items) |n| if (n.eql(&zone)) {
            return .{ .bogus = fail(.chain_loop, zone, .dnskey, null) };
        };
        try s.in_progress.append(s.a, zone);
        const st = try s.computeZoneStatus(zone);
        _ = s.in_progress.pop();
        try s.zone_cache.append(s.a, .{ .name = zone, .status = st });
        return st;
    }

    fn computeZoneStatus(s: *Session, zone: Name) Allocator.Error!KeyStatus {
        const anchor = s.v.anchors.closest(&zone) orelse
            return .{ .indeterminate = fail(.no_trust_anchor, zone, .dnskey, null) };
        if (anchor.name.eql(&zone)) return s.anchoredKeys(zone, anchor);

        const m = switch (try s.fetch(zone, .ds)) {
            .ok => |m| m,
            .err => |f| return failureToKey(f),
        };
        const ans = try rrset_mod.group(s.a, m.answer);
        const auth = try rrset_mod.group(s.a, m.authority);

        if (findSet(ans.sets, &zone, .ds)) |ds_set| {
            if (!ds_set.isSigned()) {
                // Unsigned DS: acceptable only if the parent side is insecure.
                const parent = zone.parent() orelse return .{ .bogus = fail(.missing_signature, zone, .ds, null) };
                return switch (try s.nameStatus(parent)) {
                    .insecure => |i| .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
                    .signed_zone => .{ .bogus = fail(.missing_signature, zone, .ds, null) },
                    .bogus => |f| .{ .bogus = f },
                    .indeterminate => |f| .{ .indeterminate = f },
                };
            }
            const p = ds_set.sigs[0].rrsig.signer;
            if (!zone.isStrictSubdomainOf(&p)) return .{ .bogus = fail(.bad_signer, zone, .ds, null) };
            switch (try s.zoneStatus(p)) {
                .secure => |pk| switch (try s.verifyWithKeys(ds_set, pk)) {
                    .ok => {},
                    .err => |f| return .{ .bogus = .{ .reason = if (f.reason == .resource_limit) .resource_limit else .ds_not_authenticated, .name = zone, .rtype = .ds, .detail = f.detail } },
                },
                .insecure => |i| return .{ .insecure = i },
                .bogus => |f| return .{ .bogus = f },
                .indeterminate => |f| return .{ .indeterminate = f },
            }
            return s.keysFromDs(zone, ds_set.rdatas);
        }

        // Negative DS response.
        const denial = try s.collectDenial(&auth, &zone, true);
        switch (denial) {
            .none => |soa_owner| {
                // Unsigned negative answer: the zone that answered must be
                // provably insecure.
                const y = soa_owner orelse (zone.parent() orelse return .{ .bogus = fail(.denial_missing, zone, .ds, null) });
                if (!zone.isStrictSubdomainOf(&y)) return .{ .bogus = fail(.malformed_response, zone, .ds, null) };
                return switch (try s.nameStatus(y)) {
                    .insecure => |i| .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
                    .signed_zone => .{ .bogus = fail(.denial_missing, zone, .ds, null) },
                    .bogus => |f| .{ .bogus = f },
                    .indeterminate => |f| .{ .indeterminate = f },
                };
            },
            .failed => |f| return failureToKey(f),
            .insecure => |i| return .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
            .ok => |d| {
                return switch (try s.proveInsecureDelegation(&d, zone)) {
                    .proven => |r| .{ .insecure = .{ .reason = r, .zone = zone } },
                    .not_proven => |f| .{ .bogus = f },
                };
            },
        }
    }

    fn failureToKey(f: Failure) KeyStatus {
        return switch (f.reason) {
            .no_trust_anchor, .fetch_failed, .upstream_rcode, .truncated => .{ .indeterminate = f },
            else => .{ .bogus = f },
        };
    }

    const DsUse = struct { usable: std.ArrayList(rdata.Ds), unsupported_seen: bool };

    fn usableDs(s: *Session, ds_rdatas: []const []const u8) Allocator.Error!DsUse {
        var out: DsUse = .{ .usable = .empty, .unsupported_seen = false };
        var has_strong = false;
        for (ds_rdatas) |rd| {
            const d = rdata.Ds.parse(rd) catch continue;
            const ok_digest = keys.digestSupported(d.digest_type) and (d.digest_type != .sha1 or s.v.policy.allow_sha1);
            const ok_alg = crypto.isSupported(d.algorithm) and (!crypto.usesSha1(d.algorithm) or s.v.policy.allow_sha1);
            if (!ok_digest or !ok_alg) {
                out.unsupported_seen = true;
                continue;
            }
            if (d.digest_type != .sha1) has_strong = true;
            try out.usable.append(s.a, d);
        }
        if (has_strong) {
            // RFC 4509 §3: ignore SHA-1 DS when SHA-256 (or stronger) exists.
            var i: usize = 0;
            while (i < out.usable.items.len) {
                if (out.usable.items[i].digest_type == .sha1) _ = out.usable.swapRemove(i) else i += 1;
            }
        }
        return out;
    }

    fn unsupportedOutcome(s: *Session, zone: Name) KeyStatus {
        return switch (s.v.policy.unsupported_algorithm) {
            .insecure => .{ .insecure = .{ .reason = .unsupported_algorithm_policy, .zone = zone } },
            .fail => .{ .bogus = fail(.unsupported_algorithm, zone, .ds, null) },
        };
    }

    fn fetchKeyset(s: *Session, zone: Name) Allocator.Error!union(enum) { ok: *const RrSet, err: KeyStatus } {
        const m = switch (try s.fetch(zone, .dnskey)) {
            .ok => |m| m,
            .err => |f| return .{ .err = if (f.reason == .fetch_failed or f.reason == .upstream_rcode or f.reason == .truncated)
                .{ .indeterminate = f }
            else
                .{ .bogus = f } },
        };
        const ans = try rrset_mod.group(s.a, m.answer);
        const ks = findSet(ans.sets, &zone, .dnskey) orelse return .{ .err = .{ .bogus = fail(.dnskey_missing, zone, .dnskey, null) } };
        if (!ks.isSigned()) return .{ .err = .{ .bogus = fail(.missing_signature, zone, .dnskey, null) } };
        return .{ .ok = ks };
    }

    /// Authenticates the zone's DNSKEY RRset from DS records that are
    /// themselves already trusted (authenticated, or a trust anchor).
    fn keysFromDs(s: *Session, zone: Name, ds_rdatas: []const []const u8) Allocator.Error!KeyStatus {
        const use = try s.usableDs(ds_rdatas);
        if (use.usable.items.len == 0) return s.unsupportedOutcome(zone);
        const ks = switch (try s.fetchKeyset(zone)) {
            .ok => |k| k,
            .err => |st| return st,
        };
        var last: ?Failure = null;
        var failures: u32 = 0;
        for (use.usable.items) |ds| {
            for (ks.rdatas) |kr| {
                if (keys.dsMatches(ds, &zone, kr) != .match) continue;
                const key = rdata.Dnskey.parse(kr) catch continue;
                if (key.protocol != 3 or !key.isZoneKey() or key.isRevoked()) continue;
                for (ks.sigs) |*sig| {
                    if (sig.rrsig.key_tag != ds.key_tag or sig.rrsig.algorithm != ds.algorithm) continue;
                    if (s.stats.verifications >= s.v.policy.max_verifications or failures >= s.v.policy.max_failures_per_rrset) {
                        return .{ .bogus = fail(.resource_limit, zone, .dnskey, null) };
                    }
                    s.stats.verifications += 1;
                    if (rrset_mod.verify(s.a, ks, sig, &zone, kr, s.now, s.v.policy.clock_skew)) |_| {
                        return .{ .secure = ks };
                    } else |e| {
                        if (e == error.OutOfMemory) return error.OutOfMemory;
                        failures += 1;
                        last = fail(Reason.fromSigError(e), zone, .dnskey, e);
                    }
                }
            }
        }
        if (last) |l| {
            if (l.reason == .signature_invalid) return .{ .bogus = .{ .reason = .dnskey_not_authenticated, .name = zone, .rtype = .dnskey, .detail = l.detail } };
            return .{ .bogus = l };
        }
        return .{ .bogus = fail(.dnskey_not_authenticated, zone, .dnskey, null) };
    }

    fn anchoredKeys(s: *Session, zone: Name, anchor: *const anchors_mod.Anchor) Allocator.Error!KeyStatus {
        if (anchor.ds.len > 0) {
            const st = try s.keysFromDs(zone, anchor.ds);
            if (st == .secure or anchor.dnskey.len == 0) return st;
        }
        // DNSKEY anchors: the anchored key itself must sign the key set.
        var supported = false;
        for (anchor.dnskey) |ak| {
            const k = rdata.Dnskey.parse(ak) catch continue;
            if (crypto.isSupported(k.algorithm) and (!crypto.usesSha1(k.algorithm) or s.v.policy.allow_sha1)) supported = true;
        }
        if (!supported) return s.unsupportedOutcome(zone);
        const ks = switch (try s.fetchKeyset(zone)) {
            .ok => |k| k,
            .err => |st| return st,
        };
        const trusted: RrSet = blk: {
            var list: std.ArrayList([]const u8) = .empty;
            for (ks.rdatas) |kr| for (anchor.dnskey) |ak| {
                if (std.mem.eql(u8, kr, ak)) try list.append(s.a, kr);
            };
            break :blk .{ .name = zone, .type = .dnskey, .class = .in, .ttl = 0, .rdatas = list.items, .sigs = &.{} };
        };
        if (trusted.rdatas.len == 0) return .{ .bogus = fail(.dnskey_not_authenticated, zone, .dnskey, null) };
        return switch (try s.verifyWithKeys(ks, &trusted)) {
            .ok => .{ .secure = ks },
            .err => |f| .{ .bogus = .{ .reason = if (f.reason == .signature_invalid) .dnskey_not_authenticated else f.reason, .name = zone, .rtype = .dnskey, .detail = f.detail } },
        };
    }

    // ----- insecurity proofs for unsigned data -------------------------------

    /// Is unsigned data at `start` legitimately unsigned?
    fn nameStatus(s: *Session, start: Name) Allocator.Error!NameStatus {
        var x = start;
        var steps: u32 = 0;
        while (true) : (steps += 1) {
            if (steps > wire_name.max_labels + 1) return .{ .bogus = fail(.chain_loop, start, .ds, null) };
            const anchor = s.v.anchors.closest(&x) orelse
                return .{ .indeterminate = fail(.no_trust_anchor, x, .ds, null) };
            if (anchor.name.eql(&x)) return keyToName(try s.zoneStatus(x), x);

            const m = switch (try s.fetch(x, .ds)) {
                .ok => |m| m,
                .err => |f| return switch (failureToKey(f)) {
                    .bogus => |ff| .{ .bogus = ff },
                    .indeterminate => |ff| .{ .indeterminate = ff },
                    else => unreachable,
                },
            };
            const ans = try rrset_mod.group(s.a, m.answer);
            const auth = try rrset_mod.group(s.a, m.authority);
            if (findSet(ans.sets, &x, .ds)) |ds_set| {
                if (ds_set.isSigned()) return keyToName(try s.zoneStatus(x), x);
                x = x.parent() orelse return .{ .bogus = fail(.missing_signature, start, .ds, null) };
                continue;
            }
            switch (try s.collectDenial(&auth, &x, true)) {
                .none => |soa_owner| {
                    if (soa_owner) |y| {
                        if (x.isStrictSubdomainOf(&y)) return keyToName(try s.zoneStatus(y), y);
                    }
                    x = x.parent() orelse return .{ .bogus = fail(.denial_missing, start, .ds, null) };
                },
                .failed => |f| return switch (failureToKey(f)) {
                    .bogus => |ff| .{ .bogus = ff },
                    .indeterminate => |ff| .{ .indeterminate = ff },
                    else => unreachable,
                },
                .insecure => |i| return .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
                .ok => |d| {
                    return switch (try s.proveInsecureDelegation(&d, x)) {
                        .proven => |r| .{ .insecure = .{ .reason = r, .zone = x } },
                        // x exists inside the signed zone d.zone (or does not
                        // exist at all): unsigned data there is not acceptable.
                        .not_proven => .{ .signed_zone = d.zone },
                    };
                },
            }
        }
    }

    fn keyToName(k: KeyStatus, zone: Name) NameStatus {
        return switch (k) {
            .secure => .{ .signed_zone = zone },
            .insecure => |i| .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
            .bogus => |f| .{ .bogus = f },
            .indeterminate => |f| .{ .indeterminate = f },
        };
    }

    // ----- denial records ------------------------------------------------------

    const Denial = struct {
        zone: Name,
        nsec_recs: []nsec.Record,
        nsec3_recs: []nsec3.Record,
    };

    const DenialCollect = union(enum) {
        /// No signed NSEC/NSEC3 at all; the SOA owner, if an SOA was present.
        none: ?Name,
        failed: Failure,
        /// The zone that signed the denial records is itself insecure.
        insecure: struct { reason: Reason, zone: Name },
        ok: Denial,
    };

    /// Authenticates the NSEC/NSEC3 (and SOA) RRsets of an authority section
    /// for denying something at `target`. With `strict_parent`, the signer
    /// must be a proper ancestor of `target` (DS denials come from the
    /// parent side).
    fn collectDenial(s: *Session, auth: *const rrset_mod.Grouped, target: *const Name, strict_parent: bool) Allocator.Error!DenialCollect {
        var soa_owner: ?Name = null;
        var zone: ?Name = null;
        for (auth.sets) |*set| {
            if (set.type == .soa) soa_owner = set.name;
            if (set.type != .nsec and set.type != .nsec3) continue;
            if (!set.isSigned()) continue;
            const signer = set.sigs[0].rrsig.signer;
            const ok_rel = if (strict_parent) target.isStrictSubdomainOf(&signer) else target.isSubdomainOf(&signer);
            if (!ok_rel) continue;
            if (zone == null or signer.labelCount() > zone.?.labelCount()) zone = signer;
        }
        const z = zone orelse {
            // Unsigned NSEC/NSEC3 or SOA cannot prove anything; a signed SOA
            // without denial records means a signed zone omitted its proof.
            for (auth.sets) |*set| if (set.type == .soa and set.isSigned()) {
                if (target.isSubdomainOf(&set.name)) {
                    return switch (try s.zoneStatus(set.sigs[0].rrsig.signer)) {
                        .secure => .{ .failed = fail(.denial_missing, target.*, .soa, null) },
                        .insecure => |i| .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
                        .bogus => |f| .{ .failed = f },
                        .indeterminate => |f| .{ .failed = f },
                    };
                }
            };
            return .{ .none = soa_owner };
        };
        const ks = switch (try s.zoneStatus(z)) {
            .secure => |k| k,
            .insecure => |i| return .{ .insecure = .{ .reason = i.reason, .zone = i.zone } },
            .bogus => |f| return .{ .failed = f },
            .indeterminate => |f| return .{ .failed = f },
        };
        var n_list: std.ArrayList(nsec.Record) = .empty;
        var n3_list: std.ArrayList(nsec3.Record) = .empty;
        for (auth.sets) |*set| {
            const relevant = set.type == .nsec or set.type == .nsec3 or set.type == .soa;
            if (!relevant) continue;
            if (!set.isSigned() or !set.sigs[0].rrsig.signer.eql(&z)) {
                if (set.type == .soa and set.name.eql(&z)) return .{ .failed = fail(.missing_signature, set.name, .soa, null) };
                continue;
            }
            switch (try s.verifyWithKeys(set, ks)) {
                .ok => {},
                .err => |f| return .{ .failed = f },
            }
            // Denial records must not themselves be wildcard expansions.
            if (labelsUsed(set, z) != set.name.rrsigLabelCount() and set.type != .soa) {
                return .{ .failed = fail(.denial_failed, set.name, set.type, null) };
            }
            for (set.rdatas) |rd| switch (set.type) {
                .nsec => {
                    const parsed = rdata.Nsec.parse(rd) catch return .{ .failed = fail(.malformed_response, set.name, .nsec, null) };
                    try n_list.append(s.a, .{ .owner = set.name, .nsec = parsed, .zone = z });
                },
                .nsec3 => {
                    const rec = nsec3.Record.fromRr(set.name, rd, &z) catch |e| switch (e) {
                        error.Ignored => continue,
                        else => return .{ .failed = fail(.malformed_response, set.name, .nsec3, e) },
                    };
                    try n3_list.append(s.a, rec);
                },
                else => {},
            };
        }
        if (n_list.items.len == 0 and n3_list.items.len == 0) return .{ .failed = fail(.denial_missing, target.*, .nsec, null) };
        return .{ .ok = .{ .zone = z, .nsec_recs = n_list.items, .nsec3_recs = n3_list.items } };
    }

    const ProofOutcome = union(enum) { proven: Reason, not_proven: Failure };

    fn proveInsecureDelegation(s: *Session, d: *const Denial, child: Name) Allocator.Error!ProofOutcome {
        if (d.nsec_recs.len > 0) {
            return switch (nsec.provesInsecureDelegation(d.nsec_recs, &child)) {
                .proven => .{ .proven = .insecure_delegation },
                .failed => .{ .not_proven = fail(.denial_failed, child, .ds, null) },
            };
        }
        var p = switch (try s.nsec3Proof(d)) {
            .ok => |p| p,
            .err => |o| return o,
        };
        return switch (p.provesInsecureDelegation(&child)) {
            .proven => .{ .proven = .insecure_delegation },
            .opt_out => .{ .proven = .nsec3_opt_out },
            .resource_limit => .{ .not_proven = fail(.resource_limit, child, .ds, null) },
            else => .{ .not_proven = fail(.denial_failed, child, .ds, null) },
        };
    }

    fn nsec3Proof(s: *Session, d: *const Denial) Allocator.Error!union(enum) { ok: nsec3.Proof, err: ProofOutcome } {
        const scratch = try s.a.alloc(nsec3.Record, d.nsec3_recs.len);
        const cfg: nsec3.Config = .{ .max_iterations = s.v.policy.max_nsec3_iterations, .max_hashes = s.v.policy.max_nsec3_hashes };
        return switch (nsec3.Proof.init(d.nsec3_recs, d.zone, cfg, scratch)) {
            .ok => |p| .{ .ok = p },
            .err => |e| switch (e) {
                .iterations_exceeded => switch (s.v.policy.nsec3_iterations) {
                    .insecure => .{ .err = .{ .proven = .nsec3_iterations_policy } },
                    .fail => .{ .err = .{ .not_proven = fail(.nsec3_iterations_exceeded, d.zone, .nsec3, null) } },
                },
                .inconsistent_params => .{ .err = .{ .not_proven = fail(.nsec3_inconsistent_params, d.zone, .nsec3, null) } },
                .no_records => .{ .err = .{ .not_proven = fail(.denial_missing, d.zone, .nsec3, null) } },
            },
        };
    }

    const DenialKind = union(enum) { nxdomain, nodata: Type, wildcard: u8 };

    /// Proves a denial (or a wildcard expansion) for `sname` from the
    /// response's own authority section.
    fn proveDenial(s: *Session, auth: *const rrset_mod.Grouped, sname: Name, kind: DenialKind, acc: *Acc) Allocator.Error!?Verdict {
        const strict = kind == .nodata and kind.nodata == .ds;
        switch (try s.collectDenial(auth, &sname, strict)) {
            .none => |soa_owner| {
                // A wildcard expansion was signed by a secure zone, so that zone
                // must also prove the name does not exist.
                if (kind == .wildcard) return .{ .bogus = fail(.denial_missing, sname, .nsec, null) };
                // No signed proof at all: only acceptable in an insecure zone.
                // When the response names its zone (SOA), test that zone: an
                // unsigned denial claiming to come from a signed zone is bogus.
                const probe = if (soa_owner) |y| (if (sname.isSubdomainOf(&y)) y else sname) else sname;
                return switch (try s.nameStatus(probe)) {
                    .insecure => |i| blk: {
                        acc.markInsecure(i.reason, i.zone);
                        break :blk null;
                    },
                    .signed_zone => .{ .bogus = fail(.denial_missing, sname, .nsec, null) },
                    .bogus => |f| .{ .bogus = f },
                    .indeterminate => |f| .{ .indeterminate = f },
                };
            },
            .failed => |f| return switch (failureToKey(f)) {
                .bogus => |ff| .{ .bogus = ff },
                .indeterminate => |ff| .{ .indeterminate = ff },
                else => unreachable,
            },
            .insecure => |i| {
                if (kind == .wildcard) return .{ .bogus = fail(.denial_failed, sname, .nsec, null) };
                acc.markInsecure(i.reason, i.zone);
                return null;
            },
            .ok => |d| {
                if (d.nsec_recs.len > 0) {
                    const r = switch (kind) {
                        .nxdomain => nsec.provesNxDomain(d.nsec_recs, &sname),
                        .nodata => |t| nsec.provesNoData(d.nsec_recs, &sname, t),
                        .wildcard => |l| nsec.provesWildcardAnswer(d.nsec_recs, &sname, l),
                    };
                    return switch (r) {
                        .proven => null,
                        .failed => .{ .bogus = fail(.denial_failed, sname, .nsec, null) },
                    };
                }
                var p = switch (try s.nsec3Proof(&d)) {
                    .ok => |p| p,
                    .err => |o| return switch (o) {
                        .proven => |reason| blk: {
                            acc.markInsecure(reason, d.zone);
                            break :blk null;
                        },
                        .not_proven => |f| .{ .bogus = f },
                    },
                };
                const r = switch (kind) {
                    .nxdomain => p.provesNxDomain(&sname),
                    .nodata => |t| p.provesNoData(&sname, t),
                    .wildcard => |l| p.provesWildcardAnswer(&sname, l),
                };
                return switch (r) {
                    .proven => null,
                    .opt_out => blk: {
                        acc.markInsecure(.nsec3_opt_out, d.zone);
                        break :blk null;
                    },
                    .resource_limit => .{ .bogus = fail(.resource_limit, sname, .nsec3, null) },
                    .iterations_exceeded => .{ .bogus = fail(.nsec3_iterations_exceeded, sname, .nsec3, null) },
                    .failed => .{ .bogus = fail(.denial_failed, sname, .nsec3, null) },
                };
            },
        }
    }

    // ----- the response ---------------------------------------------------------

    fn validateResponse(s: *Session, qname: Name, qtype: Type, m: *const message.Message) Allocator.Error!Verdict {
        if (shapeCheck(m, qname, qtype)) |f| return switch (f.reason) {
            .truncated, .upstream_rcode => .{ .indeterminate = f },
            else => .{ .bogus = f },
        };
        if (qtype == .any or qtype.isMetaOrQtype()) return .{ .bogus = fail(.malformed_response, qname, qtype, null) };
        if (s.v.anchors.closest(&qname) == null) return .{ .indeterminate = fail(.no_trust_anchor, qname, qtype, null) };

        const ans = try rrset_mod.group(s.a, m.answer);
        const auth = try rrset_mod.group(s.a, m.authority);
        var acc: Acc = .{};
        var chain: std.ArrayList(RrSet) = .empty;
        var sname = qname;
        var positive = false;
        var steps: u32 = 0;

        while (true) : (steps += 1) {
            if (steps > s.v.policy.max_chain) return .{ .bogus = fail(.cname_loop, sname, qtype, null) };
            // DNAME first (RFC 6672): a DNAME owned by a proper ancestor of
            // sname redirects it, whatever the query type.
            if (findDname(ans.sets, &sname)) |set| {
                if (set.rdatas.len != 1) return .{ .bogus = fail(.malformed_response, set.name, .dname, null) };
                if (try s.acceptSet(set, &auth, &acc)) |bad| return bad;
                try chain.append(s.a, try s.dupeSet(set));
                const target = rdata.singleName(set.rdatas[0]) catch return .{ .bogus = fail(.malformed_response, set.name, .dname, null) };
                const next = substitute(&sname, &set.name, &target) orelse return .{ .bogus = fail(.dname_mismatch, sname, .dname, null) };
                // The synthesised CNAME is unsigned (RFC 6672 §5.3.1); if
                // present it must agree with the DNAME, and it is not used.
                if (findSet(ans.sets, &sname, .cname)) |c| {
                    const ct = rdata.singleName(c.rdatas[0]) catch return .{ .bogus = fail(.dname_mismatch, sname, .cname, null) };
                    if (c.rdatas.len != 1 or !ct.eql(&next)) return .{ .bogus = fail(.dname_mismatch, sname, .cname, null) };
                }
                sname = next;
                continue;
            }
            if (findSet(ans.sets, &sname, qtype)) |set| {
                if (try s.acceptSet(set, &auth, &acc)) |bad| return bad;
                try chain.append(s.a, try s.dupeSet(set));
                positive = true;
                break;
            }
            if (qtype != .cname) {
                if (findSet(ans.sets, &sname, .cname)) |set| {
                    if (set.rdatas.len != 1) return .{ .bogus = fail(.malformed_response, sname, .cname, null) };
                    if (try s.acceptSet(set, &auth, &acc)) |bad| return bad;
                    try chain.append(s.a, try s.dupeSet(set));
                    sname = rdata.singleName(set.rdatas[0]) catch return .{ .bogus = fail(.malformed_response, sname, .cname, null) };
                    continue;
                }
            }
            break;
        }

        const rcode = m.rcode();
        if (positive) {
            if (rcode != .noerror) return .{ .bogus = fail(.malformed_response, sname, qtype, null) };
        } else {
            const kind: DenialKind = if (rcode == .nxdomain) .nxdomain else .{ .nodata = qtype };
            if (try s.proveDenial(&auth, sname, kind, &acc)) |bad| return bad;
        }

        const answer: Answer = .{
            .rcode = rcode,
            .qname = qname,
            .qtype = qtype,
            .final_name = sname,
            .rrsets = chain.items,
            .ttl = if (acc.ttl == std.math.maxInt(u32)) 0 else acc.ttl,
        };
        if (acc.insecure) |i| return .{ .insecure = .{ .answer = answer, .reason = i.reason, .zone = i.zone } };
        return .{ .secure = answer };
    }

    /// Deep copy into the session arena, so the verdict does not borrow
    /// from the caller's response message.
    fn dupeSet(s: *Session, set: *const RrSet) Allocator.Error!RrSet {
        var out = set.*;
        const rds = try s.a.alloc([]const u8, set.rdatas.len);
        for (set.rdatas, 0..) |rd, i| rds[i] = try s.a.dupe(u8, rd);
        out.rdatas = rds;
        const sigs = try s.a.alloc(rrset_mod.Sig, set.sigs.len);
        for (set.sigs, 0..) |sig, i| {
            const rd = try s.a.dupe(u8, sig.rdata);
            sigs[i] = .{ .rrsig = rdata.Rrsig.parse(rd) catch unreachable, .rdata = rd, .ttl = sig.ttl };
        }
        out.sigs = sigs;
        return out;
    }

    /// Validates a chain RRset, including the wildcard proof if its
    /// signature shows wildcard expansion. Returns a verdict only on failure.
    fn acceptSet(s: *Session, set: *const RrSet, auth: *const rrset_mod.Grouped, acc: *Acc) Allocator.Error!?Verdict {
        switch (try s.validateSet(set)) {
            .secure => |sec| {
                acc.ttl = @min(acc.ttl, sec.ttl);
                if (sec.labels < set.name.rrsigLabelCount()) {
                    if (try s.proveDenial(auth, set.name, .{ .wildcard = sec.labels }, acc)) |bad| return bad;
                }
                return null;
            },
            .insecure => |i| {
                acc.markInsecure(i.reason, i.zone);
                acc.ttl = @min(acc.ttl, set.ttl);
                return null;
            },
            .bogus => |f| return .{ .bogus = f },
            .indeterminate => |f| return .{ .indeterminate = f },
        }
    }
};

fn findSet(sets: []RrSet, n: *const Name, t: Type) ?*RrSet {
    for (sets) |*s| if (s.type == t and s.class == .in and s.name.eql(n)) return s;
    return null;
}

/// A DNAME RRset whose owner is a proper ancestor of `n`.
fn findDname(sets: []RrSet, n: *const Name) ?*RrSet {
    var best: ?*RrSet = null;
    for (sets) |*s| {
        if (s.type != .dname or s.class != .in) continue;
        if (!n.isStrictSubdomainOf(&s.name)) continue;
        if (best == null or s.name.labelCount() > best.?.name.labelCount()) best = s;
    }
    return best;
}

/// RFC 6672 substitution: replace the `owner` suffix of `n` with `target`.
fn substitute(n: *const Name, owner: *const Name, target: *const Name) ?Name {
    const keep = n.labelCount() - owner.labelCount();
    var out = target.*;
    var i: usize = keep;
    while (i > 0) {
        i -= 1;
        out = out.prepend(n.label(i)) catch return null;
    }
    return out;
}

test "DNAME substitution" {
    const n = try Name.fromText("a.b.example.");
    const o = try Name.fromText("example.");
    const t = try Name.fromText("example.net.");
    const r = substitute(&n, &o, &t).?;
    try std.testing.expect(r.eql(&(try Name.fromText("a.b.example.net."))));
}
