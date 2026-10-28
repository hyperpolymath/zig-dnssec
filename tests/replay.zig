// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Offline validator tests over responses recorded from NSD + Unbound by
//! tests/crosscheck/run.sh (tests/testdata/crosscheck.traces), plus targeted
//! negative tests made by mutating those recorded responses: tampered data,
//! stripped signatures, a removed chain link, forged denial, time travel,
//! wrong trust anchor, and resource limits.

const std = @import("std");
const testing = std.testing;
const lib = @import("dnssec");
const Name = lib.wire.Name;
const Type = lib.wire.Type;
const Message = lib.wire.Message;
const transport = lib.stub.transport;
const validator = lib.sec.validator;

const traces_src = @embedFile("testdata/crosscheck.traces");
const anchor_src = @embedFile("testdata/crosscheck-root.anchor");

/// 2026-10-14T00:00:00Z: inside the fixtures' signing window.
const now: i64 = 1791936000;

const Scenario = struct {
    qname: Name,
    qtype: Type,
    unbound: validator.Security,
    records: []transport.Recorded,
};

const Corpus = struct {
    arena: std.heap.ArenaAllocator,
    scenarios: []Scenario,

    fn load() !Corpus {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        var list: std.ArrayList(Scenario) = .empty;
        var cur: ?Scenario = null;
        var recs: std.ArrayList(transport.Recorded) = .empty;
        var lines = std.mem.splitScalar(u8, traces_src, '\n');
        while (lines.next()) |line| {
            if (line.len == 0 or line[0] == ';') continue;
            if (std.mem.startsWith(u8, line, "@query ")) {
                if (cur) |*c| {
                    c.records = try recs.toOwnedSlice(a);
                    try list.append(a, c.*);
                }
                var it = std.mem.tokenizeScalar(u8, line[7..], ' ');
                const n = try Name.fromText(it.next().?);
                const t = Type.fromMnemonic(it.next().?).?;
                const u = std.meta.stringToEnum(validator.Security, it.next().?).?;
                cur = .{ .qname = n, .qtype = t, .unbound = u, .records = &.{} };
                continue;
            }
            var t = try transport.Trace.parse(a, line);
            try recs.appendSlice(a, t.records);
            // The trace arena is owned by `a`'s parent arena; nothing to free.
            _ = &t;
        }
        if (cur) |*c| {
            c.records = try recs.toOwnedSlice(a);
            try list.append(a, c.*);
        }
        return .{ .arena = arena, .scenarios = list.items };
    }

    fn deinit(c: *Corpus) void {
        c.arena.deinit();
    }

    fn find(c: *Corpus, qname: []const u8, qtype: Type) !*Scenario {
        const n = try Name.fromText(qname);
        for (c.scenarios) |*s| if (s.qtype == qtype and s.qname.eql(&n)) return s;
        return error.NoSuchScenario;
    }
};

fn resolveWith(records: []const transport.Recorded, anchors_text: []const u8, qname: Name, qtype: Type, policy: validator.Policy, t: i64) !validator.Result {
    var anchors = try validator.TrustAnchors.fromText(testing.allocator, anchors_text);
    defer anchors.deinit();
    var replay: transport.ReplayTransport = .{ .records = records };
    var stub: lib.stub.client.StubClient = .{ .transport = replay.transport(), .anchors = &anchors, .policy = policy };
    return stub.resolve(testing.allocator, qname, qtype, t);
}

fn endsWith(n: Name, suffix: []const u8) bool {
    const s = Name.fromText(suffix) catch return false;
    return n.isSubdomainOf(&s);
}

const permissive: validator.Policy = .{ .unsupported_algorithm = .insecure, .nsec3_iterations = .insecure };

test "every recorded cross-check scenario matches Unbound, except the documented policy cases" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    try testing.expect(corpus.scenarios.len >= 250);
    var checked: usize = 0;
    for (corpus.scenarios) |*s| {
        var r = try resolveWith(s.records, anchor_src, s.qname, s.qtype, .{}, now);
        defer r.deinit();
        var p = try resolveWith(s.records, anchor_src, s.qname, s.qtype, permissive, now);
        defer p.deinit();
        var expect_default = s.unbound;
        var expect_permissive = s.unbound;
        // Ed448 is not in Zig's std: default policy fails, permissive policy
        // reports insecure (RFC 4035 §5.2); Unbound validates it.
        const is_parent_side_ds = s.qtype == .ds and s.qname.eql(&(try Name.fromText("ed448.test.")));
        if (endsWith(s.qname, "ed448.test.") and s.unbound == .secure and !is_parent_side_ds) {
            expect_default = .bogus;
            expect_permissive = .insecure;
        }
        // NSEC3 iterations above 150: Unbound returns insecure; our default
        // policy fails instead (RFC 9276 §3.2 allows either).
        if (endsWith(s.qname, "highiter.test.") and s.unbound == .insecure) {
            expect_default = .bogus;
        }
        if (r.security() != expect_default or p.security() != expect_permissive) {
            var b: [300]u8 = undefined;
            std.debug.print("mismatch: {s} {t}: ours {t}/{t}, expected {t}/{t}\n", .{ s.qname.toText(&b), s.qtype, r.security(), p.security(), expect_default, expect_permissive });
            return error.TestUnexpectedResult;
        }
        checked += 1;
    }
    try testing.expectEqual(corpus.scenarios.len, checked);
}

test "specific failure reasons for the broken zones" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const cases = [_]struct { q: []const u8, t: Type, reason: validator.Reason }{
        .{ .q = "www.expired.test.", .t = .a, .reason = .signature_expired },
        .{ .q = "www.notyet.test.", .t = .a, .reason = .signature_not_yet_valid },
        .{ .q = "www.wrongkey.test.", .t = .a, .reason = .dnskey_not_authenticated },
        .{ .q = "www.nodnskey.test.", .t = .a, .reason = .dnskey_missing },
        .{ .q = "www.tampered.test.", .t = .a, .reason = .signature_invalid },
        .{ .q = "www.badsig.test.", .t = .aaaa, .reason = .signature_invalid },
        .{ .q = "nx.highiter.test.", .t = .a, .reason = .nsec3_iterations_exceeded },
        .{ .q = "www.ed448.test.", .t = .a, .reason = .unsupported_algorithm },
    };
    for (cases) |c| {
        const s = try corpus.find(c.q, c.t);
        var r = try resolveWith(s.records, anchor_src, s.qname, s.qtype, .{}, now);
        defer r.deinit();
        try testing.expect(r.verdict == .bogus);
        try testing.expectEqual(c.reason, r.verdict.bogus.reason);
    }
    // Insecure verdicts carry the proof's reason and location.
    const ins = [_]struct { q: []const u8, t: Type, reason: validator.Reason, zone: []const u8 }{
        .{ .q = "www.insecure.test.", .t = .a, .reason = .insecure_delegation, .zone = "insecure.test." },
        .{ .q = "www.island.test.", .t = .a, .reason = .insecure_delegation, .zone = "island.test." },
        // ldns-signzone -p still emits an NSEC3 for the unsigned delegation, so
        // this is proven by a matching NSEC3 (NS, no DS) inside the Opt-Out zone.
        .{ .q = "www.unsigned.ecdsa256.test.", .t = .a, .reason = .insecure_delegation, .zone = "unsigned.ecdsa256.test." },
    };
    for (ins) |c| {
        const s = try corpus.find(c.q, c.t);
        var r = try resolveWith(s.records, anchor_src, s.qname, s.qtype, .{}, now);
        defer r.deinit();
        try testing.expect(r.verdict == .insecure);
        try testing.expectEqual(c.reason, r.verdict.insecure.reason);
        try testing.expect(r.verdict.insecure.zone.eql(&(try Name.fromText(c.zone))));
    }
    // The tampered zone's other records are still secure.
    const ok = try corpus.find("www.tampered.test.", .aaaa);
    var r = try resolveWith(ok.records, anchor_src, ok.qname, ok.qtype, .{}, now);
    defer r.deinit();
    try testing.expect(r.verdict == .secure);
}

// ---------------------------------------------------------------------------
// Mutations of recorded responses.
// ---------------------------------------------------------------------------

const Mutation = union(enum) {
    /// Flip the last octet of the first A record in the answer.
    tamper_a,
    /// Remove every RRSIG from the given section.
    strip_rrsig: lib.wire.message.Section,
    /// Remove every record of a type from all sections.
    drop_type: Type,
    /// Set the RCODE.
    set_rcode: u4,
};

fn mutate(gpa: std.mem.Allocator, bytes: []const u8, m: Mutation) ![]u8 {
    var msg = try Message.parse(gpa, bytes);
    defer msg.deinit();
    const out = try gpa.alloc(u8, 65535);
    errdefer gpa.free(out);
    var h = msg.header;
    if (m == .set_rcode) h.flags.rcode = m.set_rcode;
    var b = try lib.wire.Builder.init(out, h);
    for (msg.questions) |q| try b.question(q.name, q.qtype, q.qclass);
    var tampered = false;
    const sections = [_]lib.wire.message.Section{ .answer, .authority, .additional };
    for (sections) |sec| {
        for (msg.section(sec)) |rr| {
            if (m == .strip_rrsig and m.strip_rrsig == sec and rr.type == .rrsig) continue;
            if (m == .drop_type and rr.type == m.drop_type) continue;
            if (m == .tamper_a and rr.type == .a and sec == .answer and !tampered) {
                var rd: [4]u8 = rr.rdata[0..4].*;
                rd[3] ^= 0x01;
                tampered = true;
                var copy = rr;
                copy.rdata = &rd;
                try b.record(sec, copy);
                continue;
            }
            try b.record(sec, rr);
        }
    }
    if (msg.edns) |e| try b.opt(e.udp_size, e.do_bit, e.options);
    const wire = b.finish();
    return gpa.realloc(out, wire.len);
}

/// Copies a scenario, applying `m` to the responses for (qname, qtype).
fn withMutation(a: std.mem.Allocator, s: *const Scenario, qname: []const u8, qtype: Type, m: Mutation) ![]transport.Recorded {
    const n = try Name.fromText(qname);
    const out = try a.dupe(transport.Recorded, s.records);
    var hit = false;
    for (out) |*r| {
        if (r.qtype == qtype and r.qname.eql(&n)) {
            r.response = try mutate(a, r.response, m);
            hit = true;
        }
    }
    if (!hit) return error.NothingToMutate;
    return out;
}

fn merged(a: std.mem.Allocator, x: []const transport.Recorded, y: []const transport.Recorded) ![]transport.Recorded {
    const out = try a.alloc(transport.Recorded, x.len + y.len);
    @memcpy(out[0..x.len], x);
    @memcpy(out[x.len..], y);
    return out;
}

fn expectBogus(records: []const transport.Recorded, q: []const u8, t: Type, reason: ?validator.Reason) !void {
    var r = try resolveWith(records, anchor_src, try Name.fromText(q), t, .{}, now);
    defer r.deinit();
    if (r.verdict != .bogus) {
        std.debug.print("expected bogus for {s}, got {t}\n", .{ q, r.security() });
        return error.TestUnexpectedResult;
    }
    if (reason) |want| {
        if (r.verdict.bogus.reason != want) {
            std.debug.print("{s}: reason {t}, expected {t}\n", .{ q, r.verdict.bogus.reason, want });
            return error.TestUnexpectedResult;
        }
    }
}

test "negative: tampered answer, stripped signatures, missing chain link, forged denial" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const www = try corpus.find("www.rsasha256.test.", .a);

    // Baseline is secure.
    {
        var r = try resolveWith(www.records, anchor_src, www.qname, .a, .{}, now);
        defer r.deinit();
        try testing.expect(r.verdict == .secure);
    }
    // 1. Tampered A record.
    try expectBogus(try withMutation(a, www, "www.rsasha256.test.", .a, .tamper_a), "www.rsasha256.test.", .a, .signature_invalid);
    // 2. Answer with its RRSIGs stripped (a downgrade attempt): the zone is
    //    provably signed (the DS query for www proves www is not a cut), so
    //    the unsigned answer is bogus, not insecure.
    const www_ds = try corpus.find("www.rsasha256.test.", .ds);
    const stripped = try withMutation(a, www, "www.rsasha256.test.", .a, .{ .strip_rrsig = .answer });
    try expectBogus(try merged(a, stripped, www_ds.records), "www.rsasha256.test.", .a, .missing_signature);
    //    Without that extra response the stub cannot finish the insecurity
    //    check and reports indeterminate: still not an answer.
    {
        var r = try resolveWith(stripped, anchor_src, www.qname, .a, .{}, now);
        defer r.deinit();
        try testing.expect(r.verdict == .indeterminate);
    }
    // 3. Missing chain link: the zone's DNSKEY RRset removed.
    try expectBogus(try withMutation(a, www, "rsasha256.test.", .dnskey, .{ .drop_type = .dnskey }), "www.rsasha256.test.", .a, .dnskey_missing);
    // 4. DS RRset removed from the parent's answer, with no denial proof:
    //    claiming "no DS" without proof must not make the zone insecure.
    try expectBogus(try withMutation(a, www, "rsasha256.test.", .ds, .{ .drop_type = .ds }), "www.rsasha256.test.", .a, null);
    // 5. DS RRSIG stripped.
    try expectBogus(try withMutation(a, www, "rsasha256.test.", .ds, .{ .strip_rrsig = .answer }), "www.rsasha256.test.", .a, null);
    // 6. Root DNSKEY signatures stripped.
    try expectBogus(try withMutation(a, www, ".", .dnskey, .{ .strip_rrsig = .answer }), "www.rsasha256.test.", .a, null);
    // 7. A positive answer relabelled NXDOMAIN.
    try expectBogus(try withMutation(a, www, "www.rsasha256.test.", .a, .{ .set_rcode = 3 }), "www.rsasha256.test.", .a, .malformed_response);

    // 8. NXDOMAIN with its NSEC proof removed.
    const nx = try corpus.find("nx.rsasha256.test.", .a);
    {
        var r = try resolveWith(nx.records, anchor_src, nx.qname, .a, .{}, now);
        defer r.deinit();
        try testing.expect(r.verdict == .secure);
        try testing.expectEqual(lib.wire.types.Rcode.nxdomain, r.verdict.secure.rcode);
    }
    try expectBogus(try withMutation(a, nx, "nx.rsasha256.test.", .a, .{ .drop_type = .nsec }), "nx.rsasha256.test.", .a, .denial_missing);
    // 9. ...or with the NSEC signatures removed.
    try expectBogus(try withMutation(a, nx, "nx.rsasha256.test.", .a, .{ .strip_rrsig = .authority }), "nx.rsasha256.test.", .a, null);
    // 10. NSEC3 NXDOMAIN with its proof removed.
    const nx3 = try corpus.find("nx.rsasha512.test.", .a);
    try expectBogus(try withMutation(a, nx3, "nx.rsasha512.test.", .a, .{ .drop_type = .nsec3 }), "nx.rsasha512.test.", .a, .denial_missing);
    // 11. An existing name's answer replaced by an empty NOERROR (NODATA
    //     claim with no proof).
    try expectBogus(try merged(a, try withMutation(a, www, "www.rsasha256.test.", .a, .{ .drop_type = .a }), www_ds.records), "www.rsasha256.test.", .a, .denial_missing);
    // 12. Wildcard answer without its NSEC proof of non-existence.
    const wild = try corpus.find("foo.wild.rsasha256.test.", .a);
    try expectBogus(try withMutation(a, wild, "foo.wild.rsasha256.test.", .a, .{ .drop_type = .nsec }), "foo.wild.rsasha256.test.", .a, null);
    // 13. Insecure delegation proof removed: the unsigned zone can no
    //     longer be shown to be unsigned.
    const ins = try corpus.find("www.insecure.test.", .a);
    try expectBogus(try withMutation(a, ins, "insecure.test.", .ds, .{ .drop_type = .nsec3 }), "www.insecure.test.", .a, null);
}

test "negative: time travel, wrong trust anchor, no trust anchor, budgets, fetch failure" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const www = try corpus.find("www.rsasha256.test.", .a);

    // After the signing window: 2027-11-01.
    {
        var r = try resolveWith(www.records, anchor_src, www.qname, .a, .{}, 1824940800);
        defer r.deinit();
        try testing.expect(r.verdict == .bogus);
        try testing.expectEqual(validator.Reason.signature_expired, r.verdict.bogus.reason);
    }
    // Before it: 2026-09-01.
    {
        var r = try resolveWith(www.records, anchor_src, www.qname, .a, .{}, 1788220800);
        defer r.deinit();
        try testing.expectEqual(validator.Reason.signature_not_yet_valid, r.verdict.bogus.reason);
    }
    // A different root anchor (the IANA root): nothing verifies.
    {
        var r = try resolveWith(www.records, lib.sec.anchors.iana_root_ds, www.qname, .a, .{}, now);
        defer r.deinit();
        try testing.expect(r.verdict == .bogus);
        try testing.expectEqual(validator.Reason.dnskey_not_authenticated, r.verdict.bogus.reason);
    }
    // An anchor that covers nothing on the path: indeterminate, not insecure.
    {
        var r = try resolveWith(www.records, "example. DS 1 13 2 0000000000000000000000000000000000000000000000000000000000000000", www.qname, .a, .{}, now);
        defer r.deinit();
        try testing.expect(r.verdict == .indeterminate);
        try testing.expectEqual(validator.Reason.no_trust_anchor, r.verdict.indeterminate.reason);
    }
    // Signature-verification budget (KeyTrap-class defence).
    {
        var r = try resolveWith(www.records, anchor_src, www.qname, .a, .{ .max_verifications = 1 }, now);
        defer r.deinit();
        try testing.expect(r.verdict == .bogus);
        try testing.expectEqual(validator.Reason.resource_limit, r.verdict.bogus.reason);
    }
    // Fetch budget.
    {
        var r = try resolveWith(www.records, anchor_src, www.qname, .a, .{ .max_fetches = 1 }, now);
        defer r.deinit();
        try testing.expect(r.verdict == .bogus);
        try testing.expectEqual(validator.Reason.resource_limit, r.verdict.bogus.reason);
    }
    // A chain fetch that fails (record missing from the replay): indeterminate.
    {
        var partial: std.ArrayList(transport.Recorded) = .empty;
        defer partial.deinit(testing.allocator);
        for (www.records) |rec| if (rec.qtype != .ds) try partial.append(testing.allocator, rec);
        var r = try resolveWith(partial.items, anchor_src, www.qname, .a, .{}, now);
        defer r.deinit();
        try testing.expect(r.verdict == .indeterminate);
        try testing.expectEqual(validator.Reason.fetch_failed, r.verdict.indeterminate.reason);
    }
    // SHA-1 disabled by policy: the SHA-1-only DS zone and the RSASHA1 zone
    // become failures (never silently insecure under the default policy).
    {
        const s = try corpus.find("www.dssha1.test.", .a);
        var r = try resolveWith(s.records, anchor_src, s.qname, .a, .{ .allow_sha1 = false }, now);
        defer r.deinit();
        try testing.expect(r.verdict == .bogus);
        try testing.expectEqual(validator.Reason.unsupported_algorithm, r.verdict.bogus.reason);
        const s2 = try corpus.find("www.rsasha1.test.", .a);
        var r2 = try resolveWith(s2.records, anchor_src, s2.qname, .a, .{ .allow_sha1 = false }, now);
        defer r2.deinit();
        try testing.expect(r2.verdict == .bogus);
    }
}

test "resolveSecure refuses every non-secure verdict" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    var anchors = try validator.TrustAnchors.fromText(testing.allocator, anchor_src);
    defer anchors.deinit();
    const cases = [_]struct { q: []const u8, err: anyerror }{
        .{ .q = "www.insecure.test.", .err = error.Insecure },
        .{ .q = "www.expired.test.", .err = error.Bogus },
    };
    for (cases) |c| {
        const s = try corpus.find(c.q, .a);
        var replay: transport.ReplayTransport = .{ .records = s.records };
        var stub: lib.stub.client.StubClient = .{ .transport = replay.transport(), .anchors = &anchors };
        try testing.expectError(c.err, stub.resolveSecure(testing.allocator, s.qname, .a, now));
    }
    const ok = try corpus.find("www.ed25519.test.", .a);
    var replay: transport.ReplayTransport = .{ .records = ok.records };
    var stub: lib.stub.client.StubClient = .{ .transport = replay.transport(), .anchors = &anchors };
    var r = try stub.resolveSecure(testing.allocator, ok.qname, .a, now);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.verdict.secure.rrsets.len);
}

// ---------------------------------------------------------------------------
// Insecurity claimed through an unverified RRSIG signer name.
// ---------------------------------------------------------------------------

/// The recorded response for (qname, qtype) in `records`.
fn recorded(records: []const transport.Recorded, qname: []const u8, qtype: Type) ![]const u8 {
    const n = try Name.fromText(qname);
    for (records) |r| if (r.qtype == qtype and r.qname.eql(&n)) return r.response;
    return error.NothingRecorded;
}

/// An attacker's negative answer for (qname, qtype): the SOA of `template`'s
/// authority section with its RRSIG, every NSEC/NSEC3 removed, and the
/// RRSIG(SOA) Signer's Name rewritten to `signer`. The signature no longer
/// verifies; only the unauthenticated signer *name* points at a zone that
/// is provably insecure.
fn forgedDenial(gpa: std.mem.Allocator, template: []const u8, qname: []const u8, qtype: Type, rcode: u4, signer: []const u8) ![]u8 {
    var msg = try Message.parse(gpa, template);
    defer msg.deinit();
    const out = try gpa.alloc(u8, 65535);
    errdefer gpa.free(out);
    var h = msg.header;
    h.flags.rcode = rcode;
    var b = try lib.wire.Builder.init(out, h);
    try b.question(try Name.fromText(qname), qtype, .in);
    const signer_name = try Name.fromText(signer);
    var sig_rd: [2048]u8 = undefined;
    var soa_seen = false;
    for (msg.authority) |rr| {
        switch (rr.type) {
            .soa => {
                try b.record(.authority, rr);
                soa_seen = true;
            },
            .rrsig => {
                const sig = try lib.wire.rdata.Rrsig.parse(rr.rdata);
                if (sig.type_covered != .soa) continue;
                var n: usize = 18;
                @memcpy(sig_rd[0..18], rr.rdata[0..18]);
                @memcpy(sig_rd[n..][0..signer_name.len], signer_name.bytes());
                n += signer_name.len;
                @memcpy(sig_rd[n..][0..sig.signature.len], sig.signature);
                n += sig.signature.len;
                var copy = rr;
                copy.rdata = sig_rd[0..n];
                try b.record(.authority, copy);
            },
            else => {},
        }
    }
    if (!soa_seen) return error.TemplateHasNoSoa;
    if (msg.edns) |e| try b.opt(e.udp_size, e.do_bit, e.options);
    const wire = b.finish();
    return gpa.realloc(out, wire.len);
}

test "negative: an RRSIG naming an insecure zone as signer proves nothing" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const www = try corpus.find("www.rsasha256.test.", .a);
    const ins = try corpus.find("www.insecure.test.", .a);
    // A NODATA from test. (SOA test. + NSEC3 proof) for the insecure
    // delegation insecure.test.: the attacker's raw material.
    const template = try recorded(ins.records, "insecure.test.", .ds);
    const evil = "insecure.test."; // provably insecure, so its keys are never checked

    // 1. A forged NXDOMAIN for a name in a signed zone, whose only "proof"
    //    is an SOA whose RRSIG claims to be signed by the insecure zone.
    {
        const nx = try forgedDenial(a, template, "www.rsasha256.test.", .a, 3, evil);
        const first = [_]transport.Recorded{.{ .qname = www.qname, .qtype = .a, .response = nx }};
        const records = try merged(a, &first, try merged(a, www.records, ins.records));
        try expectBogus(records, "www.rsasha256.test.", .a, null);
    }
    // 2. A tampered answer, plus a forged "no DS" for its zone in the same
    //    style: the signed zone must not become insecure, so the tampered
    //    data must not come back as an (insecure) answer.
    {
        const tampered = try mutate(a, try recorded(www.records, "www.rsasha256.test.", .a), .tamper_a);
        const no_ds = try forgedDenial(a, template, "rsasha256.test.", .ds, 0, evil);
        const first = [_]transport.Recorded{
            .{ .qname = www.qname, .qtype = .a, .response = tampered },
            .{ .qname = try Name.fromText("rsasha256.test."), .qtype = .ds, .response = no_ds },
        };
        const records = try merged(a, &first, try merged(a, www.records, ins.records));
        try expectBogus(records, "www.rsasha256.test.", .a, null);
    }
    // 3. The same forged "no DS", for the NSEC3-signed zone of the opt-out
    //    test zone's sibling, with the answer's RRSIGs stripped instead.
    {
        const s = try corpus.find("www.ecdsa256.test.", .a);
        const stripped = try mutate(a, try recorded(s.records, "www.ecdsa256.test.", .a), .{ .strip_rrsig = .answer });
        const no_ds = try forgedDenial(a, template, "ecdsa256.test.", .ds, 0, evil);
        const first = [_]transport.Recorded{
            .{ .qname = s.qname, .qtype = .a, .response = stripped },
            .{ .qname = try Name.fromText("ecdsa256.test."), .qtype = .ds, .response = no_ds },
            .{ .qname = try Name.fromText("www.ecdsa256.test."), .qtype = .ds, .response = try forgedDenial(a, template, "www.ecdsa256.test.", .ds, 0, evil) },
        };
        const records = try merged(a, &first, try merged(a, s.records, ins.records));
        try expectBogus(records, "www.ecdsa256.test.", .a, null);
    }
}

// ---------------------------------------------------------------------------
// Review findings: attacker-controlled RRSIG ordering, signer names, Labels
// and TTLs, and the closest-trust-anchor rule (RFC 4035 §5.2).
// ---------------------------------------------------------------------------

const Section = lib.wire.message.Section;
const Rr = lib.wire.message.Rr;

/// A rebuilt response: the question replaced, one extra record inserted before
/// or after the records of a section, and/or every received TTL in a section
/// overwritten. None of these touch a signature — that is the point. The
/// question, the TTL field and the order and number of RRSIGs are all under the
/// responder's control and none of them is covered by an RRSIG.
const Rewrite = struct {
    question: ?struct { name: []const u8, qtype: Type } = null,
    prepend: ?struct { sec: Section, rr: Rr } = null,
    append: ?struct { sec: Section, rr: Rr } = null,
    ttl: ?struct { sec: Section, value: u32 } = null,
    /// Record types to omit from every section. Dropping the signatures is how
    /// a signed response is turned into the unsigned one an insecure zone would
    /// have sent; the received bytes stay byte-identical otherwise.
    drop: []const Type = &.{},
};

fn dropped(list: []const Type, t: Type) bool {
    for (list) |d| if (d == t) return true;
    return false;
}

fn rewrite(gpa: std.mem.Allocator, bytes: []const u8, rw: Rewrite) ![]u8 {
    var msg = try Message.parse(gpa, bytes);
    defer msg.deinit();
    const out = try gpa.alloc(u8, 65535);
    errdefer gpa.free(out);
    var b = try lib.wire.Builder.init(out, msg.header);
    if (rw.question) |q| {
        try b.question(try Name.fromText(q.name), q.qtype, .in);
    } else {
        for (msg.questions) |qq| try b.question(qq.name, qq.qtype, qq.qclass);
    }
    const sections = [_]Section{ .answer, .authority, .additional };
    for (sections) |sec| {
        if (rw.prepend) |p| if (p.sec == sec) try b.record(sec, p.rr);
        for (msg.section(sec)) |rr| {
            if (dropped(rw.drop, rr.type)) continue;
            if (rw.ttl) |t| if (t.sec == sec and rr.type != .opt) {
                var copy = rr;
                copy.ttl = t.value;
                try b.record(sec, copy);
                continue;
            };
            try b.record(sec, rr);
        }
        if (rw.append) |ap| if (ap.sec == sec) try b.record(sec, ap.rr);
    }
    if (msg.edns) |e| try b.opt(e.udp_size, e.do_bit, e.options);
    const wire = b.finish();
    return gpa.realloc(out, wire.len);
}

/// Finds the (only) record of `t` in `sec` of a recorded response.
fn findRr(gpa: std.mem.Allocator, bytes: []const u8, sec: Section, t: Type) !Rr {
    var msg = try Message.parse(gpa, bytes);
    defer msg.deinit();
    for (msg.section(sec)) |rr| if (rr.type == t) {
        return .{
            .name = rr.name,
            .type = rr.type,
            .class = rr.class,
            .ttl = rr.ttl,
            .rdata = try gpa.dupe(u8, rr.rdata),
        };
    };
    return error.NoSuchRecord;
}

/// A forged RRSIG derived from `sig` by rewriting fields the signature covers.
/// It never verifies; it only has to *name* what the attacker wants named.
fn forgedSig(gpa: std.mem.Allocator, sig: Rr, labels: ?u8, signer: ?[]const u8) !Rr {
    const parsed = try lib.wire.rdata.Rrsig.parse(sig.rdata);
    var rd = try gpa.dupe(u8, sig.rdata);
    if (labels) |l| rd[3] = l;
    if (signer) |s| {
        const n = try Name.fromText(s);
        const out = try gpa.alloc(u8, 18 + n.len + parsed.signature.len);
        @memcpy(out[0..18], sig.rdata[0..18]);
        @memcpy(out[18..][0..n.len], n.bytes());
        @memcpy(out[18 + n.len ..], parsed.signature);
        rd = out;
    }
    return .{ .name = sig.name, .type = .rrsig, .class = sig.class, .ttl = sig.ttl, .rdata = rd };
}

/// island.test. is signed but has no DS in test.: from the root anchor alone it
/// is a proven insecure delegation. Anchoring it turns it into a secure island
/// (RFC 4035 §5.2), which is the configuration these tests exercise.
const island_dnskey = "island.test. 3600 IN DNSKEY 257 3 13 O2BGSZFEbAKy5NdvF4kdLuY+duAOTQMj5FMG31B4EVfyiOpVarKoj3KRpabXfTAq4gc4mbJlxf/dvg1VzMOmfg==\n";

fn anchoredAt(gpa: std.mem.Allocator, owner: []const u8) ![]const u8 {
    // The same key material, asserted at a different owner: an island anchor
    // below the insecure delegation.
    const rest = std.mem.indexOfScalar(u8, island_dnskey, ' ').?;
    return std.fmt.allocPrint(gpa, "{s}{s} {s}", .{ anchor_src, owner, island_dnskey[rest + 1 ..] });
}

test "positive: an anchored island below an insecure delegation validates as secure" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const island = try corpus.find("island.test.", .dnskey);
    const www = try corpus.find("www.island.test.", .a);
    const records = try merged(a, www.records, island.records);
    const anchors = try std.fmt.allocPrint(a, "{s}{s}", .{ anchor_src, island_dnskey });

    // Without the island anchor this is a proven insecure delegation.
    {
        var r = try resolveWith(records, anchor_src, www.qname, .a, .{}, now);
        defer r.deinit();
        try testing.expectEqual(validator.Security.insecure, r.security());
        try testing.expectEqual(validator.Reason.insecure_delegation, r.verdict.insecure.reason);
    }
    // With it, the island's own key authenticates the answer: secure, and the
    // closest-anchor rule below must not cost us that.
    {
        var r = try resolveWith(records, anchors, www.qname, .a, .{}, now);
        defer r.deinit();
        if (r.security() != .secure) {
            std.debug.print("anchored island: expected secure, got {t}\n", .{r.security()});
            return error.TestUnexpectedResult;
        }
    }
}

test "negative: an RRSIG naming an insecure ancestor cannot bypass a closer island anchor" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const www = try corpus.find("www.island.test.", .a);
    // An island anchor strictly below the insecure delegation at island.test.
    const anchors = try anchoredAt(a, "www.island.test.");

    // The responder tampers with the address and leaves the real RRSIG, which
    // names island.test. - a zone that is provably insecure from the root
    // anchor. zoneStatus(island.test.) says "insecure", and that used to be
    // enough to hand the unverified answer back as `.insecure`, i.e. usable,
    // without honouring the closer anchor for the owner.
    const tampered = try mutate(a, try recorded(www.records, "www.island.test.", .a), .tamper_a);
    const first = [_]transport.Recorded{.{ .qname = www.qname, .qtype = .a, .response = tampered }};
    const records = try merged(a, &first, www.records);

    var r = try resolveWith(records, anchors, try Name.fromText("www.island.test."), .a, .{}, now);
    defer r.deinit();
    if (r.security() == .insecure) {
        std.debug.print("tampered answer accepted as insecure (zone {}); expected refusal\n", .{r.verdict.insecure.zone});
        return error.TestUnexpectedResult;
    }
    try testing.expectEqual(validator.Security.bogus, r.security());
    try testing.expectEqual(validator.Reason.bad_signer, r.verdict.bogus.reason);
}

test "negative: a forged denial signer cannot bypass a closer island anchor" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const nx = try corpus.find("nx.island.test.", .a);
    const anchors = try anchoredAt(a, "www.island.test.");

    // island.test.'s own NXDOMAIN proof, re-questioned as a NODATA for a name
    // inside the configured island. The NSEC RRSIGs name island.test., which is
    // insecure from the root anchor; the signer used to be read from that
    // unauthenticated name and the denial accepted as proof of insecurity
    // *before any signature over the denial records was checked*.
    const forged = try rewrite(a, try recorded(nx.records, "nx.island.test.", .a), .{
        .question = .{ .name = "www.island.test.", .qtype = .mx },
    });
    const first = [_]transport.Recorded{.{ .qname = try Name.fromText("www.island.test."), .qtype = .mx, .response = forged }};
    const records = try merged(a, &first, nx.records);

    var r = try resolveWith(records, anchors, try Name.fromText("www.island.test."), .mx, .{}, now);
    defer r.deinit();
    if (r.security() == .insecure) {
        std.debug.print("forged NXDOMAIN accepted as insecure (reason {t}); expected refusal\n", .{r.verdict.insecure.reason});
        return error.TestUnexpectedResult;
    }
}

test "negative: an extra DS RRSIG naming another ancestor cannot break a valid chain" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const s = try corpus.find("www.rsasha256.test.", .a);

    // The DS RRset for rsasha256.test. is validly signed by test. Prepending
    // one extraneous RRSIG over the same DS that names the root made the old
    // code pick `sigs[0]` and only that signer: it loaded the root's keys, the
    // real signature from test. was never tried, and an otherwise valid chain
    // came back bogus. An untrusted upstream could do that at will.
    const ds_resp = try recorded(s.records, "rsasha256.test.", .ds);
    const real = try findRr(a, ds_resp, .answer, .rrsig);
    const forged = try forgedSig(a, real, null, ".");
    const evil_ds = try rewrite(a, ds_resp, .{ .prepend = .{ .sec = .answer, .rr = forged } });

    // Sanity: the forged RRSIG is really first, and really names the root.
    {
        const first_sig = try findRr(a, evil_ds, .answer, .rrsig);
        const parsed = try lib.wire.rdata.Rrsig.parse(first_sig.rdata);
        try testing.expect(parsed.signer.isRoot());
    }

    const records = try withResponse(a, s.records, "rsasha256.test.", .ds, evil_ds);
    var r = try resolveWith(records, anchor_src, s.qname, .a, .{}, now);
    defer r.deinit();
    if (r.security() != .secure) {
        std.debug.print("valid chain broken by an extraneous DS RRSIG: got {t}\n", .{r.security()});
        return error.TestUnexpectedResult;
    }
}

/// Replaces the recorded response for (qname, qtype).
fn withResponse(a: std.mem.Allocator, records: []const transport.Recorded, qname: []const u8, qtype: Type, response: []const u8) ![]transport.Recorded {
    const n = try Name.fromText(qname);
    const out = try a.dupe(transport.Recorded, records);
    var hit = false;
    for (out) |*r| {
        if (r.qtype == qtype and r.qname.eql(&n)) {
            r.response = response;
            hit = true;
        }
    }
    if (!hit) return error.NothingToReplace;
    return out;
}

test "negative: a forged same-signer RRSIG cannot change the wildcard Labels" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const s = try corpus.find("foo.wild.rsasha256.test.", .a);
    const resp = try recorded(s.records, "foo.wild.rsasha256.test.", .a);

    // The answer is a wildcard expansion of *.wild.rsasha256.test.: the real
    // RRSIG carries Labels=3 for a 4-label owner, and the response brings the
    // NSEC that proves the expansion. Appending a second RRSIG by the *same*
    // signer with Labels=2 used to make the validator take the smaller of the
    // two, so a valid answer was judged a wildcard expansion at the wrong depth
    // and rejected for want of a proof nobody was obliged to send.
    const real = try findRr(a, resp, .answer, .rrsig);
    try testing.expectEqual(@as(u8, 3), (try lib.wire.rdata.Rrsig.parse(real.rdata)).labels);
    const forged = try forgedSig(a, real, 2, null);
    const evil = try rewrite(a, resp, .{ .append = .{ .sec = .answer, .rr = forged } });

    const records = try withResponse(a, s.records, "foo.wild.rsasha256.test.", .a, evil);
    var r = try resolveWith(records, anchor_src, s.qname, .a, .{}, now);
    defer r.deinit();
    if (r.security() != .secure) {
        std.debug.print("wildcard answer rejected because of a forged Labels field: got {t}\n", .{r.security()});
        return error.TestUnexpectedResult;
    }
}

test "negative: an insecure answer cannot outlive the proof that allowed it" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const www = try corpus.find("www.island.test.", .a);
    const resp = try recorded(www.records, "www.island.test.", .a);

    // The received TTL is not signed; the RRSIG's Original TTL is. An on-path
    // responder can therefore raise the TTL of unsigned data it is serving as
    // `insecure`, and the C ABI hands that number to the caller as the answer's
    // cache duration. The proof that made the data acceptable - test.'s NSEC3
    // showing no DS for island.test. - has its own, much shorter lifetime, and
    // the answer must not outlive it.
    const evil = try rewrite(a, resp, .{ .ttl = .{ .sec = .answer, .value = 86400 } });
    const records = try withResponse(a, www.records, "www.island.test.", .a, evil);

    var r = try resolveWith(records, anchor_src, www.qname, .a, .{}, now);
    defer r.deinit();
    try testing.expectEqual(validator.Security.insecure, r.security());
    try testing.expectEqual(validator.Reason.insecure_delegation, r.verdict.insecure.reason);
    const ttl = r.verdict.insecure.answer.ttl;
    // The proof's own TTL in these fixtures is 1s (Unbound ran with
    // cache-max-ttl=1); the forged data TTL is 86400s.
    if (ttl >= 86400) {
        std.debug.print("insecure answer cached for {d}s, the attacker-chosen TTL\n", .{ttl});
        return error.TestUnexpectedResult;
    }
    try testing.expect(ttl <= 300);
}

test "negative: for QTYPE=CNAME a synthesised CNAME below a DNAME is the answer" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const s = try corpus.find("www.redir.dname.test.", .a);
    const resp = try recorded(s.records, "www.redir.dname.test.", .a);

    // RFC 6672 §5.3.1: redir.dname.test. DNAME rsasha256.test. makes the
    // server synthesise www.redir.dname.test. CNAME www.rsasha256.test. For
    // QTYPE=CNAME that synthesised record *is* the answer. The validator used
    // to redirect past it and look for a CNAME at the target, which a correct
    // response does not carry, so a valid answer came back bogus for want of a
    // NODATA proof nobody was obliged to send.
    const cname_resp = try rewrite(a, resp, .{ .question = .{ .name = "www.redir.dname.test.", .qtype = .cname } });
    const first = [_]transport.Recorded{.{ .qname = try Name.fromText("www.redir.dname.test."), .qtype = .cname, .response = cname_resp }};
    const records = try merged(a, &first, s.records);

    var r = try resolveWith(records, anchor_src, try Name.fromText("www.redir.dname.test."), .cname, .{}, now);
    defer r.deinit();
    if (r.security() != .secure) {
        std.debug.print("QTYPE=CNAME below a DNAME: expected secure, got {t}\n", .{r.security()});
        return error.TestUnexpectedResult;
    }
    // The chain is the authenticated DNAME plus the synthesised CNAME, and it
    // stops at the original name: the target is not chased for this qtype.
    const ans = r.verdict.secure;
    try testing.expectEqual(@as(usize, 2), ans.rrsets.len);
    try testing.expectEqual(Type.dname, ans.rrsets[0].type);
    try testing.expectEqual(Type.cname, ans.rrsets[1].type);
    try testing.expect(ans.final_name.eql(&(try Name.fromText("www.redir.dname.test."))));
}

test "negative: QTYPE=RRSIG is refused rather than misreported" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const s = try corpus.find("www.rsasha256.test.", .a);
    // `group` reads every RRSIG as a signature and never as data, so an RRSIG
    // answer groups into no RRset at all and would be judged as NODATA. Nothing
    // signs an RRSIG RRset, so there is no verdict to give: refuse the query
    // type instead of reporting a correctly signed response as bogus.
    const resp = try rewrite(a, try recorded(s.records, "www.rsasha256.test.", .a), .{
        .question = .{ .name = "www.rsasha256.test.", .qtype = .rrsig },
    });
    const first = [_]transport.Recorded{.{ .qname = s.qname, .qtype = .rrsig, .response = resp }};
    const records = try merged(a, &first, s.records);
    try expectBogus(records, "www.rsasha256.test.", .rrsig, .malformed_response);
}

test "negative: a forged SOA owner cannot reach over a closer island anchor" {
    var corpus = try Corpus.load();
    defer corpus.deinit();
    const a = corpus.arena.allocator();
    const nx = try corpus.find("nx.island.test.", .a);
    const anchors = try anchoredAt(a, "www.island.test.");

    // An unsigned NXDOMAIN for a name inside the configured island, whose SOA
    // names island.test. - provably insecure from the root anchor, but an
    // ANCESTOR of the anchor at www.island.test. The SOA owner is
    // unauthenticated data, and ancestry alone is not a sufficient test of it:
    // the insecurity of island.test. says nothing about the anchored subtree
    // below it. Accepting the hint let a responder dispose of a negative answer
    // inside a secure island with no proof at all.
    const forged = try rewrite(a, try recorded(nx.records, "nx.island.test.", .a), .{
        .question = .{ .name = "x.www.island.test.", .qtype = .a },
        .drop = &.{ .rrsig, .nsec, .nsec3 },
    });
    // Sanity: the authority section still carries the SOA and nothing signed.
    {
        var msg = try Message.parse(a, forged);
        defer msg.deinit();
        var soa = false;
        var signed = false;
        for (msg.authority) |rr| {
            if (rr.type == .soa) soa = true;
            if (rr.type == .rrsig or rr.type == .nsec or rr.type == .nsec3) signed = true;
        }
        try testing.expect(soa);
        try testing.expect(!signed);
    }

    const first = [_]transport.Recorded{.{ .qname = try Name.fromText("x.www.island.test."), .qtype = .a, .response = forged }};
    const records = try merged(a, &first, nx.records);

    var r = try resolveWith(records, anchors, try Name.fromText("x.www.island.test."), .a, .{}, now);
    defer r.deinit();
    if (r.security() == .insecure) {
        std.debug.print("unsigned NXDOMAIN accepted as insecure ({} {}); expected refusal\n", .{ r.verdict.insecure.reason, r.verdict.insecure.zone });
        return error.TestUnexpectedResult;
    }
}
