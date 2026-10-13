// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Offline validator tests over responses recorded from NSD + Unbound by
//! crosscheck/run.sh (tests/testdata/crosscheck.traces), plus targeted
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
        try testing.expect(r.verdict == .bogus or r.verdict == .indeterminate);
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
