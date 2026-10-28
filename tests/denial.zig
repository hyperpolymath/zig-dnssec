// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Denial-of-existence tests built from the RFC 4035 and RFC 5155 example
//! zones: each NSEC/NSEC3 record used is first authenticated (its RRSIG is
//! verified with the zone key), then fed to the proof logic with exactly
//! the set of records the corresponding Appendix B example response holds.

const std = @import("std");
const testing = std.testing;
const lib = @import("dnssec");
const text = lib.wire.text;
const Name = lib.wire.Name;
const Type = lib.wire.Type;
const rdata = lib.wire.rdata;
const rrset = lib.sec.rrset;
const keys = lib.sec.keys;
const nsec = lib.sec.nsec;
const nsec3 = lib.sec.nsec3;

const Zone = struct {
    z: text.Zone,
    arena: std.heap.ArenaAllocator,
    g: rrset.Grouped,
    now: u32,

    fn init(src: []const u8, now: u32) !Zone {
        var z = try text.parseZone(testing.allocator, src, .{}, null);
        errdefer z.deinit();
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        errdefer arena.deinit();
        const g = try rrset.group(arena.allocator(), z.records);
        return .{ .z = z, .arena = arena, .g = g, .now = now };
    }

    fn deinit(self: *Zone) void {
        self.arena.deinit();
        self.z.deinit();
    }

    fn find(self: *Zone, owner: []const u8, t: Type) !*const rrset.RrSet {
        const n = try Name.fromText(owner);
        for (self.g.sets) |*s| if (s.type == t and s.name.eql(&n)) return s;
        return error.MissingRrset;
    }

    /// Verifies the RRset's signature with the apex keys and returns it.
    fn authenticated(self: *Zone, owner: []const u8, t: Type) !*const rrset.RrSet {
        const s = try self.find(owner, t);
        const ks = try self.find("example.", .dnskey);
        const sig = &s.sigs[0];
        const key = for (ks.rdatas) |kr| {
            if (keys.keyTag(kr) == sig.rrsig.key_tag) break kr;
        } else return error.NoKey;
        try rrset.verify(testing.allocator, s, sig, &ks.name, key, self.now, 0);
        return s;
    }

    fn nsecRecord(self: *Zone, owner: []const u8) !nsec.Record {
        const s = try self.authenticated(owner, .nsec);
        return .{ .owner = s.name, .nsec = try rdata.Nsec.parse(s.rdatas[0]), .zone = s.sigs[0].rrsig.signer };
    }

    fn nsec3Record(self: *Zone, owner: []const u8) !nsec3.Record {
        const s = try self.authenticated(owner, .nsec3);
        return nsec3.Record.fromRr(s.name, s.rdatas[0], &s.sigs[0].rrsig.signer);
    }
};

fn nm(t: []const u8) Name {
    return Name.fromText(t) catch unreachable;
}

// ---------------------------------------------------------------------------
// NSEC: RFC 4035 Appendix A zone, Appendix B responses.
// ---------------------------------------------------------------------------

const rfc4035_zone = @embedFile("testdata/rfc/rfc4035-appendix-a.zone");
const t2004: u32 = 1082419200;

test "RFC 4035 B.2 Name Error: ml.example." {
    var z = try Zone.init(rfc4035_zone, t2004);
    defer z.deinit();
    const recs = [_]nsec.Record{ try z.nsecRecord("b.example."), try z.nsecRecord("example.") };
    try testing.expectEqual(nsec.Result.proven, nsec.provesNxDomain(&recs, &nm("ml.example.")));
    // Without the wildcard-denying NSEC the proof is incomplete.
    try testing.expectEqual(nsec.Result{ .failed = .no_proof }, nsec.provesNxDomain(recs[0..1], &nm("ml.example.")));
    // An existing name cannot be denied with the same records.
    try testing.expect(nsec.provesNxDomain(&recs, &nm("b.example.")) != .proven);
}

test "RFC 4035 B.3 No Data: ns1.example. MX" {
    var z = try Zone.init(rfc4035_zone, t2004);
    defer z.deinit();
    const recs = [_]nsec.Record{try z.nsecRecord("ns1.example.")};
    try testing.expectEqual(nsec.Result.proven, nsec.provesNoData(&recs, &nm("ns1.example."), .mx));
    try testing.expectEqual(nsec.Result{ .failed = .type_present }, nsec.provesNoData(&recs, &nm("ns1.example."), .a));
}

test "RFC 4035 B.5 Referral to unsigned zone: b.example. is an insecure delegation" {
    var z = try Zone.init(rfc4035_zone, t2004);
    defer z.deinit();
    const recs = [_]nsec.Record{try z.nsecRecord("b.example.")};
    try testing.expectEqual(nsec.Result.proven, nsec.provesInsecureDelegation(&recs, &nm("b.example.")));
    // The parent-side NSEC cannot deny anything below the cut.
    try testing.expect(nsec.provesNxDomain(&recs, &nm("x.b.example.")) != .proven);
    try testing.expectEqual(nsec.Result{ .failed = .ancestor_delegation }, nsec.provesNoData(&recs, &nm("b.example."), .a));
    // a.example. has a DS: not insecure.
    const a = [_]nsec.Record{try z.nsecRecord("a.example.")};
    try testing.expectEqual(nsec.Result{ .failed = .not_insecure_delegation }, nsec.provesInsecureDelegation(&a, &nm("a.example.")));
}

test "RFC 4035 B.6 Wildcard Expansion: a.z.w.example. MX from *.w.example." {
    var z = try Zone.init(rfc4035_zone, t2004);
    defer z.deinit();
    // The wildcard MX RRSIG verifies over the expanded owner (Labels = 2).
    const mx = try z.find("*.w.example.", .mx);
    try testing.expectEqual(@as(u8, 2), mx.sigs[0].rrsig.labels);
    const recs = [_]nsec.Record{try z.nsecRecord("x.y.w.example.")};
    try testing.expectEqual(nsec.Result.proven, nsec.provesWildcardAnswer(&recs, &nm("a.z.w.example."), 2));
    // A wildcard claimed at the wrong level is rejected.
    try testing.expectEqual(nsec.Result{ .failed = .wrong_closest_encloser }, nsec.provesWildcardAnswer(&recs, &nm("a.z.w.example."), 1));
}

test "RFC 4035 B.7 Wildcard No Data: a.z.w.example. AAAA" {
    var z = try Zone.init(rfc4035_zone, t2004);
    defer z.deinit();
    const recs = [_]nsec.Record{ try z.nsecRecord("x.y.w.example."), try z.nsecRecord("*.w.example.") };
    try testing.expectEqual(nsec.Result.proven, nsec.provesNoData(&recs, &nm("a.z.w.example."), .aaaa));
    try testing.expectEqual(nsec.Result{ .failed = .type_present }, nsec.provesNoData(&recs, &nm("a.z.w.example."), .mx));
}

test "RFC 4035 B.8 DS Child Zone No Data: apex NSEC cannot deny the parent-side DS" {
    var z = try Zone.init(rfc4035_zone, t2004);
    defer z.deinit();
    const recs = [_]nsec.Record{try z.nsecRecord("example.")};
    // The RFC shows this as the child's answer; a validator must obtain the
    // DS denial from the parent, so the child-side NSEC is not accepted.
    try testing.expectEqual(nsec.Result{ .failed = .child_side_for_ds }, nsec.provesNoData(&recs, &nm("example."), .ds));
}

// ---------------------------------------------------------------------------
// NSEC3: RFC 5155 Appendix A zone, Appendix B responses. Every NSEC3 in
// that zone has the Opt-Out flag set, so proofs whose next closer name is
// covered must come out as `opt_out` (RFC 5155 §9.2: no AD bit).
// ---------------------------------------------------------------------------

const rfc5155_zone = @embedFile("testdata/rfc/rfc5155-appendix-a.zone");
const t2010: u32 = 1262304000;

fn proof(recs: []const nsec3.Record, scratch: []nsec3.Record) !nsec3.Proof {
    return switch (nsec3.Proof.init(recs, nm("example."), .{}, scratch)) {
        .ok => |p| p,
        .err => error.ProofInit,
    };
}

test "RFC 5155 B.1 Name Error: a.c.x.w.example." {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const recs = [_]nsec3.Record{
        try z.nsec3Record("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example."),
        try z.nsec3Record("b4um86eghhds6nea196smvmlo4ors995.example."),
        try z.nsec3Record("35mthgpgcu1qg68fab165klnsnk3dpvl.example."),
    };
    var scratch: [8]nsec3.Record = undefined;
    var p = try proof(&recs, &scratch);
    const ce = p.closestEncloser(&nm("a.c.x.w.example."));
    try testing.expect(ce == .ok);
    try testing.expect(ce.ok.closest.eql(&nm("x.w.example.")));
    try testing.expect(ce.ok.next_closer.eql(&nm("c.x.w.example.")));
    try testing.expectEqual(nsec3.Result.opt_out, p.provesNxDomain(&nm("a.c.x.w.example.")));
    // Drop the wildcard cover: incomplete.
    var p2 = try proof(recs[0..2], &scratch);
    try testing.expect(p2.provesNxDomain(&nm("a.c.x.w.example.")) == .failed);
}

test "RFC 5155 B.2 No Data: ns1.example. MX" {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const recs = [_]nsec3.Record{try z.nsec3Record("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.")};
    var scratch: [8]nsec3.Record = undefined;
    var p = try proof(&recs, &scratch);
    try testing.expectEqual(nsec3.Result.proven, p.provesNoData(&nm("ns1.example."), .mx));
    try testing.expectEqual(nsec3.Result{ .failed = .type_present }, p.provesNoData(&nm("ns1.example."), .a));
    try testing.expectEqual(nsec3.Result{ .failed = .name_exists }, p.provesNxDomain(&nm("ns1.example.")));
}

test "RFC 5155 B.2.1 No Data, empty non-terminal: y.w.example. A" {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const recs = [_]nsec3.Record{try z.nsec3Record("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.")};
    var scratch: [8]nsec3.Record = undefined;
    var p = try proof(&recs, &scratch);
    try testing.expectEqual(nsec3.Result.proven, p.provesNoData(&nm("y.w.example."), .a));
}

test "RFC 5155 B.3 Referral to an Opt-Out unsigned zone: c.example." {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const recs = [_]nsec3.Record{
        try z.nsec3Record("35mthgpgcu1qg68fab165klnsnk3dpvl.example."),
        try z.nsec3Record("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example."),
    };
    var scratch: [8]nsec3.Record = undefined;
    var p = try proof(&recs, &scratch);
    try testing.expectEqual(nsec3.Result.opt_out, p.provesInsecureDelegation(&nm("c.example.")));
    try testing.expectEqual(nsec3.Result.opt_out, p.provesNoData(&nm("c.example."), .ds));
}

test "RFC 5155 B.4 Wildcard Expansion: a.z.w.example. MX" {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const mx = try z.authenticated("*.w.example.", .mx);
    try testing.expectEqual(@as(u8, 2), mx.sigs[0].rrsig.labels);
    const recs = [_]nsec3.Record{try z.nsec3Record("q04jkcevqvmu85r014c7dkba38o0ji5r.example.")};
    var scratch: [8]nsec3.Record = undefined;
    var p = try proof(&recs, &scratch);
    try testing.expectEqual(nsec3.Result.opt_out, p.provesWildcardAnswer(&nm("a.z.w.example."), 2));
    try testing.expect(p.provesWildcardAnswer(&nm("a.z.w.example."), 1) == .failed);
}

test "RFC 5155 B.5 Wildcard No Data: a.z.w.example. AAAA" {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const recs = [_]nsec3.Record{
        try z.nsec3Record("k8udemvp1j2f7eg6jebps17vp3n8i58h.example."),
        try z.nsec3Record("q04jkcevqvmu85r014c7dkba38o0ji5r.example."),
        try z.nsec3Record("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example."),
    };
    var scratch: [8]nsec3.Record = undefined;
    var p = try proof(&recs, &scratch);
    try testing.expectEqual(nsec3.Result.opt_out, p.provesNoData(&nm("a.z.w.example."), .aaaa));
    try testing.expectEqual(nsec3.Result{ .failed = .type_present }, p.provesNoData(&nm("a.z.w.example."), .mx));
}

test "RFC 5155 B.6 DS Child Zone No Data: apex NSEC3 cannot deny the parent-side DS" {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const recs = [_]nsec3.Record{try z.nsec3Record("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.")};
    var scratch: [8]nsec3.Record = undefined;
    var p = try proof(&recs, &scratch);
    try testing.expectEqual(nsec3.Result{ .failed = .child_side_for_ds }, p.provesNoData(&nm("example."), .ds));
}

test "NSEC3 iteration limit and parameter consistency" {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const recs = [_]nsec3.Record{try z.nsec3Record("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.")};
    var scratch: [8]nsec3.Record = undefined;
    // The zone uses 12 iterations; a limit of 10 refuses it.
    const r = nsec3.Proof.init(&recs, nm("example."), .{ .max_iterations = 10 }, &scratch);
    try testing.expect(r == .err and r.err == .iterations_exceeded);
    var mixed = [_]nsec3.Record{ recs[0], recs[0] };
    mixed[1].nsec3.salt = &.{0x01};
    const r2 = nsec3.Proof.init(&mixed, nm("example."), .{}, &scratch);
    try testing.expect(r2 == .err and r2.err == .inconsistent_params);
    const r3 = nsec3.Proof.init(&recs, nm("example.org."), .{}, &scratch);
    try testing.expect(r3 == .err and r3.err == .no_records);
}

test "NSEC3 hash budget is enforced" {
    var z = try Zone.init(rfc5155_zone, t2010);
    defer z.deinit();
    const recs = [_]nsec3.Record{try z.nsec3Record("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.")};
    var scratch: [8]nsec3.Record = undefined;
    var p = switch (nsec3.Proof.init(&recs, nm("example."), .{ .max_hashes = 3 }, &scratch)) {
        .ok => |pp| pp,
        .err => return error.ProofInit,
    };
    // A ten-label name needs more than three hashes to walk to the apex.
    try testing.expectEqual(nsec3.Result.resource_limit, p.provesNxDomain(&nm("a.b.c.d.e.f.g.h.i.example.")));
}
