// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! NSEC3 hashed denial of existence (RFC 5155 §5, §7.2, §8, with the
//! RFC 6840 §4.1/§4.3/§4.4 clarifications and RFC 9276 iteration limits).
//!
//! As with nsec.zig, records must already be authenticated by the caller.
//! Hash computations are counted against a budget so that crafted
//! responses cannot force unbounded work (cf. CVE-2023-50868).

const std = @import("std");
const wire_name = @import("../wire/name.zig");
const types = @import("../wire/types.zig");
const rdata = @import("../wire/rdata.zig");
const encoding = @import("../wire/encoding.zig");

const Name = wire_name.Name;
const Type = types.Type;
const Sha1 = std.crypto.hash.Sha1;

pub const hash_len = Sha1.digest_length;

/// An authenticated NSEC3 record in usable form.
pub const Record = struct {
    owner: Name,
    /// The zone this NSEC3 belongs to: the owner minus its hash label.
    zone: Name,
    /// Hash decoded from the owner's first label.
    owner_hash: [hash_len]u8,
    nsec3: rdata.Nsec3,

    pub const FromRrError = error{
        /// Unknown hash algorithm or Flags other than 0/1 (RFC 5155 §8.1,
        /// §8.2): the record must be ignored.
        Ignored,
        /// Owner is not <base32hex(hash)>.<zone>, or the hash lengths differ.
        BadOwner,
        MalformedRdata,
    };

    /// Builds a Record from an NSEC3 RR authenticated by `signer`.
    pub fn fromRr(owner: Name, rd: []const u8, signer: *const Name) FromRrError!Record {
        const n3 = rdata.Nsec3.parse(rd) catch return error.MalformedRdata;
        if (n3.hash_algorithm != .sha1) return error.Ignored;
        if (n3.flags & ~rdata.Nsec3.flag_opt_out != 0) return error.Ignored;
        const zone = owner.parent() orelse return error.BadOwner;
        if (!zone.eql(signer)) return error.BadOwner;
        const label = owner.label(0);
        var buf: [64]u8 = undefined;
        if (label.len != encoding.base32HexEncodedLen(hash_len)) return error.BadOwner;
        const dec = encoding.base32HexDecode(&buf, label) catch return error.BadOwner;
        if (dec.len != hash_len) return error.BadOwner;
        var rec: Record = .{ .owner = owner, .zone = zone, .owner_hash = undefined, .nsec3 = n3 };
        @memcpy(&rec.owner_hash, dec);
        return rec;
    }

    fn sameParams(a: *const Record, b: *const Record) bool {
        return a.nsec3.hash_algorithm == b.nsec3.hash_algorithm and
            a.nsec3.iterations == b.nsec3.iterations and
            std.mem.eql(u8, a.nsec3.salt, b.nsec3.salt);
    }
};

/// RFC 5155 §5: IH(salt, x, 0) = H(x || salt); IH(salt, x, k) =
/// H(IH(salt, x, k-1) || salt). x is the canonical (lowercase) wire name.
pub fn hashName(n: *const Name, salt: []const u8, iterations: u16) [hash_len]u8 {
    const lc = n.lowercase();
    var digest: [hash_len]u8 = undefined;
    var h = Sha1.init(.{});
    h.update(lc.bytes());
    h.update(salt);
    h.final(&digest);
    var k: u32 = 0;
    while (k < iterations) : (k += 1) {
        var hh = Sha1.init(.{});
        hh.update(&digest);
        hh.update(salt);
        hh.final(&digest);
    }
    return digest;
}

pub const Config = struct {
    /// NSEC3 iteration counts above this are not processed (RFC 9276 §3.2).
    max_iterations: u16 = 150,
    /// Maximum distinct hash computations for one proof.
    max_hashes: u32 = 128,
};

pub const Failure = enum {
    no_proof,
    /// QNAME (or the name that must be denied) has a matching NSEC3.
    name_exists,
    type_present,
    cname_present,
    wildcard_exists,
    /// A matching NSEC3 for a candidate encloser without a covered next
    /// closer name (RFC 5155 §8.3: bogus).
    bad_closest_encloser,
    ancestor_delegation,
    dname,
    child_side_for_ds,
    not_insecure_delegation,
    /// Records for the zone disagree on algorithm, iterations or salt.
    inconsistent_params,
    /// No usable NSEC3 records for the zone.
    no_records,
};

pub const Result = union(enum) {
    proven,
    /// The proof relies on an Opt-Out NSEC3 covering the next closer name:
    /// the answer cannot be secure (RFC 5155 §9.2) but is not bogus.
    opt_out,
    failed: Failure,
    /// Iterations above `Config.max_iterations` (policy decides).
    iterations_exceeded,
    /// Hash budget exhausted.
    resource_limit,
};

/// A proof context over the authenticated NSEC3 records of one zone.
pub const Proof = struct {
    recs: []const Record,
    zone: Name,
    cfg: Config,
    hashes_left: u32,
    cache_names: [16]Name = undefined,
    cache_hashes: [16][hash_len]u8 = undefined,
    cache_len: usize = 0,
    salt: []const u8 = &.{},
    iterations: u16 = 0,

    const InitError = enum { no_records, inconsistent_params, iterations_exceeded };

    /// `recs` may contain records for several zones; only those of `zone`
    /// are used.
    pub fn init(all: []const Record, zone: Name, cfg: Config, scratch: []Record) union(enum) { ok: Proof, err: InitError } {
        var n: usize = 0;
        for (all) |*r| {
            if (!r.zone.eql(&zone)) continue;
            if (n >= scratch.len) break;
            scratch[n] = r.*;
            n += 1;
        }
        if (n == 0) return .{ .err = .no_records };
        for (scratch[1..n]) |*r| if (!r.sameParams(&scratch[0])) return .{ .err = .inconsistent_params };
        if (scratch[0].nsec3.iterations > cfg.max_iterations) return .{ .err = .iterations_exceeded };
        return .{ .ok = .{
            .recs = scratch[0..n],
            .zone = zone,
            .cfg = cfg,
            .hashes_left = cfg.max_hashes,
            .salt = scratch[0].nsec3.salt,
            .iterations = scratch[0].nsec3.iterations,
        } };
    }

    fn hashOf(p: *Proof, n: *const Name) ?[hash_len]u8 {
        for (p.cache_names[0..p.cache_len], 0..) |*c, i| {
            if (c.eql(n)) return p.cache_hashes[i];
        }
        if (p.hashes_left == 0) return null;
        p.hashes_left -= 1;
        const h = hashName(n, p.salt, p.iterations);
        const slot = if (p.cache_len < p.cache_names.len) blk: {
            p.cache_len += 1;
            break :blk p.cache_len - 1;
        } else p.hashes_left % p.cache_names.len;
        p.cache_names[slot] = n.*;
        p.cache_hashes[slot] = h;
        return h;
    }

    const Lookup = union(enum) { found: *const Record, none, budget };

    fn match(p: *Proof, n: *const Name) Lookup {
        if (!n.isSubdomainOf(&p.zone)) return .none;
        const h = p.hashOf(n) orelse return .budget;
        for (p.recs) |*r| if (std.mem.eql(u8, &r.owner_hash, &h)) return .{ .found = r };
        return .none;
    }

    fn cover(p: *Proof, n: *const Name) Lookup {
        if (!n.isSubdomainOf(&p.zone)) return .none;
        const h = p.hashOf(n) orelse return .budget;
        for (p.recs) |*r| {
            const next = r.nsec3.next_hashed_owner;
            if (next.len != hash_len) continue;
            const after_owner = std.mem.order(u8, &r.owner_hash, &h) == .lt;
            const before_next = std.mem.order(u8, &h, next) == .lt;
            const in_range = if (std.mem.order(u8, &r.owner_hash, next) == .lt)
                after_owner and before_next
            else
                after_owner or before_next; // last NSEC3 in the hash order
            if (in_range) return .{ .found = r };
        }
        return .none;
    }

    pub const Encloser = struct {
        closest: Name,
        next_closer: Name,
        next_closer_cover: *const Record,
    };

    const CeResult = union(enum) { ok: Encloser, res: Result };

    /// RFC 5155 §8.3 closest (provable) encloser proof for `qname`.
    pub fn closestEncloser(p: *Proof, qname: *const Name) CeResult {
        if (!qname.isSubdomainOf(&p.zone)) return .{ .res = .{ .failed = .no_proof } };
        var sname = qname.*;
        var prev: ?Name = null;
        var prev_cover: ?*const Record = null;
        while (true) {
            switch (p.match(&sname)) {
                .budget => return .{ .res = .resource_limit },
                .found => |m| {
                    if (prev_cover) |pc| {
                        // RFC 5155 §8.3 last paragraph / RFC 6840 §4.1.
                        if (m.nsec3.types.has(.dname)) return .{ .res = .{ .failed = .dname } };
                        if (m.nsec3.types.has(.ns) and !m.nsec3.types.has(.soa)) return .{ .res = .{ .failed = .ancestor_delegation } };
                        return .{ .ok = .{ .closest = sname, .next_closer = prev.?, .next_closer_cover = pc } };
                    }
                    if (sname.eql(qname)) return .{ .res = .{ .failed = .name_exists } };
                    return .{ .res = .{ .failed = .bad_closest_encloser } };
                },
                .none => {},
            }
            prev_cover = switch (p.cover(&sname)) {
                .budget => return .{ .res = .resource_limit },
                .found => |c| c,
                .none => null,
            };
            if (sname.eql(&p.zone)) return .{ .res = .{ .failed = .no_proof } };
            prev = sname;
            sname = sname.parent().?;
        }
    }

    fn nodataBits(m: *const Record, qtype: Type) Result {
        if (qtype == .ds) {
            if (m.nsec3.types.has(.soa)) return .{ .failed = .child_side_for_ds };
        } else if (m.nsec3.types.has(.ns) and !m.nsec3.types.has(.soa)) {
            return .{ .failed = .ancestor_delegation };
        }
        if (m.nsec3.types.has(qtype)) return .{ .failed = .type_present };
        if (m.nsec3.types.has(.cname)) return .{ .failed = .cname_present };
        return .proven;
    }

    /// §8.4 Name Error.
    pub fn provesNxDomain(p: *Proof, qname: *const Name) Result {
        const ce = switch (p.closestEncloser(qname)) {
            .ok => |e| e,
            .res => |r| return r,
        };
        const wc = ce.closest.prepend("*") catch return .{ .failed = .no_proof };
        switch (p.cover(&wc)) {
            .budget => return .resource_limit,
            .none => {
                return switch (p.match(&wc)) {
                    .budget => .resource_limit,
                    .found => .{ .failed = .wildcard_exists },
                    .none => .{ .failed = .no_proof },
                };
            },
            .found => {},
        }
        if (ce.next_closer_cover.nsec3.optOut()) return .opt_out;
        return .proven;
    }

    /// §8.5 / §8.6 / §8.7 No Data (including wildcard No Data).
    pub fn provesNoData(p: *Proof, qname: *const Name, qtype: Type) Result {
        switch (p.match(qname)) {
            .budget => return .resource_limit,
            .found => |m| return nodataBits(m, qtype),
            .none => {},
        }
        const ce = switch (p.closestEncloser(qname)) {
            .ok => |e| e,
            .res => |r| return r,
        };
        if (qtype == .ds) {
            // §8.6: no matching NSEC3 -> must be an Opt-Out span.
            if (ce.next_closer_cover.nsec3.optOut()) return .opt_out;
            return .{ .failed = .no_proof };
        }
        // §8.7: wildcard No Data.
        const wc = ce.closest.prepend("*") catch return .{ .failed = .no_proof };
        switch (p.match(&wc)) {
            .budget => return .resource_limit,
            .found => |m| {
                const r = nodataBits(m, qtype);
                if (r != .proven) return r;
                if (ce.next_closer_cover.nsec3.optOut()) return .opt_out;
                return .proven;
            },
            .none => return .{ .failed = .no_proof },
        }
    }

    /// §8.8 Wildcard answer: the RRSIG Labels value gives the closest
    /// encloser; the next closer name must be covered.
    pub fn provesWildcardAnswer(p: *Proof, qname: *const Name, labels: u8) Result {
        if (labels >= qname.labelCount()) return .{ .failed = .no_proof };
        const ce = qname.suffix(labels);
        if (!ce.isSubdomainOf(&p.zone)) return .{ .failed = .no_proof };
        const next_closer = qname.suffix(@as(usize, labels) + 1);
        return switch (p.cover(&next_closer)) {
            .budget => .resource_limit,
            .none => .{ .failed = .no_proof },
            .found => |c| if (c.nsec3.optOut()) .opt_out else .proven,
        };
    }

    /// §8.9 / RFC 6840 §4.4: `child` is a delegation with no DS (insecure),
    /// either by a matching NSEC3 (NS set, DS and SOA clear) or by an
    /// Opt-Out NSEC3 covering the next closer name.
    pub fn provesInsecureDelegation(p: *Proof, child: *const Name) Result {
        if (!child.isStrictSubdomainOf(&p.zone)) return .{ .failed = .child_side_for_ds };
        switch (p.match(child)) {
            .budget => return .resource_limit,
            .found => |m| {
                if (!m.nsec3.types.has(.ns) or m.nsec3.types.has(.ds) or m.nsec3.types.has(.soa))
                    return .{ .failed = .not_insecure_delegation };
                return .proven;
            },
            .none => {},
        }
        const ce = switch (p.closestEncloser(child)) {
            .ok => |e| e,
            .res => |r| return r,
        };
        if (ce.next_closer_cover.nsec3.optOut()) return .opt_out;
        return .{ .failed = .not_insecure_delegation };
    }
};

// ---------------------------------------------------------------------------
// Tests: RFC 5155 Appendix A hash vectors. Full proof tests over the
// Appendix B responses live in tests/denial.zig.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "RFC 5155 Appendix A hash vectors (salt aabbccdd, 12 iterations)" {
    const salt = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const cases = [_][2][]const u8{
        .{ "example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom" },
        .{ "a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl" },
        .{ "ai.example.", "gjeqe526plbf1g8mklp59enfd789njgi" },
        .{ "ns1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr" },
        .{ "ns2.example.", "q04jkcevqvmu85r014c7dkba38o0ji5r" },
        .{ "w.example.", "k8udemvp1j2f7eg6jebps17vp3n8i58h" },
        .{ "*.w.example.", "r53bq7cc2uvmubfu5ocmm6pers9tk9en" },
        .{ "x.w.example.", "b4um86eghhds6nea196smvmlo4ors995" },
        .{ "y.w.example.", "ji6neoaepv8b5o6k4ev33abha8ht9fgc" },
        .{ "x.y.w.example.", "2vptu5timamqttgl4luu9kg21e0aor3s" },
        .{ "xx.example.", "t644ebqk9bibcna874givr6joj62mlhv" },
        .{ "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.", "kohar7mbb8dc2ce8a9qvl8hon4k53uhi" },
    };
    for (cases) |c| {
        const n = try Name.fromText(c[0]);
        const h = hashName(&n, &salt, 12);
        var b32: [40]u8 = undefined;
        try testing.expectEqualStrings(c[1], encoding.base32HexEncode(&b32, &h));
        // Case-insensitivity of the input name.
        var up: [80]u8 = undefined;
        const upper = std.ascii.upperString(up[0..c[0].len], c[0]);
        const n2 = try Name.fromText(upper);
        try testing.expectEqualSlices(u8, &h, &hashName(&n2, &salt, 12));
    }
}

test "Record.fromRr owner checks" {
    var rd: [5 + 1 + 20 + 2]u8 = undefined;
    rd[0] = 1;
    rd[1] = 0;
    rd[2] = 0;
    rd[3] = 0;
    rd[4] = 0;
    rd[5] = 20;
    @memset(rd[6..26], 0x22);
    rd[26] = 0;
    rd[27] = 1;
    rd[27] = 0;
    const zone = try Name.fromText("example.");
    const good = try Name.fromText("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.");
    _ = try Record.fromRr(good, rd[0..26], &zone);
    const other_zone = try Name.fromText("example.org.");
    try testing.expectError(error.BadOwner, Record.fromRr(good, rd[0..26], &other_zone));
    const bad_label = try Name.fromText("notbase32hash.example.");
    try testing.expectError(error.BadOwner, Record.fromRr(bad_label, rd[0..26], &zone));
    rd[1] = 2; // unknown flag
    try testing.expectError(error.Ignored, Record.fromRr(good, rd[0..26], &zone));
    rd[1] = 0;
    rd[0] = 2; // unknown hash algorithm
    try testing.expectError(error.Ignored, Record.fromRr(good, rd[0..26], &zone));
}
