// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! NSEC denial of existence (RFC 4035 §5.4 with the RFC 6840 §4.1, §4.3,
//! §4.4 clarifications).
//!
//! Every function here assumes its NSEC records have already been
//! authenticated by the caller (signature verified under a secure zone key)
//! and carry the name of the zone that signed them. This module is pure
//! logic over those authenticated records.

const std = @import("std");
const wire_name = @import("../wire/name.zig");
const types = @import("../wire/types.zig");
const rdata = @import("../wire/rdata.zig");

const Name = wire_name.Name;
const Type = types.Type;

pub const Record = struct {
    owner: Name,
    nsec: rdata.Nsec,
    /// Signer (zone) of the RRSIG that authenticated this NSEC.
    zone: Name,
};

pub const Failure = enum {
    /// No NSEC covers / matches the name that must be denied.
    no_proof,
    /// The NSEC matching QNAME lists QTYPE.
    type_present,
    /// The NSEC matching QNAME lists CNAME (RFC 6840 §4.3).
    cname_present,
    /// A wildcard that could have matched exists.
    wildcard_exists,
    /// QNAME is an empty non-terminal, so it exists (NXDOMAIN is false).
    name_exists,
    /// Parent-side NSEC at a delegation used below the cut (RFC 6840 §4.1).
    ancestor_delegation,
    /// NSEC with the DNAME bit used to deny names below it (RFC 6840 §4.1).
    dname,
    /// Child-apex NSEC used to deny a DS record (DS lives in the parent).
    child_side_for_ds,
    /// For insecure-delegation proofs: the matching NSEC has no NS bit
    /// (RFC 6840 §4.4) or has the DS or SOA bit.
    not_insecure_delegation,
    /// The wildcard proof does not match the RRSIG-indicated closest encloser.
    wrong_closest_encloser,
};

pub const Result = union(enum) {
    proven,
    failed: Failure,
};

fn isAncestorDelegation(r: *const Record) bool {
    return r.nsec.types.has(.ns) and !r.nsec.types.has(.soa) and r.zone.labelCount() < r.owner.labelCount();
}

/// Name `n` lies strictly between owner and next in canonical order (with
/// wrap-around for the last NSEC in the zone), and the record may be used
/// to deny it.
pub fn covers(r: *const Record, n: *const Name) bool {
    if (!n.isSubdomainOf(&r.zone)) return false;
    const after_owner = r.owner.canonicalOrder(n) == .lt;
    const before_next = n.canonicalOrder(&r.nsec.next) == .lt;
    const in_range = if (r.owner.canonicalOrder(&r.nsec.next) == .lt)
        after_owner and before_next
    else
        // Last NSEC of the zone: next is the apex.
        after_owner or before_next;
    if (!in_range) return false;
    // RFC 6840 §4.1: nothing below a delegation or DNAME can be denied by
    // the NSEC at that owner.
    if (n.isStrictSubdomainOf(&r.owner)) {
        if (isAncestorDelegation(r) or r.nsec.types.has(.dname)) return false;
    }
    return true;
}

pub fn matches(r: *const Record, n: *const Name) bool {
    return r.owner.eql(n);
}

/// Labels of the closest encloser implied by an NSEC that covers `qname`
/// (RFC 4035 §5.4): the longest common ancestor with the owner or next name.
fn closestEncloserLabels(r: *const Record, qname: *const Name) usize {
    const a = qname.commonSuffixLabels(&r.owner);
    const b = qname.commonSuffixLabels(&r.nsec.next);
    // The next name of the last NSEC is the apex; never go above the zone.
    return @max(@max(a, b), r.zone.labelCount());
}

fn findMatch(recs: []const Record, n: *const Name) ?*const Record {
    for (recs) |*r| if (matches(r, n)) return r;
    return null;
}

fn findCover(recs: []const Record, n: *const Name) ?*const Record {
    for (recs) |*r| if (covers(r, n)) return r;
    return null;
}

/// Checks a matching NSEC's bitmap for a NODATA proof at its owner.
fn nodataAtMatch(r: *const Record, qtype: Type) Result {
    if (qtype == .ds) {
        // The DS RRset lives on the parent side; an apex NSEC (SOA bit)
        // comes from the child and cannot deny it.
        if (r.nsec.types.has(.soa) and !r.owner.isRoot()) return .{ .failed = .child_side_for_ds };
    } else if (isAncestorDelegation(r)) {
        return .{ .failed = .ancestor_delegation };
    }
    if (r.nsec.types.has(qtype)) return .{ .failed = .type_present };
    if (r.nsec.types.has(.cname)) return .{ .failed = .cname_present };
    return .proven;
}

/// NOERROR/NODATA for (qname, qtype), including the empty non-terminal case
/// and wildcard NODATA (RFC 4035 §3.1.3.4).
pub fn provesNoData(recs: []const Record, qname: *const Name, qtype: Type) Result {
    if (findMatch(recs, qname)) |r| return nodataAtMatch(r, qtype);
    // Empty non-terminal: an NSEC whose owner sorts before qname and whose
    // next name is a descendant of qname (RFC 4035 §3.1.3.2, as in Unbound).
    for (recs) |*r| {
        if (r.nsec.next.isStrictSubdomainOf(qname) and r.owner.canonicalOrder(qname) == .lt and qname.isSubdomainOf(&r.zone)) {
            return .proven;
        }
    }
    // Wildcard NODATA: qname does not exist, and the wildcard at the
    // closest encloser exists without qtype.
    const cov = findCover(recs, qname) orelse return .{ .failed = .no_proof };
    const ce = qname.suffix(closestEncloserLabels(cov, qname));
    const wc = ce.prepend("*") catch return .{ .failed = .no_proof };
    if (findMatch(recs, &wc)) |w| return nodataAtMatch(w, qtype);
    return .{ .failed = .no_proof };
}

/// NXDOMAIN: qname is covered, is not an empty non-terminal, and the
/// wildcard at its closest encloser is covered as well.
pub fn provesNxDomain(recs: []const Record, qname: *const Name) Result {
    if (findMatch(recs, qname) != null) return .{ .failed = .name_exists };
    const cov = findCover(recs, qname) orelse return .{ .failed = .no_proof };
    if (cov.nsec.next.isStrictSubdomainOf(qname)) return .{ .failed = .name_exists };
    const ce = qname.suffix(closestEncloserLabels(cov, qname));
    const wc = ce.prepend("*") catch return .{ .failed = .no_proof };
    if (findMatch(recs, &wc) != null) return .{ .failed = .wildcard_exists };
    if (findCover(recs, &wc) == null) return .{ .failed = .no_proof };
    return .proven;
}

/// For a positive answer synthesised from a wildcard whose RRSIG Labels
/// field is `labels`: qname itself must not exist, and the closest encloser
/// implied by the covering NSEC must be the wildcard's parent.
pub fn provesWildcardAnswer(recs: []const Record, qname: *const Name, labels: u8) Result {
    const cov = findCover(recs, qname) orelse return .{ .failed = .no_proof };
    if (cov.nsec.next.isStrictSubdomainOf(qname)) return .{ .failed = .name_exists };
    if (closestEncloserLabels(cov, qname) != labels) return .{ .failed = .wrong_closest_encloser };
    return .proven;
}

/// Insecure delegation at `child` (RFC 4035 §5.2, RFC 6840 §4.4): a
/// parent-side NSEC matching `child` with NS set and DS, SOA clear.
pub fn provesInsecureDelegation(recs: []const Record, child: *const Name) Result {
    const r = findMatch(recs, child) orelse return .{ .failed = .no_proof };
    if (!child.isStrictSubdomainOf(&r.zone)) {
        return .{ .failed = .child_side_for_ds };
    }
    if (!r.nsec.types.has(.ns) or r.nsec.types.has(.ds) or r.nsec.types.has(.soa)) {
        return .{ .failed = .not_insecure_delegation };
    }
    return .proven;
}

// ---------------------------------------------------------------------------
// Tests use the RFC 4035 Appendix A zone's NSEC chain (see tests/denial.zig
// for full-response tests); here, small synthetic chains.
// ---------------------------------------------------------------------------

const testing = std.testing;

fn mk(owner: []const u8, next: []const u8, tlist: []const Type, zone: []const u8, store: *[64]u8) !Record {
    const nx = try Name.fromText(next);
    @memcpy(store[0..nx.len], nx.bytes());
    var len: usize = nx.len;
    var bm: [34]u8 = @splat(0);
    var maxo: usize = 0;
    for (tlist) |t| {
        const v = t.toInt();
        std.debug.assert(v < 256);
        bm[2 + v / 8] |= @as(u8, 0x80) >> @intCast(v % 8);
        maxo = @max(maxo, v / 8 + 1);
    }
    if (maxo > 0) {
        bm[0] = 0;
        bm[1] = @intCast(maxo);
        @memcpy(store[len..][0 .. 2 + maxo], bm[0 .. 2 + maxo]);
        len += 2 + maxo;
    }
    return .{ .owner = try Name.fromText(owner), .nsec = try rdata.Nsec.parse(store[0..len]), .zone = try Name.fromText(zone) };
}

test "NSEC cover, wrap-around and NXDOMAIN with wildcard denial" {
    var s1: [64]u8 = undefined;
    var s2: [64]u8 = undefined;
    var s3: [64]u8 = undefined;
    const recs = [_]Record{
        try mk("example.", "b.example.", &.{ .soa, .ns, .rrsig, .nsec }, "example.", &s1),
        try mk("b.example.", "d.example.", &.{ .a, .rrsig, .nsec }, "example.", &s2),
        try mk("d.example.", "example.", &.{ .a, .rrsig, .nsec }, "example.", &s3),
    };
    const c = try Name.fromText("c.example.");
    try testing.expect(covers(&recs[1], &c));
    try testing.expect(!covers(&recs[0], &c));
    const z = try Name.fromText("z.example.");
    try testing.expect(covers(&recs[2], &z)); // wrap-around
    try testing.expectEqual(Result.proven, provesNxDomain(&recs, &c));
    // "*.example." sorts before b.example, after example.: covered by recs[0].
    const b = try Name.fromText("b.example.");
    try testing.expectEqual(Result{ .failed = .name_exists }, provesNxDomain(&recs, &b));
    try testing.expectEqual(Result.proven, provesNoData(&recs, &b, .mx));
    try testing.expectEqual(Result{ .failed = .type_present }, provesNoData(&recs, &b, .a));
    // Missing wildcard denial.
    try testing.expectEqual(Result{ .failed = .no_proof }, provesNxDomain(recs[1..], &c));
    // Out-of-zone names are never covered.
    const other = try Name.fromText("c.example.org.");
    try testing.expect(!covers(&recs[2], &other));
}

test "NSEC: empty non-terminal is NODATA, not NXDOMAIN" {
    var s1: [64]u8 = undefined;
    var s2: [64]u8 = undefined;
    const recs = [_]Record{
        try mk("example.", "a.b.example.", &.{ .soa, .ns, .rrsig, .nsec }, "example.", &s1),
        try mk("a.b.example.", "example.", &.{ .a, .rrsig, .nsec }, "example.", &s2),
    };
    const ent = try Name.fromText("b.example.");
    try testing.expectEqual(Result{ .failed = .name_exists }, provesNxDomain(&recs, &ent));
    try testing.expectEqual(Result.proven, provesNoData(&recs, &ent, .a));
}

test "NSEC: ancestor delegation and DNAME cannot deny names below them (RFC 6840 §4.1)" {
    var s1: [64]u8 = undefined;
    var s2: [64]u8 = undefined;
    const recs = [_]Record{
        try mk("sub.example.", "z.example.", &.{ .ns, .rrsig, .nsec }, "example.", &s1),
        try mk("d.example.", "e.example.", &.{ .dname, .rrsig, .nsec }, "example.", &s2),
    };
    const below = try Name.fromText("x.sub.example.");
    try testing.expect(!covers(&recs[0], &below));
    const sub = try Name.fromText("sub.example.");
    try testing.expectEqual(Result{ .failed = .ancestor_delegation }, provesNoData(&recs, &sub, .a));
    // ...but it does prove there is no DS, i.e. an insecure delegation.
    try testing.expectEqual(Result.proven, provesNoData(&recs, &sub, .ds));
    try testing.expectEqual(Result.proven, provesInsecureDelegation(&recs, &sub));
    const below_dname = try Name.fromText("x.d.example.");
    try testing.expect(!covers(&recs[1], &below_dname));
}

test "NSEC: CNAME bit blocks NODATA (RFC 6840 §4.3) and insecure-delegation rules" {
    var s1: [64]u8 = undefined;
    var s2: [64]u8 = undefined;
    var s3: [64]u8 = undefined;
    const recs = [_]Record{
        try mk("c.example.", "d.example.", &.{ .cname, .rrsig, .nsec }, "example.", &s1),
        try mk("d.example.", "e.example.", &.{ .a, .rrsig, .nsec }, "example.", &s2),
        try mk("e.example.", "f.example.", &.{ .ns, .ds, .rrsig, .nsec }, "example.", &s3),
    };
    const c = try Name.fromText("c.example.");
    try testing.expectEqual(Result{ .failed = .cname_present }, provesNoData(&recs, &c, .a));
    const d = try Name.fromText("d.example.");
    // RFC 6840 §4.4: no NS bit -> not a delegation.
    try testing.expectEqual(Result{ .failed = .not_insecure_delegation }, provesInsecureDelegation(&recs, &d));
    const e = try Name.fromText("e.example.");
    try testing.expectEqual(Result{ .failed = .not_insecure_delegation }, provesInsecureDelegation(&recs, &e));
}

test "NSEC: wildcard answer needs the right closest encloser" {
    var s1: [64]u8 = undefined;
    const recs = [_]Record{
        try mk("*.w.example.", "x.w.example.", &.{ .mx, .rrsig, .nsec }, "example.", &s1),
    };
    // a.z.w.example. expanded from *.w.example. (Labels = 2).
    const q2 = try Name.fromText("a.w.example.");
    try testing.expectEqual(Result.proven, provesWildcardAnswer(&recs, &q2, 2));
    try testing.expectEqual(Result{ .failed = .wrong_closest_encloser }, provesWildcardAnswer(&recs, &q2, 1));
}
