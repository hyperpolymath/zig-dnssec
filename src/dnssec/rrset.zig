// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! RRsets, their RRSIGs, canonical signed data (RFC 4034 §3.1.8.1, §6;
//! RFC 4035 §5.3.2) and single-signature verification (RFC 4035 §5.3.1).

const std = @import("std");
const wire_name = @import("../wire/name.zig");
const types = @import("../wire/types.zig");
const rdata = @import("../wire/rdata.zig");
const message = @import("../wire/message.zig");
const crypto = @import("crypto.zig");
const keys = @import("keys.zig");

const Name = wire_name.Name;
const Type = types.Type;
const Allocator = std.mem.Allocator;

pub const Sig = struct {
    rrsig: rdata.Rrsig,
    rdata: []const u8,
    ttl: u32,
};

pub const RrSet = struct {
    name: Name,
    type: Type,
    class: types.Class,
    /// Minimum TTL over the member records.
    ttl: u32,
    rdatas: []const []const u8,
    sigs: []const Sig,

    pub fn isSigned(s: *const RrSet) bool {
        return s.sigs.len > 0;
    }
};

pub const Grouped = struct {
    sets: []RrSet,
    /// RRSIGs whose covered RRset is not present in the same section.
    orphan_sigs: []Sig,
};

/// Groups records into RRsets (same owner, type, class) and attaches the
/// RRSIGs that cover each one.
///
/// Every RRSIG record is read as a *signature* and never as data, so a
/// QTYPE=RRSIG answer is grouped into no RRset at all (its records land in
/// `orphan_sigs`). That is deliberate: nothing signs an RRSIG RRset, so there
/// is no way to authenticate one, and a positive answer would be
/// indistinguishable from a NODATA denial. Callers must reject QTYPE=RRSIG
/// before validating — `validator.validateResponse` and the C ABI both do.
pub fn group(a: Allocator, rrs: []const message.Rr) Allocator.Error!Grouped {
    var sets: std.ArrayList(RrSet) = .empty;
    var members: std.ArrayList(std.ArrayList([]const u8)) = .empty;
    var sig_lists: std.ArrayList(std.ArrayList(Sig)) = .empty;
    var orphans: std.ArrayList(Sig) = .empty;

    for (rrs) |*rr| {
        if (rr.type == .rrsig) continue;
        const idx = for (sets.items, 0..) |*s, i| {
            if (s.type == rr.type and s.class == rr.class and s.name.eql(&rr.name)) break i;
        } else blk: {
            try sets.append(a, .{ .name = rr.name, .type = rr.type, .class = rr.class, .ttl = rr.ttl, .rdatas = &.{}, .sigs = &.{} });
            try members.append(a, .empty);
            try sig_lists.append(a, .empty);
            break :blk sets.items.len - 1;
        };
        sets.items[idx].ttl = @min(sets.items[idx].ttl, rr.ttl);
        try members.items[idx].append(a, rr.rdata);
    }
    for (rrs) |*rr| {
        if (rr.type != .rrsig) continue;
        const parsed = rdata.Rrsig.parse(rr.rdata) catch continue; // validated at parse time
        const sig: Sig = .{ .rrsig = parsed, .rdata = rr.rdata, .ttl = rr.ttl };
        for (sets.items, 0..) |*s, i| {
            if (s.type == parsed.type_covered and s.class == rr.class and s.name.eql(&rr.name)) {
                try sig_lists.items[i].append(a, sig);
                break;
            }
        } else try orphans.append(a, sig);
    }
    for (sets.items, 0..) |*s, i| {
        s.rdatas = members.items[i].items;
        s.sigs = sig_lists.items[i].items;
    }
    return .{ .sets = sets.items, .orphan_sigs = orphans.items };
}

/// RFC 1982 serial-number "a <= b" for 32-bit RRSIG timestamps.
pub fn serialLe(a: u32, b: u32) bool {
    return (b -% a) < 0x8000_0000;
}

pub const TimeStatus = enum { valid, not_yet_valid, expired, bad_period };

/// RFC 4034 §3.1.5 / RFC 4035 §5.3.1 validity window check. `skew` widens
/// the window symmetrically (0 = strict).
pub fn checkTime(inception: u32, expiration: u32, now: u32, skew: u32) TimeStatus {
    if (!serialLe(inception, expiration)) return .bad_period;
    if (!serialLe(inception, now +% skew)) return .not_yet_valid;
    if (!serialLe(now -% skew, expiration)) return .expired;
    return .valid;
}

pub const SigError = crypto.VerifyError || Allocator.Error || error{
    /// RRSIG Signer's Name is not an ancestor-or-self of the owner.
    SignerNotAncestor,
    /// RRSIG Labels exceeds the owner's label count.
    BadLabelCount,
    SignatureNotYetValid,
    SignatureExpired,
    /// Inception after expiration.
    BadValidityPeriod,
    /// DNSKEY owner differs from the RRSIG Signer's Name.
    KeyOwnerMismatch,
    KeyTagMismatch,
    KeyAlgorithmMismatch,
    /// DNSKEY Protocol field is not 3.
    KeyBadProtocol,
    /// DNSKEY Zone Key flag (bit 7) is clear.
    KeyNotZoneKey,
    /// DNSKEY REVOKE flag set (RFC 5011 §2.1).
    KeyRevoked,
    MalformedKey,
};

/// The owner name to use in signed data: the canonical owner, or the
/// wildcard it was expanded from when Labels < owner labels.
pub fn signingOwner(owner: *const Name, labels: u8) SigError!Name {
    const fqdn_labels = owner.labelCount();
    if (labels > fqdn_labels) return error.BadLabelCount;
    const lc = owner.lowercase();
    if (labels == fqdn_labels) return lc;
    const base = lc.suffix(labels);
    return base.prepend("*") catch error.BadLabelCount;
}

/// True if the RRSIG indicates the RRset was synthesised from a wildcard.
pub fn isWildcardExpansion(owner: *const Name, sig: *const rdata.Rrsig) bool {
    return sig.labels < owner.labelCount() and !(owner.isWildcard() and sig.labels + 1 == owner.labelCount());
}

fn lessThanSlice(_: void, x: []const u8, y: []const u8) bool {
    return std.mem.order(u8, x, y) == .lt;
}

/// Builds the data covered by `sig` over `set` (RFC 4034 §3.1.8.1).
pub fn signedData(a: Allocator, set: *const RrSet, sig: *const Sig) SigError![]u8 {
    const owner = try signingOwner(&set.name, sig.rrsig.labels);
    // Canonicalise each RDATA, then sort and de-duplicate (RFC 4034 §6.3).
    const canon = try a.alloc([]const u8, set.rdatas.len);
    for (set.rdatas, 0..) |rd, i| {
        const buf = try a.alloc(u8, rd.len);
        canon[i] = rdata.canonicalize(set.type, rd, buf) catch return error.MalformedKey;
    }
    std.mem.sort([]const u8, canon, {}, lessThanSlice);

    var out: std.ArrayList(u8) = .empty;
    // RRSIG RDATA without the signature, signer in canonical (lowercase) form.
    try out.appendSlice(a, sig.rrsig.signed_prefix[0..18]);
    const signer_lc = sig.rrsig.signer.lowercase();
    try out.appendSlice(a, signer_lc.bytes());

    var prev: ?[]const u8 = null;
    for (canon) |rd| {
        if (prev) |p| if (std.mem.eql(u8, p, rd)) continue;
        prev = rd;
        try out.appendSlice(a, owner.bytes());
        var hdr: [10]u8 = undefined;
        std.mem.writeInt(u16, hdr[0..2], set.type.toInt(), .big);
        std.mem.writeInt(u16, hdr[2..4], set.class.toInt(), .big);
        std.mem.writeInt(u32, hdr[4..8], sig.rrsig.original_ttl, .big);
        std.mem.writeInt(u16, hdr[8..10], @intCast(rd.len), .big);
        try out.appendSlice(a, &hdr);
        try out.appendSlice(a, rd);
    }
    return out.items;
}

/// All RFC 4035 §5.3.1 checks that do not need cryptography.
pub fn checkSigAndKey(
    set: *const RrSet,
    sig: *const Sig,
    key_owner: *const Name,
    key_rdata: []const u8,
    now: u32,
    skew: u32,
) SigError!rdata.Dnskey {
    const s = &sig.rrsig;
    if (!set.name.isSubdomainOf(&s.signer)) return error.SignerNotAncestor;
    if (s.labels > set.name.labelCount()) return error.BadLabelCount;
    switch (checkTime(s.inception, s.expiration, now, skew)) {
        .valid => {},
        .not_yet_valid => return error.SignatureNotYetValid,
        .expired => return error.SignatureExpired,
        .bad_period => return error.BadValidityPeriod,
    }
    if (!key_owner.eql(&s.signer)) return error.KeyOwnerMismatch;
    const key = rdata.Dnskey.parse(key_rdata) catch return error.MalformedKey;
    if (key.protocol != 3) return error.KeyBadProtocol;
    if (!key.isZoneKey()) return error.KeyNotZoneKey;
    if (key.isRevoked()) return error.KeyRevoked;
    if (key.algorithm != s.algorithm) return error.KeyAlgorithmMismatch;
    if (keys.keyTag(key_rdata) != s.key_tag) return error.KeyTagMismatch;
    return key;
}

/// Verifies one RRSIG over one RRset with one DNSKEY. Every check of
/// RFC 4035 §5.3.1 is applied before the signature itself is checked.
pub fn verify(
    a: Allocator,
    set: *const RrSet,
    sig: *const Sig,
    key_owner: *const Name,
    key_rdata: []const u8,
    now: u32,
    skew: u32,
) SigError!void {
    const key = try checkSigAndKey(set, sig, key_owner, key_rdata, now, skew);
    if (!crypto.isSupported(key.algorithm)) return error.UnsupportedAlgorithm;
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const data = try signedData(arena.allocator(), set, sig);
    try crypto.verify(key.algorithm, key.public_key, &.{data}, sig.rrsig.signature);
}

/// TTL to report for a validated RRset (RFC 4035 §5.3.3): no more than the
/// received TTL, the RRSIG's Original TTL, or the time left until this
/// signature stops being acceptable.
///
/// "Stops being acceptable" is the expiration *widened by `skew`*, because
/// `checkTime` accepts a signature for that long. Measuring to the bare
/// expiration instead makes an already-expired signature — one accepted only
/// inside the skew window — wrap to a huge remaining lifetime in RFC 1982
/// arithmetic, so the answer would advertise a cache lifetime of hours while
/// the signature is only good for the seconds of skew left.
pub fn effectiveTtl(set: *const RrSet, sig: *const Sig, now: u32, skew: u32) u32 {
    var ttl = @min(set.ttl, sig.rrsig.original_ttl);
    ttl = @min(ttl, sig.ttl);
    const acceptable_until = sig.rrsig.expiration +% skew;
    const left = acceptable_until -% now;
    // A successful `checkTime` guarantees `left < 2^31`; the zero below is the
    // fail-closed value if this is ever reached with an unacceptable signature.
    if (left < 0x8000_0000) ttl = @min(ttl, left) else ttl = 0;
    return ttl;
}

const testing = std.testing;

test "serial arithmetic and validity windows" {
    try testing.expect(serialLe(1, 2));
    try testing.expect(serialLe(5, 5));
    try testing.expect(!serialLe(2, 1));
    try testing.expect(serialLe(0xFFFF_FFF0, 0x10)); // wrap-around
    try testing.expectEqual(TimeStatus.valid, checkTime(100, 200, 150, 0));
    try testing.expectEqual(TimeStatus.valid, checkTime(100, 200, 100, 0));
    try testing.expectEqual(TimeStatus.valid, checkTime(100, 200, 200, 0));
    try testing.expectEqual(TimeStatus.not_yet_valid, checkTime(100, 200, 99, 0));
    try testing.expectEqual(TimeStatus.expired, checkTime(100, 200, 201, 0));
    try testing.expectEqual(TimeStatus.valid, checkTime(100, 200, 205, 10));
    try testing.expectEqual(TimeStatus.bad_period, checkTime(200, 100, 150, 0));
    try testing.expectEqual(TimeStatus.valid, checkTime(0xFFFF_FF00, 0x100, 0, 0));
}

test "wildcard signing owner" {
    const n = try Name.fromText("a.b.Example.");
    const o = try signingOwner(&n, 2);
    try testing.expect(o.eql(&(try Name.fromText("*.b.example."))));
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("*.b.example.", o.toText(&buf));
    const same = try signingOwner(&n, 3);
    try testing.expectEqualStrings("a.b.example.", same.toText(&buf));
    try testing.expectError(error.BadLabelCount, signingOwner(&n, 4));
}

/// An RRSIG RDATA over A/IN, signed by the root, with a one-octet signature.
/// Only the fields `effectiveTtl` reads are meaningful; the signature itself
/// is never checked here.
fn sigRdata(original_ttl: u32, inception: u32, expiration: u32) [20]u8 {
    var rd: [20]u8 = undefined;
    std.mem.writeInt(u16, rd[0..2], 1, .big); // covers A
    rd[2] = 8; // RSASHA256
    rd[3] = 1; // labels
    std.mem.writeInt(u32, rd[4..8], original_ttl, .big);
    std.mem.writeInt(u32, rd[8..12], expiration, .big);
    std.mem.writeInt(u32, rd[12..16], inception, .big);
    std.mem.writeInt(u16, rd[16..18], 1234, .big);
    rd[18] = 0; // signer = root
    rd[19] = 0xAA;
    return rd;
}

test "effectiveTtl is bounded by the window the signature is actually accepted in" {
    const owner = try Name.fromText("a.");
    const rdatas = [_][]const u8{&.{ 1, 2, 3, 4 }};
    var rd = sigRdata(3600, 1_000, 2_000);
    const sig: Sig = .{ .rrsig = try rdata.Rrsig.parse(&rd), .rdata = &rd, .ttl = 3600 };
    const set: RrSet = .{ .name = owner, .type = .a, .class = .in, .ttl = 3600, .rdatas = &rdatas, .sigs = &.{sig} };

    // checkTime agrees the signature is acceptable at each instant below, so
    // the TTL bound and the validity window cannot disagree.
    try testing.expectEqual(TimeStatus.valid, checkTime(1_000, 2_000, 1_000, 0));
    try testing.expectEqual(@as(u32, 1_000), effectiveTtl(&set, &sig, 1_000, 0));

    // Expired, but accepted because the configured skew still covers it: 50
    // seconds of skew remain. The answer must not outlive that. Measuring to
    // the bare expiration instead made `expiration -% now` wrap to 0xFFFFFFCE,
    // which is >= 2^31, so the bound was skipped and the caller was told the
    // answer was cacheable for the full received TTL of an hour.
    try testing.expectEqual(TimeStatus.valid, checkTime(1_000, 2_000, 2_050, 100));
    try testing.expectEqual(@as(u32, 50), effectiveTtl(&set, &sig, 2_050, 100));

    // The same instant with no skew is simply expired: fail closed at zero
    // rather than at a large TTL.
    try testing.expectEqual(TimeStatus.expired, checkTime(1_000, 2_000, 2_050, 0));
    try testing.expectEqual(@as(u32, 0), effectiveTtl(&set, &sig, 2_050, 0));

    // The received TTL and the RRSIG's Original TTL still cap the result.
    var rd2 = sigRdata(60, 1_000, 2_000);
    const sig2: Sig = .{ .rrsig = try rdata.Rrsig.parse(&rd2), .rdata = &rd2, .ttl = 3600 };
    try testing.expectEqual(@as(u32, 60), effectiveTtl(&set, &sig2, 1_000, 0));

    // Serial wrap-around (RFC 1982): expiry just past 2^32.
    var rd3 = sigRdata(3600, 0xFFFF_FF00, 0x0000_0100);
    const sig3: Sig = .{ .rrsig = try rdata.Rrsig.parse(&rd3), .rdata = &rd3, .ttl = 3600 };
    try testing.expectEqual(TimeStatus.valid, checkTime(0xFFFF_FF00, 0x0000_0100, 0, 0));
    try testing.expectEqual(@as(u32, 0x100), effectiveTtl(&set, &sig3, 0, 0));
}
