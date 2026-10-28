// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! RDATA layouts and typed views.
//!
//! RDATA is stored *uncompressed* once a message has been parsed: names
//! embedded in RDATA are expanded during parsing (only for the types where
//! compression is permitted, RFC 3597 §4). The functions here then work on
//! that uncompressed form: typed parsing with strict length checks, the
//! canonical form for DNSSEC (RFC 4034 §6.2 as corrected by RFC 6840 §5.1),
//! and the name layout used by the message builder.

const std = @import("std");
const name_mod = @import("name.zig");
const types = @import("types.zig");
const Name = name_mod.Name;
const Type = types.Type;

pub const Error = name_mod.Error || error{
    /// RDATA does not match the structure required by its type.
    MalformedRdata,
    /// A compression pointer in RDATA of a type where compression is forbidden.
    CompressionForbidden,
};

/// One element of an RDATA layout.
pub const Field = union(enum) {
    /// A domain name.
    name,
    /// A fixed number of opaque octets.
    fixed: u16,
    /// A <character-string>: one length octet followed by that many octets.
    char_string,
    /// The remainder of the RDATA, opaque (may be empty).
    rest,
};

pub const Layout = struct {
    fields: []const Field,
    /// Whether a receiver may decompress names in this type (RFC 3597 §4:
    /// RFC 1035 well-known types MUST, the listed later types SHOULD).
    decompress: bool,
    /// Whether names are lowercased in canonical form (RFC 4034 §6.2 item 3,
    /// RFC 6840 §5.1).
    lowercase_names: bool,
};

const L = struct {
    const one_name: []const Field = &.{.name};
    const two_names: []const Field = &.{ .name, .name };
    const soa: []const Field = &.{ .name, .name, .{ .fixed = 20 } };
    const pref_name: []const Field = &.{ .{ .fixed = 2 }, .name };
    const px: []const Field = &.{ .{ .fixed = 2 }, .name, .name };
    const srv: []const Field = &.{ .{ .fixed = 6 }, .name };
    const naptr: []const Field = &.{ .{ .fixed = 4 }, .char_string, .char_string, .char_string, .name };
    const rrsig: []const Field = &.{ .{ .fixed = 18 }, .name, .rest };
    const nsec: []const Field = &.{ .name, .rest };
    // RFC 9460 §2.2: SvcPriority (2 octets), TargetName, then the SvcParams
    // (which carry no domain names — §2.4.3 forbids embedding one).
    const svcb: []const Field = &.{ .{ .fixed = 2 }, .name, .rest };
};

/// The layout for types that embed domain names, or null for types whose
/// RDATA contains no names (handled as opaque octets).
pub fn layoutOf(t: Type) ?Layout {
    return switch (t) {
        .ns, .md, .mf, .cname, .mb, .mg, .mr, .ptr => .{ .fields = L.one_name, .decompress = true, .lowercase_names = true },
        .soa => .{ .fields = L.soa, .decompress = true, .lowercase_names = true },
        .minfo => .{ .fields = L.two_names, .decompress = true, .lowercase_names = true },
        .mx => .{ .fields = L.pref_name, .decompress = true, .lowercase_names = true },
        .rp => .{ .fields = L.two_names, .decompress = true, .lowercase_names = true },
        .afsdb, .rt => .{ .fields = L.pref_name, .decompress = true, .lowercase_names = true },
        .kx => .{ .fields = L.pref_name, .decompress = false, .lowercase_names = true },
        .px => .{ .fields = L.px, .decompress = true, .lowercase_names = true },
        .srv => .{ .fields = L.srv, .decompress = true, .lowercase_names = true },
        .naptr => .{ .fields = L.naptr, .decompress = true, .lowercase_names = true },
        .sig => .{ .fields = L.rrsig, .decompress = true, .lowercase_names = true },
        .nxt => .{ .fields = L.nsec, .decompress = true, .lowercase_names = true },
        .dname => .{ .fields = L.one_name, .decompress = false, .lowercase_names = true },
        .rrsig => .{ .fields = L.rrsig, .decompress = false, .lowercase_names = true },
        // RFC 6840 §5.1: NSEC next-domain names are NOT lowercased.
        .nsec => .{ .fields = L.nsec, .decompress = false, .lowercase_names = false },
        // RFC 9460 §2.4.2: the SVCB/HTTPS TargetName MUST NOT be compressed.
        // It is still a domain name, so DNSSEC canonical form lowercases it
        // (RFC 4034 §6.2). Treating these types as opaque made a valid
        // signature over a TargetName with any uppercase ASCII fail.
        .svcb, .https => .{ .fields = L.svcb, .decompress = false, .lowercase_names = true },
        else => null,
    };
}

/// Types whose names may be compressed by a *sender* (RFC 3597 §4: only
/// the RFC 1035 well-known types).
pub fn senderMayCompress(t: Type) bool {
    return switch (t) {
        .ns, .md, .mf, .cname, .soa, .mb, .mg, .mr, .ptr, .minfo, .mx => true,
        else => false,
    };
}

/// Expands the RDATA at `msg[start..start+rdlen]` into `out`, decompressing
/// names when the type allows it and rejecting pointers where it does not.
/// Returns the uncompressed RDATA slice of `out`.
pub fn expand(msg: []const u8, start: usize, rdlen: usize, t: Type, out: []u8) Error![]u8 {
    const end = start + rdlen;
    if (end > msg.len) return error.Truncated;
    const layout = layoutOf(t) orelse {
        if (rdlen > out.len) return error.MalformedRdata;
        @memcpy(out[0..rdlen], msg[start..end]);
        return out[0..rdlen];
    };
    var p = start;
    var o: usize = 0;
    for (layout.fields) |f| {
        switch (f) {
            .name => {
                if (p >= end) return error.MalformedRdata;
                // Names must not run past the RDATA. Parse within the full
                // message (so pointers resolve) but check the in-RDATA extent.
                const n = if (layout.decompress)
                    try Name.readFromMessage(msg[0..end], &p)
                else
                    Name.readUncompressed(msg[0..end], &p) catch |e| switch (e) {
                        error.BadPointer => return error.CompressionForbidden,
                        else => return e,
                    };
                if (p > end) return error.MalformedRdata;
                if (o + n.len > out.len) return error.MalformedRdata;
                @memcpy(out[o..][0..n.len], n.bytes());
                o += n.len;
            },
            .fixed => |k| {
                if (p + k > end) return error.MalformedRdata;
                if (o + k > out.len) return error.MalformedRdata;
                @memcpy(out[o..][0..k], msg[p..][0..k]);
                o += k;
                p += k;
            },
            .char_string => {
                if (p >= end) return error.MalformedRdata;
                const k: usize = 1 + @as(usize, msg[p]);
                if (p + k > end) return error.MalformedRdata;
                if (o + k > out.len) return error.MalformedRdata;
                @memcpy(out[o..][0..k], msg[p..][0..k]);
                o += k;
                p += k;
            },
            .rest => {
                const k = end - p;
                if (o + k > out.len) return error.MalformedRdata;
                @memcpy(out[o..][0..k], msg[p..end]);
                o += k;
                p = end;
            },
        }
    }
    if (p != end) return error.MalformedRdata;
    return out[0..o];
}

/// Writes the canonical form of uncompressed RDATA (names lowercased for the
/// RFC 4034 §6.2 / RFC 6840 §5.1 types) into `out`. `out.len` must be at
/// least `rdata.len`. The RDATA must already have passed `validate`.
pub fn canonicalize(t: Type, rdata: []const u8, out: []u8) Error![]u8 {
    std.debug.assert(out.len >= rdata.len);
    @memcpy(out[0..rdata.len], rdata);
    const layout = layoutOf(t) orelse return out[0..rdata.len];
    if (!layout.lowercase_names) return out[0..rdata.len];
    var p: usize = 0;
    for (layout.fields) |f| {
        switch (f) {
            .name => {
                const start = p;
                const n = try Name.readUncompressed(rdata, &p);
                const lc = n.lowercase();
                @memcpy(out[start..][0..lc.len], lc.bytes());
            },
            .fixed => |k| p += k,
            .char_string => p += 1 + @as(usize, rdata[p]),
            .rest => p = rdata.len,
        }
    }
    return out[0..rdata.len];
}

/// Structural validation of uncompressed RDATA for the types this library
/// interprets. Unknown types are accepted as opaque.
pub fn validate(t: Type, rdata: []const u8) Error!void {
    switch (t) {
        .a => if (rdata.len != 4) return error.MalformedRdata,
        .aaaa => if (rdata.len != 16) return error.MalformedRdata,
        .txt => {
            if (rdata.len == 0) return error.MalformedRdata;
            var p: usize = 0;
            while (p < rdata.len) p += 1 + @as(usize, rdata[p]);
            if (p != rdata.len) return error.MalformedRdata;
        },
        .dnskey, .cdnskey => _ = try Dnskey.parse(rdata),
        .ds, .cds => _ = try Ds.parse(rdata),
        .rrsig => _ = try Rrsig.parse(rdata),
        .nsec => _ = try Nsec.parse(rdata),
        .nsec3 => _ = try Nsec3.parse(rdata),
        .nsec3param => _ = try Nsec3Param.parse(rdata),
        .opt => try validateOptions(rdata),
        else => if (layoutOf(t)) |layout| {
            var p: usize = 0;
            for (layout.fields) |f| switch (f) {
                .name => _ = try Name.readUncompressed(rdata, &p),
                .fixed => |k| {
                    if (p + k > rdata.len) return error.MalformedRdata;
                    p += k;
                },
                .char_string => {
                    if (p >= rdata.len) return error.MalformedRdata;
                    p += 1 + @as(usize, rdata[p]);
                    if (p > rdata.len) return error.MalformedRdata;
                },
                .rest => p = rdata.len,
            };
            if (p != rdata.len) return error.MalformedRdata;
        },
    }
}

fn validateOptions(rdata: []const u8) Error!void {
    var p: usize = 0;
    while (p < rdata.len) {
        if (p + 4 > rdata.len) return error.MalformedRdata;
        const len = std.mem.readInt(u16, rdata[p + 2 ..][0..2], .big);
        p += 4 + @as(usize, len);
        if (p > rdata.len) return error.MalformedRdata;
    }
}

fn be16(b: []const u8) u16 {
    return std.mem.readInt(u16, b[0..2], .big);
}
fn be32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .big);
}

/// The single name in NS/CNAME/DNAME/PTR RDATA.
pub fn singleName(rdata: []const u8) Error!Name {
    return Name.fromWire(rdata) catch return error.MalformedRdata;
}

pub const Soa = struct {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,

    pub fn parse(rdata: []const u8) Error!Soa {
        var p: usize = 0;
        const m = try Name.readUncompressed(rdata, &p);
        const r = try Name.readUncompressed(rdata, &p);
        if (rdata.len - p != 20) return error.MalformedRdata;
        const f = rdata[p..];
        return .{
            .mname = m,
            .rname = r,
            .serial = be32(f[0..]),
            .refresh = be32(f[4..]),
            .retry = be32(f[8..]),
            .expire = be32(f[12..]),
            .minimum = be32(f[16..]),
        };
    }
};

/// DNSKEY (RFC 4034 §2.1).
pub const Dnskey = struct {
    flags: u16,
    protocol: u8,
    algorithm: types.Algorithm,
    public_key: []const u8,

    pub const flag_zone: u16 = 0x0100; // bit 7
    pub const flag_revoke: u16 = 0x0080; // bit 8 (RFC 5011)
    pub const flag_sep: u16 = 0x0001; // bit 15

    pub fn parse(rdata: []const u8) Error!Dnskey {
        if (rdata.len < 5) return error.MalformedRdata;
        return .{
            .flags = be16(rdata[0..]),
            .protocol = rdata[2],
            .algorithm = @fromBackingInt(@intCast(rdata[3])),
            .public_key = rdata[4..],
        };
    }

    pub fn isZoneKey(k: Dnskey) bool {
        return k.flags & flag_zone != 0;
    }
    pub fn isRevoked(k: Dnskey) bool {
        return k.flags & flag_revoke != 0;
    }
};

/// DS (RFC 4034 §5.1).
pub const Ds = struct {
    key_tag: u16,
    algorithm: types.Algorithm,
    digest_type: types.DigestType,
    digest: []const u8,

    pub fn parse(rdata: []const u8) Error!Ds {
        if (rdata.len < 5) return error.MalformedRdata;
        const d: Ds = .{
            .key_tag = be16(rdata[0..]),
            .algorithm = @fromBackingInt(@intCast(rdata[2])),
            .digest_type = @fromBackingInt(@intCast(rdata[3])),
            .digest = rdata[4..],
        };
        if (digestLength(d.digest_type)) |len| {
            if (d.digest.len != len) return error.MalformedRdata;
        }
        return d;
    }
};

pub fn digestLength(dt: types.DigestType) ?usize {
    return switch (dt) {
        .sha1 => 20,
        .sha256 => 32,
        .sha384 => 48,
        .gost94 => 32,
        else => null,
    };
}

/// RRSIG (RFC 4034 §3.1).
pub const Rrsig = struct {
    type_covered: Type,
    algorithm: types.Algorithm,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer: Name,
    signature: []const u8,
    /// RDATA up to and including the signer's name (the part that is
    /// itself covered by the signature, RFC 4034 §3.1.8.1).
    signed_prefix: []const u8,

    pub fn parse(rdata: []const u8) Error!Rrsig {
        if (rdata.len < 18 + 1 + 1) return error.MalformedRdata;
        var p: usize = 18;
        const signer = Name.readUncompressed(rdata, &p) catch |e| switch (e) {
            error.BadPointer => return error.CompressionForbidden,
            error.Truncated => return error.MalformedRdata,
            else => return e,
        };
        if (p >= rdata.len) return error.MalformedRdata; // empty signature
        return .{
            .type_covered = @fromBackingInt(@intCast(be16(rdata[0..]))),
            .algorithm = @fromBackingInt(@intCast(rdata[2])),
            .labels = rdata[3],
            .original_ttl = be32(rdata[4..]),
            .expiration = be32(rdata[8..]),
            .inception = be32(rdata[12..]),
            .key_tag = be16(rdata[16..]),
            .signer = signer,
            .signature = rdata[p..],
            .signed_prefix = rdata[0..p],
        };
    }
};

/// A validated NSEC/NSEC3 type bitmap (RFC 4034 §4.1.2).
pub const TypeBitmap = struct {
    raw: []const u8,

    /// Windows must appear in strictly increasing order with bitmap lengths
    /// of 1..32 octets. Trailing zero octets (a sender MUST NOT) are
    /// tolerated because they introduce no ambiguity; ordering and length
    /// violations are rejected because they do.
    pub fn parse(raw: []const u8) Error!TypeBitmap {
        var p: usize = 0;
        var last_window: i16 = -1;
        while (p < raw.len) {
            if (p + 2 > raw.len) return error.MalformedRdata;
            const window = raw[p];
            const len = raw[p + 1];
            if (@as(i16, window) <= last_window) return error.MalformedRdata;
            if (len == 0 or len > 32) return error.MalformedRdata;
            if (p + 2 + len > raw.len) return error.MalformedRdata;
            last_window = window;
            p += 2 + @as(usize, len);
        }
        return .{ .raw = raw };
    }

    pub fn has(self: TypeBitmap, t: Type) bool {
        const v = t.toInt();
        const window: u8 = @intCast(v >> 8);
        const bit: u8 = @intCast(v & 0xFF);
        var p: usize = 0;
        while (p + 2 <= self.raw.len) {
            const w = self.raw[p];
            const len = self.raw[p + 1];
            if (w == window) {
                const octet = bit / 8;
                if (octet >= len) return false;
                return (self.raw[p + 2 + octet] & (@as(u8, 0x80) >> @intCast(bit % 8))) != 0;
            }
            if (w > window) return false;
            p += 2 + @as(usize, len);
        }
        return false;
    }

    pub fn isEmpty(self: TypeBitmap) bool {
        var p: usize = 0;
        while (p + 2 <= self.raw.len) {
            const len = self.raw[p + 1];
            for (self.raw[p + 2 ..][0..len]) |b| if (b != 0) return false;
            p += 2 + @as(usize, len);
        }
        return true;
    }
};

/// NSEC (RFC 4034 §4.1).
pub const Nsec = struct {
    next: Name,
    types: TypeBitmap,

    pub fn parse(rdata: []const u8) Error!Nsec {
        var p: usize = 0;
        const next = Name.readUncompressed(rdata, &p) catch |e| switch (e) {
            error.BadPointer => return error.CompressionForbidden,
            error.Truncated => return error.MalformedRdata,
            else => return e,
        };
        return .{ .next = next, .types = try TypeBitmap.parse(rdata[p..]) };
    }
};

/// NSEC3 (RFC 5155 §3.2).
pub const Nsec3 = struct {
    hash_algorithm: types.Nsec3HashAlgorithm,
    flags: u8,
    iterations: u16,
    salt: []const u8,
    next_hashed_owner: []const u8,
    types: TypeBitmap,

    pub const flag_opt_out: u8 = 0x01;

    pub fn parse(rdata: []const u8) Error!Nsec3 {
        if (rdata.len < 5) return error.MalformedRdata;
        const salt_len: usize = rdata[4];
        var p: usize = 5;
        if (p + salt_len + 1 > rdata.len) return error.MalformedRdata;
        const salt = rdata[p..][0..salt_len];
        p += salt_len;
        const hash_len: usize = rdata[p];
        p += 1;
        if (hash_len == 0) return error.MalformedRdata;
        if (p + hash_len > rdata.len) return error.MalformedRdata;
        const next = rdata[p..][0..hash_len];
        p += hash_len;
        const ha: types.Nsec3HashAlgorithm = @fromBackingInt(@intCast(rdata[0]));
        if (ha == .sha1 and hash_len != 20) return error.MalformedRdata;
        return .{
            .hash_algorithm = ha,
            .flags = rdata[1],
            .iterations = be16(rdata[2..]),
            .salt = salt,
            .next_hashed_owner = next,
            .types = try TypeBitmap.parse(rdata[p..]),
        };
    }

    pub fn optOut(self: Nsec3) bool {
        return self.flags & flag_opt_out != 0;
    }
};

/// NSEC3PARAM (RFC 5155 §4.2).
pub const Nsec3Param = struct {
    hash_algorithm: types.Nsec3HashAlgorithm,
    flags: u8,
    iterations: u16,
    salt: []const u8,

    pub fn parse(rdata: []const u8) Error!Nsec3Param {
        if (rdata.len < 5) return error.MalformedRdata;
        const salt_len: usize = rdata[4];
        if (rdata.len != 5 + salt_len) return error.MalformedRdata;
        return .{
            .hash_algorithm = @fromBackingInt(@intCast(rdata[0])),
            .flags = rdata[1],
            .iterations = be16(rdata[2..]),
            .salt = rdata[5..],
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "type bitmap: RFC 4034 §4.3 example (A MX RRSIG NSEC TYPE1234)" {
    const bm = [_]u8{
        0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03,
        0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20,
    };
    const tb = try TypeBitmap.parse(&bm);
    try testing.expect(tb.has(.a));
    try testing.expect(tb.has(.mx));
    try testing.expect(tb.has(.rrsig));
    try testing.expect(tb.has(.nsec));
    try testing.expect(tb.has(Type.fromInt(1234)));
    try testing.expect(!tb.has(.ns));
    try testing.expect(!tb.has(.aaaa));
    try testing.expect(!tb.has(Type.fromInt(1235)));
    try testing.expect(!tb.has(Type.fromInt(65535)));
    try testing.expect(!tb.isEmpty());
}

test "type bitmap rejects disorder and bad lengths" {
    try testing.expectError(error.MalformedRdata, TypeBitmap.parse(&.{ 1, 1, 0x40, 0, 1, 0x40 }));
    try testing.expectError(error.MalformedRdata, TypeBitmap.parse(&.{ 0, 1, 0x40, 0, 1, 0x40 }));
    try testing.expectError(error.MalformedRdata, TypeBitmap.parse(&.{ 0, 0 }));
    try testing.expectError(error.MalformedRdata, TypeBitmap.parse(&([_]u8{ 0, 33 } ++ @as([33]u8, @splat(0)))));
    try testing.expectError(error.MalformedRdata, TypeBitmap.parse(&.{ 0, 4, 1 }));
    try testing.expectError(error.MalformedRdata, TypeBitmap.parse(&.{0}));
    const empty = try TypeBitmap.parse(&.{});
    try testing.expect(empty.isEmpty());
}

test "NSEC3 parse bounds" {
    // alg 1, flags 1, iter 12, salt aabbccdd, hash len 20, bitmap A RRSIG
    var rd: [5 + 4 + 1 + 20 + 8]u8 = undefined;
    rd[0] = 1;
    rd[1] = 1;
    rd[2] = 0;
    rd[3] = 12;
    rd[4] = 4;
    @memcpy(rd[5..9], &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd });
    rd[9] = 20;
    @memset(rd[10..30], 0x11);
    @memcpy(rd[30..38], &[_]u8{ 0, 6, 0x40, 0, 0, 0, 0, 0x02 });
    const n = try Nsec3.parse(&rd);
    try testing.expect(n.optOut());
    try testing.expectEqual(@as(u16, 12), n.iterations);
    try testing.expect(n.types.has(.a));
    try testing.expect(n.types.has(.rrsig));
    // Truncations at every length must fail cleanly.
    for (0..rd.len - 8) |k| {
        if (Nsec3.parse(rd[0..k])) |_| return error.TestUnexpectedResult else |_| {}
    }
    // SHA-1 with wrong hash length.
    var bad = rd;
    bad[9] = 19;
    try testing.expectError(error.MalformedRdata, Nsec3.parse(&bad));
}

test "RRSIG signer must not be compressed" {
    var rd = @as([18]u8, @splat(0)) ++ [_]u8{ 0xC0, 0x0C, 1, 2, 3 };
    try testing.expectError(error.CompressionForbidden, Rrsig.parse(&rd));
    var ok = @as([18]u8, @splat(0)) ++ [_]u8{ 0, 0xAB };
    const s = try Rrsig.parse(&ok);
    try testing.expect(s.signer.isRoot());
    try testing.expectEqual(@as(usize, 1), s.signature.len);
    var nosig = @as([18]u8, @splat(0)) ++ [_]u8{0};
    try testing.expectError(error.MalformedRdata, Rrsig.parse(&nosig));
}

test "DS digest length enforced for known digest types" {
    var rd = [_]u8{ 0, 1, 8, 2 } ++ @as([31]u8, @splat(0));
    try testing.expectError(error.MalformedRdata, Ds.parse(&rd));
    var rd2 = [_]u8{ 0, 1, 8, 2 } ++ @as([32]u8, @splat(0));
    _ = try Ds.parse(&rd2);
    var rd3 = [_]u8{ 0, 1, 8, 99 } ++ @as([3]u8, @splat(0));
    _ = try Ds.parse(&rd3);
}

test "canonicalize lowercases RRSIG signer but not NSEC next name" {
    var rr = @as([18]u8, @splat(0)) ++ [_]u8{ 2, 'E', 'x', 0, 0xAA };
    var out: [rr.len]u8 = undefined;
    const c = try canonicalize(.rrsig, &rr, &out);
    try testing.expectEqualSlices(u8, &(@as([18]u8, @splat(0)) ++ [_]u8{ 2, 'e', 'x', 0, 0xAA }), c);
    var ns = [_]u8{ 2, 'E', 'x', 0, 0, 1, 0x40 };
    var out2: [ns.len]u8 = undefined;
    const c2 = try canonicalize(.nsec, &ns, &out2);
    try testing.expectEqualSlices(u8, &ns, c2);
    var mx = [_]u8{ 0, 10, 2, 'M', 'X', 0 };
    var out3: [mx.len]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 10, 2, 'm', 'x', 0 }, try canonicalize(.mx, &mx, &out3));
}

test "canonicalize lowercases the SVCB and HTTPS TargetName" {
    // RFC 9460 §2.2: SvcPriority (2), TargetName, SvcParams. The TargetName is
    // a domain name, so RFC 4034 §6.2 puts it in lowercase canonical form;
    // treating the whole RDATA as opaque made a valid signature over an
    // uppercase TargetName fail to verify.
    //   1 SVCB.EXAMPLE. alpn="h2,h3"
    const rd = [_]u8{
        0x00, 0x01, //  SvcPriority 1 (ServiceMode)
        0x04, 'S',
        'V',  'C',
        'B',  0x07,
        'E',  'X',
        'A',  'M',
        'P',  'L',
        'E',
        0x00, //      root label
        0x00, 0x01, 0x00, 0x06, 'h', '2', ',', 'h', '3', // alpn
    };
    var out: [rd.len]u8 = undefined;
    const want = [_]u8{
        0x00, 0x01,
        0x04, 's',
        'v',  'c',
        'b',  0x07,
        'e',  'x',
        'a',  'm',
        'p',  'l',
        'e',  0x00,
        0x00, 0x01,
        0x00, 0x06,
        'h',  '2',
        ',',  'h',
        '3',
    };
    try testing.expectEqualSlices(u8, &want, try canonicalize(.svcb, &rd, &out));
    try testing.expectEqualSlices(u8, &want, try canonicalize(.https, &rd, &out));
    // Only the name is touched: the SvcParams after it (16 octets in) are
    // opaque and keep their case, so an alpn value is not corrupted.
    try testing.expectEqualSlices(u8, rd[16..], out[16..]);

    // AliasMode ("1 a." with no parameters): the target is still lowercased.
    const alias = [_]u8{ 0x00, 0x01, 0x01, 'A', 0x00 };
    var out2: [alias.len]u8 = undefined;
    try validate(.svcb, &alias);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x01, 'a', 0x00 }, try canonicalize(.svcb, &alias, &out2));
    // Priority octets alone, with no TargetName, are not a valid SVCB.
    try testing.expectError(error.Truncated, validate(.svcb, &[_]u8{ 0x00, 0x01 }));
    // Fewer than the two priority octets.
    try testing.expectError(error.MalformedRdata, validate(.https, &[_]u8{0x00}));

    // RFC 9460 §2.4.2: the TargetName MUST NOT be compressed.
    const compressed = [_]u8{ 0x00, 0x01, 0xC0, 0x0C };
    var buf: [64]u8 = undefined;
    try testing.expectError(error.CompressionForbidden, expand(&compressed, 0, compressed.len, .svcb, &buf));
    // Uncompressed, `expand` round-trips it unchanged.
    var buf2: [rd.len]u8 = undefined;
    try testing.expectEqualSlices(u8, &rd, try expand(&rd, 0, rd.len, .https, &buf2));
}
