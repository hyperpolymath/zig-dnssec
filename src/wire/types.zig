// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Numeric registries used on the wire: RR types, classes, opcodes, rcodes,
//! DNSSEC algorithm and digest numbers.

const std = @import("std");

/// RR TYPE (RFC 1035 §3.2.2 and later). Non-exhaustive: unknown types are
/// carried opaquely (RFC 3597).
pub const Type = enum(u16) {
    a = 1,
    ns = 2,
    md = 3,
    mf = 4,
    cname = 5,
    soa = 6,
    mb = 7,
    mg = 8,
    mr = 9,
    null = 10,
    wks = 11,
    ptr = 12,
    hinfo = 13,
    minfo = 14,
    mx = 15,
    txt = 16,
    rp = 17,
    afsdb = 18,
    rt = 21,
    sig = 24,
    key = 25,
    px = 26,
    aaaa = 28,
    nxt = 30,
    srv = 33,
    naptr = 35,
    kx = 36,
    a6 = 38,
    dname = 39,
    opt = 41,
    ds = 43,
    rrsig = 46,
    nsec = 47,
    dnskey = 48,
    nsec3 = 50,
    nsec3param = 51,
    tlsa = 52,
    cds = 59,
    cdnskey = 60,
    svcb = 64,
    https = 65,
    tsig = 250,
    ixfr = 251,
    axfr = 252,
    any = 255,
    caa = 257,
    _,

    pub fn fromInt(v: u16) Type {
        return @enumFromInt(v);
    }

    pub fn toInt(t: Type) u16 {
        return @intFromEnum(t);
    }

    /// Meta-types and QTYPE-only values (RFC 6895 §3.1) never appear as data.
    pub fn isMetaOrQtype(t: Type) bool {
        const v = t.toInt();
        return v == 41 or (v >= 128 and v <= 255);
    }

    /// Mnemonic for presentation; unknown types render as TYPEnnn.
    pub fn mnemonic(t: Type, buf: []u8) []const u8 {
        if (std.enums.tagName(Type, t)) |tag| {
            const n = @min(buf.len, tag.len);
            return std.ascii.upperString(buf[0..n], tag[0..n]);
        }
        return std.fmt.bufPrint(buf, "TYPE{d}", .{@intFromEnum(t)}) catch buf[0..0];
    }

    pub fn fromMnemonic(text: []const u8) ?Type {
        var lower: [16]u8 = undefined;
        if (text.len <= lower.len) {
            if (std.meta.stringToEnum(Type, std.ascii.lowerString(&lower, text))) |t| return t;
        }
        if (text.len > 4 and std.ascii.eqlIgnoreCase(text[0..4], "TYPE")) {
            const v = std.fmt.parseInt(u16, text[4..], 10) catch return null;
            return @enumFromInt(v);
        }
        return null;
    }
};

pub const Class = enum(u16) {
    in = 1,
    ch = 3,
    hs = 4,
    none = 254,
    any = 255,
    _,

    pub fn toInt(c: Class) u16 {
        return @intFromEnum(c);
    }
};

pub const Opcode = enum(u4) {
    query = 0,
    iquery = 1,
    status = 2,
    notify = 4,
    update = 5,
    _,
};

pub const Rcode = enum(u12) {
    noerror = 0,
    formerr = 1,
    servfail = 2,
    nxdomain = 3,
    notimp = 4,
    refused = 5,
    yxdomain = 6,
    yxrrset = 7,
    nxrrset = 8,
    notauth = 9,
    notzone = 10,
    badvers = 16,
    _,
};

/// DNS Security Algorithm Numbers (IANA registry, RFC 9904 columns).
pub const Algorithm = enum(u8) {
    rsamd5 = 1,
    dh = 2,
    dsa = 3,
    rsasha1 = 5,
    dsa_nsec3_sha1 = 6,
    rsasha1_nsec3_sha1 = 7,
    rsasha256 = 8,
    rsasha512 = 10,
    ecc_gost = 12,
    ecdsap256sha256 = 13,
    ecdsap384sha384 = 14,
    ed25519 = 15,
    ed448 = 16,
    sm2sm3 = 17,
    ecc_gost12 = 23,
    indirect = 252,
    privatedns = 253,
    privateoid = 254,
    _,
};

/// DS digest types.
pub const DigestType = enum(u8) {
    sha1 = 1,
    sha256 = 2,
    gost94 = 3,
    sha384 = 4,
    gost2012 = 5,
    sm3 = 6,
    _,
};

/// NSEC3 hash algorithms (RFC 5155 §11).
pub const Nsec3HashAlgorithm = enum(u8) {
    sha1 = 1,
    _,
};

test "type mnemonic round trip" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("RRSIG", Type.rrsig.mnemonic(&buf));
    try std.testing.expectEqualStrings("TYPE65280", Type.fromInt(65280).mnemonic(&buf));
    try std.testing.expectEqual(Type.nsec3param, Type.fromMnemonic("nsec3param").?);
    try std.testing.expectEqual(Type.fromInt(65280), Type.fromMnemonic("TYPE65280").?);
    try std.testing.expect(Type.fromMnemonic("BOGUS") == null);
}
