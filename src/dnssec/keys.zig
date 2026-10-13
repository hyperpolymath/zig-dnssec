// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! DNSKEY key tags (RFC 4034 Appendix B) and DS digests (RFC 4034 §5.1.4,
//! RFC 4509, RFC 6605 §2).

const std = @import("std");
const wire_name = @import("../wire/name.zig");
const types = @import("../wire/types.zig");
const rdata = @import("../wire/rdata.zig");

const Name = wire_name.Name;

/// RFC 4034 Appendix B key tag over complete DNSKEY RDATA.
pub fn keyTag(dnskey_rdata: []const u8) u16 {
    if (dnskey_rdata.len >= 4 and dnskey_rdata[3] == @intFromEnum(types.Algorithm.rsamd5)) {
        // Appendix B.1: the most significant 16 of the least significant
        // 24 bits of the modulus.
        if (dnskey_rdata.len < 7) return 0;
        const n = dnskey_rdata.len;
        return std.mem.readInt(u16, dnskey_rdata[n - 3 ..][0..2], .big);
    }
    var ac: u32 = 0;
    for (dnskey_rdata, 0..) |b, i| {
        ac += if (i & 1 != 0) b else @as(u32, b) << 8;
    }
    ac += (ac >> 16) & 0xFFFF;
    return @truncate(ac);
}

pub fn digestSupported(dt: types.DigestType) bool {
    return switch (dt) {
        .sha1, .sha256, .sha384 => true,
        else => false,
    };
}

/// Computes the DS digest of `owner` (canonicalised) and the DNSKEY RDATA.
/// Returns the digest length written to `out`, or null if unsupported.
pub fn dsDigest(dt: types.DigestType, owner: *const Name, dnskey_rdata: []const u8, out: *[64]u8) ?usize {
    const lc = owner.lowercase();
    switch (dt) {
        .sha1 => {
            var h = std.crypto.hash.Sha1.init(.{});
            h.update(lc.bytes());
            h.update(dnskey_rdata);
            h.final(out[0..20]);
            return 20;
        },
        .sha256 => {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(lc.bytes());
            h.update(dnskey_rdata);
            h.final(out[0..32]);
            return 32;
        },
        .sha384 => {
            var h = std.crypto.hash.sha2.Sha384.init(.{});
            h.update(lc.bytes());
            h.update(dnskey_rdata);
            h.final(out[0..48]);
            return 48;
        },
        else => return null,
    }
}

pub const DsMatch = enum { match, mismatch, unsupported_digest };

/// Does `ds` (parsed DS RDATA) authenticate the DNSKEY `dnskey_rdata` at
/// `owner`? Compares key tag, algorithm and digest.
pub fn dsMatches(ds: rdata.Ds, owner: *const Name, dnskey_rdata: []const u8) DsMatch {
    const key = rdata.Dnskey.parse(dnskey_rdata) catch return .mismatch;
    if (key.algorithm != ds.algorithm) return .mismatch;
    if (keyTag(dnskey_rdata) != ds.key_tag) return .mismatch;
    var buf: [64]u8 = undefined;
    const n = dsDigest(ds.digest_type, owner, dnskey_rdata, &buf) orelse return .unsupported_digest;
    if (n != ds.digest.len) return .mismatch;
    return if (std.mem.eql(u8, buf[0..n], ds.digest)) .match else .mismatch;
}
