// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Text encodings used by DNSSEC presentation formats: Base32hex without
//! padding (RFC 4648 §7, as used for NSEC3 owner labels, RFC 5155 §3.3),
//! Base64 and hex.

const std = @import("std");

pub const Error = error{InvalidEncoding};

const b32hex_alphabet = "0123456789abcdefghijklmnopqrstuv";

pub fn base32HexEncodedLen(n: usize) usize {
    return (n * 8 + 4) / 5;
}

/// Lowercase Base32hex without padding.
pub fn base32HexEncode(out: []u8, in: []const u8) []u8 {
    const len = base32HexEncodedLen(in.len);
    std.debug.assert(out.len >= len);
    var acc: u16 = 0;
    var bits: u4 = 0;
    var o: usize = 0;
    for (in) |byte| {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[o] = b32hex_alphabet[(acc >> bits) & 0x1F];
            o += 1;
        }
    }
    if (bits > 0) {
        out[o] = b32hex_alphabet[(acc << (5 - bits)) & 0x1F];
        o += 1;
    }
    return out[0..o];
}

fn b32val(c: u8) ?u5 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'v' => @intCast(c - 'a' + 10),
        'A'...'V' => @intCast(c - 'A' + 10),
        else => null,
    };
}

/// Decodes unpadded Base32hex (either case). Rejects non-zero trailing bits
/// and impossible lengths so that each byte string has exactly one encoding.
pub fn base32HexDecode(out: []u8, in: []const u8) Error![]u8 {
    switch (in.len % 8) {
        0, 2, 4, 5, 7 => {},
        else => return error.InvalidEncoding,
    }
    var acc: u16 = 0;
    var bits: u5 = 0;
    var o: usize = 0;
    for (in) |c| {
        const v = b32val(c) orelse return error.InvalidEncoding;
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out.len) return error.InvalidEncoding;
            const sh: u4 = @intCast(bits);
            out[o] = @truncate(acc >> sh);
            o += 1;
            acc &= (@as(u16, 1) << sh) - 1;
        }
    }
    if (acc != 0) return error.InvalidEncoding;
    return out[0..o];
}

pub fn hexDecode(out: []u8, in: []const u8) Error![]u8 {
    if (in.len % 2 != 0 or out.len < in.len / 2) return error.InvalidEncoding;
    return std.fmt.hexToBytes(out[0 .. in.len / 2], in) catch error.InvalidEncoding;
}

pub fn base64Decode(gpa: std.mem.Allocator, in: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(in) catch return error.InvalidEncoding;
    const out = try gpa.alloc(u8, n);
    errdefer gpa.free(out);
    dec.decode(out, in) catch return error.InvalidEncoding;
    return out;
}

const testing = std.testing;

test "base32hex RFC 4648 §10 vectors (lowercase, unpadded)" {
    const cases = [_][2][]const u8{
        .{ "", "" },
        .{ "f", "co" },
        .{ "fo", "cpng" },
        .{ "foo", "cpnmu" },
        .{ "foob", "cpnmuog" },
        .{ "fooba", "cpnmuoj1" },
        .{ "foobar", "cpnmuoj1e8" },
    };
    for (cases) |c| {
        var buf: [32]u8 = undefined;
        try testing.expectEqualStrings(c[1], base32HexEncode(&buf, c[0]));
        var dec: [32]u8 = undefined;
        try testing.expectEqualStrings(c[0], try base32HexDecode(&dec, c[1]));
        var upper: [32]u8 = undefined;
        const u = std.ascii.upperString(upper[0..c[1].len], c[1]);
        try testing.expectEqualStrings(c[0], try base32HexDecode(&dec, u));
    }
}

test "base32hex rejects bad input" {
    var dec: [32]u8 = undefined;
    try testing.expectError(error.InvalidEncoding, base32HexDecode(&dec, "c"));
    try testing.expectError(error.InvalidEncoding, base32HexDecode(&dec, "cpn"));
    try testing.expectError(error.InvalidEncoding, base32HexDecode(&dec, "cw"));
    try testing.expectError(error.InvalidEncoding, base32HexDecode(&dec, "cp")); // non-zero pad bits
    try testing.expectError(error.InvalidEncoding, base32HexDecode(&dec, "c="));
}
