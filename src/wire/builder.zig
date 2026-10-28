// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! DNS message encoding with name compression (RFC 1035 §4.1.4).
//!
//! Owner names and question names are always compressible. Names inside
//! RDATA are compressed only for the RFC 1035 well-known types
//! (RFC 3597 §4); every other type is written uncompressed. Pointers are only
//! ever emitted to names this builder wrote earlier, so they always point
//! backwards.

const std = @import("std");
const name_mod = @import("name.zig");
const types = @import("types.zig");
const rdata_mod = @import("rdata.zig");
const message = @import("message.zig");

const Name = name_mod.Name;
const Type = types.Type;

pub const Error = error{
    /// The output buffer (or the 65535-octet message limit) is exhausted.
    NoSpace,
    /// Records added out of section order.
    SectionOrder,
    /// RDATA that does not match its type's layout.
    MalformedRdata,
};

const max_compression_entries = 256;

pub const Builder = struct {
    buf: []u8,
    len: usize,
    header: message.Header,
    stage: Stage = .question,
    counts: [4]u16 = .{ 0, 0, 0, 0 },
    comp: [max_compression_entries]u16 = undefined,
    comp_len: usize = 0,

    const Stage = enum(u2) { question = 0, answer = 1, authority = 2, additional = 3 };

    pub fn init(buf: []u8, header: message.Header) Error!Builder {
        if (buf.len < message.header_len) return error.NoSpace;
        const cap = @min(buf.len, message.max_message_len);
        return .{ .buf = buf[0..cap], .len = message.header_len, .header = header };
    }

    fn advance(b: *Builder, to: Stage) Error!void {
        if (@backingInt(to) < @backingInt(b.stage)) return error.SectionOrder;
        b.stage = to;
    }

    fn put(b: *Builder, bytes: []const u8) Error!void {
        if (b.len + bytes.len > b.buf.len) return error.NoSpace;
        @memcpy(b.buf[b.len..][0..bytes.len], bytes);
        b.len += bytes.len;
    }

    fn put16(b: *Builder, v: u16) Error!void {
        var t: [2]u8 = undefined;
        std.mem.writeInt(u16, &t, v, .big);
        try b.put(&t);
    }

    fn put32(b: *Builder, v: u32) Error!void {
        var t: [4]u8 = undefined;
        std.mem.writeInt(u32, &t, v, .big);
        try b.put(&t);
    }

    /// Finds an earlier occurrence of exactly `suffix` (byte-exact, so case
    /// is preserved) and returns its offset.
    fn findSuffix(b: *const Builder, suffix: []const u8) ?u16 {
        for (b.comp[0..b.comp_len]) |off| {
            var p: usize = off;
            const n = Name.readFromMessage(b.buf[0..b.len], &p) catch continue;
            if (std.mem.eql(u8, n.bytes(), suffix)) return off;
        }
        return null;
    }

    fn writeName(b: *Builder, n: *const Name, compress: bool) Error!void {
        const wire = n.bytes();
        var p: usize = 0;
        while (wire[p] != 0) {
            if (compress) {
                if (b.findSuffix(wire[p..])) |off| {
                    try b.put16(0xC000 | off);
                    return;
                }
                if (b.len < 0x4000 and b.comp_len < max_compression_entries) {
                    b.comp[b.comp_len] = @intCast(b.len);
                    b.comp_len += 1;
                }
            }
            const l: usize = wire[p];
            try b.put(wire[p..][0 .. 1 + l]);
            p += 1 + l;
        }
        try b.put(&.{0});
    }

    pub fn question(b: *Builder, n: Name, qtype: Type, qclass: types.Class) Error!void {
        try b.advance(.question);
        if (b.counts[0] == std.math.maxInt(u16)) return error.NoSpace;
        try b.writeName(&n, true);
        try b.put16(qtype.toInt());
        try b.put16(qclass.toInt());
        b.counts[0] += 1;
    }

    pub fn record(b: *Builder, section: message.Section, rr: message.Rr) Error!void {
        const stage: Stage = switch (section) {
            .answer => .answer,
            .authority => .authority,
            .additional => .additional,
        };
        try b.advance(stage);
        const idx = @backingInt(stage);
        if (b.counts[idx] == std.math.maxInt(u16)) return error.NoSpace;
        try b.writeName(&rr.name, true);
        try b.put16(rr.type.toInt());
        try b.put16(rr.class.toInt());
        try b.put32(rr.ttl);
        const rdlen_at = b.len;
        try b.put16(0);
        const rdata_start = b.len;
        try b.writeRdata(rr.type, rr.rdata);
        const rdlen = b.len - rdata_start;
        if (rdlen > std.math.maxInt(u16)) return error.NoSpace;
        std.mem.writeInt(u16, b.buf[rdlen_at..][0..2], @intCast(rdlen), .big);
        b.counts[idx] += 1;
    }

    fn writeRdata(b: *Builder, t: Type, rd: []const u8) Error!void {
        const layout = rdata_mod.layoutOf(t) orelse return b.put(rd);
        const compress = rdata_mod.senderMayCompress(t);
        var p: usize = 0;
        for (layout.fields) |f| switch (f) {
            .name => {
                const n = Name.readUncompressed(rd, &p) catch return error.MalformedRdata;
                try b.writeName(&n, compress);
            },
            .fixed => |k| {
                if (p + k > rd.len) return error.MalformedRdata;
                try b.put(rd[p..][0..k]);
                p += k;
            },
            .char_string => {
                if (p >= rd.len) return error.MalformedRdata;
                const k: usize = 1 + @as(usize, rd[p]);
                if (p + k > rd.len) return error.MalformedRdata;
                try b.put(rd[p..][0..k]);
                p += k;
            },
            .rest => {
                try b.put(rd[p..]);
                p = rd.len;
            },
        };
        if (p != rd.len) return error.MalformedRdata;
    }

    /// Adds an EDNS(0) OPT pseudo-RR (RFC 6891).
    pub fn opt(b: *Builder, udp_size: u16, do_bit: bool, options: []const u8) Error!void {
        try b.advance(.additional);
        if (b.counts[3] == std.math.maxInt(u16)) return error.NoSpace;
        try b.put(&.{0}); // root owner
        try b.put16(Type.opt.toInt());
        try b.put16(udp_size);
        try b.put32(if (do_bit) 0x8000 else 0);
        if (options.len > std.math.maxInt(u16)) return error.NoSpace;
        try b.put16(@intCast(options.len));
        try b.put(options);
        b.counts[3] += 1;
    }

    /// Writes the header (with the final section counts) and returns the
    /// encoded message.
    pub fn finish(b: *Builder) []u8 {
        var h = b.header;
        h.qdcount = b.counts[0];
        h.ancount = b.counts[1];
        h.nscount = b.counts[2];
        h.arcount = b.counts[3];
        std.mem.writeInt(u16, b.buf[0..2], h.id, .big);
        std.mem.writeInt(u16, b.buf[2..4], h.flags.toInt(), .big);
        std.mem.writeInt(u16, b.buf[4..6], h.qdcount, .big);
        std.mem.writeInt(u16, b.buf[6..8], h.ancount, .big);
        std.mem.writeInt(u16, b.buf[8..10], h.nscount, .big);
        std.mem.writeInt(u16, b.buf[10..12], h.arcount, .big);
        return b.buf[0..b.len];
    }
};

/// Convenience: encodes a standard query with EDNS(0).
pub fn encodeQuery(
    buf: []u8,
    id: u16,
    qname: Name,
    qtype: Type,
    opts: struct { rd: bool = true, cd: bool = false, do_bit: bool = true, udp_size: u16 = 1232 },
) Error![]u8 {
    var b = try Builder.init(buf, .{ .id = id, .flags = .{ .rd = opts.rd, .cd = opts.cd } });
    try b.question(qname, qtype, .in);
    try b.opt(opts.udp_size, opts.do_bit, &.{});
    return b.finish();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn nm(t: []const u8) Name {
    return Name.fromText(t) catch unreachable;
}

test "round trip with compression" {
    var buf: [1024]u8 = undefined;
    var b = try Builder.init(&buf, .{ .id = 0xBEEF, .flags = .{ .qr = true, .rd = true, .ra = true } });
    try b.question(nm("www.example.com."), .a, .in);
    const cname_rd = nm("web.Example.com.");
    try b.record(.answer, .{ .name = nm("www.example.com."), .type = .cname, .class = .in, .ttl = 300, .rdata = cname_rd.bytes() });
    try b.record(.answer, .{ .name = nm("web.Example.com."), .type = .a, .class = .in, .ttl = 300, .rdata = &.{ 192, 0, 2, 1 } });
    var soa_rd: [255 * 2 + 20]u8 = undefined;
    const mname = nm("ns1.example.com.");
    const rname = nm("hostmaster.example.com.");
    @memcpy(soa_rd[0..mname.len], mname.bytes());
    @memcpy(soa_rd[mname.len..][0..rname.len], rname.bytes());
    @memset(soa_rd[mname.len + rname.len ..][0..20], 7);
    const soa = soa_rd[0 .. mname.len + rname.len + 20];
    try b.record(.authority, .{ .name = nm("example.com."), .type = .soa, .class = .in, .ttl = 3600, .rdata = soa });
    try b.opt(1232, true, &.{});
    const wire = b.finish();

    // Owner of the second answer is a pointer (case-preserving match).
    var m = try message.Message.parse(testing.allocator, wire);
    defer m.deinit();
    try testing.expectEqual(@as(u16, 0xBEEF), m.header.id);
    try testing.expectEqual(@as(usize, 1), m.questions.len);
    try testing.expectEqual(@as(usize, 2), m.answer.len);
    try testing.expectEqual(@as(usize, 1), m.authority.len);
    try testing.expectEqual(@as(usize, 0), m.additional.len);
    try testing.expect(m.edns.?.do_bit);
    try testing.expectEqual(@as(u16, 1232), m.edns.?.udp_size);
    try testing.expectEqualSlices(u8, cname_rd.bytes(), m.answer[0].rdata);
    try testing.expectEqualSlices(u8, soa, m.authority[0].rdata);
    try testing.expect(m.answer[1].name.eql(&nm("web.example.com.")));
    const s = try rdata_mod.Soa.parse(m.authority[0].rdata);
    try testing.expect(s.rname.eql(&rname));
    // Compression saved space versus the uncompressed size.
    const uncompressed = 12 + (17 + 4) + (17 + 10 + 17) + (17 + 10 + 4) + (13 + 10 + soa.len) + 11;
    try testing.expect(wire.len < uncompressed);
}

test "RRSIG and NSEC RDATA are never compressed by the builder" {
    var buf: [512]u8 = undefined;
    var b = try Builder.init(&buf, .{});
    try b.question(nm("example."), .nsec, .in);
    const next = nm("a.example.");
    var nsec_rd: [64]u8 = undefined;
    @memcpy(nsec_rd[0..next.len], next.bytes());
    @memcpy(nsec_rd[next.len..][0..3], &[_]u8{ 0, 1, 0x40 });
    try b.record(.answer, .{ .name = nm("example."), .type = .nsec, .class = .in, .ttl = 1, .rdata = nsec_rd[0 .. next.len + 3] });
    const wire = b.finish();
    // The NSEC next name must appear literally, not as a pointer.
    try testing.expect(std.mem.find(u8, wire, next.bytes()) != null);
    var m = try message.Message.parse(testing.allocator, wire);
    defer m.deinit();
    try testing.expectEqualSlices(u8, nsec_rd[0 .. next.len + 3], m.answer[0].rdata);
}

test "every strict prefix of a valid message is rejected" {
    var buf: [512]u8 = undefined;
    var b = try Builder.init(&buf, .{ .flags = .{ .qr = true } });
    try b.question(nm("a.example."), .mx, .in);
    const mx_target = nm("mail.a.example.");
    var mx_rd: [300]u8 = undefined;
    mx_rd[0] = 0;
    mx_rd[1] = 10;
    @memcpy(mx_rd[2..][0..mx_target.len], mx_target.bytes());
    try b.record(.answer, .{ .name = nm("a.example."), .type = .mx, .class = .in, .ttl = 60, .rdata = mx_rd[0 .. 2 + mx_target.len] });
    try b.opt(4096, true, &.{ 0, 10, 0, 2, 0xAB, 0xCD });
    const wire = b.finish();
    var m = try message.Message.parse(testing.allocator, wire);
    m.deinit();
    for (0..wire.len) |k| {
        if (message.Message.parse(testing.allocator, wire[0..k])) |mm| {
            var x = mm;
            x.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "malformed records are rejected" {
    const A = testing.allocator;
    // A record with 3-octet RDATA.
    const bad_a = [_]u8{ 0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0 } ++
        [_]u8{ 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 3, 1, 2, 3 };
    try testing.expectError(error.MalformedRdata, message.Message.parse(A, &bad_a));
    // OPT in the answer section.
    const opt_ans = [_]u8{ 0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0 } ++
        [_]u8{ 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.BadOpt, message.Message.parse(A, &opt_ans));
    // Two OPT records.
    const two_opt = [_]u8{ 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 2 } ++
        [_]u8{ 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0 } ++ [_]u8{ 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.BadOpt, message.Message.parse(A, &two_opt));
    // OPT with non-root owner.
    const opt_owner = [_]u8{ 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1 } ++
        [_]u8{ 1, 'a', 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.BadOpt, message.Message.parse(A, &opt_owner));
    // Type ANY used as a record type.
    const any_rr = [_]u8{ 0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0 } ++
        [_]u8{ 0, 0, 255, 0, 1, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.BadRecordType, message.Message.parse(A, &any_rr));
    // RDLENGTH running past the end.
    const long_rd = [_]u8{ 0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0 } ++
        [_]u8{ 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4 };
    try testing.expectError(error.Truncated, message.Message.parse(A, &long_rd));
    // CNAME whose name runs past RDLENGTH (name continues into next bytes).
    const cname_over = [_]u8{ 0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0 } ++
        [_]u8{ 0, 0, 5, 0, 1, 0, 0, 0, 0, 0, 2, 1, 'a', 0 };
    try testing.expectError(error.Truncated, message.Message.parse(A, &cname_over));
    // DNAME target compressed (forbidden).
    const dname_ptr = [_]u8{ 0, 0, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0 } ++
        [_]u8{ 1, 'a', 0, 0, 39, 0, 1 } ++
        [_]u8{ 1, 'b', 0xC0, 12, 0, 39, 0, 1, 0, 0, 0, 0, 0, 2, 0xC0, 12 };
    try testing.expectError(error.CompressionForbidden, message.Message.parse(A, &dname_ptr));
}

test "encodeQuery" {
    var buf: [512]u8 = undefined;
    const q = try encodeQuery(&buf, 0, nm("example.org."), .dnskey, .{ .cd = true });
    var m = try message.Message.parse(testing.allocator, q);
    defer m.deinit();
    try testing.expect(m.header.flags.cd);
    try testing.expect(m.header.flags.rd);
    try testing.expect(!m.header.flags.qr);
    try testing.expectEqual(Type.dnskey, m.questions[0].qtype);
    try testing.expect(m.edns.?.do_bit);
}
