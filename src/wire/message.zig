// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! DNS message decoding (RFC 1035 §4.1, EDNS(0) per RFC 6891).
//!
//! `Message.parse` is strict: every length is bounds-checked, every RDATA of
//! a type this library interprets is structurally validated, names in RDATA
//! are decompressed only where RFC 3597 §4 permits it, and any malformed or
//! trailing data rejects the whole message. Nothing in a parsed `Message`
//! aliases the input buffer.

const std = @import("std");
const name_mod = @import("name.zig");
const types = @import("types.zig");
const rdata_mod = @import("rdata.zig");

const Name = name_mod.Name;
const Type = types.Type;
const Class = types.Class;

pub const max_message_len = 65535;
pub const header_len = 12;

pub const ParseError = rdata_mod.Error || std.mem.Allocator.Error || error{
    /// The input is larger than a DNS message can be.
    MessageTooLong,
    /// Octets remain after the last record announced by the header.
    TrailingData,
    /// An OPT pseudo-RR outside the additional section, with a non-root
    /// owner, or more than one of them (RFC 6891 §6.1.1).
    BadOpt,
    /// A meta-type or QTYPE-only value used as a record type.
    BadRecordType,
};

pub const Flags = struct {
    qr: bool = false,
    opcode: types.Opcode = .query,
    aa: bool = false,
    tc: bool = false,
    rd: bool = false,
    ra: bool = false,
    z: bool = false,
    ad: bool = false,
    cd: bool = false,
    rcode: u4 = 0,

    pub fn fromInt(v: u16) Flags {
        return .{
            .qr = v & 0x8000 != 0,
            .opcode = @fromBackingInt(@intCast(@as(u4, @truncate(v >> 11)))),
            .aa = v & 0x0400 != 0,
            .tc = v & 0x0200 != 0,
            .rd = v & 0x0100 != 0,
            .ra = v & 0x0080 != 0,
            .z = v & 0x0040 != 0,
            .ad = v & 0x0020 != 0,
            .cd = v & 0x0010 != 0,
            .rcode = @truncate(v),
        };
    }

    pub fn toInt(f: Flags) u16 {
        var v: u16 = 0;
        if (f.qr) v |= 0x8000;
        v |= @as(u16, @backingInt(f.opcode)) << 11;
        if (f.aa) v |= 0x0400;
        if (f.tc) v |= 0x0200;
        if (f.rd) v |= 0x0100;
        if (f.ra) v |= 0x0080;
        if (f.z) v |= 0x0040;
        if (f.ad) v |= 0x0020;
        if (f.cd) v |= 0x0010;
        v |= f.rcode;
        return v;
    }
};

pub const Header = struct {
    id: u16 = 0,
    flags: Flags = .{},
    qdcount: u16 = 0,
    ancount: u16 = 0,
    nscount: u16 = 0,
    arcount: u16 = 0,

    pub fn parse(b: []const u8) error{Truncated}!Header {
        if (b.len < header_len) return error.Truncated;
        return .{
            .id = std.mem.readInt(u16, b[0..2], .big),
            .flags = .fromInt(std.mem.readInt(u16, b[2..4], .big)),
            .qdcount = std.mem.readInt(u16, b[4..6], .big),
            .ancount = std.mem.readInt(u16, b[6..8], .big),
            .nscount = std.mem.readInt(u16, b[8..10], .big),
            .arcount = std.mem.readInt(u16, b[10..12], .big),
        };
    }
};

pub const Question = struct {
    name: Name,
    qtype: Type,
    qclass: Class,
};

/// A resource record with uncompressed RDATA.
pub const Rr = struct {
    name: Name,
    type: Type,
    class: Class,
    ttl: u32,
    rdata: []const u8,
};

pub const Edns = struct {
    udp_size: u16,
    extended_rcode_high: u8,
    version: u8,
    do_bit: bool,
    options: []const u8,
};

pub const Section = enum { answer, authority, additional };

pub const Message = struct {
    arena: std.heap.ArenaAllocator,
    header: Header,
    questions: []Question,
    answer: []Rr,
    authority: []Rr,
    /// Additional section without the OPT pseudo-RR (see `edns`).
    additional: []Rr,
    edns: ?Edns,

    pub fn deinit(m: *Message) void {
        m.arena.deinit();
        m.* = undefined;
    }

    /// Full 12-bit RCODE (header RCODE plus the EDNS extended bits).
    pub fn rcode(m: *const Message) types.Rcode {
        const hi: u12 = if (m.edns) |e| @as(u12, e.extended_rcode_high) << 4 else 0;
        return @fromBackingInt(@intCast(hi | m.header.flags.rcode));
    }

    pub fn section(m: *const Message, s: Section) []Rr {
        return switch (s) {
            .answer => m.answer,
            .authority => m.authority,
            .additional => m.additional,
        };
    }

    pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) ParseError!Message {
        if (bytes.len > max_message_len) return error.MessageTooLong;
        const header = try Header.parse(bytes);

        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();

        var pos: usize = header_len;

        // Each question needs at least 5 octets and each RR at least 11;
        // reject impossible counts before allocating for them.
        const min_needed = @as(usize, header.qdcount) * 5 +
            (@as(usize, header.ancount) + header.nscount + header.arcount) * 11;
        if (header_len + min_needed > bytes.len) return error.Truncated;

        const questions = try a.alloc(Question, header.qdcount);
        for (questions) |*q| {
            const n = try Name.readFromMessage(bytes, &pos);
            if (pos + 4 > bytes.len) return error.Truncated;
            q.* = .{
                .name = n,
                .qtype = @fromBackingInt(@intCast(std.mem.readInt(u16, bytes[pos..][0..2], .big))),
                .qclass = @fromBackingInt(@intCast(std.mem.readInt(u16, bytes[pos + 2 ..][0..2], .big))),
            };
            pos += 4;
        }

        const answer = try a.alloc(Rr, header.ancount);
        for (answer) |*rr| rr.* = try readRr(a, bytes, &pos, .answer);
        const authority = try a.alloc(Rr, header.nscount);
        for (authority) |*rr| rr.* = try readRr(a, bytes, &pos, .authority);

        var additional: std.ArrayList(Rr) = .empty;
        try additional.ensureTotalCapacityPrecise(a, header.arcount);
        var edns: ?Edns = null;
        for (0..header.arcount) |_| {
            const rr = try readRr(a, bytes, &pos, .additional);
            if (rr.type == .opt) {
                if (edns != null) return error.BadOpt;
                if (!rr.name.isRoot()) return error.BadOpt;
                edns = .{
                    .udp_size = rr.class.toInt(),
                    .extended_rcode_high = @truncate(rr.ttl >> 24),
                    .version = @truncate(rr.ttl >> 16),
                    .do_bit = rr.ttl & 0x8000 != 0,
                    .options = rr.rdata,
                };
            } else {
                additional.appendAssumeCapacity(rr);
            }
        }
        if (pos != bytes.len) return error.TrailingData;

        return .{
            .arena = arena,
            .header = header,
            .questions = questions,
            .answer = answer,
            .authority = authority,
            .additional = additional.items,
            .edns = edns,
        };
    }
};

fn readRr(a: std.mem.Allocator, bytes: []const u8, pos: *usize, section: Section) ParseError!Rr {
    const owner = try Name.readFromMessage(bytes, pos);
    if (pos.* + 10 > bytes.len) return error.Truncated;
    const f = bytes[pos.*..][0..10];
    const t: Type = @fromBackingInt(@intCast(std.mem.readInt(u16, f[0..2], .big)));
    const class: Class = @fromBackingInt(@intCast(std.mem.readInt(u16, f[2..4], .big)));
    const ttl = std.mem.readInt(u32, f[4..8], .big);
    const rdlen: usize = std.mem.readInt(u16, f[8..10], .big);
    pos.* += 10;
    if (pos.* + rdlen > bytes.len) return error.Truncated;

    switch (t.toInt()) {
        0, 251...255 => return error.BadRecordType,
        else => {},
    }
    if (t == .opt and section != .additional) return error.BadOpt;
    if ((t == .tsig or t.toInt() == 249) and section != .additional) return error.BadRecordType;

    // Expanded RDATA can grow by at most 255 octets per embedded name; no
    // supported layout has more than four names.
    const cap = rdlen + 4 * name_mod.max_wire_len;
    const buf = try a.alloc(u8, cap);
    const expanded = try rdata_mod.expand(bytes, pos.*, rdlen, t, buf);
    if (expanded.len > max_message_len) return error.MalformedRdata;
    try rdata_mod.validate(t, expanded);
    pos.* += rdlen;
    return .{ .name = owner, .type = t, .class = class, .ttl = ttl, .rdata = expanded };
}

// ---------------------------------------------------------------------------
// Tests (round-trip tests live in builder.zig)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "flags round trip" {
    const f: Flags = .{ .qr = true, .opcode = .query, .rd = true, .ra = true, .ad = true, .cd = true, .rcode = 3 };
    try testing.expectEqual(f, Flags.fromInt(f.toInt()));
    try testing.expectEqual(@as(u16, 0x81B3), f.toInt());
}

test "header-only and truncated inputs" {
    try testing.expectError(error.Truncated, Message.parse(testing.allocator, &.{ 0, 1, 2 }));
    var m = try Message.parse(testing.allocator, &([_]u8{ 0x12, 0x34, 0x81, 0x80 } ++ @as([8]u8, @splat(0))));
    defer m.deinit();
    try testing.expectEqual(@as(u16, 0x1234), m.header.id);
    try testing.expect(m.header.flags.qr);
    try testing.expectEqual(@as(usize, 0), m.questions.len);
    // Count claims more than the data can hold.
    try testing.expectError(error.Truncated, Message.parse(testing.allocator, &([_]u8{ 0, 0, 0, 0, 0xFF, 0xFF } ++ @as([6]u8, @splat(0)))));
}

test "trailing data is rejected" {
    try testing.expectError(error.TrailingData, Message.parse(testing.allocator, &(@as([12]u8, @splat(0)) ++ [_]u8{0})));
}

test "oversized input is rejected" {
    const big = try testing.allocator.alloc(u8, max_message_len + 1);
    defer testing.allocator.free(big);
    @memset(big, 0);
    try testing.expectError(error.MessageTooLong, Message.parse(testing.allocator, big));
}
