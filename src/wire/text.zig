// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Presentation (master-file) format: a parser for the record types this
//! library needs (trust anchors, test vectors, fixtures) and a formatter for
//! diagnostics. Supports $ORIGIN, $TTL, parentheses, comments, quoted
//! strings, omitted owners, and RFC 3597 generic RDATA (`\# len hex`).
//!
//! Supported types: A AAAA NS CNAME DNAME PTR MX SOA TXT DNSKEY CDNSKEY DS
//! CDS RRSIG NSEC NSEC3 NSEC3PARAM, plus any type in generic form.

const std = @import("std");
const name_mod = @import("name.zig");
const types = @import("types.zig");
const rdata_mod = @import("rdata.zig");
const message = @import("message.zig");
const encoding = @import("encoding.zig");

const Name = name_mod.Name;
const Type = types.Type;
const Rr = message.Rr;

pub const Error = name_mod.Error || rdata_mod.Error || encoding.Error || std.mem.Allocator.Error || error{
    Syntax,
    UnknownType,
    UnbalancedParentheses,
    UnterminatedString,
    BadNumber,
    BadAddress,
    BadTime,
    BadAlgorithm,
};

pub const Options = struct {
    origin: ?Name = null,
    default_ttl: u32 = 3600,
    default_class: types.Class = .in,
};

pub const Diagnostics = struct {
    line: usize = 0,
};

pub const Zone = struct {
    arena: std.heap.ArenaAllocator,
    records: []Rr,

    pub fn deinit(z: *Zone) void {
        z.arena.deinit();
        z.* = undefined;
    }
};

const Token = struct {
    text: []const u8,
    quoted: bool,
};

const Entry = struct {
    line: usize,
    owner_omitted: bool,
    tokens: []Token,
};

/// Splits text into logical entries (one per record or directive).
fn tokenize(a: std.mem.Allocator, text: []const u8, diag: ?*Diagnostics) Error![]Entry {
    var entries: std.ArrayList(Entry) = .empty;
    var tokens: std.ArrayList(Token) = .empty;
    var depth: usize = 0;
    var line: usize = 1;
    var entry_line: usize = 1;
    var at_line_start = true;
    var owner_omitted = false;
    var i: usize = 0;
    while (i < text.len) {
        const c = text[i];
        if (c == '\n') {
            line += 1;
            i += 1;
            if (depth == 0) {
                if (tokens.items.len > 0) {
                    try entries.append(a, .{ .line = entry_line, .owner_omitted = owner_omitted, .tokens = try tokens.toOwnedSlice(a) });
                }
                at_line_start = true;
            }
            continue;
        }
        if (c == ' ' or c == '\t' or c == '\r') {
            if (at_line_start and depth == 0 and tokens.items.len == 0) owner_omitted = true;
            at_line_start = false;
            i += 1;
            continue;
        }
        if (at_line_start) {
            owner_omitted = false;
            entry_line = line;
            at_line_start = false;
        }
        if (tokens.items.len == 0 and depth == 0) entry_line = line;
        switch (c) {
            ';' => {
                while (i < text.len and text[i] != '\n') i += 1;
            },
            '(' => {
                depth += 1;
                i += 1;
            },
            ')' => {
                if (depth == 0) {
                    if (diag) |d| d.line = line;
                    return error.UnbalancedParentheses;
                }
                depth -= 1;
                i += 1;
            },
            '"' => {
                const start = i + 1;
                var j = start;
                while (j < text.len and text[j] != '"') : (j += 1) {
                    if (text[j] == '\\') j += 1;
                    if (j < text.len and text[j] == '\n') line += 1;
                }
                if (j >= text.len) {
                    if (diag) |d| d.line = line;
                    return error.UnterminatedString;
                }
                try tokens.append(a, .{ .text = text[start..j], .quoted = true });
                i = j + 1;
            },
            else => {
                const start = i;
                while (i < text.len) : (i += 1) {
                    const d = text[i];
                    if (d == '\\') {
                        i += 1;
                        continue;
                    }
                    if (d == ' ' or d == '\t' or d == '\r' or d == '\n' or d == ';' or d == '(' or d == ')' or d == '"') break;
                }
                try tokens.append(a, .{ .text = text[start..@min(i, text.len)], .quoted = false });
            },
        }
    }
    if (depth != 0) {
        if (diag) |d| d.line = line;
        return error.UnbalancedParentheses;
    }
    if (tokens.items.len > 0) {
        try entries.append(a, .{ .line = entry_line, .owner_omitted = owner_omitted, .tokens = try tokens.toOwnedSlice(a) });
    }
    return entries.items;
}

fn parseTtl(t: []const u8) Error!u32 {
    if (t.len == 0) return error.BadNumber;
    if (std.ascii.isDigit(t[t.len - 1])) {
        return std.fmt.parseInt(u32, t, 10) catch error.BadNumber;
    }
    // BIND-style units, e.g. 1h30m.
    var total: u64 = 0;
    var acc: u64 = 0;
    var have_digit = false;
    for (t) |c| {
        if (std.ascii.isDigit(c)) {
            acc = acc * 10 + (c - '0');
            have_digit = true;
            if (acc > std.math.maxInt(u32)) return error.BadNumber;
            continue;
        }
        if (!have_digit) return error.BadNumber;
        const mult: u64 = switch (std.ascii.toLower(c)) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            'w' => 604800,
            else => return error.BadNumber,
        };
        // Checked, and bailed on as soon as the sum cannot fit: every term is
        // non-negative, so a partial sum past u32 can never come back. Plain
        // u64 accumulation let a long-enough compound TTL such as repeated
        // `4294967295w` overflow before the final range check - a panic in
        // Debug and ReleaseSafe, and a wrapped, wrongly small TTL otherwise,
        // from a public zone parser.
        const term = std.math.mul(u64, acc, mult) catch return error.BadNumber;
        total = std.math.add(u64, total, term) catch return error.BadNumber;
        if (total > std.math.maxInt(u32)) return error.BadNumber;
        acc = 0;
        have_digit = false;
    }
    if (have_digit) return error.BadNumber;
    if (total > std.math.maxInt(u32)) return error.BadNumber;
    return @intCast(total);
}

fn isTtl(t: []const u8) bool {
    return t.len > 0 and std.ascii.isDigit(t[0]) and (parseTtl(t) catch null) != null;
}

fn parseClass(t: []const u8) ?types.Class {
    if (std.ascii.eqlIgnoreCase(t, "IN")) return .in;
    if (std.ascii.eqlIgnoreCase(t, "CH")) return .ch;
    if (std.ascii.eqlIgnoreCase(t, "HS")) return .hs;
    if (t.len > 5 and std.ascii.eqlIgnoreCase(t[0..5], "CLASS")) {
        const v = std.fmt.parseInt(u16, t[5..], 10) catch return null;
        return @fromBackingInt(@intCast(v));
    }
    return null;
}

pub fn parseAlgorithm(t: []const u8) Error!types.Algorithm {
    if (t.len > 0 and std.ascii.isDigit(t[0])) {
        return @fromBackingInt(@intCast(std.fmt.parseInt(u8, t, 10) catch return error.BadAlgorithm));
    }
    const names = .{
        .{ "RSAMD5", types.Algorithm.rsamd5 },                         .{ "DSA", types.Algorithm.dsa },
        .{ "RSASHA1", types.Algorithm.rsasha1 },                       .{ "DSA-NSEC3-SHA1", types.Algorithm.dsa_nsec3_sha1 },
        .{ "RSASHA1-NSEC3-SHA1", types.Algorithm.rsasha1_nsec3_sha1 }, .{ "RSASHA256", types.Algorithm.rsasha256 },
        .{ "RSASHA512", types.Algorithm.rsasha512 },                   .{ "ECC-GOST", types.Algorithm.ecc_gost },
        .{ "ECDSAP256SHA256", types.Algorithm.ecdsap256sha256 },       .{ "ECDSAP384SHA384", types.Algorithm.ecdsap384sha384 },
        .{ "ED25519", types.Algorithm.ed25519 },                       .{ "ED448", types.Algorithm.ed448 },
    };
    inline for (names) |n| {
        if (std.ascii.eqlIgnoreCase(t, n[0])) return n[1];
    }
    return error.BadAlgorithm;
}

/// Converts YYYYMMDDHHmmSS (UTC) or a plain decimal to RRSIG time (seconds
/// since the epoch modulo 2^32, RFC 4034 §3.2).
pub fn parseRrsigTime(t: []const u8) Error!u32 {
    if (t.len != 14) {
        return std.fmt.parseInt(u32, t, 10) catch error.BadTime;
    }
    for (t) |c| if (!std.ascii.isDigit(c)) return error.BadTime;
    const y = std.fmt.parseInt(i64, t[0..4], 10) catch return error.BadTime;
    const mo = std.fmt.parseInt(i64, t[4..6], 10) catch return error.BadTime;
    const d = std.fmt.parseInt(i64, t[6..8], 10) catch return error.BadTime;
    const h = std.fmt.parseInt(i64, t[8..10], 10) catch return error.BadTime;
    const mi = std.fmt.parseInt(i64, t[10..12], 10) catch return error.BadTime;
    const s = std.fmt.parseInt(i64, t[12..14], 10) catch return error.BadTime;
    if (mo < 1 or mo > 12 or d < 1 or h > 23 or mi > 59 or s > 60) return error.BadTime;
    // `d <= 31` is not a calendar. daysFromCivil normalises rather than fails,
    // so 20230231000000 used to be encoded as a March timestamp: a zone file or
    // test vector stating an impossible RRSIG inception or expiration was
    // silently recorded as a different instant than the text says.
    const month_len = [_]i64{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const lim = if (mo == 2 and isLeapYear(y)) @as(i64, 29) else month_len[@intCast(mo - 1)];
    if (d > lim) return error.BadTime;
    const days = daysFromCivil(y, mo, d);
    const secs = days * 86400 + h * 3600 + mi * 60 + s;
    if (secs < 0) return error.BadTime;
    return @truncate(@as(u64, @intCast(secs)));
}

fn isLeapYear(y: i64) bool {
    return (@rem(y, 4) == 0 and @rem(y, 100) != 0) or @rem(y, 400) == 0;
}

/// Howard Hinnant's days_from_civil.
fn daysFromCivil(y_in: i64, m: i64, d: i64) i64 {
    const y = if (m <= 2) y_in - 1 else y_in;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn parseIp4(t: []const u8, out: *[4]u8) Error!void {
    var it = std.mem.splitScalar(u8, t, '.');
    var k: usize = 0;
    while (it.next()) |part| : (k += 1) {
        if (k >= 4 or part.len == 0 or part.len > 3) return error.BadAddress;
        out[k] = std.fmt.parseInt(u8, part, 10) catch return error.BadAddress;
    }
    if (k != 4) return error.BadAddress;
}

fn parseIp6(t: []const u8, out: *[16]u8) Error!void {
    const a = std.Io.net.Ip6Address.parse(t, 0) catch return error.BadAddress;
    out.* = a.bytes;
}

const RdataWriter = struct {
    list: std.ArrayList(u8),
    a: std.mem.Allocator,

    fn bytes(w: *RdataWriter, b: []const u8) Error!void {
        try w.list.appendSlice(w.a, b);
    }
    fn byte(w: *RdataWriter, b: u8) Error!void {
        try w.list.append(w.a, b);
    }
    fn u16be(w: *RdataWriter, v: u16) Error!void {
        var t: [2]u8 = undefined;
        std.mem.writeInt(u16, &t, v, .big);
        try w.bytes(&t);
    }
    fn u32be(w: *RdataWriter, v: u32) Error!void {
        var t: [4]u8 = undefined;
        std.mem.writeInt(u32, &t, v, .big);
        try w.bytes(&t);
    }
    fn name(w: *RdataWriter, t: []const u8, origin: ?*const Name) Error!void {
        const n = try Name.fromTextRelative(t, origin);
        try w.bytes(n.bytes());
    }
};

fn num(comptime T: type, t: []const u8) Error!T {
    return std.fmt.parseInt(T, t, 10) catch error.BadNumber;
}

fn joined(a: std.mem.Allocator, toks: []const Token) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (toks) |t| try out.appendSlice(a, t.text);
    return out.items;
}

fn encodeBitmap(w: *RdataWriter, toks: []const Token) Error!void {
    var present: [256][32]u8 = undefined;
    var used: [256]u8 = @splat(0);
    for (toks) |t| {
        const ty = Type.fromMnemonic(t.text) orelse return error.UnknownType;
        const v = ty.toInt();
        const win: u8 = @intCast(v >> 8);
        const bit: u8 = @intCast(v & 0xFF);
        if (used[win] == 0) present[win] = @splat(0);
        present[win][bit / 8] |= @as(u8, 0x80) >> @intCast(bit % 8);
        used[win] = @max(used[win], bit / 8 + 1);
    }
    for (0..256) |win| {
        if (used[win] == 0) continue;
        try w.byte(@intCast(win));
        try w.byte(used[win]);
        try w.bytes(present[win][0..used[win]]);
    }
}

fn charString(w: *RdataWriter, t: Token) Error!void {
    var buf: [256]u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < t.text.len) {
        var c = t.text[i];
        if (c == '\\' and i + 1 < t.text.len) {
            if (i + 3 < t.text.len and std.ascii.isDigit(t.text[i + 1])) {
                const v = std.fmt.parseInt(u16, t.text[i + 1 .. i + 4], 10) catch return error.Syntax;
                if (v > 255) return error.Syntax;
                c = @intCast(v);
                i += 4;
            } else {
                c = t.text[i + 1];
                i += 2;
            }
        } else i += 1;
        if (n >= 255) return error.Syntax;
        buf[n] = c;
        n += 1;
    }
    try w.byte(@intCast(n));
    try w.bytes(buf[0..n]);
}

fn encodeRdata(a: std.mem.Allocator, t: Type, toks: []const Token, origin: ?*const Name) Error![]u8 {
    var w: RdataWriter = .{ .list = .empty, .a = a };
    if (toks.len >= 1 and std.mem.eql(u8, toks[0].text, "\\#")) {
        if (toks.len < 2) return error.Syntax;
        const len = try num(u16, toks[1].text);
        const hex = try joined(a, toks[2..]);
        const out = try a.alloc(u8, hex.len / 2);
        const dec = try encoding.hexDecode(out, hex);
        if (dec.len != len) return error.Syntax;
        try rdata_mod.validate(t, dec);
        return dec;
    }
    const need = struct {
        fn at(ts: []const Token, n: usize) Error!void {
            if (ts.len < n) return error.Syntax;
        }
        fn exactly(ts: []const Token, n: usize) Error!void {
            if (ts.len != n) return error.Syntax;
        }
    };
    switch (t) {
        .a => {
            try need.exactly(toks, 1);
            var ip: [4]u8 = undefined;
            try parseIp4(toks[0].text, &ip);
            try w.bytes(&ip);
        },
        .aaaa => {
            try need.exactly(toks, 1);
            var ip: [16]u8 = undefined;
            try parseIp6(toks[0].text, &ip);
            try w.bytes(&ip);
        },
        .ns, .cname, .dname, .ptr => {
            try need.exactly(toks, 1);
            try w.name(toks[0].text, origin);
        },
        .mx => {
            try need.exactly(toks, 2);
            try w.u16be(try num(u16, toks[0].text));
            try w.name(toks[1].text, origin);
        },
        .soa => {
            try need.exactly(toks, 7);
            try w.name(toks[0].text, origin);
            try w.name(toks[1].text, origin);
            try w.u32be(try num(u32, toks[2].text));
            for (toks[3..7]) |x| try w.u32be(try parseTtl(x.text));
        },
        .txt => {
            try need.at(toks, 1);
            for (toks) |x| try charString(&w, x);
        },
        .hinfo => {
            try need.exactly(toks, 2);
            for (toks) |x| try charString(&w, x);
        },
        .dnskey, .cdnskey => {
            try need.at(toks, 4);
            try w.u16be(try num(u16, toks[0].text));
            try w.byte(try num(u8, toks[1].text));
            try w.byte(@backingInt(try parseAlgorithm(toks[2].text)));
            const key = try encoding.base64Decode(a, try joined(a, toks[3..]));
            try w.bytes(key);
        },
        .ds, .cds => {
            try need.at(toks, 4);
            try w.u16be(try num(u16, toks[0].text));
            try w.byte(@backingInt(try parseAlgorithm(toks[1].text)));
            try w.byte(try num(u8, toks[2].text));
            const hex = try joined(a, toks[3..]);
            const out = try a.alloc(u8, hex.len / 2);
            try w.bytes(try encoding.hexDecode(out, hex));
        },
        .rrsig => {
            try need.at(toks, 9);
            const covered = Type.fromMnemonic(toks[0].text) orelse return error.UnknownType;
            try w.u16be(covered.toInt());
            try w.byte(@backingInt(try parseAlgorithm(toks[1].text)));
            try w.byte(try num(u8, toks[2].text));
            try w.u32be(try parseTtl(toks[3].text));
            try w.u32be(try parseRrsigTime(toks[4].text));
            try w.u32be(try parseRrsigTime(toks[5].text));
            try w.u16be(try num(u16, toks[6].text));
            try w.name(toks[7].text, origin);
            try w.bytes(try encoding.base64Decode(a, try joined(a, toks[8..])));
        },
        .nsec => {
            try need.at(toks, 1);
            try w.name(toks[0].text, origin);
            try encodeBitmap(&w, toks[1..]);
        },
        .nsec3 => {
            try need.at(toks, 5);
            try w.byte(try num(u8, toks[0].text));
            try w.byte(try num(u8, toks[1].text));
            try w.u16be(try num(u16, toks[2].text));
            if (std.mem.eql(u8, toks[3].text, "-")) {
                try w.byte(0);
            } else {
                var salt: [255]u8 = undefined;
                const s = try encoding.hexDecode(&salt, toks[3].text);
                try w.byte(@intCast(s.len));
                try w.bytes(s);
            }
            var hash: [255]u8 = undefined;
            const hsh = try encoding.base32HexDecode(&hash, toks[4].text);
            try w.byte(@intCast(hsh.len));
            try w.bytes(hsh);
            try encodeBitmap(&w, toks[5..]);
        },
        .nsec3param => {
            try need.exactly(toks, 4);
            try w.byte(try num(u8, toks[0].text));
            try w.byte(try num(u8, toks[1].text));
            try w.u16be(try num(u16, toks[2].text));
            if (std.mem.eql(u8, toks[3].text, "-")) {
                try w.byte(0);
            } else {
                var salt: [255]u8 = undefined;
                const s = try encoding.hexDecode(&salt, toks[3].text);
                try w.byte(@intCast(s.len));
                try w.bytes(s);
            }
        },
        else => return error.UnknownType,
    }
    if (w.list.items.len > std.math.maxInt(u16)) return error.MalformedRdata;
    try rdata_mod.validate(t, w.list.items);
    return w.list.items;
}

/// Parses a zone fragment into records.
pub fn parseZone(gpa: std.mem.Allocator, text: []const u8, opts: Options, diag: ?*Diagnostics) Error!Zone {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const entries = try tokenize(a, text, diag);
    var records: std.ArrayList(Rr) = .empty;
    var origin = opts.origin;
    var default_ttl = opts.default_ttl;
    var last_owner: ?Name = null;
    for (entries) |e| {
        if (diag) |d| d.line = e.line;
        var toks = e.tokens;
        if (!e.owner_omitted and toks[0].text.len > 0 and toks[0].text[0] == '$') {
            if (std.ascii.eqlIgnoreCase(toks[0].text, "$ORIGIN")) {
                if (toks.len != 2) return error.Syntax;
                origin = try Name.fromText(toks[1].text);
            } else if (std.ascii.eqlIgnoreCase(toks[0].text, "$TTL")) {
                if (toks.len != 2) return error.Syntax;
                default_ttl = try parseTtl(toks[1].text);
            } else return error.Syntax;
            continue;
        }
        var owner: Name = undefined;
        if (e.owner_omitted) {
            owner = last_owner orelse return error.Syntax;
        } else {
            owner = try Name.fromTextRelative(toks[0].text, if (origin) |*o| o else null);
            toks = toks[1..];
        }
        last_owner = owner;
        var ttl = default_ttl;
        var class = opts.default_class;
        var k: usize = 0;
        while (k < 2 and toks.len > 0) : (k += 1) {
            if (isTtl(toks[0].text)) {
                ttl = try parseTtl(toks[0].text);
                toks = toks[1..];
            } else if (parseClass(toks[0].text)) |c| {
                class = c;
                toks = toks[1..];
            } else break;
        }
        if (toks.len == 0) return error.Syntax;
        const t = Type.fromMnemonic(toks[0].text) orelse return error.UnknownType;
        const rd = try encodeRdata(a, t, toks[1..], if (origin) |*o| o else null);
        try records.append(a, .{ .name = owner, .type = t, .class = class, .ttl = ttl, .rdata = rd });
    }
    return .{ .arena = arena, .records = records.items };
}

// ---------------------------------------------------------------------------
// Formatting (diagnostics only; not a complete presentation-format writer)
// ---------------------------------------------------------------------------

/// RFC 3597 §5 unknown-type form: `\# <length> <hex>`. Valid presentation
/// format for any RDATA, used where the complete form does not fit a stack
/// buffer.
fn genericRdata(w: *std.Io.Writer, rd: []const u8) std.Io.Writer.Error!void {
    try w.print("\\# {d}", .{rd.len});
    for (rd) |b| try w.print(" {x:0>2}", .{b});
}

pub fn formatRr(w: *std.Io.Writer, rr: *const Rr) std.Io.Writer.Error!void {
    var tb: [16]u8 = undefined;
    try rr.name.format(w);
    try w.print(" {d} ", .{rr.ttl});
    if (rr.class == .in) try w.writeAll("IN ") else try w.print("CLASS{d} ", .{rr.class.toInt()});
    try w.writeAll(rr.type.mnemonic(&tb));
    try w.writeByte(' ');
    const rd = rr.rdata;
    switch (rr.type) {
        .a => if (rd.len == 4) return w.print("{d}.{d}.{d}.{d}", .{ rd[0], rd[1], rd[2], rd[3] }),
        .aaaa => if (rd.len == 16) {
            const addr: std.Io.net.Ip6Address = .{ .bytes = rd[0..16].*, .port = 0 };
            var b: [64]u8 = undefined;
            var fw: std.Io.Writer = .fixed(&b);
            addr.format(&fw) catch {};
            const s = fw.buffered();
            // Ip6Address formats as "[addr]:port"; keep the address only.
            if (s.len > 2 and s[0] == '[') {
                if (std.mem.findScalar(u8, s, ']')) |end| return w.writeAll(s[1..end]);
            }
        },
        .mx => if (rd.len >= 3) {
            if (Name.fromWire(rd[2..])) |n| {
                try w.print("{d} ", .{std.mem.readInt(u16, rd[0..2], .big)});
                return n.format(w);
            } else |_| {}
        },
        .soa => if (rdata_mod.Soa.parse(rd)) |s| {
            try s.mname.format(w);
            try w.writeByte(' ');
            try s.rname.format(w);
            return w.print(" {d} {d} {d} {d} {d}", .{ s.serial, s.refresh, s.retry, s.expire, s.minimum });
        } else |_| {},
        .txt => {
            var p: usize = 0;
            while (p < rd.len) {
                const l = rd[p];
                if (p + 1 + l > rd.len) break;
                if (p > 0) try w.writeByte(' ');
                try w.writeByte('"');
                for (rd[p + 1 ..][0..l]) |c| {
                    if (c == '"' or c == '\\') try w.print("\\{c}", .{c}) else if (c >= 0x20 and c < 0x7F) try w.writeByte(c) else try w.print("\\{d:0>3}", .{c});
                }
                try w.writeByte('"');
                p += 1 + l;
            }
            if (p == rd.len) return;
        },
        .ns, .cname, .dname, .ptr => if (Name.fromWire(rd)) |n| return n.format(w) else |_| {},
        .ds => if (rdata_mod.Ds.parse(rd)) |d| {
            return w.print("{d} {d} {d} {x}", .{ d.key_tag, @backingInt(d.algorithm), @backingInt(d.digest_type), d.digest });
        } else |_| {},
        .dnskey => if (rdata_mod.Dnskey.parse(rd)) |k| {
            // RFC 4034 §2.2 presentation form: the public key in base64. A
            // "(256-octet key)" placeholder is not RDATA and cannot be parsed
            // or reused, and both the CLI and the C ABI promise presentation
            // format for answer records.
            var kb: [1024]u8 = undefined;
            const need = std.base64.standard.Encoder.calcSize(k.public_key.len);
            // RFC 3597 generic form replaces the WHOLE RDATA, so this has to be
            // decided before any of it is written: emitting the flags and then
            // `\# <len>` would be neither presentation form nor generic form.
            if (need > kb.len) return genericRdata(w, rd);
            try w.print("{d} {d} {d} ", .{ k.flags, k.protocol, @backingInt(k.algorithm) });
            return w.writeAll(std.base64.standard.Encoder.encode(&kb, k.public_key));
        } else |_| {},
        .rrsig => if (rdata_mod.Rrsig.parse(rd)) |s| {
            try w.print("{s} {d} {d} {d} {d} {d} {d} ", .{ s.type_covered.mnemonic(&tb), @backingInt(s.algorithm), s.labels, s.original_ttl, s.expiration, s.inception, s.key_tag });
            try s.signer.format(w);
            return w.writeAll(" (signature)");
        } else |_| {},
        // NSEC and NSEC3 used to stand in for their type bitmaps with
        // "(types)", which is likewise not parseable. The bitmap is small, so
        // it is enumerated into a stack buffer and written as mnemonics.
        .nsec => if (rdata_mod.Nsec.parse(rd)) |n| {
            try n.next.format(w);
            var tbuf: [128]Type = undefined;
            for (n.types.fill(&tbuf)) |t| {
                var mb: [16]u8 = undefined;
                try w.print(" {s}", .{t.mnemonic(&mb)});
            }
            return;
        } else |_| {},
        .nsec3 => if (rdata_mod.Nsec3.parse(rd)) |n| {
            var b32: [512]u8 = undefined;
            try w.print("{d} {d} {d} {x} {s}", .{ @backingInt(n.hash_algorithm), n.flags, n.iterations, n.salt, encoding.base32HexEncode(&b32, n.next_hashed_owner) });
            var tbuf: [128]Type = undefined;
            for (n.types.fill(&tbuf)) |t| {
                var mb: [16]u8 = undefined;
                try w.print(" {s}", .{t.mnemonic(&mb)});
            }
            return;
        } else |_| {},
        else => {},
    }
    try w.print("\\# {d} {x}", .{ rd.len, rd });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse a small zone with directives, parentheses and comments" {
    const text =
        \\$ORIGIN example.
        \\$TTL 1h
        \\@   IN SOA ns1 bugs.x.w.example. ( 1 ; serial
        \\        3600 300 3600000 3600 )
        \\    3600 IN NS ns1
        \\ns1 A 192.0.2.1
        \\    AAAA 2001:db8::1
        \\txt TXT "hello world" bare "a\"b"
        \\a NSEC b.example. A RRSIG NSEC TYPE1234
        \\
    ;
    var d: Diagnostics = .{};
    var z = try parseZone(testing.allocator, text, .{}, &d);
    defer z.deinit();
    try testing.expectEqual(@as(usize, 6), z.records.len);
    try testing.expectEqual(Type.soa, z.records[0].type);
    try testing.expectEqual(@as(u32, 3600), z.records[0].ttl);
    const soa = try rdata_mod.Soa.parse(z.records[0].rdata);
    try testing.expect(soa.mname.eql(&(try Name.fromText("ns1.example."))));
    try testing.expectEqual(@as(u32, 3600000), soa.expire);
    try testing.expect(z.records[1].name.eql(&(try Name.fromText("example."))));
    try testing.expectEqual(Type.aaaa, z.records[3].type);
    try testing.expect(z.records[3].name.eql(&(try Name.fromText("ns1.example."))));
    try testing.expectEqualSlices(u8, &.{ 11, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 4, 'b', 'a', 'r', 'e', 3, 'a', '"', 'b' }, z.records[4].rdata);
    const nsec = try rdata_mod.Nsec.parse(z.records[5].rdata);
    try testing.expect(nsec.types.has(Type.fromInt(1234)));
    try testing.expect(nsec.types.has(.a));
}

test "RRSIG time parsing" {
    // RFC 4034 §3.3 example: 20030322173103 = 1048354263.
    try testing.expectEqual(@as(u32, 1048354263), try parseRrsigTime("20030322173103"));
    try testing.expectEqual(@as(u32, 0), try parseRrsigTime("19700101000000"));
    try testing.expectEqual(@as(u32, 1048354263), try parseRrsigTime("1048354263"));
    try testing.expectError(error.BadTime, parseRrsigTime("20031322173103"));
}

test "syntax errors are reported" {
    try testing.expectError(error.UnbalancedParentheses, parseZone(testing.allocator, "a. A ( 1.2.3.4", .{}, null));
    try testing.expectError(error.BadAddress, parseZone(testing.allocator, "a. A 1.2.3", .{}, null));
    try testing.expectError(error.UnknownType, parseZone(testing.allocator, "a. FOO 1", .{}, null));
    try testing.expectError(error.UnterminatedString, parseZone(testing.allocator, "a. TXT \"abc", .{}, null));
    try testing.expectError(error.Syntax, parseZone(testing.allocator, " A 1.2.3.4", .{}, null));
}

test "generic RDATA" {
    var z = try parseZone(testing.allocator, "a. TYPE65280 \\# 3 abcdef\nb. A \\# 4 c0000201", .{}, null);
    defer z.deinit();
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd, 0xef }, z.records[0].rdata);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, z.records[1].rdata);
}

test "compound TTLs cannot overflow the accumulator" {
    // Every component is capped at u32, but plain u64 accumulation let a long
    // enough compound TTL overflow before the final range check: a panic in
    // Debug and ReleaseSafe, and a wrapped, wrongly small TTL in an unchecked
    // build, from the public zone parser.
    var text: [4096]u8 = undefined;
    var n: usize = 0;
    for (0..300) |_| {
        @memcpy(text[n..][0..11], "4294967295w");
        n += 11;
    }
    try testing.expectError(error.BadNumber, parseTtl(text[0..n]));
    // The bound is applied per term, so the work a hostile zone file can cause
    // is bounded too, not just the final result.
    try testing.expectError(error.BadNumber, parseTtl("4294967295w"));
    try testing.expectError(error.BadNumber, parseTtl("4294967296"));
    // 7101 weeks is the largest whole number of weeks that fits in u32
    // (4294684800); 7102 weeks (4295289600) does not.
    try testing.expectError(error.BadNumber, parseTtl("7102w"));
    // Legitimate values, including the largest representable one.
    try testing.expectEqual(@as(u32, 7101 * 604800), try parseTtl("7101w"));
    try testing.expectEqual(@as(u32, 710 * 604800), try parseTtl("710w"));
    try testing.expectEqual(@as(u32, 4294967295), try parseTtl("4294967295"));
    try testing.expectEqual(@as(u32, 604800), try parseTtl("1w"));
    try testing.expectEqual(@as(u32, 86400 + 3600 + 60 + 1), try parseTtl("1d1h1m1s"));
}

test "RRSIG timestamps reject impossible calendar dates" {
    // daysFromCivil normalises instead of failing, so a `d <= 31` range check
    // let 20230231000000 through as a March timestamp: a zone file or test
    // vector stating an impossible inception or expiration was encoded as a
    // different instant than the text says.
    try testing.expectError(error.BadTime, parseRrsigTime("20230231000000"));
    try testing.expectError(error.BadTime, parseRrsigTime("20230431000000")); // April has 30 days
    try testing.expectError(error.BadTime, parseRrsigTime("20230229000000")); // 2023 is not a leap year
    try testing.expectError(error.BadTime, parseRrsigTime("19000229000000")); // century, not 400-year
    try testing.expectError(error.BadTime, parseRrsigTime("20231301000000")); // month 13
    try testing.expectError(error.BadTime, parseRrsigTime("20230001000000")); // month 0
    try testing.expectError(error.BadTime, parseRrsigTime("20230100000000")); // day 0
    // Real leap years are accepted, including both century rules.
    _ = try parseRrsigTime("20240229000000");
    _ = try parseRrsigTime("20000229000000");
    // Month ends, and the leap second the field's own range allows.
    _ = try parseRrsigTime("20230228235959");
    _ = try parseRrsigTime("20231231000000");
    _ = try parseRrsigTime("20230630235960");
}

test "formatRr emits complete, parseable RDATA for DNSKEY, NSEC and NSEC3" {
    // Both the CLI and the C ABI promise presentation-format answer records.
    // "(256-octet key)" for a DNSKEY and "(types)" for the NSEC/NSEC3 bitmaps
    // are not RDATA: they cannot be parsed, re-signed or reused, and a secure
    // DNSKEY answer reaches this formatter through both paths.
    const owner = try Name.fromText("example.");

    // DNSKEY: flags 256, protocol 3, algorithm 8, key DE AD BE EF.
    {
        const rd = [_]u8{ 0x01, 0x00, 0x03, 0x08, 0xDE, 0xAD, 0xBE, 0xEF };
        const rr: Rr = .{ .name = owner, .type = .dnskey, .class = .in, .ttl = 3600, .rdata = &rd };
        var out: [256]u8 = undefined;
        _ = &out;
        var w = std.Io.Writer.fixed(&out);
        try formatRr(&w, &rr);
        try testing.expectEqualStrings("example. 3600 IN DNSKEY 256 3 8 3q2+7w==", w.buffered());
    }

    // NSEC: window 0, four octets 0x40 0x01 0x00 0x08 = types 1 (A), 15 (MX)
    // and 28 (AAAA).
    {
        const rd = [_]u8{ 2, 'n', 'x', 0, 0, 4, 0x40, 0x01, 0x00, 0x08 };
        const rr: Rr = .{ .name = owner, .type = .nsec, .class = .in, .ttl = 300, .rdata = &rd };
        var out: [256]u8 = undefined;
        _ = &out;
        var w = std.Io.Writer.fixed(&out);
        try formatRr(&w, &rr);
        try testing.expectEqualStrings("example. 300 IN NSEC nx. A MX AAAA", w.buffered());
    }

    // NSEC3: algorithm 1, flags 0, 12 iterations, salt AABB, base32hex next.
    {
        const hash = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
        var rd: [64]u8 = undefined;
        rd[0] = 1;
        rd[1] = 0;
        std.mem.writeInt(u16, rd[2..4], 12, .big);
        rd[4] = 2;
        rd[5] = 0xAA;
        rd[6] = 0xBB;
        rd[7] = 20;
        @memcpy(rd[8..28], &hash);
        rd[28] = 0;
        rd[29] = 4;
        rd[30] = 0x40;
        rd[31] = 0x01;
        rd[32] = 0x00;
        rd[33] = 0x08;
        const rr: Rr = .{ .name = owner, .type = .nsec3, .class = .in, .ttl = 300, .rdata = rd[0..34] };
        var out: [256]u8 = undefined;
        _ = &out;
        var w = std.Io.Writer.fixed(&out);
        try formatRr(&w, &rr);
        const got = w.buffered();
        // The bitmap is enumerated, not elided, and the output ends with it.
        try testing.expect(std.mem.endsWith(u8, got, " A MX AAAA"));
        try testing.expect(std.mem.indexOf(u8, got, "(types)") == null);
        try testing.expect(std.mem.startsWith(u8, got, "example. 300 IN NSEC3 1 0 12 aabb "));
    }

    // A DNSKEY too large for the stack buffer falls back to RFC 3597 generic
    // form rather than printing a placeholder or overrunning.
    {
        var big: [2048]u8 = undefined;
        big[0] = 0x01;
        big[1] = 0x00;
        big[2] = 0x03;
        big[3] = 0x08;
        @memset(big[4..], 0x5A);
        const rr: Rr = .{ .name = owner, .type = .dnskey, .class = .in, .ttl = 3600, .rdata = &big };
        var out: [8192]u8 = undefined;
        _ = &out;
        var w = std.Io.Writer.fixed(&out);
        try formatRr(&w, &rr);
        try testing.expect(std.mem.startsWith(u8, w.buffered(), "example. 3600 IN DNSKEY \\# 2048 01 00 03 08 5a"));
    }
}
