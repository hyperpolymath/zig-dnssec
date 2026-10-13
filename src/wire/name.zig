// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Domain names (RFC 1035 §3.1, §4.1.4) and DNSSEC canonical ordering
//! (RFC 4034 §6.1).
//!
//! A `Name` always holds an *uncompressed* wire-format name, including the
//! terminating root label, in a fixed 255-octet buffer. Construction goes
//! through validating functions only (`fromWire`, `fromText`, `readFromMessage`),
//! so a `Name` value that came out of this module is always well formed:
//! every label is 1..63 octets, the total length is at most 255 octets, and
//! the last octet is the zero-length root label.

const std = @import("std");

pub const max_wire_len = 255;
pub const max_label_len = 63;
/// 255 octets allows at most 127 one-octet labels plus the root label.
pub const max_labels = 127;

pub const Error = error{
    /// The input ended before the name was complete.
    Truncated,
    /// The name would exceed 255 octets in uncompressed wire form.
    NameTooLong,
    /// A label longer than 63 octets.
    LabelTooLong,
    /// Label type bits 0b01 or 0b10 (extended / binary labels, deprecated).
    BadLabelType,
    /// A compression pointer that does not point strictly backwards, points
    /// into the header, or appears where compression is forbidden.
    BadPointer,
    /// Presentation-format syntax error.
    InvalidText,
    /// An empty (non-root) label in presentation format, e.g. "a..b".
    EmptyLabel,
};

pub const Name = struct {
    buf: [max_wire_len]u8 = undefined,
    /// Total octets including the root label; 1 for the root name.
    len: u8,

    pub const root: Name = blk: {
        var n: Name = .{ .len = 1 };
        n.buf[0] = 0;
        break :blk n;
    };

    /// The uncompressed wire representation, including the root label.
    pub fn bytes(self: *const Name) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn isRoot(self: *const Name) bool {
        return self.len == 1;
    }

    /// Validates an uncompressed wire-format name occupying the whole slice.
    pub fn fromWire(wire: []const u8) Error!Name {
        var pos: usize = 0;
        const n = try readUncompressed(wire, &pos);
        if (pos != wire.len) return error.InvalidText;
        return n;
    }

    /// Reads an uncompressed name starting at `pos.*` (compression pointers
    /// are rejected). Advances `pos`.
    pub fn readUncompressed(data: []const u8, pos: *usize) Error!Name {
        var out: Name = .{ .len = 0 };
        var p = pos.*;
        while (true) {
            if (p >= data.len) return error.Truncated;
            const b = data[p];
            switch (b & 0xC0) {
                0x00 => {
                    const l: usize = b;
                    // Computed in usize: `out.len` is a u8. A non-root label must
                    // leave room for the terminating root label.
                    const new_len = @as(usize, out.len) + 1 + l;
                    if (new_len > max_wire_len or (l != 0 and new_len == max_wire_len)) return error.NameTooLong;
                    if (p + 1 + l > data.len) return error.Truncated;
                    out.buf[out.len] = b;
                    @memcpy(out.buf[out.len + 1 ..][0..l], data[p + 1 ..][0..l]);
                    out.len += @intCast(1 + l);
                    p += 1 + l;
                    if (l == 0) break;
                },
                0xC0 => return error.BadPointer,
                else => return error.BadLabelType,
            }
        }
        pos.* = p;
        return out;
    }

    /// Reads a possibly-compressed name from a complete DNS message.
    ///
    /// Compression pointers must point strictly before the start of the
    /// label run that contains them and must not point into the 12-octet
    /// header. Targets therefore strictly decrease, which guarantees
    /// termination without a hop counter. `pos.*` is advanced past the name
    /// as it appears at the original position (i.e. past the first pointer).
    pub fn readFromMessage(msg: []const u8, pos: *usize) Error!Name {
        var out: Name = .{ .len = 0 };
        var p = pos.*;
        var run_start = p;
        var end_pos: ?usize = null;
        while (true) {
            if (p >= msg.len) return error.Truncated;
            const b = msg[p];
            switch (b & 0xC0) {
                0x00 => {
                    const l: usize = b;
                    // Computed in usize: `out.len` is a u8. A non-root label must
                    // leave room for the terminating root label.
                    const new_len = @as(usize, out.len) + 1 + l;
                    if (new_len > max_wire_len or (l != 0 and new_len == max_wire_len)) return error.NameTooLong;
                    if (p + 1 + l > msg.len) return error.Truncated;
                    out.buf[out.len] = b;
                    @memcpy(out.buf[out.len + 1 ..][0..l], msg[p + 1 ..][0..l]);
                    out.len += @intCast(1 + l);
                    p += 1 + l;
                    if (l == 0) break;
                },
                0xC0 => {
                    if (p + 1 >= msg.len) return error.Truncated;
                    const target: usize = (@as(usize, b & 0x3F) << 8) | msg[p + 1];
                    if (target < 12 or target >= run_start) return error.BadPointer;
                    if (end_pos == null) end_pos = p + 2;
                    run_start = target;
                    p = target;
                },
                else => return error.BadLabelType,
            }
        }
        pos.* = end_pos orelse p;
        return out;
    }

    /// Parses an absolute presentation-format name ("www.example.com.").
    /// A missing trailing dot is accepted only if `origin` is null, in which
    /// case the name is treated as absolute. Supports `\.`-style and `\DDD`
    /// escapes (RFC 1035 §5.1).
    pub fn fromText(text: []const u8) Error!Name {
        return fromTextRelative(text, null);
    }

    /// Like `fromText`, but a name without a trailing dot is made relative to
    /// `origin` (when given). "@" denotes the origin.
    pub fn fromTextRelative(text: []const u8, origin: ?*const Name) Error!Name {
        if (text.len == 0) return error.InvalidText;
        if (std.mem.eql(u8, text, "@")) {
            if (origin) |o| return o.*;
            return error.InvalidText;
        }
        if (std.mem.eql(u8, text, ".")) return root;

        var out: Name = .{ .len = 0 };
        var lbl: [max_label_len]u8 = undefined;
        var label_len: usize = 0;
        var i: usize = 0;
        var absolute = false;
        while (i < text.len) {
            const c = text[i];
            if (c == '.') {
                if (label_len == 0) return error.EmptyLabel;
                try out.appendLabel(lbl[0..label_len]);
                label_len = 0;
                i += 1;
                if (i == text.len) absolute = true;
                continue;
            }
            var octet: u8 = c;
            if (c == '\\') {
                if (i + 1 >= text.len) return error.InvalidText;
                const d = text[i + 1];
                if (std.ascii.isDigit(d)) {
                    if (i + 4 > text.len) return error.InvalidText;
                    const ds = text[i + 1 .. i + 4];
                    for (ds) |x| if (!std.ascii.isDigit(x)) return error.InvalidText;
                    const v = std.fmt.parseInt(u16, ds, 10) catch return error.InvalidText;
                    if (v > 255) return error.InvalidText;
                    octet = @intCast(v);
                    i += 4;
                } else {
                    octet = d;
                    i += 2;
                }
            } else {
                i += 1;
            }
            if (label_len >= max_label_len) return error.LabelTooLong;
            lbl[label_len] = octet;
            label_len += 1;
        }
        if (label_len > 0) try out.appendLabel(lbl[0..label_len]);
        if (!absolute) {
            if (origin) |o| {
                if (out.len + o.len > max_wire_len) return error.NameTooLong;
                @memcpy(out.buf[out.len..][0..o.len], o.bytes());
                out.len += o.len;
                return out;
            }
        }
        if (out.len + 1 > max_wire_len) return error.NameTooLong;
        out.buf[out.len] = 0;
        out.len += 1;
        return out;
    }

    fn appendLabel(self: *Name, l: []const u8) Error!void {
        if (l.len == 0) return error.EmptyLabel;
        if (l.len > max_label_len) return error.LabelTooLong;
        // Reserve one octet for the root label that must still follow.
        if (@as(usize, self.len) + 1 + l.len + 1 > max_wire_len) return error.NameTooLong;
        self.buf[self.len] = @intCast(l.len);
        @memcpy(self.buf[self.len + 1 ..][0..l.len], l);
        self.len += @intCast(1 + l.len);
    }

    /// Number of labels, not counting the root label (RFC 4034 §3.1.3 rules:
    /// a leading "*" label is not counted by `rrsigLabelCount`).
    pub fn labelCount(self: *const Name) u8 {
        var count: u8 = 0;
        var p: usize = 0;
        while (self.buf[p] != 0) : (p += 1 + self.buf[p]) count += 1;
        return count;
    }

    /// The "Labels" value an RRSIG over this owner would carry
    /// (RFC 4034 §3.1.3): label count excluding root and a leading wildcard.
    pub fn rrsigLabelCount(self: *const Name) u8 {
        const c = self.labelCount();
        return if (self.isWildcard()) c - 1 else c;
    }

    pub fn isWildcard(self: *const Name) bool {
        return self.len >= 3 and self.buf[0] == 1 and self.buf[1] == '*';
    }

    /// Returns the i-th label (0 = leftmost), without its length octet.
    pub fn label(self: *const Name, index: usize) []const u8 {
        var p: usize = 0;
        var i: usize = 0;
        while (self.buf[p] != 0) : (p += 1 + self.buf[p]) {
            if (i == index) return self.buf[p + 1 ..][0..self.buf[p]];
            i += 1;
        }
        return &.{};
    }

    /// Fills `offsets` with the start offset of each non-root label and
    /// returns how many there are.
    fn labelOffsets(self: *const Name, offsets: *[max_labels]u8) usize {
        var n: usize = 0;
        var p: usize = 0;
        while (self.buf[p] != 0) : (p += 1 + self.buf[p]) {
            offsets[n] = @intCast(p);
            n += 1;
        }
        return n;
    }

    /// The parent name (leftmost label removed), or null for the root.
    pub fn parent(self: *const Name) ?Name {
        if (self.isRoot()) return null;
        const skip: usize = 1 + @as(usize, self.buf[0]);
        var out: Name = .{ .len = self.len - @as(u8, @intCast(skip)) };
        @memcpy(out.buf[0..out.len], self.buf[skip..self.len]);
        return out;
    }

    /// The rightmost `n` labels of this name (n <= labelCount()).
    pub fn suffix(self: *const Name, n: usize) Name {
        const total = self.labelCount();
        std.debug.assert(n <= total);
        var out = self.*;
        var drop = total - n;
        while (drop > 0) : (drop -= 1) out = out.parent().?;
        return out;
    }

    /// Prepends one label, e.g. `example.` + "*" -> `*.example.`.
    pub fn prepend(self: *const Name, l: []const u8) Error!Name {
        if (l.len == 0) return error.EmptyLabel;
        if (l.len > max_label_len) return error.LabelTooLong;
        if (@as(usize, self.len) + 1 + l.len > max_wire_len) return error.NameTooLong;
        var out: Name = .{ .len = 0 };
        out.buf[0] = @intCast(l.len);
        @memcpy(out.buf[1..][0..l.len], l);
        @memcpy(out.buf[1 + l.len ..][0..self.len], self.bytes());
        out.len = @intCast(1 + l.len + self.len);
        return out;
    }

    /// ASCII-lowercased copy (RFC 4034 §6.2: only A-Z are folded).
    pub fn lowercase(self: *const Name) Name {
        var out = self.*;
        var p: usize = 0;
        while (out.buf[p] != 0) : (p += 1 + out.buf[p]) {
            for (out.buf[p + 1 ..][0..out.buf[p]]) |*c| c.* = std.ascii.toLower(c.*);
        }
        return out;
    }

    /// Case-insensitive equality (DNS names compare ASCII-case-insensitively).
    pub fn eql(a: *const Name, b: *const Name) bool {
        if (a.len != b.len) return false;
        // Length octets are < 64 and so unaffected by toLower.
        for (a.bytes(), b.bytes()) |x, y| {
            if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
        }
        return true;
    }

    /// True if `self` is `ancestor` or a descendant of it.
    pub fn isSubdomainOf(self: *const Name, ancestor: *const Name) bool {
        if (ancestor.len > self.len) return false;
        const self_labels = self.labelCount();
        const anc_labels = ancestor.labelCount();
        if (anc_labels > self_labels) return false;
        const tail = self.suffix(anc_labels);
        return tail.eql(ancestor);
    }

    /// True if `self` is a proper (strict) descendant of `ancestor`.
    pub fn isStrictSubdomainOf(self: *const Name, ancestor: *const Name) bool {
        return self.labelCount() > ancestor.labelCount() and self.isSubdomainOf(ancestor);
    }

    /// Number of rightmost labels shared with `other` (case-insensitive).
    pub fn commonSuffixLabels(a: *const Name, b: *const Name) usize {
        var oa: [max_labels]u8 = undefined;
        var ob: [max_labels]u8 = undefined;
        const na = a.labelOffsets(&oa);
        const nb = b.labelOffsets(&ob);
        var k: usize = 0;
        while (k < na and k < nb) : (k += 1) {
            const la = a.buf[oa[na - 1 - k]..][0 .. 1 + @as(usize, a.buf[oa[na - 1 - k]])];
            const lb = b.buf[ob[nb - 1 - k]..][0 .. 1 + @as(usize, b.buf[ob[nb - 1 - k]])];
            if (!std.ascii.eqlIgnoreCase(la, lb)) break;
        }
        return k;
    }

    /// RFC 4034 §6.1 canonical ordering: compare label by label from the
    /// rightmost, each label as a left-justified octet string after
    /// lowercasing; a missing label sorts first.
    pub fn canonicalOrder(a: *const Name, b: *const Name) std.math.Order {
        var oa: [max_labels]u8 = undefined;
        var ob: [max_labels]u8 = undefined;
        const na = a.labelOffsets(&oa);
        const nb = b.labelOffsets(&ob);
        var k: usize = 0;
        while (k < na and k < nb) : (k += 1) {
            const pa = oa[na - 1 - k];
            const pb = ob[nb - 1 - k];
            const la = a.buf[pa + 1 ..][0..a.buf[pa]];
            const lb = b.buf[pb + 1 ..][0..b.buf[pb]];
            const ord = orderLabel(la, lb);
            if (ord != .eq) return ord;
        }
        return std.math.order(na, nb);
    }

    pub fn canonicalLessThan(a: *const Name, b: *const Name) bool {
        return canonicalOrder(a, b) == .lt;
    }

    /// Writes the presentation format (always absolute, with trailing dot).
    pub fn format(self: *const Name, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.isRoot()) return w.writeAll(".");
        var p: usize = 0;
        while (self.buf[p] != 0) : (p += 1 + self.buf[p]) {
            for (self.buf[p + 1 ..][0..self.buf[p]]) |c| {
                if (std.mem.findScalar(u8, ".\\\"();@$", c) != null) {
                    try w.print("\\{c}", .{c});
                } else if (c >= 0x21 and c <= 0x7E) {
                    try w.writeByte(c);
                } else {
                    try w.print("\\{d:0>3}", .{c});
                }
            }
            try w.writeByte('.');
        }
    }

    /// Renders into `buf`; returns the written slice.
    pub fn toText(self: *const Name, buf: []u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        self.format(&w) catch return buf[0..w.end];
        return w.buffered();
    }
};

fn orderLabel(a: []const u8, b: []const u8) std.math.Order {
    const n = @min(a.len, b.len);
    for (a[0..n], b[0..n]) |x, y| {
        const lx = std.ascii.toLower(x);
        const ly = std.ascii.toLower(y);
        if (lx < ly) return .lt;
        if (lx > ly) return .gt;
    }
    return std.math.order(a.len, b.len);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "fromText and format round trip" {
    var buf: [512]u8 = undefined;
    const n = try Name.fromText("www.Example.COM.");
    try testing.expectEqualStrings("www.Example.COM.", n.toText(&buf));
    try testing.expectEqual(@as(u8, 3), n.labelCount());
    const r = try Name.fromText(".");
    try testing.expect(r.isRoot());
    try testing.expectEqualStrings(".", r.toText(&buf));
    const e = try Name.fromText("a\\.b.c\\032d.");
    try testing.expectEqual(@as(u8, 2), e.labelCount());
    try testing.expectEqualStrings("a\\.b.c\\032d.", e.toText(&buf));
}

test "fromText rejects malformed names" {
    try testing.expectError(error.EmptyLabel, Name.fromText("a..b."));
    try testing.expectError(error.EmptyLabel, Name.fromText(".a."));
    try testing.expectError(error.InvalidText, Name.fromText("a\\25"));
    try testing.expectError(error.InvalidText, Name.fromText("a\\256."));
    const long_label = (rep('a', 64) ++ ".");
    try testing.expectError(error.LabelTooLong, Name.fromText(long_label));
    // 4 * 63-octet labels = 256 octets with length bytes, + root = too long.
    const l63 = rep('b', 63);
    try testing.expectError(error.NameTooLong, Name.fromText((l63 ++ "." ++ l63 ++ "." ++ l63 ++ "." ++ l63 ++ ".")));
    // 3*64 + 62 = 254 octets of labels + root = 255: exactly the maximum.
    const ok = try Name.fromText((l63 ++ "." ++ l63 ++ "." ++ l63 ++ "." ++ rep('c', 61) ++ "."));
    try testing.expectEqual(@as(u8, 255), ok.len);
}

test "RFC 4034 §6.1 canonical ordering example" {
    // The example list from RFC 4034 §6.1, already in canonical order.
    const names = [_][]const u8{
        "example.",         "a.example.",      "yljkjljk.a.example.",
        "Z.a.example.",     "zABC.a.EXAMPLE.", "z.example.",
        "\\001.z.example.", "*.z.example.",    "\\200.z.example.",
    };
    var parsed: [names.len]Name = undefined;
    for (names, 0..) |t, i| parsed[i] = try Name.fromText(t);
    for (0..names.len - 1) |i| {
        try testing.expectEqual(std.math.Order.lt, parsed[i].canonicalOrder(&parsed[i + 1]));
        try testing.expectEqual(std.math.Order.gt, parsed[i + 1].canonicalOrder(&parsed[i]));
    }
    try testing.expectEqual(std.math.Order.eq, parsed[3].canonicalOrder(&(try Name.fromText("z.A.example."))));
}

test "subdomain, parent, suffix, wildcard" {
    const n = try Name.fromText("a.b.example.");
    const ex = try Name.fromText("EXAMPLE.");
    try testing.expect(n.isSubdomainOf(&ex));
    try testing.expect(n.isStrictSubdomainOf(&ex));
    try testing.expect(ex.isSubdomainOf(&ex));
    try testing.expect(!ex.isStrictSubdomainOf(&ex));
    try testing.expect(n.isSubdomainOf(&Name.root));
    try testing.expect(!ex.isSubdomainOf(&n));
    const notsub = try Name.fromText("xexample.");
    try testing.expect(!notsub.isSubdomainOf(&ex));
    try testing.expect(n.parent().?.eql(&(try Name.fromText("b.example."))));
    try testing.expect(n.suffix(1).eql(&ex));
    try testing.expect(n.suffix(0).isRoot());
    const w = try ex.prepend("*");
    try testing.expect(w.isWildcard());
    try testing.expectEqual(@as(u8, 1), w.rrsigLabelCount());
    try testing.expectEqual(@as(usize, 1), n.commonSuffixLabels(&(try Name.fromText("c.Example."))));
}

test "RFC 1035 §4.1.4 compression example" {
    // F.ISI.ARPA at offset 20, FOO.F.ISI.ARPA at 40 (FOO + ptr 20),
    // ARPA at 64 (ptr 26), root at 92.
    var msg = @as([100]u8, @splat(0));
    const f_isi_arpa = [_]u8{ 1, 'F', 3, 'I', 'S', 'I', 4, 'A', 'R', 'P', 'A', 0 };
    @memcpy(msg[20..32], &f_isi_arpa);
    msg[40] = 3;
    @memcpy(msg[41..44], "FOO");
    msg[44] = 0xC0;
    msg[45] = 20;
    msg[64] = 0xC0;
    msg[65] = 26;
    msg[92] = 0;

    var pos: usize = 20;
    const a = try Name.readFromMessage(&msg, &pos);
    try testing.expectEqual(@as(usize, 32), pos);
    try testing.expect(a.eql(&(try Name.fromText("f.isi.arpa."))));
    pos = 40;
    const b = try Name.readFromMessage(&msg, &pos);
    try testing.expectEqual(@as(usize, 46), pos);
    try testing.expect(b.eql(&(try Name.fromText("foo.f.isi.arpa."))));
    pos = 64;
    const c = try Name.readFromMessage(&msg, &pos);
    try testing.expectEqual(@as(usize, 66), pos);
    try testing.expect(c.eql(&(try Name.fromText("arpa."))));
    pos = 92;
    const d = try Name.readFromMessage(&msg, &pos);
    try testing.expect(d.isRoot());
    try testing.expectEqual(@as(usize, 93), pos);
}

test "compression pointer abuse is rejected" {
    var msg = @as([40]u8, @splat(0));
    // Self-pointer at 20.
    msg[20] = 0xC0;
    msg[21] = 20;
    var pos: usize = 20;
    try testing.expectError(error.BadPointer, Name.readFromMessage(&msg, &pos));
    // Forward pointer.
    msg[20] = 0xC0;
    msg[21] = 30;
    pos = 20;
    try testing.expectError(error.BadPointer, Name.readFromMessage(&msg, &pos));
    // Pointer into header.
    msg[20] = 0xC0;
    msg[21] = 4;
    pos = 20;
    try testing.expectError(error.BadPointer, Name.readFromMessage(&msg, &pos));
    // Loop: 14: "a" ptr->16?  label at 14 'a', pointer at 16 -> 14 (not < run start 14).
    msg[14] = 1;
    msg[15] = 'a';
    msg[16] = 0xC0;
    msg[17] = 14;
    pos = 14;
    try testing.expectError(error.BadPointer, Name.readFromMessage(&msg, &pos));
    // Two-step loop: 30 -> 22 -> label "b" then pointer to 26 (> 22): rejected.
    msg[22] = 1;
    msg[23] = 'b';
    msg[24] = 0xC0;
    msg[25] = 26;
    msg[26] = 0xC0;
    msg[27] = 22;
    msg[30] = 0xC0;
    msg[31] = 22;
    pos = 30;
    try testing.expectError(error.BadPointer, Name.readFromMessage(&msg, &pos));
    // Extended label types.
    msg[20] = 0x41;
    pos = 20;
    try testing.expectError(error.BadLabelType, Name.readFromMessage(&msg, &pos));
    msg[20] = 0x80;
    pos = 20;
    try testing.expectError(error.BadLabelType, Name.readFromMessage(&msg, &pos));
    // Truncated label.
    const short = [_]u8{ 5, 'a', 'b' };
    pos = 0;
    try testing.expectError(error.Truncated, Name.readFromMessage(&short, &pos));
    // Truncated pointer.
    const tp = @as([13]u8, @splat(0)) ++ [_]u8{0xC0};
    pos = 13;
    try testing.expectError(error.Truncated, Name.readFromMessage(&tp, &pos));
}

test "compressed name longer than 255 octets is rejected" {
    // Build a chain: each name adds a 63-octet label in front of the previous.
    var msg: [400]u8 = @as([400]u8, @splat(0));
    var off: usize = 12;
    msg[off] = 0; // root at 12
    var prev: usize = 12;
    off = 13;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const start = off;
        msg[off] = 63;
        @memset(msg[off + 1 .. off + 64], 'x');
        msg[off + 64] = 0xC0 | @as(u8, @intCast(prev >> 8));
        msg[off + 65] = @intCast(prev & 0xFF);
        prev = start;
        off += 66;
    }
    var pos: usize = prev;
    try testing.expectError(error.NameTooLong, Name.readFromMessage(&msg, &pos));
}

fn rep(comptime c: u8, comptime n: usize) [n]u8 {
    return @splat(c);
}

test "regression (fuzzer): labels reaching exactly 255 octets without a root label" {
    // 3*64 + 62 = 254 octets of labels; one more label would make 256 with
    // the root: NameTooLong, never an integer overflow of the u8 length.
    var msg: [12 + 300]u8 = @splat(0);
    var p: usize = 12;
    for (0..3) |_| {
        msg[p] = 63;
        @memset(msg[p + 1 .. p + 64], 'a');
        p += 64;
    }
    msg[p] = 61;
    @memset(msg[p + 1 .. p + 62], 'b');
    p += 62; // 254 octets of labels so far, no root yet
    msg[p] = 1;
    msg[p + 1] = 'c';
    msg[p + 2] = 0;
    var pos: usize = 12;
    try testing.expectError(error.NameTooLong, Name.readFromMessage(&msg, &pos));
    pos = 12;
    try testing.expectError(error.NameTooLong, Name.readUncompressed(&msg, &pos));
    // 254 octets of labels + root = 255: the maximum, accepted.
    msg[p] = 0;
    pos = 12;
    const n = try Name.readFromMessage(&msg, &pos);
    try testing.expectEqual(@as(u8, 255), n.len);
}
