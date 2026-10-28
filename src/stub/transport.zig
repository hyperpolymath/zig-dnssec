// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Transport abstraction for the stub client, plus a replay transport that
//! answers from recorded responses (used by tests and offline analysis).

const std = @import("std");
const wire_name = @import("../wire/name.zig");
const types = @import("../wire/types.zig");
const message = @import("../wire/message.zig");

const Name = wire_name.Name;
const Allocator = std.mem.Allocator;

/// Sends one DNS query message and returns the response message bytes
/// (allocated with `gpa`, owned by the caller).
pub const Transport = struct {
    ptr: *anyopaque,
    exchangeFn: *const fn (ptr: *anyopaque, gpa: Allocator, query: []u8) anyerror![]u8,

    pub fn exchange(t: Transport, gpa: Allocator, query: []u8) anyerror![]u8 {
        return t.exchangeFn(t.ptr, gpa, query);
    }
};

/// A recorded exchange: the question and the raw response.
pub const Recorded = struct {
    qname: Name,
    qtype: types.Type,
    response: []const u8,
};

/// Answers queries from a fixed list of recorded responses, matching on
/// (QNAME, QTYPE) and copying the query ID into the reply. Unknown
/// questions fail with `error.NoRecordedResponse`.
pub const ReplayTransport = struct {
    records: []const Recorded,
    /// Number of exchanges served (for assertions in tests).
    served: usize = 0,

    pub fn transport(self: *ReplayTransport) Transport {
        return .{ .ptr = self, .exchangeFn = exchange };
    }

    fn exchange(ptr: *anyopaque, gpa: Allocator, query: []u8) anyerror![]u8 {
        const self: *ReplayTransport = @ptrCast(@alignCast(ptr));
        var q = try message.Message.parse(gpa, query);
        defer q.deinit();
        if (q.questions.len != 1) return error.NoRecordedResponse;
        for (self.records) |r| {
            if (r.qtype == q.questions[0].qtype and r.qname.eql(&q.questions[0].name)) {
                const out = try gpa.dupe(u8, r.response);
                if (out.len >= 2) @memcpy(out[0..2], query[0..2]);
                self.served += 1;
                return out;
            }
        }
        return error.NoRecordedResponse;
    }
};

/// Trace file format, one exchange per line:
///   <qname> <QTYPE> <base64 response>
/// Lines starting with ';' and blank lines are ignored.
pub const Trace = struct {
    arena: std.heap.ArenaAllocator,
    records: []Recorded,

    pub fn parse(gpa: Allocator, text: []const u8) !Trace {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        var list: std.ArrayList(Recorded) = .empty;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == ';') continue;
            var it = std.mem.tokenizeAny(u8, line, " \t");
            const n = it.next() orelse return error.BadTrace;
            const t = it.next() orelse return error.BadTrace;
            const b = it.next() orelse return error.BadTrace;
            if (it.next() != null) return error.BadTrace;
            const dec = std.base64.standard.Decoder;
            const len = dec.calcSizeForSlice(b) catch return error.BadTrace;
            const bytes = try a.alloc(u8, len);
            dec.decode(bytes, b) catch return error.BadTrace;
            try list.append(a, .{
                .qname = Name.fromText(n) catch return error.BadTrace,
                .qtype = types.Type.fromMnemonic(t) orelse return error.BadTrace,
                .response = bytes,
            });
        }
        return .{ .arena = arena, .records = list.items };
    }

    pub fn deinit(t: *Trace) void {
        t.arena.deinit();
        t.* = undefined;
    }

    pub fn writeLine(w: *std.Io.Writer, qname: Name, qtype: types.Type, response: []const u8) !void {
        var tb: [16]u8 = undefined;
        try qname.format(w);
        try w.print(" {s} ", .{qtype.mnemonic(&tb)});
        try std.base64.standard.Encoder.encodeWriter(w, response);
        try w.writeByte('\n');
    }
};
