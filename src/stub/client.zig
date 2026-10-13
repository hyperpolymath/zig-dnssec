// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Validating stub resolver: sends queries (RD=1, CD=1, EDNS DO=1, RFC 8467
//! block padding) over a `Transport` and authenticates the answers with the
//! `Validator`, fetching DS/DNSKEY records through the same transport.

const std = @import("std");
const wire_name = @import("../wire/name.zig");
const types = @import("../wire/types.zig");
const message = @import("../wire/message.zig");
const builder = @import("../wire/builder.zig");
const validator_mod = @import("../dnssec/validator.zig");
const transport_mod = @import("transport.zig");

const Name = wire_name.Name;
const Type = types.Type;
const Allocator = std.mem.Allocator;

pub const QueryError = error{
    /// Response ID, QR bit, opcode or question does not match the query.
    ResponseMismatch,
};

pub const NotSecure = error{
    /// The verdict was insecure (proven), and the caller required secure.
    Insecure,
    /// Validation failed.
    Bogus,
    /// Security could not be determined (no anchor, fetch failure, ...).
    Indeterminate,
};

/// Optional hook to observe every exchange (used to record traces).
pub const Observer = struct {
    ptr: *anyopaque,
    onExchange: *const fn (ptr: *anyopaque, qname: Name, qtype: Type, response: []const u8) void,
};

pub const StubClient = struct {
    transport: transport_mod.Transport,
    anchors: *const validator_mod.TrustAnchors,
    policy: validator_mod.Policy = .{},
    /// RFC 8484 §4.1: DoH clients SHOULD use ID 0. Other transports should
    /// set a random ID.
    query_id: u16 = 0,
    /// RFC 8467 block size for query padding (0 disables padding).
    pad_block: u16 = 128,
    observer: ?Observer = null,

    /// Sends one query and returns the parsed, matched response.
    pub fn query(self: *StubClient, gpa: Allocator, qname: Name, qtype: Type) !message.Message {
        var buf: [512]u8 = undefined;
        const q = try buildQuery(&buf, self.query_id, qname, qtype, self.pad_block);
        const resp = try self.transport.exchange(gpa, q);
        defer gpa.free(resp);
        if (self.observer) |o| o.onExchange(o.ptr, qname, qtype, resp);
        var m = try message.Message.parse(gpa, resp);
        errdefer m.deinit();
        const h = m.header;
        if (h.id != self.query_id or !h.flags.qr or h.flags.opcode != .query) return error.ResponseMismatch;
        if (m.questions.len != 1) return error.ResponseMismatch;
        const mq = m.questions[0];
        if (!mq.name.eql(&qname) or mq.qtype != qtype or mq.qclass != .in) return error.ResponseMismatch;
        return m;
    }

    fn fetchThunk(ptr: *anyopaque, gpa: Allocator, qname: Name, qtype: Type) anyerror!message.Message {
        const self: *StubClient = @ptrCast(@alignCast(ptr));
        return self.query(gpa, qname, qtype);
    }

    /// Queries and validates. The returned `Result` must be `deinit`ed and
    /// its verdict inspected; nothing here treats a non-secure verdict as
    /// success.
    pub fn resolve(self: *StubClient, gpa: Allocator, qname: Name, qtype: Type, now: i64) !validator_mod.Result {
        var m = try self.query(gpa, qname, qtype);
        defer m.deinit();
        const v: validator_mod.Validator = .{
            .anchors = self.anchors,
            .policy = self.policy,
            .fetcher = .{ .ptr = self, .fetchFn = fetchThunk },
        };
        return v.validate(gpa, qname, qtype, &m, now);
    }

    /// Like `resolve`, but any verdict other than `.secure` is an error.
    /// On success the caller owns the returned Result.
    pub fn resolveSecure(self: *StubClient, gpa: Allocator, qname: Name, qtype: Type, now: i64) !validator_mod.Result {
        var r = try self.resolve(gpa, qname, qtype, now);
        switch (r.verdict) {
            .secure => return r,
            .insecure => {
                r.deinit();
                return error.Insecure;
            },
            .bogus => {
                r.deinit();
                return error.Bogus;
            },
            .indeterminate => {
                r.deinit();
                return error.Indeterminate;
            },
        }
    }
};

/// Builds the query: RD=1, CD=1 (we validate ourselves, RFC 4035 §3.2.2),
/// EDNS(0) DO=1, and an RFC 7830 Padding option sized per RFC 8467.
pub fn buildQuery(buf: []u8, id: u16, qname: Name, qtype: Type, pad_block: u16) ![]u8 {
    // Unpadded size: header + question + OPT (11) [+ padding option header 4].
    const base = message.header_len + qname.len + 4 + 11;
    var opts: [4 + 512]u8 = undefined;
    var opts_len: usize = 0;
    if (pad_block > 0) {
        const with_hdr = base + 4;
        const padded = std.mem.alignForward(usize, with_hdr, pad_block);
        const pad = padded - with_hdr;
        if (pad > 512) return error.NoSpace;
        std.mem.writeInt(u16, opts[0..2], 12, .big); // EDNS option 12: Padding
        std.mem.writeInt(u16, opts[2..4], @intCast(pad), .big);
        @memset(opts[4..][0..pad], 0);
        opts_len = 4 + pad;
    }
    var b = try builder.Builder.init(buf, .{ .id = id, .flags = .{ .rd = true, .cd = true } });
    try b.question(qname, qtype, .in);
    try b.opt(1232, true, opts[0..opts_len]);
    return b.finish();
}

test "query is padded to the block size and carries DO and CD" {
    var buf: [512]u8 = undefined;
    const q = try buildQuery(&buf, 0, try Name.fromText("www.example.org."), .aaaa, 128);
    try std.testing.expectEqual(@as(usize, 128), q.len);
    var m = try message.Message.parse(std.testing.allocator, q);
    defer m.deinit();
    try std.testing.expect(m.header.flags.cd and m.header.flags.rd);
    try std.testing.expect(m.edns.?.do_bit);
    const q2 = try buildQuery(&buf, 0, try Name.fromText("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.org."), .a, 128);
    try std.testing.expectEqual(@as(usize, 128), q2.len);
    const q3 = try buildQuery(&buf, 0, try Name.fromText("a."), .a, 0);
    try std.testing.expectEqual(@as(usize, 12 + 3 + 4 + 11), q3.len);
}
