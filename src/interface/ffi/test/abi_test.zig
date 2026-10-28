// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Tests of the C ABI. Most calls go through the header's own declarations
//! (`h.zig_dnssec_*`, the extern functions translate-c makes from
//! zig_dnssec.h), so they exercise the exported symbols with the C calling
//! convention exactly as a C caller would. The allocator-checked tests call
//! the same code through `ffi.validateTraceWith` under the leak checker.
//!
//! Fixtures are the recorded cross-check responses (tests/testdata/), replayed
//! offline.

const std = @import("std");
const testing = std.testing;
const h = @import("zig_dnssec_h");
const ffi = @import("ffi");
const lib = @import("dnssec");

const traces_src = @embedFile("crosscheck.traces");
const anchor_src = @embedFile("crosscheck-root.anchor");

/// 2026-10-14T00:00:00Z: inside the fixtures' signing window.
const now: i64 = 1791936000;

const qtype_a: u16 = 1;
const qtype_aaaa: u16 = 28;

/// The trace lines of one recorded scenario, as a NUL-terminated string.
fn scenario(gpa: std.mem.Allocator, qname: []const u8, qtype: []const u8) ![:0]u8 {
    var header_buf: [300]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buf, "@query {s} {s} ", .{ qname, qtype });
    const start = std.mem.indexOf(u8, traces_src, header) orelse return error.NoSuchScenario;
    const body_start = std.mem.indexOfScalarPos(u8, traces_src, start, '\n').? + 1;
    const end = std.mem.indexOfPos(u8, traces_src, body_start, "\n@query ") orelse traces_src.len;
    return gpa.dupeSentinel(u8, traces_src[body_start..end], 0);
}

fn poisoned() h.zig_dnssec_verdict {
    var v: h.zig_dnssec_verdict = undefined;
    @memset(std.mem.asBytes(&v), 0xAA);
    return v;
}

fn whereText(v: *const h.zig_dnssec_verdict) []const u8 {
    return std.mem.sliceTo(&v.where, 0);
}

const anchors_z: [:0]const u8 = anchor_src;

test "ABI version and layout" {
    try testing.expectEqual(@as(u32, h.ZIG_DNSSEC_ABI_VERSION), h.zig_dnssec_abi_version());
    try testing.expectEqual(@as(usize, 1048), @sizeOf(h.zig_dnssec_verdict));
    try testing.expectEqual(@as(usize, 4), @alignOf(h.zig_dnssec_verdict));
}

test "secure answer: verdict, text and NUL" {
    const trace = try scenario(testing.allocator, "www.rsasha256.test.", "A");
    defer testing.allocator.free(trace);
    var v = poisoned();
    var text: [4096]u8 = undefined;
    const rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.rsasha256.test.", qtype_a, now, 0, &v, &text, text.len);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_SECURE), v.security);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_REASON_NONE), v.reason);
    try testing.expectEqual(@as(u16, 0), v.reserved);
    try testing.expectEqual(@as(u16, 0), v.rcode);
    try testing.expectEqual(@as(u16, 0), v.rtype);
    try testing.expect(v.ttl > 0);
    try testing.expect(v.verifications > 0);
    try testing.expectEqualStrings("", whereText(&v));
    const body = text[0..v.text_len];
    try testing.expectEqual(@as(u8, 0), text[v.text_len]);
    try testing.expect(std.mem.startsWith(u8, body, "www.rsasha256.test."));
    try testing.expect(std.mem.endsWith(u8, body, "\n"));
    try testing.expect(std.mem.indexOf(u8, body, "\tA\t") != null or std.mem.indexOf(u8, body, " A ") != null);
}

test "insecure answer carries the reason, the zone and the answer" {
    const trace = try scenario(testing.allocator, "www.insecure.test.", "A");
    defer testing.allocator.free(trace);
    var v = poisoned();
    var text: [4096]u8 = undefined;
    const rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.insecure.test.", qtype_a, now, 0, &v, &text, text.len);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_INSECURE), v.security);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_REASON_INSECURE_DELEGATION), v.reason);
    try testing.expectEqualStrings("insecure.test.", whereText(&v));
    try testing.expect(v.text_len > 0);
    try testing.expect(std.mem.startsWith(u8, text[0..v.text_len], "www.insecure.test."));
}

test "bogus answer: no answer text at all" {
    const trace = try scenario(testing.allocator, "www.expired.test.", "A");
    defer testing.allocator.free(trace);
    var v = poisoned();
    var text: [4096]u8 = undefined;
    @memset(&text, 'X');
    const rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.expired.test.", qtype_a, now, 0, &v, &text, text.len);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_BOGUS), v.security);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_REASON_SIGNATURE_EXPIRED), v.reason);
    try testing.expectEqual(@as(u32, 0), v.text_len);
    try testing.expectEqual(@as(u32, 0), v.ttl);
    try testing.expect(whereText(&v).len > 0);
    try testing.expect(v.rtype != 0);
    // The buffer is the empty string; nothing past the NUL was touched.
    try testing.expectEqual(@as(u8, 0), text[0]);
    for (text[1..]) |c| try testing.expectEqual(@as(u8, 'X'), c);
}

test "every recorded bogus scenario yields no answer text through the C ABI" {
    var lines = std.mem.splitScalar(u8, traces_src, '\n');
    var checked: usize = 0;
    var text: [65536]u8 = undefined;
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "@query ")) continue;
        var it = std.mem.tokenizeScalar(u8, line[7..], ' ');
        const qname = it.next().?;
        const qtype_text = it.next().?;
        const expected = it.next().?;
        if (!std.mem.eql(u8, expected, "bogus")) continue;
        const trace = try scenario(testing.allocator, qname, qtype_text);
        defer testing.allocator.free(trace);
        const qname_z = try testing.allocator.dupeSentinel(u8, qname, 0);
        defer testing.allocator.free(qname_z);
        const qtype = lib.wire.Type.fromMnemonic(qtype_text).?.toInt();
        var v = poisoned();
        @memset(&text, 'X');
        const rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, qname_z.ptr, qtype, now, 0, &v, &text, text.len);
        try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
        // Unbound's bogus is ours too in every recorded case (tests/replay.zig).
        try testing.expect(v.security == h.ZIG_DNSSEC_SECURITY_BOGUS);
        try testing.expectEqual(@as(u32, 0), v.text_len);
        try testing.expectEqual(@as(u8, 0), text[0]);
        try testing.expectEqual(@as(u8, 'X'), text[1]);
        checked += 1;
    }
    try testing.expect(checked >= 40);
}

test "policy flags reach the validator" {
    const trace = try scenario(testing.allocator, "www.ed448.test.", "A");
    defer testing.allocator.free(trace);
    var v = poisoned();
    var rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.ed448.test.", qtype_a, now, 0, &v, null, 0);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_BOGUS), v.security);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_REASON_UNSUPPORTED_ALGORITHM), v.reason);

    rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.ed448.test.", qtype_a, now, h.ZIG_DNSSEC_POLICY_UNSUPPORTED_INSECURE, &v, null, 0);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_INSECURE), v.security);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_REASON_UNSUPPORTED_ALGORITHM_POLICY), v.reason);
    // text == NULL: verdict only, but the size is still reported.
    try testing.expect(v.text_len > 0);

    const hi = try scenario(testing.allocator, "nx.highiter.test.", "A");
    defer testing.allocator.free(hi);
    rc = h.zig_dnssec_validate_trace(hi.ptr, anchors_z.ptr, "nx.highiter.test.", qtype_a, now, 0, &v, null, 0);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_REASON_NSEC3_ITERATIONS_EXCEEDED), v.reason);
    rc = h.zig_dnssec_validate_trace(hi.ptr, anchors_z.ptr, "nx.highiter.test.", qtype_a, now, h.ZIG_DNSSEC_POLICY_ITERATIONS_INSECURE, &v, null, 0);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_INSECURE), v.security);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_REASON_NSEC3_ITERATIONS_POLICY), v.reason);
}

test "bad arguments fail closed: status set, security NONE" {
    const trace = try scenario(testing.allocator, "www.rsasha256.test.", "A");
    defer testing.allocator.free(trace);
    const T = struct {
        trace: ?[*:0]const u8,
        anchors: ?[*:0]const u8,
        qname: ?[*:0]const u8,
        qtype: u16 = qtype_a,
        policy: u32 = 0,
        expect: c_int,
    };
    const cases = [_]T{
        .{ .trace = null, .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .expect = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT },
        .{ .trace = trace.ptr, .anchors = anchors_z.ptr, .qname = null, .expect = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT },
        .{ .trace = trace.ptr, .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .policy = 8, .expect = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT },
        .{ .trace = trace.ptr, .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .policy = 0x8000_0000, .expect = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT },
        .{ .trace = trace.ptr, .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .qtype = 0, .expect = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT },
        .{ .trace = trace.ptr, .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .qtype = 255, .expect = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT },
        .{ .trace = trace.ptr, .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .qtype = 41, .expect = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT },
        // QTYPE=RRSIG (46) is refused here, not validated: nothing signs an
        // RRSIG RRset, so there is no verdict to give. Accepting it used to
        // hand the caller a bogus answer for a correctly signed response.
        .{ .trace = trace.ptr, .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .qtype = 46, .expect = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT },
        .{ .trace = trace.ptr, .anchors = anchors_z.ptr, .qname = "a..b", .expect = h.ZIG_DNSSEC_ERR_BAD_NAME },
        .{ .trace = trace.ptr, .anchors = "not an anchor", .qname = "www.rsasha256.test.", .expect = h.ZIG_DNSSEC_ERR_BAD_ANCHORS },
        .{ .trace = trace.ptr, .anchors = "", .qname = "www.rsasha256.test.", .expect = h.ZIG_DNSSEC_ERR_BAD_ANCHORS },
        .{ .trace = trace.ptr, .anchors = ". 3600 IN A 192.0.2.1\n", .qname = "www.rsasha256.test.", .expect = h.ZIG_DNSSEC_ERR_BAD_ANCHORS },
        .{ .trace = "www.rsasha256.test. A !!!not-base64!!!\n", .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .expect = h.ZIG_DNSSEC_ERR_BAD_TRACE },
        // A trace with nothing for the question: the initial query fails.
        .{ .trace = "", .anchors = anchors_z.ptr, .qname = "www.rsasha256.test.", .expect = h.ZIG_DNSSEC_ERR_QUERY_FAILED },
    };
    for (cases) |c| {
        var v = poisoned();
        var text: [64]u8 = undefined;
        @memset(&text, 'X');
        const rc = h.zig_dnssec_validate_trace(c.trace, c.anchors, c.qname, c.qtype, now, c.policy, &v, &text, text.len);
        try testing.expectEqual(c.expect, rc);
        try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_NONE), v.security);
        try testing.expectEqual(@as(u32, 0), v.text_len);
        try testing.expect(text[0] == 0 or text[0] == 'X');
    }
    // A NULL verdict pointer is rejected without writing anything.
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT), h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.rsasha256.test.", qtype_a, now, 0, null, null, 0));
}

test "NULL anchors select the IANA root, which does not sign the fixtures" {
    const trace = try scenario(testing.allocator, "www.rsasha256.test.", "A");
    defer testing.allocator.free(trace);
    var v = poisoned();
    var text: [256]u8 = undefined;
    const rc = h.zig_dnssec_validate_trace(trace.ptr, null, "www.rsasha256.test.", qtype_a, now, 0, &v, &text, text.len);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_BOGUS), v.security);
    try testing.expectEqual(@as(u32, 0), v.text_len);
}

test "a buffer that is too small: status, size needed, no verdict" {
    const trace = try scenario(testing.allocator, "www.rsasha256.test.", "A");
    defer testing.allocator.free(trace);
    var v = poisoned();
    var small: [4]u8 = undefined;
    var rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.rsasha256.test.", qtype_a, now, 0, &v, &small, small.len);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_ERR_BUFFER_TOO_SMALL), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_NONE), v.security);
    try testing.expectEqual(@as(u8, 0), small[0]);
    const need = v.text_len;
    try testing.expect(need > small.len);

    // Exactly the size needed plus the NUL is enough.
    const buf = try testing.allocator.alloc(u8, need + 1);
    defer testing.allocator.free(buf);
    rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.rsasha256.test.", qtype_a, now, 0, &v, buf.ptr, buf.len);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_SECURE), v.security);
    try testing.expectEqual(need, v.text_len);
    try testing.expectEqual(@as(u8, 0), buf[need]);
    // One byte less is not.
    rc = h.zig_dnssec_validate_trace(trace.ptr, anchors_z.ptr, "www.rsasha256.test.", qtype_a, now, 0, &v, buf.ptr, need);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_ERR_BUFFER_TOO_SMALL), rc);
}

// ---- callback transport ----------------------------------------------------

const Served = struct {
    records: []const lib.stub.transport.Recorded,
    calls: usize = 0,
    fail: bool = false,
};

fn serve(ctx: ?*anyopaque, query: [*c]const u8, query_len: usize, response: [*c]u8, cap: usize, len: [*c]usize) callconv(.c) c_int {
    const s: *Served = @ptrCast(@alignCast(ctx.?));
    s.calls += 1;
    if (s.fail) return 1;
    var replay: lib.stub.transport.ReplayTransport = .{ .records = s.records };
    const q = testing.allocator.dupe(u8, query[0..query_len]) catch return 1;
    defer testing.allocator.free(q);
    const r = replay.transport().exchange(testing.allocator, q) catch return 1;
    defer testing.allocator.free(r);
    if (r.len > cap) return 1;
    @memcpy(response[0..r.len], r);
    len.* = r.len;
    return 0;
}

test "callback transport: queries go through the caller's function" {
    const trace = try scenario(testing.allocator, "www.ecdsa256.test.", "AAAA");
    defer testing.allocator.free(trace);
    var parsed = try lib.stub.transport.Trace.parse(testing.allocator, trace);
    defer parsed.deinit();
    var served: Served = .{ .records = parsed.records };
    var v = poisoned();
    var text: [4096]u8 = undefined;
    const rc = h.zig_dnssec_validate(serve, &served, anchors_z.ptr, "www.ecdsa256.test.", qtype_aaaa, now, 0, &v, &text, text.len);
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_OK), rc);
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_SECURE), v.security);
    try testing.expectEqual(served.calls, v.fetches + 1);
    try testing.expect(std.mem.startsWith(u8, text[0..v.text_len], "www.ecdsa256.test."));

    // A failing transport on the first query is QUERY_FAILED, not a verdict.
    served = .{ .records = parsed.records, .fail = true };
    v = poisoned();
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_ERR_QUERY_FAILED), h.zig_dnssec_validate(serve, &served, anchors_z.ptr, "www.ecdsa256.test.", qtype_aaaa, now, 0, &v, &text, text.len));
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_NONE), v.security);

    // A NULL callback is an invalid argument.
    v = poisoned();
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT), h.zig_dnssec_validate(null, null, anchors_z.ptr, "www.ecdsa256.test.", qtype_aaaa, now, 0, &v, &text, text.len));
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_NONE), v.security);
}

fn lie(ctx: ?*anyopaque, query: [*c]const u8, query_len: usize, response: [*c]u8, cap: usize, len: [*c]usize) callconv(.c) c_int {
    _ = .{ ctx, query, query_len, response };
    len.* = cap + 1;
    return 0;
}

test "callback transport: a length beyond the buffer is a failed exchange" {
    var v = poisoned();
    try testing.expectEqual(@as(c_int, h.ZIG_DNSSEC_ERR_QUERY_FAILED), h.zig_dnssec_validate(lie, null, anchors_z.ptr, "www.ecdsa256.test.", qtype_aaaa, now, 0, &v, null, 0));
    try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_NONE), v.security);
}

test "names" {
    try testing.expectEqualStrings("ok", std.mem.span(h.zig_dnssec_status_name(h.ZIG_DNSSEC_OK)));
    try testing.expectEqualStrings("buffer_too_small", std.mem.span(h.zig_dnssec_status_name(h.ZIG_DNSSEC_ERR_BUFFER_TOO_SMALL)));
    try testing.expectEqualStrings("unknown", std.mem.span(h.zig_dnssec_status_name(-1)));
    try testing.expectEqualStrings("unknown", std.mem.span(h.zig_dnssec_status_name(99)));
    try testing.expectEqualStrings("none", std.mem.span(h.zig_dnssec_security_name(h.ZIG_DNSSEC_SECURITY_NONE)));
    try testing.expectEqualStrings("secure", std.mem.span(h.zig_dnssec_security_name(h.ZIG_DNSSEC_SECURITY_SECURE)));
    try testing.expectEqualStrings("indeterminate", std.mem.span(h.zig_dnssec_security_name(h.ZIG_DNSSEC_SECURITY_INDETERMINATE)));
    try testing.expectEqualStrings("unknown", std.mem.span(h.zig_dnssec_security_name(5)));
    try testing.expectEqualStrings("none", std.mem.span(h.zig_dnssec_reason_name(0)));
    try testing.expectEqualStrings("signature_expired", std.mem.span(h.zig_dnssec_reason_name(h.ZIG_DNSSEC_REASON_SIGNATURE_EXPIRED)));
    try testing.expectEqualStrings("truncated", std.mem.span(h.zig_dnssec_reason_name(h.ZIG_DNSSEC_REASON_TRUNCATED)));
    try testing.expectEqualStrings("unknown", std.mem.span(h.zig_dnssec_reason_name(30)));
    try testing.expectEqualStrings("unknown", std.mem.span(h.zig_dnssec_reason_name(255)));
    // Every validator reason has a name equal to its Zig tag.
    for (std.enums.values(lib.sec.validator.Reason)) |r| {
        try testing.expectEqualStrings(@tagName(r), std.mem.span(h.zig_dnssec_reason_name(ffi.reasonCode(r))));
    }
}

test "no leaks, through the allocator-parametric core" {
    const qs = [_]struct { n: [:0]const u8, t: []const u8, ty: u16 }{
        .{ .n = "www.rsasha256.test.", .t = "A", .ty = qtype_a },
        .{ .n = "www.insecure.test.", .t = "A", .ty = qtype_a },
        .{ .n = "www.expired.test.", .t = "A", .ty = qtype_a },
        .{ .n = "nx.ecdsa256.test.", .t = "A", .ty = qtype_a },
    };
    for (qs) |q| {
        const trace = try scenario(testing.allocator, q.n, q.t);
        defer testing.allocator.free(trace);
        var v: h.zig_dnssec_verdict = undefined;
        var text: [4096]u8 = undefined;
        const st = ffi.validateTraceWith(testing.allocator, trace.ptr, .{
            .anchors = anchors_z.ptr,
            .qname = q.n.ptr,
            .qtype = q.ty,
            .now = now,
            .policy = 0,
            .out = &v,
            .text = &text,
            .text_cap = text.len,
        });
        try testing.expectEqual(ffi.Status.ok, st);
        try testing.expect(v.security != h.ZIG_DNSSEC_SECURITY_NONE);
    }
}

test "no leaks or crashes when allocation fails at any point" {
    const trace = try scenario(testing.allocator, "www.rsasha256.test.", "A");
    defer testing.allocator.free(trace);
    var i: usize = 0;
    while (true) : (i += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        var v: h.zig_dnssec_verdict = undefined;
        var text: [4096]u8 = undefined;
        const st = ffi.validateTraceWith(failing.allocator(), trace.ptr, .{
            .anchors = anchors_z.ptr,
            .qname = "www.rsasha256.test.",
            .qtype = qtype_a,
            .now = now,
            .policy = 0,
            .out = &v,
            .text = &text,
            .text_cap = text.len,
        });
        if (!failing.has_induced_failure) {
            try testing.expectEqual(ffi.Status.ok, st);
            try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_SECURE), v.security);
            break;
        }
        // An allocation failure never produces a verdict that could be used.
        if (st != .ok) {
            try testing.expectEqual(@as(u8, h.ZIG_DNSSEC_SECURITY_NONE), v.security);
        } else {
            try testing.expect(v.security != h.ZIG_DNSSEC_SECURITY_SECURE);
        }
    }
    try testing.expect(i > 10);
}
