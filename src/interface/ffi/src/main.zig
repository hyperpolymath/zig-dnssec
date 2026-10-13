// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! zig-dnssec C ABI, version 1: the Zig side of the seam.
//!
//! The contract is `src/interface/ffi/include/zig_dnssec.h`. This file does
//! not restate it: the verdict struct *is* the header's struct (through
//! translate-c), every exported function is checked at compile time to have
//! exactly the type the header declares, and every code is taken from the
//! header's macros by name, so a reason added to the validator without a
//! header macro does not compile.
//!
//! Experimental and unreviewed, like the library.

const std = @import("std");
const lib = @import("dnssec");
pub const h = @import("zig_dnssec_h");

const Allocator = std.mem.Allocator;
const validator = lib.sec.validator;
const TrustAnchors = lib.sec.anchors.TrustAnchors;
const transport = lib.stub.transport;
const StubClient = lib.stub.client.StubClient;
const Name = lib.wire.Name;
const Type = lib.wire.Type;

pub const Verdict = h.zig_dnssec_verdict;

/// Call status, valued from the header.
pub const Status = enum(c_int) {
    ok = h.ZIG_DNSSEC_OK,
    invalid_argument = h.ZIG_DNSSEC_ERR_INVALID_ARGUMENT,
    out_of_memory = h.ZIG_DNSSEC_ERR_OUT_OF_MEMORY,
    bad_anchors = h.ZIG_DNSSEC_ERR_BAD_ANCHORS,
    bad_name = h.ZIG_DNSSEC_ERR_BAD_NAME,
    bad_trace = h.ZIG_DNSSEC_ERR_BAD_TRACE,
    query_failed = h.ZIG_DNSSEC_ERR_QUERY_FAILED,
    buffer_too_small = h.ZIG_DNSSEC_ERR_BUFFER_TOO_SMALL,
};

/// verdict.security, valued from the header. `none` is 0 so that a zeroed
/// verdict never reads as secure.
pub const Security = enum(u8) {
    none = h.ZIG_DNSSEC_SECURITY_NONE,
    secure = h.ZIG_DNSSEC_SECURITY_SECURE,
    insecure = h.ZIG_DNSSEC_SECURITY_INSECURE,
    bogus = h.ZIG_DNSSEC_SECURITY_BOGUS,
    indeterminate = h.ZIG_DNSSEC_SECURITY_INDETERMINATE,
};

pub const policy_mask: u32 = h.ZIG_DNSSEC_POLICY_UNSUPPORTED_INSECURE |
    h.ZIG_DNSSEC_POLICY_ITERATIONS_INSECURE |
    h.ZIG_DNSSEC_POLICY_NO_SHA1;

fn upperComptime(comptime s: []const u8) [s.len]u8 {
    @setEvalBranchQuota(10_000);
    var out: [s.len]u8 = undefined;
    for (s, 0..) |c, i| out[i] = std.ascii.toUpper(c);
    return out;
}

/// The header macro that carries the code of reason `r`.
pub fn reasonMacro(comptime r: validator.Reason) []const u8 {
    return "ZIG_DNSSEC_REASON_" ++ upperComptime(@tagName(r));
}

/// The reason code of `r`, read from the header macro of the same name.
pub fn reasonCode(r: validator.Reason) u8 {
    @setEvalBranchQuota(100_000);
    switch (r) {
        inline else => |tag| return @field(h, reasonMacro(tag)),
    }
}

/// Reason names by code; index 0 is "none".
const reason_names: [std.enums.values(validator.Reason).len + 1][*:0]const u8 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [std.enums.values(validator.Reason).len + 1][*:0]const u8 = undefined;
    for (&t) |*e| e.* = "unknown";
    t[h.ZIG_DNSSEC_REASON_NONE] = "none";
    for (std.enums.values(validator.Reason)) |r| {
        const code = @field(h, reasonMacro(r));
        if (code >= t.len) @compileError("reason codes must be dense: " ++ reasonMacro(r));
        if (!std.mem.eql(u8, std.mem.span(t[code]), "unknown")) @compileError("duplicate reason code: " ++ reasonMacro(r));
        t[code] = @tagName(r);
    }
    break :blk t;
};

// ---------------------------------------------------------------------------
// Core, allocator-parametric (the tests run it under the leak checker)
// ---------------------------------------------------------------------------

pub const Request = struct {
    anchors: ?[*:0]const u8,
    qname: ?[*:0]const u8,
    qtype: u16,
    now: i64,
    policy: u32,
    out: ?*Verdict,
    text: ?[*]u8,
    text_cap: usize,
};

/// Runs one validation over `t` and fills the verdict. Keeps the header's
/// fail-closed rules: `security` stays NONE unless the result is OK, and
/// answer text is produced only for SECURE and INSECURE.
pub fn run(gpa: Allocator, t: transport.Transport, req: Request) Status {
    const out = req.out orelse return .invalid_argument;
    out.* = std.mem.zeroes(Verdict);
    if (req.text) |p| {
        if (req.text_cap > 0) p[0] = 0;
    }
    if (req.policy & ~policy_mask != 0) return .invalid_argument;
    const qname_z = req.qname orelse return .invalid_argument;
    const qtype = Type.fromInt(req.qtype);
    if (req.qtype == 0 or qtype.isMetaOrQtype()) return .invalid_argument;
    const qname = Name.fromText(std.mem.span(qname_z)) catch return .bad_name;

    var anchors = if (req.anchors) |a|
        TrustAnchors.fromText(gpa, std.mem.span(a)) catch |e| return switch (e) {
            error.OutOfMemory => .out_of_memory,
            else => .bad_anchors,
        }
    else
        TrustAnchors.ianaRoot(gpa) catch |e| return switch (e) {
            error.OutOfMemory => .out_of_memory,
            else => .bad_anchors,
        };
    defer anchors.deinit();
    if (anchors.anchors.len == 0) return .bad_anchors;

    var policy: validator.Policy = .{};
    if (req.policy & h.ZIG_DNSSEC_POLICY_UNSUPPORTED_INSECURE != 0) policy.unsupported_algorithm = .insecure;
    if (req.policy & h.ZIG_DNSSEC_POLICY_ITERATIONS_INSECURE != 0) policy.nsec3_iterations = .insecure;
    if (req.policy & h.ZIG_DNSSEC_POLICY_NO_SHA1 != 0) policy.allow_sha1 = false;

    var client: StubClient = .{ .transport = t, .anchors = &anchors, .policy = policy };
    var result = client.resolve(gpa, qname, qtype, req.now) catch |e| return switch (e) {
        error.OutOfMemory => .out_of_memory,
        else => .query_failed,
    };
    defer result.deinit();

    // Only the SECURE and INSECURE arms carry an answer; the failure arms
    // have no path to answer data.
    const answer: ?*const validator.Answer = switch (result.verdict) {
        .secure => |*ans| ans,
        .insecure => |*ins| &ins.answer,
        .bogus, .indeterminate => null,
    };
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    if (answer) |ans| writeAnswer(&text.writer, ans) catch return .out_of_memory;
    const body = text.written();
    const body_len = std.math.cast(u32, body.len) orelse return .out_of_memory;

    if (req.text) |p| {
        if (req.text_cap < body.len + 1) {
            out.text_len = body_len;
            return .buffer_too_small;
        }
        @memcpy(p[0..body.len], body);
        p[body.len] = 0;
    }

    out.text_len = body_len;
    out.fetches = result.stats.fetches;
    out.verifications = result.stats.verifications;
    switch (result.verdict) {
        .secure => |ans| {
            out.security = @backingInt(Security.secure);
            out.rcode = @backingInt(ans.rcode);
            out.ttl = ans.ttl;
        },
        .insecure => |ins| {
            out.security = @backingInt(Security.insecure);
            out.reason = reasonCode(ins.reason);
            out.rcode = @backingInt(ins.answer.rcode);
            out.ttl = ins.answer.ttl;
            setWhere(out, &ins.zone);
        },
        .bogus, .indeterminate => |f| {
            out.security = @backingInt(if (result.verdict == .bogus) Security.bogus else Security.indeterminate);
            out.reason = reasonCode(f.reason);
            out.rtype = f.rtype.toInt();
            setWhere(out, &f.name);
        },
    }
    return .ok;
}

fn setWhere(out: *Verdict, n: *const Name) void {
    const buf: []u8 = out.where[0 .. out.where.len - 1];
    const s = n.toText(buf);
    out.where[s.len] = 0;
}

fn writeAnswer(w: *std.Io.Writer, ans: *const validator.Answer) !void {
    for (ans.rrsets) |set| {
        for (set.rdatas) |rd| {
            const rr: lib.wire.Rr = .{ .name = set.name, .type = set.type, .class = set.class, .ttl = set.ttl, .rdata = rd };
            try lib.wire.text.formatRr(w, &rr);
            try w.writeByte('\n');
        }
    }
}

/// Transport over a caller-supplied C callback.
pub const CallbackTransport = struct {
    exchange: h.zig_dnssec_exchange_fn,
    ctx: ?*anyopaque,

    pub fn asTransport(self: *CallbackTransport) transport.Transport {
        return .{ .ptr = self, .exchangeFn = exchangeImpl };
    }

    fn exchangeImpl(ptr: *anyopaque, gpa: Allocator, query: []u8) anyerror![]u8 {
        const self: *CallbackTransport = @ptrCast(@alignCast(ptr));
        const f = self.exchange orelse return error.ExchangeFailed;
        const buf = try gpa.alloc(u8, 65535);
        errdefer gpa.free(buf);
        var len: usize = 0;
        if (f(self.ctx, query.ptr, query.len, buf.ptr, buf.len, &len) != 0) return error.ExchangeFailed;
        if (len > buf.len) return error.ExchangeFailed;
        return gpa.realloc(buf, len);
    }
};

pub fn validateWith(
    gpa: Allocator,
    exchange: h.zig_dnssec_exchange_fn,
    ctx: ?*anyopaque,
    req: Request,
) Status {
    if (exchange == null) {
        if (req.out) |o| o.* = std.mem.zeroes(Verdict);
        return .invalid_argument;
    }
    var cb: CallbackTransport = .{ .exchange = exchange, .ctx = ctx };
    return run(gpa, cb.asTransport(), req);
}

pub fn validateTraceWith(gpa: Allocator, trace: ?[*:0]const u8, req: Request) Status {
    const tz = trace orelse {
        if (req.out) |o| o.* = std.mem.zeroes(Verdict);
        return .invalid_argument;
    };
    if (req.out == null) return .invalid_argument;
    var tr = transport.Trace.parse(gpa, std.mem.span(tz)) catch |e| {
        req.out.?.* = std.mem.zeroes(Verdict);
        return switch (e) {
            error.OutOfMemory => .out_of_memory,
            else => .bad_trace,
        };
    };
    defer tr.deinit();
    var replay: transport.ReplayTransport = .{ .records = tr.records };
    return run(gpa, replay.transport(), req);
}

// ---------------------------------------------------------------------------
// Exported C functions
// ---------------------------------------------------------------------------

const c_allocator = std.heap.smp_allocator;

fn abiVersion() callconv(.c) u32 {
    return h.ZIG_DNSSEC_ABI_VERSION;
}

fn validateC(
    exchange: h.zig_dnssec_exchange_fn,
    ctx: ?*anyopaque,
    anchors: [*c]const u8,
    qname: [*c]const u8,
    qtype: u16,
    now: i64,
    policy: u32,
    out: [*c]Verdict,
    text: [*c]u8,
    text_cap: usize,
) callconv(.c) c_int {
    return @backingInt(validateWith(c_allocator, exchange, ctx, .{
        .anchors = @ptrCast(anchors),
        .qname = @ptrCast(qname),
        .qtype = qtype,
        .now = now,
        .policy = policy,
        .out = out,
        .text = text,
        .text_cap = text_cap,
    }));
}

fn validateTraceC(
    trace: [*c]const u8,
    anchors: [*c]const u8,
    qname: [*c]const u8,
    qtype: u16,
    now: i64,
    policy: u32,
    out: [*c]Verdict,
    text: [*c]u8,
    text_cap: usize,
) callconv(.c) c_int {
    return @backingInt(validateTraceWith(c_allocator, @ptrCast(trace), .{
        .anchors = @ptrCast(anchors),
        .qname = @ptrCast(qname),
        .qtype = qtype,
        .now = now,
        .policy = policy,
        .out = out,
        .text = text,
        .text_cap = text_cap,
    }));
}

fn statusName(status: c_int) callconv(.c) [*c]const u8 {
    const s = std.enums.fromInt(Status, status) orelse return "unknown";
    return @tagName(s);
}

fn securityName(security: u8) callconv(.c) [*c]const u8 {
    const s = std.enums.fromInt(Security, security) orelse return "unknown";
    return @tagName(s);
}

fn reasonName(reason: u8) callconv(.c) [*c]const u8 {
    if (reason >= reason_names.len) return "unknown";
    return reason_names[reason];
}

/// Exports each function under its header name after checking that its type
/// is exactly the type the header declares.
fn exportChecked(comptime f: anytype, comptime name: []const u8) void {
    if (@TypeOf(f) != @TypeOf(@field(h, name)))
        @compileError(name ++ ": implementation type " ++ @typeName(@TypeOf(f)) ++
            " differs from the header's " ++ @typeName(@TypeOf(@field(h, name))));
    @export(&f, .{ .name = name });
}

comptime {
    exportChecked(abiVersion, "zig_dnssec_abi_version");
    exportChecked(validateC, "zig_dnssec_validate");
    exportChecked(validateTraceC, "zig_dnssec_validate_trace");
    exportChecked(statusName, "zig_dnssec_status_name");
    exportChecked(securityName, "zig_dnssec_security_name");
    exportChecked(reasonName, "zig_dnssec_reason_name");
}
