// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! dnssec-stub: query a name over DoH and print the validation verdict.
//!
//!   dnssec-stub [options] NAME TYPE
//!     --doh URL        DoH endpoint (default https://dns.quad9.net/dns-query)
//!     --ca FILE        PEM CA bundle to trust instead of the system store
//!     --anchors FILE   trust anchors (DS/DNSKEY presentation format);
//!                      default: the built-in IANA root DS records
//!     --now SECONDS    validation time (default: system clock)
//!     --record FILE    append every exchange to a trace file
//!     --replay FILE    answer from a trace file instead of the network
//!     --unsupported-insecure   policy: unsupported algorithms -> insecure
//!     --iterations-insecure    policy: NSEC3 iterations over limit -> insecure
//!     --no-sha1        policy: refuse SHA-1 based algorithms and digests
//!     --no-proxy       ignore https_proxy (it is used, via CONNECT, otherwise)
//!
//! Output: one line "verdict=<v> reason=<r> at=<name> rcode=<rc>" followed by
//! the answer chain for secure/insecure verdicts. Exit status 0 = secure,
//! 1 = insecure, 2 = bogus, 3 = indeterminate, 4 = usage/transport error.

const std = @import("std");
const lib = @import("dnssec");

const Name = lib.wire.Name;
const Type = lib.wire.Type;

const Recorder = struct {
    w: *std.Io.Writer,

    fn on(ptr: *anyopaque, qname: Name, qtype: Type, response: []const u8) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        lib.stub.transport.Trace.writeLine(self.w, qname, qtype, response) catch {};
        self.w.flush() catch {};
    }
};

fn usage() noreturn {
    std.debug.print("usage: dnssec-stub [--doh URL] [--ca FILE] [--anchors FILE] [--now S] [--record FILE] [--replay FILE] [--unsupported-insecure] [--iterations-insecure] [--no-sha1] NAME TYPE\n", .{});
    std.process.exit(4);
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    var doh_url: []const u8 = "https://dns.quad9.net/dns-query";
    var ca_file: ?[]const u8 = null;
    var anchors_file: ?[]const u8 = null;
    var now_arg: ?i64 = null;
    var record_file: ?[]const u8 = null;
    var replay_file: ?[]const u8 = null;
    var no_proxy = false;
    var policy: lib.sec.validator.Policy = .{};
    var positional: std.ArrayList([]const u8) = .empty;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const needsValue = struct {
            fn f(all: []const [:0]const u8, idx: *usize) []const u8 {
                idx.* += 1;
                if (idx.* >= all.len) usage();
                return all[idx.*];
            }
        }.f;
        if (std.mem.eql(u8, a, "--doh")) {
            doh_url = needsValue(args, &i);
        } else if (std.mem.eql(u8, a, "--ca")) {
            ca_file = needsValue(args, &i);
        } else if (std.mem.eql(u8, a, "--anchors")) {
            anchors_file = needsValue(args, &i);
        } else if (std.mem.eql(u8, a, "--now")) {
            now_arg = std.fmt.parseInt(i64, needsValue(args, &i), 10) catch usage();
        } else if (std.mem.eql(u8, a, "--record")) {
            record_file = needsValue(args, &i);
        } else if (std.mem.eql(u8, a, "--replay")) {
            replay_file = needsValue(args, &i);
        } else if (std.mem.eql(u8, a, "--unsupported-insecure")) {
            policy.unsupported_algorithm = .insecure;
        } else if (std.mem.eql(u8, a, "--iterations-insecure")) {
            policy.nsec3_iterations = .insecure;
        } else if (std.mem.eql(u8, a, "--no-proxy")) {
            no_proxy = true;
        } else if (std.mem.eql(u8, a, "--no-sha1")) {
            policy.allow_sha1 = false;
        } else if (a.len > 0 and a[0] == '-') {
            usage();
        } else {
            try positional.append(arena, a);
        }
    }
    if (positional.items.len != 2) usage();
    const qname = Name.fromText(positional.items[0]) catch {
        std.debug.print("bad name\n", .{});
        return 4;
    };
    const qtype = Type.fromMnemonic(positional.items[1]) orelse {
        std.debug.print("bad type\n", .{});
        return 4;
    };

    const cwd = std.Io.Dir.cwd();
    var anchors = if (anchors_file) |f| blk: {
        const src = try cwd.readFileAlloc(io, f, arena, .limited(1 << 20));
        break :blk try lib.sec.anchors.TrustAnchors.fromText(gpa, src);
    } else try lib.sec.anchors.TrustAnchors.ianaRoot(gpa);
    defer anchors.deinit();

    const now: i64 = now_arg orelse std.Io.Clock.real.now(io).toSeconds();

    // Transport: replay or DoH.
    var replay: lib.stub.transport.ReplayTransport = undefined;
    var trace: ?lib.stub.transport.Trace = null;
    defer if (trace) |*t| t.deinit();
    var doh: lib.stub.doh.DohTransport = undefined;
    var transport: lib.stub.transport.Transport = undefined;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    if (replay_file) |f| {
        const src = try cwd.readFileAlloc(io, f, arena, .limited(64 << 20));
        trace = try lib.stub.transport.Trace.parse(gpa, src);
        replay = .{ .records = trace.?.records };
        transport = replay.transport();
    } else {
        const ts = std.Io.Clock.real.now(io);
        if (ca_file) |f| {
            try bundle.addCertsFromFilePath(gpa, io, ts, cwd, f);
        } else {
            try bundle.rescan(gpa, io, ts);
        }
        // An HTTP CONNECT proxy from https_proxy, except for loopback targets.
        var proxy: ?lib.stub.doh.Proxy = null;
        if (!no_proxy and !isLoopbackUrl(doh_url)) {
            const env = init.environ_map.get("https_proxy") orelse init.environ_map.get("HTTPS_PROXY");
            if (env) |p| proxy = try lib.stub.doh.Proxy.parse(p);
        }
        doh = try lib.stub.doh.DohTransport.init(io, doh_url, &bundle, proxy);
        transport = doh.transport();
    }

    var stub: lib.stub.client.StubClient = .{ .transport = transport, .anchors = &anchors, .policy = policy };

    var rec_buf: [4096]u8 = undefined;
    var rec_file: ?std.Io.File = null;
    var rec_writer: std.Io.File.Writer = undefined;
    var recorder: Recorder = undefined;
    if (record_file) |f| {
        rec_file = try cwd.createFile(io, f, .{ .truncate = false });
        rec_writer = rec_file.?.writer(io, &rec_buf);
        try rec_writer.seekTo(try rec_file.?.length(io));
        recorder = .{ .w = &rec_writer.interface };
        stub.observer = .{ .ptr = &recorder, .onExchange = Recorder.on };
    }
    defer if (rec_file) |file| file.close(io);

    var out_buf: [8192]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &out_buf);
    const w = &out.interface;
    defer w.flush() catch {};

    var result = stub.resolve(gpa, qname, qtype, now) catch |e| {
        try w.print("verdict=error reason={t}\n", .{e});
        return 4;
    };
    defer result.deinit();

    var nb: [1024]u8 = undefined;
    switch (result.verdict) {
        .secure => |ans| {
            try w.print("verdict=secure reason=- at=- rcode={t}\n", .{ans.rcode});
            try printAnswer(w, &ans);
        },
        .insecure => |ins| {
            try w.print("verdict=insecure reason={t} at={s} rcode={t}\n", .{ ins.reason, ins.zone.toText(&nb), ins.answer.rcode });
            try printAnswer(w, &ins.answer);
        },
        .bogus => |f| {
            try w.print("verdict=bogus reason={t} at={s} type={t}", .{ f.reason, f.name.toText(&nb), f.rtype });
            if (f.detail) |d| try w.print(" detail={t}", .{d});
            try w.writeByte('\n');
        },
        .indeterminate => |f| {
            try w.print("verdict=indeterminate reason={t} at={s} type={t}", .{ f.reason, f.name.toText(&nb), f.rtype });
            if (f.detail) |d| try w.print(" detail={t}", .{d});
            try w.writeByte('\n');
        },
    }
    try w.print("; fetches={d} verifications={d}\n", .{ result.stats.fetches, result.stats.verifications });
    return switch (result.verdict) {
        .secure => 0,
        .insecure => 1,
        .bogus => 2,
        .indeterminate => 3,
    };
}

fn isLoopbackUrl(url: []const u8) bool {
    const uri = std.Uri.parse(url) catch return false;
    const host = uri.host orelse return false;
    const h = switch (host) {
        .raw => |r| r,
        .percent_encoded => |p| p,
    };
    return std.mem.eql(u8, h, "localhost") or std.mem.eql(u8, h, "127.0.0.1") or std.mem.eql(u8, h, "[::1]");
}

fn printAnswer(w: *std.Io.Writer, ans: *const lib.sec.validator.Answer) !void {
    for (ans.rrsets) |set| {
        for (set.rdatas) |rd| {
            const rr: lib.wire.Rr = .{ .name = set.name, .type = set.type, .class = set.class, .ttl = set.ttl, .rdata = rd };
            try lib.wire.text.formatRr(w, &rr);
            try w.writeByte('\n');
        }
    }
}
