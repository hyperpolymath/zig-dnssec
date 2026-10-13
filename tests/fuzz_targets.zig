// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Fuzz targets shared by the coverage-guided `std.testing.fuzz` tests
//! (tests/fuzz.zig) and the standalone mutation fuzzer (tools/fuzz.zig).
//! Each target takes arbitrary bytes and must never crash, leak, or trip a
//! safety check; the differential target additionally checks that no
//! mutation of a recorded response can produce a *different* secure answer.

const std = @import("std");
const lib = @import("dnssec");
const Name = lib.wire.Name;
const Type = lib.wire.Type;
const Message = lib.wire.Message;
const transport = lib.stub.transport;
const validator = lib.sec.validator;

pub const traces_src = @embedFile("testdata/crosscheck.traces");
pub const anchor_src = @embedFile("testdata/crosscheck-root.anchor");
pub const now: i64 = 1791936000;

// ---------------------------------------------------------------------------
// Seed corpus: every distinct response recorded by the cross-check, grouped
// by scenario. Loaded once into a process-lifetime arena.
// ---------------------------------------------------------------------------

pub const Scenario = struct {
    qname: Name,
    qtype: Type,
    records: []transport.Recorded,
};

pub const Corpus = struct {
    scenarios: []Scenario,
    responses: [][]const u8,
};

var corpus_once: ?Corpus = null;
var corpus_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);

pub fn corpus() *const Corpus {
    if (corpus_once == null) corpus_once = loadCorpus() catch @panic("corpus");
    return &corpus_once.?;
}

fn loadCorpus() !Corpus {
    const a = corpus_arena.allocator();
    var scenarios: std.ArrayList(Scenario) = .empty;
    var responses: std.ArrayList([]const u8) = .empty;
    var recs: std.ArrayList(transport.Recorded) = .empty;
    var cur: ?Scenario = null;
    var lines = std.mem.splitScalar(u8, traces_src, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == ';') continue;
        if (std.mem.startsWith(u8, line, "@query ")) {
            if (cur) |*c| {
                c.records = try recs.toOwnedSlice(a);
                try scenarios.append(a, c.*);
            }
            var it = std.mem.tokenizeScalar(u8, line[7..], ' ');
            cur = .{ .qname = try Name.fromText(it.next().?), .qtype = Type.fromMnemonic(it.next().?).?, .records = &.{} };
            continue;
        }
        const t = try transport.Trace.parse(a, line);
        for (t.records) |r| {
            try recs.append(a, r);
            try responses.append(a, r.response);
        }
    }
    if (cur) |*c| {
        c.records = try recs.toOwnedSlice(a);
        try scenarios.append(a, c.*);
    }
    return .{ .scenarios = scenarios.items, .responses = responses.items };
}

// ---------------------------------------------------------------------------
// A small mutation language: input = seed selector + list of 3-byte ops.
// ---------------------------------------------------------------------------

pub fn mutate(seed: []const u8, program: []const u8, out: []u8) []u8 {
    var len = @min(seed.len, out.len);
    @memcpy(out[0..len], seed[0..len]);
    var i: usize = 0;
    while (i + 3 <= program.len) : (i += 3) {
        const op = program[i];
        const pos_raw = (@as(usize, program[i + 1]) << 8) | program[i + 2];
        const pos = if (len == 0) 0 else pos_raw % len;
        switch (op % 7) {
            0 => if (len > 0) {
                out[pos] ^= @as(u8, 1) << @intCast((op >> 3) & 7);
            },
            1 => if (len > 0) {
                out[pos] = program[i + 1] ^ program[i + 2] ^ op;
            },
            2 => if (len < out.len) { // insert a byte
                std.mem.copyBackwards(u8, out[pos + 1 .. len + 1], out[pos..len]);
                out[pos] = op;
                len += 1;
            },
            3 => if (len > 0) { // delete a byte
                std.mem.copyForwards(u8, out[pos .. len - 1], out[pos + 1 .. len]);
                len -= 1;
            },
            4 => len = pos, // truncate
            5 => if (len >= 2) { // interesting 16-bit values (counts, lengths, pointers)
                const p = @min(pos, len - 2);
                const vals = [_]u16{ 0, 1, 0x7FFF, 0xFFFF, 0xC00C, 0xC000, @intCast(@min(len, 0xFFFF)), 255, 256 };
                std.mem.writeInt(u16, out[p..][0..2], vals[op % vals.len], .big);
            },
            6 => if (len > 0) { // duplicate a chunk (stress counts and compression)
                const n = @min(@as(usize, op % 32) + 1, len - pos, out.len - len);
                std.mem.copyBackwards(u8, out[pos + n .. len + n], out[pos..len]);
                len += n;
            },
            else => unreachable,
        }
    }
    return out[0..len];
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// Decoder on raw bytes; if it parses, the re-encoded message must parse to
/// the same records.
pub fn decodeRaw(gpa: std.mem.Allocator, bytes: []const u8) !void {
    var m = Message.parse(gpa, bytes) catch return;
    defer m.deinit();
    var buf: [65535]u8 = undefined;
    var b = lib.wire.Builder.init(&buf, m.header) catch return;
    for (m.questions) |q| b.question(q.name, q.qtype, q.qclass) catch return;
    const secs = [_]lib.wire.message.Section{ .answer, .authority, .additional };
    for (secs) |s| for (m.section(s)) |rr| b.record(s, rr) catch return;
    if (m.edns) |e| b.opt(e.udp_size, e.do_bit, e.options) catch return;
    const wire = b.finish();
    var m2 = try Message.parse(gpa, wire); // must succeed: we just encoded it
    defer m2.deinit();
    if (m2.answer.len != m.answer.len or m2.authority.len != m.authority.len or m2.additional.len != m.additional.len)
        return error.RoundTripMismatch;
    for (secs) |s| for (m.section(s), m2.section(s)) |x, y| {
        if (!x.name.eql(&y.name) or x.type != y.type or !std.mem.eql(u8, x.rdata, y.rdata)) return error.RoundTripMismatch;
    };
}

/// Decoder on a mutated recorded response.
pub fn decodeMutated(gpa: std.mem.Allocator, input: []const u8) !void {
    const c = corpus();
    if (input.len < 2 or c.responses.len == 0) return decodeRaw(gpa, input);
    const idx = std.mem.readInt(u16, input[0..2], .little) % c.responses.len;
    var buf: [65535]u8 = undefined;
    return decodeRaw(gpa, mutate(c.responses[idx], input[2..], &buf));
}

/// NSEC3 RDATA parser, owner-label decoding and proof logic on arbitrary
/// records and query names.
pub fn nsec3(gpa: std.mem.Allocator, input: []const u8) !void {
    _ = gpa;
    if (input.len < 2) return;
    const zone = Name.fromText("example.") catch unreachable;
    // Split the input into up to 4 records plus a query name.
    var recs: [4]lib.sec.nsec3.Record = undefined;
    var n: usize = 0;
    var p: usize = 1;
    const count = input[0] % 5;
    var k: usize = 0;
    while (k < count and p + 2 <= input.len) : (k += 1) {
        const len = @min(@as(usize, input[p]) | (@as(usize, input[p + 1] & 1) << 8), input.len - p - 2);
        const rd = input[p + 2 ..][0..len];
        p += 2 + len;
        _ = lib.wire.rdata.Nsec3.parse(rd) catch continue;
        // Owner: a hash label derived from the next 20 input bytes (or zeros).
        var h: [20]u8 = @splat(0);
        const hl = @min(20, input.len - p);
        @memcpy(h[0..hl], input[p..][0..hl]);
        p += hl;
        var b32: [32]u8 = undefined;
        const label = lib.wire.encoding.base32HexEncode(&b32, &h);
        const owner = zone.prepend(label) catch continue;
        recs[n] = lib.sec.nsec3.Record.fromRr(owner, rd, &zone) catch continue;
        n += 1;
    }
    // Query name: labels from the remaining bytes.
    var q = zone;
    var rest = input[@min(p, input.len)..];
    while (rest.len > 0) {
        const l = @min(@as(usize, rest[0] % 64), rest.len - 1);
        if (l == 0) break;
        q = q.prepend(rest[1..][0..l]) catch break;
        rest = rest[1 + l ..];
    }
    var scratch: [4]lib.sec.nsec3.Record = undefined;
    switch (lib.sec.nsec3.Proof.init(recs[0..n], zone, .{ .max_iterations = 20, .max_hashes = 64 }, &scratch)) {
        .err => {},
        .ok => |pr| {
            var proof = pr;
            _ = proof.provesNxDomain(&q);
            _ = proof.provesNoData(&q, .a);
            _ = proof.provesNoData(&q, .ds);
            _ = proof.provesWildcardAnswer(&q, @intCast(@min(q.labelCount(), input[0])));
            _ = proof.provesInsecureDelegation(&q);
        },
    }
    // Standalone type-bitmap parsing on the raw input too.
    if (lib.wire.rdata.TypeBitmap.parse(input)) |tb| {
        _ = tb.has(.a);
        _ = tb.has(Type.fromInt(std.mem.readInt(u16, input[0..2], .little)));
        _ = tb.isEmpty();
    } else |_| {}
    var out: [512]u8 = undefined;
    _ = lib.wire.encoding.base32HexDecode(&out, input[0..@min(input.len, 400)]) catch {};
}

/// Presentation-format parser.
pub fn presentation(gpa: std.mem.Allocator, input: []const u8) !void {
    var d: lib.wire.text.Diagnostics = .{};
    var z = lib.wire.text.parseZone(gpa, input, .{}, &d) catch return;
    z.deinit();
}

/// Differential: mutate one recorded response of a scenario and validate.
/// A secure verdict must give exactly the unmutated scenario's answer.
pub fn validatorDifferential(gpa: std.mem.Allocator, input: []const u8) !void {
    const c = corpus();
    if (input.len < 3 or c.scenarios.len == 0) return;
    const s = &c.scenarios[std.mem.readInt(u16, input[0..2], .little) % c.scenarios.len];
    if (s.records.len == 0) return;
    const which = input[2] % s.records.len;

    var anchors = try validator.TrustAnchors.fromText(gpa, anchor_src);
    defer anchors.deinit();

    // Baseline.
    var base_replay: transport.ReplayTransport = .{ .records = s.records };
    var base_stub: lib.stub.client.StubClient = .{ .transport = base_replay.transport(), .anchors = &anchors };
    var base = base_stub.resolve(gpa, s.qname, s.qtype, now) catch return;
    defer base.deinit();

    const recs = try gpa.dupe(transport.Recorded, s.records);
    defer gpa.free(recs);
    var buf: [65535]u8 = undefined;
    recs[which].response = mutate(s.records[which].response, input[3..], &buf);
    var replay: transport.ReplayTransport = .{ .records = recs };
    var stub: lib.stub.client.StubClient = .{ .transport = replay.transport(), .anchors = &anchors };
    var r = stub.resolve(gpa, s.qname, s.qtype, now) catch return;
    defer r.deinit();

    if (r.verdict != .secure) return;
    if (base.verdict != .secure) return error.MutationMadeAnswerSecure;
    const x = r.verdict.secure;
    const y = base.verdict.secure;
    if (x.rcode != y.rcode or !x.final_name.eql(&y.final_name) or x.rrsets.len != y.rrsets.len)
        return error.SecureAnswerChanged;
    for (x.rrsets, y.rrsets) |xs, ys| {
        if (xs.type != ys.type or !xs.name.eql(&ys.name) or !sameRdataSet(xs.rdatas, ys.rdatas)) return error.SecureAnswerChanged;
    }
}

fn sameRdataSet(a: []const []const u8, b: []const []const u8) bool {
    for (a) |x| {
        var found = false;
        for (b) |y| if (std.mem.eql(u8, x, y)) {
            found = true;
        };
        if (!found) return false;
    }
    for (b) |y| {
        var found = false;
        for (a) |x| if (std.mem.eql(u8, x, y)) {
            found = true;
        };
        if (!found) return false;
    }
    return true;
}
