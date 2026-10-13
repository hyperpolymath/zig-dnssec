// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Standalone, reproducible mutation fuzzer for the targets in
//! tests/fuzz_targets.zig. Build in ReleaseSafe so that bounds, overflow and
//! unreachable checks stay on:
//!
//!   zig build fuzz-tool -Doptimize=ReleaseSafe
//!   ./zig-out/bin/dnssec-fuzz <target> <seconds> [seed]
//!
//! Targets: decode-raw, decode-mutated, nsec3, presentation, differential,
//! all. A crash is a finding; the input that caused it is printed in hex
//! before the target runs whenever DNSSEC_FUZZ_TRACE is set.

const std = @import("std");
const t = @import("fuzz_targets");

const Target = enum { @"decode-raw", @"decode-mutated", nsec3, presentation, differential };

fn runOne(target: Target, gpa: std.mem.Allocator, input: []const u8) !void {
    return switch (target) {
        .@"decode-raw" => t.decodeRaw(gpa, input),
        .@"decode-mutated" => t.decodeMutated(gpa, input),
        .nsec3 => t.nsec3(gpa, input),
        .presentation => t.presentation(gpa, input),
        .differential => t.validatorDifferential(gpa, input),
    };
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) {
        std.debug.print("usage: dnssec-fuzz <decode-raw|decode-mutated|nsec3|presentation|differential|all> <seconds> [seed]\n", .{});
        return 2;
    }
    const secs = try std.fmt.parseInt(u32, args[2], 10);
    const seed: u64 = if (args.len > 3) try std.fmt.parseInt(u64, args[3], 0) else 0x5eed_d15c;
    const trace = init.environ_map.get("DNSSEC_FUZZ_TRACE") != null;

    var targets: std.ArrayList(Target) = .empty;
    if (std.mem.eql(u8, args[1], "all")) {
        try targets.appendSlice(arena, std.enums.values(Target));
    } else {
        try targets.append(arena, std.meta.stringToEnum(Target, args[1]) orelse return 2);
    }

    _ = t.corpus(); // load once, outside the timed loop
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg.deinit();
    const gpa = dbg.allocator();

    for (targets.items) |target| {
        var prng: std.Random.DefaultPrng = .init(seed ^ @backingInt(target));
        const rnd = prng.random();
        const start = std.Io.Clock.awake.now(io);
        var iterations: u64 = 0;
        var buf: [4096]u8 = undefined;
        while (true) {
            if (iterations % 256 == 0) {
                const el = start.durationTo(std.Io.Clock.awake.now(io));
                if (el.toSeconds() >= secs) break;
            }
            // Mostly short inputs; occasionally long ones.
            const len = if (rnd.int(u8) < 230) rnd.uintLessThan(usize, 300) else rnd.uintLessThan(usize, buf.len);
            rnd.bytes(buf[0..len]);
            if (trace) std.debug.print("{t} {x}\n", .{ target, buf[0..len] });
            runOne(target, gpa, buf[0..len]) catch |e| switch (e) {
                error.OutOfMemory => return e,
                else => {
                    std.debug.print("FINDING target={t} iteration={d} error={t} input={x}\n", .{ target, iterations, e, buf[0..len] });
                    return 1;
                },
            };
            iterations += 1;
        }
        std.debug.print("target={t} seed=0x{x} seconds={d} iterations={d} findings=0\n", .{ target, seed, secs, iterations });
    }
    return 0;
}
