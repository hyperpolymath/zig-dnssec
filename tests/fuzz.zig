// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Coverage-guided fuzz tests (std.testing.fuzz). Under plain `zig build
//! test` each runs once on an empty input; `zig build fuzz -Dfuzz-limit=N`
//! (or `zig build test --fuzz=N`) runs the coverage-guided fuzzer.
//! tests/fuzz/dnssec-fuzz.zig drives the same targets with a reproducible mutation
//! fuzzer in ReleaseSafe.

const std = @import("std");
const t = @import("fuzz_targets.zig");
const Smith = std.testing.Smith;

fn bytes(smith: *Smith, buf: []u8) []u8 {
    const n = smith.slice(buf);
    return buf[0..n];
}

test "fuzz: message decoder on raw bytes" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *Smith) anyerror!void {
            var buf: [2048]u8 = undefined;
            try t.decodeRaw(std.testing.allocator, bytes(smith, &buf));
        }
    }.one, .{});
}

test "fuzz: message decoder on mutated recorded responses" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            try t.decodeMutated(std.testing.allocator, bytes(smith, &buf));
        }
    }.one, .{
        .corpus = &.{
            // u8 overflow in Name.readFromMessage at the 255-octet boundary,
            // found by `zig build fuzz --fuzz` on 2026-10-13 (fixed).
            @embedFile("fuzz/corpus/decode-mutated-0001.bin"),
        },
    });
}

test "fuzz: NSEC3 parser and proofs" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            try t.nsec3(std.testing.allocator, bytes(smith, &buf));
        }
    }.one, .{});
}

test "fuzz: presentation-format parser" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            try t.presentation(std.testing.allocator, bytes(smith, &buf));
        }
    }.one, .{});
}

test "mutator smoke test" {
    const c = t.corpus();
    try std.testing.expect(c.responses.len > 500);
    var out: [65535]u8 = undefined;
    const m = t.mutate(c.responses[0], &.{ 0, 0, 5, 2, 0, 1, 3, 0, 2, 4, 0, 40 }, &out);
    try std.testing.expect(m.len <= 40);
}
