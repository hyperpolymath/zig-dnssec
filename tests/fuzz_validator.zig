// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Differential fuzz test of the whole validator (slow: two full
//! validations per input). Kept out of the `fuzz` step; run with
//! `zig build fuzz-validator --fuzz=N -Doptimize=ReleaseSafe`, or use
//! `dnssec-fuzz differential <seconds>`.

const std = @import("std");
const t = @import("fuzz_targets.zig");
const Smith = std.testing.Smith;

test "fuzz: validator never accepts a mutated response as a different secure answer" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const n = smith.slice(&buf);
            try t.validatorDifferential(std.testing.allocator, buf[0..n]);
        }
    }.one, .{});
}
