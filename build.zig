// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("dnssec", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "dnssec-stub",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/dnssec-stub.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "dnssec", .module = mod }},
        }),
    });
    b.installArtifact(exe);
    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run", "Run dnssec-stub").dependOn(&run.step);

    const test_step = b.step("test", "Run unit tests and RFC known-answer tests");

    const mod_tests = b.addTest(.{ .root_module = mod });
    test_step.dependOn(&b.addRunArtifact(mod_tests).step);

    const vectors = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/vectors.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dnssec", .module = mod }},
    }) });
    test_step.dependOn(&b.addRunArtifact(vectors).step);

    const denial = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/denial.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dnssec", .module = mod }},
    }) });
    test_step.dependOn(&b.addRunArtifact(denial).step);

    const replay = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/replay.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dnssec", .module = mod }},
    }) });
    test_step.dependOn(&b.addRunArtifact(replay).step);
}
