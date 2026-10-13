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
            .root_source_file = b.path("src/cli/dnssec-stub.zig"),
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

    const fuzz_targets = b.createModule(.{
        .root_source_file = b.path("tests/fuzz_targets.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dnssec", .module = mod }},
    });
    const fuzz_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dnssec", .module = mod }},
    }) });
    test_step.dependOn(&b.addRunArtifact(fuzz_tests).step);
    b.step("fuzz", "Fuzz tests only; run with --fuzz[=limit]").dependOn(&b.addRunArtifact(fuzz_tests).step);
    const fuzz_validator = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/fuzz_validator.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "dnssec", .module = mod }},
    }) });
    test_step.dependOn(&b.addRunArtifact(fuzz_validator).step);
    b.step("fuzz-validator", "Differential validator fuzz test; run with --fuzz[=limit]").dependOn(&b.addRunArtifact(fuzz_validator).step);

    const fuzz_exe = b.addExecutable(.{
        .name = "dnssec-fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz/dnssec-fuzz.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "fuzz_targets", .module = fuzz_targets }},
        }),
    });
    const fuzz_install = b.addInstallArtifact(fuzz_exe, .{});
    b.step("fuzz-tool", "Build the standalone mutation fuzzer (use -Doptimize=ReleaseSafe)").dependOn(&fuzz_install.step);
}
