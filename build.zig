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

    // ---- C ABI seam (src/interface/) ---------------------------------------
    // The header is the contract: translate-c turns it into the module the
    // Zig implementation is type-checked against.
    const header_path = b.path("src/interface/ffi/include/zig_dnssec.h");
    const header_mod = b.addTranslateC(.{
        .root_source_file = header_path,
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    }).createModule();

    const ffi_static = b.addLibrary(.{
        .name = "zig_dnssec",
        .linkage = .static,
        .root_module = ffiModule(b, target, optimize, mod, header_mod, null),
    });
    const ffi_shared = b.addLibrary(.{
        .name = "zig_dnssec",
        .linkage = .dynamic,
        .root_module = ffiModule(b, target, optimize, mod, header_mod, true),
    });
    const ffi_step = b.step("ffi", "Build the C ABI (static and shared libzig_dnssec) and install the header");
    ffi_step.dependOn(&b.addInstallArtifact(ffi_static, .{}).step);
    ffi_step.dependOn(&b.addInstallArtifact(ffi_shared, .{}).step);
    ffi_step.dependOn(&b.addInstallFileWithDir(header_path, .header, "zig_dnssec.h").step);

    // C-ABI behaviour: calls through the header's declarations into the
    // library, plus allocator-checked calls of the same code.
    const ffi_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/interface/ffi/test/abi_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ffi", .module = ffiModule(b, target, optimize, mod, header_mod, null) },
            .{ .name = "zig_dnssec_h", .module = header_mod },
            .{ .name = "dnssec", .module = mod },
        },
    }) });
    ffi_tests.root_module.addAnonymousImport("crosscheck.traces", .{ .root_source_file = b.path("tests/testdata/crosscheck.traces") });
    ffi_tests.root_module.addAnonymousImport("crosscheck-root.anchor", .{ .root_source_file = b.path("tests/testdata/crosscheck-root.anchor") });
    test_step.dependOn(&b.addRunArtifact(ffi_tests).step);

    // The Idris2 model and the header must agree: codes, names and layout.
    const seam_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/interface/ffi/test/seam_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ffi", .module = ffiModule(b, target, optimize, mod, header_mod, null) },
            .{ .name = "zig_dnssec_h", .module = header_mod },
            .{ .name = "dnssec", .module = mod },
        },
    }) });
    seam_tests.root_module.addAnonymousImport("Types.idr", .{ .root_source_file = b.path("src/interface/Abi/Types.idr") });
    seam_tests.root_module.addAnonymousImport("Layout.idr", .{ .root_source_file = b.path("src/interface/Abi/Layout.idr") });
    seam_tests.root_module.addAnonymousImport("Foreign.idr", .{ .root_source_file = b.path("src/interface/Abi/Foreign.idr") });
    test_step.dependOn(&b.addRunArtifact(seam_tests).step);
}

fn ffiModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    dnssec: *std.Build.Module,
    header: *std.Build.Module,
    pic: ?bool,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/interface/ffi/src/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = pic,
        .imports = &.{
            .{ .name = "dnssec", .module = dnssec },
            .{ .name = "zig_dnssec_h", .module = header },
        },
    });
}
