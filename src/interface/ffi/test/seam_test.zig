// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Keeps the three sides of the seam in step: the C header (the contract),
//! the Zig validator, and the Idris2 model in src/interface/Abi/.
//!
//! The Idris sources are read as text and the facts they state (codes,
//! field offsets, foreign signatures) are compared with the header as the C
//! compiler sees it (translate-c). The Idris side's own proofs (round trips,
//! alignment, the answer rule) are checked by `idris2 --typecheck`; this test
//! checks that what it proves things *about* is the real interface.

const std = @import("std");
const testing = std.testing;
const h = @import("zig_dnssec_h");
const lib = @import("dnssec");
// Links the exported functions, whose types the signature checks inspect.
comptime {
    _ = @import("ffi");
}

const types_idr = @embedFile("Types.idr");
const layout_idr = @embedFile("Layout.idr");
const foreign_idr = @embedFile("Foreign.idr");

/// "Nsec3OptOut" -> "NSEC3_OPT_OUT"
fn screaming(buf: []u8, camel: []const u8) []const u8 {
    var n: usize = 0;
    for (camel, 0..) |c, i| {
        if (i > 0 and std.ascii.isUpper(c)) {
            buf[n] = '_';
            n += 1;
        }
        buf[n] = std.ascii.toUpper(c);
        n += 1;
    }
    return buf[0..n];
}

/// The header's integer macros, by name, as the C preprocessor defines them.
fn macro(name: []const u8) ?i64 {
    @setEvalBranchQuota(100_000);
    inline for (comptime std.meta.declarations(h)) |d| {
        if (comptime std.mem.startsWith(u8, d, "ZIG_DNSSEC_")) {
            const v = @field(h, d);
            if (comptime (@typeInfo(@TypeOf(v)) == .int or @typeInfo(@TypeOf(v)) == .comptime_int)) {
                if (std.mem.eql(u8, d, name)) return v;
            }
        }
    }
    return null;
}

/// Header macro names with a given prefix.
fn macrosWithPrefix(gpa: std.mem.Allocator, prefix: []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    @setEvalBranchQuota(100_000);
    inline for (comptime std.meta.declarations(h)) |d| {
        if (std.mem.startsWith(u8, d, prefix)) try list.append(gpa, d);
    }
    return list.toOwnedSlice(gpa);
}

const Clause = struct { ctor: []const u8, value: i64 };

/// Lines of the form "<fun> <Ctor> = <int>" in Types.idr.
fn clauses(gpa: std.mem.Allocator, fun: []const u8) ![]Clause {
    var list: std.ArrayList(Clause) = .empty;
    var lines = std.mem.splitScalar(u8, types_idr, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const f = it.next() orelse continue;
        if (!std.mem.eql(u8, f, fun)) continue;
        const ctor = it.next() orelse continue;
        const eq = it.next() orelse continue;
        if (!std.mem.eql(u8, eq, "=")) continue;
        const v = it.next() orelse continue;
        try list.append(gpa, .{ .ctor = ctor, .value = try std.fmt.parseInt(i64, v, 10) });
    }
    return list.toOwnedSlice(gpa);
}

fn expectCodes(fun: []const u8, comptime prefix: []const u8, ok_name: ?[]const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = try clauses(a, fun);
    try testing.expect(cs.len > 0);
    var buf: [128]u8 = undefined;
    var seen: std.StringHashMap(void) = .init(a);
    for (cs) |c| {
        const name = if (ok_name != null and std.mem.eql(u8, c.ctor, "Ok"))
            ok_name.?
        else
            try std.fmt.allocPrint(a, "{s}{s}", .{ prefix, screaming(&buf, c.ctor) });
        const v = macro(name) orelse {
            std.debug.print("Idris {s} {s}: header has no {s}\n", .{ fun, c.ctor, name });
            return error.MissingMacro;
        };
        if (v != c.value) {
            std.debug.print("Idris {s} {s} = {d}, header {s} = {d}\n", .{ fun, c.ctor, c.value, name, v });
            return error.CodeMismatch;
        }
        try seen.put(name, {});
    }
    // ... and every header code of this family is modelled in Idris (NONE is
    // the absence of a value and is deliberately not a constructor).
    for (try macrosWithPrefix(a, prefix)) |m| {
        if (std.mem.endsWith(u8, m, "_NONE")) continue;
        if (!seen.contains(m)) {
            std.debug.print("header {s} has no Idris constructor in {s}\n", .{ m, fun });
            return error.UnmodelledMacro;
        }
    }
}

test "Idris status codes are the header's" {
    try expectCodes("statusCode", "ZIG_DNSSEC_ERR_", "ZIG_DNSSEC_OK");
}

test "Idris security codes are the header's" {
    try expectCodes("securityCode", "ZIG_DNSSEC_SECURITY_", null);
}

test "Idris reason codes are the header's" {
    try expectCodes("reasonCode", "ZIG_DNSSEC_REASON_", null);
}

test "Idris policy bits are the header's" {
    try expectCodes("policyBit", "ZIG_DNSSEC_POLICY_", null);
}

test "Idris reasons are the validator's reasons, one for one" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cs = try clauses(arena.allocator(), "reasonCode");
    const zig_reasons = std.enums.values(lib.sec.validator.Reason);
    try testing.expectEqual(zig_reasons.len, cs.len);
    var buf: [128]u8 = undefined;
    for (zig_reasons) |r| {
        const found = for (cs) |c| {
            const snake = std.ascii.lowerString(&buf, screaming(&buf, c.ctor));
            if (std.mem.eql(u8, snake, @tagName(r))) break true;
        } else false;
        if (!found) {
            std.debug.print("validator reason {t} has no Idris constructor\n", .{r});
            return error.UnmodelledReason;
        }
    }
}

test "Idris verdict layout is the C compiler's" {
    const V = h.zig_dnssec_verdict;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, layout_idr, '\n');
    while (lines.next()) |line| {
        const at = std.mem.indexOf(u8, line, "MkField \"") orelse continue;
        var rest = line[at + "MkField \"".len ..];
        const q = std.mem.indexOfScalar(u8, rest, '"') orelse continue;
        const name = rest[0..q];
        rest = rest[q + 1 ..];
        var it = std.mem.tokenizeScalar(u8, rest, ' ');
        const off = try std.fmt.parseInt(usize, it.next().?, 10);
        const size = try std.fmt.parseInt(usize, it.next().?, 10);
        const alignment = try std.fmt.parseInt(usize, it.next().?, 10);
        var matched = false;
        const vi = @typeInfo(V).@"struct";
        inline for (vi.field_names, vi.field_types) |fname, FT| {
            if (std.mem.eql(u8, fname, name)) {
                matched = true;
                try testing.expectEqual(@offsetOf(V, fname), off);
                try testing.expectEqual(@sizeOf(FT), size);
                const elem_align = switch (@typeInfo(FT)) {
                    .array => |arr| @alignOf(arr.child),
                    else => @alignOf(FT),
                };
                try testing.expectEqual(elem_align, alignment);
            }
        }
        if (!matched) {
            std.debug.print("Idris field {s} is not in zig_dnssec_verdict\n", .{name});
            return error.UnknownField;
        }
        count += 1;
    }
    try testing.expectEqual(@typeInfo(V).@"struct".field_names.len, count);

    const total = std.mem.indexOf(u8, layout_idr, "MkStructLayout verdictFields ").?;
    var it = std.mem.tokenizeAny(u8, layout_idr[total + "MkStructLayout verdictFields ".len ..], " \n");
    try testing.expectEqual(@sizeOf(V), try std.fmt.parseInt(usize, it.next().?, 10));
    try testing.expectEqual(@alignOf(V), try std.fmt.parseInt(usize, it.next().?, 10));

    const wm = std.mem.indexOf(u8, layout_idr, "whereMax = ").?;
    var wit = std.mem.tokenizeAny(u8, layout_idr[wm + "whereMax = ".len ..], " \n");
    try testing.expectEqual(@as(i64, h.ZIG_DNSSEC_WHERE_MAX), try std.fmt.parseInt(i64, wit.next().?, 10));
}

const Kind = enum { pointer, c_int, u8, u16, u32, u64, i64, other };

fn kindOf(comptime T: type) Kind {
    return switch (@typeInfo(T)) {
        .pointer => .pointer,
        .optional => |o| if (@typeInfo(o.child) == .pointer) .pointer else .other,
        .int => if (T == c_int) .c_int else if (T == u8) .u8 else if (T == u16) .u16 else if (T == u32) .u32 else if (T == u64 or T == usize) .u64 else if (T == i64) .i64 else .other,
        else => .other,
    };
}

fn idrisKind(t: []const u8) Kind {
    if (std.mem.eql(u8, t, "String") or std.mem.eql(u8, t, "AnyPtr") or std.mem.eql(u8, t, "Buffer")) return .pointer;
    if (std.mem.eql(u8, t, "Int")) return .c_int;
    if (std.mem.eql(u8, t, "Bits8")) return .u8;
    if (std.mem.eql(u8, t, "Bits16")) return .u16;
    if (std.mem.eql(u8, t, "Bits32")) return .u32;
    if (std.mem.eql(u8, t, "Bits64")) return .u64;
    if (std.mem.eql(u8, t, "Int64")) return .i64;
    return .other;
}

const header_functions = [_][]const u8{
    "zig_dnssec_abi_version",
    "zig_dnssec_validate",
    "zig_dnssec_validate_trace",
    "zig_dnssec_status_name",
    "zig_dnssec_security_name",
    "zig_dnssec_reason_name",
};

fn signatureMatches(sym: []const u8, args: []const Kind, ret: Kind) !bool {
    inline for (header_functions) |name| {
        if (std.mem.eql(u8, name, sym)) {
            const info = @typeInfo(@TypeOf(@field(h, name))).@"fn";
            if (info.param_types.len != args.len) return false;
            inline for (info.param_types, 0..) |pt, i| {
                if (kindOf(pt.?) != args[i]) return false;
            }
            return kindOf(info.return_type.?) == ret;
        }
    }
    return error.NotInHeader;
}

test "Idris foreign declarations match the header's functions" {
    var lines = std.mem.splitScalar(u8, foreign_idr, '\n');
    var checked: usize = 0;
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "%foreign \"C:")) continue;
        const spec = line["%foreign \"C:".len..];
        const comma = std.mem.indexOfScalar(u8, spec, ',').?;
        const sym = spec[0..comma];
        try testing.expect(std.mem.startsWith(u8, spec[comma + 1 ..], "libzig_dnssec\""));
        // The declaration is the next non-comment line: "prim__x : A -> B -> PrimIO R".
        const decl = while (lines.next()) |l| {
            if (l.len > 0 and !std.mem.startsWith(u8, l, "--")) break l;
        } else return error.NoDeclaration;
        const colon = std.mem.indexOf(u8, decl, " : ").?;
        var parts = std.mem.splitSequence(u8, decl[colon + 3 ..], " -> ");
        var args: [16]Kind = undefined;
        var n: usize = 0;
        var ret: Kind = .other;
        while (parts.next()) |p| {
            const t = std.mem.trim(u8, p, " ");
            if (std.mem.startsWith(u8, t, "PrimIO ")) {
                ret = idrisKind(t["PrimIO ".len..]);
            } else {
                args[n] = idrisKind(t);
                n += 1;
            }
        }
        if (!try signatureMatches(sym, args[0..n], ret)) {
            std.debug.print("Idris foreign {s} does not match the header: {s}\n", .{ sym, decl });
            return error.SignatureMismatch;
        }
        checked += 1;
    }
    try testing.expect(checked >= 3);

    const v = std.mem.indexOf(u8, foreign_idr, "abiVersion = ").?;
    var it = std.mem.tokenizeAny(u8, foreign_idr[v + "abiVersion = ".len ..], " \n");
    try testing.expectEqual(@as(i64, h.ZIG_DNSSEC_ABI_VERSION), try std.fmt.parseInt(i64, it.next().?, 10));
}

test "the Idris model has no escape hatches" {
    for ([_][]const u8{ types_idr, layout_idr, foreign_idr }) |src| {
        try testing.expect(std.mem.indexOf(u8, src, "%default total") != null);
        for ([_][]const u8{ "believe_me", "assert_total", "assert_smaller", "idris_crash", "%default partial", "partial\n" }) |bad| {
            if (std.mem.indexOf(u8, src, bad) != null) {
                std.debug.print("found {s} in the Idris model\n", .{bad});
                return error.EscapeHatch;
            }
        }
    }
}
