// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Trust anchors: statically configured DS and/or DNSKEY records.
//!
//! Assumptions (see SECURITY.md): anchors are static configuration. There
//! is no RFC 5011 automated rollover, no negative trust anchors (RFC 7646)
//! and no persistence. Whoever supplies the anchor text is trusted
//! completely; an anchor update is a software/configuration update.

const std = @import("std");
const wire_name = @import("../wire/name.zig");
const text = @import("../wire/text.zig");
const types = @import("../wire/types.zig");

const Name = wire_name.Name;

/// IANA root zone KSK DS records (KSK-2017, tag 20326; KSK-2024, tag 38696),
/// as published in https://data.iana.org/root-anchors/root-anchors.xml.
/// Cross-checked on 2026-10-13 against that file (S/MIME signature verified
/// with the ICANN Root CA bundle) and against Ubuntu's dns-root-data
/// package (2024071801). Re-verify before use; anchors change.
pub const iana_root_ds =
    \\. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
    \\. IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
;

pub const Anchor = struct {
    name: Name,
    /// DS RDATA (trusted without signature).
    ds: []const []const u8,
    /// DNSKEY RDATA (trusted without signature).
    dnskey: []const []const u8,
};

pub const TrustAnchors = struct {
    arena: std.heap.ArenaAllocator,
    anchors: []Anchor,

    pub const Error = text.Error || error{NotAnAnchorRecord};

    /// Parses DS and DNSKEY records in presentation format. Any other record
    /// type is rejected rather than ignored.
    pub fn fromText(gpa: std.mem.Allocator, src: []const u8) Error!TrustAnchors {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        var zone = try text.parseZone(gpa, src, .{}, null);
        defer zone.deinit();

        var list: std.ArrayList(Anchor) = .empty;
        var ds_lists: std.ArrayList(std.ArrayList([]const u8)) = .empty;
        var key_lists: std.ArrayList(std.ArrayList([]const u8)) = .empty;
        for (zone.records) |rr| {
            if (rr.type != .ds and rr.type != .dnskey) return error.NotAnAnchorRecord;
            if (rr.class != .in) return error.NotAnAnchorRecord;
            const idx = for (list.items, 0..) |*an, i| {
                if (an.name.eql(&rr.name)) break i;
            } else blk: {
                try list.append(a, .{ .name = rr.name.lowercase(), .ds = &.{}, .dnskey = &.{} });
                try ds_lists.append(a, .empty);
                try key_lists.append(a, .empty);
                break :blk list.items.len - 1;
            };
            const copy = try a.dupe(u8, rr.rdata);
            if (rr.type == .ds) try ds_lists.items[idx].append(a, copy) else try key_lists.items[idx].append(a, copy);
        }
        for (list.items, 0..) |*an, i| {
            an.ds = ds_lists.items[i].items;
            an.dnskey = key_lists.items[i].items;
        }
        return .{ .arena = arena, .anchors = list.items };
    }

    pub fn ianaRoot(gpa: std.mem.Allocator) Error!TrustAnchors {
        return fromText(gpa, iana_root_ds);
    }

    pub fn deinit(t: *TrustAnchors) void {
        t.arena.deinit();
        t.* = undefined;
    }

    /// The anchor with the longest name that is an ancestor-or-self of `n`.
    pub fn closest(t: *const TrustAnchors, n: *const Name) ?*const Anchor {
        var best: ?*const Anchor = null;
        for (t.anchors) |*an| {
            if (!n.isSubdomainOf(&an.name)) continue;
            if (best == null or an.name.labelCount() > best.?.name.labelCount()) best = an;
        }
        return best;
    }
};

test "root anchors parse and match" {
    var ta = try TrustAnchors.ianaRoot(std.testing.allocator);
    defer ta.deinit();
    try std.testing.expectEqual(@as(usize, 1), ta.anchors.len);
    try std.testing.expectEqual(@as(usize, 2), ta.anchors[0].ds.len);
    const n = try Name.fromText("www.example.org.");
    try std.testing.expect(ta.closest(&n) != null);
    try std.testing.expectError(error.NotAnAnchorRecord, TrustAnchors.fromText(std.testing.allocator, "a. A 1.2.3.4"));
}

test "closest anchor prefers the deepest island" {
    var ta = try TrustAnchors.fromText(std.testing.allocator,
        \\. DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
        \\example. DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=
    );
    defer ta.deinit();
    const n = try Name.fromText("a.EXAMPLE.");
    try std.testing.expect(ta.closest(&n).?.name.eql(&(try Name.fromText("example."))));
    const o = try Name.fromText("org.");
    try std.testing.expect(ta.closest(&o).?.name.isRoot());
}
