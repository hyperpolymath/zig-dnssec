// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Known-answer tests from the RFCs. Records are transcribed from the RFC
//! text verbatim except where an erratum is noted.

const std = @import("std");
const testing = std.testing;
const lib = @import("dnssec");
const text = lib.wire.text;
const Name = lib.wire.Name;
const rdata = lib.wire.rdata;
const rrset = lib.sec.rrset;
const keys = lib.sec.keys;
const crypto = lib.sec.crypto;
const Type = lib.wire.Type;

const Fixture = struct {
    zone: text.Zone,
    grouped: rrset.Grouped,
    arena: std.heap.ArenaAllocator,

    fn init(src: []const u8) !Fixture {
        var z = try text.parseZone(testing.allocator, src, .{}, null);
        errdefer z.deinit();
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        errdefer arena.deinit();
        const g = try rrset.group(arena.allocator(), z.records);
        return .{ .zone = z, .grouped = g, .arena = arena };
    }

    fn deinit(f: *Fixture) void {
        f.arena.deinit();
        f.zone.deinit();
    }

    fn set(f: *Fixture, t: Type) *rrset.RrSet {
        for (f.grouped.sets) |*s| if (s.type == t) return s;
        @panic("missing rrset");
    }

    /// Verifies the first RRSIG of the set of type `t` with the (single)
    /// DNSKEY in the fixture.
    fn verifyWith(f: *Fixture, t: Type, now: u32) !void {
        const k = f.set(.dnskey);
        const s = f.set(t);
        try testing.expect(s.sigs.len >= 1);
        try rrset.verify(testing.allocator, s, &s.sigs[0], &k.name, k.rdatas[0], now, 0);
    }
};

fn expectDsMatch(f: *Fixture) !void {
    const k = f.set(.dnskey);
    const d = f.set(.ds);
    const ds = try rdata.Ds.parse(d.rdatas[0]);
    try testing.expectEqual(keys.DsMatch.match, keys.dsMatches(ds, &k.name, k.rdatas[0]));
}

test "RFC 4034 §5.4 DS (SHA-1) and key tag 60485" {
    var f = try Fixture.init(
        \\dskey.example.com. 86400 IN DNSKEY 256 3 5 ( AQOeiiR0GOMYkDshWoSKz9Xz
        \\                                          fwJr1AYtsmx3TGkJaNXVbfi/
        \\                                          2pHm822aJ5iI9BMzNXxeYCmZ
        \\                                          DRD99WYwYqUSdjMmmAphXdvx
        \\                                          egXd/M5+X7OrzKBaMbCVdFLU
        \\                                          Uh6DhweJBjEVv5f2wwjM9Xzc
        \\                                          nOf+EPbtG9DMBmADjFDc2w/r
        \\                                          ljwvFw==
        \\                                          ) ;  key id = 60485
        \\dskey.example.com. 86400 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A
        \\                                           98631FAD1A292118 )
    );
    defer f.deinit();
    try testing.expectEqual(@as(u16, 60485), keys.keyTag(f.set(.dnskey).rdatas[0]));
    try expectDsMatch(&f);
}

test "RFC 4509 §2.3 DS (SHA-256)" {
    var f = try Fixture.init(
        \\dskey.example.com. 86400 IN DNSKEY 256 3 5 ( AQOeiiR0GOMYkDshWoSKz9Xz
        \\                                             fwJr1AYtsmx3TGkJaNXVbfi/
        \\                                             2pHm822aJ5iI9BMzNXxeYCmZ
        \\                                             DRD99WYwYqUSdjMmmAphXdvx
        \\                                             egXd/M5+X7OrzKBaMbCVdFLU
        \\                                             Uh6DhweJBjEVv5f2wwjM9Xzc
        \\                                             nOf+EPbtG9DMBmADjFDc2w/r
        \\                                             ljwvFw==
        \\                                             ) ;  key id = 60485
        \\dskey.example.com. 86400 IN DS 60485 5 2   ( D4B7D520E7BB5F0F67674A0C
        \\                                             CEB1E3E0614B93C4F9E99B83
        \\                                             83F6A1E4469DA50A )
    );
    defer f.deinit();
    try expectDsMatch(&f);
    // A one-bit change in the digest must not match.
    const d = f.set(.ds);
    var copy: [36]u8 = undefined;
    @memcpy(copy[0..d.rdatas[0].len], d.rdatas[0]);
    copy[10] ^= 0x01;
    const ds = try rdata.Ds.parse(copy[0..d.rdatas[0].len]);
    const k = f.set(.dnskey);
    try testing.expectEqual(keys.DsMatch.mismatch, keys.dsMatches(ds, &k.name, k.rdatas[0]));
}

// 2010-01-01T00:00:00Z, inside the RFC 5702 examples' 2000..2030 window.
const t2010: u32 = 1262304000;

test "RFC 5702 §6.1 RSA/SHA-256 (512-bit key)" {
    var f = try Fixture.init(
        \\example.net.     3600  IN  DNSKEY  (256 3 8 AwEAAcFcGsaxxdgiuuGmCkVI
        \\                 my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P
        \\                 kxUdp6p/DlUmObdk= );{id = 9033 (zsk), size = 512b}
        \\www.example.net. 3600  IN  A  192.0.2.91
        \\www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
        \\                  20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
        \\                  l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
        \\                  cFYK/lPtPiVYP4bwg==);{id = 9033}
    );
    defer f.deinit();
    try testing.expectEqual(@as(u16, 9033), keys.keyTag(f.set(.dnskey).rdatas[0]));
    try f.verifyWith(.a, t2010);
}

test "RFC 5702 §6.2 RSA/SHA-512 (1024-bit key)" {
    var f = try Fixture.init(
        \\example.net.    3600  IN  DNSKEY  (256 3 10 AwEAAdHoNTOW+et86KuJOWRD
        \\                p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
        \\                xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
        \\                pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL
        \\                );{id = 3740 (zsk), size = 1024b}
        \\www.example.net. 3600  IN  A  192.0.2.91
        \\www.example.net. 3600  IN  RRSIG  (A 10 3 3600 20300101000000
        \\                 20000101000000 3740 example.net. tsb4wnjRUDnB1BUi+t
        \\                 6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
        \\                 eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
        \\                 DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
        \\                 =);{id = 3740}
    );
    defer f.deinit();
    try testing.expectEqual(@as(u16, 3740), keys.keyTag(f.set(.dnskey).rdatas[0]));
    try f.verifyWith(.a, t2010);
}

// 2010-08-20T00:00:00Z, inside the RFC 6605 examples' validity windows.
const t2010aug: u32 = 1282262400;

const rfc6605_p256 =
    \\example.net. 3600 IN DNSKEY 257 3 13 (
    \\        GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
    \\        krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )
    \\example.net. 3600 IN DS 55648 13 2 (
    \\        b4c8c1fe2e7477127b27115656ad6256f424625bf5c1
    \\        e2770ce6d6e37df61d17 )
    \\www.example.net. 3600 IN A 192.0.2.1
    \\www.example.net. 3600 IN RRSIG A 13 3 3600 (
    \\        20100909100439 20100812100439 55648 example.net.
    \\        qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
    \\        yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== )
;

test "RFC 6605 §6.1 ECDSA P-256" {
    var f = try Fixture.init(rfc6605_p256);
    defer f.deinit();
    try expectDsMatch(&f);
    try f.verifyWith(.a, t2010aug);
}

test "RFC 6605 §6.2 ECDSA P-384 (DS with SHA-384)" {
    var f = try Fixture.init(
        \\example.net. 3600 IN DNSKEY 257 3 14 (
        \\        xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
        \\        w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
        \\        /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 )
        \\example.net. 3600 IN DS 10771 14 4 (
        \\        72d7b62976ce06438e9c0bf319013cf801f09ecc84b8
        \\        d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94
        \\        6df983d6 )
        \\www.example.net. 3600 IN A 192.0.2.1
        \\www.example.net. 3600 IN RRSIG A 14 3 3600 (
        \\        20100909102025 20100812102025 10771 example.net.
        \\        /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
        \\        95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
        \\        WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm )
    );
    defer f.deinit();
    try expectDsMatch(&f);
    try f.verifyWith(.a, t2010aug);
}

// RFC 8080 §6 examples. The published RRSIG lines read "RRSIG MX 3 3600 (",
// i.e. the Algorithm field is missing, and they nest parentheses. Re-signing
// the published private key with Zig's deterministic Ed25519 reproduces the
// published signatures byte-for-byte only when the RRSIG Labels field is 3,
// so the intended record is "RRSIG MX 15 3 3600 ...". Labels = 3 exceeds the
// two labels of the owner "example.com.", which RFC 4035 §5.3.1 requires a
// validator to reject. The tests therefore check (a) the raw Ed25519
// signature verifies over the data as signed, and (b) the full RRSIG check
// rejects the record with BadLabelCount.
const t2015: u32 = 1439000000; // between 1438207200 and 1440021600

fn rfc8080SignedData(buf: []u8, s: *const rrset.RrSet) []const u8 {
    const sig = &s.sigs[0].rrsig;
    var n: usize = 0;
    @memcpy(buf[n..][0..sig.signed_prefix.len], sig.signed_prefix);
    n += sig.signed_prefix.len;
    const owner = s.name.lowercase();
    @memcpy(buf[n..][0..owner.len], owner.bytes());
    n += owner.len;
    const hdr = [_]u8{ 0, 15, 0, 1, 0, 0, 0x0e, 0x10, 0, @intCast(s.rdatas[0].len) };
    @memcpy(buf[n..][0..hdr.len], &hdr);
    n += hdr.len;
    @memcpy(buf[n..][0..s.rdatas[0].len], s.rdatas[0]);
    n += s.rdatas[0].len;
    return buf[0..n];
}

fn checkRfc8080(src: []const u8) !void {
    var f = try Fixture.init(src);
    defer f.deinit();
    try expectDsMatch(&f);
    const k = f.set(.dnskey);
    const mx = f.set(.mx);
    try testing.expectError(error.BadLabelCount, f.verifyWith(.mx, t2015));
    var buf: [512]u8 = undefined;
    const data = rfc8080SignedData(&buf, mx);
    const key = try rdata.Dnskey.parse(k.rdatas[0]);
    try crypto.verify(.ed25519, key.public_key, &.{data}, mx.sigs[0].rrsig.signature);
    buf[data.len - 1] ^= 1;
    try testing.expectError(error.InvalidSignature, crypto.verify(.ed25519, key.public_key, &.{data}, mx.sigs[0].rrsig.signature));
}

test "RFC 8080 §6.1 Ed25519 example 1" {
    try checkRfc8080(
        \\example.com. 3600 IN DNSKEY 257 3 15 (
        \\             l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )
        \\example.com. 3600 IN DS 3613 15 2 (
        \\             3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79
        \\             a304b )
        \\example.com. 3600 IN MX 10 mail.example.com.
        \\example.com. 3600 IN RRSIG MX 15 3 3600 (
        \\             1440021600 1438207200 3613 example.com.
        \\             Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj
        \\             H5GaMWeG96GUVZu6ECKOQmemHDg== )
    );
}

test "RFC 8080 §6.1 Ed25519 example 2" {
    try checkRfc8080(
        \\example.com. 3600 IN DNSKEY 257 3 15 (
        \\             zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs= )
        \\example.com. 3600 IN DS 35217 15 2 (
        \\             401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c
        \\             6614c )
        \\example.com. 3600 IN MX 10 mail.example.com.
        \\example.com. 3600 IN RRSIG MX 15 3 3600 (
        \\             1440021600 1438207200 35217 example.com.
        \\             5LL2obmzdqjWI+Xto5eP5adXt/T5tMhasWvwcyW4L3SzfcRawOle9bodhC+
        \\             oip9ayUGjY9T/rL4rN3bOuESGDA== )
    );
}

test "RFC 8080 §6.2 Ed448: DS digest matches, signature reported unsupported" {
    var f = try Fixture.init(
        \\example.com. 3600 IN DNSKEY 257 3 16 (
        \\             3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx
        \\             1FYYUcJKm1MDpJtIA )
        \\example.com. 3600 IN DS 9713 16 2 (
        \\             6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2
        \\             b19c7 )
        \\example.com. 3600 IN MX 10 mail.example.com.
        \\example.com. 3600 IN RRSIG MX 16 3 3600 (
        \\             1440021600 1438207200 9713 example.com.
        \\             Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Qy/lSLFoIk1L+9e3
        \\             9GPL+5tVzDPN3f9kAwiu8KCuPPjtl227ayaCZtRKZuJax7n9NuYlZJIusX0
        \\             SOIOKBGzG+yWYtz1/jjbzl5GGkWvREUCUA )
    );
    defer f.deinit();
    try expectDsMatch(&f);
    // Same Labels defect as the Ed25519 examples; and Ed448 is not in std.
    try testing.expectError(error.BadLabelCount, f.verifyWith(.mx, t2015));
    const key = try rdata.Dnskey.parse(f.set(.dnskey).rdatas[0]);
    var buf: [512]u8 = undefined;
    const mx = f.set(.mx);
    const data = rfc8080SignedData(&buf, mx);
    try testing.expectError(error.UnsupportedAlgorithm, crypto.verify(key.algorithm, key.public_key, &.{data}, mx.sigs[0].rrsig.signature));
}

// ---------------------------------------------------------------------------
// Negative tests on a known-good vector (RFC 6605 P-256).
// ---------------------------------------------------------------------------

test "negative: tampered record, wrong time, wrong key, key flags" {
    var f = try Fixture.init(rfc6605_p256);
    defer f.deinit();
    const k = f.set(.dnskey);
    const a = f.set(.a);

    // Tampered RDATA.
    const orig = a.rdatas[0];
    const tampered = [_]u8{ 192, 0, 2, 2 };
    const list = [_][]const u8{&tampered};
    a.rdatas = &list;
    try testing.expectError(error.InvalidSignature, rrset.verify(testing.allocator, a, &a.sigs[0], &k.name, k.rdatas[0], t2010aug, 0));
    const restore = [_][]const u8{orig};
    a.rdatas = &restore;
    try rrset.verify(testing.allocator, a, &a.sigs[0], &k.name, k.rdatas[0], t2010aug, 0);

    // Expired / not yet valid.
    try testing.expectError(error.SignatureExpired, rrset.verify(testing.allocator, a, &a.sigs[0], &k.name, k.rdatas[0], 1284026680, 0));
    try testing.expectError(error.SignatureNotYetValid, rrset.verify(testing.allocator, a, &a.sigs[0], &k.name, k.rdatas[0], 1281607478, 0));

    // A different key (the P-384 vector's key) with the same owner.
    var other = try text.parseZone(testing.allocator,
        \\example.net. 3600 IN DNSKEY 257 3 13 (
        \\        xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
        \\        w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8 )
    , .{}, null);
    defer other.deinit();
    try testing.expectError(error.KeyTagMismatch, rrset.verify(testing.allocator, a, &a.sigs[0], &k.name, other.records[0].rdata, t2010aug, 0));

    // Zone-key flag cleared / revoke flag set / wrong protocol.
    var buf: [128]u8 = undefined;
    const kr = k.rdatas[0];
    @memcpy(buf[0..kr.len], kr);
    buf[0] = 0x00; // flags 0x0001: SEP only
    try testing.expectError(error.KeyNotZoneKey, rrset.verify(testing.allocator, a, &a.sigs[0], &k.name, buf[0..kr.len], t2010aug, 0));
    buf[0] = 0x01;
    buf[1] = 0x81; // REVOKE
    try testing.expectError(error.KeyRevoked, rrset.verify(testing.allocator, a, &a.sigs[0], &k.name, buf[0..kr.len], t2010aug, 0));
    buf[1] = 0x01;
    buf[2] = 2;
    try testing.expectError(error.KeyBadProtocol, rrset.verify(testing.allocator, a, &a.sigs[0], &k.name, buf[0..kr.len], t2010aug, 0));

    // Key owner differs from signer.
    const wrong_owner = try Name.fromText("example.org.");
    try testing.expectError(error.KeyOwnerMismatch, rrset.verify(testing.allocator, a, &a.sigs[0], &wrong_owner, k.rdatas[0], t2010aug, 0));

    // Signature bit flip.
    var sig_rd: [256]u8 = undefined;
    const srd = a.sigs[0].rdata;
    @memcpy(sig_rd[0..srd.len], srd);
    sig_rd[srd.len - 5] ^= 0x40;
    const bad_sig: rrset.Sig = .{ .rrsig = try rdata.Rrsig.parse(sig_rd[0..srd.len]), .rdata = sig_rd[0..srd.len], .ttl = 3600 };
    try testing.expectError(error.InvalidSignature, rrset.verify(testing.allocator, a, &bad_sig, &k.name, k.rdatas[0], t2010aug, 0));
}

test "case and duplicate insensitivity of signed data" {
    var f = try Fixture.init(
        \\EXAMPLE.net. 3600 IN DNSKEY 257 3 13 (
        \\        GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
        \\        krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )
        \\WWW.Example.NET. 3600 IN A 192.0.2.1
        \\www.example.net. 3600 IN A 192.0.2.1
        \\www.example.net. 3600 IN RRSIG A 13 3 3600 (
        \\        20100909100439 20100812100439 55648 Example.Net.
        \\        qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
        \\        yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== )
    );
    defer f.deinit();
    try testing.expectEqual(@as(usize, 2), f.set(.a).rdatas.len);
    try f.verifyWith(.a, t2010aug);
}

// ---------------------------------------------------------------------------
// Whole signed zones from the RFC appendices: every RRSIG must verify with
// the apex DNSKEY whose tag it names, at a time inside its window.
// ---------------------------------------------------------------------------

fn verifyWholeZone(src: []const u8, now: u32, expected_alg: lib.wire.types.Algorithm) !usize {
    var z = try text.parseZone(testing.allocator, src, .{}, null);
    defer z.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const g = try rrset.group(arena.allocator(), z.records);
    try testing.expectEqual(@as(usize, 0), g.orphan_sigs.len);
    const apex = try Name.fromText("example.");
    var dnskeys: ?*const rrset.RrSet = null;
    for (g.sets) |*s| if (s.type == .dnskey and s.name.eql(&apex)) {
        dnskeys = s;
    };
    const ks = dnskeys orelse return error.TestUnexpectedResult;
    var verified: usize = 0;
    for (g.sets) |*s| {
        for (s.sigs) |*sig| {
            try testing.expectEqual(expected_alg, sig.rrsig.algorithm);
            const key = for (ks.rdatas) |kr| {
                if (keys.keyTag(kr) == sig.rrsig.key_tag) break kr;
            } else return error.TestUnexpectedResult;
            try rrset.verify(testing.allocator, s, sig, &ks.name, key, now, 0);
            verified += 1;
        }
    }
    var total: usize = 0;
    for (z.records) |r| {
        if (r.type == .rrsig) total += 1;
    }
    try testing.expectEqual(total, verified);
    return verified;
}

test "RFC 4035 Appendix A: all 27 RSASHA1 signatures verify" {
    // 2004-04-20T00:00:00Z
    try testing.expectEqual(@as(usize, 27), try verifyWholeZone(@embedFile("testdata/rfc/rfc4035-appendix-a.zone"), 1082419200, .rsasha1));
}

test "RFC 5155 Appendix A: all 30 RSASHA1-NSEC3-SHA1 signatures verify" {
    // 2010-01-01T00:00:00Z
    try testing.expectEqual(@as(usize, 30), try verifyWholeZone(@embedFile("testdata/rfc/rfc5155-appendix-a.zone"), 1262304000, .rsasha1_nsec3_sha1));
}

test "RFC 4035 Appendix A: signatures fail outside their window and after tampering" {
    const src = @embedFile("testdata/rfc/rfc4035-appendix-a.zone");
    try testing.expectError(error.SignatureExpired, verifyWholeZone(src, 1100000000, .rsasha1));
    try testing.expectError(error.SignatureNotYetValid, verifyWholeZone(src, 1000000000, .rsasha1));
    // Change one address in the zone text.
    const idx = std.mem.find(u8, src, "192.0.2.1").?;
    var copy: [src.len]u8 = src.*;
    copy[idx + 8] = '9';
    try testing.expectError(error.InvalidSignature, verifyWholeZone(&copy, 1082419200, .rsasha1));
}
