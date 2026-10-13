// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! Signature verification for DNSSEC algorithms, delegating every
//! cryptographic primitive to the Zig standard library (no primitives are
//! implemented here). This module only parses the DNSKEY public-key encodings
//! (RFC 3110, RFC 6605, RFC 8080) and dispatches.
//!
//! Supported (Zig 0.17.0 std):
//!   5  RSASHA1             std.crypto.Certificate.rsa.PKCS1v1_5Signature + Sha1
//!   7  RSASHA1-NSEC3-SHA1  as above
//!   8  RSASHA256           ... + sha2.Sha256
//!   10 RSASHA512           ... + sha2.Sha512
//!   13 ECDSAP256SHA256     std.crypto.sign.ecdsa.EcdsaP256Sha256
//!   14 ECDSAP384SHA384     std.crypto.sign.ecdsa.EcdsaP384Sha384
//!   15 ED25519             std.crypto.sign.Ed25519 (cofactorless verifyStrict)
//! Not supported: 16 ED448 (no Ed448/Curve448 in std), 12/23 GOST, 17 SM2SM3,
//! and the MUST-NOT algorithms 1, 3, 6.

const std = @import("std");
const types = @import("../wire/types.zig");
const Algorithm = types.Algorithm;

const rsa = std.crypto.Certificate.rsa;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

pub const VerifyError = error{
    /// The algorithm is not implemented by this library.
    UnsupportedAlgorithm,
    /// An RSA modulus size outside what this build dispatches on.
    UnsupportedKeySize,
    /// The DNSKEY public-key field is malformed for its algorithm.
    BadKey,
    /// The signature field is malformed (wrong length) for its algorithm.
    BadSignature,
    /// The signature does not verify.
    InvalidSignature,
};

pub fn isSupported(alg: Algorithm) bool {
    return switch (alg) {
        .rsasha1, .rsasha1_nsec3_sha1, .rsasha256, .rsasha512, .ecdsap256sha256, .ecdsap384sha384, .ed25519 => true,
        else => false,
    };
}

pub fn usesSha1(alg: Algorithm) bool {
    return alg == .rsasha1 or alg == .rsasha1_nsec3_sha1;
}

/// Verifies `signature` over the concatenation of `parts`.
pub fn verify(alg: Algorithm, public_key: []const u8, parts: []const []const u8, signature: []const u8) VerifyError!void {
    switch (alg) {
        .rsasha1, .rsasha1_nsec3_sha1 => return verifyRsa(Sha1, 512, public_key, parts, signature),
        .rsasha256 => return verifyRsa(Sha256, 512, public_key, parts, signature),
        // RFC 5702 §2.2: RSA/SHA-512 keys are 1024..4096 bits.
        .rsasha512 => return verifyRsa(Sha512, 1024, public_key, parts, signature),
        .ecdsap256sha256 => return verifyEcdsa(EcdsaP256, public_key, parts, signature),
        .ecdsap384sha384 => return verifyEcdsa(EcdsaP384, public_key, parts, signature),
        .ed25519 => return verifyEd25519(public_key, parts, signature),
        else => return error.UnsupportedAlgorithm,
    }
}

pub const RsaKey = struct {
    exponent: []const u8,
    modulus: []const u8,
};

/// RFC 3110 §2: exponent length (1 octet, or 0 followed by 2 octets),
/// exponent, modulus. Leading zero octets are prohibited in both.
pub fn parseRsaKey(key: []const u8) VerifyError!RsaKey {
    if (key.len < 1) return error.BadKey;
    var p: usize = 1;
    var elen: usize = key[0];
    if (elen == 0) {
        if (key.len < 3) return error.BadKey;
        elen = std.mem.readInt(u16, key[1..3], .big);
        p = 3;
        // The long form is only for exponents longer than 255 octets.
        if (elen <= 255) return error.BadKey;
    }
    if (elen == 0 or p + elen >= key.len) return error.BadKey;
    const exponent = key[p..][0..elen];
    const modulus = key[p + elen ..];
    if (exponent[0] == 0 or modulus[0] == 0) return error.BadKey;
    return .{ .exponent = exponent, .modulus = modulus };
}

/// Number of significant bits in a big-endian integer without leading zeros.
fn bitLength(be: []const u8) usize {
    if (be.len == 0) return 0;
    return (be.len - 1) * 8 + (8 - @clz(be[0]));
}

/// The std RSA verifier takes the modulus length as a comptime parameter.
/// We instantiate it for every whole-octet modulus length from 64 to 512
/// octets (512..4096 bits), stepping by 1 octet, so any key size RFC 3110
/// allows is covered.
const max_mod_octets = 512;

fn verifyRsa(comptime Hash: type, comptime min_bits: usize, key: []const u8, parts: []const []const u8, signature: []const u8) VerifyError!void {
    const k = try parseRsaKey(key);
    const bits = bitLength(k.modulus);
    if (bits < min_bits or bits > 4096) return error.UnsupportedKeySize;
    // The std verifier limits public exponents to 32 bits.
    if (k.exponent.len > 4) return error.UnsupportedKeySize;
    if (signature.len != k.modulus.len) return error.BadSignature;
    const public_key = rsa.PublicKey.fromBytes(k.exponent, k.modulus) catch return error.BadKey;
    return dispatchRsa(Hash, min_bits / 8, k.modulus.len, signature, parts, public_key);
}

fn dispatchRsa(comptime Hash: type, comptime min_octets: usize, len: usize, signature: []const u8, parts: []const []const u8, pk: rsa.PublicKey) VerifyError!void {
    if (len < min_octets or len > max_mod_octets) return error.UnsupportedKeySize;
    switch (len) {
        inline min_octets...max_mod_octets => |L| {
            rsa.PKCS1v1_5Signature.concatVerify(L, signature[0..L], parts, pk, Hash) catch
                return error.InvalidSignature;
        },
        else => unreachable,
    }
}

fn verifyEcdsa(comptime Scheme: type, key: []const u8, parts: []const []const u8, signature: []const u8) VerifyError!void {
    const coord = Scheme.SecretKey.encoded_length; // field element size
    // RFC 6605 §4: the public key is Q = x | y (uncompressed, no 0x04 prefix).
    if (key.len != 2 * coord) return error.BadKey;
    if (signature.len != Scheme.Signature.encoded_length) return error.BadSignature;
    var sec1: [1 + 2 * coord]u8 = undefined;
    sec1[0] = 0x04;
    @memcpy(sec1[1..], key);
    const pk = Scheme.PublicKey.fromSec1(&sec1) catch return error.BadKey;
    const sig = Scheme.Signature.fromBytes(signature[0..Scheme.Signature.encoded_length].*);
    var v = sig.verifier(pk) catch return error.InvalidSignature;
    for (parts) |part| v.update(part);
    v.verify() catch return error.InvalidSignature;
}

fn verifyEd25519(key: []const u8, parts: []const []const u8, signature: []const u8) VerifyError!void {
    if (key.len != Ed25519.PublicKey.encoded_length) return error.BadKey;
    if (signature.len != Ed25519.Signature.encoded_length) return error.BadSignature;
    const pk = Ed25519.PublicKey.fromBytes(key[0..32].*) catch return error.BadKey;
    const sig = Ed25519.Signature.fromBytes(signature[0..64].*);
    var v = sig.verifier(pk) catch return error.InvalidSignature;
    for (parts) |part| v.update(part);
    // Cofactorless verification, matching OpenSSL (used by Unbound and ldns).
    v.verifyStrict() catch return error.InvalidSignature;
}

// ---------------------------------------------------------------------------
// Tests. Known-answer vectors from the RFCs live in tests/vectors.zig.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "RFC 3110 key parsing" {
    try testing.expectError(error.BadKey, parseRsaKey(&.{}));
    try testing.expectError(error.BadKey, parseRsaKey(&.{ 3, 1, 0, 1 })); // no modulus
    try testing.expectError(error.BadKey, parseRsaKey(&.{ 1, 0, 0xC1 })); // leading zero exponent
    try testing.expectError(error.BadKey, parseRsaKey(&.{ 1, 3, 0, 0xC1 })); // leading zero modulus
    try testing.expectError(error.BadKey, parseRsaKey(&.{ 0, 0, 3, 1, 0, 1, 0xC1 })); // long form for short exponent
    const k = try parseRsaKey(&.{ 3, 1, 0, 1, 0xC1, 0x23 });
    try testing.expectEqualSlices(u8, &.{ 1, 0, 1 }, k.exponent);
    try testing.expectEqualSlices(u8, &.{ 0xC1, 0x23 }, k.modulus);
}

test "unsupported algorithms are reported, not accepted" {
    try testing.expectError(error.UnsupportedAlgorithm, verify(.ed448, &.{}, &.{}, &.{}));
    try testing.expectError(error.UnsupportedAlgorithm, verify(.rsamd5, &.{}, &.{}, &.{}));
    try testing.expectError(error.UnsupportedAlgorithm, verify(.dsa, &.{}, &.{}, &.{}));
    try testing.expectError(error.UnsupportedAlgorithm, verify(.ecc_gost, &.{}, &.{}, &.{}));
    try testing.expectError(error.UnsupportedAlgorithm, verify(@enumFromInt(200), &.{}, &.{}, &.{}));
}

test "Ed25519 round trip through std, and tamper detection" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(7));
    const msg = "dnssec signed data";
    const sig = try kp.sign(msg, null);
    const pk = kp.public_key.toBytes();
    const sb = sig.toBytes();
    try verify(.ed25519, &pk, &.{ "dnssec ", "signed data" }, &sb);
    try testing.expectError(error.InvalidSignature, verify(.ed25519, &pk, &.{"dnssec signed dat4"}, &sb));
    var bad = sb;
    bad[3] ^= 1;
    try testing.expectError(error.InvalidSignature, verify(.ed25519, &pk, &.{msg}, &bad));
    try testing.expectError(error.BadSignature, verify(.ed25519, &pk, &.{msg}, sb[0..63]));
    try testing.expectError(error.BadKey, verify(.ed25519, pk[0..31], &.{msg}, &sb));
}

test "ECDSA P-256 round trip through std" {
    const kp = try EcdsaP256.KeyPair.generateDeterministic(@splat(9));
    const msg = "abc";
    const sig = try kp.sign(msg, null);
    const sec1 = kp.public_key.toUncompressedSec1();
    try verify(.ecdsap256sha256, sec1[1..], &.{msg}, &sig.toBytes());
    try testing.expectError(error.InvalidSignature, verify(.ecdsap256sha256, sec1[1..], &.{"abd"}, &sig.toBytes()));
    try testing.expectError(error.BadKey, verify(.ecdsap256sha256, &sec1, &.{msg}, &sig.toBytes()));
}
