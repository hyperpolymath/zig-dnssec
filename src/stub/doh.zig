// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! DNS over HTTPS (RFC 8484), HTTP/1.1 over TLS, built directly on
//! std.crypto.tls.Client and std.http's response-head parser.
//!
//! Why not std.http.Client: in Zig 0.17.0 its HTTPS-through-CONNECT-proxy
//! path does not start TLS inside the tunnel, so the request (here: the DNS
//! query) leaves the proxy in cleartext. That was verified by observation
//! (see SECURITY.md). This transport opens its own connection, optionally
//! through an HTTP CONNECT proxy, and always performs TLS end to end with
//! certificate and host-name verification against the configured bundle.
//!
//! Each exchange uses a fresh connection (no keep-alive). Requests are POST
//! `application/dns-message`; the response must be 200 with that media
//! type, identity encoding, a Content-Length, and at most 65535 octets.
//! HTTP/2 is not supported, so HTTP/2-only servers (e.g. Unbound's DoH
//! listener) cannot be used directly.

const std = @import("std");
const transport_mod = @import("transport.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const media_type = "application/dns-message";

pub const Error = error{
    InsecureUrl,
    HttpStatus,
    BadContentType,
    ResponseTooLarge,
    MissingContentLength,
    UnexpectedContentEncoding,
    UnexpectedTransferEncoding,
    ProxyRefused,
};

pub const Proxy = struct {
    host: []const u8,
    port: u16,

    /// Parses "http://host:port" (as in the https_proxy variable).
    pub fn parse(url: []const u8) !Proxy {
        const uri = try std.Uri.parse(url);
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.UnsupportedProxyScheme;
        const host = switch (uri.host orelse return error.UriMissingHost) {
            .raw => |r| r,
            .percent_encoded => |p| p,
        };
        if (uri.user != null or uri.password != null) return error.ProxyAuthUnsupported;
        return .{ .host = host, .port = uri.port orelse 80 };
    }
};

pub const DohTransport = struct {
    io: Io,
    host: []const u8,
    port: u16,
    path: []const u8,
    /// The query component of the configured request target, without the
    /// leading "?", or null when the URL has none. `std.Uri` stores the query
    /// separately from `path`, so it has to be carried and re-joined here:
    /// RFC 9112 §3.2.2 defines the request target as path *and* query, and a
    /// DoH template such as `https://resolver.example/dns-query?token=...`
    /// (RFC 8484 §3.1) uses the query for routing or authentication. Both
    /// fields borrow from the `url` slice given to `init`.
    query: ?[]const u8 = null,
    proxy: ?Proxy,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: Io.RwLock = .init,

    /// `url` must be https. Its path and query together form the request
    /// target. The bundle must already be populated (e.g. `Bundle.rescan`).
    pub fn init(io: Io, url: []const u8, ca_bundle: *std.crypto.Certificate.Bundle, proxy: ?Proxy) !DohTransport {
        const uri = try std.Uri.parse(url);
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.InsecureUrl;
        const host = switch (uri.host orelse return error.UriMissingHost) {
            .raw => |r| r,
            .percent_encoded => |p| p,
        };
        // Kept in the form it appeared in the URL: a request target is
        // percent-encoded on the wire, so decoding it here would corrupt any
        // reserved octet a DoH template carries.
        const path = switch (uri.path) {
            .raw => |r| r,
            .percent_encoded => |p| p,
        };
        const query: ?[]const u8 = if (uri.query) |q| switch (q) {
            .raw => |r| r,
            .percent_encoded => |p| p,
        } else null;
        return .{
            .io = io,
            .host = host,
            .port = uri.port orelse 443,
            .path = if (path.len == 0) "/" else path,
            .query = if (query) |q| (if (q.len == 0) null else q) else null,
            .proxy = proxy,
            .ca_bundle = ca_bundle,
        };
    }

    /// The origin-form request target (RFC 9112 §3.2.1): path, then "?" and
    /// the query when one was configured. Written straight to the wire, so a
    /// long template needs no buffer here.
    fn writeRequestTarget(self: *const DohTransport, w: anytype) !void {
        try w.writeAll(self.path);
        if (self.query) |q| {
            try w.writeByte('?');
            try w.writeAll(q);
        }
    }

    pub fn transport(self: *DohTransport) transport_mod.Transport {
        return .{ .ptr = self, .exchangeFn = exchangeThunk };
    }

    fn exchangeThunk(ptr: *anyopaque, gpa: Allocator, query: []u8) anyerror![]u8 {
        const self: *DohTransport = @ptrCast(@alignCast(ptr));
        return self.exchange(gpa, query);
    }

    fn connectTcp(self: *DohTransport, host: []const u8, port: u16) !Io.net.Stream {
        if (Io.net.IpAddress.parse(host, port)) |addr| {
            return addr.connect(self.io, .{ .mode = .stream });
        } else |_| {
            const hn = try Io.net.HostName.init(host);
            return hn.connect(self.io, port, .{ .mode = .stream });
        }
    }

    pub fn exchange(self: *DohTransport, gpa: Allocator, query: []const u8) ![]u8 {
        const io = self.io;
        const tls_len = std.crypto.tls.Client.min_buffer_len;
        const bufs = try gpa.alloc(u8, 4 * tls_len + 8192);
        defer gpa.free(bufs);
        const sock_read = bufs[0..tls_len];
        const sock_write = bufs[tls_len..][0..tls_len];
        const tls_read = bufs[2 * tls_len ..][0 .. tls_len + 8192];
        const tls_write = bufs[3 * tls_len + 8192 ..][0..tls_len];

        const stream = if (self.proxy) |p| try self.connectTcp(p.host, p.port) else try self.connectTcp(self.host, self.port);
        defer stream.close(io);
        var sr = stream.reader(io, sock_read);
        var sw = stream.writer(io, sock_write);

        if (self.proxy != null) {
            // RFC 9110 §9.3.6 CONNECT; TLS then runs end to end through it.
            try sw.interface.print("CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n\r\n", .{ self.host, self.port, self.host, self.port });
            try sw.interface.flush();
            var hr: std.http.Reader = .{ .in = &sr.interface, .state = .ready, .interface = undefined, .max_head_len = 4096 };
            const head_bytes = try hr.receiveHead();
            const head = try std.http.Client.Response.Head.parse(head_bytes);
            if (head.status != .ok) return error.ProxyRefused;
        }

        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        var tls = try std.crypto.tls.Client.init(&sr.interface, &sw.interface, .{
            .host = .{ .explicit = self.host },
            .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &self.ca_lock, .bundle = self.ca_bundle } },
            .read_buffer = tls_read,
            .write_buffer = tls_write,
            .entropy = &entropy,
            .realtime_now = Io.Clock.real.now(io),
        });

        const w = &tls.writer;
        try w.writeAll("POST ");
        try self.writeRequestTarget(w);
        try w.writeAll(" HTTP/1.1\r\n");
        if (self.port == 443) try w.print("Host: {s}\r\n", .{self.host}) else try w.print("Host: {s}:{d}\r\n", .{ self.host, self.port });
        try w.print("Content-Type: {s}\r\nAccept: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ media_type, media_type, query.len });
        try w.writeAll(query);
        try w.flush();
        try sw.interface.flush();

        var hr: std.http.Reader = .{ .in = &tls.reader, .state = .ready, .interface = undefined, .max_head_len = 8192 };
        const head_bytes = try hr.receiveHead();
        const head = try std.http.Client.Response.Head.parse(head_bytes);
        if (head.status != .ok) return error.HttpStatus;
        const ct = head.content_type orelse return error.BadContentType;
        const essence = std.mem.trim(u8, ct[0 .. std.mem.findScalar(u8, ct, ';') orelse ct.len], " ");
        if (!std.ascii.eqlIgnoreCase(essence, media_type)) return error.BadContentType;
        if (head.content_encoding != .identity) return error.UnexpectedContentEncoding;
        if (head.transfer_encoding != .none) return error.UnexpectedTransferEncoding;
        const len = head.content_length orelse return error.MissingContentLength;
        if (len > 65535) return error.ResponseTooLarge;
        const body = try gpa.alloc(u8, @intCast(len));
        errdefer gpa.free(body);
        var transfer: [64]u8 = undefined;
        const br = hr.bodyReader(&transfer, .none, len);
        try br.readSliceAll(body);
        return body;
    }
};

test "the configured query component stays in the request target" {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    // `init` only stores the Io; it performs no I/O, so nothing here reads it.
    const io: Io = undefined;
    const testing = std.testing;

    // RFC 8484 §3.1 allows a DoH URI template to carry a query, and operators
    // use one for routing or authentication. std.Uri keeps the query separate
    // from `path`, so retaining only `path` sent "POST /dns-query" and silently
    // dropped it.
    var t = try DohTransport.init(io, "https://resolver.example:8443/dns-query?token=abc%20def&kid=k1", &bundle, null);
    try testing.expectEqualStrings("resolver.example", t.host);
    try testing.expectEqual(@as(u16, 8443), t.port);
    try testing.expectEqualStrings("/dns-query", t.path);
    try testing.expectEqualStrings("token=abc%20def&kid=k1", t.query.?);
    // The target is percent-encoded on the wire, so escapes survive verbatim
    // rather than being decoded into reserved octets.
    var buf: [128]u8 = undefined;
    _ = &buf;
    var w = std.Io.Writer.fixed(&buf);
    try t.writeRequestTarget(&w);
    try testing.expectEqualStrings("/dns-query?token=abc%20def&kid=k1", w.buffered());

    // No query: the target is the path alone, and an empty path becomes "/".
    var t2 = try DohTransport.init(io, "https://dns.example", &bundle, null);
    try testing.expectEqual(@as(u16, 443), t2.port);
    try testing.expectEqualStrings("/", t2.path);
    try testing.expect(t2.query == null);
    var buf2: [128]u8 = undefined;
    _ = &buf2;
    var w2 = std.Io.Writer.fixed(&buf2);
    try t2.writeRequestTarget(&w2);
    try testing.expectEqualStrings("/", w2.buffered());

    // A present-but-empty query is not a query: no bare "?" on the wire.
    const t3 = try DohTransport.init(io, "https://dns.example/dns-query?", &bundle, null);
    try testing.expectEqualStrings("/dns-query", t3.path);
    try testing.expect(t3.query == null);

    // A proxy is parsed independently of the target.
    const p = try Proxy.parse("http://proxy.example:3128");
    const t4 = try DohTransport.init(io, "https://dns.example/dns-query?a=b", &bundle, p);
    try testing.expectEqualStrings("proxy.example", t4.proxy.?.host);
    try testing.expectEqual(@as(u16, 3128), t4.proxy.?.port);

    // http is still refused; a query is never a reason to relax that.
    try testing.expectError(error.InsecureUrl, DohTransport.init(io, "http://dns.example/dns-query?a=b", &bundle, null));
}
