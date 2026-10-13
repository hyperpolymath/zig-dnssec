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
    proxy: ?Proxy,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: Io.RwLock = .init,

    /// `url` must be https. `path` may include a query string. The bundle
    /// must already be populated (e.g. `Bundle.rescan`).
    pub fn init(io: Io, url: []const u8, ca_bundle: *std.crypto.Certificate.Bundle, proxy: ?Proxy) !DohTransport {
        const uri = try std.Uri.parse(url);
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.InsecureUrl;
        const host = switch (uri.host orelse return error.UriMissingHost) {
            .raw => |r| r,
            .percent_encoded => |p| p,
        };
        const path = switch (uri.path) {
            .raw => |r| r,
            .percent_encoded => |p| p,
        };
        return .{
            .io = io,
            .host = host,
            .port = uri.port orelse 443,
            .path = if (path.len == 0) "/" else path,
            .proxy = proxy,
            .ca_bundle = ca_bundle,
        };
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
        try w.print("POST {s} HTTP/1.1\r\n", .{self.path});
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
