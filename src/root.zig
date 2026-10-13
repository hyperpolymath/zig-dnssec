// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell

//! zig-dnssec — an experimental, pure-Zig DNS wire-format codec and DNSSEC
//! validator with a DoH stub client. See README.md: this code has not been
//! independently reviewed and must not be relied on for security decisions.

pub const sec = struct {
    pub const crypto = @import("dnssec/crypto.zig");
    pub const keys = @import("dnssec/keys.zig");
    pub const rrset = @import("dnssec/rrset.zig");
    pub const nsec = @import("dnssec/nsec.zig");
    pub const nsec3 = @import("dnssec/nsec3.zig");
    pub const anchors = @import("dnssec/anchors.zig");
    pub const validator = @import("dnssec/validator.zig");
};

pub const stub = struct {
    pub const transport = @import("stub/transport.zig");
    pub const doh = @import("stub/doh.zig");
    pub const client = @import("stub/client.zig");
};

pub const wire = struct {
    pub const name = @import("wire/name.zig");
    pub const encoding = @import("wire/encoding.zig");
    pub const text = @import("wire/text.zig");
    pub const types = @import("wire/types.zig");
    pub const rdata = @import("wire/rdata.zig");
    pub const message = @import("wire/message.zig");
    pub const builder = @import("wire/builder.zig");

    pub const Name = name.Name;
    pub const Type = types.Type;
    pub const Class = types.Class;
    pub const Message = message.Message;
    pub const Rr = message.Rr;
    pub const Builder = builder.Builder;
};

test {
    @import("std").testing.refAllDecls(wire);
    _ = @import("wire/name.zig");
    _ = @import("wire/types.zig");
    _ = @import("wire/rdata.zig");
    _ = @import("wire/message.zig");
    _ = @import("wire/builder.zig");
    _ = @import("dnssec/crypto.zig");
    _ = @import("wire/encoding.zig");
    _ = @import("wire/text.zig");
    _ = @import("dnssec/keys.zig");
    _ = @import("dnssec/rrset.zig");
    _ = @import("dnssec/nsec.zig");
    _ = @import("dnssec/nsec3.zig");
    _ = @import("dnssec/anchors.zig");
    _ = @import("dnssec/validator.zig");
    _ = @import("stub/transport.zig");
    _ = @import("stub/doh.zig");
    _ = @import("stub/client.zig");
}
