const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const store = @import("store.zig");
const storeio = @import("storeio.zig");

pub const AuthDomainPrefix = "FLINT-SYNC-AUTH/1\x00";

pub const ConfigError = error{
    Usage,
    OutOfMemory,
};

/// Loads a 32-byte key from a file containing 64 lowercase hex characters
/// (with an optional trailing `\n` or `\r\n`), per `docs/flint-server-spec.md` §3.2.
pub fn loadAuthKeyFile(io: Io, allocator: Allocator, path: []const u8) ConfigError![32]u8 {
    const raw = storeio.readFileBounded(io, allocator, path, 4096) catch return error.Usage;
    defer allocator.free(raw);

    const trimmed = std.mem.trimEnd(u8, raw, "\r\n");
    return store.decodeLowerHexFixed(32, trimmed) orelse return error.Usage;
}

/// Loads an allowlist of 64-char lowercase hex Ed25519 public keys (one per line,
/// ignoring blank lines and `#` comments), per `docs/flint-server-spec.md` §3.2.
pub fn loadAllowAuthorFile(io: Io, allocator: Allocator, path: []const u8) ConfigError![][64]u8 {
    const raw = storeio.readFileBounded(io, allocator, path, store.MaxFileReadBytes) catch return error.Usage;
    defer allocator.free(raw);

    var list: std.ArrayList([64]u8) = .empty;
    errdefer list.deinit(allocator);

    var start: usize = 0;
    while (start <= raw.len) {
        const end = std.mem.indexOfScalarPos(u8, raw, start, '\n') orelse raw.len;
        const line_raw = raw[start..end];
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len > 0 and line[0] != '#') {
            if (!store.isValidHex64(line)) return error.Usage;
            var entry: [64]u8 = undefined;
            @memcpy(&entry, line);
            try list.append(allocator, entry);
        }
        if (end == raw.len) break;
        start = end + 1;
    }

    return list.toOwnedSlice(allocator);
}

/// Computes `HMAC-SHA256(key, "FLINT-SYNC-AUTH/1\x00" || nonce)` over the raw 32-byte key
/// and raw 16-byte nonce (`docs/flint-server-spec.md` §2.2 & §3.2).
pub fn computeAuthHmac(key: [32]u8, nonce: [16]u8) [32]u8 {
    var h = HmacSha256.init(&key);
    h.update(AuthDomainPrefix);
    h.update(&nonce);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

pub fn verifyAuthHmacHex(key: [32]u8, nonce: [16]u8, mac_hex: []const u8) bool {
    const provided = store.decodeLowerHexFixed(32, mac_hex) orelse return false;
    const expected_raw = computeAuthHmac(key, nonce);
    return std.crypto.timing_safe.eql([32]u8, provided, expected_raw);
}

test "HMAC-SHA256 challenge verification" {
    const key: [32]u8 = @splat(0x42);
    const nonce: [16]u8 = @splat(0x07);
    const mac = computeAuthHmac(key, nonce);
    const mac_hex = store.encodeLowerHexFixed(32, mac);
    try std.testing.expect(verifyAuthHmacHex(key, nonce, &mac_hex));

    var bad_hex = mac_hex;
    bad_hex[0] = if (bad_hex[0] == '0') '1' else '0';
    try std.testing.expect(!verifyAuthHmacHex(key, nonce, &bad_hex));
}
