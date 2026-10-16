const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store.zig");
const json = @import("json.zig");
const ed25519 = @import("ed25519.zig");
const Manifest = store.Manifest;

pub const ManifestError = error{
    ChangeMalformed,
    ManifestTorn,
    SigInvalid,
    OutOfMemory,
};

/// Validates a normalized relative manifest path (`/` separators):
/// non-empty, no leading `/`, and every segment nonempty and neither `.`
/// nor `..` (`docs/flint-blobs-spec.md` §2 — bad spellings are refused
/// `manifest_torn` and never produced by a conforming writer). NUL is a
/// path byte on POSIX but is refused here: it cannot survive a filesystem
/// materialization and has no legitimate use in a source inventory.
pub fn isValidManifestPath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/') return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0) return false;
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
        if (std.mem.indexOfScalar(u8, segment, 0) != null) return false;
    }
    return true;
}

/// Parses and validates a single JSONL manifest line into a `Manifest`,
/// enforcing §1/§2 shape: UUID stream/change, lowercase-hex author and sig,
/// sorted `files`, normalized paths, and the `reason` pairing rule.
/// Structural failures are `ChangeMalformed`; path-containment violations
/// are `ManifestTorn` per the spec's refusal naming.
pub fn parseManifestLine(allocator: Allocator, raw_line: []const u8) ManifestError!Manifest {
    const s = std.mem.trimEnd(u8, raw_line, "\r\n");
    if (s.len == 0 or std.mem.indexOfScalar(u8, s, '\n') != null or std.mem.indexOfScalar(u8, s, '\r') != null) {
        return error.ChangeMalformed;
    }

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, s, .{}) catch return error.ChangeMalformed;
    defer parsed.deinit();

    var m = json.parseManifestFromValue(allocator, parsed.value) catch |err| switch (err) {
        error.ChangeMalformed, error.StreamMalformed => return error.ChangeMalformed,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer m.deinit(allocator);

    if (!store.isValidUUID(m.stream)) return error.ChangeMalformed;
    if (!store.isValidUUID(m.change)) return error.ChangeMalformed;
    if (!store.isValidHex64(m.author)) return error.ChangeMalformed;
    if (!store.isValidHex128(m.sig)) return error.ChangeMalformed;

    var prev_path: ?[]const u8 = null;
    for (m.files) |f| {
        if (!isValidManifestPath(f.path)) return error.ManifestTorn;
        if (f.blob) |blob_id| {
            if (!store.isValidHex64(blob_id)) return error.ChangeMalformed;
            if (f.reason != null) return error.ChangeMalformed;
        } else {
            const reason = f.reason orelse return error.ChangeMalformed;
            if (!std.mem.eql(u8, reason, "too_large") and !std.mem.eql(u8, reason, "unsupported")) {
                return error.ChangeMalformed;
            }
        }
        if (prev_path) |prev| {
            if (std.mem.order(u8, prev, f.path) != .lt) return error.ChangeMalformed;
        }
        prev_path = f.path;
    }

    return m;
}

/// Builds the canonical `"flint-manifest-v1\n" || canonical(<stream,change,
/// author,files>)` signature preimage — a domain deliberately disjoint from
/// the `FLINT-CHANGE/1` preimage (`docs/flint-blobs-spec.md` §5).
pub fn manifestSigMsg(allocator: Allocator, m: *const Manifest) ManifestError![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    aw.writer.writeAll("flint-manifest-v1\n") catch return error.OutOfMemory;
    json.writeManifestCanonical(&aw.writer, m) catch return error.OutOfMemory;

    return aw.toOwnedSlice();
}

/// Verifies a manifest's Ed25519 signature under `author_hex` — the bound
/// Change's author, which `put_manifest` requires `m.author` to equal.
pub fn verifyManifest(allocator: Allocator, m: *const Manifest, author_hex: []const u8) ManifestError!void {
    const msg = try manifestSigMsg(allocator, m);
    defer allocator.free(msg);

    const pub_bytes = store.decodeLowerHexFixed(32, author_hex) orelse return error.ChangeMalformed;
    const sig_bytes = store.decodeLowerHexFixed(64, m.sig) orelse return error.ChangeMalformed;

    if (!ed25519.verify(msg, sig_bytes, pub_bytes)) {
        return error.SigInvalid;
    }
}

/// Signs a `Manifest` in place with a 32-byte Ed25519 seed (used by tests).
pub fn signManifestWithSeed(allocator: Allocator, m: *Manifest, seed: [32]u8) !void {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const pub_hex = store.encodeLowerHexFixed(32, kp.public_key.toBytes());
    allocator.free(m.author);
    m.author = try allocator.dupe(u8, &pub_hex);

    const msg = try manifestSigMsg(allocator, m);
    defer allocator.free(msg);

    const sig = try kp.sign(msg, null);
    const sig_hex = store.encodeLowerHexFixed(64, sig.toBytes());
    allocator.free(m.sig);
    m.sig = try allocator.dupe(u8, &sig_hex);
}

test "isValidManifestPath accepts normalized relative paths and refuses escapes" {
    try std.testing.expect(isValidManifestPath("src/main.zig"));
    try std.testing.expect(isValidManifestPath("a"));
    try std.testing.expect(isValidManifestPath("a.b/c-d_e/f.go"));

    try std.testing.expect(!isValidManifestPath(""));
    try std.testing.expect(!isValidManifestPath("/abs/path"));
    try std.testing.expect(!isValidManifestPath("../escape"));
    try std.testing.expect(!isValidManifestPath("a/../b"));
    try std.testing.expect(!isValidManifestPath("a/./b"));
    try std.testing.expect(!isValidManifestPath("a//b"));
    try std.testing.expect(!isValidManifestPath("a/"));
    try std.testing.expect(!isValidManifestPath("a\x00b"));
}

test "parseManifestLine validates shape, sorted files, and reason pairing" {
    const allocator = std.testing.allocator;
    const blob = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const good = "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"b.zig\",\"blob\":\"" ++ blob ++ "\",\"bytes\":4,\"mode\":755},{\"path\":\"x/a.go\",\"blob\":null,\"bytes\":0,\"mode\":644,\"reason\":\"unsupported\"}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}";
    var m = try parseManifestLine(allocator, good);
    defer m.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), m.files.len);
    try std.testing.expectEqualStrings("unsupported", m.files[1].reason.?);

    const bad = [_][]const u8{
        // unsorted and duplicate paths
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"b\",\"blob\":\"" ++ blob ++ "\",\"bytes\":1,\"mode\":644},{\"path\":\"a\",\"blob\":\"" ++ blob ++ "\",\"bytes\":1,\"mode\":644}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"a\",\"blob\":\"" ++ blob ++ "\",\"bytes\":1,\"mode\":644},{\"path\":\"a\",\"blob\":\"" ++ blob ++ "\",\"bytes\":1,\"mode\":644}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
        // reason on a blobbed entry; blob null without reason; bad reason value
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"a\",\"blob\":\"" ++ blob ++ "\",\"bytes\":1,\"mode\":644,\"reason\":\"too_large\"}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"a\",\"blob\":null,\"bytes\":1,\"mode\":644}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"a\",\"blob\":null,\"bytes\":1,\"mode\":644,\"reason\":\"missing\"}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
        // short blob id, bad sig hex, wrong stream shape
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"a\",\"blob\":\"ab\",\"bytes\":1,\"mode\":644}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[],\"sig\":\"00\"}",
        "{\"stream\":\"main\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
    };
    for (bad) |line| {
        try std.testing.expectError(error.ChangeMalformed, parseManifestLine(allocator, line));
    }

    const torn = [_][]const u8{
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"../x\",\"blob\":\"" ++ blob ++ "\",\"bytes\":1,\"mode\":644}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"/etc/passwd\",\"blob\":\"" ++ blob ++ "\",\"bytes\":1,\"mode\":644}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
        "{\"stream\":\"0199de2d-dc00-7000-8000-000000000010\",\"change\":\"0199de2d-dc00-7000-8000-000000000100\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"a/./b\",\"blob\":\"" ++ blob ++ "\",\"bytes\":1,\"mode\":644}],\"sig\":\"" ++ @as([128]u8, @splat('0')) ++ "\"}",
    };
    for (torn) |line| {
        try std.testing.expectError(error.ManifestTorn, parseManifestLine(allocator, line));
    }
}

test "manifest signature binds stream, change, author and every file entry" {
    const allocator = std.testing.allocator;
    const seed: [32]u8 = @splat(0x42);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const author_hex = store.encodeLowerHexFixed(32, kp.public_key.toBytes());
    const blob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const zero_sig: [128]u8 = @splat('0');

    var files = [_]store.ManifestFile{.{ .path = "src/main.zig", .blob = blob, .bytes = 7, .mode = 644 }};
    var m = Manifest{
        .stream = "0199de2d-dc00-7000-8000-000000000010",
        .change = "0199de2d-dc00-7000-8000-000000000100",
        .author = try allocator.dupe(u8, &author_hex),
        .files = &files,
        .sig = try allocator.dupe(u8, &zero_sig),
    };
    try signManifestWithSeed(allocator, &m, seed);
    defer allocator.free(m.author);
    defer allocator.free(m.sig);

    try verifyManifest(allocator, &m, &author_hex);

    // Any field substitution — a different valid blob, the change id, or the
    // key it is checked under — must fail, never crash.
    files[0].blob = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    try std.testing.expectError(error.SigInvalid, verifyManifest(allocator, &m, &author_hex));
    files[0].blob = blob;
    m.change = "0199de2d-dc00-7000-8000-000000000101";
    try std.testing.expectError(error.SigInvalid, verifyManifest(allocator, &m, &author_hex));
    m.change = "0199de2d-dc00-7000-8000-000000000100";
    const other: [64]u8 = @splat('a');
    try std.testing.expectError(error.SigInvalid, verifyManifest(allocator, &m, &other));

    // The signed form is the flint-manifest-v1 domain plus canonical JSON.
    const msg = try manifestSigMsg(allocator, &m);
    defer allocator.free(msg);
    try std.testing.expect(std.mem.startsWith(u8, msg, "flint-manifest-v1\n{"));
}
