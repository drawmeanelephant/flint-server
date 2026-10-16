const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const json = @import("json.zig");
const change = @import("change.zig");
const manifest = @import("manifest.zig");
const storeio = @import("storeio.zig");
const contentio = @import("contentio.zig");
const proto = @import("proto.zig");

// spec_rev 4 content layer coverage (issue #43): blob_put/blob_get,
// put_manifest/get_manifest — signed-inventory binding, detached-change and
// fork content, idempotent resends, refusal surface, torn-log recovery.
fn testSignedChangeLine(
    allocator: Allocator,
    seed: [32]u8,
    id: []const u8,
    parent: ?[]const u8,
    stream_id: []const u8,
    ts: i64,
    message: []const u8,
) ![]u8 {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const author_hex = store.encodeLowerHexFixed(32, kp.public_key.toBytes());
    const zero_sig: [128]u8 = @splat('0');
    var c = store.Change{
        .id = try allocator.dupe(u8, id),
        .parent = if (parent) |p| try allocator.dupe(u8, p) else null,
        .stream = try allocator.dupe(u8, stream_id),
        .ts = ts,
        .author = try allocator.dupe(u8, &author_hex),
        .message = try allocator.dupe(u8, message),
        .ops = try allocator.alloc(store.Op, 0),
        .merged = null,
        .sig = try allocator.dupe(u8, &zero_sig),
    };
    defer c.deinit(allocator);
    try change.signChangeWithSeed(allocator, &c, seed);
    const line = try json.marshalChangeLine(allocator, &c);
    defer allocator.free(line);
    return allocator.dupe(u8, line[0 .. line.len - 1]);
}

fn testSignedManifestLine(
    allocator: Allocator,
    seed: [32]u8,
    stream_id: []const u8,
    change_id: []const u8,
    files: []const store.ManifestFile,
) ![]u8 {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const author_hex = store.encodeLowerHexFixed(32, kp.public_key.toBytes());
    const zero_sig: [128]u8 = @splat('0');
    var files_copy = try allocator.alloc(store.ManifestFile, files.len);
    var initialized: usize = 0;
    errdefer {
        for (files_copy[0..initialized]) |*f| f.deinit(allocator);
        allocator.free(files_copy);
    }
    for (files, 0..) |f, i| {
        files_copy[i] = try f.clone(allocator);
        initialized += 1;
    }
    var m = store.Manifest{
        .stream = try allocator.dupe(u8, stream_id),
        .change = try allocator.dupe(u8, change_id),
        .author = try allocator.dupe(u8, &author_hex),
        .files = files_copy,
        .sig = try allocator.dupe(u8, &zero_sig),
    };
    defer {
        allocator.free(m.stream);
        allocator.free(m.change);
        allocator.free(m.author);
        for (m.files) |*f| f.deinit(allocator);
        allocator.free(m.files);
        allocator.free(m.sig);
    }
    try manifest.signManifestWithSeed(allocator, &m, seed);
    const line = try json.marshalManifestLine(allocator, &m);
    defer allocator.free(line);
    return allocator.dupe(u8, line[0 .. line.len - 1]);
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return store.encodeLowerHexFixed(32, digest);
}

fn hexEncodeAlloc(allocator: Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    const hex_chars = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out;
}

fn tempStorePath(allocator: Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    return std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
}

fn callLine(
    allocator: Allocator,
    root_path: []const u8,
    allow_authors: ?[]const [64]u8,
    line: []const u8,
) ![]u8 {
    var session = proto.Session{ .root_path = root_path, .allow_authors = allow_authors };
    var out: Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try proto.handleLine(std.testing.io, allocator, &session, line, &out.writer);
    return out.toOwnedSlice();
}

test "blob_put/blob_get round-trip, idempotent put, id checks on both ends" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tempStorePath(allocator, &tmp);
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const payload = "package main\n\nfunc Add() {}\n";
    const id_hex = sha256Hex(payload);
    const payload_hex = try hexEncodeAlloc(allocator, payload);
    defer allocator.free(payload_hex);

    try contentio.putBlob(io, allocator, root_path, &id_hex, payload_hex);
    // Content-addressed: the same put is idempotent.
    try contentio.putBlob(io, allocator, root_path, &id_hex, payload_hex);

    const got = try contentio.getBlob(io, allocator, root_path, &id_hex);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(payload, got);

    // The blob landed at the documented portable layout.
    const blob_path = try std.fs.path.join(allocator, &.{ root_path, "blobs", id_hex[0..2], id_hex[2..] });
    defer allocator.free(blob_path);
    try std.testing.expect(storeio.fileExists(io, blob_path));

    const missing: [64]u8 = @splat('1');
    try std.testing.expectError(error.BlobMissing, contentio.getBlob(io, allocator, root_path, &missing));

    // Hash mismatch, undecodable hex, and bad id shape are blob_malformed.
    const wrong: [64]u8 = @splat('2');
    try std.testing.expectError(error.BlobMalformed, contentio.putBlob(io, allocator, root_path, &wrong, payload_hex));
    try std.testing.expectError(error.BlobMalformed, contentio.putBlob(io, allocator, root_path, &id_hex, "zz"));
    try std.testing.expectError(error.BlobMalformed, contentio.putBlob(io, allocator, root_path, &id_hex, "abc"));
    try std.testing.expectError(error.BlobMalformed, contentio.putBlob(io, allocator, root_path, "short", payload_hex));

    // Over-cap decoded size refuses BlobTooLarge (change_too_large on wire).
    const big_hex = try allocator.alloc(u8, (store.MaxBlobBytes + 1) * 2);
    defer allocator.free(big_hex);
    @memset(big_hex, 'a');
    try std.testing.expectError(error.BlobTooLarge, contentio.putBlob(io, allocator, root_path, &id_hex, big_hex));

    // A corrupted blob on disk fails its id check at read.
    try storeio.writeFileSafe(io, allocator, blob_path, "tampered");
    try std.testing.expectError(error.BlobMalformed, contentio.getBlob(io, allocator, root_path, &id_hex));
}

test "put_manifest stores signed lines for chain and detached changes; resends skip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tempStorePath(allocator, &tmp);
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const seed: [32]u8 = @splat(0x42);
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const c2_id = "0199de2d-dc00-7000-8000-000000000101";
    const d1_id = "0199de2d-dc00-7000-8000-000000000102";

    try storeio.createStream(io, allocator, root_path, .{
        .id = stream_id,
        .name = "main",
        .created = 1760000000000,
    });
    const c1_line = try testSignedChangeLine(allocator, seed, c1_id, null, stream_id, 1760000000000, "first");
    defer allocator.free(c1_line);
    const c2_line = try testSignedChangeLine(allocator, seed, c2_id, c1_id, stream_id, 1760000001000, "second");
    defer allocator.free(c2_line);
    const head = try storeio.appendStreamChanges(io, allocator, root_path, stream_id, null, &.{ c1_line, c2_line }, null);
    defer if (head) |h| allocator.free(h);
    const d1_line = try testSignedChangeLine(allocator, seed, d1_id, c1_id, stream_id, 1760000002000, "detached");
    defer allocator.free(d1_line);
    const dep = try storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{d1_line}, null);
    defer if (dep.head) |h| allocator.free(h);

    const blob_id = sha256Hex("blob bytes");
    const files_1 = [_]store.ManifestFile{.{ .path = "a/b.zig", .blob = &blob_id, .bytes = 10, .mode = 644 }};
    const files_2 = [_]store.ManifestFile{
        .{ .path = "a/b.zig", .blob = &blob_id, .bytes = 10, .mode = 644 },
        .{ .path = "bin/tool", .blob = null, .bytes = 0, .mode = 0, .reason = "unsupported" },
    };
    const m1 = try testSignedManifestLine(allocator, seed, stream_id, c1_id, &files_1);
    defer allocator.free(m1);
    const m2 = try testSignedManifestLine(allocator, seed, stream_id, c2_id, &files_2);
    defer allocator.free(m2);
    const md = try testSignedManifestLine(allocator, seed, stream_id, d1_id, &files_1);
    defer allocator.free(md);

    // Stream resolves by name like deposit; a detached change binds fine.
    try std.testing.expectEqual(
        @as(usize, 3),
        try contentio.putManifestStreamLines(io, allocator, root_path, "main", &.{ m1, m2, md }, null),
    );
    // Byte-identical resends skip; an empty log state still counts them.
    try std.testing.expectEqual(
        @as(usize, 0),
        try contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{ m1, m2 }, null),
    );

    var log = try contentio.loadManifestLog(io, allocator, root_path, stream_id);
    defer log.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), log.raw_lines.len);
    try std.testing.expectEqualStrings(m1, log.raw_lines[0]);
    try std.testing.expectEqualStrings(d1_id, log.changes[2]);

    // Publication never moves the head or rewrites the Change log.
    var loaded = try storeio.loadStream(io, allocator, root_path, stream_id);
    defer loaded.deinit(allocator);
    try std.testing.expectEqualStrings(c2_id, loaded.stream.head.?);
    try std.testing.expectEqual(@as(usize, 3), loaded.changes.len);
}

test "put_manifest refusals: unknown change, bad sig, conflicts, torn paths, gating" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tempStorePath(allocator, &tmp);
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const seed: [32]u8 = @splat(0x42);
    const other_seed: [32]u8 = @splat(0x99);
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";

    try std.testing.expectError(
        error.StreamMissing,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{"x"}, null),
    );

    try storeio.createStream(io, allocator, root_path, .{
        .id = stream_id,
        .name = "main",
        .created = 1760000000000,
    });
    const c1_line = try testSignedChangeLine(allocator, seed, c1_id, null, stream_id, 1760000000000, "first");
    defer allocator.free(c1_line);
    const head = try storeio.appendStreamChanges(io, allocator, root_path, stream_id, null, &.{c1_line}, null);
    defer if (head) |h| allocator.free(h);

    const blob_id = sha256Hex("x");
    const files = [_]store.ManifestFile{.{ .path = "a.zig", .blob = &blob_id, .bytes = 1, .mode = 644 }};
    const m1 = try testSignedManifestLine(allocator, seed, stream_id, c1_id, &files);
    defer allocator.free(m1);

    // Empty and oversize batches refuse change_malformed (1-256 per request).
    try std.testing.expectError(
        error.ChangeMalformed,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{}, null),
    );
    var oversize: [store.MaxManifestBatch + 1][]const u8 = undefined;
    for (&oversize) |*slot| slot.* = m1;
    try std.testing.expectError(
        error.ChangeMalformed,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &oversize, null),
    );

    // A manifest for a change nobody holds refuses change_missing.
    const m_unknown = try testSignedManifestLine(allocator, seed, stream_id, "0199de2d-dc00-7000-8000-000000000999", &files);
    defer allocator.free(m_unknown);
    try std.testing.expectError(
        error.ChangeMissing,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{m_unknown}, null),
    );

    // A manifest signed by a key other than the Change's author carries a
    // foreign author field -> change_malformed before verification.
    const m_wrong_author = try testSignedManifestLine(allocator, other_seed, stream_id, c1_id, &files);
    defer allocator.free(m_wrong_author);
    try std.testing.expectError(
        error.ChangeMalformed,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{m_wrong_author}, null),
    );

    // Same author, tampered inventory -> sig_invalid.
    const tampered = try std.mem.replaceOwned(u8, allocator, m1, "\"bytes\":1", "\"bytes\":2");
    defer allocator.free(tampered);
    try std.testing.expectError(
        error.SigInvalid,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{tampered}, null),
    );

    // A containment-breaking path refuses manifest_torn.
    const bad_path = try std.mem.replaceOwned(u8, allocator, m1, "\"path\":\"a.zig\"", "\"path\":\"../a.zig\"");
    defer allocator.free(bad_path);
    try std.testing.expectError(
        error.ManifestTorn,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{bad_path}, null),
    );

    // A manifest bound to a different stream id refuses change_malformed.
    const wrong_stream = try std.mem.replaceOwned(u8, allocator, m1, stream_id, "0199de2d-dc00-7000-8000-0000000000aa");
    defer allocator.free(wrong_stream);
    try std.testing.expectError(
        error.ChangeMalformed,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{wrong_stream}, null),
    );

    // The author allowlist gates manifests exactly like Changes.
    const allow_none = [_][64]u8{@splat('a')};
    try std.testing.expectError(
        error.AuthorNotAllowed,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{m1}, &allow_none),
    );

    // Nothing was written by the refused legs.
    try std.testing.expectEqual(
        @as(usize, 1),
        try contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{m1}, null),
    );
    // The same change under different bytes is an id conflict.
    const conflict = try std.mem.replaceOwned(u8, allocator, m1, "\"bytes\":1", "\"bytes\":9");
    defer allocator.free(conflict);
    try std.testing.expectError(
        error.ChangeIdConflict,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{conflict}, null),
    );

    var log = try contentio.loadManifestLog(io, allocator, root_path, stream_id);
    defer log.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), log.raw_lines.len);
    try std.testing.expectEqualStrings(m1, log.raw_lines[0]);
}

test "manifest log recovery: torn final line refuses manifest_torn, content-less change is fine" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tempStorePath(allocator, &tmp);
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const seed: [32]u8 = @splat(0x42);
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    try storeio.createStream(io, allocator, root_path, .{
        .id = stream_id,
        .name = "main",
        .created = 1760000000000,
    });
    const c1_line = try testSignedChangeLine(allocator, seed, c1_id, null, stream_id, 1760000000000, "first");
    defer allocator.free(c1_line);
    const head = try storeio.appendStreamChanges(io, allocator, root_path, stream_id, null, &.{c1_line}, null);
    defer if (head) |h| allocator.free(h);

    // No manifest file at all: an empty log, not an error.
    {
        var log = try contentio.loadManifestLog(io, allocator, root_path, stream_id);
        defer log.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), log.raw_lines.len);
    }

    const blob_id = sha256Hex("x");
    const files = [_]store.ManifestFile{.{ .path = "a.zig", .blob = &blob_id, .bytes = 1, .mode = 644 }};
    const m1 = try testSignedManifestLine(allocator, seed, stream_id, c1_id, &files);
    defer allocator.free(m1);
    _ = try contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{m1}, null);

    const log_path = try std.fs.path.join(allocator, &.{ root_path, "manifests", "0199de2d-dc00-7000-8000-000000000010.jsonl" });
    defer allocator.free(log_path);

    // A crash mid-append leaves a torn final line: manifest_torn, and the
    // stored bytes are not silently truncated or served.
    try storeio.appendSync(io, log_path, "{\"stream\":\"torn");
    try std.testing.expectError(error.ManifestTorn, contentio.loadManifestLog(io, allocator, root_path, stream_id));
    try std.testing.expectError(
        error.ManifestTorn,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{m1}, null),
    );
    const torn_bytes = try storeio.readFileBounded(io, allocator, log_path, store.MaxManifestLogBytes);
    defer allocator.free(torn_bytes);
    const expected = try std.fmt.allocPrint(allocator, "{s}\n{{\"stream\":\"torn", .{m1});
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, torn_bytes);
}

test "get_manifest after-cursor mirrors read; forks serve their own manifests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tempStorePath(allocator, &tmp);
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const seed: [32]u8 = @splat(0x42);
    const main_id = "0199de2d-dc00-7000-8000-000000000010";
    const fork_id = "0199de2d-dc00-7000-8000-000000000020";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const c2_id = "0199de2d-dc00-7000-8000-000000000101";
    const d1_id = "0199de2d-dc00-7000-8000-000000000102";
    const f1_id = "0199de2d-dc00-7000-8000-000000000200";

    try storeio.createStream(io, allocator, root_path, .{
        .id = main_id,
        .name = "main",
        .created = 1760000000000,
    });
    const c1_line = try testSignedChangeLine(allocator, seed, c1_id, null, main_id, 1760000000000, "first");
    defer allocator.free(c1_line);
    const c2_line = try testSignedChangeLine(allocator, seed, c2_id, c1_id, main_id, 1760000001000, "second");
    defer allocator.free(c2_line);
    const head = try storeio.appendStreamChanges(io, allocator, root_path, main_id, null, &.{ c1_line, c2_line }, null);
    defer if (head) |h| allocator.free(h);
    const d1_line = try testSignedChangeLine(allocator, seed, d1_id, c1_id, main_id, 1760000002000, "preserved original");
    defer allocator.free(d1_line);
    const dep = try storeio.depositStreamChanges(io, allocator, root_path, main_id, &.{d1_line}, null);
    defer if (dep.head) |h| allocator.free(h);

    const blob_id = sha256Hex("x");
    const files = [_]store.ManifestFile{.{ .path = "a.zig", .blob = &blob_id, .bytes = 1, .mode = 644 }};
    const m1 = try testSignedManifestLine(allocator, seed, main_id, c1_id, &files);
    defer allocator.free(m1);
    const m2 = try testSignedManifestLine(allocator, seed, main_id, c2_id, &files);
    defer allocator.free(m2);
    const md = try testSignedManifestLine(allocator, seed, main_id, d1_id, &files);
    defer allocator.free(md);
    _ = try contentio.putManifestStreamLines(io, allocator, root_path, main_id, &.{ m1, m2, md }, null);

    // Change log is [c1, c2, d1]; the after-cursor selects manifests whose
    // bound change sits after it — the same range read would produce.
    const get = struct {
        fn call(a: Allocator, root: []const u8, sid: []const u8, after: ?[]const u8) ![]u8 {
            const req = if (after) |af|
                try std.fmt.allocPrint(a, "{{\"op\":\"get_manifest\",\"seq\":1,\"stream\":\"{s}\",\"after\":\"{s}\"}}", .{ sid, af })
            else
                try std.fmt.allocPrint(a, "{{\"op\":\"get_manifest\",\"seq\":1,\"stream\":\"{s}\",\"after\":null}}", .{sid});
            defer a.free(req);
            return callLine(a, root, null, req);
        }
    }.call;
    const getLines = struct {
        fn call(a: Allocator, response: []const u8) ![][]const u8 {
            var parsed = try std.json.parseFromSlice(std.json.Value, a, response, .{});
            defer parsed.deinit();
            const items = parsed.value.object.get("lines").?.array.items;
            const out = try a.alloc([]const u8, items.len);
            for (items, 0..) |item, i| out[i] = try a.dupe(u8, item.string);
            return out;
        }
    }.call;

    {
        const all = try get(allocator, root_path, main_id, null);
        defer allocator.free(all);
        const lines = try getLines(allocator, all);
        defer {
            for (lines) |l| allocator.free(l);
            allocator.free(lines);
        }
        try std.testing.expectEqual(@as(usize, 3), lines.len);
        try std.testing.expectEqualStrings(m1, lines[0]);
        try std.testing.expectEqualStrings(m2, lines[1]);
        try std.testing.expectEqualStrings(md, lines[2]);
    }

    {
        const after_c1 = try get(allocator, root_path, main_id, c1_id);
        defer allocator.free(after_c1);
        const lines = try getLines(allocator, after_c1);
        defer {
            for (lines) |l| allocator.free(l);
            allocator.free(lines);
        }
        try std.testing.expectEqual(@as(usize, 2), lines.len);
        try std.testing.expectEqualStrings(m2, lines[0]);
        try std.testing.expectEqualStrings(md, lines[1]);
    }

    const after_d1 = try get(allocator, root_path, main_id, d1_id);
    defer allocator.free(after_d1);
    try std.testing.expectEqualStrings("{\"seq\":1,\"ok\":true,\"lines\":[]}\n", after_d1);

    const after_unknown = try get(allocator, root_path, main_id, "0199de2d-dc00-7000-8000-000000000999");
    defer allocator.free(after_unknown);
    try std.testing.expectEqualStrings(
        "{\"seq\":1,\"ok\":false,\"refuse\":\"change_missing\",\"detail\":\"after change not found in stream\"}\n",
        after_unknown,
    );

    // A saved fork: content for its own appended change binds to the fork's
    // log, while the fork-origin change stays content-less on the fork.
    try storeio.createStream(io, allocator, root_path, .{
        .id = fork_id,
        .name = "recovery",
        .head = d1_id,
        .created = 1760000003000,
        .forked_from = .{ .stream = main_id, .change = d1_id },
    });
    const f1_line = try testSignedChangeLine(allocator, seed, f1_id, d1_id, fork_id, 1760000004000, "fork work");
    defer allocator.free(f1_line);
    const fh = try storeio.appendStreamChanges(io, allocator, root_path, fork_id, d1_id, &.{f1_line}, null);
    defer if (fh) |h| allocator.free(h);

    const mf = try testSignedManifestLine(allocator, seed, fork_id, f1_id, &files);
    defer allocator.free(mf);
    try std.testing.expectEqual(
        @as(usize, 1),
        try contentio.putManifestStreamLines(io, allocator, root_path, fork_id, &.{mf}, null),
    );
    const fork_all = try get(allocator, root_path, fork_id, null);
    defer allocator.free(fork_all);
    {
        const lines = try getLines(allocator, fork_all);
        defer {
            for (lines) |l| allocator.free(l);
            allocator.free(lines);
        }
        try std.testing.expectEqual(@as(usize, 1), lines.len);
        try std.testing.expectEqualStrings(mf, lines[0]);
    }
    // A main-bound manifest for the fork's own change finds nothing in
    // main's log -> change_missing.
    const mf_wrong = try testSignedManifestLine(allocator, seed, main_id, f1_id, &files);
    defer allocator.free(mf_wrong);
    try std.testing.expectError(
        error.ChangeMissing,
        contentio.putManifestStreamLines(io, allocator, root_path, main_id, &.{mf_wrong}, null),
    );
}

test "manifest log line-count bound refuses store_too_large" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tempStorePath(allocator, &tmp);
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const seed: [32]u8 = @splat(0x42);
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    try storeio.createStream(io, allocator, root_path, .{
        .id = stream_id,
        .name = "main",
        .created = 1760000000000,
    });
    const c1_line = try testSignedChangeLine(allocator, seed, c1_id, null, stream_id, 1760000000000, "first");
    defer allocator.free(c1_line);
    const head = try storeio.appendStreamChanges(io, allocator, root_path, stream_id, null, &.{c1_line}, null);
    defer if (head) |h| allocator.free(h);

    const blob_id = sha256Hex("x");
    const files = [_]store.ManifestFile{.{ .path = "a.zig", .blob = &blob_id, .bytes = 1, .mode = 644 }};
    const m1 = try testSignedManifestLine(allocator, seed, stream_id, c1_id, &files);
    defer allocator.free(m1);

    // Fill the manifest log to the 4096-line shadow bound; the next load
    // and put both refuse store_too_large.
    const log_path = try std.fs.path.join(allocator, &.{ root_path, "manifests", "0199de2d-dc00-7000-8000-000000000010.jsonl" });
    defer allocator.free(log_path);
    try contentio.ensureManifestsDir(io, allocator, root_path);
    const fill = try std.fmt.allocPrint(allocator, "{s}\n", .{m1});
    defer allocator.free(fill);
    for (0..store.MaxManifestLines + 1) |_| {
        try storeio.appendSync(io, log_path, fill);
    }
    try std.testing.expectError(error.StoreTooLarge, contentio.loadManifestLog(io, allocator, root_path, stream_id));
    try std.testing.expectError(
        error.StoreTooLarge,
        contentio.putManifestStreamLines(io, allocator, root_path, stream_id, &.{m1}, null),
    );
}

test "read-only streams dir: writes fail IoFailure and map to store_io" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tempStorePath(allocator, &tmp);
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const streams_dir = try std.fs.path.join(allocator, &.{ root_path, "streams" });
    defer allocator.free(streams_dir);
    // `.iterate = true`: on Linux `openDir` without it yields an O_PATH
    // descriptor, and `setPermissions` (fchmod) on O_PATH fails EBADF.
    var dir = try Io.Dir.cwd().openDir(io, streams_dir, .{ .iterate = true });
    defer dir.close(io);
    try dir.setPermissions(io, .fromMode(0o555));
    defer dir.setPermissions(io, .fromMode(0o755)) catch {};

    // Read-only but listable: loadStoreIndex still works; the write path refuses.
    {
        var idx = try storeio.loadStoreIndex(io, allocator, root_path);
        defer idx.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), idx.streams.len);
    }
    const st = store.Stream{
        .id = "0199de2d-dc00-7000-8000-0000000000f0",
        .name = "main",
        .created = 1760000000000,
    };
    try std.testing.expectError(error.IoFailure, storeio.createStream(io, allocator, root_path, st));

    // The refusal surface is the regression: an io/perm failure is not
    // a malformed stream record (issue #36).
    const info = storeio.refusalForError(error.IoFailure);
    try std.testing.expectEqual(store.RefusalCode.store_io, info.code);
    try std.testing.expectEqualStrings("store_io", store.RefusalCode.store_io.asText());
    try std.testing.expectEqualStrings("io error", info.detail);
    const malformed = storeio.refusalForError(error.StreamMalformed);
    try std.testing.expectEqual(store.RefusalCode.stream_malformed, malformed.code);
}
