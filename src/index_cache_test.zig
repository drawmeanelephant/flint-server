const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const json = @import("json.zig");
const change = @import("change.zig");
const storeio = @import("storeio.zig");
const proto = @import("proto.zig");
const index_cache = @import("index_cache.zig");

// Issue #46: the serving loop memoizes the parsed store index; these cover
// reuse across ops and invalidation under appends, external writes, same-size
// rewrites, torn tails, and new stream records.
fn signedChangeLine(
    allocator: Allocator,
    seed: [32]u8,
    id: []const u8,
    parent: ?[]const u8,
    stream_id: []const u8,
) ![]u8 {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const author_hex = store.encodeLowerHexFixed(32, kp.public_key.toBytes());
    const zero_sig: [128]u8 = @splat('0');
    var c = store.Change{
        .id = try allocator.dupe(u8, id),
        .parent = if (parent) |p| try allocator.dupe(u8, p) else null,
        .stream = try allocator.dupe(u8, stream_id),
        .ts = 1760000000000,
        .author = try allocator.dupe(u8, &author_hex),
        .message = try allocator.dupe(u8, "cache test"),
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

test "index cache reuses the parsed index and reloads on writes, external appends, and torn tails" {
    const a = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer a.free(root_path);
    try storeio.initStore(io, a, root_path);

    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const c2_id = "0199de2d-dc00-7000-8000-000000000101";
    const c3_id = "0199de2d-dc00-7000-8000-000000000102";

    try storeio.createStream(io, a, root_path, .{
        .id = stream_id,
        .name = "main",
        .head = null,
        .created = 1760000000000,
    });
    const c1_line = try signedChangeLine(a, seed, c1_id, null, stream_id);
    defer a.free(c1_line);
    const c2_line = try signedChangeLine(a, seed, c2_id, c1_id, stream_id);
    defer a.free(c2_line);
    const c3_line = try signedChangeLine(a, seed, c3_id, c2_id, stream_id);
    defer a.free(c3_line);

    const appended_head = try storeio.appendStreamChanges(io, a, root_path, stream_id, null, &.{c1_line}, null);
    defer if (appended_head) |h| a.free(h);

    var cache: index_cache.IndexCache = .{};
    defer cache.deinit(a);

    const idx_i1 = try cache.get(io, a, root_path);
    try std.testing.expectEqual(@as(usize, 1), cache.loads);
    try std.testing.expectEqualStrings(c1_id, idx_i1.streams[0].head.?);

    // Unchanged store: same borrowed index, no reload.
    const idx_i2 = try cache.get(io, a, root_path);
    try std.testing.expectEqual(@as(usize, 1), cache.loads);
    try std.testing.expect(idx_i1 == idx_i2);

    // A normal append changes the streams-dir fingerprint.
    const appended_head2 = try storeio.appendStreamChanges(io, a, root_path, stream_id, c1_id, &.{c2_line}, null);
    defer if (appended_head2) |h| a.free(h);
    const idx_i3 = try cache.get(io, a, root_path);
    try std.testing.expectEqual(@as(usize, 2), cache.loads);
    try std.testing.expectEqualStrings(c2_id, idx_i3.streams[0].head.?);

    // An external append to the .jsonl (head record untouched) reloads and
    // rolls the head forward across the foreign line.
    const jsonl_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.jsonl", .{ root_path, stream_id });
    defer a.free(jsonl_path);
    const json_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.json", .{ root_path, stream_id });
    defer a.free(json_path);

    const tail = try std.fmt.allocPrint(a, "{s}\n", .{c3_line});
    defer a.free(tail);
    {
        var f = try Io.Dir.cwd().openFile(io, jsonl_path, .{ .mode = .read_write });
        defer f.close(io);
        const orig_len = try f.length(io);
        try f.writePositionalAll(io, tail, orig_len);
    }
    const idx_i4 = try cache.get(io, a, root_path);
    try std.testing.expectEqual(@as(usize, 3), cache.loads);
    try std.testing.expectEqualStrings(c3_id, idx_i4.streams[0].head.?);

    // A torn tail surfaces StreamTorn rather than serving the stale index.
    {
        var f = try Io.Dir.cwd().openFile(io, jsonl_path, .{ .mode = .read_write });
        defer f.close(io);
        const len = try f.length(io);
        try f.setLength(io, len - 5);
    }
    try std.testing.expectError(error.StreamTorn, cache.get(io, a, root_path));

    // Restoring the bytes reloads cleanly and recovers the head.
    {
        var f = try Io.Dir.cwd().openFile(io, jsonl_path, .{ .mode = .read_write });
        defer f.close(io);
        const len = try f.length(io);
        try f.writePositionalAll(io, tail[tail.len - 5 ..], len);
    }
    const idx_i5 = try cache.get(io, a, root_path);
    try std.testing.expectEqual(@as(usize, 4), cache.loads);
    try std.testing.expectEqualStrings(c3_id, idx_i5.streams[0].head.?);

    // A same-size rewrite of the .json record bumps inode/mtime → reload.
    const record_bytes = try storeio.readFileBounded(io, a, json_path, store.MaxFileReadBytes);
    defer a.free(record_bytes);
    try storeio.writeFileSafe(io, a, json_path, record_bytes);
    _ = try cache.get(io, a, root_path);
    try std.testing.expectEqual(@as(usize, 5), cache.loads);

    // A new stream record appears without restarting the server.
    try storeio.createStream(io, a, root_path, .{
        .id = "0199de2d-dc00-7000-8000-000000000020",
        .name = "other",
        .head = null,
        .created = 1760000000000,
    });
    const idx_i6 = try cache.get(io, a, root_path);
    try std.testing.expectEqual(@as(usize, 6), cache.loads);
    try std.testing.expectEqual(@as(usize, 2), idx_i6.streams.len);
}

test "session heads and list share a memoized index that reloads after writes" {
    const a = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer a.free(root_path);
    try storeio.initStore(io, a, root_path);

    var cache: index_cache.IndexCache = .{};
    defer cache.deinit(a);
    var session = proto.Session{ .root_path = root_path, .index_cache = &cache };
    var out: Io.Writer.Allocating = .init(a);
    defer out.deinit();

    try proto.handleLine(io, a, &session, "{\"op\":\"heads\",\"seq\":1}", &out.writer);
    try std.testing.expectEqualStrings(
        "{\"seq\":1,\"ok\":true,\"heads\":{}}\n",
        out.written(),
    );
    try std.testing.expectEqual(@as(usize, 1), cache.loads);

    // A second read op reuses the memoized index.
    out.clearRetainingCapacity();
    try proto.handleLine(io, a, &session, "{\"op\":\"list\",\"seq\":2}", &out.writer);
    try std.testing.expectEqualStrings(
        "{\"seq\":2,\"ok\":true,\"streams\":[]}\n",
        out.written(),
    );
    try std.testing.expectEqual(@as(usize, 1), cache.loads);

    // The create write path invalidates the memo.
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    out.clearRetainingCapacity();
    const create_line = "{\"op\":\"create\",\"seq\":3,\"record\":{\"id\":\"" ++ stream_id ++ "\",\"name\":\"main\",\"head\":null,\"created\":1760000000000,\"forked_from\":null}}";
    try proto.handleLine(io, a, &session, create_line, &out.writer);
    try std.testing.expectEqualStrings("{\"seq\":3,\"ok\":true}\n", out.written());

    out.clearRetainingCapacity();
    try proto.handleLine(io, a, &session, "{\"op\":\"heads\",\"seq\":4}", &out.writer);
    try std.testing.expectEqualStrings(
        "{\"seq\":4,\"ok\":true,\"heads\":{\"" ++ stream_id ++ "\":null}}\n",
        out.written(),
    );
    try std.testing.expectEqual(@as(usize, 2), cache.loads);

    // A write through the store layer (another connection's path) reloads.
    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const c1_line = try signedChangeLine(a, seed, c1_id, null, stream_id);
    defer a.free(c1_line);
    const appended_head3 = try storeio.appendStreamChanges(io, a, root_path, stream_id, null, &.{c1_line}, null);
    defer if (appended_head3) |h| a.free(h);

    out.clearRetainingCapacity();
    try proto.handleLine(io, a, &session, "{\"op\":\"heads\",\"seq\":5}", &out.writer);
    try std.testing.expectEqualStrings(
        "{\"seq\":5,\"ok\":true,\"heads\":{\"" ++ stream_id ++ "\":\"" ++ c1_id ++ "\"}}\n",
        out.written(),
    );
    try std.testing.expectEqual(@as(usize, 3), cache.loads);
}
