const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store.zig");
const json = @import("json.zig");
const change = @import("change.zig");
const storeio = @import("storeio.zig");
const Change = store.Change;

// spec_rev 3 `deposit` coverage (issue #40): detached Change lines, idempotent
// resends, refusal surface, and log loading of interleaved detached lines.
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
    var c = Change{
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

test "deposit stores detached changes without moving the head and skips resends" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const c2_id = "0199de2d-dc00-7000-8000-000000000101";
    const d1_id = "0199de2d-dc00-7000-8000-000000000102";
    const d2_id = "0199de2d-dc00-7000-8000-000000000103";
    const d3_id = "0199de2d-dc00-7000-8000-000000000104";

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

    // A detached change rooted at c1 stores without moving the head.
    const d1_line = try testSignedChangeLine(allocator, seed, d1_id, c1_id, stream_id, 1760000002000, "detached");
    defer allocator.free(d1_line);
    // The stream field also resolves by name (wire op takes id-or-name).
    const res1 = try storeio.depositStreamChanges(io, allocator, root_path, "main", &.{d1_line}, null);
    defer if (res1.head) |h| allocator.free(h);
    try std.testing.expectEqual(@as(usize, 1), res1.stored);
    try std.testing.expectEqualStrings(c2_id, res1.head.?);

    // Batch ancestry: d3 may parent d2 deposited earlier in the same batch.
    const d2_line = try testSignedChangeLine(allocator, seed, d2_id, c1_id, stream_id, 1760000003000, "detached root");
    defer allocator.free(d2_line);
    const d3_line = try testSignedChangeLine(allocator, seed, d3_id, d2_id, stream_id, 1760000004000, "detached child");
    defer allocator.free(d3_line);
    const res2 = try storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{ d2_line, d3_line }, null);
    defer if (res2.head) |h| allocator.free(h);
    try std.testing.expectEqual(@as(usize, 2), res2.stored);
    try std.testing.expectEqualStrings(c2_id, res2.head.?);

    // Byte-identical resends skip and do not count toward stored.
    const res3 = try storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{ d1_line, d2_line }, null);
    defer if (res3.head) |h| allocator.free(h);
    try std.testing.expectEqual(@as(usize, 0), res3.stored);

    var loaded = try storeio.loadStream(io, allocator, root_path, stream_id);
    defer loaded.deinit(allocator);
    try std.testing.expectEqualStrings(c2_id, loaded.stream.head.?);
    try std.testing.expectEqual(@as(usize, 5), loaded.changes.len);
    try std.testing.expectEqualStrings(d3_id, loaded.changes[4].id);

    // A crash between a later appendSync and the record write still rolls the
    // head forward past interleaved detached lines to the chain tip.
    const c3_id = "0199de2d-dc00-7000-8000-000000000105";
    const c3_line = try testSignedChangeLine(allocator, seed, c3_id, c2_id, stream_id, 1760000005000, "third");
    defer allocator.free(c3_line);
    const jsonl_path = try std.fs.path.join(allocator, &.{ root_path, "streams", "0199de2d-dc00-7000-8000-000000000010.jsonl" });
    defer allocator.free(jsonl_path);
    try storeio.appendSync(io, jsonl_path, c3_line);
    try storeio.appendSync(io, jsonl_path, "\n");
    {
        var rel = try storeio.loadStream(io, allocator, root_path, stream_id);
        defer rel.deinit(allocator);
        try std.testing.expectEqualStrings(c3_id, rel.stream.head.?);
    }
}

test "deposit refusals: extends head, unknown parent, id conflict, bounds, allowlist" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const c2_id = "0199de2d-dc00-7000-8000-000000000101";
    const d1_id = "0199de2d-dc00-7000-8000-000000000102";

    try std.testing.expectError(
        error.StreamMissing,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{"x"}, null),
    );

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

    // Empty and oversize batches refuse change_malformed (1-256 per request).
    try std.testing.expectError(
        error.ChangeMalformed,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{}, null),
    );
    var oversize: [store.MaxDepositBatch + 1][]const u8 = undefined;
    for (&oversize) |*slot| slot.* = c1_line;
    try std.testing.expectError(
        error.ChangeMalformed,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &oversize, null),
    );

    // A detached change whose parent is the current head is an append.
    const extends_head = try testSignedChangeLine(allocator, seed, d1_id, c2_id, stream_id, 1760000002000, "extends");
    defer allocator.free(extends_head);
    try std.testing.expectError(
        error.DetachedExtendsHead,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{extends_head}, null),
    );

    // An unknown parent refuses; so does the same id under different bytes.
    const orphan = try testSignedChangeLine(allocator, seed, d1_id, "0199de2d-dc00-7000-8000-00000000ffff", stream_id, 1760000002000, "orphan");
    defer allocator.free(orphan);
    try std.testing.expectError(
        error.DetachedParentUnknown,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{orphan}, null),
    );
    const conflict_line = try std.fmt.allocPrint(allocator, "{s} ", .{c1_line});
    defer allocator.free(conflict_line);
    try std.testing.expectError(
        error.ChangeIdConflict,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{conflict_line}, null),
    );

    // Wrong stream binding, bad message, and bad signature refuse in kind.
    const wrong_stream = try testSignedChangeLine(allocator, seed, d1_id, c1_id, "0199de2d-dc00-7000-8000-000000000099", 1760000002000, "foreign");
    defer allocator.free(wrong_stream);
    try std.testing.expectError(
        error.ChangeMalformed,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{wrong_stream}, null),
    );
    const bad_msg = try testSignedChangeLine(allocator, seed, d1_id, c1_id, stream_id, 1760000002000, "   ");
    defer allocator.free(bad_msg);
    try std.testing.expectError(
        error.MessageInvalid,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{bad_msg}, null),
    );
    const detached = try testSignedChangeLine(allocator, seed, d1_id, c1_id, stream_id, 1760000002000, "detached");
    defer allocator.free(detached);
    // Tampering the signed message leaves a well-formed line with a bad sig.
    const bad_sig = try std.mem.replaceOwned(u8, allocator, detached, "\"detached\"", "\"detachex\"");
    defer allocator.free(bad_sig);
    try std.testing.expectError(
        error.SigInvalid,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{bad_sig}, null),
    );
    const allow_none = [_][64]u8{@splat('a')};
    try std.testing.expectError(
        error.AuthorNotAllowed,
        storeio.depositStreamChanges(io, allocator, root_path, stream_id, &.{detached}, &allow_none),
    );

    // Nothing was written: head and log are untouched.
    var loaded = try storeio.loadStream(io, allocator, root_path, stream_id);
    defer loaded.deinit(allocator);
    try std.testing.expectEqualStrings(c2_id, loaded.stream.head.?);
    try std.testing.expectEqual(@as(usize, 2), loaded.changes.len);
}

test "loadStream tolerates detached lines but refuses orphan and duplicate ids" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer allocator.free(root_path);
    try storeio.initStore(io, allocator, root_path);

    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
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
    const d1_line = try testSignedChangeLine(allocator, seed, d1_id, c1_id, stream_id, 1760000002000, "detached");
    defer allocator.free(d1_line);
    const c3_id = "0199de2d-dc00-7000-8000-000000000105";
    const c3_line = try testSignedChangeLine(allocator, seed, c3_id, c2_id, stream_id, 1760000003000, "third");
    defer allocator.free(c3_line);

    const jsonl_path = try std.fs.path.join(allocator, &.{ root_path, "streams", "0199de2d-dc00-7000-8000-000000000010.jsonl" });
    defer allocator.free(jsonl_path);
    const json_path = try std.fs.path.join(allocator, &.{ root_path, "streams", "0199de2d-dc00-7000-8000-000000000010.json" });
    defer allocator.free(json_path);

    // Log interleaving a detached line between chain lines:
    // [c1, c2, d1(parent c1), c3(parent c2)]. A line whose parent equals the
    // chain cursor extends it; d1's parent is behind the cursor, so d1 is
    // detached and the head chain reaches c3.
    const interleaved = try std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n{s}\n", .{ c1_line, c2_line, d1_line, c3_line });
    defer allocator.free(interleaved);
    try storeio.appendSync(io, jsonl_path, interleaved);
    {
        var loaded = try storeio.loadStream(io, allocator, root_path, stream_id);
        defer loaded.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 4), loaded.changes.len);
        try std.testing.expectEqualStrings(c3_id, loaded.stream.head.?);
    }

    // An orphan detached line (unknown parent) corrupts the log.
    const orphan = try testSignedChangeLine(allocator, seed, d1_id, "0199de2d-dc00-7000-8000-00000000ffff", stream_id, 1760000002000, "orphan");
    defer allocator.free(orphan);
    const orphan_log = try std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n", .{ c1_line, c2_line, orphan });
    defer allocator.free(orphan_log);
    try storeio.writeFileSafe(io, allocator, jsonl_path, orphan_log);
    try std.testing.expectError(error.ChangeMalformed, storeio.loadStream(io, allocator, root_path, stream_id));

    // A duplicate id — even byte-identical — corrupts the log.
    const dup_log = try std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n{s}\n", .{ c1_line, c2_line, d1_line, d1_line });
    defer allocator.free(dup_log);
    try storeio.writeFileSafe(io, allocator, jsonl_path, dup_log);
    try std.testing.expectError(error.ChangeMalformed, storeio.loadStream(io, allocator, root_path, stream_id));

    // Restore the healthy interleaved log for the store index check.
    try storeio.writeFileSafe(io, allocator, jsonl_path, interleaved);
    var idx = try storeio.loadStoreIndex(io, allocator, root_path);
    defer idx.deinit(allocator);
    try std.testing.expectEqualStrings(c3_id, idx.streams[0].head.?);
    try std.testing.expectEqual(@as(usize, 4), idx.total_changes);
}
