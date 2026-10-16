const std = @import("std");
const Io = std.Io;
const json = @import("json.zig");
const storeio = @import("storeio.zig");
const indexcache = @import("indexcache.zig");
const proto = @import("proto.zig");
const serve = @import("serve.zig");
const conf = @import("conformance_test.zig");

// Wire-level index-cache coverage (issue #46, merged with the deposit and
// content ops): session-shared caches reuse one parse, every mutating op —
// create/append/deposit and the content writes — drops it even on refusal,
// and external store churn still forces real reloads.

test "index cache: session reuses one parse, invalidates on writes, and survives external churn" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var ts = try conf.TempStore.init(a);
    defer ts.deinit(a);

    const seed: [32]u8 = @splat(0x42);
    const main_id = "01928374-0000-7000-8000-000000000000";
    const c1 = "01928374-0000-7000-8000-000000000001";
    const c2 = "01928374-0000-7000-8000-000000000002";
    const log_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.jsonl", .{ ts.root_path, main_id });
    defer a.free(log_path);

    const c1_line = try conf.makeSignedChangeLine(a, seed, c1, null, main_id, 1, "first", &.{}, null);
    defer a.free(c1_line);
    const c2_line = try conf.makeSignedChangeLine(a, seed, c2, c1, main_id, 2, "second", &.{}, null);
    defer a.free(c2_line);

    var cache: indexcache.StoreIndexCache = .{};
    defer cache.deinit(a);
    var session = proto.Session{ .root_path = ts.root_path, .index_cache = &cache };
    var out: Io.Writer.Allocating = .init(a);
    defer out.deinit();
    var req: Io.Writer.Allocating = .init(a);
    defer req.deinit();
    var sent: usize = 0;

    // Mutations run with the cache attached and drop it even on the empty cache.
    {
        const reply = try conf.sendLine(&session, &out, &sent, "{\"op\":\"create\",\"seq\":1,\"record\":{\"id\":\"01928374-0000-7000-8000-000000000000\",\"name\":\"main\",\"head\":null,\"created\":1,\"forked_from\":null}}");
        try std.testing.expectEqualStrings("{\"seq\":1,\"ok\":true}\n", reply);
    }

    // Perf smoke: the first index read parses; list/heads/open/read then all
    // hit the cache without re-reading the store.
    _ = try conf.sendLine(&session, &out, &sent, "{\"op\":\"list\",\"seq\":2}");
    try std.testing.expectEqual(@as(usize, 1), cache.loads);
    _ = try conf.sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":3}");
    _ = try conf.sendLine(&session, &out, &sent, "{\"op\":\"open\",\"seq\":4,\"stream\":\"main\"}");
    _ = try conf.sendLine(&session, &out, &sent, "{\"op\":\"read\",\"seq\":5,\"stream\":\"01928374-0000-7000-8000-000000000000\"}");
    try std.testing.expectEqual(@as(usize, 1), cache.loads);

    // Deposit while cached: the append invalidates, and the next index read
    // reloads and reports the new head.
    try req.writer.print("{{\"op\":\"append\",\"seq\":6,\"stream\":\"{s}\",\"expected_head\":null,\"changes\":[", .{main_id});
    try json.writeGoJsonString(&req.writer, c1_line);
    try req.writer.writeAll("]}");
    {
        const reply = try conf.sendLine(&session, &out, &sent, req.written());
        const expected = try std.fmt.allocPrint(a, "{{\"seq\":6,\"ok\":true,\"head\":\"{s}\"}}\n", .{c1});
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, reply);
        req.clearRetainingCapacity();
    }
    {
        const reply = try conf.sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":7}");
        const expected = try std.fmt.allocPrint(a, "{{\"seq\":7,\"ok\":true,\"heads\":{{\"{s}\":\"{s}\"}}}}\n", .{ main_id, c1 });
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, reply);
        try std.testing.expectEqual(@as(usize, 2), cache.loads);
    }

    // External append mid-session, left torn by a crash between the .jsonl
    // append and the .json head update: the fingerprint mismatch forces a
    // reload whose roll-forward still recovers head = c2.
    {
        const line_nl = try std.fmt.allocPrint(a, "{s}\n", .{c2_line});
        defer a.free(line_nl);
        try storeio.appendSync(io, log_path, line_nl);
        const reply = try conf.sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":8}");
        const expected = try std.fmt.allocPrint(a, "{{\"seq\":8,\"ok\":true,\"heads\":{{\"{s}\":\"{s}\"}}}}\n", .{ main_id, c2 });
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, reply);
        try std.testing.expectEqual(@as(usize, 3), cache.loads);
    }

    // A torn tail appearing after the cache was filled still refuses
    // stream_torn instead of serving the stale parse.
    try storeio.appendSync(io, log_path, "{\"partial\"");
    {
        const reply = try conf.sendLine(&session, &out, &sent, "{\"op\":\"list\",\"seq\":9}");
        try std.testing.expectEqualStrings(
            "{\"seq\":9,\"ok\":false,\"refuse\":\"stream_torn\",\"detail\":\"jsonl missing trailing newline\"}\n",
            reply,
        );
        try std.testing.expectEqual(@as(usize, 3), cache.loads);
    }

    // Repairing the tail is picked up on the next request.
    {
        const repaired = try std.fmt.allocPrint(a, "{s}\n{s}\n", .{ c1_line, c2_line });
        defer a.free(repaired);
        try storeio.writeFileSafe(io, a, log_path, repaired);
        const reply = try conf.sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":10}");
        const expected = try std.fmt.allocPrint(a, "{{\"seq\":10,\"ok\":true,\"heads\":{{\"{s}\":\"{s}\"}}}}\n", .{ main_id, c2 });
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, reply);
        try std.testing.expectEqual(@as(usize, 4), cache.loads);
    }

    // heads must not reorder the cached index: name order ("alpha" before
    // "main") survives a heads call that emits in id order.
    _ = try conf.sendLine(&session, &out, &sent, "{\"op\":\"create\",\"seq\":11,\"record\":{\"id\":\"01928374-0000-7000-8000-00000000ff00\",\"name\":\"alpha\",\"head\":null,\"created\":2,\"forked_from\":null}}");
    const list_a = try a.dupe(u8, try conf.sendLine(&session, &out, &sent, "{\"op\":\"list\",\"seq\":12}"));
    defer a.free(list_a);
    _ = try conf.sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":13}");
    const list_b = try conf.sendLine(&session, &out, &sent, "{\"op\":\"list\",\"seq\":14}");
    // Identical payload apart from the seq echo.
    try std.testing.expectEqualStrings(
        list_a[std.mem.indexOf(u8, list_a, "\"streams\"").?..],
        list_b[std.mem.indexOf(u8, list_b, "\"streams\"").?..],
    );
    const alpha_pos = std.mem.indexOf(u8, list_b, "\"name\":\"alpha\"").?;
    const main_pos = std.mem.indexOf(u8, list_b, "\"name\":\"main\"").?;
    try std.testing.expect(alpha_pos < main_pos);
}

test "index cache: deposit invalidates so the next read serves the detached line" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var ts = try conf.TempStore.init(a);
    defer ts.deinit(a);

    const seed: [32]u8 = @splat(0x42);
    const main_id = "01928374-0000-7000-8000-000000000000";
    const c1 = "01928374-0000-7000-8000-000000000001";
    const d1 = "01928374-0000-7000-8000-000000000002";

    const c1_line = try conf.makeSignedChangeLine(a, seed, c1, null, main_id, 1, "first", &.{}, null);
    defer a.free(c1_line);
    // A null parent with head = c1 is a detached line, not an append.
    const d1_line = try conf.makeSignedChangeLine(a, seed, d1, null, main_id, 2, "detached", &.{}, null);
    defer a.free(d1_line);
    // Parenting the current head is an append, so deposit refuses it.
    const bad_line = try conf.makeSignedChangeLine(a, seed, "01928374-0000-7000-8000-000000000003", c1, main_id, 3, "extends head", &.{}, null);
    defer a.free(bad_line);

    try storeio.createStream(io, a, ts.root_path, .{
        .id = main_id,
        .name = "main",
        .created = 1,
    });
    const head = try storeio.appendStreamChanges(io, a, ts.root_path, main_id, null, &.{c1_line}, null);
    defer if (head) |h| a.free(h);

    var cache: indexcache.StoreIndexCache = .{};
    defer cache.deinit(a);
    var session = proto.Session{ .root_path = ts.root_path, .index_cache = &cache };
    var out: Io.Writer.Allocating = .init(a);
    defer out.deinit();
    var req: Io.Writer.Allocating = .init(a);
    defer req.deinit();
    var sent: usize = 0;

    _ = try conf.sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":1}");
    try std.testing.expectEqual(@as(usize, 1), cache.loads);

    // deposit writes streams/<id>.jsonl like append: the cache drops and the
    // next read reloads, serving the detached line rather than the stale
    // one-change parse.
    try req.writer.print("{{\"op\":\"deposit\",\"seq\":2,\"stream\":\"{s}\",\"changes\":[", .{main_id});
    try json.writeGoJsonString(&req.writer, d1_line);
    try req.writer.writeAll("]}");
    {
        const reply = try conf.sendLine(&session, &out, &sent, req.written());
        const expected = try std.fmt.allocPrint(a, "{{\"seq\":2,\"ok\":true,\"head\":\"{s}\",\"stored\":1}}\n", .{c1});
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, reply);
    }
    {
        const reply = try conf.sendLine(&session, &out, &sent, "{\"op\":\"read\",\"seq\":3,\"stream\":\"01928374-0000-7000-8000-000000000000\"}");
        try std.testing.expectEqual(@as(usize, 2), cache.loads);
        try std.testing.expect(std.mem.indexOf(u8, reply, d1) != null);
    }

    // A refused deposit attempt still drops the cache: a partial fsynced
    // append must never leave the stale parse serving.
    req.clearRetainingCapacity();
    try req.writer.print("{{\"op\":\"deposit\",\"seq\":4,\"stream\":\"{s}\",\"changes\":[", .{main_id});
    try json.writeGoJsonString(&req.writer, bad_line);
    try req.writer.writeAll("]}");
    {
        const reply = try conf.sendLine(&session, &out, &sent, req.written());
        try std.testing.expectEqualStrings(
            "{\"seq\":4,\"ok\":false,\"refuse\":\"change_malformed\",\"detail\":\"extends head\"}\n",
            reply,
        );
    }
    _ = try conf.sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":5}");
    try std.testing.expectEqual(@as(usize, 3), cache.loads);
}

test "index cache: serveStream shares a transport-provided cache across sessions" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var ts = try conf.TempStore.init(a);
    defer ts.deinit(a);

    try storeio.createStream(io, a, ts.root_path, .{
        .id = "01928374-0000-7000-8000-000000000000",
        .name = "main",
        .created = 1,
    });

    var shared: indexcache.StoreIndexCache = .{};
    defer shared.deinit(a);
    const cfg = serve.ServeConfig{ .root_path = ts.root_path, .index_cache = &shared };

    var in1 = Io.Reader.fixed("{\"op\":\"heads\",\"seq\":1}\n");
    var out1: Io.Writer.Allocating = .init(a);
    defer out1.deinit();
    try serve.serveStream(io, a, cfg, &in1, &out1.writer);
    try std.testing.expectEqual(@as(usize, 1), shared.loads);

    // A second session on the same transport cache does not re-parse.
    var in2 = Io.Reader.fixed("{\"op\":\"heads\",\"seq\":1}\n");
    var out2: Io.Writer.Allocating = .init(a);
    defer out2.deinit();
    try serve.serveStream(io, a, cfg, &in2, &out2.writer);
    try std.testing.expectEqual(@as(usize, 1), shared.loads);
    try std.testing.expectEqualStrings(out1.written(), out2.written());
}
