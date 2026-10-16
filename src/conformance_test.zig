const std = @import("std");
const Io = std.Io;
const store = @import("store.zig");
const json = @import("json.zig");
const ed25519 = @import("ed25519.zig");
const change = @import("change.zig");
const jsonl = @import("jsonl.zig");
const storeio = @import("storeio.zig");
const indexcache = @import("indexcache.zig");
const auth = @import("auth.zig");
const proto = @import("proto.zig");
const serve = @import("serve.zig");

const TempStore = struct {
    tmp: std.testing.TmpDir,
    root_path: []u8,

    pub fn init(allocator: std.mem.Allocator) !TempStore {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
        errdefer allocator.free(root_path);
        try storeio.initStore(std.testing.io, allocator, root_path);
        return .{ .tmp = tmp, .root_path = root_path };
    }

    pub fn deinit(self: *TempStore, allocator: std.mem.Allocator) void {
        allocator.free(self.root_path);
        self.tmp.cleanup();
    }
};

fn makeSignedChangeLine(
    alloc: std.mem.Allocator,
    s_seed: [32]u8,
    id: []const u8,
    parent: ?[]const u8,
    stream: []const u8,
    ts_val: i64,
    msg: []const u8,
    ops: []const store.Op,
    merged: ?[]const u8,
) ![]u8 {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(s_seed);
    const author_hex = store.encodeLowerHexFixed(32, kp.public_key.toBytes());
    const zero_sig: [128]u8 = @splat('0');

    const ops_copy = try alloc.alloc(store.Op, ops.len);
    var init_ops: usize = 0;
    errdefer {
        for (ops_copy[0..init_ops]) |*op| op.deinit(alloc);
        alloc.free(ops_copy);
    }
    for (ops, 0..) |op, i| {
        ops_copy[i] = try op.clone(alloc);
        init_ops += 1;
    }

    var c = store.Change{
        .id = try alloc.dupe(u8, id),
        .parent = if (parent) |p| try alloc.dupe(u8, p) else null,
        .stream = try alloc.dupe(u8, stream),
        .ts = ts_val,
        .author = try alloc.dupe(u8, &author_hex),
        .message = try alloc.dupe(u8, msg),
        .ops = ops_copy,
        .merged = if (merged) |m| try alloc.dupe(u8, m) else null,
        .sig = try alloc.dupe(u8, &zero_sig),
    };
    defer c.deinit(alloc);

    try change.signChangeWithSeed(alloc, &c, s_seed);
    const line = try json.marshalChangeLine(alloc, &c);
    defer alloc.free(line);
    return alloc.dupe(u8, line[0 .. line.len - 1]);
}

fn replayTranscript(
    allocator: std.mem.Allocator,
    cfg: serve.ServeConfig,
    transcript_path: []const u8,
) !void {
    const raw = try storeio.readFileBounded(std.testing.io, allocator, transcript_path, store.MaxFileReadBytes);
    defer allocator.free(raw);

    var req_buf: Io.Writer.Allocating = .init(allocator);
    defer req_buf.deinit();
    var exp_buf: Io.Writer.Allocating = .init(allocator);
    defer exp_buf.deinit();

    var start: usize = 0;
    while (start <= raw.len) {
        const end = std.mem.indexOfScalarPos(u8, raw, start, '\n') orelse raw.len;
        var line = raw[start..end];
        if (line.len > 0 and line[line.len - 1] == '\r') {
            line = line[0 .. line.len - 1];
        }
        if (line.len > 0 and line[0] != '#') {
            if (std.mem.startsWith(u8, line, "> ")) {
                try req_buf.writer.writeAll(line[2..]);
                try req_buf.writer.writeByte('\n');
            } else if (std.mem.startsWith(u8, line, "< ")) {
                try exp_buf.writer.writeAll(line[2..]);
                try exp_buf.writer.writeByte('\n');
            } else {
                return error.InvalidTranscriptLine;
            }
        }
        if (end == raw.len) break;
        start = end + 1;
    }

    var in_reader = Io.Reader.fixed(req_buf.written());
    var out_writer: Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();

    try serve.serveStream(std.testing.io, allocator, cfg, &in_reader, &out_writer.writer);
    try std.testing.expectEqualStrings(exp_buf.written(), out_writer.written());
}

test "M106a: testdata/sig/good.jsonl and preimage.hex match byte-for-byte" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const good_raw = try storeio.readFileBounded(io, allocator, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer allocator.free(good_raw);

    const preimage_raw = try storeio.readFileBounded(io, allocator, "testdata/sig/preimage.hex", store.MaxFileReadBytes);
    defer allocator.free(preimage_raw);
    const preimage_expected = std.mem.trim(u8, preimage_raw, " \t\r\n");

    const lines = try jsonl.readJsonlLines(allocator, good_raw);
    defer allocator.free(lines);
    try std.testing.expect(lines.len >= 1);

    for (lines, 0..) |line, idx| {
        var c = try change.parseChange(allocator, line);
        defer c.deinit(allocator);

        if (idx == 0) {
            const msg = try change.sigMsg(allocator, &c);
            defer allocator.free(msg);

            const hex_out = try allocator.alloc(u8, msg.len * 2);
            defer allocator.free(hex_out);
            const hex_chars = "0123456789abcdef";
            for (msg, 0..) |b, bi| {
                hex_out[bi * 2] = hex_chars[b >> 4];
                hex_out[bi * 2 + 1] = hex_chars[b & 0x0f];
            }
            try std.testing.expectEqualStrings(preimage_expected, hex_out);

            // Also verify round-trip JSON marshaling of line 0 matches good.jsonl line 0 byte-for-byte.
            const marshaled = try json.marshalChangeLine(allocator, &c);
            defer allocator.free(marshaled);
            try std.testing.expectEqualStrings(line, marshaled[0 .. marshaled.len - 1]);
        }

        try change.verifyChange(allocator, &c);
    }
}

test "M106a: testdata/sig/bad.jsonl every line is rejected with SigInvalid" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const bad_raw = try storeio.readFileBounded(io, allocator, "testdata/sig/bad.jsonl", store.MaxFileReadBytes);
    defer allocator.free(bad_raw);

    const lines = try jsonl.readJsonlLines(allocator, bad_raw);
    defer allocator.free(lines);
    try std.testing.expect(lines.len >= 1);

    for (lines) |line| {
        var c = try change.parseChange(allocator, line);
        defer c.deinit(allocator);
        try std.testing.expectError(error.SigInvalid, change.verifyChange(allocator, &c));
    }
}

test "M106a & M106b: initStore, stream record round-trip, roll-forward, torn stream, bounds" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ts = try TempStore.init(allocator);
    defer ts.deinit(allocator);

    // Re-init on existing store refuses StreamExists.
    try std.testing.expectError(error.StreamExists, storeio.initStore(io, allocator, ts.root_path));

    const good_raw = try storeio.readFileBounded(io, allocator, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer allocator.free(good_raw);
    const good_lines = try jsonl.readJsonlLines(allocator, good_raw);
    defer allocator.free(good_lines);

    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const c2_id = "0199de2d-dc00-7000-8000-000000000101";

    const c2_line = try makeSignedChangeLine(
        allocator,
        seed,
        c2_id,
        c1_id,
        stream_id,
        1760000001000,
        "second change with <html&chars>",
        &.{},
        null,
    );
    defer allocator.free(c2_line);

    const st = store.Stream{
        .id = stream_id,
        .name = "main",
        .head = null,
        .created = 1760000000000,
        .forked_from = null,
    };
    try storeio.createStream(io, allocator, ts.root_path, st);

    // §2.4: createStream writes streams/<id>.json only; .jsonl is created lazily by the first append.
    const jsonl_path = try std.fmt.allocPrint(allocator, "{s}/streams/{s}.jsonl", .{ ts.root_path, stream_id });
    defer allocator.free(jsonl_path);
    try std.testing.expect(!storeio.fileExists(io, jsonl_path));

    // Simulate crash after a multi-change batch appendSync ([c1, c2]) before writeFileSafe updates head (head is still null).
    const batch_with_nl = try std.fmt.allocPrint(allocator, "{s}\n{s}\n", .{ good_lines[0], c2_line });
    defer allocator.free(batch_with_nl);
    try storeio.appendSync(io, jsonl_path, batch_with_nl);

    // Both loadStoreIndex and loadStream must roll head forward across the 2-change batch from null to c2_id.
    {
        var idx = try storeio.loadStoreIndex(io, allocator, ts.root_path);
        defer idx.deinit(allocator);
        try std.testing.expectEqualStrings(c2_id, idx.streams[0].head.?);
    }
    {
        var loaded = try storeio.loadStream(io, allocator, ts.root_path, stream_id);
        defer loaded.deinit(allocator);
        try std.testing.expectEqualStrings(c2_id, loaded.stream.head.?);
        try std.testing.expectEqual(@as(usize, 2), loaded.changes.len);
    }

    // Check readFileBounded bound -> StoreTooLarge.
    try std.testing.expectError(error.StoreTooLarge, storeio.readFileBounded(io, allocator, jsonl_path, 16));

    // Simulate torn final line in .jsonl -> StreamTorn.
    try storeio.appendSync(io, jsonl_path, "{\"truncated\":true");
    try std.testing.expectError(error.StreamTorn, storeio.loadStream(io, allocator, ts.root_path, stream_id));
}

test "M106c: append all-or-nothing batch rollback, message_invalid, sig_invalid, create refusals" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ts = try TempStore.init(allocator);
    defer ts.deinit(allocator);

    const seed = store.decodeLowerHexFixed(32, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const c2_id = "0199de2d-dc00-7000-8000-000000000101";

    // Create refusals: bad stream name -> StreamMalformed, non-null head on root stream -> StreamMalformed.
    try std.testing.expectError(error.StreamMalformed, storeio.createStream(io, allocator, ts.root_path, .{
        .id = stream_id,
        .name = "Bad_Name",
        .head = null,
        .created = 1760000000000,
    }));
    try std.testing.expectError(error.StreamMalformed, storeio.createStream(io, allocator, ts.root_path, .{
        .id = stream_id,
        .name = "main",
        .head = c1_id,
        .created = 1760000000000,
    }));

    // Valid create.
    try storeio.createStream(io, allocator, ts.root_path, .{
        .id = stream_id,
        .name = "main",
        .head = null,
        .created = 1760000000000,
    });

    // Duplicate stream id or name -> StreamExists.
    try std.testing.expectError(error.StreamExists, storeio.createStream(io, allocator, ts.root_path, .{
        .id = stream_id,
        .name = "other",
        .head = null,
        .created = 1760000000000,
    }));
    try std.testing.expectError(error.StreamExists, storeio.createStream(io, allocator, ts.root_path, .{
        .id = "0199de2d-dc00-7000-8000-000000000099",
        .name = "main",
        .head = null,
        .created = 1760000000000,
    }));

    const c1_line = try makeSignedChangeLine(allocator, seed, c1_id, null, stream_id, 1760000000000, "first valid commit", &.{}, null);
    defer allocator.free(c1_line);

    const c2_bad_msg = try makeSignedChangeLine(allocator, seed, c2_id, c1_id, stream_id, 1760000001000, "   ", &.{}, null);
    defer allocator.free(c2_bad_msg);

    // Batch [c1_line, c2_bad_msg] must fail with MessageInvalid and NOT write c1_line (all-or-nothing).
    try std.testing.expectError(
        error.MessageInvalid,
        storeio.appendStreamChanges(io, allocator, ts.root_path, stream_id, null, &.{ c1_line, c2_bad_msg }, null),
    );
    {
        var loaded = try storeio.loadStream(io, allocator, ts.root_path, stream_id);
        defer loaded.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), loaded.changes.len);
        try std.testing.expect(loaded.stream.head == null);
    }
}

test "M106c & M106f: golden transcript hello_list.ndjson" {
    const allocator = std.testing.allocator;
    var ts = try TempStore.init(allocator);
    defer ts.deinit(allocator);

    try replayTranscript(allocator, .{ .root_path = ts.root_path }, "testdata/sync/hello_list.ndjson");
}

test "M106c & M106f: golden transcript push_pull.ndjson" {
    const allocator = std.testing.allocator;
    var ts = try TempStore.init(allocator);
    defer ts.deinit(allocator);

    try replayTranscript(allocator, .{ .root_path = ts.root_path }, "testdata/sync/push_pull.ndjson");
}

test "M106d & M106f: golden transcript auth_refuse.ndjson and successful HMAC auth + allowlist files" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ts = try TempStore.init(allocator);
    defer ts.deinit(allocator);

    const auth_key: [32]u8 = @splat(0x11);
    const fixed_nonce = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    // Test loading --auth-key and --allow-author from files outside the store root.
    var ext_tmp = std.testing.tmpDir(.{});
    defer ext_tmp.cleanup();
    const ext_dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{ext_tmp.sub_path});
    defer allocator.free(ext_dir);

    const key_file_path = try std.fmt.allocPrint(allocator, "{s}/auth.key", .{ext_dir});
    defer allocator.free(key_file_path);
    const key_hex = store.encodeLowerHexFixed(32, auth_key);
    try storeio.writeFileSafe(io, allocator, key_file_path, &(key_hex ++ .{'\n'}));
    const loaded_key = try auth.loadAuthKeyFile(io, allocator, key_file_path);
    try std.testing.expectEqualSlices(u8, &auth_key, &loaded_key);

    const allow_file_path = try std.fmt.allocPrint(allocator, "{s}/allow.txt", .{ext_dir});
    defer allocator.free(allow_file_path);
    try storeio.writeFileSafe(
        io,
        allocator,
        allow_file_path,
        "# allowed authors\nd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\n\n",
    );
    const loaded_allow = try auth.loadAllowAuthorFile(io, allocator, allow_file_path);
    defer allocator.free(loaded_allow);
    try std.testing.expectEqual(@as(usize, 1), loaded_allow.len);

    try replayTranscript(allocator, .{
        .root_path = ts.root_path,
        .auth_key = loaded_key,
        .fixed_nonce = fixed_nonce,
    }, "testdata/sync/auth_refuse.ndjson");

    // Verify valid HMAC succeeds and allows subsequent verbs.
    const mac = auth.computeAuthHmac(loaded_key, fixed_nonce);
    const mac_hex = store.encodeLowerHexFixed(32, mac);
    const nonce_hex = store.encodeLowerHexFixed(16, fixed_nonce);

    const req = try std.fmt.allocPrint(
        allocator,
        "{{\"op\":\"hello\",\"seq\":1,\"proto\":\"FLINT-SYNC/1\"}}\n" ++
            "{{\"op\":\"auth\",\"seq\":2,\"nonce\":\"{s}\",\"hmac\":\"{s}\"}}\n" ++
            "{{\"op\":\"list\",\"seq\":3}}\n",
        .{ nonce_hex, mac_hex },
    );
    defer allocator.free(req);

    var in_r = Io.Reader.fixed(req);
    var out_w: Io.Writer.Allocating = .init(allocator);
    defer out_w.deinit();

    try serve.serveStream(io, allocator, .{
        .root_path = ts.root_path,
        .auth_key = loaded_key,
        .fixed_nonce = fixed_nonce,
    }, &in_r, &out_w.writer);

    const expected = try std.fmt.allocPrint(
        allocator,
        "{{\"seq\":1,\"ok\":true,\"proto\":\"FLINT-SYNC/1\",\"server\":\"flintd\",\"nonce\":\"{s}\",\"spec_rev\":{d}}}\n" ++
            "{{\"seq\":2,\"ok\":true}}\n" ++
            "{{\"seq\":3,\"ok\":true,\"streams\":[]}}\n",
        .{ nonce_hex, proto.SpecRev },
    );
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, out_w.written());

    // Verify --allow-author gating on append.
    const good_raw = try storeio.readFileBounded(io, allocator, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer allocator.free(good_raw);
    const good_lines = try jsonl.readJsonlLines(allocator, good_raw);
    defer allocator.free(good_lines);

    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    try storeio.createStream(io, allocator, ts.root_path, .{
        .id = stream_id,
        .name = "main",
        .head = null,
        .created = 1760000000000,
        .forked_from = null,
    });

    const other_author: [64]u8 = @splat('a');
    const allow_other = [_][64]u8{other_author};
    try std.testing.expectError(
        error.AuthorNotAllowed,
        storeio.appendStreamChanges(io, allocator, ts.root_path, stream_id, null, &.{good_lines[0]}, &allow_other),
    );

    const nh = try storeio.appendStreamChanges(io, allocator, ts.root_path, stream_id, null, &.{good_lines[0]}, loaded_allow);
    defer if (nh) |h| allocator.free(h);
    try std.testing.expectEqualStrings("0199de2d-dc00-7000-8000-000000000100", nh.?);
}

test "M106f: two-client sync journey, fork validation, and client/server store portability" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ts = try TempStore.init(allocator);
    defer ts.deinit(allocator);

    // Portability leg: simulate client-only artifacts (`ws/`, `KEY`, `CONFIG.json`) inside the store root;
    // `flintd` must ignore them and serve `streams/` cleanly.
    const ws_dir = try std.fmt.allocPrint(allocator, "{s}/ws", .{ts.root_path});
    defer allocator.free(ws_dir);
    try Io.Dir.cwd().createDirPath(io, ws_dir);
    const key_path = try std.fmt.allocPrint(allocator, "{s}/KEY", .{ts.root_path});
    defer allocator.free(key_path);
    try storeio.writeFileSafe(io, allocator, key_path, "0000000000000000000000000000000000000000000000000000000000000000\n");

    const seed: [32]u8 = @splat(0x42);

    const main_id = "01928374-0000-7000-8000-000000000000";
    const c1_id = "01928374-0000-7000-8000-000000000001";
    const c2_id = "01928374-0000-7000-8000-000000000002";
    const c3_id = "01928374-0000-7000-8000-000000000003";
    const fork_id = "01928374-0000-7000-8000-000000000099";

    const c1_line = try makeSignedChangeLine(allocator, seed, c1_id, null, main_id, 1700000001, "client A initial commit", &.{}, null);
    defer allocator.free(c1_line);
    const c2_line = try makeSignedChangeLine(allocator, seed, c2_id, c1_id, main_id, 1700000002, "client A second commit", &.{}, null);
    defer allocator.free(c2_line);
    const c3_stale_line = try makeSignedChangeLine(allocator, seed, c3_id, c1_id, main_id, 1700000003, "client B divergent commit", &.{}, null);
    defer allocator.free(c3_stale_line);
    const c3_merged_line = try makeSignedChangeLine(allocator, seed, c3_id, c2_id, main_id, 1700000004, "client B merged commit", &.{}, c1_id);
    defer allocator.free(c3_merged_line);

    // 1. Client A creates main and pushes c1 and c2.
    try storeio.createStream(io, allocator, ts.root_path, .{
        .id = main_id,
        .name = "main",
        .head = null,
        .created = 1700000000,
        .forked_from = null,
    });
    const nh_a = try storeio.appendStreamChanges(io, allocator, ts.root_path, main_id, null, &.{ c1_line, c2_line }, null);
    defer if (nh_a) |h| allocator.free(h);
    try std.testing.expectEqualStrings(c2_id, nh_a.?);

    // 2. Client B (at stale head c1) attempts to push c3_stale -> refused with StaleHead.
    try std.testing.expectError(
        error.StaleHead,
        storeio.appendStreamChanges(io, allocator, ts.root_path, main_id, c1_id, &.{c3_stale_line}, null),
    );

    // 3. Client B pulls changes after c1, merges on top of c2, and pushes c3_merged with expected_head = c2.
    const nh_b = try storeio.appendStreamChanges(io, allocator, ts.root_path, main_id, c2_id, &.{c3_merged_line}, null);
    defer if (nh_b) |h| allocator.free(h);
    try std.testing.expectEqualStrings(c3_id, nh_b.?);

    // 4. Create a forked stream from main@c2_id; verify unresolvable change is refused with ChangeMissing.
    try std.testing.expectError(
        error.ChangeMissing,
        storeio.createStream(io, allocator, ts.root_path, .{
            .id = fork_id,
            .name = "feat",
            .head = "01928374-0000-7000-8000-000000009999",
            .created = 1700000005,
            .forked_from = .{ .stream = main_id, .change = "01928374-0000-7000-8000-000000009999" },
        }),
    );

    try storeio.createStream(io, allocator, ts.root_path, .{
        .id = fork_id,
        .name = "feat",
        .head = c2_id,
        .created = 1700000005,
        .forked_from = .{ .stream = main_id, .change = c2_id },
    });

    // Verify full store index and both streams load cleanly with all signatures valid.
    var idx = try storeio.loadStoreIndex(io, allocator, ts.root_path);
    defer idx.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), idx.streams.len);
    try std.testing.expectEqual(@as(usize, 3), idx.total_changes);

    // 5. Multi-hop fork chain resolution (§2.4):
    // fork_id ("feat") was forked from main@c2_id. Append c4 on feat, then create fork2 ("subfeat")
    // pointing its forked_from at {stream: fork_id, change: c1_id} where c1_id lives in grandparent main
    // before the c2_id fork cutoff.
    const c4_id = "01928374-0000-7000-8000-000000000004";
    const fork2_id = "01928374-0000-7000-8000-000000000098";
    const c4_line = try makeSignedChangeLine(allocator, seed, c4_id, c2_id, fork_id, 1700000006, "commit on feat", &.{}, null);
    defer allocator.free(c4_line);
    const nh_feat = try storeio.appendStreamChanges(io, allocator, ts.root_path, fork_id, c2_id, &.{c4_line}, null);
    defer if (nh_feat) |h| allocator.free(h);

    // c3_id was committed on main AFTER fork_id forked at c2_id -> NOT in fork_id's history -> ChangeMissing!
    try std.testing.expectError(
        error.ChangeMissing,
        storeio.createStream(io, allocator, ts.root_path, .{
            .id = fork2_id,
            .name = "subfeat",
            .head = c3_id,
            .created = 1700000007,
            .forked_from = .{ .stream = fork_id, .change = c3_id },
        }),
    );

    // c1_id WAS in main's history before fork_id's fork point c2_id -> resolves through fork chain!
    try storeio.createStream(io, allocator, ts.root_path, .{
        .id = fork2_id,
        .name = "subfeat",
        .head = c1_id,
        .created = 1700000007,
        .forked_from = .{ .stream = fork_id, .change = c1_id },
    });

    // Empty batch with matching expected_head -> ChangeMalformed (§2.3).
    try std.testing.expectError(
        error.ChangeMalformed,
        storeio.appendStreamChanges(io, allocator, ts.root_path, main_id, c3_id, &.{}, null),
    );
}

test "M106c: bounded line reader refuses >4 MiB unterminated line with store_too_large" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var ts = try TempStore.init(allocator);
    defer ts.deinit(allocator);

    // Construct an unterminated request line of MaxLineBytes + 64 bytes.
    const big_len = store.MaxLineBytes + 64;
    const big_input = try allocator.alloc(u8, big_len);
    defer allocator.free(big_input);
    @memset(big_input, 'a');

    var in_r = Io.Reader.fixed(big_input);
    var out_w: Io.Writer.Allocating = .init(allocator);
    defer out_w.deinit();

    try serve.serveStream(io, allocator, .{ .root_path = ts.root_path }, &in_r, &out_w.writer);
    try std.testing.expectEqualStrings(
        "{\"seq\":0,\"ok\":false,\"refuse\":\"store_too_large\",\"detail\":\"line exceeds 4 MiB\"}\n",
        out_w.written(),
    );
}

test "request metadata resets on malformed input and never stores arbitrary operation strings" {
    const allocator = std.testing.allocator;
    var session = proto.Session{ .root_path = "unused" };
    var output: Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    try proto.handleLine(
        std.testing.io,
        allocator,
        &session,
        "{\"op\":\"private-client-content\",\"seq\":42}",
        &output.writer,
    );
    try std.testing.expectEqual(@as(?u32, 42), session.request_seq);
    try std.testing.expectEqual(.unknown, session.request_op);

    output.clearRetainingCapacity();
    try proto.handleLine(std.testing.io, allocator, &session, "not json", &output.writer);
    try std.testing.expectEqual(@as(?u32, null), session.request_seq);
    try std.testing.expectEqual(.unknown, session.request_op);
}

fn expectFileBytes(path: []const u8, expected: []const u8) !void {
    const bytes = try storeio.readFileBounded(std.testing.io, std.testing.allocator, path, store.MaxFileReadBytes);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings(expected, bytes);
}

test "storage boundary: crash cuts recover complete batches but never truncate torn bytes" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const raw = try storeio.readFileBounded(io, a, "testdata/sync/push_pull.ndjson", store.MaxFileReadBytes);
    defer a.free(raw);
    var changes: ?std.json.Parsed(std.json.Value) = null;
    defer if (changes) |*p| p.deinit();
    var transcript = std.mem.splitScalar(u8, raw, '\n');
    while (transcript.next()) |line| {
        if (!std.mem.startsWith(u8, line, "> ") or std.mem.indexOf(u8, line, "\"op\":\"append\"") == null) continue;
        changes = try std.json.parseFromSlice(std.json.Value, a, line[2..], .{});
        break;
    }
    const lines = changes.?.value.object.get("changes").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    var first = try change.parseChange(a, lines[0].string);
    defer first.deinit(a);
    var last = try change.parseChange(a, lines[1].string);
    defer last.deinit(a);
    const batch = try std.fmt.allocPrint(a, "{s}\n{s}\n", .{ lines[0].string, lines[1].string });
    defer a.free(batch);

    // Durable append, interrupted metadata publication, and a second recovery.
    for ([_]?[]const u8{ null, first.id, last.id }) |head| {
        var ts = try TempStore.init(a);
        defer ts.deinit(a);
        const record_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.json", .{ ts.root_path, first.stream });
        defer a.free(record_path);
        const log_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.jsonl", .{ ts.root_path, first.stream });
        defer a.free(log_path);
        const tmp_path = try std.fmt.allocPrint(a, "{s}.tmp-abandoned", .{record_path});
        defer a.free(tmp_path);
        const record_bytes = try json.marshalStreamRecord(a, .{
            .id = first.stream,
            .name = "main",
            .head = head,
            .created = first.ts,
        });
        defer a.free(record_bytes);
        try storeio.writeFileSafe(io, a, record_path, record_bytes);
        try storeio.appendSync(io, log_path, batch);
        try storeio.appendSync(io, tmp_path, "{\"head\":\"unfinished");

        for (0..2) |_| {
            var idx = try storeio.loadStoreIndex(io, a, ts.root_path);
            defer idx.deinit(a);
            try std.testing.expectEqualStrings(last.id, idx.streams[0].head.?);
            var loaded = try storeio.loadStream(io, a, ts.root_path, first.stream);
            defer loaded.deinit(a);
            try std.testing.expectEqual(@as(usize, 2), loaded.changes.len);
            try std.testing.expectEqualStrings(last.id, loaded.stream.head.?);
            try expectFileBytes(log_path, batch);
            try expectFileBytes(tmp_path, "{\"head\":\"unfinished");
        }
    }

    // These are process-crash disk images, not power-loss simulation. Even a
    // complete JSON object without its final newline must remain stream_torn.
    for ([_]usize{ 1, lines[1].string.len / 2, lines[1].string.len }) |cut| {
        var ts = try TempStore.init(a);
        defer ts.deinit(a);
        try storeio.createStream(io, a, ts.root_path, .{ .id = first.stream, .name = "main", .created = first.ts });
        const head = try storeio.appendStreamChanges(io, a, ts.root_path, first.stream, null, &.{lines[0].string}, null);
        defer if (head) |h| a.free(h);
        const record_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.json", .{ ts.root_path, first.stream });
        defer a.free(record_path);
        const log_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.jsonl", .{ ts.root_path, first.stream });
        defer a.free(log_path);
        const before = try storeio.readFileBounded(io, a, record_path, store.MaxFileReadBytes);
        defer a.free(before);
        const torn = try std.fmt.allocPrint(a, "{s}\n{s}", .{ lines[0].string, lines[1].string[0..cut] });
        defer a.free(torn);
        try storeio.writeFileSafe(io, a, log_path, torn);
        try std.testing.expectError(error.StreamTorn, storeio.loadStoreIndex(io, a, ts.root_path));
        try std.testing.expectError(error.StreamTorn, storeio.loadStream(io, a, ts.root_path, first.stream));
        try expectFileBytes(record_path, before);
        try expectFileBytes(log_path, torn);
    }
}

test "storage boundary: exactly 4 MiB is readable and the next append changes no bytes" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var ts = try TempStore.init(a);
    defer ts.deinit(a);
    const stream_id = "01928374-0000-7000-8000-000000000000";
    const c1 = "01928374-0000-7000-8000-000000000001";
    const c2 = "01928374-0000-7000-8000-000000000002";
    const c3 = "01928374-0000-7000-8000-000000000003";
    const seed: [32]u8 = @splat(0x42);
    const first = try makeSignedChangeLine(a, seed, c1, null, stream_id, 1, "first", &.{}, null);
    defer a.free(first);
    const second = try makeSignedChangeLine(a, seed, c2, c1, stream_id, 2, "second", &.{}, null);
    defer a.free(second);
    const third = try makeSignedChangeLine(a, seed, c3, c2, stream_id, 3, "third", &.{}, null);
    defer a.free(third);
    try storeio.createStream(io, a, ts.root_path, .{ .id = stream_id, .name = "main", .created = 1 });

    // JSON whitespace is not signed. Use it to reach the exact byte boundary
    // with valid signatures, without an oversized message or thousands of Ops.
    const padded = try a.alloc(u8, store.MaxFileReadBytes - second.len - 2);
    defer a.free(padded);
    @memcpy(padded[0..first.len], first);
    @memset(padded[first.len..], ' ');
    const h1 = try storeio.appendStreamChanges(io, a, ts.root_path, stream_id, null, &.{padded}, null);
    defer if (h1) |h| a.free(h);
    const h2 = try storeio.appendStreamChanges(io, a, ts.root_path, stream_id, c1, &.{second}, null);
    defer if (h2) |h| a.free(h);
    try std.testing.expectEqualStrings(c2, h2.?);
    const log_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.jsonl", .{ ts.root_path, stream_id });
    defer a.free(log_path);
    const record_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.json", .{ ts.root_path, stream_id });
    defer a.free(record_path);
    const log_before = try storeio.readFileBounded(io, a, log_path, store.MaxFileReadBytes);
    defer a.free(log_before);
    const record_before = try storeio.readFileBounded(io, a, record_path, store.MaxFileReadBytes);
    defer a.free(record_before);
    try std.testing.expectEqual(store.MaxFileReadBytes, log_before.len);
    var loaded = try storeio.loadStream(io, a, ts.root_path, stream_id);
    defer loaded.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), loaded.changes.len);
    try std.testing.expectError(error.StoreTooLarge, storeio.appendStreamChanges(io, a, ts.root_path, stream_id, c2, &.{third}, null));
    try expectFileBytes(log_path, log_before);
    try expectFileBytes(record_path, record_before);
}

test "storage boundary: 4096 signed Changes fit and the next append is atomic refusal" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var ts = try TempStore.init(a);
    defer ts.deinit(a);
    const stream_id = "01928374-0000-7000-8000-000000000000";
    const seed: [32]u8 = @splat(0x42);
    try storeio.createStream(io, a, ts.root_path, .{ .id = stream_id, .name = "main", .created = 1 });
    const log_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.jsonl", .{ ts.root_path, stream_id });
    defer a.free(log_path);
    const record_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.json", .{ ts.root_path, stream_id });
    defer a.free(record_path);
    var history: Io.Writer.Allocating = .init(a);
    defer history.deinit();
    var parent: ?[]u8 = null;
    defer if (parent) |p| a.free(p);
    for (1..store.MaxChanges) |i| {
        const id = try std.fmt.allocPrint(a, "01928374-0000-7000-8000-{x:0>12}", .{i});
        errdefer a.free(id);
        const line = try makeSignedChangeLine(a, seed, id, parent, stream_id, @intCast(i), "capacity", &.{}, null);
        defer a.free(line);
        try history.writer.print("{s}\n", .{line});
        if (parent) |p| a.free(p);
        parent = id;
    }
    try storeio.appendSync(io, log_path, history.written());
    // Publish the fixture's head so the test measures append, not recovery.
    const record_bytes = try json.marshalStreamRecord(a, .{ .id = stream_id, .name = "main", .head = parent, .created = 1 });
    defer a.free(record_bytes);
    try storeio.writeFileSafe(io, a, record_path, record_bytes);
    const final_id = "01928374-0000-7000-8000-000000001000";
    const final = try makeSignedChangeLine(a, seed, final_id, parent, stream_id, 4096, "last slot", &.{}, null);
    defer a.free(final);
    const head = try storeio.appendStreamChanges(io, a, ts.root_path, stream_id, parent, &.{final}, null);
    defer if (head) |h| a.free(h);
    try std.testing.expectEqualStrings(final_id, head.?);
    var idx = try storeio.loadStoreIndex(io, a, ts.root_path);
    defer idx.deinit(a);
    try std.testing.expectEqual(store.MaxChanges, idx.total_changes);
    const extra = try makeSignedChangeLine(a, seed, "01928374-0000-7000-8000-000000001001", final_id, stream_id, 4097, "overflow", &.{}, null);
    defer a.free(extra);
    const log_before = try storeio.readFileBounded(io, a, log_path, store.MaxFileReadBytes);
    defer a.free(log_before);
    const record_before = try storeio.readFileBounded(io, a, record_path, store.MaxFileReadBytes);
    defer a.free(record_before);
    try std.testing.expectError(error.StoreTooLarge, storeio.appendStreamChanges(io, a, ts.root_path, stream_id, final_id, &.{extra}, null));
    try expectFileBytes(log_path, log_before);
    try expectFileBytes(record_path, record_before);
}

/// Sends one request line through `handleLine` and returns the slice of
/// `out` written for it.
fn sendLine(
    session: *proto.Session,
    out: *Io.Writer.Allocating,
    sent: *usize,
    line: []const u8,
) ![]const u8 {
    try proto.handleLine(std.testing.io, std.testing.allocator, session, line, &out.writer);
    const reply = out.written()[sent.*..];
    sent.* = out.written().len;
    return reply;
}

test "index cache: session reuses one parse, invalidates on writes, and survives external churn" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var ts = try TempStore.init(a);
    defer ts.deinit(a);

    const seed: [32]u8 = @splat(0x42);
    const main_id = "01928374-0000-7000-8000-000000000000";
    const c1 = "01928374-0000-7000-8000-000000000001";
    const c2 = "01928374-0000-7000-8000-000000000002";
    const log_path = try std.fmt.allocPrint(a, "{s}/streams/{s}.jsonl", .{ ts.root_path, main_id });
    defer a.free(log_path);

    const c1_line = try makeSignedChangeLine(a, seed, c1, null, main_id, 1, "first", &.{}, null);
    defer a.free(c1_line);
    const c2_line = try makeSignedChangeLine(a, seed, c2, c1, main_id, 2, "second", &.{}, null);
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
        const reply = try sendLine(&session, &out, &sent, "{\"op\":\"create\",\"seq\":1,\"record\":{\"id\":\"01928374-0000-7000-8000-000000000000\",\"name\":\"main\",\"head\":null,\"created\":1,\"forked_from\":null}}");
        try std.testing.expectEqualStrings("{\"seq\":1,\"ok\":true}\n", reply);
    }

    // Perf smoke: the first index read parses; list/heads/open/read then all
    // hit the cache without re-reading the store.
    _ = try sendLine(&session, &out, &sent, "{\"op\":\"list\",\"seq\":2}");
    try std.testing.expectEqual(@as(usize, 1), cache.loads);
    _ = try sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":3}");
    _ = try sendLine(&session, &out, &sent, "{\"op\":\"open\",\"seq\":4,\"stream\":\"main\"}");
    _ = try sendLine(&session, &out, &sent, "{\"op\":\"read\",\"seq\":5,\"stream\":\"01928374-0000-7000-8000-000000000000\"}");
    try std.testing.expectEqual(@as(usize, 1), cache.loads);

    // Deposit while cached: the append invalidates, and the next index read
    // reloads and reports the new head.
    try req.writer.print("{{\"op\":\"append\",\"seq\":6,\"stream\":\"{s}\",\"expected_head\":null,\"changes\":[", .{main_id});
    try json.writeGoJsonString(&req.writer, c1_line);
    try req.writer.writeAll("]}");
    {
        const reply = try sendLine(&session, &out, &sent, req.written());
        const expected = try std.fmt.allocPrint(a, "{{\"seq\":6,\"ok\":true,\"head\":\"{s}\"}}\n", .{c1});
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, reply);
        req.clearRetainingCapacity();
    }
    {
        const reply = try sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":7}");
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
        const reply = try sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":8}");
        const expected = try std.fmt.allocPrint(a, "{{\"seq\":8,\"ok\":true,\"heads\":{{\"{s}\":\"{s}\"}}}}\n", .{ main_id, c2 });
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, reply);
        try std.testing.expectEqual(@as(usize, 3), cache.loads);
    }

    // A torn tail appearing after the cache was filled still refuses
    // stream_torn instead of serving the stale parse.
    try storeio.appendSync(io, log_path, "{\"partial\"");
    {
        const reply = try sendLine(&session, &out, &sent, "{\"op\":\"list\",\"seq\":9}");
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
        const reply = try sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":10}");
        const expected = try std.fmt.allocPrint(a, "{{\"seq\":10,\"ok\":true,\"heads\":{{\"{s}\":\"{s}\"}}}}\n", .{ main_id, c2 });
        defer a.free(expected);
        try std.testing.expectEqualStrings(expected, reply);
        try std.testing.expectEqual(@as(usize, 4), cache.loads);
    }

    // heads must not reorder the cached index: name order ("alpha" before
    // "main") survives a heads call that emits in id order.
    _ = try sendLine(&session, &out, &sent, "{\"op\":\"create\",\"seq\":11,\"record\":{\"id\":\"01928374-0000-7000-8000-00000000ff00\",\"name\":\"alpha\",\"head\":null,\"created\":2,\"forked_from\":null}}");
    const list_a = try a.dupe(u8, try sendLine(&session, &out, &sent, "{\"op\":\"list\",\"seq\":12}"));
    defer a.free(list_a);
    _ = try sendLine(&session, &out, &sent, "{\"op\":\"heads\",\"seq\":13}");
    const list_b = try sendLine(&session, &out, &sent, "{\"op\":\"list\",\"seq\":14}");
    // Identical payload apart from the seq echo.
    try std.testing.expectEqualStrings(
        list_a[std.mem.indexOf(u8, list_a, "\"streams\"").?..],
        list_b[std.mem.indexOf(u8, list_b, "\"streams\"").?..],
    );
    const alpha_pos = std.mem.indexOf(u8, list_b, "\"name\":\"alpha\"").?;
    const main_pos = std.mem.indexOf(u8, list_b, "\"name\":\"main\"").?;
    try std.testing.expect(alpha_pos < main_pos);
}

test "index cache: serveStream shares a transport-provided cache across sessions" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var ts = try TempStore.init(a);
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
