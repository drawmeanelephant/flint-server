const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const json = @import("json.zig");
const storeio = @import("storeio.zig");
const auth = @import("auth.zig");
const logging = @import("logging.zig");
const RefusalCode = store.RefusalCode;
const Stream = store.Stream;

/// Protocol-visible spec revision, kept in lockstep with the repo-root
/// SPECREV file by tools/tests/test_specrev.py (docs/spec-versioning.md).
/// Announced in `hello` ok replies.
pub const SpecRev: u32 = 3;

pub const Session = struct {
    root_path: []const u8,
    auth_key: ?[32]u8 = null,
    allow_authors: ?[]const [64]u8 = null,
    fixed_nonce: ?[16]u8 = null,
    hello_done: bool = false,
    authed: bool = false,
    nonce: [16]u8 = undefined,
    close_after_reply: bool = false,
    request_seq: ?u32 = null,
    request_op: logging.Operation = .unknown,
};

pub fn writeRefusal(
    w: *Io.Writer,
    seq: u64,
    code: RefusalCode,
    detail: []const u8,
) Io.Writer.Error!void {
    try w.print("{{\"seq\":{d},\"ok\":false,\"refuse\":", .{seq});
    try json.writeGoJsonString(w, code.asText());
    try w.writeAll(",\"detail\":");
    try json.writeGoJsonString(w, detail);
    try w.writeAll("}\n");
}

fn writeStoreErrorRefusal(w: *Io.Writer, seq: u64, err: storeio.StoreError) Io.Writer.Error!void {
    const info = storeio.refusalForError(err);
    try writeRefusal(w, seq, info.code, info.detail);
}

pub fn handleLine(
    io: Io,
    allocator: Allocator,
    session: *Session,
    raw_line: []const u8,
    w: *Io.Writer,
) !void {
    session.request_seq = null;
    session.request_op = .unknown;
    const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
        raw_line[0 .. raw_line.len - 1]
    else
        raw_line;

    if (line.len > store.MaxLineBytes) {
        session.close_after_reply = true;
        try writeRefusal(w, 0, .store_too_large, "line exceeds 4 MiB");
        return;
    }

    if (line.len == 0) {
        try writeRefusal(w, 0, .usage, "empty request line");
        return;
    }

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
        try writeRefusal(w, 0, .usage, "malformed json request");
        return;
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => {
            try writeRefusal(w, 0, .usage, "request must be a json object");
            return;
        },
    };

    var seq_val: u64 = 0;
    if (obj.get("seq")) |s_val| {
        switch (s_val) {
            .integer => |n| {
                if (n >= 0 and n <= std.math.maxInt(u32)) {
                    seq_val = @intCast(n);
                } else {
                    try writeRefusal(w, 0, .usage, "invalid seq");
                    return;
                }
            },
            else => {
                try writeRefusal(w, 0, .usage, "invalid seq");
                return;
            },
        }
    } else {
        try writeRefusal(w, 0, .usage, "missing seq");
        return;
    }

    session.request_seq = @intCast(seq_val);
    const op_val = obj.get("op") orelse {
        try writeRefusal(w, seq_val, .usage, "missing op");
        return;
    };
    const op_str = switch (op_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq_val, .usage, "invalid op");
            return;
        },
    };
    if (op_str.len == 0) {
        try writeRefusal(w, seq_val, .usage, "missing op");
        return;
    }
    session.request_op = std.meta.stringToEnum(logging.Operation, op_str) orelse .unknown;

    if (std.mem.eql(u8, op_str, "hello")) {
        try handleHello(io, session, obj, seq_val, w);
        return;
    }

    if (std.mem.eql(u8, op_str, "auth")) {
        try handleAuth(session, obj, seq_val, w);
        return;
    }

    if (session.auth_key != null and !session.authed) {
        try writeRefusal(w, seq_val, .auth_required, "authentication required");
        return;
    }

    if (std.mem.eql(u8, op_str, "list")) {
        try handleList(io, allocator, session, seq_val, w);
    } else if (std.mem.eql(u8, op_str, "heads")) {
        try handleHeads(io, allocator, session, seq_val, w);
    } else if (std.mem.eql(u8, op_str, "open")) {
        try handleOpen(io, allocator, session, obj, seq_val, w);
    } else if (std.mem.eql(u8, op_str, "read")) {
        try handleRead(io, allocator, session, obj, seq_val, w);
    } else if (std.mem.eql(u8, op_str, "create")) {
        try handleCreate(io, allocator, session, obj, seq_val, w);
    } else if (std.mem.eql(u8, op_str, "append")) {
        try handleAppend(io, allocator, session, obj, seq_val, w);
    } else if (std.mem.eql(u8, op_str, "deposit")) {
        try handleDeposit(io, allocator, session, obj, seq_val, w);
    } else {
        try writeRefusal(w, seq_val, .usage, "unknown op");
    }
}

fn handleHello(
    io: Io,
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    const proto_val = obj.get("proto") orelse {
        try writeRefusal(w, seq, .proto_version, "missing proto");
        return;
    };
    const proto_str = switch (proto_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq, .proto_version, "invalid proto");
            return;
        },
    };
    if (!std.mem.eql(u8, proto_str, "FLINT-SYNC/1")) {
        try writeRefusal(w, seq, .proto_version, "expected FLINT-SYNC/1");
        return;
    }

    session.hello_done = true;
    if (session.auth_key != null) {
        session.authed = false;
        if (session.fixed_nonce) |fn_bytes| {
            session.nonce = fn_bytes;
        } else {
            io.random(&session.nonce);
        }
        const nonce_hex = store.encodeLowerHexFixed(16, session.nonce);
        try w.print(
            "{{\"seq\":{d},\"ok\":true,\"proto\":\"FLINT-SYNC/1\",\"server\":\"flintd\",\"nonce\":\"{s}\",\"spec_rev\":{d}}}\n",
            .{ seq, nonce_hex, SpecRev },
        );
    } else {
        session.authed = true;
        try w.print(
            "{{\"seq\":{d},\"ok\":true,\"proto\":\"FLINT-SYNC/1\",\"server\":\"flintd\",\"spec_rev\":{d}}}\n",
            .{ seq, SpecRev },
        );
    }
}

fn handleAuth(
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    if (session.auth_key == null) {
        try writeRefusal(w, seq, .usage, "auth not enabled on this server");
        return;
    }
    if (!session.hello_done) {
        session.close_after_reply = true;
        try writeRefusal(w, seq, .auth_failed, "hello required before auth");
        return;
    }

    const nonce_val = obj.get("nonce") orelse {
        session.close_after_reply = true;
        try writeRefusal(w, seq, .auth_failed, "missing nonce");
        return;
    };
    const nonce_str = switch (nonce_val) {
        .string => |s| s,
        else => {
            session.close_after_reply = true;
            try writeRefusal(w, seq, .auth_failed, "invalid nonce");
            return;
        },
    };
    const expected_nonce_hex = store.encodeLowerHexFixed(16, session.nonce);
    if (!std.mem.eql(u8, nonce_str, &expected_nonce_hex)) {
        session.close_after_reply = true;
        try writeRefusal(w, seq, .auth_failed, "nonce mismatch");
        return;
    }

    const hmac_val = obj.get("hmac") orelse {
        session.close_after_reply = true;
        try writeRefusal(w, seq, .auth_failed, "missing hmac");
        return;
    };
    const hmac_str = switch (hmac_val) {
        .string => |s| s,
        else => {
            session.close_after_reply = true;
            try writeRefusal(w, seq, .auth_failed, "invalid hmac");
            return;
        },
    };

    if (!auth.verifyAuthHmacHex(session.auth_key.?, session.nonce, hmac_str)) {
        session.close_after_reply = true;
        try writeRefusal(w, seq, .auth_failed, "hmac mismatch");
        return;
    }

    session.authed = true;
    try w.print("{{\"seq\":{d},\"ok\":true}}\n", .{seq});
}

fn handleList(
    io: Io,
    allocator: Allocator,
    session: *Session,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    var idx = storeio.loadStoreIndex(io, allocator, session.root_path) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer idx.deinit(allocator);

    try w.print("{{\"seq\":{d},\"ok\":true,\"streams\":[", .{seq});
    for (idx.streams, 0..) |st, i| {
        if (i > 0) try w.writeByte(',');
        try json.writeStream(w, st);
    }
    try w.writeAll("]}\n");
}

fn streamByIdLessThan(_: void, a: Stream, b: Stream) bool {
    return std.mem.order(u8, a.id, b.id) == .lt;
}

fn handleHeads(
    io: Io,
    allocator: Allocator,
    session: *Session,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    var idx = storeio.loadStoreIndex(io, allocator, session.root_path) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer idx.deinit(allocator);

    // Sort by stream id so the JSON object keys are emitted in canonical order.
    std.mem.sort(Stream, idx.streams, {}, streamByIdLessThan);

    try w.print("{{\"seq\":{d},\"ok\":true,\"heads\":{{", .{seq});
    for (idx.streams, 0..) |st, i| {
        if (i > 0) try w.writeByte(',');
        try json.writeGoJsonString(w, st.id);
        try w.writeByte(':');
        try json.writeNullableString(w, st.head);
    }
    try w.writeAll("}}\n");
}

fn handleOpen(
    io: Io,
    allocator: Allocator,
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    const stream_val = obj.get("stream") orelse obj.get("name") orelse {
        try writeRefusal(w, seq, .usage, "missing stream");
        return;
    };
    const req_stream = switch (stream_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq, .usage, "invalid stream");
            return;
        },
    };
    if (req_stream.len == 0) {
        try writeRefusal(w, seq, .usage, "empty stream");
        return;
    }

    var idx = storeio.loadStoreIndex(io, allocator, session.root_path) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer idx.deinit(allocator);

    const found = idx.findByNameOrId(req_stream) orelse {
        try writeRefusal(w, seq, .stream_missing, "stream not found");
        return;
    };

    try w.print("{{\"seq\":{d},\"ok\":true,\"record\":", .{seq});
    try json.writeStream(w, found.*);
    try w.writeAll("}\n");
}

fn handleRead(
    io: Io,
    allocator: Allocator,
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    const stream_val = obj.get("stream") orelse {
        try writeRefusal(w, seq, .usage, "missing stream");
        return;
    };
    const stream_arg = switch (stream_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq, .usage, "invalid stream");
            return;
        },
    };
    if (stream_arg.len == 0) {
        try writeRefusal(w, seq, .usage, "empty stream");
        return;
    }

    var after_opt: ?[]const u8 = null;
    if (obj.get("after")) |after_val| {
        switch (after_val) {
            .null => after_opt = null,
            .string => |s| {
                if (s.len > 0) after_opt = s;
            },
            else => {
                try writeRefusal(w, seq, .usage, "invalid after");
                return;
            },
        }
    }

    var limit: usize = store.DefaultReadLimit;
    if (obj.get("limit")) |limit_val| {
        switch (limit_val) {
            .null => {},
            .integer => |n| {
                if (n <= 0) {
                    try writeRefusal(w, seq, .usage, "invalid limit");
                    return;
                }
                const n_usize: usize = @intCast(@min(n, @as(i64, store.MaxReadLimit)));
                limit = @min(n_usize, store.MaxReadLimit);
            },
            else => {
                try writeRefusal(w, seq, .usage, "invalid limit");
                return;
            },
        }
    }

    var idx = storeio.loadStoreIndex(io, allocator, session.root_path) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer idx.deinit(allocator);

    const found_st = idx.findById(stream_arg) orelse {
        try writeRefusal(w, seq, .stream_missing, "stream not found");
        return;
    };

    var loaded = storeio.loadStream(io, allocator, session.root_path, found_st.id) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer loaded.deinit(allocator);

    var start_idx: usize = 0;
    if (after_opt) |after_id| {
        var matched = false;
        for (loaded.changes, 0..) |c, i| {
            if (std.mem.eql(u8, c.id, after_id)) {
                start_idx = i + 1;
                matched = true;
                break;
            }
        }
        if (!matched) {
            if (loaded.stream.forked_from) |ff| {
                const in_fork_chain = storeio.isChangeReachableInForkChain(
                    io,
                    allocator,
                    session.root_path,
                    ff.stream,
                    after_id,
                    ff.change,
                    idx.streams.len + 1,
                ) catch |err| {
                    try writeStoreErrorRefusal(w, seq, err);
                    return;
                };
                if (in_fork_chain) {
                    start_idx = 0;
                    matched = true;
                }
            }
            if (!matched) {
                try writeRefusal(w, seq, .change_missing, "after change not found in stream");
                return;
            }
        }
    }

    const remaining = loaded.raw_lines[start_idx..];
    const count = @min(remaining.len, limit);
    const more = remaining.len > limit;

    try w.print("{{\"seq\":{d},\"ok\":true,\"record\":", .{seq});
    try json.writeStream(w, loaded.stream);
    try w.writeAll(",\"head\":");
    try json.writeNullableString(w, loaded.stream.head);
    try w.writeAll(",\"changes\":[");
    for (remaining[0..count], 0..) |raw_line, i| {
        if (i > 0) try w.writeByte(',');
        try json.writeGoJsonString(w, raw_line);
    }
    try w.print("],\"more\":{s}}}\n", .{if (more) "true" else "false"});
}

fn handleCreate(
    io: Io,
    allocator: Allocator,
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    const rec_val = obj.get("record") orelse {
        try writeRefusal(w, seq, .stream_malformed, "missing record");
        return;
    };
    if (rec_val != .object) {
        try writeRefusal(w, seq, .stream_malformed, "record must be an object");
        return;
    }

    var record = json.parseStreamFromValue(allocator, rec_val) catch |err| switch (err) {
        error.StreamMalformed, error.ChangeMalformed => {
            try writeRefusal(w, seq, .stream_malformed, "invalid stream record");
            return;
        },
        error.OutOfMemory => return error.WriteFailed,
    };
    defer record.deinit(allocator);

    storeio.createStream(io, allocator, session.root_path, record) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };

    try w.print("{{\"seq\":{d},\"ok\":true}}\n", .{seq});
}

fn handleAppend(
    io: Io,
    allocator: Allocator,
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    const stream_val = obj.get("stream") orelse {
        try writeRefusal(w, seq, .usage, "missing stream");
        return;
    };
    const stream_id = switch (stream_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq, .usage, "invalid stream");
            return;
        },
    };
    if (stream_id.len == 0) {
        try writeRefusal(w, seq, .usage, "empty stream");
        return;
    }

    var expected_head: ?[]const u8 = null;
    if (obj.get("expected_head")) |eh_val| {
        switch (eh_val) {
            .null => expected_head = null,
            .string => |s| {
                if (s.len > 0) expected_head = s;
            },
            else => {
                try writeRefusal(w, seq, .usage, "invalid expected_head");
                return;
            },
        }
    }

    const changes_val = obj.get("changes") orelse {
        try writeRefusal(w, seq, .usage, "missing changes");
        return;
    };
    const changes_arr = switch (changes_val) {
        .array => |arr| arr.items,
        else => {
            try writeRefusal(w, seq, .usage, "changes must be an array");
            return;
        },
    };

    var raw_lines = allocator.alloc([]const u8, changes_arr.len) catch return error.WriteFailed;
    defer allocator.free(raw_lines);

    for (changes_arr, 0..) |item, i| {
        switch (item) {
            .string => |s| raw_lines[i] = s,
            else => {
                try writeRefusal(w, seq, .change_malformed, "change entry must be a raw JSONL string");
                return;
            },
        }
    }

    const new_head = storeio.appendStreamChanges(
        io,
        allocator,
        session.root_path,
        stream_id,
        expected_head,
        raw_lines,
        session.allow_authors,
    ) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer if (new_head) |nh| allocator.free(nh);

    try w.print("{{\"seq\":{d},\"ok\":true,\"head\":", .{seq});
    try json.writeNullableString(w, new_head);
    try w.writeAll("}\n");
}

fn handleDeposit(
    io: Io,
    allocator: Allocator,
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    const stream_val = obj.get("stream") orelse {
        try writeRefusal(w, seq, .usage, "missing stream");
        return;
    };
    const stream_arg = switch (stream_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq, .usage, "invalid stream");
            return;
        },
    };
    if (stream_arg.len == 0) {
        try writeRefusal(w, seq, .usage, "empty stream");
        return;
    }

    const changes_val = obj.get("changes") orelse {
        try writeRefusal(w, seq, .usage, "missing changes");
        return;
    };
    const changes_arr = switch (changes_val) {
        .array => |arr| arr.items,
        else => {
            try writeRefusal(w, seq, .usage, "changes must be an array");
            return;
        },
    };

    var raw_lines = allocator.alloc([]const u8, changes_arr.len) catch return error.WriteFailed;
    defer allocator.free(raw_lines);

    for (changes_arr, 0..) |item, i| {
        switch (item) {
            .string => |s| raw_lines[i] = s,
            else => {
                try writeRefusal(w, seq, .change_malformed, "change entry must be a raw JSONL string");
                return;
            },
        }
    }

    const result = storeio.depositStreamChanges(
        io,
        allocator,
        session.root_path,
        stream_arg,
        raw_lines,
        session.allow_authors,
    ) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer if (result.head) |h| allocator.free(h);

    try w.print("{{\"seq\":{d},\"ok\":true,\"head\":", .{seq});
    try json.writeNullableString(w, result.head);
    try w.print(",\"stored\":{d}}}\n", .{result.stored});
}

test "hello reply announces the embedded spec revision" {
    const allocator = std.testing.allocator;
    var session = Session{ .root_path = "unused" };
    var output: Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    try handleLine(
        std.testing.io,
        allocator,
        &session,
        "{\"op\":\"hello\",\"seq\":1,\"proto\":\"FLINT-SYNC/1\"}",
        &output.writer,
    );
    const expected = try std.fmt.allocPrint(
        allocator,
        "{{\"seq\":1,\"ok\":true,\"proto\":\"FLINT-SYNC/1\",\"server\":\"flintd\",\"spec_rev\":{d}}}\n",
        .{SpecRev},
    );
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, output.written());
    try std.testing.expect(SpecRev > 0);
}

test "hello auth challenge reply announces the spec revision" {
    const allocator = std.testing.allocator;
    var session = Session{
        .root_path = "unused",
        .auth_key = @splat(0x11),
        .fixed_nonce = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    };
    var output: Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    try handleLine(
        std.testing.io,
        allocator,
        &session,
        "{\"op\":\"hello\",\"seq\":1,\"proto\":\"FLINT-SYNC/1\"}",
        &output.writer,
    );
    const expected = try std.fmt.allocPrint(
        allocator,
        "{{\"seq\":1,\"ok\":true,\"proto\":\"FLINT-SYNC/1\",\"server\":\"flintd\",\"nonce\":\"{s}\",\"spec_rev\":{d}}}\n",
        .{ store.encodeLowerHexFixed(16, session.nonce), SpecRev },
    );
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, output.written());
}

test "request without seq refuses usage" {
    const allocator = std.testing.allocator;
    var session = Session{ .root_path = "unused" };
    var output: Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    try handleLine(std.testing.io, allocator, &session, "{\"op\":\"list\"}", &output.writer);
    try std.testing.expectEqualStrings(
        "{\"seq\":0,\"ok\":false,\"refuse\":\"usage\",\"detail\":\"missing seq\"}\n",
        output.written(),
    );
    try std.testing.expectEqual(@as(?u32, null), session.request_seq);
}
