const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const json = @import("json.zig");
const storeio = @import("storeio.zig");
const contentio = @import("contentio.zig");
const proto = @import("proto.zig");

const Session = proto.Session;
const writeRefusal = proto.writeRefusal;
const writeStoreErrorRefusal = proto.writeStoreErrorRefusal;

/// `put_manifest` (spec_rev 4, flint-client docs/flint-blobs-spec.md §9):
/// appends signed manifest lines to `manifests/<stream>.jsonl`. Stream takes
/// an id or name like `deposit`; `lines` are raw JSONL strings.
pub fn handlePutManifest(
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

    const lines_val = obj.get("lines") orelse {
        try writeRefusal(w, seq, .usage, "missing lines");
        return;
    };
    const lines_arr = switch (lines_val) {
        .array => |arr| arr.items,
        else => {
            try writeRefusal(w, seq, .usage, "lines must be an array");
            return;
        },
    };

    var raw_lines = allocator.alloc([]const u8, lines_arr.len) catch return error.WriteFailed;
    defer allocator.free(raw_lines);

    for (lines_arr, 0..) |item, i| {
        switch (item) {
            .string => |s| raw_lines[i] = s,
            else => {
                try writeRefusal(w, seq, .change_malformed, "manifest line must be a raw JSONL string");
                return;
            },
        }
    }

    const stored = contentio.putManifestStreamLines(
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

    try w.print("{{\"seq\":{d},\"ok\":true,\"stored\":{d}}}\n", .{ seq, stored });
}

/// `get_manifest` (spec_rev 4): returns manifest lines verbatim for the
/// change range `read`'s `after` cursor would produce — a null `after`
/// yields the whole manifest log, a change id yields the lines bound to
/// changes after it in the log, and an unknown `after` refuses
/// `change_missing`.
pub fn handleGetManifest(
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

    // The `after` cursor lives in the Change log, exactly like `read`: a
    // manifest line is in range when its bound change sits after it. An
    // `after` that resolves only through the fork chain selects everything.
    var wanted: ?std.StringHashMap(void) = null;
    defer if (wanted) |*set| set.deinit();
    if (after_opt) |after_id| {
        var matched = false;
        for (loaded.changes, 0..) |c, i| {
            if (std.mem.eql(u8, c.id, after_id)) {
                var set: std.StringHashMap(void) = .init(allocator);
                for (loaded.changes[i + 1 ..]) |rest| {
                    set.put(rest.id, {}) catch return error.WriteFailed;
                }
                wanted = set;
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
                    matched = true;
                }
            }
            if (!matched) {
                try writeRefusal(w, seq, .change_missing, "after change not found in stream");
                return;
            }
        }
    }

    var log = contentio.loadManifestLog(io, allocator, session.root_path, found_st.id) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer log.deinit(allocator);

    try w.print("{{\"seq\":{d},\"ok\":true,\"lines\":[", .{seq});
    var emitted: usize = 0;
    for (log.raw_lines, log.changes) |raw_line, change_id| {
        if (wanted) |*set| {
            if (!set.contains(change_id)) continue;
        }
        if (emitted > 0) try w.writeByte(',');
        try json.writeGoJsonString(w, raw_line);
        emitted += 1;
    }
    try w.writeAll("]}\n");
}

/// `blob_put` (spec_rev 4): stores a content-addressed blob after checking
/// `id` against the SHA-256 of the decoded `hex` bytes. Idempotent.
pub fn handleBlobPut(
    io: Io,
    allocator: Allocator,
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    const id_val = obj.get("id") orelse {
        try writeRefusal(w, seq, .usage, "missing id");
        return;
    };
    const id_str = switch (id_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq, .usage, "invalid id");
            return;
        },
    };
    if (id_str.len == 0) {
        try writeRefusal(w, seq, .usage, "empty id");
        return;
    }

    const hex_val = obj.get("hex") orelse {
        try writeRefusal(w, seq, .usage, "missing hex");
        return;
    };
    const hex_str = switch (hex_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq, .usage, "invalid hex");
            return;
        },
    };

    contentio.putBlob(io, allocator, session.root_path, id_str, hex_str) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };

    try w.print("{{\"seq\":{d},\"ok\":true}}\n", .{seq});
}

/// `blob_get` (spec_rev 4): returns the stored blob's raw bytes as
/// lowercase hex; a missing id refuses `blob_missing`.
pub fn handleBlobGet(
    io: Io,
    allocator: Allocator,
    session: *Session,
    obj: std.json.ObjectMap,
    seq: u64,
    w: *Io.Writer,
) Io.Writer.Error!void {
    const id_val = obj.get("id") orelse {
        try writeRefusal(w, seq, .usage, "missing id");
        return;
    };
    const id_str = switch (id_val) {
        .string => |s| s,
        else => {
            try writeRefusal(w, seq, .usage, "invalid id");
            return;
        },
    };
    if (id_str.len == 0) {
        try writeRefusal(w, seq, .usage, "empty id");
        return;
    }

    const bytes = contentio.getBlob(io, allocator, session.root_path, id_str) catch |err| {
        try writeStoreErrorRefusal(w, seq, err);
        return;
    };
    defer allocator.free(bytes);

    try w.print("{{\"seq\":{d},\"ok\":true,\"hex\":\"", .{seq});
    const hex_chars = "0123456789abcdef";
    for (bytes) |b| {
        try w.writeByte(hex_chars[b >> 4]);
        try w.writeByte(hex_chars[b & 0x0f]);
    }
    try w.writeAll("\"}\n");
}
