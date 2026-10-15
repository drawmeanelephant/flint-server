const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const json = @import("json.zig");
const change = @import("change.zig");
const jsonl = @import("jsonl.zig");
const Stream = store.Stream;
const Change = store.Change;
const RefusalCode = store.RefusalCode;

pub const StoreError = error{
    StoreNotFound,
    StoreMissing,
    StreamMissing,
    StreamExists,
    StaleHead,
    ChangeMalformed,
    ChangeMissing,
    SigInvalid,
    StoreTooLarge,
    StreamMalformed,
    StreamTorn,
    MessageInvalid,
    AuthorNotAllowed,
    Usage,
    IoFailure,
    OutOfMemory,
};

pub const RefusalInfo = struct {
    code: RefusalCode,
    detail: []const u8,
};

pub fn refusalForError(err: StoreError) RefusalInfo {
    return switch (err) {
        error.StoreNotFound => .{ .code = .store_not_found, .detail = "no --store and FLINT_STORE unset" },
        error.StoreMissing => .{ .code = .store_missing, .detail = "streams/ directory missing" },
        error.StreamMissing => .{ .code = .stream_missing, .detail = "stream not found" },
        error.StreamExists => .{ .code = .stream_exists, .detail = "stream already exists" },
        error.StaleHead => .{ .code = .stale_head, .detail = "expected_head mismatch" },
        error.ChangeMalformed => .{ .code = .change_malformed, .detail = "malformed change" },
        error.ChangeMissing => .{ .code = .change_missing, .detail = "change not found" },
        error.SigInvalid => .{ .code = .sig_invalid, .detail = "signature verification failed" },
        error.StoreTooLarge => .{ .code = .store_too_large, .detail = "store bound exceeded" },
        error.StreamMalformed => .{ .code = .stream_malformed, .detail = "malformed stream record" },
        error.StreamTorn => .{ .code = .stream_torn, .detail = "jsonl missing trailing newline" },
        error.MessageInvalid => .{ .code = .message_invalid, .detail = "invalid commit message" },
        error.AuthorNotAllowed => .{ .code = .author_not_allowed, .detail = "author not in allowlist" },
        error.Usage => .{ .code = .usage, .detail = "invalid request" },
        error.IoFailure => .{ .code = .stream_malformed, .detail = "io error" },
        error.OutOfMemory => .{ .code = .store_too_large, .detail = "out of memory" },
    };
}

pub fn optStrEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

pub fn dirExists(io: Io, path: []const u8) bool {
    var d = Io.Dir.cwd().openDir(io, path, .{}) catch return false;
    d.close(io);
    return true;
}

pub fn fileExists(io: Io, path: []const u8) bool {
    var f = Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    f.close(io);
    return true;
}

/// Fsyncs a directory. Note `.iterate = true`: on Linux, `openDir` with `.iterate = false`
/// opens with `O_PATH`, and `fsync` on an `O_PATH` descriptor fails with `EBADF`.
pub fn syncDir(io: Io, path: []const u8) StoreError!void {
    const target = if (path.len == 0) "." else path;
    var d = Io.Dir.cwd().openDir(io, target, .{ .iterate = true }) catch return error.IoFailure;
    defer d.close(io);
    const f: Io.File = .{ .handle = d.handle, .flags = .{ .nonblocking = false } };
    f.sync(io) catch return error.IoFailure;
}

/// Crash-safe file replacement matching `writeFileSafe` in `user/go/flint/fsys.go`:
/// writes `<path>.tmp-<rand>`, `fsync`s the temp file, closes it, renames over `<path>`,
/// and `fsync`s the parent directory.
pub fn writeFileSafe(io: Io, allocator: Allocator, path: []const u8, data: []const u8) StoreError!void {
    var rand_bytes: [8]u8 = undefined;
    io.random(&rand_bytes);
    const rand_hex = store.encodeLowerHexFixed(8, rand_bytes);
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{s}", .{ path, rand_hex });
    defer allocator.free(tmp_path);

    {
        var f = Io.Dir.cwd().createFile(io, tmp_path, .{ .truncate = true }) catch return error.IoFailure;
        errdefer {
            f.close(io);
            Io.Dir.cwd().deleteFile(io, tmp_path) catch {};
        }
        f.writeStreamingAll(io, data) catch return error.IoFailure;
        f.sync(io) catch return error.IoFailure;
        f.close(io);
    }

    Io.Dir.rename(Io.Dir.cwd(), tmp_path, Io.Dir.cwd(), path, io) catch {
        Io.Dir.cwd().deleteFile(io, tmp_path) catch {};
        return error.IoFailure;
    };

    const parent = std.fs.path.dirname(path) orelse ".";
    try syncDir(io, parent);
}

/// Appends `data` to `path` and `fsync`s the file before returning,
/// matching `appendSync` in `user/go/flint/fsys.go`.
pub fn appendSync(io: Io, path: []const u8, data: []const u8) StoreError!void {
    var f = Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => Io.Dir.cwd().createFile(io, path, .{ .truncate = false }) catch return error.IoFailure,
        else => return error.IoFailure,
    };
    defer f.close(io);

    const end_pos = f.length(io) catch return error.IoFailure;
    f.writePositionalAll(io, data, end_pos) catch return error.IoFailure;
    f.sync(io) catch return error.IoFailure;
}

pub fn readFileBounded(io: Io, allocator: Allocator, path: []const u8, max_bytes: usize) StoreError![]u8 {
    var f = Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => return error.StreamMissing,
        else => return error.IoFailure,
    };
    defer f.close(io);

    const file_len = f.length(io) catch return error.IoFailure;
    if (file_len > max_bytes) return error.StoreTooLarge;

    const len_usize: usize = @intCast(file_len);
    const buf = try allocator.alloc(u8, len_usize);
    errdefer allocator.free(buf);

    var total: usize = 0;
    while (total < len_usize) {
        var iov = [1][]u8{buf[total..]};
        const n = f.readPositional(io, &iov, total) catch return error.IoFailure;
        if (n == 0) break;
        total += n;
    }
    if (total != len_usize) return error.IoFailure;
    return buf;
}

/// Initializes a bare server store at `root_path` (`flintd init`).
/// Creates `<root_path>/streams/`. Refuses `StreamExists` if `<root_path>/streams/` already exists.
pub fn initStore(io: Io, allocator: Allocator, root_path: []const u8) StoreError!void {
    const streams_dir = try std.fs.path.join(allocator, &.{ root_path, "streams" });
    defer allocator.free(streams_dir);

    if (dirExists(io, streams_dir)) {
        return error.StreamExists;
    }

    Io.Dir.cwd().createDirPath(io, streams_dir) catch return error.IoFailure;
    try syncDir(io, streams_dir);
    try syncDir(io, root_path);
}

pub const StoreIndex = struct {
    streams: []Stream,
    total_changes: usize,

    pub fn deinit(self: *StoreIndex, allocator: Allocator) void {
        for (self.streams) |*st| st.deinit(allocator);
        allocator.free(self.streams);
    }

    pub fn findById(self: *const StoreIndex, id: []const u8) ?*const Stream {
        for (self.streams) |*st| {
            if (std.mem.eql(u8, st.id, id)) return st;
        }
        return null;
    }

    pub fn findByName(self: *const StoreIndex, name: []const u8) ?*const Stream {
        for (self.streams) |*st| {
            if (std.mem.eql(u8, st.name, name)) return st;
        }
        return null;
    }

    pub fn findByNameOrId(self: *const StoreIndex, name_or_id: []const u8) ?*const Stream {
        if (self.findById(name_or_id)) |st| return st;
        return self.findByName(name_or_id);
    }
};

fn streamLessThan(_: void, a: Stream, b: Stream) bool {
    const cmp = std.mem.order(u8, a.name, b.name);
    if (cmp != .eq) return cmp == .lt;
    return std.mem.order(u8, a.id, b.id) == .lt;
}

fn strLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// Scans `<root>/streams/`, loads all stream metadata records, verifies `.jsonl` line framing
/// and total change count bounds (`MaxChanges = 4096`, `MaxFileReadBytes = 4 MiB`),
/// and performs head roll-forward recovery if a previous append crashed between `.jsonl` and `.json`.
pub fn loadStoreIndex(io: Io, allocator: Allocator, root_path: []const u8) StoreError!StoreIndex {
    const streams_dir_path = try std.fs.path.join(allocator, &.{ root_path, "streams" });
    defer allocator.free(streams_dir_path);

    var dir = Io.Dir.cwd().openDir(io, streams_dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return error.StoreMissing,
        else => return error.IoFailure,
    };
    defer dir.close(io);

    var json_stems: std.ArrayList([]u8) = .empty;
    defer {
        for (json_stems.items) |s| allocator.free(s);
        json_stems.deinit(allocator);
    }

    var jsonl_stems: std.ArrayList([]u8) = .empty;
    defer {
        for (jsonl_stems.items) |s| allocator.free(s);
        jsonl_stems.deinit(allocator);
    }

    var it = dir.iterate();
    while (it.next(io) catch return error.IoFailure) |entry| {
        if (std.mem.indexOf(u8, entry.name, ".tmp-") != null) continue;
        if (entry.kind != .file) continue;

        if (std.mem.endsWith(u8, entry.name, ".json")) {
            const stem = entry.name[0 .. entry.name.len - ".json".len];
            if (!store.isValidUUID(stem)) return error.StreamMalformed;
            try json_stems.append(allocator, try allocator.dupe(u8, stem));
        } else if (std.mem.endsWith(u8, entry.name, ".jsonl")) {
            const stem = entry.name[0 .. entry.name.len - ".jsonl".len];
            if (!store.isValidUUID(stem)) return error.StreamMalformed;
            try jsonl_stems.append(allocator, try allocator.dupe(u8, stem));
        }
    }

    // Every .jsonl must have a matching .json.
    for (jsonl_stems.items) |jl_stem| {
        var found = false;
        for (json_stems.items) |j_stem| {
            if (std.mem.eql(u8, jl_stem, j_stem)) {
                found = true;
                break;
            }
        }
        if (!found) return error.StreamMalformed;
    }

    std.mem.sort([]u8, json_stems.items, {}, strLessThan);

    var streams: std.ArrayList(Stream) = .empty;
    errdefer {
        for (streams.items) |*st| st.deinit(allocator);
        streams.deinit(allocator);
    }

    var total_changes: usize = 0;

    for (json_stems.items) |stem| {
        const json_file = try std.fmt.allocPrint(allocator, "{s}.json", .{stem});
        defer allocator.free(json_file);
        const json_path = try std.fs.path.join(allocator, &.{ streams_dir_path, json_file });
        defer allocator.free(json_path);

        const raw_json = try readFileBounded(io, allocator, json_path, store.MaxFileReadBytes);
        defer allocator.free(raw_json);

        var st = json.parseStreamSlice(allocator, raw_json) catch |err| switch (err) {
            error.StreamMalformed, error.ChangeMalformed => return error.StreamMalformed,
            error.OutOfMemory => return error.OutOfMemory,
        };
        errdefer st.deinit(allocator);

        if (!std.mem.eql(u8, st.id, stem)) return error.StreamMalformed;

        for (streams.items) |existing| {
            if (std.mem.eql(u8, existing.id, st.id) or std.mem.eql(u8, existing.name, st.name)) {
                return error.StreamMalformed;
            }
        }

        const jsonl_file = try std.fmt.allocPrint(allocator, "{s}.jsonl", .{stem});
        defer allocator.free(jsonl_file);
        const jsonl_path = try std.fs.path.join(allocator, &.{ streams_dir_path, jsonl_file });
        defer allocator.free(jsonl_path);

        if (fileExists(io, jsonl_path)) {
            const raw_jsonl = try readFileBounded(io, allocator, jsonl_path, store.MaxFileReadBytes);
            defer allocator.free(raw_jsonl);

            const lines = jsonl.readJsonlLines(allocator, raw_jsonl) catch |err| switch (err) {
                error.StreamTorn => return error.StreamTorn,
                error.ChangeMalformed => return error.ChangeMalformed,
                error.OutOfMemory => return error.OutOfMemory,
            };
            defer allocator.free(lines);

            total_changes += lines.len;
            if (total_changes > store.MaxChanges) return error.StoreTooLarge;

            // Check if last line needs head roll-forward recovery.
            if (lines.len > 0) {
                var last_change = change.parseChange(allocator, lines[lines.len - 1]) catch |err| switch (err) {
                    error.ChangeMalformed, error.SigInvalid => return error.ChangeMalformed,
                    error.OutOfMemory => return error.OutOfMemory,
                };
                defer last_change.deinit(allocator);

                if (!optStrEql(st.head, last_change.id) and optStrEql(last_change.parent, st.head)) {
                    const new_head = try allocator.dupe(u8, last_change.id);
                    if (st.head) |old_h| allocator.free(old_h);
                    st.head = new_head;
                    const updated_bytes = try json.marshalStreamRecord(allocator, st);
                    defer allocator.free(updated_bytes);
                    try writeFileSafe(io, allocator, json_path, updated_bytes);
                }
            }
        }

        try streams.append(allocator, st);
    }

    std.mem.sort(Stream, streams.items, {}, streamLessThan);

    return .{
        .streams = try streams.toOwnedSlice(allocator),
        .total_changes = total_changes,
    };
}

pub const LoadedStream = struct {
    stream: Stream,
    changes: []Change,
    raw_lines: [][]u8,

    pub fn deinit(self: *LoadedStream, allocator: Allocator) void {
        self.stream.deinit(allocator);
        for (self.changes) |*c| c.deinit(allocator);
        allocator.free(self.changes);
        for (self.raw_lines) |line| allocator.free(line);
        allocator.free(self.raw_lines);
    }
};

/// Loads a single stream's metadata record and full change log (`streams/<id>.json` and `streams/<id>.jsonl`),
/// verifying every change's schema, parent chain, and Ed25519 signature, and performing head roll-forward
/// recovery if `last.parent == st.head` (`user/go/flint/stream.go` `LoadStream`).
pub fn loadStream(io: Io, allocator: Allocator, root_path: []const u8, stream_id: []const u8) StoreError!LoadedStream {
    const streams_dir_path = try std.fs.path.join(allocator, &.{ root_path, "streams" });
    defer allocator.free(streams_dir_path);

    if (!dirExists(io, streams_dir_path)) return error.StoreMissing;
    if (!store.isValidUUID(stream_id)) return error.StreamMissing;

    const json_file = try std.fmt.allocPrint(allocator, "{s}.json", .{stream_id});
    defer allocator.free(json_file);
    const json_path = try std.fs.path.join(allocator, &.{ streams_dir_path, json_file });
    defer allocator.free(json_path);

    const raw_json = try readFileBounded(io, allocator, json_path, store.MaxFileReadBytes);
    defer allocator.free(raw_json);

    var st = json.parseStreamSlice(allocator, raw_json) catch |err| switch (err) {
        error.StreamMalformed, error.ChangeMalformed => return error.StreamMalformed,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer st.deinit(allocator);

    if (!std.mem.eql(u8, st.id, stream_id)) return error.StreamMalformed;

    const jsonl_file = try std.fmt.allocPrint(allocator, "{s}.jsonl", .{stream_id});
    defer allocator.free(jsonl_file);
    const jsonl_path = try std.fs.path.join(allocator, &.{ streams_dir_path, jsonl_file });
    defer allocator.free(jsonl_path);

    var raw_jsonl: []u8 = &.{};
    var has_jsonl = false;
    if (fileExists(io, jsonl_path)) {
        raw_jsonl = try readFileBounded(io, allocator, jsonl_path, store.MaxFileReadBytes);
        has_jsonl = true;
    }
    defer if (has_jsonl) allocator.free(raw_jsonl);

    const lines = jsonl.readJsonlLines(allocator, raw_jsonl) catch |err| switch (err) {
        error.StreamTorn => return error.StreamTorn,
        error.ChangeMalformed => return error.ChangeMalformed,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer allocator.free(lines);

    if (lines.len > store.MaxChanges) return error.StoreTooLarge;

    var changes: std.ArrayList(Change) = .empty;
    errdefer {
        for (changes.items) |*c| c.deinit(allocator);
        changes.deinit(allocator);
    }

    var raw_lines_owned: std.ArrayList([]u8) = .empty;
    errdefer {
        for (raw_lines_owned.items) |l| allocator.free(l);
        raw_lines_owned.deinit(allocator);
    }

    for (lines, 0..) |line, idx| {
        var c = change.parseChange(allocator, line) catch |err| switch (err) {
            error.ChangeMalformed, error.SigInvalid => return error.ChangeMalformed,
            error.OutOfMemory => return error.OutOfMemory,
        };
        errdefer c.deinit(allocator);

        if (!std.mem.eql(u8, c.stream, stream_id)) return error.ChangeMalformed;

        if (idx == 0) {
            const expected_first_parent: ?[]const u8 = if (st.forked_from) |ff| ff.change else null;
            if (!optStrEql(c.parent, expected_first_parent)) return error.ChangeMalformed;
        } else {
            const prev_id = changes.items[idx - 1].id;
            if (!optStrEql(c.parent, prev_id)) return error.ChangeMalformed;
        }

        change.verifyChange(allocator, &c) catch |err| switch (err) {
            error.SigInvalid => return error.SigInvalid,
            error.ChangeMalformed => return error.ChangeMalformed,
            error.OutOfMemory => return error.OutOfMemory,
        };

        try changes.append(allocator, c);
        try raw_lines_owned.append(allocator, try allocator.dupe(u8, line));
    }

    if (changes.items.len == 0) {
        const expected_empty_head: ?[]const u8 = if (st.forked_from) |ff| ff.change else null;
        if (!optStrEql(st.head, expected_empty_head)) return error.StreamMalformed;
    } else {
        const last = changes.items[changes.items.len - 1];
        if (!optStrEql(st.head, last.id)) {
            if (optStrEql(last.parent, st.head)) {
                const new_head = try allocator.dupe(u8, last.id);
                if (st.head) |old_h| allocator.free(old_h);
                st.head = new_head;
                const updated_bytes = try json.marshalStreamRecord(allocator, st);
                defer allocator.free(updated_bytes);
                try writeFileSafe(io, allocator, json_path, updated_bytes);
            } else {
                return error.StreamMalformed;
            }
        }
    }

    return .{
        .stream = st,
        .changes = try changes.toOwnedSlice(allocator),
        .raw_lines = try raw_lines_owned.toOwnedSlice(allocator),
    };
}

fn changeExistsInStream(loaded: *const LoadedStream, change_id: []const u8) bool {
    for (loaded.changes) |c| {
        if (std.mem.eql(u8, c.id, change_id)) return true;
    }
    return false;
}

/// Creates a new stream record and empty `.jsonl` log (`docs/flint-server-spec.md` §2.4).
pub fn createStream(
    io: Io,
    allocator: Allocator,
    root_path: []const u8,
    record: Stream,
) StoreError!void {
    if (!store.validateStreamShape(&record)) return error.StreamMalformed;

    var idx = try loadStoreIndex(io, allocator, root_path);
    defer idx.deinit(allocator);

    for (idx.streams) |existing| {
        if (std.mem.eql(u8, existing.id, record.id) or std.mem.eql(u8, existing.name, record.name)) {
            return error.StreamExists;
        }
    }

    if (record.forked_from) |ff| {
        if (!optStrEql(record.head, ff.change)) return error.StreamMalformed;
        var origin = loadStream(io, allocator, root_path, ff.stream) catch |err| switch (err) {
            error.StreamMissing => return error.StreamMissing,
            else => return err,
        };
        defer origin.deinit(allocator);

        if (!changeExistsInStream(&origin, ff.change)) {
            return error.ChangeMissing;
        }
    } else {
        if (record.head != null) return error.StreamMalformed;
    }

    const streams_dir_path = try std.fs.path.join(allocator, &.{ root_path, "streams" });
    defer allocator.free(streams_dir_path);

    const jsonl_file = try std.fmt.allocPrint(allocator, "{s}.jsonl", .{record.id});
    defer allocator.free(jsonl_file);
    const jsonl_path = try std.fs.path.join(allocator, &.{ streams_dir_path, jsonl_file });
    defer allocator.free(jsonl_path);

    const json_file = try std.fmt.allocPrint(allocator, "{s}.json", .{record.id});
    defer allocator.free(json_file);
    const json_path = try std.fs.path.join(allocator, &.{ streams_dir_path, json_file });
    defer allocator.free(json_path);

    const record_bytes = try json.marshalStreamRecord(allocator, record);
    defer allocator.free(record_bytes);

    try writeFileSafe(io, allocator, jsonl_path, "");
    try writeFileSafe(io, allocator, json_path, record_bytes);
}

fn isAuthorAllowed(author_hex: []const u8, allowlist: ?[]const [64]u8) bool {
    const list = allowlist orelse return true;
    if (author_hex.len != 64) return false;
    for (list) |allowed| {
        if (std.mem.eql(u8, &allowed, author_hex)) return true;
    }
    return false;
}

/// Validates and appends a batch of raw JSONL change lines to `<root>/streams/<stream_id>.jsonl`,
/// then atomically updates `<root>/streams/<stream_id>.json` (`docs/flint-server-spec.md` §2.3).
/// Returns the new head UUID (owned by caller if non-null).
pub fn appendStreamChanges(
    io: Io,
    allocator: Allocator,
    root_path: []const u8,
    stream_id: []const u8,
    expected_head: ?[]const u8,
    raw_lines: []const []const u8,
    allow_authors: ?[]const [64]u8,
) StoreError!?[]u8 {
    // 1. Load store index to check store health and total change count.
    var idx = try loadStoreIndex(io, allocator, root_path);
    defer idx.deinit(allocator);

    // 2. Load target stream.
    var loaded = try loadStream(io, allocator, root_path, stream_id);
    defer loaded.deinit(allocator);

    // 3. Compare stream.head against expected_head.
    if (!optStrEql(loaded.stream.head, expected_head)) {
        return error.StaleHead;
    }

    // 4. Check store change bound.
    if (idx.total_changes + raw_lines.len > store.MaxChanges) {
        return error.StoreTooLarge;
    }

    if (raw_lines.len == 0) {
        if (loaded.stream.head) |h| {
            return try allocator.dupe(u8, h);
        }
        return null;
    }

    // 5. Validate all incoming lines in order before touching disk.
    var parsed_batch: std.ArrayList(Change) = .empty;
    defer {
        for (parsed_batch.items) |*c| c.deinit(allocator);
        parsed_batch.deinit(allocator);
    }

    var append_buf: std.Io.Writer.Allocating = .init(allocator);
    defer append_buf.deinit();

    var prev_head: ?[]const u8 = loaded.stream.head;

    for (raw_lines) |raw_line| {
        const trimmed = std.mem.trimEnd(u8, raw_line, "\r\n");
        if (trimmed.len == 0 or std.mem.indexOfScalar(u8, trimmed, '\n') != null or std.mem.indexOfScalar(u8, trimmed, '\r') != null) {
            return error.ChangeMalformed;
        }

        var c = change.parseChange(allocator, trimmed) catch |err| switch (err) {
            error.ChangeMalformed, error.SigInvalid => return error.ChangeMalformed,
            error.OutOfMemory => return error.OutOfMemory,
        };
        errdefer c.deinit(allocator);

        if (!std.mem.eql(u8, c.stream, stream_id)) return error.ChangeMalformed;
        if (!optStrEql(c.parent, prev_head)) return error.ChangeMalformed;
        if (!store.isValidMessage(c.message)) return error.MessageInvalid;

        if (c.merged) |m| {
            if (!store.isValidUUID(m)) return error.ChangeMalformed;
        }

        change.verifyChange(allocator, &c) catch |err| switch (err) {
            error.SigInvalid => return error.SigInvalid,
            error.ChangeMalformed => return error.ChangeMalformed,
            error.OutOfMemory => return error.OutOfMemory,
        };

        if (!isAuthorAllowed(c.author, allow_authors)) {
            return error.AuthorNotAllowed;
        }

        // Reject duplicate change IDs in the stream or within this batch.
        if (changeExistsInStream(&loaded, c.id)) return error.ChangeMalformed;
        for (parsed_batch.items) |prev_c| {
            if (std.mem.eql(u8, prev_c.id, c.id)) return error.ChangeMalformed;
        }

        append_buf.writer.writeAll(trimmed) catch return error.OutOfMemory;
        append_buf.writer.writeByte('\n') catch return error.OutOfMemory;

        try parsed_batch.append(allocator, c);
        prev_head = parsed_batch.items[parsed_batch.items.len - 1].id;
    }

    const streams_dir_path = try std.fs.path.join(allocator, &.{ root_path, "streams" });
    defer allocator.free(streams_dir_path);

    const jsonl_file = try std.fmt.allocPrint(allocator, "{s}.jsonl", .{stream_id});
    defer allocator.free(jsonl_file);
    const jsonl_path = try std.fs.path.join(allocator, &.{ streams_dir_path, jsonl_file });
    defer allocator.free(jsonl_path);

    const json_file = try std.fmt.allocPrint(allocator, "{s}.json", .{stream_id});
    defer allocator.free(json_file);
    const json_path = try std.fs.path.join(allocator, &.{ streams_dir_path, json_file });
    defer allocator.free(json_path);

    var existing_jsonl_len: usize = 0;
    if (fileExists(io, jsonl_path)) {
        var f = Io.Dir.cwd().openFile(io, jsonl_path, .{ .mode = .read_only }) catch return error.IoFailure;
        existing_jsonl_len = @intCast(f.length(io) catch {
            f.close(io);
            return error.IoFailure;
        });
        f.close(io);
    }
    if (existing_jsonl_len + append_buf.written().len > store.MaxFileReadBytes) {
        return error.StoreTooLarge;
    }

    // 6. Append verbatim raw lines to streams/<id>.jsonl + fsync.
    try appendSync(io, jsonl_path, append_buf.written());

    // 7. Rewrite streams/<id>.json with head = last.id via writeFileSafe.
    const new_head_str = parsed_batch.items[parsed_batch.items.len - 1].id;
    const new_head_copy = try allocator.dupe(u8, new_head_str);
    if (loaded.stream.head) |old_h| allocator.free(old_h);
    loaded.stream.head = new_head_copy;

    const updated_record = try json.marshalStreamRecord(allocator, loaded.stream);
    defer allocator.free(updated_record);
    try writeFileSafe(io, allocator, json_path, updated_record);

    return try allocator.dupe(u8, new_head_str);
}
