const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const jsonl = @import("jsonl.zig");
const storeio = @import("storeio.zig");
const StoreError = storeio.StoreError;
const StoreIndex = storeio.StoreIndex;

/// Order-independent fingerprint of `streams/`: one hash per `.json`/`.jsonl`
/// entry (name, size, mtime, ctime, inode) summed over the directory so
/// iteration order cannot affect the result.
const StreamsDirFingerprint = struct {
    entries: u64,
    sum: u64,

    fn eql(a: StreamsDirFingerprint, b: StreamsDirFingerprint) bool {
        return a.entries == b.entries and a.sum == b.sum;
    }
};

fn fingerprintStreamsDir(io: Io, root_path: []const u8) StoreError!StreamsDirFingerprint {
    var root = Io.Dir.cwd().openDir(io, root_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return error.StoreMissing,
        else => return error.IoFailure,
    };
    defer root.close(io);

    var dir = root.openDir(io, "streams", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return error.StoreMissing,
        else => return error.IoFailure,
    };
    defer dir.close(io);

    var fp = StreamsDirFingerprint{ .entries = 0, .sum = 0 };
    var it = dir.iterate();
    while (it.next(io) catch return error.IoFailure) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.indexOf(u8, entry.name, ".tmp-") != null) continue;
        if (!std.mem.endsWith(u8, entry.name, ".json") and !std.mem.endsWith(u8, entry.name, ".jsonl")) continue;

        const st = dir.statFile(io, entry.name, .{}) catch return error.IoFailure;
        var h = std.hash.Wyhash.init(0);
        h.update(entry.name);
        h.update(std.mem.asBytes(&st.size));
        h.update(std.mem.asBytes(&st.mtime.nanoseconds));
        h.update(std.mem.asBytes(&st.ctime.nanoseconds));
        h.update(std.mem.asBytes(&st.inode));
        fp.sum +%= h.final();
        fp.entries +%= 1;
    }
    return fp;
}

/// Caches the parsed `StoreIndex` across requests so a session does not
/// re-scan and re-parse every stream record and change log per op
/// (issue #46: `loadStoreIndex` is O(store) per request otherwise).
///
/// Crash-safety and the refusal surface are unchanged: the cache only ever
/// *skips* a reload, it never substitutes different validation. `get` returns
/// the cached index only when a fresh `StreamsDirFingerprint` of `streams/`
/// matches the state that was parsed; any external append, rewrite, create or
/// torn tail changes an entry's size/mtime/inode or the entry count and forces
/// the same `loadStoreIndex` call the uncached path performs — including its
/// roll-forward recovery and torn-tail refusals. The fingerprint is taken
/// *after* each load so a roll-forward rewrite lands inside the captured
/// state. `flintd`'s own writes additionally call `invalidate` after every
/// mutation attempt, and a failed reload leaves the cache empty rather than
/// serving a stale or torn view.
///
/// Stat granularity bound: a rewrite that preserves a file's name, size,
/// inode and both timestamps to the nanosecond is not detectable without
/// reading the file, so the fingerprint cannot see it. That is the accepted
/// single-writer trade-off; every other mutation is caught.
pub const StoreIndexCache = struct {
    index: ?StoreIndex = null,
    fingerprint: ?StreamsDirFingerprint = null,
    /// Number of real `loadStoreIndex` calls; instrumentation so tests can
    /// assert repeated ops reuse one parse without timing dependencies.
    loads: usize = 0,

    pub fn deinit(self: *StoreIndexCache, allocator: Allocator) void {
        self.invalidate(allocator);
    }

    /// Drops the cached index. Call after any op that may have mutated the store.
    pub fn invalidate(self: *StoreIndexCache, allocator: Allocator) void {
        if (self.index) |*idx| idx.deinit(allocator);
        self.index = null;
        self.fingerprint = null;
    }

    /// Returns the store index, reusing the cached parse while `streams/` is
    /// unchanged. The returned pointer borrows from the cache and stays valid
    /// until the next `get`, `invalidate` or `deinit` on this cache.
    pub fn get(self: *StoreIndexCache, io: Io, allocator: Allocator, root_path: []const u8) StoreError!*const StoreIndex {
        if (self.fingerprint) |cached| {
            // A fingerprint failure falls through to a real load so the
            // refusal surface stays exactly that of `loadStoreIndex`.
            if (fingerprintStreamsDir(io, root_path) catch null) |now| {
                if (now.eql(cached)) return &self.index.?;
            }
        }
        self.invalidate(allocator);
        const loaded = try storeio.loadStoreIndex(io, allocator, root_path);
        self.index = loaded;
        self.fingerprint = fingerprintStreamsDir(io, root_path) catch null;
        self.loads += 1;
        return &self.index.?;
    }
};

fn tmpStoreRoot(allocator: Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    const root_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    errdefer allocator.free(root_path);
    try storeio.initStore(std.testing.io, allocator, root_path);
    return root_path;
}

test "index cache reuses one parse across gets and matches a fresh load" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmpStoreRoot(allocator, &tmp);
    defer allocator.free(root_path);

    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    try storeio.createStream(io, allocator, root_path, .{
        .id = stream_id,
        .name = "main",
        .created = 1760000000000,
    });

    const good_raw = try storeio.readFileBounded(io, allocator, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer allocator.free(good_raw);
    const good_lines = try jsonl.readJsonlLines(allocator, good_raw);
    defer allocator.free(good_lines);
    const nh = try storeio.appendStreamChanges(io, allocator, root_path, stream_id, null, &.{good_lines[0]}, null);
    defer if (nh) |h| allocator.free(h);

    var cache: StoreIndexCache = .{};
    defer cache.deinit(allocator);

    const cached = try cache.get(io, allocator, root_path);
    try std.testing.expectEqual(@as(usize, 1), cache.loads);

    // Cached contents are identical to a fresh load.
    var fresh = try storeio.loadStoreIndex(io, allocator, root_path);
    defer fresh.deinit(allocator);
    try std.testing.expectEqual(fresh.total_changes, cached.total_changes);
    try std.testing.expectEqual(fresh.streams.len, cached.streams.len);
    for (fresh.streams, cached.streams) |want, got| {
        try std.testing.expectEqualStrings(want.id, got.id);
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expect(storeio.optStrEql(want.head, got.head));
    }

    // Repeated gets do not re-parse.
    _ = try cache.get(io, allocator, root_path);
    _ = try cache.get(io, allocator, root_path);
    try std.testing.expectEqual(@as(usize, 1), cache.loads);

    // Explicit invalidate forces a reload.
    cache.invalidate(allocator);
    _ = try cache.get(io, allocator, root_path);
    try std.testing.expectEqual(@as(usize, 2), cache.loads);
}

test "index cache reloads on external append, create, delete and torn tail" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmpStoreRoot(allocator, &tmp);
    defer allocator.free(root_path);

    const stream_id = "0199de2d-dc00-7000-8000-000000000010";
    const c1_id = "0199de2d-dc00-7000-8000-000000000100";
    const jsonl_path = try std.fmt.allocPrint(allocator, "{s}/streams/{s}.jsonl", .{ root_path, stream_id });
    defer allocator.free(jsonl_path);
    const json_path = try std.fmt.allocPrint(allocator, "{s}/streams/{s}.json", .{ root_path, stream_id });
    defer allocator.free(json_path);

    try storeio.createStream(io, allocator, root_path, .{
        .id = stream_id,
        .name = "main",
        .created = 1760000000000,
    });

    const good_raw = try storeio.readFileBounded(io, allocator, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer allocator.free(good_raw);
    const good_lines = try jsonl.readJsonlLines(allocator, good_raw);
    defer allocator.free(good_lines);
    const line_nl = try std.fmt.allocPrint(allocator, "{s}\n", .{good_lines[0]});
    defer allocator.free(line_nl);

    var cache: StoreIndexCache = .{};
    defer cache.deinit(allocator);

    {
        const idx = try cache.get(io, allocator, root_path);
        try std.testing.expectEqual(@as(usize, 1), cache.loads);
        try std.testing.expect(idx.streams[0].head == null);
    }

    // External writer appends to the .jsonl only (its crash landed between the
    // append and the .json head update): the fingerprint mismatch must force
    // a real reload, and the reload's roll-forward recovers head = c1.
    try storeio.appendSync(io, jsonl_path, line_nl);
    {
        const idx = try cache.get(io, allocator, root_path);
        try std.testing.expectEqual(@as(usize, 2), cache.loads);
        try std.testing.expectEqualStrings(c1_id, idx.streams[0].head.?);
    }
    // The recovered .json rewrite lands inside the captured fingerprint, so
    // the next get hits the cache instead of reloading forever.
    _ = try cache.get(io, allocator, root_path);
    try std.testing.expectEqual(@as(usize, 2), cache.loads);

    // External create mid-session is detected the same way.
    try storeio.createStream(io, allocator, root_path, .{
        .id = "0199de2d-dc00-7000-8000-000000000020",
        .name = "other",
        .created = 1760000000001,
    });
    {
        const idx = try cache.get(io, allocator, root_path);
        try std.testing.expectEqual(@as(usize, 3), cache.loads);
        try std.testing.expectEqual(@as(usize, 2), idx.streams.len);
    }

    // Torn tail appearing after the cache was filled still refuses
    // stream_torn; the failed load leaves the cache empty rather than serving
    // the stale parse.
    try storeio.appendSync(io, jsonl_path, "{\"truncated\":true");
    try std.testing.expectError(error.StreamTorn, cache.get(io, allocator, root_path));
    try std.testing.expect(cache.index == null);

    // After the tail is repaired the cache reloads and serves again.
    {
        var f = try Io.Dir.cwd().createFile(io, jsonl_path, .{ .truncate = true });
        defer f.close(io);
        try f.writeStreamingAll(io, line_nl);
        try f.sync(io);
    }
    {
        const idx = try cache.get(io, allocator, root_path);
        try std.testing.expectEqualStrings(c1_id, idx.findById(stream_id).?.head.?);
    }

    // External delete of both files drops the stream from the cached view.
    try Io.Dir.cwd().deleteFile(io, jsonl_path);
    try Io.Dir.cwd().deleteFile(io, json_path);
    {
        const idx = try cache.get(io, allocator, root_path);
        try std.testing.expectEqual(@as(usize, 1), idx.streams.len);
        try std.testing.expectEqualStrings("other", idx.streams[0].name);
    }
}
