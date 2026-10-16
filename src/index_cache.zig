const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const storeio = @import("storeio.zig");

/// Memoized `loadStoreIndex` for long-lived serving loops (issue #46).
/// Validity is probed with a `streams/` directory fingerprint — entry names
/// plus each entry's inode, size, and mtime — so appends, torn tails,
/// same-size rewrites, and mutations by other processes all force a reload;
/// the cache never trusts in-process state. Sessions are serialized
/// (spec §3.3), so no locking is required.
pub const IndexCache = struct {
    index: ?storeio.StoreIndex = null,
    stamp: ?[]StampEntry = null,
    /// Total real `loadStoreIndex` runs; surfaced for tests and profiling.
    loads: usize = 0,

    const StampEntry = struct {
        name: []u8,
        inode: u64,
        size: u64,
        mtime_ns: i96,
        kind: Io.File.Kind,
    };

    /// Returns the cached index, reloading only when the `streams/` fingerprint
    /// changed. The returned pointer is borrowed: valid until the next `get`
    /// or `deinit` on this cache, and must not be mutated or freed.
    pub fn get(
        self: *IndexCache,
        io: Io,
        allocator: Allocator,
        root_path: []const u8,
    ) storeio.StoreError!*const storeio.StoreIndex {
        const fresh: ?[]StampEntry = stampStreamsDir(io, allocator, root_path) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        defer if (fresh) |f| freeStampEntries(allocator, f);

        if (fresh) |f| {
            if (self.index != null and self.stamp != null and stampEntriesEql(self.stamp.?, f)) {
                return &self.index.?;
            }
        } else {
            // The probe failed, so a cached index could mask a missing or
            // racing store; drop it and let loadStoreIndex surface the error.
            self.clear(allocator);
        }

        var idx = try storeio.loadStoreIndex(io, allocator, root_path);
        errdefer idx.deinit(allocator);
        const owned_stamp: ?[]StampEntry = if (fresh) |f| try dupeStampEntries(allocator, f) else null;

        self.clear(allocator);
        self.index = idx;
        self.stamp = owned_stamp;
        self.loads += 1;
        return &self.index.?;
    }

    pub fn deinit(self: *IndexCache, allocator: Allocator) void {
        self.clear(allocator);
    }

    fn clear(self: *IndexCache, allocator: Allocator) void {
        if (self.index) |*idx| idx.deinit(allocator);
        self.index = null;
        if (self.stamp) |s| freeStampEntries(allocator, s);
        self.stamp = null;
    }
};

fn stampStreamsDir(io: Io, allocator: Allocator, root_path: []const u8) ![]IndexCache.StampEntry {
    const streams_dir_path = try std.fs.path.join(allocator, &.{ root_path, "streams" });
    defer allocator.free(streams_dir_path);

    var dir = try Io.Dir.cwd().openDir(io, streams_dir_path, .{ .iterate = true });
    defer dir.close(io);

    var entries: std.ArrayList(IndexCache.StampEntry) = .empty;
    errdefer {
        for (entries.items) |e| allocator.free(e.name);
        entries.deinit(allocator);
    }

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const st = try dir.statFile(io, entry.name, .{ .follow_symlinks = false });
        try entries.append(allocator, .{
            .name = try allocator.dupe(u8, entry.name),
            .inode = @intCast(st.inode),
            .size = st.size,
            .mtime_ns = st.mtime.nanoseconds,
            .kind = st.kind,
        });
    }

    std.mem.sort(IndexCache.StampEntry, entries.items, {}, stampEntryLessThan);
    return entries.toOwnedSlice(allocator);
}

fn stampEntryLessThan(_: void, a: IndexCache.StampEntry, b: IndexCache.StampEntry) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}

fn stampEntriesEql(a: []const IndexCache.StampEntry, b: []const IndexCache.StampEntry) bool {
    if (a.len != b.len) return false;
    for (a, b) |ea, eb| {
        if (!std.mem.eql(u8, ea.name, eb.name) or
            ea.inode != eb.inode or
            ea.size != eb.size or
            ea.mtime_ns != eb.mtime_ns or
            ea.kind != eb.kind) return false;
    }
    return true;
}

fn dupeStampEntries(allocator: Allocator, entries: []const IndexCache.StampEntry) ![]IndexCache.StampEntry {
    const out = try allocator.alloc(IndexCache.StampEntry, entries.len);
    var init: usize = 0;
    errdefer {
        for (out[0..init]) |e| allocator.free(e.name);
        allocator.free(out);
    }
    for (entries, 0..) |e, i| {
        out[i] = e;
        out[i].name = try allocator.dupe(u8, e.name);
        init += 1;
    }
    return out;
}

fn freeStampEntries(allocator: Allocator, entries: []IndexCache.StampEntry) void {
    for (entries) |e| allocator.free(e.name);
    allocator.free(entries);
}
