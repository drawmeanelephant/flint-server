// Content-layer storage (docs/flint-blobs-spec.md §1/§9): content-addressed
// blobs under `blobs/<2>/<62>` and signed manifest logs under
// `manifests/<stream-id>.jsonl`. Wire-facing validation lives here so
// proto.zig handlers stay thin.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const storeio = @import("storeio.zig");
const manifest_mod = @import("manifest.zig");
const StoreError = storeio.StoreError;

// --- Content layer (docs/flint-blobs-spec.md §1/§9): blobs + manifests ----

/// Per-blob decoded byte bound (client spec: 1_800_000 bytes); the hex wire
/// form is 2x, staying inside the 4 MiB request bound.
pub const MaxBlobBytes: usize = 1_800_000;

pub fn blobPath(allocator: Allocator, root: []const u8, blob_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/blobs/{s}/{s}", .{ root, blob_id[0..2], blob_id[2..] });
}

pub fn manifestLogPath(allocator: Allocator, root: []const u8, stream_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/manifests/{s}.jsonl", .{ root, stream_id });
}

/// `blob_put`: stores decoded bytes iff SHA-256(bytes) == id. Idempotent —
/// an existing blob under the id is a no-op resend. Bytes arrive hex-decoded.
pub fn putBlob(io: Io, allocator: Allocator, root: []const u8, blob_id: []const u8, bytes: []const u8) StoreError!void {
    if (blob_id.len != 64) return error.BlobMalformed;
    for (blob_id) |c| {
        if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return error.BlobMalformed;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const want = store.decodeLowerHexFixed(32, blob_id) orelse return error.BlobMalformed;
    if (!std.mem.eql(u8, &digest, &want)) return error.BlobMalformed;
    const path = try blobPath(allocator, root, blob_id);
    defer allocator.free(path);
    if (storeio.fileExists(io, path)) return;
    const bdir = try std.fmt.allocPrint(allocator, "{s}/blobs/{s}", .{ root, blob_id[0..2] });
    defer allocator.free(bdir);
    Io.Dir.cwd().createDirPath(io, bdir) catch return error.IoFailure;
    try storeio.writeFileSafe(io, allocator, path, bytes);
}

/// `blob_get`: raw bytes for a content id, or BlobMissing.
pub fn readBlob(io: Io, allocator: Allocator, root: []const u8, blob_id: []const u8) StoreError![]u8 {
    const path = try blobPath(allocator, root, blob_id);
    defer allocator.free(path);
    if (!storeio.fileExists(io, path)) return error.BlobMissing;
    const data = storeio.readFileBounded(io, allocator, path, MaxBlobBytes + 1) catch |err| switch (err) {
        error.StoreTooLarge => return error.BlobMalformed,
        else => return err,
    };
    if (data.len > MaxBlobBytes) {
        allocator.free(data);
        return error.BlobMalformed;
    }
    return data;
}

/// Loads raw manifest lines for a stream id. Missing log = empty.
pub fn loadManifestLog(io: Io, allocator: Allocator, root: []const u8, stream_id: []const u8) StoreError![][]u8 {
    const path = try manifestLogPath(allocator, root, stream_id);
    defer allocator.free(path);
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |l| allocator.free(l);
        out.deinit(allocator);
    }
    if (!storeio.fileExists(io, path)) return out.toOwnedSlice(allocator);
    const raw = try storeio.readFileBounded(io, allocator, path, store.MaxLineBytes);
    defer allocator.free(raw);
    if (raw.len == 0) return out.toOwnedSlice(allocator);
    if (raw[raw.len - 1] != '\n') return error.ManifestTorn;
    var it = std.mem.splitScalar(u8, raw, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try out.append(allocator, try allocator.dupe(u8, line));
    }
    return out.toOwnedSlice(allocator);
}

pub const PutManifestResult = struct { stored: usize };

/// `put_manifest` — spec §9: appends signed manifest lines bound to Changes
/// already in the stream log (head chain or detached). Per line: parses,
/// `stream` matches the resolved stream, `change` exists in the log,
/// `author` equals that Change's author and the signature verifies under it
/// (this is the author's attestation, not a publisher's), author allowlist
/// applies. Dedupe by `change` like `deposit`: byte-identical resend skips,
/// same change id under different bytes is an id conflict. All-or-nothing:
/// nothing is appended when any line fails.
pub fn putManifestLines(
    io: Io,
    allocator: Allocator,
    root_path: []const u8,
    stream_id: []const u8,
    raw_lines: []const []const u8,
    allow_authors: ?[]const [64]u8,
    detail_out: ?*?[]const u8,
) StoreError!PutManifestResult {
    if (detail_out) |d| d.* = null;
    var idx = try storeio.loadStoreIndex(io, allocator, root_path);
    defer idx.deinit(allocator);
    const rec = idx.findByNameOrId(stream_id) orelse return error.StreamMissing;
    const resolved_id = rec.id;

    if (raw_lines.len == 0 or raw_lines.len > 256) {
        if (detail_out) |d| d.* = "batch size out of bounds";
        return error.ManifestMalformed;
    }

    var loaded = try storeio.loadStream(io, allocator, root_path, resolved_id);
    defer loaded.deinit(allocator);

    // change id -> author over the whole log (detached lines included).
    var author_by_change = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = author_by_change.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        author_by_change.deinit();
    }
    for (loaded.changes) |c| {
        try author_by_change.put(try allocator.dupe(u8, c.id), c.author);
    }

    // Existing manifest lines -> dedupe by change id.
    const existing = try loadManifestLog(io, allocator, root_path, resolved_id);
    defer {
        for (existing) |l| allocator.free(l);
        allocator.free(existing);
    }
    var line_by_change = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = line_by_change.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        line_by_change.deinit();
    }
    for (existing) |l| {
        var m = manifest_mod.parseManifestLine(allocator, l) catch return error.ManifestMalformed;
        defer m.deinit(allocator);
        try line_by_change.put(try allocator.dupe(u8, m.change), l);
    }

    var batch: std.ArrayList([]const u8) = .empty;
    defer batch.deinit(allocator);
    var batch_changes = std.StringHashMap(void).init(allocator);
    defer {
        var it = batch_changes.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        batch_changes.deinit();
    }

    var stored: usize = 0;
    for (raw_lines) |raw_line| {
        const trimmed = std.mem.trimEnd(u8, raw_line, "\r\n");
        if (trimmed.len == 0 or std.mem.indexOfScalar(u8, trimmed, '\n') != null or
            std.mem.indexOfScalar(u8, trimmed, '\r') != null)
        {
            return error.ManifestMalformed;
        }

        var m = manifest_mod.parseManifestLine(allocator, trimmed) catch return error.ManifestMalformed;
        defer m.deinit(allocator);

        if (!std.mem.eql(u8, m.stream, resolved_id)) return error.ManifestMalformed;

        const change_author = author_by_change.get(m.change) orelse
            return error.ChangeMissing;
        if (!std.mem.eql(u8, m.author, change_author)) return error.SigInvalid;

        if (allow_authors) |allowed| {
            var ok = false;
            for (allowed) |a| {
                if (std.mem.eql(u8, &a, change_author)) {
                    ok = true;
                    break;
                }
            }
            if (!ok) return error.AuthorNotAllowed;
        }

        const verified = manifest_mod.verifyManifest(allocator, &m) catch |err| switch (err) {
            error.ManifestMalformed => return error.ManifestMalformed,
            error.OutOfMemory => return error.OutOfMemory,
            error.WriteFailed => return error.IoFailure,
        };
        if (!verified) return error.SigInvalid;

        if (line_by_change.get(m.change)) |prev| {
            if (!std.mem.eql(u8, prev, trimmed)) {
                if (detail_out) |d| d.* = "id conflict";
                return error.ManifestMalformed;
            }
            continue; // byte-identical resend
        }
        if (batch_changes.contains(m.change)) {
            if (detail_out) |d| d.* = "id conflict";
            return error.ManifestMalformed;
        }
        try batch_changes.put(try allocator.dupe(u8, m.change), {});
        try batch.append(allocator, trimmed);
        stored += 1;
    }

    if (batch.items.len == 0) return .{ .stored = 0 };

    const mdir = try std.fmt.allocPrint(allocator, "{s}/manifests", .{root_path});
    defer allocator.free(mdir);
    Io.Dir.cwd().createDirPath(io, mdir) catch return error.IoFailure;

    const path = try manifestLogPath(allocator, root_path, resolved_id);
    defer allocator.free(path);
    try appendLines(io, allocator, path, batch.items);
    return .{ .stored = stored };
}

fn appendLines(io: Io, allocator: Allocator, path: []const u8, lines: []const []const u8) StoreError!void {
    var f = Io.Dir.cwd().createFile(io, path, .{ .truncate = false, .read = true }) catch
        return error.IoFailure;
    defer f.close(io);
    const len = f.length(io) catch return error.IoFailure;
    var off = len;
    for (lines) |line| {
        f.writePositionalAll(io, line, off) catch return error.IoFailure;
        off += line.len;
        f.writePositionalAll(io, "\n", off) catch return error.IoFailure;
        off += 1;
    }
    _ = allocator;
    f.sync(io) catch return error.IoFailure;
}

/// `get_manifest`: manifest lines in log order. `after` names the manifest
/// whose change id bounds the range; when `after` names a Change without a
/// manifest, all lines return (conservative resend — the receiver dedupes).
pub fn getManifestLines(
    io: Io,
    allocator: Allocator,
    root_path: []const u8,
    stream_id: []const u8,
    after: ?[]const u8,
) StoreError![][]const u8 {
    var idx = try storeio.loadStoreIndex(io, allocator, root_path);
    defer idx.deinit(allocator);
    const rec = idx.findByNameOrId(stream_id) orelse return error.StreamMissing;
    const resolved_id = rec.id;

    const lines = try loadManifestLog(io, allocator, root_path, resolved_id);
    errdefer {
        for (lines) |l| allocator.free(l);
        allocator.free(lines);
    }

    if (after == null) return @ptrCast(lines);

    // Find the manifest whose change matches `after`.
    var pos: ?usize = null;
    for (lines, 0..) |l, i| {
        var m = manifest_mod.parseManifestLine(allocator, l) catch return error.ManifestMalformed;
        defer m.deinit(allocator);
        if (std.mem.eql(u8, m.change, after.?)) {
            pos = i;
            break;
        }
    }
    if (pos == null) {
        // `after` is a Change id without a manifest: valid when the Change
        // exists (pre-content revision) — return all lines; otherwise refuse.
        var loaded = try storeio.loadStream(io, allocator, root_path, resolved_id);
        defer loaded.deinit(allocator);
        var found = false;
        for (loaded.changes) |c| {
            if (std.mem.eql(u8, c.id, after.?)) found = true;
        }
        if (!found) return error.ChangeMissing;
        return @ptrCast(lines);
    }
    var out: std.ArrayList([]u8) = .empty;
    errdefer out.deinit(allocator);
    for (lines[pos.? + 1 ..]) |l| try out.append(allocator, l);
    for (lines[0 .. pos.? + 1]) |l| allocator.free(l);
    allocator.free(lines);
    return @ptrCast(try out.toOwnedSlice(allocator));
}
